// Filesystem driver: reads a directory, builds the fileContents/depFileContents
// maps the engine expects, and invokes runFullScan.
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { listFiles } from './util/glob.js';
import { hardenGitArgs, hardenGitEnv } from './util/git-hardening.js';
import { runFullScan, shouldScan, isKubernetesManifest, isCloudFormationTemplate, isInstructionFile } from './engine.js';
import { appendScanSnapshot } from './posture/security-trend.js';
import { recover as recoverFixHistory } from './posture/fix-history.js';
import { stampScan } from './posture/ruleset-version.js';

const DEP_FILE_NAMES = new Set([
  'package.json','package-lock.json','yarn.lock','pnpm-lock.yaml',
  'requirements.txt','pyproject.toml','poetry.lock','Pipfile.lock',
  'composer.json','composer.lock','Gemfile','Gemfile.lock',
  // go.sum, not just go.mod: go.mod lists what this module REQUIRES, go.sum
  // lists what was RESOLVED — the transitive graph that is actually shipped.
  // `_parseGoSum` and its dispatch entry have always existed in engine.js; the
  // file simply never reached them, so Go SCA saw direct requires only.
  // Measured by bench/sca-replay at 15 of 549 labelled vulnerable versions.
  'go.mod','go.sum','Cargo.toml','Cargo.lock',
  'pom.xml','build.gradle','build.gradle.kts',
  'pubspec.yaml','pubspec.lock',
]);

// Python requirements files are `requirements/dev.txt`, `requirements-dev.txt`
// and `requirements/base.txt` at least as often as they are the bare name.
// pallets/flask ships `requirements/dev.txt` and scored 0 of 11 labelled
// vulnerabilities until this matched.
//
// Deliberately narrow. An arbitrary `.txt` reaching the PyPI parser would
// invent components out of prose, which is a worse failure than missing one:
// a false dependency is unfalsifiable noise in a supply-chain report.
const REQUIREMENTS_FILE = /^requirements(?:[._-][\w.-]+)?\.txt$/i;
const REQUIREMENTS_DIR_FILE = /(?:^|\/)requirements\/[\w.-]+\.txt$/i;

export function isDepFile(rel) {
  const base = rel.split('/').pop();
  if (DEP_FILE_NAMES.has(base)) return true;
  if (REQUIREMENTS_FILE.test(base)) return true;
  if (REQUIREMENTS_DIR_FILE.test(rel.split(path.sep).join('/'))) return true;
  return false;
}

// Two caps, because the two kinds of file cost completely different amounts to
// process.
//
// A CODE file over the cap is skipped to protect the analysis path: parsing and
// walking an AST of a multi-megabyte generated file is where a scan goes from
// slow to hung.
//
// A MANIFEST is read by JSON.parse or a line loop. Applying the code cap to it
// bought nothing and cost everything: npm/cli's package-lock.json is 666 KB,
// next.js's pnpm-lock.yaml is 910 KB, magento2's composer.lock is 501 KB — so
// on every project large enough for supply-chain risk to matter, the lockfile
// was dropped and SCA silently fell back to the exact versions that happened to
// appear in package.json. That is DIRECT dependencies only, while the headline
// claim of this feature is transitive reachability.
//
// The manifest cap is larger, not absent. Reading an unbounded file into memory
// to parse it is how a scan becomes a denial of service against its own host.
const MAX_CODE_BYTES = 500_000;
const MAX_DEP_BYTES = 10_000_000;

const DEFAULT_IGNORE = [
  '**/node_modules/**','**/.git/**','**/__pycache__/**','**/vendor/**',
  '**/dist/**','**/build/**','**/.next/**','**/venv/**','**/env/**','**/.venv/**',
  '**/target/**','**/bin/**','**/obj/**','**/.cache/**','**/coverage/**',
  '**/bower_components/**','**/tests/**','**/test/**','**/__tests__/**','**/spec/**','**/mocks/**',
];

export async function readTree(root, { ignore = [] } = {}) {
  const entries = await listFiles(root, { ignore: [...DEFAULT_IGNORE, ...ignore] });
  const fileContents = {};
  const depFileContents = {};
  for (const rel of entries) {
    const abs = path.join(root, rel);
    let stat;
    try { stat = await fs.stat(abs); } catch { continue; }
    const dep = isDepFile(rel);
    if (stat.size > (dep ? MAX_DEP_BYTES : MAX_CODE_BYTES)) continue;
    let content;
    try { content = await fs.readFile(abs, 'utf8'); } catch { continue; }
    const base = path.basename(rel);
    if (dep) depFileContents[rel] = content;
    // Cross-language taint module needs to see openapi/swagger specs even
    // though they aren't "code" per se. Stash them in depFileContents so
    // they ride through to runFullScan without polluting the SAST loop.
    if (/(?:openapi|swagger)\.(?:ya?ml|json)$/i.test(base)) depFileContents[rel] = content;
    else if (/\.proto$/i.test(base)) depFileContents[rel] = content;
    else if (/\.(?:graphql|gql)$/i.test(base)) depFileContents[rel] = content;
    else if (/\.tf$/i.test(base)) depFileContents[rel] = content;
    // A Kubernetes manifest is admitted on CONTENT, not on living under a
    // directory named k8s/ — see isKubernetesManifest. Without this the
    // k8s-admission detector is wired into the dispatch and never invoked by it.
    // BOTH gates must open, exactly as the k8s fix required: runScan admits a
    // file here, then runFullScan re-filters the same list. Opening only one
    // leaves the detector just as dark.
    // A CloudFormation template is a `.yaml`/`.json` that no path predicate can
    // recognise — same problem as a Kubernetes manifest, same fix, and the same
    // requirement that BOTH gates open: runFullScan re-filters this exact list.
    if (shouldScan(rel) || isKubernetesManifest(rel, content) || isCloudFormationTemplate(rel, content) || isInstructionFile(rel)) fileContents[rel] = content;
    // Auxiliary files: .properties files are referenced by Java rules
    // (e.g. OWASP Benchmark's benchmark.properties resolves algorithm
    // aliases). They are not scannable for vulns themselves, but the
    // project index parses key=value lines for cross-file lookup.
    else if (/\.properties$/i.test(rel)) fileContents[rel] = content;
  }
  return { fileContents, depFileContents };
}

// Feat-10: incremental scan via `--changed-since <git-ref>`. Returns the set of
// repo-relative paths modified since the ref, or null if git is unavailable.
//
// `root` is the scan target's repository, not this project's own trusted
// checkout — hardened per FR-PROV-024 / the second Finding Provenance PRD
// audit (same exposure class as provenance/git-evidence.js: a hostile
// .git/config's `core.fsmonitor` fires on the `git status --porcelain`
// call below just from reading repo state).
export function changedSince(root, gitRef) {
  if (!gitRef) return null;
  try {
    const out = cp.execFileSync('git', hardenGitArgs(['diff', '--name-only', `${gitRef}...HEAD`]), {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv(),
    });
    const set = new Set(out.split('\n').filter(Boolean));
    // Also include uncommitted changes
    try {
      const dirty = cp.execFileSync('git', hardenGitArgs(['status', '--porcelain']), {
        cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv(),
      });
      for (const line of dirty.split('\n')) {
        const f = line.slice(3).trim();
        if (f) set.add(f);
      }
    } catch {}
    return set;
  } catch {
    return null;
  }
}

export async function runScan(rootDir, opts = {}) {
  const root = path.resolve(rootDir);
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  // Premortem 2R4.1: reconcile any pending entries from a crash mid-apply_fix
  // before we do anything else. Idempotent + best-effort; logs to stderr.
  try {
    const recovered = await recoverFixHistory(root);
    if (Array.isArray(recovered) && recovered.length) {
      for (const r of recovered) {
        process.stderr.write(`agentic-security: recovered fix-history entry ${r.id} → status=${r.status}${r.error ? ' (' + r.error + ')' : ''}\n`);
      }
    }
  } catch (_) { /* best-effort */ }
  // Caller may pre-build fileContents (used by the MCP server's scan_diff to
  // scope a scan to a specific file list without walking the whole tree).
  let fileContents, depFileContents;
  // `completeScan` answers ONE question for the whole pipeline: does the file
  // set below cover all of `root`, or only a subset of it? Anything downstream
  // that reasons about the ABSENCE of a finding — most importantly the
  // provenance lifecycle ledger, whose remediation pass closes every open
  // stableId missing from this scan — is only sound on a complete scan. A
  // subset scan that claims completeness marks the entire rest of the project
  // remediated. It starts true and is only ever narrowed, so a new subsetting
  // path added later must opt OUT explicitly rather than silently inherit a
  // false claim of coverage.
  let completeScan = true;
  if (opts.fileContents) {
    // Caller-supplied file list (MCP `scan_diff`, the LSP's on-save scan): by
    // construction a subset of the tree, not a scan of it.
    fileContents = opts.fileContents;
    depFileContents = opts.depFileContents || {};
    completeScan = false;
  } else {
    ({ fileContents, depFileContents } = await readTree(root, opts));
  }

  // Feat-10: incremental mode — restrict the scan to files changed since a git ref
  if (opts.changedSince) {
    const changed = changedSince(root, opts.changedSince);
    if (changed) {
      const filtered = {};
      for (const f of Object.keys(fileContents)) {
        if (changed.has(f)) filtered[f] = fileContents[f];
      }
      fileContents = filtered;
      // Only when the filter actually applied. A `changedSince` that resolved
      // to null (not a git repo / bad ref) is warned about below and scans the
      // whole tree, which IS complete.
      completeScan = false;
    } else if (opts.onProgress) {
      opts.onProgress({ phase: 'warning', file: 'changedSince ignored: not a git repo or invalid ref', current: 0, total: 0 });
    }
  }

  // R8: `resume` is opt-in. Left undefined here, runFullScan falls back to the
  // AGENTIC_SECURITY_RESUME=1 env var, which is off by default.
  const scan = await runFullScan({ fileContents, depFileContents, scanRoot: root, resume: opts.resume, deep: opts.deep, deepInCi: opts.deepInCi, completeScan }, opts.onProgress || (()=>{}));
  // Premortem 2R4.2: stamp ruleset version + source on the scan result, and
  // notify if the operator pinned a different version than what's installed.
  try { stampScan(root, scan); } catch {}
  // Append snapshot to history for /security-trend (non-blocking, never throws)
  try { appendScanSnapshot(scan, root); } catch {}
  return {
    scan,
    meta: { scanId: cryptoUUID(), startedAt, durationMs: Date.now() - t0, root, mode: opts.changedSince ? 'incremental' : 'full' },
  };
}

export const scanPath = runScan;

function cryptoUUID(){
  return globalThis.crypto?.randomUUID?.() || `scan-${Date.now().toString(36)}`;
}
