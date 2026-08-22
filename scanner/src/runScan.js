// Filesystem driver: reads a directory, builds the fileContents/depFileContents
// maps the engine expects, and invokes runFullScan.
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { listFiles } from './util/glob.js';
import { runFullScan, shouldScan, isKubernetesManifest, isInstructionFile } from './engine.js';
import { appendScanSnapshot } from './posture/security-trend.js';
import { recover as recoverFixHistory } from './posture/fix-history.js';
import { stampScan } from './posture/ruleset-version.js';

const DEP_FILE_NAMES = new Set([
  'package.json','package-lock.json','yarn.lock','pnpm-lock.yaml',
  'requirements.txt','pyproject.toml','poetry.lock','Pipfile.lock',
  'composer.json','composer.lock','Gemfile','Gemfile.lock',
  'go.mod','Cargo.toml','Cargo.lock',
  'pom.xml','build.gradle','build.gradle.kts',
  'pubspec.yaml','pubspec.lock',
]);

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
    if (stat.size > 500_000) continue;
    let content;
    try { content = await fs.readFile(abs, 'utf8'); } catch { continue; }
    const base = path.basename(rel);
    if (DEP_FILE_NAMES.has(base)) depFileContents[rel] = content;
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
    if (shouldScan(rel) || isKubernetesManifest(rel, content) || isInstructionFile(rel)) fileContents[rel] = content;
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
export function changedSince(root, gitRef) {
  if (!gitRef) return null;
  try {
    const out = cp.execFileSync('git', ['diff', '--name-only', `${gitRef}...HEAD`], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    const set = new Set(out.split('\n').filter(Boolean));
    // Also include uncommitted changes
    try {
      const dirty = cp.execFileSync('git', ['status', '--porcelain'], {
        cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
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
  if (opts.fileContents) {
    fileContents = opts.fileContents;
    depFileContents = opts.depFileContents || {};
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
    } else if (opts.onProgress) {
      opts.onProgress({ phase: 'warning', file: 'changedSince ignored: not a git repo or invalid ref', current: 0, total: 0 });
    }
  }

  // R8: `resume` is opt-in. Left undefined here, runFullScan falls back to the
  // AGENTIC_SECURITY_RESUME=1 env var, which is off by default.
  const scan = await runFullScan({ fileContents, depFileContents, scanRoot: root, resume: opts.resume, deep: opts.deep, deepInCi: opts.deepInCi }, opts.onProgress || (()=>{}));
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
