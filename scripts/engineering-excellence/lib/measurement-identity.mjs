// ScanMeasurementIdentity (PRD 15.1): who, what and where a measurement was taken, and whether it is allowed to support a release claim.
//
// A measurement is VALID only when it names an exact commit with a clean source tree, an exact bundle whose digest matches its own sidecar,
// the configuration it ran under and the corpus it ran on. Anything else produces a record that still describes the run, with
// `measurementValid: false` and the reasons, so a dirty or stale run can be kept as a diagnostic and can never be mistaken for evidence.
//
// This module reads; it never stashes, cleans, builds or modifies the checkout.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import * as os from 'node:os';
import { REPO_ROOT } from './model.mjs';

// Files the program itself rewrites while it works. They do not make the SCANNER source dirty for measurement purposes, and they are
// listed in the record so the exclusion is visible rather than silent.
export const BOOKKEEPING_PATHS = Object.freeze([
  /^scripts\/engineering-excellence\/(status\.json|events\.jsonl|data\/(inventory\.verification|baseline\.results)\.json)$/,
  /^docs\/engineering-excellence\//,
]);

const SECRETISH = /(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|ENDPOINT|HOST|URL|PROXY)/i;
const sha256 = (data) => createHash('sha256').update(data).digest('hex');

function run(cmd, args, cwd, timeout = 8000, { raw = false } = {}) {
  try {
    const out = execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout, maxBuffer: 16 * 1024 * 1024 });
    return raw ? out : out.trim();
  } catch { return null; }
}

export function sha256File(path) {
  try { return sha256(readFileSync(path)); } catch { return null; }
}

/** Digest of a set of files (path and content digest, sorted): a corpus identity that changes when any listed file does. */
export function digestOfFiles(root, rels) {
  const parts = [];
  for (const rel of [...rels].sort()) {
    const p = join(root, rel);
    parts.push(`${rel}\0${existsSync(p) && statSync(p).isFile() ? sha256File(p) : 'missing'}`);
  }
  return sha256(parts.join('\n'));
}

export function digestOfTree(root, relDir, { maxFiles = 20000 } = {}) {
  const out = [];
  const walk = (dir) => {
    if (out.length > maxFiles) return;
    let entries = [];
    try { entries = readdirSync(join(root, dir), { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const rel = `${dir}/${e.name}`;
      if (e.isDirectory()) { if (e.name !== 'node_modules' && e.name !== '.git' && e.name !== '.agentic-security') walk(rel); } else if (e.isFile()) out.push(rel);
    }
  };
  walk(relDir);
  return { files: out.length, sha256: digestOfFiles(root, out), truncated: out.length > maxFiles };
}

/** Toolchain versions. A missing tool is recorded as null, never guessed. */
export function toolchain(cwd = REPO_ROOT) {
  const first = (s) => (s ? s.split('\n')[0].slice(0, 120) : null);
  return {
    node: process.version,
    npm: first(run('npm', ['--version'], cwd)),
    git: first(run('git', ['--version'], cwd)),
    python3: first(run('python3', ['--version'], cwd)),
    java: first(run('java', ['-version'], cwd)),
    go: first(run('go', ['version'], cwd)),
    ghc: first(run('ghc', ['--version'], cwd)),
    os: `${os.platform()} ${os.release()} ${os.arch()}`,
    cpus: os.cpus().length,
    memoryGb: Math.round(os.totalmem() / 2 ** 30),
  };
}

/** The knobs that change what a scan does. Values of anything that could be a credential or an address are replaced by `<set>`. */
export function configSnapshot(env = process.env) {
  const knobs = {};
  for (const k of Object.keys(env).filter((x) => x.startsWith('AGENTIC_SECURITY_')).sort()) knobs[k] = SECRETISH.test(k) ? '<set>' : String(env[k]).slice(0, 80);
  const endpoint = env.AGENTIC_SECURITY_LLM_ENDPOINT || '';
  let modelEndpointMode = 'none';
  if (endpoint) {
    try {
      const h = new URL(endpoint.split(',')[0]).hostname.toLowerCase();
      modelEndpointMode = h === 'localhost' || h === '::1' || /^127\./.test(h) ? 'loopback' : 'remote';
    } catch { modelEndpointMode = 'unparseable'; }
  }
  return { knobs, modelEndpointMode, modelValidatorEnabled: modelEndpointMode !== 'none' && env.AGENTIC_SECURITY_LLM_VALIDATE !== '0' };
}

export function checkoutState(root = REPO_ROOT) {
  const commit = run('git', ['rev-parse', 'HEAD'], root);
  const branch = run('git', ['rev-parse', '--abbrev-ref', 'HEAD'], root);
  const porcelain = run('git', ['status', '--porcelain', '--untracked-files=all'], root, 30000, { raw: true });
  if (porcelain === null) return { commit, branch, available: false, dirtyPaths: [], ignoredBookkeeping: [] };
  const dirtyPaths = []; const ignoredBookkeeping = [];
  for (const line of porcelain.split('\n').filter(Boolean)) {
    const rel = line.slice(3).replace(/^"|"$/g, '').split(' -> ').pop();
    (BOOKKEEPING_PATHS.some((re) => re.test(rel)) ? ignoredBookkeeping : dirtyPaths).push(rel);
  }
  return { commit, branch, available: true, dirtyPaths, ignoredBookkeeping };
}

/**
 * Build the identity for a measurement. `corpus` is `{ id, files: [rel...] }` or `{ id, tree: relDir }`; omit it for a measurement that
 * has no corpus (a build or a scan-time probe).
 */
export function measurementIdentity(root = REPO_ROOT, { corpus = null, bundleRel = 'scanner/dist/agentic-security.mjs', env = process.env, startedAt = new Date().toISOString() } = {}) {
  const invalidReasons = [];
  const co = checkoutState(root);
  if (!co.available || !co.commit) invalidReasons.push('git_unavailable');
  if (co.dirtyPaths.length) invalidReasons.push('dirty_worktree');

  const bundlePath = join(root, bundleRel);
  const bundleSha256 = sha256File(bundlePath);
  if (!bundleSha256) invalidReasons.push('bundle_missing');
  const sidecar = existsSync(`${bundlePath}.sha256`) ? readFileSync(`${bundlePath}.sha256`, 'utf8').trim().split(/\s+/)[0] : null;
  if (bundleSha256 && !sidecar) invalidReasons.push('bundle_sidecar_missing');
  else if (bundleSha256 && sidecar !== bundleSha256) invalidReasons.push('bundle_sidecar_mismatch');

  const cfg = configSnapshot(env);
  const configSha256 = sha256(JSON.stringify(cfg));
  let corpusId = null; let corpusSha256 = null; let corpusFiles = null;
  if (corpus) {
    corpusId = corpus.id;
    if (corpus.files) { corpusSha256 = digestOfFiles(root, corpus.files); corpusFiles = corpus.files.length; if (corpus.files.some((f) => !existsSync(join(root, f)))) invalidReasons.push('corpus_incomplete'); }
    else if (corpus.tree) { const t = digestOfTree(root, corpus.tree); corpusSha256 = t.sha256; corpusFiles = t.files; if (!t.files) invalidReasons.push('corpus_empty'); }
  }
  return {
    schemaVersion: 1,
    sourceCommit: co.commit,
    sourceBranch: co.branch,
    sourceTreeClean: co.available && co.dirtyPaths.length === 0,
    dirtyPaths: co.dirtyPaths.slice(0, 50),
    bookkeepingPathsIgnored: co.ignoredBookkeeping.length,
    bundleSha256,
    bundleSidecarSha256: sidecar,
    lockfileSha256: sha256File(join(root, 'scanner', 'package-lock.json')),
    configSha256,
    config: cfg,
    corpusId, corpusSha256, corpusFiles,
    toolchain: toolchain(root),
    startedAt,
    measurementValid: invalidReasons.length === 0,
    releaseTrust: invalidReasons.length === 0 ? 'trusted' : 'untrusted_for_release',
    invalidReasons,
  };
}

/** A claim-grade check: throws with the reasons when the identity is not valid. */
export function assertValidForRelease(identity) {
  if (!identity.measurementValid) throw new Error(`measurement is untrusted_for_release: ${identity.invalidReasons.join(', ')}`);
  return identity;
}
