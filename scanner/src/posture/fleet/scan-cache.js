// The content-addressed scan cache (PRD 4, requirement 5). A repository's scan result is reused only when EVERYTHING that could
// change it is unchanged: the commit (and any uncommitted change), the lockfiles, the scan configuration and the scanner itself.
//
//   key = sha256( repository fingerprint, lockfile digests, configuration, scanner identity )
//
// Anything that cannot be determined makes the key `null`, and a null key means "do not cache": an unknown input must never be
// treated as an unchanged one. The scanner identity is the package version plus the SHA-256 recorded for the shipped bundle, so a
// change to scanner logic changes the key. A source checkout with no built bundle has no such identity and therefore never reuses
// a cached result.
//
// A cached record carries its own digest; one that was edited, truncated or does not match its key is a miss, never a hit.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { STATE_DIR_NAME } from '../state-dir.js';

const LOCKFILES = Object.freeze(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'go.sum', 'Cargo.lock', 'Pipfile.lock', 'poetry.lock', 'requirements.txt', 'Gemfile.lock', 'composer.lock', 'flake.lock', 'cabal.project.freeze', 'stack.yaml.lock']);
const SKIP = new Set(['.git', 'node_modules', STATE_DIR_NAME]);
const sha = (s) => createHash('sha256').update(s).digest('hex');
const MAX_FILES = 5000; const MAX_FILE_BYTES = 2 * 1024 * 1024; const MAX_TOTAL_BYTES = 128 * 1024 * 1024;

function git(repo, args, timeout = 10000) {
  const r = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
  return r.error || r.status !== 0 ? null : r.stdout;
}

function treeDigest(root) {
  const h = createHash('sha256'); let files = 0; let total = 0; let complete = true;
  const walk = (d, rel) => {
    let ents = [];
    try { ents = fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)); } catch { complete = false; return; }
    for (const e of ents) {
      if (!complete) return;
      if (SKIP.has(e.name)) continue;
      const p = path.join(d, e.name); const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { h.update(`L ${r}\0`); continue; }
      if (e.isDirectory()) { walk(p, r); continue; }
      if (!e.isFile()) continue;
      if (++files > MAX_FILES) { complete = false; return; }
      let st; try { st = fs.statSync(p); } catch { complete = false; return; }
      total += st.size;
      if (total > MAX_TOTAL_BYTES) { complete = false; return; }
      if (st.size > MAX_FILE_BYTES) { h.update(`B ${r} ${st.size}\0`); continue; }
      try { h.update(`F ${r}\0${sha(fs.readFileSync(p))}\0`); } catch { complete = false; return; }
    }
  };
  walk(root, '');
  return complete ? h.digest('hex') : null;
}

/** What identifies this repository's content right now, or null parts where it cannot be determined. */
export function repoFingerprint(repoPath) {
  const head = git(repoPath, ['rev-parse', 'HEAD']);
  const commit = head ? head.trim() : null;
  let content = null; let dirty = null;
  if (commit) {
    const status = git(repoPath, ['status', '--porcelain=v1', '-uall']);
    dirty = status == null ? null : status.trim().length > 0;
    if (dirty === false) content = `git:${commit}`;
    else if (dirty === true) { const t = treeDigest(repoPath); content = t ? `git+worktree:${commit}:${t}` : null; }
  } else { const t = treeDigest(repoPath); content = t ? `tree:${t}` : null; }
  const lock = {};
  for (const f of LOCKFILES) { try { const st = fs.statSync(path.join(repoPath, f)); if (st.isFile() && st.size <= 32 * 1024 * 1024) lock[f] = sha(fs.readFileSync(path.join(repoPath, f))); } catch { /* absent */ } }
  return { commit, dirty, content, lockfiles: lock };
}

/** Package version + the bundle's recorded hash. Null when the scanner cannot be identified (a source checkout), which disables the cache. */
export function scannerIdentity() {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    for (const base of [path.join(here, '..', '..', '..'), path.join(here, '..', '..', '..', '..')]) {
      const pkg = path.join(base, 'package.json');
      const sidecar = path.join(base, 'dist', 'agentic-security.mjs.sha256');
      if (fs.existsSync(pkg) && fs.existsSync(sidecar)) {
        const version = JSON.parse(fs.readFileSync(pkg, 'utf8')).version;
        const digest = fs.readFileSync(sidecar, 'utf8').trim().split(/\s+/)[0];
        if (version && /^[0-9a-f]{64}$/i.test(digest)) return `${version}+${digest}`;
      }
    }
  } catch { /* unknown */ }
  return null;
}

export function cacheKey({ fingerprint, config, identity }) {
  if (!fingerprint?.content || !identity) return null;
  return sha(JSON.stringify({ c: fingerprint.content, l: fingerprint.lockfiles, cfg: config, id: identity }));
}

export function readCache(dir, key) {
  if (!key || !/^[0-9a-f]{64}$/.test(key)) return null;
  try {
    const doc = JSON.parse(fs.readFileSync(path.join(dir, `${key}.json`), 'utf8'));
    if (doc.key !== key) return null;
    const { digest, ...rest } = doc;
    return digest === sha(JSON.stringify(rest)) ? doc : null;
  } catch { return null; }
}

export function writeCache(dir, key, payload) {
  if (!key || !/^[0-9a-f]{64}$/.test(key)) return false;
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const body = { schema: 'agentic-security/fleet-scan-cache', version: 1, key, ...payload };
    const doc = { ...body, digest: sha(JSON.stringify(body)) };
    const tmp = path.join(dir, `.${key}.${process.pid}.tmp`);
    fs.writeFileSync(tmp, JSON.stringify(doc), { mode: 0o600 });
    fs.renameSync(tmp, path.join(dir, `${key}.json`));
    return true;
  } catch { return false; }
}
