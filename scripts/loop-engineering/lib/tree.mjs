// Source-tree digests used for evidence freshness. The file list comes from git
// (tracked + untracked-but-not-ignored), so the controller's own state
// directory, node_modules and build caches are excluded by .gitignore and never
// perturb a digest.
import { execFileSync } from 'node:child_process';
import { statSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { sha256, atomicWriteJson, readJson } from './util.mjs';

export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') { re += '.*'; i++; if (glob[i + 1] === '/') i++; } else re += '[^/]*';
    } else if ('\\^$+?.()|{}[]'.includes(c)) re += '\\' + c;
    else re += c;
  }
  return new RegExp(`^${re}$`);
}

// Outputs DERIVED from the evidence itself. Digesting them would make verification circular: writing "N requirements verified" would
// invalidate the evidence that produced N. Nothing else is exempt, and neither can change what any requirement verified.
export const DERIVED_FILES = new Set(['docs/completion-status.json']);
const DERIVED_BLOCK = /<!-- generated:completion-status:start -->[\s\S]*?<!-- generated:completion-status:end -->/;
export function digestBytes(rel, buf) {
  return rel === 'README.md' ? Buffer.from(buf.toString('utf8').replace(DERIVED_BLOCK, '<!-- completion-status -->')) : buf;
}

export function listRepoFiles(repoRoot) {
  const out = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: repoRoot, maxBuffer: 256 * 1024 * 1024, timeout: 60000 });
  const files = out.toString('utf8').split('\0').filter(Boolean);
  // Defence in depth: never digest controller state even if .gitignore is edited.
  return [...new Set(files)].filter((f) => !f.startsWith('.loop-engineering/') && !f.startsWith('.git/') && !DERIVED_FILES.has(f)).sort();
}

export class TreeIndex {
  constructor(repoRoot, cachePath = null) {
    this.repoRoot = repoRoot;
    this.cachePath = cachePath;
    this.cache = cachePath ? (readJson(cachePath, {}) || {}) : {};
    this.files = new Map(); // path -> sha
    this.builtAt = 0;
  }
  build() {
    const list = listRepoFiles(this.repoRoot);
    const next = new Map();
    const cache = this.cache;
    const newCache = {};
    for (const f of list) {
      const abs = join(this.repoRoot, f);
      let st;
      try { st = statSync(abs); } catch { continue; }       // deleted since ls-files
      if (!st.isFile()) continue;
      const key = `${st.mtimeMs}:${st.size}:${st.ino}`;
      const hit = cache[f];
      let sha;
      if (hit && hit.key === key) sha = hit.sha;
      else { try { sha = sha256(digestBytes(f, readFileSync(abs))); } catch { continue; } }
      newCache[f] = { key, sha };
      next.set(f, sha);
    }
    this.files = next;
    this.cache = newCache;
    this.builtAt = Date.now();
    if (this.cachePath) { try { atomicWriteJson(this.cachePath, newCache); } catch { /* cache is an optimisation only */ } }
    return this;
  }
  digestFor(globs) {
    const res = globs.map(globToRegExp);
    const h = [];
    for (const [f, sha] of this.files) if (res.some((r) => r.test(f))) h.push(`${f}\0${sha}`);
    h.sort();
    return { digest: sha256(h.join('\n')), fileCount: h.length };
  }
  wholeTree() { return this.digestFor(['**']); }
  has(path) { return this.files.has(path) || existsSync(join(this.repoRoot, path)); }
}
