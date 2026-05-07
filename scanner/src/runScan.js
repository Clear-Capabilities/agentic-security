// Filesystem driver: reads a directory, builds the fileContents/depFileContents
// maps the engine expects, and invokes runFullScan.
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import fg from 'fast-glob';
import { runFullScan, shouldScan } from './engine.js';

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
  const entries = await fg('**/*', {
    cwd: root, dot: false, onlyFiles: true,
    ignore: [...DEFAULT_IGNORE, ...ignore], followSymbolicLinks: false,
    suppressErrors: true,
  });
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
    if (shouldScan(rel)) fileContents[rel] = content;
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
  let { fileContents, depFileContents } = await readTree(root, opts);

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

  const scan = await runFullScan({ fileContents, depFileContents, scanRoot: root }, opts.onProgress || (()=>{}));
  return {
    scan,
    meta: { scanId: cryptoUUID(), startedAt, durationMs: Date.now() - t0, root, mode: opts.changedSince ? 'incremental' : 'full' },
  };
}

export const scanPath = runScan;

function cryptoUUID(){
  return globalThis.crypto?.randomUUID?.() || `scan-${Date.now().toString(36)}`;
}
