//
// Which files DCI analyses, and how they are read. Reading goes through `readRepoFile`, so a symlink, a file that
// resolves outside the repository, or an oversized file is skipped with a counted reason, never followed.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { listFiles } from '../util/glob.js';
import { STATE_DIR_NAME } from '../posture/state-dir.js';
import { readRepoFile, snapshotHashOf, normalizeText, safeRelPath } from './canonical.js';

export const SOURCE_EXTS = /\.(?:js|jsx|mjs|cjs|ts|tsx|py|java|cs|kt|go|php|rb|rs|c|cc|cpp|h|hpp|l?hs|nix)$/i;
export const IGNORE_GLOBS = ['node_modules/**', '.git/**', 'dist/**', 'build/**', 'vendor/**', '**/.agentic-security/**', 'dist-newstyle/**', '.stack-work/**', '.direnv/**', 'coverage/**', '**/*.min.js'];

/** Read the analysable source set. Returns { ok, fileContents, skipped, snapshotHash } or { ok:false, reason }. */
export async function readSnapshot(root, { maxFiles = 3000 } = {}) {
  let rootReal;
  try { rootReal = fs.realpathSync(root); } catch { return { ok: false, reason: 'root-not-found' }; }
  const rels = (await listFiles(rootReal, { ignore: IGNORE_GLOBS })).filter(f => SOURCE_EXTS.test(f)).sort();
  if (rels.length > maxFiles) return { ok: false, reason: 'too-many-files', count: rels.length, limit: maxFiles };
  const fileContents = {};
  const skipped = [];
  for (const rel of rels) {
    const r = readRepoFile(rootReal, rel);
    if (r.ok) fileContents[rel] = r.text;
    else skipped.push({ file: rel, reason: r.reason });
  }
  for (const l of findSymlinks(rootReal)) skipped.push({ file: l, reason: 'symlink' });
  skipped.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  return { ok: true, rootReal, fileContents, skipped, snapshotHash: snapshotHashOf(fileContents) };
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'vendor', STATE_DIR_NAME, 'dist-newstyle', '.stack-work', '.direnv', 'coverage']);

/** Symlinked source files and directories (never followed), so they are counted as skipped instead of vanishing. */
function findSymlinks(rootReal, limit = 5000) {
  const found = [];
  let seen = 0;
  const walk = (abs, rel) => {
    let entries;
    try { entries = fs.readdirSync(abs, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (++seen > limit) return;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { if (e.name.indexOf('.') === -1 || SOURCE_EXTS.test(e.name)) found.push(r); continue; }
      if (e.isDirectory() && !SKIP_DIRS.has(e.name)) walk(path.join(abs, e.name), r);
    }
  };
  walk(rootReal, '');
  return found;
}

/**
 * Read the analysable source set as it was at a git ref, without touching the working tree. `ref` is passed to git as a
 * single argv element after `--end-of-options`-style validation, never through a shell. Returns the same shape as
 * `readSnapshot`, or { ok:false, reason }.
 */
export function readGitSnapshot(root, ref, { maxFiles = 3000 } = {}) {
  if (typeof ref !== 'string' || !/^[A-Za-z0-9._\/~^@{}:-]{1,200}$/.test(ref) || ref.startsWith('-')) return { ok: false, reason: 'bad-ref' };
  let rootReal;
  try { rootReal = fs.realpathSync(root); } catch { return { ok: false, reason: 'root-not-found' }; }
  const git = (args, max = 64 * 1024 * 1024) => execFileSync('git', ['-C', rootReal, ...args], { encoding: 'utf8', timeout: 30000, maxBuffer: max, stdio: ['ignore', 'pipe', 'ignore'] });
  let commit;
  try { commit = git(['rev-parse', '--verify', `${ref}^{commit}`]).trim(); } catch { return { ok: false, reason: 'unknown-ref' }; }
  let names;
  try { names = git(['ls-tree', '-r', '--name-only', '-z', commit]).split('\0').filter(Boolean); } catch { return { ok: false, reason: 'ls-tree-failed' }; }
  const ignore = IGNORE_GLOBS.map(g => new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*\//g, '(?:.*/)?').replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*') + '$'));
  const rels = names.filter(f => SOURCE_EXTS.test(f) && safeRelPath(f) === f && !ignore.some(re => re.test(f))).sort();
  if (rels.length > maxFiles) return { ok: false, reason: 'too-many-files', count: rels.length, limit: maxFiles };
  const fileContents = {};
  const skipped = [];
  for (const rel of rels) {
    try {
      const mode = git(['ls-tree', commit, '--', rel]).split(' ')[0];
      if (mode === '120000' || mode === '160000') { skipped.push({ file: rel, reason: 'symlink-or-submodule' }); continue; }
      const text = git(['show', `${commit}:${rel}`], 2 * 1024 * 1024);
      fileContents[rel] = normalizeText(text);
    } catch { skipped.push({ file: rel, reason: 'unreadable-at-ref' }); }
  }
  return { ok: true, rootReal, fileContents, skipped, snapshotHash: snapshotHashOf(fileContents), commit };
}
