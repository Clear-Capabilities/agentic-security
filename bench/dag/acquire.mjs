// Acquires the pinned real-code projects listed in manifest.json into
// bench/dag/.cache/<id>/ (gitignored) by fetching exactly the pinned commit.
// Never moves a pin: if a pinned commit cannot be fetched the project is
// reported unresolved, not substituted.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CACHE = path.join(HERE, '.cache');

function git(cwd, args, timeout = 600000) {
  return spawnSync('git', args, { cwd, encoding: 'utf8', timeout });
}

export function acquire(p) {
  const dir = path.join(CACHE, p.id);
  if (!p.commit) return { id: p.id, ok: false, reason: 'unresolved in manifest' };
  if (fs.existsSync(path.join(dir, '.git'))) {
    const head = git(dir, ['rev-parse', 'HEAD']).stdout.trim();
    if (head === p.commit) return { id: p.id, ok: true, dir, reused: true };
    fs.rmSync(dir, { recursive: true, force: true });
  }
  fs.mkdirSync(dir, { recursive: true });
  const steps = [
    ['init', '-q'],
    ['remote', 'add', 'origin', p.url],
    ...(p.sparse ? [['sparse-checkout', 'init', '--cone'], ['sparse-checkout', 'set', ...p.sparse]] : []),
    ['fetch', '-q', '--depth', '1', ...(p.sparse ? ['--filter=blob:none'] : []), 'origin', p.commit],
    ['checkout', '-q', 'FETCH_HEAD'],
  ];
  for (const s of steps) {
    const r = git(dir, s);
    if (r.status !== 0) return { id: p.id, ok: false, reason: `git ${s[0]} failed: ${(r.stderr || '').trim().slice(0, 200)}` };
  }
  const head = git(dir, ['rev-parse', 'HEAD']).stdout.trim();
  if (head !== p.commit) return { id: p.id, ok: false, reason: `HEAD ${head} != pinned ${p.commit}` };
  return { id: p.id, ok: true, dir };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));
  for (const p of manifest.projects) {
    const r = acquire(p);
    console.log(r.ok ? `ok   ${p.id}${r.reused ? ' (cached)' : ''}` : `FAIL ${p.id}: ${r.reason}`);
  }
}
