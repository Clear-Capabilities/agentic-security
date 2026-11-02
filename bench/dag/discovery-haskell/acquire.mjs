// Acquires the Haskell DISCOVERY set: shallow clones of the projects in manifest.json at their pinned commits (a `branch` entry is fetched
// at that commit as well) into bench/dag/discovery-haskell/.cache/<id>/ (gitignored). Never substitutes a project; a pin that cannot be
// fetched is reported, not replaced. usage: node bench/dag/discovery-haskell/acquire.mjs
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, '.cache');
const manifest = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));
const git = (cwd, args) => spawnSync('git', args, { cwd, encoding: 'utf8', timeout: 900000 });

let failed = 0;
for (const p of manifest.projects) {
  const dir = path.join(CACHE, p.id);
  fs.mkdirSync(CACHE, { recursive: true });
  if (!fs.existsSync(path.join(dir, '.git'))) {
    fs.mkdirSync(dir, { recursive: true });
    git(dir, ['init', '-q']);
    git(dir, ['remote', 'add', 'origin', p.url]);
    const f = git(dir, ['fetch', '-q', '--depth', '1', 'origin', p.commit]);
    if (f.status !== 0) { console.log(`FAIL ${p.id}: ${(f.stderr || '').slice(0, 200)}`); failed++; continue; }
    git(dir, ['checkout', '-q', 'FETCH_HEAD']);
  }
  const head = git(dir, ['rev-parse', 'HEAD']).stdout.trim();
  if (head !== p.commit) { console.log(`FAIL ${p.id}: HEAD ${head} != pin ${p.commit}`); failed++; continue; }
  console.log(`ok ${p.id} ${head}`);
}
process.exit(failed ? 1 : 0);
