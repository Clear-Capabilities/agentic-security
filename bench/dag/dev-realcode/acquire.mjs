// Acquires the Python or TypeScript real-code development set into bench/dag/dev-realcode/.cache/<id>/ (gitignored) by fetching exactly
// the pinned commit of manifest-<set>.json. Never moves a pin and never substitutes a project: a pin that cannot be fetched is reported.
// usage: node bench/dag/dev-realcode/acquire.mjs --set=python|typescript
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, '.cache');
const SET = (process.argv.find((a) => a.startsWith('--set=')) || '--set=python').slice(6);
const manifest = JSON.parse(fs.readFileSync(path.join(HERE, `manifest-${SET}.json`), 'utf8'));
const git = (cwd, args) => spawnSync('git', args, { cwd, encoding: 'utf8', timeout: 1800000 });
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
