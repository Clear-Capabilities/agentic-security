// Acquires the Haskell DEVELOPMENT set (default) or the FRESH verification set (--set=fresh) for the default-scan precision work.
// Shallow clones into bench/dag/dev-haskell/.cache/<id>/ (gitignored). The first run resolves each URL to a commit and writes the manifest
// (manifest.json, or manifest-fresh.json); later runs fetch exactly the pinned commit. Never substitutes a project.
// The fresh set is acquired AFTER the engine changes are final and is scanned once; nothing was tuned against it.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(HERE, '.cache');
const SET = (process.argv.find((a) => a.startsWith('--set=')) || '--set=dev').slice(6);
const MANIFEST = path.join(HERE, SET === 'fresh' ? 'manifest-fresh.json' : 'manifest.json');

const SEEDS = {
  dev: [
    { id: 'gitit', url: 'https://github.com/jgm/gitit' },
    { id: 'hackage-server', url: 'https://github.com/haskell/hackage-server' },
    { id: 'stackage-server', url: 'https://github.com/commercialhaskell/stackage-server' },
    { id: 'ghcup-hs', url: 'https://github.com/haskell/ghcup-hs' },
    { id: 'cabal2nix', url: 'https://github.com/NixOS/cabal2nix' },
    { id: 'stack', url: 'https://github.com/commercialhaskell/stack' },
    { id: 'xmonad-contrib', url: 'https://github.com/xmonad/xmonad-contrib' },
    { id: 'pandoc', url: 'https://github.com/jgm/pandoc' },
  ],
  fresh: [
    { id: 'ihp', url: 'https://github.com/digitallyinduced/ihp' },
    { id: 'dhall-haskell', url: 'https://github.com/dhall-lang/dhall-haskell' },
    { id: 'hlint', url: 'https://github.com/ndmitchell/hlint' },
    { id: 'summoner', url: 'https://github.com/kowainik/summoner' },
    { id: 'scotty', url: 'https://github.com/scotty-web/scotty' },
    { id: 'ormolu', url: 'https://github.com/tweag/ormolu' },
  ],
};

const git = (cwd, args) => spawnSync('git', args, { cwd, encoding: 'utf8', timeout: 900000 });

const existing = fs.existsSync(MANIFEST) ? JSON.parse(fs.readFileSync(MANIFEST, 'utf8')) : { projects: SEEDS[SET] };
const out = [];
for (const p of existing.projects) {
  const dir = path.join(CACHE, p.id);
  fs.mkdirSync(CACHE, { recursive: true });
  if (!fs.existsSync(path.join(dir, '.git'))) {
    fs.mkdirSync(dir, { recursive: true });
    git(dir, ['init', '-q']);
    git(dir, ['remote', 'add', 'origin', p.url]);
    const ref = p.commit || 'HEAD';
    const f = git(dir, ['fetch', '-q', '--depth', '1', 'origin', ref]);
    if (f.status !== 0) { console.log(`FAIL ${p.id}: ${(f.stderr || '').slice(0, 200)}`); out.push(p); continue; }
    git(dir, ['checkout', '-q', 'FETCH_HEAD']);
  }
  const head = git(dir, ['rev-parse', 'HEAD']).stdout.trim();
  if (p.commit && head !== p.commit) { console.log(`FAIL ${p.id}: HEAD ${head} != pin ${p.commit}`); out.push(p); continue; }
  out.push({ ...p, commit: head });
  console.log(`ok ${p.id} ${head}`);
}
fs.writeFileSync(MANIFEST, JSON.stringify({ projects: out }, null, 2) + '\n');
