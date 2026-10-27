// Scans every project of a manifest (one child process each, in parallel) with scan.mjs.
// usage: node bench/dag/dev-haskell/scan-all.mjs [--set=dev|fresh] [--out=<dir>] [--only=a,b] [--engine=<dir>]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (n) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.slice(n.length + 3) : null; };
const set = arg('set') || 'dev';
const manifest = JSON.parse(fs.readFileSync(path.join(HERE, set === 'fresh' ? 'manifest-fresh.json' : 'manifest.json'), 'utf8'));
const pass = ['out', 'engine'].map((n) => (arg(n) ? `--${n}=${arg(n)}` : null)).filter(Boolean);
const ids = arg('only') ? arg('only').split(',') : manifest.projects.map((p) => p.id);
await Promise.all(ids.map((id) => new Promise((resolve) => {
  const c = spawn(process.execPath, ['--max-old-space-size=8192', path.join(HERE, 'scan.mjs'), id, ...pass], { stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
  let s = '';
  c.stdout.on('data', (d) => { s += d; });
  c.stderr.on('data', (d) => { s += d; });
  c.on('close', (code) => { console.log(`[exit ${code}] ${s.trim().split('\n').slice(-3).join(' | ')}`); resolve(); });
})));
