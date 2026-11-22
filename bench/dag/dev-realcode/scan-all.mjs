// Scans every project of a set (one child process each, two at a time: the Python helper subprocess degrades under load) with scan.mjs.
// usage: node bench/dag/dev-realcode/scan-all.mjs --set=python|typescript [--out=<dir>] [--only=a,b] [--engine=<dir>] [--jobs=N]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (n) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.slice(n.length + 3) : null; };
const set = arg('set') || 'python';
const manifest = JSON.parse(fs.readFileSync(path.join(HERE, `manifest-${set}.json`), 'utf8'));
const pass = ['out', 'engine'].map((n) => (arg(n) ? `--${n}=${arg(n)}` : null)).filter(Boolean);
const ids = arg('only') ? arg('only').split(',') : manifest.projects.map((p) => p.id);
const jobs = Number(arg('jobs') || 2);
const queue = [...ids];
const one = (id) => new Promise((resolve) => {
  const c = spawn(process.execPath, ['--max-old-space-size=8192', path.join(HERE, 'scan.mjs'), set, id, ...pass], { stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
  let s = '';
  c.stdout.on('data', (d) => { s += d; });
  c.stderr.on('data', (d) => { s += d; });
  c.on('close', (code) => { console.log(`[exit ${code}] ${s.trim().split('\n').slice(-2).join(' | ')}`); resolve(); });
});
await Promise.all(Array.from({ length: jobs }, async () => { while (queue.length) await one(queue.shift()); }));
