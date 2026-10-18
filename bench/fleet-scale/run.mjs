#!/usr/bin/env node
// Fleet scan wall-clock scaling, measured (PRD 4 success metric: "near-linear scaling"). Generates N tiny synthetic repositories in a
// temporary directory, scans them with 1..K workers through the real CLI, and prints wall time, speedup and parallel efficiency.
//
//   node bench/fleet-scale/run.mjs [--repos 24] [--workers 1,2,4,8] [--cores-note]
//
// This measures THIS machine on THIS synthetic workload (each repository is a few small JavaScript files), cache off. It is evidence
// about the job fabric's overhead and concurrency, not a promise about real repositories, whose scan time dominates and varies.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../scanner/bin/agentic-security.js');
const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i === -1 ? d : process.argv[i + 1]; };
const N = Number(arg('repos', 24));
const WORKERS = String(arg('workers', '1,2,4,8')).split(',').map(Number);

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-scale-'));
fs.mkdirSync(path.join(root, '.git'));
const lines = ['organization: scale', 'repositories:'];
for (let i = 0; i < N; i++) {
  const id = `r${String(i).padStart(3, '0')}`; const d = path.join(root, 'org', id); fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name: `@s/${id}`, version: '1.0.0', dependencies: {} }));
  for (let f = 0; f < 6; f++) fs.writeFileSync(path.join(d, `m${f}.js`), `const { exec } = require('child_process');\nmodule.exports = (req) => { exec('ls ' + req.query.p${f}); return ${i + f}; };\n`);
  lines.push(`  - { id: ${id}, path: ./org/${id}, required: true }`);
}
fs.writeFileSync(path.join(root, 'fleet.yaml'), `${lines.join('\n')}\n`);

const rows = [];
for (const w of WORKERS) {
  fs.rmSync(path.join(root, '.agentic-security'), { recursive: true, force: true });
  const t0 = process.hrtime.bigint();
  const r = spawnSync(process.execPath, [CLI, 'fleet', 'scan', 'fleet.yaml', '--workers', String(w), '--no-cache', '--no-discover', '--json'], { cwd: root, encoding: 'utf8', timeout: 3_600_000, maxBuffer: 256 * 1024 * 1024 });
  const secs = Number(process.hrtime.bigint() - t0) / 1e9;
  let complete = null; try { complete = JSON.parse(r.stdout).health.counts.complete; } catch { /* reported below */ }
  rows.push({ workers: w, seconds: Number(secs.toFixed(2)), complete, exit: r.status });
}
const base = rows[0].seconds;
console.log(`machine: ${os.cpus().length} logical cores, ${os.cpus()[0].model.trim()}, node ${process.version}; ${N} repositories x 6 files, cache off`);
console.log('workers  seconds  speedup  efficiency  complete');
for (const r of rows) console.log(`${String(r.workers).padStart(7)}  ${String(r.seconds).padStart(7)}  ${(base / r.seconds).toFixed(2).padStart(7)}  ${((base / r.seconds / r.workers) * 100).toFixed(0).padStart(9)}%  ${r.complete}/${N}${r.exit === 0 ? '' : ` (exit ${r.exit})`}`);
fs.rmSync(root, { recursive: true, force: true });
