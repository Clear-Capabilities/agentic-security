// Scope performance (PRD "Performance and reliability"): preview of a 10,000-file tree, and the growth added by 100,000 ignored generated files.
// Targets from the PRD: preview within 10 s, and no more than 10% growth from the ignored files. The PRD names a fixed 8-vCPU 16-GB runner; a
// run anywhere else reports its own machine and is not a measurement of that target.
//
// usage: node bench/scope-perf/runner.mjs [--files 10000] [--ignored 100000] [--runs 5] [--json]
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] ? Number(argv[i + 1]) : d; };
const FILES = opt('files', 10000); const IGNORED = opt('ignored', 100000); const RUNS = opt('runs', 5);
const { buildScanInventory } = await import(pathToFileURL(path.join(HERE, '..', '..', 'scanner', 'src', 'scope', 'inventory.js')).href);

function populate(root, n, prefix, mk) {
  const perDir = 200;
  for (let i = 0; i < n; i++) {
    const dir = path.join(root, prefix, `d${Math.floor(i / perDir)}`);
    if (i % perDir === 0) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `f${i}.${mk}`), `x${i}\n`);
  }
}
const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const time = () => { const t = process.hrtime.bigint(); const r = buildScanInventory(root); return { ms: Number(process.hrtime.bigint() - t) / 1e6, r }; };

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-scope-perf-'));
try {
  cp.spawnSync('git', ['init', '-q'], { cwd: root });
  fs.writeFileSync(path.join(root, '.gitignore'), 'buck-out/\n');
  populate(root, FILES, 'src', 'hs');
  cp.spawnSync('git', ['add', '-A'], { cwd: root });
  const base = Array.from({ length: RUNS }, () => time());
  const baseMs = base.map((b) => b.ms);
  if (base[0].r.included.length < FILES) throw new Error(`fixture selected only ${base[0].r.included.length} of ${FILES} files`);
  populate(root, IGNORED, 'buck-out', 'o');
  const withIgn = Array.from({ length: RUNS }, () => time());
  const ignMs = withIgn.map((b) => b.ms);
  const included = withIgn[0].r.included.length;
  const growth = (median(ignMs) - median(baseMs)) / median(baseMs);
  const out = {
    machine: { cpus: os.cpus().length, memGB: Math.round(os.totalmem() / 2 ** 30), node: process.version, note: 'the PRD target machine is 8 vCPU / 16 GB' },
    files: FILES, ignored: IGNORED, runs: RUNS,
    previewMs: { cold: Math.round(baseMs[0]), medianWarm: Math.round(median(baseMs.slice(1))), all: baseMs.map(Math.round) },
    withIgnoredMs: { cold: Math.round(ignMs[0]), median: Math.round(median(ignMs)), all: ignMs.map(Math.round) },
    growthPercent: Math.round(growth * 1000) / 10, included,
    targets: { previewUnder10s: Math.max(...baseMs) < 10000, growthUnder10Percent: growth <= 0.10 },
  };
  if (argv.includes('--json')) console.log(JSON.stringify(out, null, 1));
  else {
    console.log(`machine: ${out.machine.cpus} cpus, ${out.machine.memGB} GB (${out.machine.note})`);
    console.log(`preview of ${FILES} files: cold ${out.previewMs.cold} ms, warm median ${out.previewMs.medianWarm} ms  (target < 10000)`);
    console.log(`with ${IGNORED} ignored generated files: median ${out.withIgnoredMs.median} ms, growth ${out.growthPercent}%  (target <= 10%)`);
  }
  process.exitCode = out.targets.previewUnder10s && out.targets.growthUnder10Percent ? 0 : 1;
} finally { fs.rmSync(root, { recursive: true, force: true }); }
