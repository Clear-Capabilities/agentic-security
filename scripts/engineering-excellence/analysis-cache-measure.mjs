#!/usr/bin/env node
// Measures the cross-scan analysis cache (E6-04): the same scan cold (no cache), warm with nothing changed, and warm after 1 and after 10 files changed,
// N times each, over one corpus. Reports wall and CPU time, how many file results were reused, and checks the warm result equals the cold result for
// the same tree. Writes docs/engineering-excellence/data/analysis-cache.json.
//
//   node scripts/engineering-excellence/analysis-cache-measure.mjs [--dir <path>] [--runs 5] [--deep]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
const dir = path.resolve(opt('--dir', path.join(ROOT, 'scanner', 'src', 'sast')));
const runs = Number(opt('--runs', '5'));
const deep = argv.includes('--deep');

const { runFullScan } = await import(path.join(ROOT, 'scanner', 'src', 'engine.js'));
const { setStateWritesEnabled } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'state-dir.js'));
const { canonicalizeScan } = await import(path.join(ROOT, 'scanner', 'src', 'pipeline', 'canonical-output.js'));
setStateWritesEnabled(true);

const base = {};
(function walk(p, rel) {
  for (const e of fs.readdirSync(p, { withFileTypes: true })) {
    if (['node_modules', '.git', 'dist', '.agentic-security'].includes(e.name)) continue;
    const r = path.join(rel, e.name);
    if (e.isDirectory()) walk(path.join(p, e.name), r);
    else if (/\.(js|mjs|ts|tsx|jsx|py)$/.test(e.name) && fs.statSync(path.join(p, e.name)).size < 300_000) base[r] = fs.readFileSync(path.join(p, e.name), 'utf8');
  }
})(dir, '');
const names = Object.keys(base).sort();
const changed = (n) => { const o = { ...base }; for (const f of names.slice(0, n)) o[f] = base[f] + `\n// edited ${f.length}\nvoid 0;\n`; return o; };

const project = () => { const b = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-cache-')); fs.writeFileSync(path.join(b, 'package.json'), '{}'); return b; };
async function timed(root, files, cache) {
  if (cache) process.env.AGENTIC_SECURITY_ANALYSIS_CACHE = '1'; else delete process.env.AGENTIC_SECURITY_ANALYSIS_CACHE;
  const c0 = process.cpuUsage(); const t0 = performance.now();
  const s = await runFullScan({ fileContents: files, scanRoot: root, deep });
  const c = process.cpuUsage(c0);
  delete process.env.AGENTIC_SECURITY_ANALYSIS_CACHE;
  return { wallMs: performance.now() - t0, cpuMs: (c.user + c.system) / 1000, resumed: s._scanMeta.checkpoint.resumed, digest: canonicalizeScan(s).digest };
}
const med = (a) => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };
const row = (rs) => ({ wallMs: { median: Math.round(med(rs.map((r) => r.wallMs))), min: Math.round(Math.min(...rs.map((r) => r.wallMs))), max: Math.round(Math.max(...rs.map((r) => r.wallMs))) }, cpuMs: { median: Math.round(med(rs.map((r) => r.cpuMs))) }, resumedFiles: med(rs.map((r) => r.resumed)) });

await timed(project(), base, false); // warm the JIT and module graph
const arms = { cold: [], warmUnchanged: [], warmOneFileChanged: [], warmTenFilesChanged: [] };
let equal = true;
for (let i = 0; i < runs; i++) {
  const root = project(); const coldRoot = project();
  await timed(root, base, true); // populate
  arms.cold.push(await timed(coldRoot, base, false));
  const w0 = await timed(root, base, true); arms.warmUnchanged.push(w0);
  const w1 = await timed(root, changed(1), true); arms.warmOneFileChanged.push(w1);
  const c1 = await timed(project(), changed(1), false);
  const w10 = await timed(root, changed(10), true); arms.warmTenFilesChanged.push(w10);
  const c10 = await timed(project(), changed(10), false);
  equal = equal && w0.digest === arms.cold[i].digest && w1.digest === c1.digest && w10.digest === c10.digest;
  for (const r of [root, coldRoot]) fs.rmSync(r, { recursive: true, force: true });
}
const pct = (a, b) => +(100 * (1 - med(a.map((r) => r.wallMs)) / med(b.map((r) => r.wallMs)))).toFixed(1);
const result = {
  schema: 'agentic-security/analysis-cache-measurement@1',
  corpus: { dir: path.relative(ROOT, dir), files: names.length, chars: Object.values(base).reduce((a, s) => a + s.length, 0), deepAnalysis: deep },
  hardware: { os: `${os.platform()} ${os.release()} ${os.arch()}`, cpus: os.cpus().length, memoryGb: Math.round(os.totalmem() / 2 ** 30), node: process.version },
  runsPerArm: runs,
  arms: Object.fromEntries(Object.entries(arms).map(([k, v]) => [k, row(v)])),
  wallReductionPct: { warmUnchanged: pct(arms.warmUnchanged, arms.cold), warmOneFileChanged: pct(arms.warmOneFileChanged, arms.cold), warmTenFilesChanged: pct(arms.warmTenFilesChanged, arms.cold) },
  warmEqualsColdForTheSameTree: equal,
  caveats: ['measured on a machine that was also running other work', 'only the per-file detector stage is cached; cross-file passes, deep analysis and annotation run on every scan, which bounds the gain', 'each arm is compared with a cold scan of the same tree, and the canonical findings were checked equal'],
};
fs.mkdirSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data', deep ? 'analysis-cache-deep.json' : 'analysis-cache.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
process.exit(equal ? 0 : 1);
