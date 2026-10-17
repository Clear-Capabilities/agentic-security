#!/usr/bin/env node
// Measures the effect of the shared source-text memo (E6-03): the same deep scan with the memo on and off, alternating, N times each, over one corpus.
// Reports CPU time (user + system, which is less sensitive to a busy machine than wall time), wall time, peak resident memory of the process, and the
// memo's hit and miss counts. Also checks that the canonical findings are identical with and without it. Writes docs/engineering-excellence/data/parse-reuse.json.
//
//   node scripts/engineering-excellence/parse-reuse-measure.mjs [--dir <path>] [--runs 5]
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

const { runFullScan } = await import(path.join(ROOT, 'scanner', 'src', 'engine.js'));
const { setStateWritesEnabled } = await import(path.join(ROOT, 'scanner', 'src', 'posture', 'state-dir.js'));
const { blankComments } = await import(path.join(ROOT, 'scanner', 'src', 'sast', '_comment-strip.js'));
const { canonicalizeScan } = await import(path.join(ROOT, 'scanner', 'src', 'pipeline', 'canonical-output.js'));
setStateWritesEnabled(false);

const files = {};
(function walk(p, rel) {
  for (const e of fs.readdirSync(p, { withFileTypes: true })) {
    if (['node_modules', '.git', 'dist', '.agentic-security'].includes(e.name)) continue;
    const r = path.join(rel, e.name);
    if (e.isDirectory()) walk(path.join(p, e.name), r);
    else if (/\.(js|mjs|ts|tsx|jsx|py)$/.test(e.name) && fs.statSync(path.join(p, e.name)).size < 300_000) files[r] = fs.readFileSync(path.join(p, e.name), 'utf8');
  }
})(dir, '');

async function once(memoOn) {
  if (memoOn) delete process.env.AGENTIC_SECURITY_NO_STRING_MEMO; else process.env.AGENTIC_SECURITY_NO_STRING_MEMO = '1';
  blankComments.reset();
  if (global.gc) global.gc();
  const c0 = process.cpuUsage(); const t0 = performance.now();
  const scan = await runFullScan({ fileContents: files, scanRoot: null, deep: true });
  const c = process.cpuUsage(c0);
  return { cpuMs: (c.user + c.system) / 1000, wallMs: performance.now() - t0, digest: canonicalizeScan(scan).digest, stats: blankComments.stats() };
}
await once(true); await once(false); // warm both paths (module load, JIT)
const on = []; const off = [];
for (let i = 0; i < runs; i++) { if (i % 2 === 0) { on.push(await once(true)); off.push(await once(false)); } else { off.push(await once(false)); on.push(await once(true)); } }
delete process.env.AGENTIC_SECURITY_NO_STRING_MEMO;
const med = (a) => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };
const sum = (rs, k) => ({ median: Math.round(med(rs.map((r) => r[k]))), min: Math.round(Math.min(...rs.map((r) => r[k]))), max: Math.round(Math.max(...rs.map((r) => r[k]))) });
const result = {
  schema: 'agentic-security/parse-reuse-measurement@1',
  corpus: { dir: path.relative(ROOT, dir), files: Object.keys(files).length, chars: Object.values(files).reduce((a, s) => a + s.length, 0) },
  hardware: { os: `${os.platform()} ${os.release()} ${os.arch()}`, cpus: os.cpus().length, memoryGb: Math.round(os.totalmem() / 2 ** 30), node: process.version },
  runsPerArm: runs, order: 'alternating, memo-on first on even runs',
  memoOn: { cpuMs: sum(on, 'cpuMs'), wallMs: sum(on, 'wallMs'), memoStats: on[on.length - 1].stats },
  memoOff: { cpuMs: sum(off, 'cpuMs'), wallMs: sum(off, 'wallMs') },
  cpuReductionPct: +(100 * (1 - med(on.map((r) => r.cpuMs)) / med(off.map((r) => r.cpuMs)))).toFixed(1),
  wallReductionPct: +(100 * (1 - med(on.map((r) => r.wallMs)) / med(off.map((r) => r.wallMs)))).toFixed(1),
  peakRssMb: Math.round(process.memoryUsage().rss / 1e6),
  canonicalFindingsIdentical: new Set([...on, ...off].map((r) => r.digest)).size === 1,
  digest: on[0].digest,
  caveats: ['wall and CPU times were measured on a machine that was also running other work; the alternating order and the medians reduce but do not remove that', 'peak RSS is the process high-water mark across both arms, not a per-arm figure'],
};
fs.mkdirSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'docs', 'engineering-excellence', 'data', 'parse-reuse.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
process.exit(result.canonicalFindingsIdentical ? 0 : 1);
