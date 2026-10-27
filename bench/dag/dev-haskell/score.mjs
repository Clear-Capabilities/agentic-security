// Scores a scan of the development set against labels.json. A labelled site counts as FLAGGED when the scan still
// reports a finding at the same project/file/line in the same stratum (stratum = vuln class as in sample.mjs).
// Precision = TP flagged / all flagged sites, over the sampled+labelled sites, per half. Sites in a scan that match no
// labelled site are listed as `unlabelled` (they are new, or they belong to the unsampled remainder).
// usage: node bench/dag/dev-haskell/score.mjs [<results dir>] [--json]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { wilson as sharedWilson } from '../../_lib/wilson.mjs';

const H = path.dirname(fileURLToPath(import.meta.url));
const arg = process.argv.slice(2).find((a) => !a.startsWith('--'));
const dir = arg ? path.resolve(arg) : path.join(H, 'results');
const asJson = process.argv.includes('--json');
const sampleDoc = JSON.parse(fs.readFileSync(path.join(H, 'sample.json'), 'utf8'));
const labels = JSON.parse(fs.readFileSync(path.join(H, 'labels.json'), 'utf8')).labels;
const stratumOf = (vuln) => (/^Path Traversal/.test(vuln) ? 'path-traversal' : vuln.replace(/^Unsafe boundary: .*/, 'unsafe-boundary'));

const now = new Map();      // site key -> finding
const populationNow = [];
let infoLowered = 0;
for (const f of fs.readdirSync(dir).sort()) {
  if (!f.endsWith('.json')) continue;
  const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  for (const r of j.haskell) {
    // a finding lowered to `info` is not a flagged site of the default scan (the dag bench drops info the same way); it is counted apart
    if (r.severity === 'info') { infoLowered++; continue; }
    populationNow.push({ project: j.id, ...r }); now.set(`${j.id}:${r.file}:${r.line}:${stratumOf(r.vuln)}`, r);
  }
}
// sampled population strata sizes (before) for extrapolation
const wilson = (k, n) => sharedWilson(k, n) || [null, null];
const out = { dir: path.relative(process.cwd(), dir), populationFlagged: populationNow.length, infoLowered, halves: {}, byStratum: {} };
const labelled = new Set();
for (const half of ['tuning', 'verification', 'all']) {
  let tp = 0, fp = 0, tpBefore = 0, fpBefore = 0;
  for (const l of Object.values(labels)) {
    if (half !== 'all' && l.half !== half) continue;
    const k = `${l.project}:${l.file}:${l.line}:${stratumOf(l.vuln)}`;
    labelled.add(k);
    if (l.label === 'TP') tpBefore++; else fpBefore++;
    if (now.has(k)) { if (l.label === 'TP') tp++; else fp++; }
  }
  const flagged = tp + fp;
  const [lo, hi] = wilson(tp, flagged);
  const [lb, hb] = wilson(tpBefore, tpBefore + fpBefore);
  out.halves[half] = { before: { flagged: tpBefore + fpBefore, tp: tpBefore, precision: tpBefore / (tpBefore + fpBefore), wilson95: [lb, hb] }, after: { flagged, tp, fp, precision: flagged ? tp / flagged : null, wilson95: [lo, hi] }, tpRetained: `${tp}/${tpBefore}` };
}
for (const l of Object.values(labels)) {
  const s = stratumOf(l.vuln); const e = (out.byStratum[s] ||= { labelled: 0, stillFlagged: 0, tpLabelled: 0, tpStillFlagged: 0 });
  e.labelled++; if (l.label === 'TP') e.tpLabelled++;
  if (now.has(`${l.project}:${l.file}:${l.line}:${s}`)) { e.stillFlagged++; if (l.label === 'TP') e.tpStillFlagged++; }
}
out.unlabelled = [...now.entries()].filter(([k]) => !labelled.has(k)).map(([k, r]) => `${k} ${r.vuln}`);
// census of the flagged sites after the fixes: the sampled ones plus the remainder labelled for completeness
{
  const rem = JSON.parse(fs.readFileSync(path.join(H, 'labels-remainder.json'), 'utf8')).labels;
  let tp = 0, flagged = 0, unknown = 0;
  for (const [k] of now) {
    const sampled = Object.values(labels).find((l) => `${l.project}:${l.file}:${l.line}:${stratumOf(l.vuln)}` === k);
    const l = sampled || rem[k];
    if (!l) { unknown++; continue; }
    flagged++; if (l.label === 'TP') tp++;
  }
  const [lo, hi] = wilson(tp, flagged);
  out.census = { flagged, tp, precision: flagged ? tp / flagged : null, wilson95: [lo, hi], unlabelled: unknown };
}
if (asJson) console.log(JSON.stringify(out, null, 1));
else {
  const f = (x) => (x == null ? 'n/a' : (100 * x).toFixed(1) + '%');
  console.log(`scan: ${out.dir}  population flagged (non-info): ${out.populationFlagged} (before: ${sampleDoc.population}); lowered to info: ${out.infoLowered}`);
  for (const [h, v] of Object.entries(out.halves)) console.log(`${h.padEnd(13)} before ${v.before.tp}/${v.before.flagged} = ${f(v.before.precision)} [${f(v.before.wilson95[0])}, ${f(v.before.wilson95[1])}]   after ${v.after.tp}/${v.after.flagged} = ${f(v.after.precision)} [${f(v.after.wilson95[0])}, ${f(v.after.wilson95[1])}]   TP retained ${v.tpRetained}`);
  for (const [s, v] of Object.entries(out.byStratum)) console.log(`  ${s.padEnd(60)} labelled ${v.labelled} still flagged ${v.stillFlagged}  (TP ${v.tpStillFlagged}/${v.tpLabelled})`);
  console.log(`census of all flagged sites after the fixes: ${out.census.tp}/${out.census.flagged} = ${f(out.census.precision)} [${f(out.census.wilson95[0])}, ${f(out.census.wilson95[1])}] (unlabelled: ${out.census.unlabelled})`);
  console.log(`unlabelled sites in this scan: ${out.unlabelled.length}  (unsampled remainder of the original population included)`);
}
