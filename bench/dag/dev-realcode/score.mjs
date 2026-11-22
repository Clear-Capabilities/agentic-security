// Scores a scan of a set against labels-<set>.json. A labelled site counts as FLAGGED when the scan still reports a non-info finding at the
// same project/file/line in the same stratum. Precision = TP flagged / all flagged labelled sites, per half (Wilson 95%).
// usage: node bench/dag/dev-realcode/score.mjs --set=python|typescript [--dir=<results dir>] [--json]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { wilson as sharedWilson } from '../../_lib/wilson.mjs';
import { stratumOf } from './lib.mjs';

const H = path.dirname(fileURLToPath(import.meta.url));
const arg = (n) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.slice(n.length + 3) : null; };
const set = arg('set') || 'python';
const dir = arg('dir') ? path.resolve(arg('dir')) : path.join(H, 'results', set);
const asJson = process.argv.includes('--json');
export function scoreSet(setName, resultsDir) {
  const labels = JSON.parse(fs.readFileSync(path.join(H, `labels-${setName}.json`), 'utf8')).labels;
  const now = new Map();
  let population = 0, infoLowered = 0;
  for (const f of fs.readdirSync(resultsDir).sort()) {
    if (!f.endsWith('.json')) continue;
    const j = JSON.parse(fs.readFileSync(path.join(resultsDir, f), 'utf8'));
    for (const r of j.findings) { if (r.severity === 'info') { infoLowered++; continue; } population++; now.set(`${j.id}:${r.file}:${r.line}:${stratumOf(r.vuln, r.cwe)}`, r); }
  }
  const wilson = (k, n) => sharedWilson(k, n) || [null, null];
  const out = { set: setName, populationFlagged: population, infoLowered, halves: {}, byStratum: {}, sites: [] };
  for (const half of ['tuning', 'verification', 'all']) {
    let tp = 0, fp = 0, tpL = 0, fpL = 0;
    for (const l of Object.values(labels)) {
      if (half !== 'all' && l.half !== half) continue;
      if (l.label === 'TP') tpL++; else fpL++;
      if (now.has(l.key)) { if (l.label === 'TP') tp++; else fp++; }
    }
    const flagged = tp + fp;
    out.halves[half] = { labelled: tpL + fpL, tpLabelled: tpL, flagged, tp, fp, precision: flagged ? tp / flagged : null, wilson95: wilson(tp, flagged), tpLost: tpL - tp };
  }
  for (const l of Object.values(labels)) {
    const e = (out.byStratum[l.stratum] ||= { labelled: 0, stillFlagged: 0, tpLabelled: 0, tpStillFlagged: 0 });
    e.labelled++; if (l.label === 'TP') e.tpLabelled++;
    if (now.has(l.key)) { e.stillFlagged++; if (l.label === 'TP') e.tpStillFlagged++; }
    out.sites.push({ key: l.key, label: l.label, flagged: now.has(l.key) });
  }
  return out;
}
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1].endsWith('score.mjs')) {
  const out = scoreSet(set, dir);
  if (asJson) console.log(JSON.stringify(out, null, 1));
  else {
    const f = (x) => (x == null ? 'n/a' : (100 * x).toFixed(1) + '%');
    console.log(`${set}: population flagged (non-info) ${out.populationFlagged}, lowered to info ${out.infoLowered}`);
    for (const [h, v] of Object.entries(out.halves)) console.log(`  ${h.padEnd(13)} ${v.tp}/${v.flagged} = ${f(v.precision)} [${f(v.wilson95[0])}, ${f(v.wilson95[1])}]  (labelled ${v.labelled}, TP labelled ${v.tpLabelled}, TP no longer flagged ${v.tpLost})`);
    for (const [s, v] of Object.entries(out.byStratum)) console.log(`    ${s.padEnd(50)} labelled ${v.labelled} still flagged ${v.stillFlagged} (TP ${v.tpStillFlagged}/${v.tpLabelled})`);
  }
}
