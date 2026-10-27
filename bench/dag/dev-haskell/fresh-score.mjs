// Scores the FRESH held-out set from fresh-labels.json: precision before (the original engine) and after (the engine with the fixes), with Wilson
// 95% intervals, under three readings of "flagged": every non-info finding; only critical/high (what the default report calls actionable); and every
// non-info finding except the `Unsafe boundary` notes (a rule whose severity an existing test pins at `low` and which claims no vulnerability class).
// Also lists the true positives the fixes lost. usage: node bench/dag/dev-haskell/fresh-score.mjs [after results dir name]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const labels = JSON.parse(fs.readFileSync(path.join(H, 'fresh-labels.json'), 'utf8')).labels;
const wl = JSON.parse(fs.readFileSync(path.join(H, 'fresh-worklist.json'), 'utf8'));
const stratumOf = (v) => (/^Path Traversal/.test(v) ? 'path-traversal' : v.replace(/^Unsafe boundary: .*/, 'unsafe-boundary'));
import { wilson as sharedWilson } from '../../_lib/wilson.mjs';
const wilson = (k, n) => sharedWilson(k, n) || [null, null];
const pct = (x) => (x == null ? 'n/a' : (100 * x).toFixed(1) + '%');
const load = (d) => { const out = new Map(); for (const f of fs.readdirSync(path.resolve(H, d)).sort()) { if (!f.endsWith('.json')) continue; const j = JSON.parse(fs.readFileSync(path.resolve(H, d, f), 'utf8')); for (const r of j.haskell) out.set(`${j.id}:${r.file}:${r.line}:${stratumOf(r.vuln)}`, r); } return out; };
const afterDir = process.argv[2] || 'results-fresh-after';
const sets = { before: load('results-fresh-before'), after: load(afterDir) };
console.log(`after = ${afterDir}`);
const readings = {
  'every non-info finding': (r) => r.severity !== 'info',
  'critical or high only': (r) => r.severity === 'critical' || r.severity === 'high',
  'non-info, without the unsafe-boundary notes': (r) => r.severity !== 'info' && !/^Unsafe boundary/.test(r.vuln),
};
for (const [name, keep] of Object.entries(readings)) {
  console.log(`\n${name}`);
  for (const [which, m] of Object.entries(sets)) {
    let n = 0, tp = 0, missing = 0;
    for (const [k, r] of m) { if (!keep(r)) continue; const l = labels[k]; if (!l) { missing++; continue; } n++; if (l.label === 'TP') tp++; }
    const [lo, hi] = wilson(tp, n);
    console.log(`  ${which.padEnd(7)} ${tp}/${n} = ${pct(n ? tp / n : null)}  [${pct(lo)}, ${pct(hi)}]${missing ? `  (${missing} flagged sites without a label)` : ''}`);
  }
}
const lost = Object.entries(labels).filter(([k, l]) => l.label === 'TP' && sets.before.has(k) && sets.before.get(k).severity !== 'info' && !(sets.after.has(k) && sets.after.get(k).severity !== 'info'));
const beforeTp = Object.entries(labels).filter(([k, l]) => l.label === 'TP' && sets.before.has(k) && sets.before.get(k).severity !== 'info');
console.log(`\ntrue positives flagged by the original engine: ${beforeTp.length}; still flagged after the fixes: ${beforeTp.length - lost.length}; lost: ${lost.length}`);
for (const [k, l] of lost) console.log(`   lost: ${k} ${l.vuln}`);
const afterTpOnly = Object.entries(labels).filter(([k, l]) => l.label === 'TP' && sets.after.has(k) && sets.after.get(k).severity !== 'info' && !(sets.before.has(k) && sets.before.get(k).severity !== 'info'));
console.log(`true positives flagged only after: ${afterTpOnly.length}`);
console.log(`worklist ${wl.items.length}; unlabelled ${wl.items.filter((x) => !labels[x.key]).length}`);
