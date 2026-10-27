// Draws the stratified, seeded sample of flagged Haskell sites and splits it into a tuning half and
// a verification half BEFORE any per-site error is looked at. Reads results/*.json from a scan, writes
// sample.json. Strata are the finding's vuln class (path-traversal variants merged, a cap of 45 so no
// rule dominates); every other class is taken whole. Within a stratum the order is a seeded shuffle and
// the halves alternate, so each class is split as evenly as its size allows.
// usage: node bench/dag/dev-haskell/sample.mjs [--seed=N]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const seedArg = process.argv.find((a) => a.startsWith('--seed='));
const SEED = seedArg ? Number(seedArg.slice(7)) : 20261026;
const CAP = 45;

function mulberry32(a) {
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(SEED);
const shuffle = (arr) => { const a = [...arr]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };

const dir = path.join(HERE, 'results');
const all = [];
for (const f of fs.readdirSync(dir).sort()) {
  if (!f.endsWith('.json')) continue;
  const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  for (const r of j.haskell) all.push({ project: j.id, ...r });
}
all.sort((a, b) => (a.project + a.file + String(a.line) + a.id < b.project + b.file + String(b.line) + b.id ? -1 : 1));
const stratumOf = (r) => (/^Path Traversal/.test(r.vuln) ? 'path-traversal' : r.vuln.replace(/^Unsafe boundary: .*/, 'unsafe-boundary'));
const strata = new Map();
for (const r of all) { const k = stratumOf(r); if (!strata.has(k)) strata.set(k, []); strata.get(k).push(r); }
const sample = [];
for (const k of [...strata.keys()].sort()) {
  const rows = shuffle(strata.get(k)).slice(0, CAP);
  rows.forEach((r, i) => sample.push({ key: `${r.project}:${r.file}:${r.line}:${r.id}`, stratum: k, half: i % 2 === 0 ? 'tuning' : 'verification', ...r }));
}
fs.writeFileSync(path.join(HERE, 'sample.json'), JSON.stringify({ seed: SEED, cap: CAP, population: all.length, strata: Object.fromEntries([...strata].map(([k, v]) => [k, v.length])), sample }, null, 1));
console.log(`seed ${SEED}: population ${all.length}, sample ${sample.length}, tuning ${sample.filter((s) => s.half === 'tuning').length}, verification ${sample.filter((s) => s.half === 'verification').length}`);
