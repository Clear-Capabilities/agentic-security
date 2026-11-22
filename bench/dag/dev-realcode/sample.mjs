// Draws the stratified, seeded sample of flagged TAINT-LAYER sites of a set (parser IR-TAINT or MULTI-SINK: the set is the instrument of the
// taint work; --layer=all widens it to every finding) and splits it into a tuning half and a verification half BEFORE any site is read. Strata
// are the finding's CWE (a cap so no class dominates); within a stratum the order is a seeded shuffle and the halves alternate. Writes
// sample-<set>.json.
// usage: node bench/dag/dev-realcode/sample.mjs --set=python|typescript [--seed=N] [--cap=N] [--layer=taint|all] [--dir=<results dir>]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (n) => { const a = process.argv.find((x) => x.startsWith(`--${n}=`)); return a ? a.slice(n.length + 3) : null; };
const set = arg('set') || 'python';
const SEED = Number(arg('seed') || 20261121);
const CAP = Number(arg('cap') || 6);
const LAYER = arg('layer') || 'taint';
const inLayer = (r) => LAYER === 'all' || r.parser === 'IR-TAINT' || r.parser === 'MULTI-SINK';
function mulberry32(a) { return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const rnd = mulberry32(SEED);
const shuffle = (arr) => { const a = [...arr]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
import { stratumOf } from './lib.mjs';
const dir = arg('dir') ? path.resolve(arg('dir')) : path.join(HERE, 'results', set);
const all = [];
for (const f of fs.readdirSync(dir).sort()) {
  if (!f.endsWith('.json')) continue;
  const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  for (const r of j.findings) if (r.severity !== 'info' && inLayer(r)) all.push({ project: j.id, ...r });
}
all.sort((a, b) => (a.project + a.file + String(a.line) + a.id < b.project + b.file + String(b.line) + b.id ? -1 : 1));
const strata = new Map();
for (const r of all) { const k = stratumOf(r.vuln, r.cwe); if (!strata.has(k)) strata.set(k, []); strata.get(k).push(r); }
const sample = [];
for (const k of [...strata.keys()].sort()) {
  const rows = shuffle(strata.get(k)).slice(0, CAP);
  rows.forEach((r, i) => sample.push({ index: sample.length + 0, key: `${r.project}:${r.file}:${r.line}:${k}`, stratum: k, half: i % 2 === 0 ? 'tuning' : 'verification', project: r.project, file: r.file, line: r.line, id: r.id, parser: r.parser, severity: r.severity, vuln: r.vuln, cwe: r.cwe }));
}
sample.forEach((s, i) => { s.index = i; });
fs.writeFileSync(path.join(HERE, `sample-${set}.json`), JSON.stringify({ set, seed: SEED, cap: CAP, layer: LAYER, population: all.length, strata: Object.fromEntries([...strata].map(([k, v]) => [k, v.length])), sample }, null, 1) + '\n');
console.log(`${set}: seed ${SEED}, cap ${CAP}: population ${all.length} (non-info), sample ${sample.length}, tuning ${sample.filter((s) => s.half === 'tuning').length}, verification ${sample.filter((s) => s.half === 'verification').length}, strata ${strata.size}`);
