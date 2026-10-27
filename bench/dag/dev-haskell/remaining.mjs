// Lists the labelled sites a scan still flags (non-info), with the trust verdict and recorded origins.
// usage: node bench/dag/dev-haskell/remaining.mjs [results dir] [--half=tuning|verification]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const arg = process.argv.slice(2).find((a) => !a.startsWith('--'));
const halfArg = process.argv.find((a) => a.startsWith('--half='));
const dir = arg ? path.resolve(arg) : path.join(H, 'results');
const half = halfArg ? halfArg.slice(7) : null;
const lab = JSON.parse(fs.readFileSync(path.join(H, 'labels.json'), 'utf8')).labels;
const stratumOf = (v) => (/^Path Traversal/.test(v) ? 'path-traversal' : v.replace(/^Unsafe boundary: .*/, 'unsafe-boundary'));
const now = {};
for (const f of fs.readdirSync(dir)) {
  if (!f.endsWith('.json')) continue;
  const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  for (const r of j.haskell) if (r.severity !== 'info') now[`${j.id}:${r.file}:${r.line}:${stratumOf(r.vuln)}`] = r;
}
for (const l of Object.values(lab)) {
  if (half && l.half !== half) continue;
  const r = now[`${l.project}:${l.file}:${l.line}:${stratumOf(l.vuln)}`];
  if (!r) continue;
  const roots = r.trust ? r.trust.roots.map((x) => `${String(x.label).slice(0, 34)}/${x.provenance}`).join(',') : '';
  console.log(`${String(l.index).padStart(3)} ${l.label} ${l.half.slice(0, 1)} ${l.project} ${l.file.split('/').pop()}:${l.line} ${r.vuln.slice(0, 26)} | ${r.trust ? r.trust.verdict : '-'} | ${roots}`);
}
