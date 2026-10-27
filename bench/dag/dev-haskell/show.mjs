// Prints sampled sites with source context, for labelling by reading the code.
// usage: node bench/dag/dev-haskell/show.mjs "<stratum>|<stratum>" [from] [to] [context-lines]
//        node bench/dag/dev-haskell/show.mjs "#12,#13" ...   (by sample index)
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const s = JSON.parse(fs.readFileSync(path.join(H, 'sample.json'), 'utf8')).sample;
const [, , sel, from = '0', to = '999', ctx = '6'] = process.argv;
let rows;
if (sel.startsWith('#')) rows = sel.split(',').map((x) => s[Number(x.slice(1))]);
else { const set = new Set(sel.split('|')); rows = s.filter((r) => set.has(r.stratum)).slice(+from, +to); }
for (const r of rows) {
  const src = fs.readFileSync(path.join(H, '.cache', r.project, r.file), 'utf8').split('\n');
  console.log(`=== #${s.indexOf(r)} ${r.project}/${r.file}:${r.line} [${r.severity}] ${r.vuln}\n  ${r.description}`);
  const a = Math.max(0, r.line - 1 - +ctx), b = Math.min(src.length, r.line + +ctx);
  for (let i = a; i < b; i++) console.log((i + 1 === r.line ? '>>' : '  ') + String(i + 1).padStart(5) + ' ' + src[i]);
}
