// Prints worklist items of the fresh set with source context. usage: node bench/dag/dev-haskell/fresh-show.mjs <filter> [from] [to] [ctx]
// <filter> is a regex over "kind|parser|vuln|project"; "!<regex>" excludes.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const H = path.dirname(fileURLToPath(import.meta.url));
const wl = JSON.parse(fs.readFileSync(path.join(H, 'fresh-worklist.json'), 'utf8')).items;
const [, , filt = '.', from = '0', to = '999', ctx = '5'] = process.argv;
const neg = filt.startsWith('!');
const byIndex = filt.startsWith('#') ? new Set(filt.slice(1).split(',').map(Number)) : null;
const re = new RegExp(neg ? filt.slice(1) : byIndex ? '.' : filt);
const rows = wl.map((x, i) => ({ ...x, i })).filter((x) => (byIndex ? byIndex.has(x.i) : re.test(`${x.kind}|${x.parser}|${x.vuln}|${x.project}`) !== neg)).slice(+from, +to);
for (const r of rows) {
  const src = fs.readFileSync(path.join(H, '.cache', r.project, r.file), 'utf8').split('\n');
  console.log(`=== #${r.i} ${r.kind} ${r.project}/${r.file}:${r.line} [${r.severity}] ${r.parser} ${r.vuln}${r.trust ? ` | trust=${r.trust}` : ''}`);
  const a = Math.max(0, r.line - 1 - +ctx), b = Math.min(src.length, r.line + +ctx);
  for (let i = a; i < b; i++) console.log((i + 1 === r.line ? '>>' : '  ') + String(i + 1).padStart(5) + ' ' + src[i]);
}
