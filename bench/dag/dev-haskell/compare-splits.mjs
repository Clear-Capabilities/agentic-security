// Compares two directories of language-support measurements (train, validation, unseen, shape-dev, shape-dev-2 for haskell), layer by layer.
// usage: node bench/dag/dev-haskell/compare-splits.mjs <before dir> <after dir>
import * as fs from 'node:fs';
import * as path from 'node:path';

const [, , a, b] = process.argv;
for (const split of ['train', 'validation', 'unseen', 'shape-dev', 'shape-dev-2']) {
  const rd = (d) => JSON.parse(fs.readFileSync(path.join(d, `${split}.json`), 'utf8')).ecosystems.haskell;
  let x; let y;
  try { x = rd(a); y = rd(b); } catch (e) { console.log(`${split}: unreadable (${e.message})`); continue; }
  const line = (e) => ['sast', 'taint'].map((l) => { const L = e.detection.layers[l]; return `${l} tp${L.tp} fp${L.fp} fn${L.fn} tn${L.tn} strictFP${L.strict ? L.strict.fp : '-'}`; }).join(' | ');
  const same = line(x) === line(y);
  console.log(`${split.padEnd(12)} ${same ? 'IDENTICAL' : 'CHANGED  '} before: ${line(x)}`);
  if (!same) console.log(`${''.padEnd(12)}           after : ${line(y)}`);
  const missB = (x.detection.layers.sast.misses || []).length + (x.detection.layers.taint.misses || []).length;
  const missA = (y.detection.layers.sast.misses || []).length + (y.detection.layers.taint.misses || []).length;
  if (missA !== missB) console.log(`${''.padEnd(12)}           misses ${missB} -> ${missA}`);
  const pairs = (e) => JSON.stringify(e.pairs && e.pairs.summary ? e.pairs.summary : e.pairs ? Object.keys(e.pairs) : null).slice(0, 120);
  if (pairs(x) !== pairs(y)) console.log(`${''.padEnd(12)}           pairs changed`);
}
