// Agreement between the first labeller (fresh-labels.json) and the independent second labeller (fresh-labels-second.json) on the fresh set.
// Binary view: true positive against anything else (the second labeller's UNSURE counts as not-TP). Reports percent agreement and Cohen's kappa,
// the disagreement list, and the fresh precision each labeller's labels would give over the same 45 sites the engine flags now.
// usage: node bench/dag/dev-haskell/second-labeler-score.mjs
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
const H = path.dirname(fileURLToPath(import.meta.url));
const first = JSON.parse(fs.readFileSync(path.join(H, 'fresh-labels.json'), 'utf8')).labels;
const second = JSON.parse(fs.readFileSync(path.join(H, 'fresh-labels-second.json'), 'utf8')).labels;
const keys = Object.keys(first).filter((k) => second[k]);
const tp = (l) => l === 'TP';
let tt = 0, tf = 0, ft = 0, ff = 0;
const dis = [];
for (const k of keys) {
  const a = tp(first[k].label), b = tp(second[k].label);
  if (a && b) tt++; else if (a) tf++; else if (b) ft++; else ff++;
  if (a !== b) dis.push({ key: k, first: first[k].label, second: second[k].label, reason: second[k].reason });
}
const n = tt + tf + ft + ff, po = (tt + ff) / n, p1 = (tt + tf) / n, p2 = (tt + ft) / n, pe = p1 * p2 + (1 - p1) * (1 - p2);
const kappa = pe === 1 ? 1 : (po - pe) / (1 - pe);
console.log(`sites labelled by both: ${n}`);
console.log(`both TP ${tt}, first only ${tf}, second only ${ft}, both not-TP ${ff}`);
console.log(`percent agreement ${(100 * po).toFixed(1)}%, Cohen's kappa ${kappa.toFixed(3)}`);
const policy = dis.filter((d) => d.first === 'TP' && /examples\/|dhall-test-server/.test(d.key));
console.log(`disagreements ${dis.length}: ${policy.length} are the first labeller calling a TP in example or test-server code (a scope policy), ${dis.length - policy.length} are other readings`);
for (const d of dis) console.log(`  ${d.key.slice(0, 100)} | first ${d.first}, second ${d.second}`);
