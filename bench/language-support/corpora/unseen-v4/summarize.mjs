// Turns a measure.mjs result for the unseen-v4 split into the baseline markdown (per family and overall, Wilson 95% intervals).
// Usage: node summarize.mjs <result.json> <out.md>
import fs from 'node:fs';
import { wilson } from '../../../dag/independent-haskell/lib.mjs';

const [, , inFile, outFile] = process.argv;
const r = JSON.parse(fs.readFileSync(inFile, 'utf8'));
const d = r.ecosystems.haskell.detection;
const fam = {};
for (const layer of ['sast', 'taint']) for (const [k, v] of Object.entries(d.layers[layer].families)) fam[k] = { layer, ...v };
const pct = (x) => (x === null || x === undefined ? 'n/a' : (100 * x).toFixed(1) + '%');
const ci = (k, n) => { const w = wilson(k, n); return w ? `${pct(w[0])} to ${pct(w[1])}` : 'n/a'; };
const rowOf = (name, layer, t) => {
  const p = t.tp + t.fp, rr = t.tp + t.fn, f1 = p && rr && t.tp ? 2 * (t.tp / p) * (t.tp / rr) / ((t.tp / p) + (t.tp / rr)) : (p && rr ? 0 : null);
  return `| ${name} | ${layer} | ${t.tp} | ${t.fp} | ${t.fn} | ${t.tn ?? ''} | ${p ? pct(t.tp / p) : 'n/a'} (${p ? ci(t.tp, p) : 'n/a'}) | ${rr ? pct(t.tp / rr) : 'n/a'} (${rr ? ci(t.tp, rr) : 'n/a'}) | ${f1 === null ? 'n/a' : pct(f1)} |`;
};
const perFamilyCases = d.perFamilyCases;
// per-family TN is safe forms minus fp
const rows = Object.keys(perFamilyCases).sort().map((k) => {
  const f = fam[k] || { layer: '?', tp: 0, fp: 0, fn: perFamilyCases[k].vulnerable };
  return rowOf(k, f.layer, { tp: f.tp, fp: f.fp, fn: f.fn, tn: perFamilyCases[k].safe - f.fp });
});
const sum = (layers) => layers.reduce((a, l) => ({ tp: a.tp + d.layers[l].tp, fp: a.fp + d.layers[l].fp, fn: a.fn + d.layers[l].fn, tn: a.tn + d.layers[l].tn }), { tp: 0, fp: 0, fn: 0, tn: 0 });
const md = `# unseen-v4 baseline (Haskell)

MEASUREMENT ONLY. Measured once, before any change to the engine by whoever follows. Never tune against this split; see ../corpora/unseen-v4/README.md and USE-LOG.md.

- Measured: ${r.measuredAt}; command: \`node bench/language-support/measure.mjs --split unseen-v4 --eco haskell --suites detection --out bench/language-support/results/unseen-v4-baseline.json\`
- Split: ${d.cases} cases (13 families, 3 vulnerable and 3 safe forms each; ${d.unknownOutcomes.total} unknown). Digest: see corpora/unseen-v4/manifest.json (sourcesSha256, labelsSha256).
- Scoring: the existing harness (family-scoped; a finding of another family in a case is not this family's false positive; line numbers are not scored, the finding only has to be of the right CWE in the right file).
- Intervals: Wilson 95%, precision over TP+FP and recall over TP+FN, with small denominators (3 vulnerable and 3 safe forms per family). Read the intervals, not the point values; a per-family row is 6 cases.

## Overall (all 13 families)

| scope | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
${rowOf('all', 'sast + taint', sum(['sast', 'taint']))}
${rowOf('pattern layer families (8)', 'sast', sum(['sast']))}
${rowOf('taint families (5)', 'taint', sum(['taint']))}

## Per family

| family | layer | TP | FP | FN | TN (safe minus FP) | precision (95%) | recall (95%) | F1 |
|---|---|---|---|---|---|---|---|---|
${rows.join('\n')}

Strict (cross-family findings counted as false positives): sast precision ${pct(d.layers.sast.strict.precision)}, taint precision ${pct(d.layers.taint.strict.precision)}.

## Caveats

- 78 forms by one author. Shapes are the author's idea of how real programs write these forms; they are not scraped from real projects.
- Forms were not compiled (library packages not installed here), so a form could contain a type error; the harness reads source text only.
- The harness does not score the flaw line (tolerance is unlimited), so a right-CWE finding on the wrong line in the file still counts as a TP; the author-labelled line is recorded in labels.json (flawLine / safeSinkLine) for a stricter later reading.
- A safe form here means the specific flaw is absent as the author reasoned it; a form can be safe for that family and still carry another weakness.
`;
fs.writeFileSync(outFile, md);
console.log(md);
