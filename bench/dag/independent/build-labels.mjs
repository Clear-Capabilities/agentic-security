// One-off: joins the hand-written verdict tables (draft-*.txt, indexed into the seeded
// samples sample-*.json) into labels.json with a canonical digest. Kept for provenance.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { canonicalLabels, digestOf } from './lib.mjs';
const out = [];
for (const [lang, draft] of [['javascript', 'draft-js.txt'], ['nix', 'draft-nix.txt']]) {
  const sample = JSON.parse(fs.readFileSync(`sample-${lang}.json`, 'utf8'));
  const rows = fs.readFileSync(draft, 'utf8').trim().split('\n').map(l => { const [i, v, ...e] = l.split('|'); return { i: +i, v, e: e.join('|') }; });
  if (rows.length !== sample.length) throw new Error(`${lang}: ${rows.length} verdicts for ${sample.length} sampled sites`);
  for (const r of rows) {
    const s = sample[r.i];
    if (!['tp', 'fp', 'ambiguous'].includes(r.v)) throw new Error('bad verdict ' + r.i);
    const id = crypto.createHash('sha256').update([s.project, s.file, s.line, s.vuln].join('|')).digest('hex').slice(0, 12);
    out.push({ id, project: s.project, language: lang, file: s.file, line: s.line, vuln: s.vuln, verdict: r.v, evidence: r.e });
  }
}
const labels = canonicalLabels(out);
fs.writeFileSync('labels.json', JSON.stringify({
  labelsVersion: 1,
  labeledBy: 'an LLM agent reading source; not a human audit, not the scanner authors',
  labelsDigest: digestOf(labels),
  labels,
}, null, 1) + '\n');
console.log(labels.length, 'labels');
