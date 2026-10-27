// One-off: joins the hand-written verdict table (draft-haskell.txt, indexed into the seeded
// sample sample-haskell.json) into labels.json with a canonical digest. Kept for provenance.
//
// `--panel [--dir <dir>]` is the second-labeler mode and never touches labels.json: it joins one draft per extra labeler
// (`draft-haskell-<labelerId>.txt`, lines `index|tp|fp|unsure|evidence`) and an optional adjudication pass
// (`adjudication-haskell.txt`, lines `index|tp|fp|ambiguous|evidence`) with the single-labeler record into `labels-panel.json`, and writes the
// agreement report (`agreement.json`, `agreement.md`). Its inputs are described by `labelers.json` in the same directory:
//   { "base": {"labelerId": "a", "model": "..."},                      the labeler behind labels.json (its ambiguous verdicts become `unsure`)
//     "labelers": [{"labelerId": "b", "model": "...", "blind": true}],   each other labeler; the draft file is draft-haskell-<labelerId>.txt
//     "adjudicator": {"labelerId": "c", "model": "..."} | null }        a third labeler who is none of the above (draft: adjudication-haskell.txt)
// The panel is refused (nothing is written) unless the labelers are distinct, on distinct models, blind, and the adjudicator is none of them.
// This tool has been exercised on a synthetic fixture only (scanner/test/bench-independent-haskell-panel.test.js).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { canonicalLabels, digestOf, buildPanel, validatePanel, agreementReport, panelDigestOf } from './lib.mjs';

if (process.argv.includes('--panel')) {
  const di = process.argv.indexOf('--dir');
  const dir = path.resolve(di > 0 ? process.argv[di + 1] : '.');
  const read = (f) => fs.readFileSync(path.join(dir, f), 'utf8');
  const cfg = JSON.parse(read('labelers.json'));
  const sample = JSON.parse(read('sample-haskell.json'));
  const baseDoc = JSON.parse(read('labels.json'));
  if (digestOf(baseDoc.labels) !== baseDoc.labelsDigest) { console.error('FAIL: labels.json does not match its recorded digest; the panel is built on an unmodified single-labeler record only.'); process.exit(1); }
  const parse = (text) => text.trim().split('\n').filter(Boolean).map((l) => { const [i, v, ...e] = l.split('|'); return { i: +i, v, e: e.join('|') }; });
  const drafts = {};
  for (const l of cfg.labelers || []) drafts[l.labelerId] = parse(read(`draft-haskell-${l.labelerId}.txt`));
  const adjudication = cfg.adjudicator ? parse(read('adjudication-haskell.txt')) : null;
  let panel;
  try {
    panel = buildPanel({
      sample, drafts, base: baseDoc.labels, baseLabelerId: cfg.base.labelerId, baseLabelsDigest: baseDoc.labelsDigest,
      labelers: [{ labelerId: cfg.base.labelerId, model: cfg.base.model, blind: cfg.base.blind !== false }, ...(cfg.labelers || []).map((l) => ({ labelerId: l.labelerId, model: l.model, blind: l.blind === true }))],
      adjudicator: cfg.adjudicator ? { labelerId: cfg.adjudicator.labelerId, model: cfg.adjudicator.model } : null, adjudication,
    });
  } catch (e) { console.error(`FAIL: ${e.message}`); process.exit(1); }
  const v = validatePanel(panel, baseDoc.labels);
  if (!v.ok) { console.error(`FAIL: the panel is not valid:\n  ${v.errors.join('\n  ')}`); process.exit(1); }
  fs.writeFileSync(path.join(dir, 'labels-panel.json'), JSON.stringify(panel, null, 1) + '\n');
  const rep = agreementReport(panel);
  fs.writeFileSync(path.join(dir, 'agreement.json'), JSON.stringify({ panelDigest: panelDigestOf(panel), baseLabelsDigest: baseDoc.labelsDigest, ...rep }, null, 1) + '\n');
  const f = (x) => (x == null ? 'n/a' : x.toFixed(3));
  const lines = [`# Labeler agreement`, '', `Panel digest: ${panelDigestOf(panel)}`, `Sites: ${rep.sites}. Labelers: ${rep.labelers.map((l) => `${l.labelerId} (${l.model})`).join(', ')}. Adjudicator: ${rep.adjudicator ? `${rep.adjudicator.labelerId} (${rep.adjudicator.model})` : 'none'}.`, '',
    '| pair | sites | percent agreement | Cohen kappa (tp / fp / unsure) | decided by both | kappa (tp / fp) |', '|---|---|---|---|---|---|',
    ...rep.pairs.map((p) => `| ${p.labelers.join(' and ')} | ${p.threeWay.n} | ${f(p.threeWay.percentAgreement)} | ${f(p.threeWay.kappa)} | ${p.decidedOnly.sites} | ${f(p.decidedOnly.kappa)} |`), '',
    `Status: agreed ${rep.statusCounts.agreed}, disagreed ${rep.statusCounts.disagreed}, one labeler unsure ${rep.statusCounts['one-unsure']}, all unsure ${rep.statusCounts['all-unsure']}. Adjudicated ${rep.adjudicated} of ${rep.nonAgreed}; still ambiguous ${rep.unsettledAfterAdjudication}.`,
    `Final: tp ${rep.finalCounts.tp}, fp ${rep.finalCounts.fp}, ambiguous ${rep.finalCounts.ambiguous}.`, '', rep.note, ''];
  fs.writeFileSync(path.join(dir, 'agreement.md'), lines.join('\n'));
  console.log(`${panel.sites.length} sites; ${rep.statusCounts.agreed} agreed, ${rep.statusCounts.disagreed} disagreed, ${rep.statusCounts['one-unsure']} one unsure, ${rep.statusCounts['all-unsure']} all unsure; wrote labels-panel.json, agreement.json, agreement.md (labels.json untouched)`);
  process.exit(0);
}

const out = [];
const sample = JSON.parse(fs.readFileSync('sample-haskell.json', 'utf8'));
const rows = fs.readFileSync('draft-haskell.txt', 'utf8').trim().split('\n').map(l => { const [i, v, ...e] = l.split('|'); return { i: +i, v, e: e.join('|') }; });
if (rows.length !== sample.length) throw new Error(`${rows.length} verdicts for ${sample.length} sampled sites`);
for (const r of rows) {
  const s = sample[r.i];
  if (!['tp', 'fp', 'ambiguous'].includes(r.v)) throw new Error('bad verdict ' + r.i);
  const id = crypto.createHash('sha256').update([s.project, s.file, s.line, s.vuln].join('|')).digest('hex').slice(0, 12);
  out.push({ id, project: s.project, language: 'haskell', file: s.file, line: s.line, vuln: s.vuln, verdict: r.v, evidence: r.e });
}
const labels = canonicalLabels(out);
fs.writeFileSync('labels.json', JSON.stringify({
  labelsVersion: 1,
  labeledBy: 'an LLM agent reading source; not a human audit, not the scanner authors',
  labelsDigest: digestOf(labels),
  labels,
}, null, 1) + '\n');
console.log(labels.length, 'labels');
