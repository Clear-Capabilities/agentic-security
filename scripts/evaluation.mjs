#!/usr/bin/env node
// Evaluation protocol driver (QA-001, QA-002, QA-003): `npm run evaluation -- <command>`.
//
//   synthetic [--json]        exercise freeze -> leakage-audited staging -> three-layer ablation -> end-to-end
//                             scoring -> real-code gates on the SYNTHETIC suite. Prints the gates as the
//                             protocol would: every real-code gate reads insufficient-population. The numbers it
//                             shows describe three tiny authored files and are NOT engine accuracy.
//   deployment-ablation [--json] [--write-frozen]
//                             X-308: the frozen, SYNTHETIC deployment-context ablation. Runs the source-only and the
//                             graph-enabled arm on identical source deployed under exploitable and non-exploitable
//                             configurations and prints paired counts with a paired-bootstrap interval. --write-frozen
//                             (re)writes the committed frozen.json from the fixtures on disk; without it the stored set is
//                             verified against the disk first and a mismatch exits 1. NOT engine accuracy, NOT a real-code gate.
//   freeze <draft.json> [--out <file>]       validate a draft protocol and write it, hash included
//   verify-protocol <file>                   exit 0 when the protocol's content still matches its hash
//   gates --protocol <file> --score <file> --labels-dir <dir> --labels-hash <hash> [--out <file>]
//                                            custodian-only: judge a sealed-split score against the protocol
//   report --protocol <file> --score <file> --population <regression|development|sealed|operational> [--run <file>] [--out <file>]
//                                            honest accuracy report: raw counts, intervals, completion, disclosed gaps, alert burden
//   economics <ledger.json>                  cost accounting from a cost ledger (kinds kept apart; failed attempts included)
//   detector-digest [<src-dir>]              digest of the detector source (default scanner/src, evaluation tooling excluded)
//   release-gate --protocol <file> --score <file> --run <file> --labels-dir <dir> --labels-hash <hash> --ledger <file> --key <pem> --out <file>
//                                            custodian-only: signed aggregate release verdict plus the sealed-evaluation ledger entry
//   verify-gate <signed.json> --public-key <pem>   exit 0 when the signed verdict verifies (and says whether a claim is allowed)
//   bakeoff-validate <manifest.json>         exit 0 when a bake-off manifest is complete and its workload digest is honest
//   bakeoff-judge <manifest.json> --entries <entries.json> --runs <runs.json> [--adapters <adapters.json>] [--out <file>]
//                                            judge a finished bake-off; an unavailable comparator is reported `not-evaluated`, never a loss
//
// Exit codes: 0 ok, 1 invalid/rejected, 2 usage.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { freezeProtocol, validateProtocol } from '../scanner/src/posture/evaluation/protocol.js';
import { buildSyntheticSuite, syntheticResolver } from '../scanner/src/posture/evaluation/synthetic.js';
import { runAblations } from '../scanner/src/posture/evaluation/runner.js';
import { scoreRun } from '../scanner/src/posture/evaluation/score.js';
import { evaluateGates } from '../scanner/src/posture/evaluation/gates.js';
import { custodianReadLabels, protectedTermsFrom } from '../scanner/src/posture/evaluation/custody.js';
import { DOMAINS } from '../scanner/src/sandbox/trust-domains.js';
import { freezeAblationSet, runPairedAblation, verifyFrozenSet, FROZEN_FILE } from '../scanner/src/posture/evaluation/deployment-ablation.js';
import { buildAccuracyReport } from '../scanner/src/posture/evaluation/report.js';
import { validateBakeoffManifest, judgeBakeoff } from '../scanner/src/posture/evaluation/bakeoff.js';
import { accountCosts } from '../scanner/src/posture/evaluation/economics.js';
import { detectorDigestOf, evaluateReleaseGates, signGateReport, verifyGateReport, verifySignedLedger, signLedger, appendSealedEvaluation, emptyLedger } from '../scanner/src/posture/evaluation/release-gate.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, '..', 'scanner', 'test', 'fixtures', 'evaluation-synthetic');
const ABLATION_FIXTURES = path.join(HERE, '..', 'scanner', 'test', 'fixtures', 'deployment-ablation');

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (name) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : undefined; };
const has = (name) => argv.includes(`--${name}`);
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const pct = (x) => (x === null || x === undefined ? 'n/a' : (x * 100).toFixed(1) + '%');

async function synthetic() {
  const suite = buildSyntheticSuite({ fixturesDir: FIXTURES });
  if (!suite.protocol) { console.error('synthetic protocol failed to freeze', JSON.stringify(suite.freezeErrors)); return 1; }
  const terms = protectedTermsFrom({ defects: suite.defects, negatives: suite.negatives });
  const ab = await runAblations({
    protocol: suite.protocol, config: {}, resolveTarget: syntheticResolver(FIXTURES), protectedTerms: terms, split: 'all', allowSealed: true,
  });
  if (!ab.ok) { console.error('ablations not comparable', JSON.stringify(ab.errors)); return 1; }
  const out = [];
  for (const run of ab.runs) {
    const score = scoreRun({ run, protocol: suite.protocol, defects: suite.defects, negatives: suite.negatives });
    const gates = evaluateGates({ protocol: suite.protocol, score, defects: suite.defects, negatives: suite.negatives });
    out.push({ layer: run.config.layer, runId: run.runId, totals: run.totals, endToEnd: score.endToEnd.micro, conditional: score.conditional.micro, completion: score.completion.rate, misses: score.misses.length, reviewQueue: score.reviewQueue.length, gatesOverall: gates.overall, gateStatuses: [...new Set(gates.gates.map((g) => g.status))] });
  }
  if (has('json')) { console.log(JSON.stringify({ synthetic: true, protocolHash: suite.protocol.protocolHash, results: out }, null, 2)); return 0; }
  console.log('SYNTHETIC suite: 3 authored files. These figures exercise the tooling; they are not engine accuracy.');
  console.log(`protocol ${suite.protocol.protocolHash}\n`);
  console.log('layer               completed  e2e recall  e2e precision  e2e F1   conditional F1  real-code gates');
  for (const r of out) {
    console.log(`${r.layer.padEnd(19)} ${String(r.totals.completed).padStart(2)}/${String(Object.values(r.totals).reduce((a, b) => a + b, 0)).padEnd(7)} ${pct(r.endToEnd.recall).padStart(10)} ${pct(r.endToEnd.precision).padStart(14)} ${pct(r.endToEnd.f1).padStart(8)} ${pct(r.conditional.f1).padStart(15)}   ${r.gatesOverall}`);
  }
  return 0;
}

async function deploymentAblation() {
  const frozenPath = path.join(ABLATION_FIXTURES, FROZEN_FILE);
  if (has('write-frozen')) {
    const f = freezeAblationSet({ fixturesDir: ABLATION_FIXTURES });
    if (!f.ok) { console.error(`cannot freeze: ${f.errors.join('; ')}`); return 1; }
    fs.writeFileSync(frozenPath, JSON.stringify(f.set, null, 2) + '\n');
    console.log(`wrote ${frozenPath} (frozenHash ${f.set.frozenHash})`);
    return 0;
  }
  let stored;
  try { stored = readJson(frozenPath); } catch (e) { console.error(`cannot read ${frozenPath}: ${e.message}`); return 1; }
  const v = verifyFrozenSet({ fixturesDir: ABLATION_FIXTURES, stored });
  if (!v.ok) { console.error(`the frozen set does not match the fixtures:\n  ${v.errors.join('\n  ')}`); return 1; }
  const r = await runPairedAblation({ fixturesDir: ABLATION_FIXTURES, stored });
  if (!r.ok) { console.error(`ablation did not run: ${r.errors.join('; ')}`); return 1; }
  const rep = r.report;
  if (has('json')) { console.log(JSON.stringify(rep, null, 2)); return 0; }
  const a = rep.arms, p = rep.paired, u = rep.uncertainty;
  console.log(rep.statement);
  console.log(`frozenHash ${rep.frozenHash}\n`);
  console.log('arm              TP  FP  FN  precision  recall');
  for (const [name, x] of [['source-only', a.sourceOnly], ['graph-enabled', a.graphEnabled]]) {
    console.log(`${name.padEnd(15)} ${String(x.tp).padStart(3)} ${String(x.fp).padStart(3)} ${String(x.fn).padStart(3)}  ${pct(x.precision).padStart(9)}  ${pct(x.recall).padStart(6)}`);
  }
  console.log(`\npaired over ${p.instances} instances (${p.cases} cases): FPs reduced ${p.falsePositivesReduced}, confirmed defects added ${p.confirmedDefectsAdded}, baseline confirmed defects LOST ${p.baselineConfirmedDefectsLost}, FPs added ${p.falsePositivesAdded}, unchanged ${p.unchanged}`);
  const d = (k) => `${pct(u[k].difference)} [${pct(u[k].low)}, ${pct(u[k].high)}]`;
  console.log(`difference (graph - source): precision ${d('precision')}, recall ${d('recall')}  (${u.method}, ${u.resamples} resamples)`);
  console.log(`  ${u.label}`);
  console.log(`runtime (non-deterministic): scan median ${rep.runtime.sourceOnlyScanMsMedian?.toFixed(0)} ms, graph arm adds median ${rep.runtime.graphEnabledAddedMsMedian?.toFixed(1)} ms`);
  const c = rep.coverage.graphEnabled;
  console.log(`coverage: graph built ${c.graphBuilt}/${c.of}; findings with context ${c.findingsWithContext}, bound ${c.findingsBoundToAService}, not assessed ${c.findingsNotAssessed}; instances with graph gaps ${c.instancesWithGraphGaps}; stale sources ${c.staleSources}`);
  console.log(`adapters validated for deployment-aware claims: ${rep.adapters.filter((x) => x.validated).map((x) => x.adapter).join(', ') || 'none'}; not validated: ${rep.adapters.filter((x) => !x.validated).map((x) => `${x.adapter} (${x.reason})`).join('; ')}`);
  console.log(`real-code gates: ${rep.realCodeGates.overall} (${rep.realCodeGates.note})`);
  return 0;
}

async function main() {
  if (cmd === 'synthetic') return synthetic();
  if (cmd === 'deployment-ablation') return deploymentAblation();
  if (cmd === 'freeze') {
    const f = argv[1]; if (!f) return 2;
    const r = freezeProtocol(readJson(f));
    if (!r.ok) { console.error(JSON.stringify(r.errors, null, 2)); return 1; }
    const out = flag('out');
    if (out) fs.writeFileSync(out, JSON.stringify(r.protocol, null, 2) + '\n'); else console.log(JSON.stringify(r.protocol, null, 2));
    return 0;
  }
  if (cmd === 'verify-protocol') {
    const f = argv[1]; if (!f) return 2;
    const v = validateProtocol(readJson(f));
    if (!v.ok) { console.error(JSON.stringify(v.errors, null, 2)); return 1; }
    console.log('protocol content matches its hash');
    return 0;
  }
  if (cmd === 'gates') {
    const [pf, sf, dir, h] = [flag('protocol'), flag('score'), flag('labels-dir'), flag('labels-hash')];
    if (!pf || !sf || !dir || !h) return 2;
    // This command is the custodian: it is the only process here allowed to read sealed labels.
    const labels = custodianReadLabels(dir, { domain: DOMAINS.VERIFIER, role: 'custodian' }, { expectedHash: h });
    if (!labels.ok) { console.error(JSON.stringify(labels.errors)); return 1; }
    const report = evaluateGates({ protocol: readJson(pf), score: readJson(sf), defects: labels.defects, negatives: labels.negatives });
    if (report.rejected) { console.error(JSON.stringify(report.errors)); return 1; }
    const text = JSON.stringify(report, null, 2) + '\n';
    const out = flag('out');
    if (out) fs.writeFileSync(out, text); else process.stdout.write(text);
    return 0;
  }
  if (cmd === 'report') {
    const [pf, sf, pop] = [flag('protocol'), flag('score'), flag('population')];
    if (!pf || !sf || !pop) return 2;
    const rf = flag('run');
    let report;
    try { report = buildAccuracyReport({ score: readJson(sf), protocol: readJson(pf), population: pop, run: rf ? readJson(rf) : null }); } catch (e) { console.error(e.message); return 1; }
    const text = JSON.stringify(report, null, 2) + '\n';
    const out = flag('out');
    if (out) fs.writeFileSync(out, text); else process.stdout.write(text);
    return 0;
  }
  if (cmd === 'economics') {
    const f = argv[1]; if (!f) return 2;
    const r = accountCosts(readJson(f));
    if (!r.ok) { console.error(JSON.stringify(r.errors, null, 2)); return 1; }
    console.log(JSON.stringify(r, null, 2));
    return 0;
  }
  if (cmd === 'detector-digest') {
    console.log(detectorDigestOf(argv[1] || path.join(HERE, '..', 'scanner', 'src')));
    return 0;
  }
  if (cmd === 'release-gate') {
    const [pf, sf, rf, dir, h, lf, kf, out] = [flag('protocol'), flag('score'), flag('run'), flag('labels-dir'), flag('labels-hash'), flag('ledger'), flag('key'), flag('out')];
    if (!pf || !sf || !rf || !dir || !h || !kf || !out) return 2;
    const labels = custodianReadLabels(dir, { domain: DOMAINS.VERIFIER, role: 'custodian' }, { expectedHash: h });
    if (!labels.ok) { console.error(JSON.stringify(labels.errors)); return 1; }
    const keyPem = fs.readFileSync(kf, 'utf8');
    let ledger = emptyLedger();
    let signedLedger = null;
    if (lf) {
      try { signedLedger = readJson(lf); } catch (e) { if (e.code !== 'ENOENT') { console.error(`ledger unreadable: ${e.message}`); return 1; } }
    }
    if (signedLedger) {
      const pub = flag('ledger-public-key');
      const v = verifySignedLedger(signedLedger, pub ? fs.readFileSync(pub, 'utf8') : (await import('node:crypto')).createPublicKey(keyPem).export({ type: 'spki', format: 'pem' }));
      if (!v.ok) { console.error(`ledger rejected: ${v.reason}`); return 1; }
      ledger = v.ledger;
    }
    const protocol = readJson(pf); const score = readJson(sf);
    const detectorDigest = detectorDigestOf(flag('detector-src') || path.join(HERE, '..', 'scanner', 'src'));
    const verdict = evaluateReleaseGates({ protocol, score, run: readJson(rf), defects: labels.defects, negatives: labels.negatives, ledger, detectorDigest });
    if (verdict.rejected) { console.error(JSON.stringify(verdict.errors)); return 1; }
    fs.writeFileSync(out, JSON.stringify(signGateReport(verdict, keyPem), null, 2) + '\n');
    if (lf) {
      const next = appendSealedEvaluation(ledger, { protocolHash: protocol.protocolHash, detectorDigest, sealedTargetIds: protocol.splits.sealed, overall: verdict.overall, score });
      fs.writeFileSync(lf, JSON.stringify(signLedger(next, keyPem), null, 2) + '\n');
    }
    console.log(`release verdict: ${verdict.overall}; new accuracy claim ${verdict.claim.allowed ? 'ALLOWED' : 'BLOCKED'}${verdict.claim.reasons.length ? ` (${verdict.claim.reasons.join(', ')})` : ''}`);
    return 0;
  }
  if (cmd === 'verify-gate') {
    const f = argv[1]; const pub = flag('public-key');
    if (!f || !pub) return 2;
    const v = verifyGateReport(readJson(f), fs.readFileSync(pub, 'utf8'));
    if (!v.ok) { console.error(v.reason); return 1; }
    console.log(`signature verifies; overall ${v.overall}; new accuracy claim ${v.claimAllowed ? 'allowed' : 'blocked'}; trust basis ${v.trustBasis} (not independent certification)`);
    return 0;
  }
  if (cmd === 'bakeoff-validate') {
    const f = argv[1]; if (!f) return 2;
    const v = validateBakeoffManifest(readJson(f));
    if (!v.ok) { console.error(JSON.stringify(v.errors, null, 2)); return 1; }
    console.log('bake-off manifest is complete and its workload digest matches');
    return 0;
  }
  if (cmd === 'bakeoff-judge') {
    const [mf, ef, rf] = [argv[1], flag('entries'), flag('runs')];
    if (!mf || !ef || !rf) return 2;
    const af = flag('adapters');
    const report = judgeBakeoff({ manifest: readJson(mf), entries: readJson(ef), runs: readJson(rf), adapters: af ? readJson(af) : {} });
    if (!report.ok) { console.error(JSON.stringify(report.errors, null, 2)); return 1; }
    const text = JSON.stringify(report, null, 2) + '\n';
    const out = flag('out');
    if (out) fs.writeFileSync(out, text); else process.stdout.write(text);
    return 0;
  }
  console.error('usage: evaluation.mjs synthetic|deployment-ablation|freeze|verify-protocol|gates|report|economics|detector-digest|release-gate|verify-gate|bakeoff-validate|bakeoff-judge (see the file header)');
  return 2;
}

main().then((c) => process.exit(c), (e) => { console.error(e?.stack || e); process.exit(1); });
