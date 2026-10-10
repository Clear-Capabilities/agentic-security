// QA-007: release evaluation gates, signed by the custodian, without holdout tuning.
//
// GENERATED populations only (test/helpers/evaluation-generated.js): these labels were never adjudicated by anyone and describe no real
// code. They let the real gate logic run end to end; nothing here is an accuracy figure, and the repository contains no real sealed
// population, so no real-code gate can read `pass` today (the second describe block pins that).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { generatedPopulation, generatedScore, unitOf } from '../helpers/evaluation-generated.js';
import { evaluateGates } from '../../src/posture/evaluation/gates.js';
import { sealLabels } from '../../src/posture/evaluation/custody.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { freezeProtocol, PREREGISTERED_THRESHOLDS } from '../../src/posture/evaluation/protocol.js';
import {
  evaluateReleaseGates, emptyLedger, appendSealedEvaluation, verifyLedger, signLedger, verifySignedLedger,
  signGateReport, verifyGateReport, detectorDigestOf, assessReleaseClaim,
} from '../../src/posture/evaluation/release-gate.js';
import { mkTestTmp } from '../helpers/tmp.js';

const SCRIPT = path.resolve(import.meta.dirname, '..', '..', '..', 'scripts', 'evaluation.mjs');
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PRIV = privateKey.export({ type: 'pkcs8', format: 'pem' });
const PUB = publicKey.export({ type: 'spki', format: 'pem' });

const pop = generatedPopulation({ per: 100 });
const statusOf = (r, id) => r.gates.find((g) => g.id === id).status;

/** An engine that detects `recall` of the positives and raises a false alarm on `fpRate` of the patched trees. */
const engine = (recall, fpRate, extra = {}) => generatedScore(pop, { detect: (t) => unitOf(t.id, 'd') < recall, falseAlarm: (t) => unitOf(t.id, 'f') < fpRate, ...extra });
const verdict = (g, { ledger = emptyLedger(), detectorDigest = 'sha256:' + 'a'.repeat(64), population = pop } = {}) => evaluateReleaseGates({ protocol: population.protocol, score: g.score, run: g.run, defects: population.defects, negatives: population.negatives, ledger, detectorDigest });

describe('[QA-007.AC01] sealed evaluation uses the preregistered scope, minimum population and thresholds; insufficient data is blocked, never a pass', () => {
  test('a good engine on a population that meets every minimum passes every gate, including the grouped-interval lower bound', () => {
    const v = verdict(engine(0.95, 0.02));
    assert.equal(v.ok, true);
    assert.equal(v.overall, 'pass', JSON.stringify(v.gates.filter((g) => g.status !== 'pass')));
    for (const id of ['overall-micro-f1', 'overall-macro-f1', 'pooled-precision', 'pooled-recall', 'completion', 'per-language-f1-lower-bound', 'answer-key-leaks', 'denominator-intact']) assert.equal(statusOf(v, id), 'pass', id);
    const lb = v.gates.find((g) => g.id === 'per-language-f1-lower-bound');
    assert.ok(lb.measured >= PREREGISTERED_THRESHOLDS.perLanguageF1LowerBound);
    assert.equal(v.claim.allowed, true);
  });

  test('one label short in one language: blocked as insufficient-population with the reason, even for a perfect engine (control above passes)', () => {
    const thin = generatedPopulation({ per: 99 });
    const g = generatedScore(thin, {});
    const v = verdict(g, { population: thin });
    assert.equal(v.overall, 'insufficient-population');
    assert.match(v.population.reason, /99\/100 positives/);
    assert.equal(v.claim.allowed, false);
    assert.ok(v.claim.reasons.includes('gate-insufficient-population'));
  });

  test('a synthetic-flagged population can exercise the machinery and can never satisfy the minimums', () => {
    const syn = generatedPopulation({ per: 100, flagSynthetic: true });
    const v = verdict(generatedScore(syn, {}), { population: syn });
    assert.equal(v.overall, 'insufficient-population');
    assert.equal(v.claim.allowed, false);
  });

  test('a run that covers a smaller convenient subset of the sealed targets cannot pass: the denominator gate fails it', () => {
    const subset = generatedScore(pop, { status: (t) => (unitOf(t.id, 's') < 0.2 ? 'unavailable' : 'completed') });
    const v = verdict(subset);
    assert.notEqual(v.overall, 'pass');
    assert.equal(statusOf(v, 'completion'), 'fail');
  });

  test('thresholds come from the frozen protocol only: a caller-supplied threshold is ignored and an edited protocol is rejected', () => {
    const g = engine(0.6, 0.3);
    const lax = evaluateReleaseGates({ protocol: pop.protocol, score: g.score, run: g.run, defects: pop.defects, negatives: pop.negatives, ledger: emptyLedger(), detectorDigest: 'sha256:' + 'a'.repeat(64), thresholds: { overallMicroF1: 0.01 } });
    assert.equal(statusOf(lax, 'overall-micro-f1'), 'fail');
    const edited = JSON.parse(JSON.stringify(pop.protocol)); edited.thresholds.overallMicroF1 = 0.1;
    const rej = evaluateReleaseGates({ protocol: edited, score: g.score, run: g.run, defects: pop.defects, negatives: pop.negatives, ledger: emptyLedger(), detectorDigest: 'x' });
    assert.equal(rej.rejected, true);
    const looser = freezeProtocol({ ...pop.draft, thresholds: { ...PREREGISTERED_THRESHOLDS, overallMicroF1: 0.5 } });
    assert.equal(looser.ok, false, 'a protocol cannot even be frozen with a looser bound');
  });

  test('a release verdict needs the run record; without it nothing is judged', () => {
    const g = engine(0.95, 0.02);
    const r = evaluateReleaseGates({ protocol: pop.protocol, score: g.score, run: null, defects: pop.defects, negatives: pop.negatives, ledger: emptyLedger(), detectorDigest: 'x' });
    assert.equal(r.rejected, true); assert.equal(r.errors[0].code, 'RUN_REQUIRED');
  });
});

describe('[QA-007.AC01] the per-language F1 lower bound is a real gate, computed over GROUPS', () => {
  test('misses concentrated in a few related groups fail the lower bound although the point estimate clears the bar; the same misses spread over independent targets pass it', () => {
    const grouped = generatedPopulation({ per: 100, groupSize: 10 });
    const missed = (t) => t.language === 'go' && Number(t.id.split('-').pop()) < 30; // three whole groups of ten
    const g = generatedScore(grouped, { detect: (t) => !missed(t) });
    const v = verdict(g, { population: grouped });
    assert.ok(g.score.endToEnd.byLanguage.go.f1 >= PREREGISTERED_THRESHOLDS.perLanguageF1, `point estimate ${g.score.endToEnd.byLanguage.go.f1} clears the per-language bar`);
    assert.equal(statusOf(v, 'per-language-f1:go'), 'pass');
    assert.equal(statusOf(v, 'per-language-f1-lower-bound'), 'fail');
    assert.ok(v.gates.find((x) => x.id === 'per-language-f1-lower-bound').measured < PREREGISTERED_THRESHOLDS.perLanguageF1LowerBound);
    assert.equal(v.overall, 'fail');
    // control: identical detections, but every target is its own independent group
    const indep = generatedPopulation({ per: 100, groupSize: 1 });
    const gi = generatedScore(indep, { detect: (t) => !missed(t) });
    const vi = verdict(gi, { population: indep });
    assert.equal(statusOf(vi, 'per-language-f1-lower-bound'), 'pass');
    assert.ok(vi.gates.find((x) => x.id === 'per-language-f1-lower-bound').measured >= PREREGISTERED_THRESHOLDS.perLanguageF1LowerBound);
  });
});

describe('[QA-007.AC01] no real-code gate can pass on this repository today', () => {
  test('the shipped synthetic suite reads insufficient-population for every population-bound gate', async () => {
    const { suite } = await import('../helpers/evaluation-suite.js');
    const s = suite();
    const g = evaluateGates({ protocol: s.protocol, score: { protocolHash: s.protocol.protocolHash, endToEnd: { micro: { f1: 1, precision: 1, recall: 1 }, macroF1: 1, byLanguage: {} }, completion: { rate: 1 } }, defects: s.defects, negatives: s.negatives });
    assert.notEqual(g.overall, 'pass');
    assert.ok(g.gates.every((x) => x.status === 'insufficient-population'));
  });
});

describe('[QA-007.AC02] a detector edit after a sealed evaluation needs a fresh sealed population; history is retained as evaluation-only', () => {
  const D1 = 'sha256:' + '1'.repeat(64); const D2 = 'sha256:' + '2'.repeat(64);

  test('same detector, same sealed targets: still allowed. Edited detector, same sealed targets: blocked, fresh population required', () => {
    const good = engine(0.95, 0.02);
    const first = verdict(good, { detectorDigest: D1 });
    assert.equal(first.claim.allowed, true);
    const ledger = appendSealedEvaluation(emptyLedger(), { protocolHash: pop.protocol.protocolHash, detectorDigest: D1, sealedTargetIds: pop.protocol.splits.sealed, overall: first.overall, score: good.score });
    assert.equal(verdict(good, { ledger, detectorDigest: D1 }).claim.allowed, true, 'no edit: a re-evaluation is fine');
    const afterEdit = verdict(engine(0.97, 0.01), { ledger, detectorDigest: D2 });
    assert.equal(afterEdit.overall, 'pass', 'the gates themselves would pass');
    assert.equal(afterEdit.claim.allowed, false);
    assert.ok(afterEdit.claim.reasons.includes('fresh-sealed-population-required'));
    assert.equal(afterEdit.claim.consumedSealedTargets.length, pop.protocol.splits.sealed.length);
  });

  test('a FRESH sealed population (different targets) after the edit is allowed; the old result is still retained, flagged evaluation-only', () => {
    const good = engine(0.95, 0.02);
    const ledger = appendSealedEvaluation(emptyLedger(), { protocolHash: pop.protocol.protocolHash, detectorDigest: D1, sealedTargetIds: pop.protocol.splits.sealed, overall: 'pass', score: good.score });
    const fresh = generatedPopulation({ per: 100, prefix: 'fresh' });
    const fg = generatedScore(fresh, {});
    const v = verdict(fg, { ledger, detectorDigest: D2, population: fresh });
    assert.equal(v.overall, 'pass');
    assert.equal(v.claim.allowed, true, JSON.stringify(v.claim.reasons));
    const c = assessReleaseClaim({ ledger, detectorDigest: D2, sealedTargetIds: fresh.protocol.splits.sealed, overall: 'pass' });
    assert.equal(c.retained.length, 1);
    assert.equal(c.retained[0].usage, 'evaluation-only'); assert.equal(c.retained[0].usableForNewClaim, false);
    assert.equal(ledger.entries.length, 1, 'nothing was deleted');
  });

  test('a passing gate without a ledger entry for this detector is not enough once other detectors consumed the same population', () => {
    const ledger = appendSealedEvaluation(emptyLedger(), { protocolHash: 'sha256:' + '9'.repeat(64), detectorDigest: D1, sealedTargetIds: pop.protocol.splits.sealed.slice(0, 5), overall: 'fail' });
    const v = verdict(engine(0.95, 0.02), { ledger, detectorDigest: D2 });
    assert.equal(v.claim.allowed, false);
    assert.ok(v.claim.reasons.includes('fresh-sealed-population-required'));
  });

  test('the detector digest follows the detector source, not the evaluation tooling', () => {
    const root = mkTestTmp('qa7-src-');
    fs.mkdirSync(path.join(root, 'sast')); fs.mkdirSync(path.join(root, 'posture', 'evaluation'), { recursive: true });
    fs.writeFileSync(path.join(root, 'sast', 'rule.js'), 'export const r = 1;\n');
    fs.writeFileSync(path.join(root, 'posture', 'evaluation', 'tool.js'), 'export const t = 1;\n');
    const a = detectorDigestOf(root);
    fs.writeFileSync(path.join(root, 'posture', 'evaluation', 'tool.js'), 'export const t = 2;\n');
    assert.equal(detectorDigestOf(root), a, 'editing the measuring instrument is not a detector edit');
    fs.writeFileSync(path.join(root, 'sast', 'rule.js'), 'export const r = 2;\n');
    assert.notEqual(detectorDigestOf(root), a, 'editing a detector is');
    fs.writeFileSync(path.join(root, 'sast', 'new-rule.js'), 'export const n = 1;\n');
    assert.notEqual(detectorDigestOf(root), detectorDigestOf(root) + 'x');
  });

  test('the ledger is tamper-evident: an edited baseline breaks the chain, and a rebuilt chain does not verify without the custodian signature', () => {
    const good = engine(0.95, 0.02);
    let ledger = appendSealedEvaluation(emptyLedger(), { protocolHash: pop.protocol.protocolHash, detectorDigest: D1, sealedTargetIds: pop.protocol.splits.sealed, overall: 'pass', score: good.score });
    ledger = appendSealedEvaluation(ledger, { protocolHash: pop.protocol.protocolHash, detectorDigest: D2, sealedTargetIds: pop.protocol.splits.sealed, overall: 'pass', score: good.score });
    assert.equal(verifyLedger(ledger).ok, true);
    const weakened = JSON.parse(JSON.stringify(ledger)); weakened.entries[0].baseline.endToEnd.micro.f1 = 0.1;
    assert.equal(verifyLedger(weakened).ok, false);
    assert.equal(verifyLedger(weakened).errors[0].code, 'ENTRY_EDITED');
    const dropped = JSON.parse(JSON.stringify(ledger)); dropped.entries.shift();
    assert.equal(verifyLedger(dropped).ok, false);
    // an attacker who recomputes every hash gets a chain that verifies but a head the custodian never signed
    const signed = signLedger(ledger, PRIV);
    assert.equal(verifySignedLedger(signed, PUB).ok, true);
    let rebuilt = emptyLedger();
    for (const e of weakened.entries) rebuilt = appendSealedEvaluation(rebuilt, { protocolHash: e.protocolHash, detectorDigest: e.detectorDigest, sealedTargetIds: e.sealedTargetIds, overall: e.overall, score: { endToEnd: { micro: { f1: 0.1 }, byLanguage: {} } } });
    assert.equal(verifyLedger(rebuilt).ok, true, 'the chain alone cannot catch this');
    assert.equal(verifySignedLedger({ ...signed, ledger: rebuilt }, PUB).ok, false);
    assert.equal(verifySignedLedger({ ...signed, ledger: rebuilt, head: rebuilt.entries.at(-1).entryHash }, PUB).ok, false, 'a forged head fails the signature');
    const other = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
    assert.equal(verifySignedLedger(signed, other).ok, false);
  });
});

describe('[QA-007.AC03] a lower-quality engine, a failed-target spike, a changed denominator, an answer-key leak or a weakened baseline fails; a genuine improvement passes', () => {
  const D = 'sha256:' + 'a'.repeat(64);
  const baseLedger = (g) => appendSealedEvaluation(emptyLedger(), { protocolHash: pop.protocol.protocolHash, detectorDigest: D, sealedTargetIds: pop.protocol.splits.sealed, overall: 'pass', score: g.score });

  test('a lower-quality engine fails: below the thresholds outright, and above them but below the recorded baseline', () => {
    const baseline = engine(0.97, 0.01);
    const ledger = baseLedger(baseline);
    assert.equal(verdict(baseline, { ledger }).overall, 'pass', 'control: the baseline engine against its own record');
    const below = verdict(engine(0.6, 0.2), { ledger });
    assert.equal(below.overall, 'fail'); assert.equal(statusOf(below, 'pooled-recall'), 'fail');
    const worse = engine(0.9, 0.05); // still over every preregistered threshold
    const regress = verdict(worse, { ledger });
    assert.equal(statusOf(regress, 'overall-micro-f1'), 'pass', 'it clears the preregistered bar');
    assert.equal(statusOf(regress, 'no-regression-vs-baseline'), 'fail');
    assert.equal(regress.overall, 'fail');
    assert.equal(regress.claim.allowed, false);
  });

  test('a failed-target spike fails the completion gate and the misses stay in the end-to-end figures', () => {
    const spike = engine(0.97, 0.01, { status: (t, v) => (v === 'pre' && unitOf(t.id, 'x') < 0.12 ? 'timeout' : 'completed') });
    const v = verdict(spike);
    assert.equal(statusOf(v, 'completion'), 'fail');
    assert.equal(v.overall, 'fail');
    assert.ok(spike.score.misses.some((m) => m.reason === 'timeout'), 'a timeout on a known positive is a miss');
  });

  test('a changed denominator fails: dropping the hard targets from the run, or scoring under another protocol', () => {
    const full = engine(0.9, 0.05);
    // remove every outcome of the targets the engine missed: the figures improve, the denominator changed
    const missed = new Set(full.score.misses.map((m) => m.targetId));
    const dropped = { ...full.run, outcomes: full.run.outcomes.filter((o) => !missed.has(o.targetId)) };
    const droppedScore = (() => { const g = generatedScore(pop, {}); return g; })();
    const rescored = engine(0.9, 0.05, { status: (t) => (missed.has(t.id) ? 'unavailable' : 'completed') });
    const v = evaluateReleaseGates({ protocol: pop.protocol, score: rescored.score, run: dropped, defects: pop.defects, negatives: pop.negatives, ledger: emptyLedger(), detectorDigest: D });
    assert.equal(statusOf(v, 'denominator-intact'), 'fail');
    assert.match(v.gates.find((g) => g.id === 'denominator-intact').reason, /has no (?:pre|post) outcome/);
    assert.ok(droppedScore);
    // a score from another protocol is refused outright
    const other = freezeProtocol({ ...pop.draft, engine: { ...pop.draft.engine, version: '0.0.1-other' } });
    const refused = evaluateReleaseGates({ protocol: other.protocol, score: full.score, run: full.run, defects: pop.defects, negatives: pop.negatives, ledger: emptyLedger(), detectorDigest: D });
    assert.equal(refused.rejected, true); assert.equal(refused.errors[0].code, 'PROTOCOL_MISMATCH');
    // scored positives that do not match the adjudicated sealed positives also fail
    const fewer = generatedPopulation({ per: 100 });
    const g2 = generatedScore({ ...fewer, defects: fewer.defects.slice(0, -5) }, {});
    const v2 = evaluateReleaseGates({ protocol: fewer.protocol, score: g2.score, run: g2.run, defects: fewer.defects, negatives: fewer.negatives, ledger: emptyLedger(), detectorDigest: D });
    assert.equal(statusOf(v2, 'denominator-intact'), 'fail');
  });

  test('an answer-key leak fails the gate whatever the figures are (control: no leak, same figures, passes)', () => {
    assert.equal(verdict(engine(0.97, 0.01)).overall, 'pass');
    const leaky = engine(0.97, 0.01, { quarantine: (t, v) => t.id === 'gen-go-7' && v === 'pre' });
    const v = verdict(leaky);
    assert.equal(statusOf(v, 'answer-key-leaks'), 'fail');
    assert.equal(v.overall, 'fail');
    assert.equal(v.gates.find((g) => g.id === 'answer-key-leaks').measured, 1);
    assert.equal(v.claim.allowed, false);
  });

  test('a weakened baseline fails: an edited ledger entry is rejected, and a protocol with looser thresholds cannot be frozen or judged', () => {
    const good = engine(0.97, 0.01);
    const ledger = baseLedger(good);
    const weakened = JSON.parse(JSON.stringify(ledger)); weakened.entries[0].baseline.endToEnd.micro.f1 = 0.2;
    const r = verdict(engine(0.9, 0.05), { ledger: weakened });
    assert.equal(r.rejected, true); assert.equal(r.errors[0].code, 'LEDGER_TAMPERED');
    const edited = JSON.parse(JSON.stringify(pop.protocol)); edited.thresholds.pooledPrecision = 0.1;
    assert.equal(evaluateGates({ protocol: edited, score: good.score, defects: pop.defects, negatives: pop.negatives }).rejected, true);
  });

  test('a genuine improvement passes, and nothing else changed: same protocol hash, same label set, same thresholds', () => {
    const before = engine(0.9, 0.05);
    const ledger = baseLedger(before);
    const labelsBefore = sealLabels(pop.defects, pop.negatives);
    const after = engine(0.97, 0.01);
    const v = verdict(after, { ledger });
    assert.equal(v.overall, 'pass'); assert.equal(statusOf(v, 'no-regression-vs-baseline'), 'pass');
    assert.equal(v.protocolHash, pop.protocol.protocolHash);
    assert.deepEqual(sealLabels(pop.defects, pop.negatives), labelsBefore, 'no label was edited');
    assert.deepEqual(pop.protocol.thresholds, PREREGISTERED_THRESHOLDS, 'no threshold was edited');
    assert.ok(after.score.endToEnd.micro.f1 > before.score.endToEnd.micro.f1);
  });
});

describe('[QA-007.AC01] the verdict is an aggregate, signed by the custodian, verifiable with the public key alone', () => {
  const g = engine(0.95, 0.02);
  const signed = () => signGateReport(verdict(g), PRIV);

  test('the signed report carries no per-case sealed outcome', () => {
    const text = JSON.stringify(signed());
    for (const needle of ['gen-go-3', 'gen-rust-0', 'dlab:', 'misses', 'falsePositives', 'perTarget']) assert.equal(text.includes(needle), false, needle);
  });

  test('it verifies; tampering with the verdict, the claim or the issuer fails; self-issued trust is stated, never certification', () => {
    const s = signed();
    const ok = verifyGateReport(s, PUB);
    assert.equal(ok.ok, true); assert.equal(ok.overall, 'pass'); assert.equal(ok.trustBasis, 'self-issued-local-key');
    const flip = JSON.parse(JSON.stringify(s)); flip.report.overall = 'pass'; flip.report.gates[0].status = 'pass'; flip.report.gates[0].measured = 0.99;
    assert.equal(verifyGateReport(flip, PUB).ok, false);
    // consistent tampering: edit the verdict AND recompute the (unkeyed) content hash. Only the custodian's signature can catch this.
    const forged = JSON.parse(JSON.stringify(s)); forged.report.claim.allowed = !forged.report.claim.allowed;
    forged.report.reportHash = digestOf({ ...forged.report, reportHash: undefined });
    const fv = verifyGateReport(forged, PUB);
    assert.equal(fv.ok, false); assert.match(fv.reason, /signature/);
    const claim = JSON.parse(JSON.stringify(s)); claim.report.claim.allowed = !claim.report.claim.allowed;
    assert.equal(verifyGateReport(claim, PUB).ok, false);
    const cert = JSON.parse(JSON.stringify(s)); cert.issuance.independentlyCertified = true;
    assert.equal(verifyGateReport(cert, PUB).ok, false);
    const other = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
    assert.equal(verifyGateReport(s, other).ok, false);
    assert.throws(() => signGateReport({ rejected: true }, PRIV), /only an accepted/);
  });

  test('the driver script verifies a signed report and refuses a tampered one (exit 0 / 1)', () => {
    const dir = mkTestTmp('qa7-cli-');
    const s = signed();
    fs.writeFileSync(path.join(dir, 'gate.json'), JSON.stringify(s));
    fs.writeFileSync(path.join(dir, 'pub.pem'), PUB);
    const run = (...a) => spawnSync(process.execPath, [SCRIPT, ...a], { encoding: 'utf8' });
    const good = run('verify-gate', path.join(dir, 'gate.json'), '--public-key', path.join(dir, 'pub.pem'));
    assert.equal(good.status, 0, good.stderr); assert.match(good.stdout, /not independent certification/);
    const bad = JSON.parse(JSON.stringify(s)); bad.report.overall = 'fail';
    fs.writeFileSync(path.join(dir, 'bad.json'), JSON.stringify(bad));
    assert.equal(run('verify-gate', path.join(dir, 'bad.json'), '--public-key', path.join(dir, 'pub.pem')).status, 1);
    const dd = run('detector-digest');
    assert.equal(dd.status, 0); assert.match(dd.stdout.trim(), /^sha256:[0-9a-f]{64}$/);
  });
});
