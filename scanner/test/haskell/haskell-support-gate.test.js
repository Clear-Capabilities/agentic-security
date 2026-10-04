// HS-011: Haskell capability promotion and coverage disclosure. Tests are tagged [HS-011.ACnn].
// The registry (docs/language-support.json) is produced by `node bench/language-support/promote.mjs` from the frozen holdout and
// the capability test suites. These tests check what it says, and that nothing can be promoted except from passing evidence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { evaluateSupport, checkPromotion, verifyRegistry, gateLayer, TARGETS, REQUIRED_CAPABILITIES, NON_PROMOTING_EVIDENCE } from '../../src/language/support-registry.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..', '..');
const DATA = path.join(HERE, '..', 'language', 'corpora', 'data');
const registry = JSON.parse(fs.readFileSync(path.join(REPO, 'docs', 'language-support.json'), 'utf8'));
const holdout = JSON.parse(fs.readFileSync(path.join(REPO, 'bench', 'language-support', 'results', 'holdout.json'), 'utf8'));
const suites = JSON.parse(fs.readFileSync(path.join(REPO, 'bench', 'language-support', 'results', 'suites.json'), 'utf8'));
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const manifest = JSON.parse(fs.readFileSync(path.join(DATA, 'manifest.json'), 'utf8'));
const frozen = () => ({ holdoutRollup: manifest.holdoutRollup, labelsSha256: sha(fs.readFileSync(path.join(DATA, 'labels', 'cases.json'), 'utf8')), privacyLabelsSha256: sha(fs.readFileSync(path.join(DATA, 'labels', 'privacy.json'), 'utf8')) });
const haskell = registry.languages.haskell;
const evalHs = (over = {}) => evaluateSupport('haskell', { measurement: holdout, suites: suites.results, capabilitySuites: suites.capabilitySuites.haskell, frozen: frozen(), tools: suites.tools, ...over });
const clone = (x) => JSON.parse(JSON.stringify(x));

test('[HS-011.AC01] SAST, security-taint and privacy field-to-sink each meet the section 9 targets on the frozen holdout, with matrices, denominators and hashes', () => {
  assert.equal(holdout.split, 'holdout');
  for (const cap of ['sast', 'taint', 'privacy-lineage']) {
    const r = haskell.rows[cap];
    assert.ok(r, cap);
    assert.equal(r.status, 'supported', `${cap}: ${r.status} ${(r.reasons || []).join('; ')}`);
    const e = r.evidence;
    for (const k of ['tp', 'fp', 'fn']) assert.ok(Number.isInteger(e[k]), `${cap}: confusion count ${k}`);
    assert.ok(e.tp + e.fn > 0 && (e.tn === undefined || e.tn >= 0), `${cap}: a nonzero positive denominator`);
    assert.ok(e.precision >= TARGETS.precision && e.recall >= TARGETS.recall && e.f1 >= TARGETS.f1, `${cap}: P/R/F1 meet ${JSON.stringify(TARGETS)}`);
  }
  // every scored family meets its own F1 gate, and the holdout has >=5 vulnerable and >=5 safe per family
  const layers = holdout.ecosystems.haskell.detection.layers;
  for (const layer of Object.values(layers)) for (const [fam, m] of Object.entries(layer.families)) assert.ok(m.f1 >= TARGETS.perFamilyF1, `${fam} F1`);
  for (const [fam, c] of Object.entries(holdout.ecosystems.haskell.detection.perFamilyCases)) assert.ok(c.vulnerable >= 5 && c.safe >= 5, `${fam}: ${c.vulnerable}/${c.safe}`);
  // the measurement names the data it ran on: the same hashes the corpus has now
  assert.deepEqual({ h: holdout.hashes.holdoutRollup, l: holdout.hashes.labelsSha256, p: holdout.hashes.privacyLabelsSha256 }, { h: frozen().holdoutRollup, l: frozen().labelsSha256, p: frozen().privacyLabelsSha256 });
  assert.deepEqual(haskell.frozen.holdoutRollup, frozen().holdoutRollup);
});

test('[HS-011.AC01] the three layers are measured independently and never combined', () => {
  assert.ok(holdout.ecosystems.haskell.detection.layers.sast && holdout.ecosystems.haskell.detection.layers.taint);
  assert.ok(holdout.ecosystems.haskell.privacy, 'privacy is its own measurement');
  assert.notDeepEqual(haskell.rows.sast.evidence.tp + haskell.rows.sast.evidence.fn, haskell.rows['privacy-lineage'].evidence.tp + haskell.rows['privacy-lineage'].evidence.fn, 'different denominators: privacy is not the taint or SAST metric');
  assert.ok(!('combined' in holdout.ecosystems.haskell.detection));
});

test('[HS-011.AC02] every required Haskell capability has passing evidence (an unavailable compiler is a failed criterion, never a skip)', () => {
  const missing = Object.keys(REQUIRED_CAPABILITIES.haskell).filter((cap) => !haskell.rows[cap] || haskell.rows[cap].status !== 'supported');
  assert.deepEqual(missing.map((c) => `${c}: ${haskell.rows[c] ? haskell.rows[c].status : 'absent'}${haskell.rows[c] && haskell.rows[c].reasons.length ? ` (${haskell.rows[c].reasons[0]})` : ''}`), [], 'every required capability must be supported');
});

test('[HS-011.AC02] partial SCA resolution in user projects is disclosed without weakening the complete supported-fixture gate', () => {
  const cases = holdout.supply.manifests;
  assert.equal(cases.exact, cases.total, 'the supported explicit-export fixtures stay at 100% exact');
  assert.ok(cases.total >= 24, 'cabal, freeze and stack fixtures');
  assert.ok(registry.limits.some((l) => /real-project accuracy is NOT measured/i.test(l)));
  // a declared-ranges project (no freeze, no plan) is reported as declared ranges, not as a resolved graph
  const supplyEvidence = haskell.rows.sca.evidence;
  assert.match(String(supplyEvidence.manifests), /^\d+\/\d+$/);
});

test('[HS-011.AC03] a row cannot be promoted from an installed parser, a structural-only detection, a taint metric used as privacy, or changed labels', () => {
  const ev = evalHs();
  const prop = (cap, evidence) => checkPromotion('haskell', cap, 'supported', evidence, ev);
  for (const bad of ['installation', 'grammar-present', 'structural-only', 'documentation', 'model-assertion']) {
    assert.ok(NON_PROMOTING_EVIDENCE.includes(bad));
    assert.equal(prop('parser', { metric: bad }).ok, false, bad);
  }
  assert.equal(prop('privacy-lineage', { metric: 'taint-holdout' }).ok, false, 'a taint metric is not a privacy metric');
  assert.equal(prop('taint', { metric: 'sast-holdout' }).ok, false, 'a structural SAST metric is not a taint metric');
  assert.equal(prop('sast', undefined).ok, false);
  // the right kind of evidence still has to agree with the measurement
  const rightKind = prop('parser', { metric: REQUIRED_CAPABILITIES.haskell.parser });
  assert.equal(rightKind.ok, ev.rows.parser.status === 'supported');

  // changed benchmark labels: the measurement was taken on other data, so nothing is supported from it
  const tampered = evalHs({ frozen: { ...frozen(), labelsSha256: 'f'.repeat(64) } });
  for (const cap of ['sast', 'taint', 'privacy-lineage']) assert.notEqual(tampered.rows[cap].status, 'supported', `${cap} under changed labels`);
  assert.match(tampered.rows.sast.reasons.join(' '), /changed benchmark labels/);
  const otherSplit = evalHs({ measurement: { ...holdout, split: 'validation' } });
  assert.notEqual(otherSplit.rows.sast.status, 'supported');
  assert.match(otherSplit.rows.sast.reasons.join(' '), /not the frozen holdout/);
  // a stored registry is demoted when the corpus it was measured on has changed
  assert.equal(verifyRegistry(registry, frozen()).ok, true);
  const stale = verifyRegistry(registry, { ...frozen(), holdoutRollup: '0'.repeat(64) });
  assert.equal(stale.ok, false);
  assert.ok(stale.stale.some((s) => s.field === 'holdoutRollup'));
});

test('[HS-011.AC03] a zero or absent denominator is never 100%, a failing target stays failed, and a skipped suite is not a pass', () => {
  assert.equal(gateLayer({ measured: false }, {}, { kind: 'taint' }).ok, false);
  assert.equal(gateLayer(null, {}, { kind: 'taint' }).ok, false);
  const weak = { measured: true, tp: 8, fp: 2, fn: 4, tn: 10, precision: 0.8, recall: 0.667, f1: 0.727, families: { a: { f1: 0.9 }, b: { f1: 0.5 } } };
  const g = gateLayer(weak, { a: { vulnerable: 5, safe: 5 }, b: { vulnerable: 2, safe: 5 } }, { kind: 'taint' });
  assert.equal(g.ok, false);
  assert.ok(g.reasons.some((r) => /precision/.test(r)) && g.reasons.some((r) => /recall/.test(r)) && g.reasons.some((r) => /family b/.test(r)));
  assert.ok(g.reasons.some((r) => /holdout has 2 vulnerable/.test(r)), 'a family without enough holdout examples cannot pass');
  const skipped = clone(suites.results);
  const name = Object.keys(skipped)[0];
  skipped[name].skipped = 1;
  const ev = evaluateSupport('haskell', { measurement: holdout, suites: skipped, capabilitySuites: suites.capabilitySuites.haskell, frozen: frozen() });
  const caps = Object.entries(suites.capabilitySuites.haskell).filter(([, files]) => files.some((f) => f.endsWith(name))).map(([c]) => c);
  for (const c of caps) assert.notEqual(ev.rows[c].status, 'supported', `${c} with a skipped test`);
});

test('[HS-011.AC03] no capability row is hand-written: the stored registry equals the evaluation of its own inputs', () => {
  const ev = evalHs();
  for (const [cap, row] of Object.entries(haskell.rows)) {
    const re = ev.rows[cap];
    // promote.mjs may demote a row after checkPromotion; it never promotes one the evaluation did not support
    if (row.status === 'supported') assert.equal(re.status, 'supported', cap);
    else assert.notEqual(re.status, 'supported', `${cap}: evaluated ${re.status}, stored ${row.status}`);
  }
});
