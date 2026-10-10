// X-606.AC01 (and the drift half of AC03): model-version, pricing, schema and measured-quality shifts invalidate the affected calibration
// explicitly and send the policy to a documented fallback or shadow state. SYNTHETIC calibration (test/helpers/routing-fixtures.js).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildCalibration } from '../../src/posture/routing/calibration.js';
import { candidateFromCatalog, routeConstrained } from '../../src/posture/routing/decide.js';
import { priceBookFromCatalog } from '../../src/posture/routing/economics.js';
import { snapshotRoutingBasis, assessDrift, applyInvalidations, SCHEMA_VERSIONS, DRIFT_KINDS } from '../../src/posture/routing/drift.js';
import { routeUnderDrift } from '../../src/posture/routing/canary.js';
import { createShadowRecorder } from '../../src/posture/routing/shadow.js';
import { syntheticPopulation, taskOf, outcomeOf, BASE_CONFIG } from '../helpers/routing-fixtures.js';

const book = priceBookFromCatalog();
const LOCAL = 'http://127.0.0.1:11434';
const NOW = '2026-06-01T00:00:00Z';
const HAIKU = 'claude-haiku-4-5'; const OPUS = 'claude-opus-4-8';
const CAPS = ['code-reasoning', 'tool-use'];
const POP = syntheticPopulation({ dev: 60, held: 240, models: [{ id: HAIKU, version: '1', acc: 0.9, costUsd: 0.002, latencyMs: 2000 }, { id: OPUS, version: '1', acc: 0.95, costUsd: 0.08, latencyMs: 900 }] });
const CAL = buildCalibration({ outcomes: POP.outcomes, config: { ...BASE_CONFIG, baselineModel: OPUS } }).artifact;
const MODELS = [{ id: HAIKU, modelVersion: '1' }, { id: OPUS, modelVersion: '1' }];
const BASIS = snapshotRoutingBasis({ calibration: CAL, priceBook: book, models: MODELS });
const POLICY = Object.freeze({ version: 'policy-1', minQualityLower: 0.8, maxIntervalWidth: 0.2, maxEvidenceAgeDays: 90, objective: 'cost', budget: { remainingUsd: 1 }, expectedOutputTokens: 500 });
const CURRENT = (o = {}) => ({ models: MODELS, priceBook: book, schemas: SCHEMA_VERSIONS, ...o });
const cand = (id, version = '1') => candidateFromCatalog({ id, provider: 'provider-a', modelVersion: version, priceBook: book, capabilities: CAPS, maxContextTokens: 200_000, endpoint: LOCAL });
const task = taskOf(1, { requiredCapabilities: CAPS });
const route = (calibration, o = {}) => routeConstrained({ task, candidates: [cand(HAIKU), cand(OPUS)], calibration, policy: POLICY, now: NOW, baselineRoute: { model: OPUS }, egress: () => ({ allowed: true }), allowSynthetic: true, ...o });
const repriced = (id, factor) => ({ ...book, version: 'catalog-v2', entries: { ...book.entries, [id]: { ...book.entries[id], in: book.entries[id].in * factor, out: book.entries[id].out * factor } } });
const strat = task.stratum;
const recent = (n, correct, model = HAIKU) => Array.from({ length: n }, (_, i) => outcomeOf({ task: taskOf(1000 + i, { requiredCapabilities: CAPS }), model, correct: i < correct, observedAt: '2026-05-20T00:00:00Z' }));

describe('[X-606.AC01] nothing has moved: the basis stays active', () => {
  test('an unchanged world, with healthy recent outcomes, invalidates nothing', () => {
    const a = assessDrift({ basis: BASIS, current: CURRENT(), recentOutcomes: recent(60, 55) });
    assert.equal(a.state, 'active');
    assert.equal(a.unchanged, true);
    assert.deepEqual(a.invalidations, []);
  });
});

describe('[X-606.AC01] model-version, pricing, schema and measured-quality shifts invalidate affected calibration and trigger fallback or shadow', () => {
  test('a new model version invalidates that model only, and the documented fallback state applies', () => {
    const a = assessDrift({ basis: BASIS, current: CURRENT({ models: [{ id: HAIKU, modelVersion: '2' }, { id: OPUS, modelVersion: '1' }] }) });
    assert.equal(a.state, 'fallback');
    assert.deepEqual(a.invalidations.filter((i) => i.kind === 'model-version').map((i) => i.model), [HAIKU]);
    assert.match(a.documentedFallback, /existing capability route stands/);
    const d = applyInvalidations(CAL, a);
    assert.ok(d.estimates.filter((e) => e.model === HAIKU).every((e) => e.label === 'invalidated' && /model-version/.test(e.reasons[0])));
    assert.ok(d.estimates.filter((e) => e.model === OPUS).every((e) => e.label === 'reliable-synthetic'), 'the other model is untouched');
  });

  test('a model that is no longer offered is invalidated, and an unreported version counts as a change', () => {
    const gone = assessDrift({ basis: BASIS, current: CURRENT({ models: [{ id: OPUS, modelVersion: '1' }] }) });
    assert.ok(gone.invalidations.some((i) => i.model === HAIKU && /no longer offered/.test(i.reason)));
    const unreported = assessDrift({ basis: BASIS, current: CURRENT({ models: [{ id: HAIKU, modelVersion: null }, { id: OPUS, modelVersion: '1' }] }) });
    assert.ok(unreported.invalidations.some((i) => i.kind === 'model-version' && i.model === HAIKU));
  });

  test('a price change invalidates the measured COST of that model, not its quality, and decisions fall back to the catalog bound', () => {
    const a = assessDrift({ basis: BASIS, current: CURRENT({ priceBook: repriced(HAIKU, 5) }) });
    assert.equal(a.state, 'fallback');
    assert.deepEqual(a.invalidations.map((i) => `${i.kind}:${i.model}`), [`pricing:${HAIKU}`]);
    const d = applyInvalidations(CAL, a);
    const e = d.estimates.find((x) => x.model === HAIKU && x.stratum === strat);
    assert.equal(e.costUsd.invalidated, true);
    assert.equal(e.costUsd.p50, null);
    assert.equal(e.label, 'reliable-synthetic', 'quality evidence still stands');
    assert.equal(route(CAL).selected.model, HAIKU);
    assert.equal(route(CAL).expectedBounds.costUsd.basis, 'measured-median');
    const after = route(d);
    const haiku = after.candidates.find((c) => c.model === HAIKU);
    assert.equal(haiku.expectedCost.basis, 'catalog-upper-bound', 'the stale measured median is no longer used');
    assert.equal(haiku.expectedCost.measuredP50Usd, null);
    assert.equal(after.selected.model, OPUS, 'a candidate with no valid measured cost ranks behind one that has it');
  });

  test('a schema change invalidates every estimate and its cost', () => {
    const a = assessDrift({ basis: BASIS, current: CURRENT({ schemas: { ...SCHEMA_VERSIONS, outcome: 'agentic-security/routing-outcome-v2' } }) });
    assert.ok(a.invalidations.some((i) => i.kind === 'schema'));
    const d = applyInvalidations(CAL, a);
    assert.equal(d.invalidatedAll, true);
    assert.ok(d.estimates.every((e) => e.label === 'invalidated'));
    const decision = route(d);
    assert.notEqual(decision.status, 'routed', 'nothing is routed on invalidated evidence');
    assert.equal(decision.status, 'fallback', 'the existing route stands, with its quality marked unverified');
    assert.equal(decision.fallback.qualityVerified, false);
  });

  test('a measured quality shift invalidates that model and stratum; too few recent outcomes does not', () => {
    const bad = assessDrift({ basis: BASIS, current: CURRENT(), recentOutcomes: recent(60, 30) });
    assert.deepEqual(bad.invalidations.map((i) => i.kind), ['quality-shift']);
    assert.equal(bad.invalidations[0].stratum, strat);
    const few = assessDrift({ basis: BASIS, current: CURRENT(), recentOutcomes: recent(12, 3) });
    assert.equal(few.state, 'active', 'twelve outcomes cannot show a shift');
    const d = applyInvalidations(CAL, bad);
    const e = d.estimates.find((x) => x.model === HAIKU && x.stratum === strat);
    assert.equal(e.label, 'invalidated');
    const decision = route(d);
    assert.notEqual(decision.selected?.model, HAIKU);
    assert.ok(decision.candidates.find((c) => c.model === HAIKU).rejections.some((r) => r.code === 'not-reliable:invalidated'));
  });

  test('the derived calibration records what it came from and leaves the original untouched', () => {
    const a = assessDrift({ basis: BASIS, current: CURRENT({ priceBook: repriced(HAIKU, 5) }) });
    const before = JSON.stringify(CAL);
    const d = applyInvalidations(CAL, a);
    assert.equal(JSON.stringify(CAL), before);
    assert.equal(d.derivedFrom, CAL.calibrationHash);
    assert.notEqual(d.calibrationHash, CAL.calibrationHash);
    assert.equal(d.invalidations.length, 1);
  });

  test('shadow can be chosen as the documented state, and every drift kind is named', () => {
    const a = assessDrift({ basis: BASIS, current: CURRENT({ priceBook: repriced(OPUS, 2) }), policy: { onInvalidation: 'shadow' } });
    assert.equal(a.state, 'shadow');
    assert.match(a.documentedFallback, /^shadow/);
    assert.deepEqual([...DRIFT_KINDS].sort(), ['model-version', 'pricing', 'quality-shift', 'schema']);
  });

  test('a snapshot edited after the fact fails closed', () => {
    const forged = { ...BASIS, models: { ...BASIS.models, [HAIKU]: '9' } };
    const a = assessDrift({ basis: forged, current: CURRENT() });
    assert.notEqual(a.state, 'active');
    assert.match(a.invalidations[0].reason, /own hash/);
  });

  test('the route follows the state: fallback keeps production, shadow records and keeps production, active decides', () => {
    const production = { model: OPUS };
    const args = { task, candidates: [cand(HAIKU), cand(OPUS)], calibration: CAL, policy: POLICY, now: NOW, egress: () => ({ allowed: true }), allowSynthetic: true, productionRoute: production };
    const fb = routeUnderDrift({ ...args, assessment: { state: 'fallback', documentedFallback: 'fallback: x' } });
    assert.equal(fb.route, production);
    assert.equal(fb.decision, undefined, 'no constrained decision is made while in fallback');
    const rec = createShadowRecorder();
    const sh = routeUnderDrift({ ...args, assessment: { state: 'shadow', documentedFallback: 'shadow: x' }, recorder: rec });
    assert.equal(sh.route, production);
    assert.equal(rec.records().length, 1);
    assert.equal(sh.shadow.proposed.model, HAIKU);
    const act = routeUnderDrift({ ...args, assessment: { state: 'active' } });
    assert.equal(act.route.model, HAIKU);
    assert.equal(act.decision.status, 'routed');
  });
});

describe('[X-606.AC03] injected price changes and degraded quality give explicit invalidation of stale estimates', () => {
  test('a price change plus a quality drop on the same model invalidates both aspects, with a reason for each', () => {
    const a = assessDrift({ basis: BASIS, current: CURRENT({ priceBook: repriced(HAIKU, 3) }), recentOutcomes: recent(60, 30) });
    assert.deepEqual(a.kinds, ['pricing', 'quality-shift']);
    const d = applyInvalidations(CAL, a);
    const e = d.estimates.find((x) => x.model === HAIKU && x.stratum === strat);
    assert.deepEqual(e.invalidatedBy, ['pricing', 'quality-shift']);
    assert.equal(e.costUsd.invalidated, true);
    assert.equal(e.label, 'invalidated');
    assert.ok(e.reasons.every((r) => typeof r === 'string' && r.length > 0));
  });
});
