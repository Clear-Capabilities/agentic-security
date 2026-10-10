// X-606.AC02 and X-606.AC03: finite canary budgets and error thresholds stop a degraded policy and restore the previous known-good policy
// without losing decision receipts; injected degraded quality, provider outage and price changes roll back safely. SYNTHETIC outcomes.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createCanary, CANARY_CEILINGS } from '../../src/posture/routing/canary.js';
import { createReceiptLog, verifyReceiptChain, exportReceipts } from '../../src/posture/routing/receipts.js';
import { buildCalibration } from '../../src/posture/routing/calibration.js';
import { priceBookFromCatalog } from '../../src/posture/routing/economics.js';
import { snapshotRoutingBasis, assessDrift, applyInvalidations, SCHEMA_VERSIONS } from '../../src/posture/routing/drift.js';
import { syntheticPopulation, taskOf, outcomeOf, BASE_CONFIG } from '../helpers/routing-fixtures.js';

const KNOWN = { policyVersion: 'policy-known-good' }; const NEXT = { policyVersion: 'policy-candidate' };
const LIMITS = Object.freeze({ maxTasks: 50, budgetUsd: 1, perCallUsdCeiling: 0.05, maxErrorRate: 0.2, minSamples: 10, maxConsecutiveErrors: 4, maxIncorrectRate: 0.3, minDecided: 10 });
const CLOCK = () => '2026-06-01T00:00:00Z';
const out = (i, o = {}) => outcomeOf({ task: taskOf(i), model: 'model-cand', correct: true, costUsd: 0.01, ...o });
const bad = (i) => out(i, { correct: false });
const down = (i) => out(i, { correct: null, status: 'provider-error', costUsd: null });
function started(over = {}) {
  const log = createReceiptLog({ now: CLOCK });
  const r = createCanary({ knownGood: KNOWN, candidate: NEXT, limits: { ...LIMITS, ...over.limits }, canaryShare: over.share ?? 0.5, log });
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  assert.equal(r.canary.start({ shadowRecords: 3 }).ok, true);
  return { c: r.canary, log };
}

describe('[X-606.AC02] a canary is finite by construction', () => {
  test('limits are mandatory and bounded: no unbounded canary can be created', () => {
    for (const bad of [undefined, {}, { ...LIMITS, maxTasks: Infinity }, { ...LIMITS, budgetUsd: Infinity }, { ...LIMITS, budgetUsd: 0 }, { ...LIMITS, maxTasks: CANARY_CEILINGS.maxTasks + 1 }, { ...LIMITS, perCallUsdCeiling: undefined }, { ...LIMITS, maxErrorRate: 2 }]) {
      assert.equal(createCanary({ knownGood: KNOWN, candidate: NEXT, limits: bad }).ok, false);
    }
    assert.equal(createCanary({ knownGood: KNOWN, candidate: NEXT, limits: LIMITS }).ok, true);
  });

  test('a canary cannot start without a recorded shadow decision, and starts only from shadow', () => {
    const c = createCanary({ knownGood: KNOWN, candidate: NEXT, limits: LIMITS }).canary;
    assert.equal(c.start({ shadowRecords: 0 }).code, 'NO_SHADOW_EVIDENCE');
    assert.equal(c.state(), 'shadow');
    assert.equal(c.start({ shadowRecords: 2 }).ok, true);
    assert.equal(c.start({ shadowRecords: 2 }).code, 'BAD_STATE');
  });

  test('before the canary starts, the known-good policy serves every task', () => {
    const c = createCanary({ knownGood: KNOWN, candidate: NEXT, limits: LIMITS, canaryShare: 1 }).canary;
    assert.equal(c.select('t-1').arm, 'known-good');
    assert.equal(c.activePolicy(), KNOWN);
  });
});

describe('[X-606.AC02] healthy canary: no trip, finite window, promotion still needs the gate', () => {
  test('a healthy window completes without rollback, then stops sending traffic to the candidate', () => {
    const { c } = started({ limits: { maxTasks: 20 } });
    for (let i = 0; i < 20; i++) assert.equal(c.observe({ taskId: `t${i}`, outcome: out(i) }).ok, true);
    assert.equal(c.state(), 'canary-complete');
    assert.equal(c.rollbackInfo(), null);
    assert.equal(c.select('anything').arm, 'known-good', 'the candidate gets no more traffic once its window is spent');
    assert.equal(c.observe({ taskId: 'x', outcome: out(99) }).code, 'NOT_IN_CANARY');
  });

  test('a canary that did not fail is not promoted: activation needs a passing promotion verdict', () => {
    const { c } = started({ limits: { maxTasks: 12 } });
    for (let i = 0; i < 12; i++) c.observe({ taskId: `t${i}`, outcome: out(i) });
    for (const verdict of [null, { status: 'unmeasured' }, { status: 'insufficient-population' }, { status: 'fail' }, { status: 'invalid' }]) {
      assert.equal(c.activate(verdict).code, 'NOT_PROMOTED');
      assert.equal(c.activePolicy(), KNOWN);
    }
    assert.equal(c.activate({ status: 'pass', verdictHash: 'sha256:v' }).ok, true);
    assert.equal(c.state(), 'active');
    assert.equal(c.activePolicy(), NEXT);
    assert.equal(c.select('t').arm, 'candidate');
  });

  test('traffic share is deterministic and roughly the requested fraction', () => {
    const { c } = started({ share: 0.25 });
    const picks = Array.from({ length: 400 }, (_, i) => c.select(`task-${i}`).arm);
    const share = picks.filter((a) => a === 'candidate').length / 400;
    assert.ok(share > 0.15 && share < 0.35, `share ${share}`);
    assert.deepEqual(picks, Array.from({ length: 400 }, (_, i) => c.select(`task-${i}`).arm));
  });
});

describe('[X-606.AC02] finite budgets and error thresholds stop a degraded policy and restore the known-good policy', () => {
  test('exhausting the canary budget stops the candidate and restores the known-good policy', () => {
    const { c } = started({ limits: { budgetUsd: 0.1 } });
    let last;
    for (let i = 0; i < 20 && c.state() === 'canary'; i++) last = c.observe({ taskId: `t${i}`, outcome: out(i, { costUsd: 0.03 }) });
    assert.equal(c.state(), 'rolled-back');
    assert.equal(last.tripped, 'budget-exhausted');
    assert.equal(c.activePolicy(), KNOWN);
    assert.equal(c.rollbackInfo().restored, 'policy-known-good');
    assert.equal(c.select('any').arm, 'known-good');
    assert.equal(c.observe({ taskId: 'late', outcome: out(77) }).code, 'NOT_IN_CANARY', 'a degraded policy cannot keep accruing');
  });

  test('an outcome with an unknown cost is charged at the per-call ceiling, so the budget trips sooner than a zero would allow', () => {
    const { c } = started({ limits: { budgetUsd: 0.2, perCallUsdCeiling: 0.05 } });
    for (let i = 0; i < 6 && c.state() === 'canary'; i++) c.observe({ taskId: `t${i}`, outcome: out(i, { costUsd: null }) });
    assert.equal(c.state(), 'rolled-back');
    assert.equal(c.rollbackInfo().code, 'budget-exhausted');
    assert.ok(c.counters().spentUsd >= 0.2);
  });

  test('the candidate is not selected once another call could overrun the remaining budget', () => {
    const { c } = started({ share: 1, limits: { budgetUsd: 0.12, perCallUsdCeiling: 0.05 } });
    assert.equal(c.select('a').arm, 'candidate');
    c.observe({ taskId: 'a', outcome: out(1, { costUsd: 0.04 }) });
    c.observe({ taskId: 'b', outcome: out(2, { costUsd: 0.04 }) });
    assert.equal(c.select('c').arm, 'known-good', '0.08 spent + 0.05 ceiling would exceed 0.12');
    assert.equal(c.state(), 'canary', 'stopped selecting before overspending, not by overspending');
  });

  test('an error rate over its threshold rolls back, but not before the minimum sample', () => {
    const { c } = started();
    for (let i = 0; i < 4; i++) c.observe({ taskId: `e${i}`, outcome: i % 2 ? out(i) : down(i) });
    assert.equal(c.state(), 'canary', 'four samples are under minSamples (10)');
    for (let i = 4; i < 20 && c.state() === 'canary'; i++) c.observe({ taskId: `e${i}`, outcome: i % 2 ? out(i) : down(i) });
    assert.equal(c.state(), 'rolled-back');
    assert.equal(c.rollbackInfo().code, 'error-rate');
  });

  test('a rolled-back canary keeps every receipt and the chain still verifies', () => {
    const { c, log } = started({ limits: { maxIncorrectRate: 0.3 } });
    for (let i = 0; i < 10; i++) c.observe({ taskId: `ok${i}`, outcome: out(i) });
    const before = log.entries();
    for (let i = 10; i < 40 && c.state() === 'canary'; i++) c.observe({ taskId: `bad${i}`, outcome: bad(i) });
    assert.equal(c.state(), 'rolled-back');
    const after = log.entries();
    assert.ok(after.length > before.length);
    assert.deepEqual(after.slice(0, before.length).map((r) => r.hash), before.map((r) => r.hash), 'no earlier receipt was changed or removed');
    assert.equal(after.at(-1).kind, 'rollback');
    assert.equal(after.at(-1).body.restored, 'policy-known-good');
    assert.equal(verifyReceiptChain(after).ok, true);
    const exported = exportReceipts(log);
    assert.equal(verifyReceiptChain(exported.receipts).ok, true);
    assert.ok(exported.byKind.canary >= 11 && exported.byKind.rollback === 1);
  });

  test('a receipt chain that lost, reordered or edited a record fails verification', () => {
    const { c, log } = started();
    for (let i = 0; i < 5; i++) c.observe({ taskId: `t${i}`, outcome: out(i) });
    const r = log.entries();
    assert.equal(verifyReceiptChain(r).ok, true);
    assert.equal(verifyReceiptChain([r[0], ...r.slice(2)]).ok, false, 'missing');
    assert.equal(verifyReceiptChain([r[1], r[0], ...r.slice(2)]).ok, false, 'reordered');
    const edited = JSON.parse(JSON.stringify(r)); edited[2].body.costUsd = 0;
    assert.equal(verifyReceiptChain(edited).ok, false, 'edited');
    assert.equal(verifyReceiptChain(r.slice(0, -1)).ok, true, 'a truncated tail is detectable only against the exported head');
    assert.notEqual(exportReceipts({ entries: () => r.slice(0, -1), head: () => r.at(-2).hash }).headHash, log.head());
  });
});

describe('[X-606.AC03] injected degraded quality, provider outage and price changes roll back safely and invalidate stale estimates', () => {
  test('degraded quality: a run of incorrect answers trips degraded-quality and restores the known-good policy', () => {
    const { c } = started();
    for (let i = 0; i < 40 && c.state() === 'canary'; i++) c.observe({ taskId: `t${i}`, outcome: i % 2 ? bad(i) : out(i) });
    assert.equal(c.state(), 'rolled-back');
    assert.equal(c.rollbackInfo().code, 'degraded-quality');
    assert.equal(c.activePolicy(), KNOWN);
  });

  test('degraded quality is not mistaken for noise below the minimum decided count', () => {
    const { c } = started();
    for (let i = 0; i < 5; i++) c.observe({ taskId: `t${i}`, outcome: bad(i) });
    assert.equal(c.state(), 'canary');
  });

  test('provider outage: consecutive provider errors trip an outage immediately, long before the error-rate sample', () => {
    const { c } = started();
    for (let i = 0; i < 4; i++) c.observe({ taskId: `t${i}`, outcome: down(i) });
    assert.equal(c.state(), 'rolled-back');
    assert.equal(c.rollbackInfo().code, 'provider-outage');
    assert.equal(c.counters().candidateTasks, 4);
  });

  test('a single error between successes resets the outage run', () => {
    const { c } = started();
    for (let i = 0; i < 12; i++) c.observe({ taskId: `t${i}`, outcome: i % 6 === 3 ? down(i) : out(i) });
    assert.equal(c.state(), 'canary', '2 errors in 12 (17%) is under the 0.2 rate threshold and never 4 in a row');
  });

  test('price change: drift invalidates the stale cost estimates, and the canary is rolled back by the drift report', () => {
    const book = priceBookFromCatalog();
    const pop = syntheticPopulation({ dev: 60, held: 240, models: [{ id: 'claude-haiku-4-5', version: '1', acc: 0.9, costUsd: 0.002 }, { id: 'claude-opus-4-8', version: '1', acc: 0.95, costUsd: 0.08 }] });
    const cal = buildCalibration({ outcomes: pop.outcomes, config: { ...BASE_CONFIG, baselineModel: 'claude-opus-4-8' } }).artifact;
    const models = [{ id: 'claude-haiku-4-5', modelVersion: '1' }, { id: 'claude-opus-4-8', modelVersion: '1' }];
    const basis = snapshotRoutingBasis({ calibration: cal, priceBook: book, models });
    const repriced = { ...book, version: 'catalog-v2', entries: { ...book.entries, 'claude-haiku-4-5': { ...book.entries['claude-haiku-4-5'], in: book.entries['claude-haiku-4-5'].in * 10 } } };
    const { c, log } = started();
    for (let i = 0; i < 6; i++) c.observe({ taskId: `t${i}`, outcome: out(i) });
    const healthy = assessDrift({ basis, current: { models, priceBook: book, schemas: SCHEMA_VERSIONS } });
    assert.equal(c.reportDrift(healthy).rolledBack, false);
    assert.equal(c.state(), 'canary');
    const drifted = assessDrift({ basis, current: { models, priceBook: repriced, schemas: SCHEMA_VERSIONS } });
    assert.equal(drifted.state, 'fallback');
    assert.equal(c.reportDrift(drifted).rolledBack, true);
    assert.equal(c.state(), 'rolled-back');
    assert.equal(c.rollbackInfo().code, 'drift-invalidation');
    assert.equal(c.activePolicy(), KNOWN);
    const stale = applyInvalidations(cal, drifted).estimates.filter((e) => e.model === 'claude-haiku-4-5');
    assert.ok(stale.length > 0 && stale.every((e) => e.costUsd.invalidated === true), 'every stale cost estimate is explicitly invalidated');
    assert.equal(verifyReceiptChain(log.entries()).ok, true);
  });

  test('price change: costs that jump past the canary budget stop it too', () => {
    const { c } = started({ limits: { budgetUsd: 0.5 } });
    for (let i = 0; i < 5; i++) c.observe({ taskId: `a${i}`, outcome: out(i, { costUsd: 0.01 }) });
    assert.equal(c.state(), 'canary');
    c.observe({ taskId: 'b', outcome: out(6, { costUsd: 0.6 }) });
    assert.equal(c.state(), 'rolled-back');
    assert.equal(c.rollbackInfo().code, 'budget-exhausted');
  });

  test('a rollback by drift is idempotent and an already rolled-back canary is not rolled back twice', () => {
    const { c, log } = started();
    const drifted = { state: 'fallback', unchanged: false, kinds: ['pricing'], invalidations: [{ kind: 'pricing' }] };
    c.reportDrift(drifted);
    const n = log.length;
    assert.equal(c.reportDrift(drifted).already, true);
    assert.equal(log.length, n);
  });
});
