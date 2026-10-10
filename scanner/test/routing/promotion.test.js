// X-605.AC03: promotion needs the PRD section 5 routing gate over sufficient paired evidence; cherry-picked tasks, dropped failures and
// unbounded replay invalidate it. Scenarios are GENERATED (test/helpers/routing-promotion-fixtures.js). `synthetic: false` in a scenario
// is a way to reach the non-synthetic branches of a gate that must refuse synthetic data; it is NOT a measurement of any model, and
// a `pass` below says only that the arithmetic and the guards behave.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { replayPaired, evaluatePromotion, freezeTaskSet } from '../../src/posture/routing/promotion.js';
import { createReceiptLog, verifyReceiptChain } from '../../src/posture/routing/receipts.js';
import { ROUTING_MINIMUMS, ROUTING_PROMOTION_TARGETS } from '../../src/posture/routing/calibration.js';
import { pairedScenario, BASE, CAND } from '../helpers/routing-promotion-fixtures.js';
import { outcomeOf } from '../helpers/routing-fixtures.js';

async function judge(s, { outcomes = s.outcomes, frozen = s.frozen, mutateReplay = null, log = null } = {}) {
  const r = await replayPaired({ frozen: s.frozen, shadowRecords: s.shadowRecords, outcomes });
  assert.equal(r.ok, true);
  const replay = mutateReplay ? mutateReplay(r) : r;
  return evaluatePromotion({ frozen, replay, log });
}
const rehash = (r) => ({ ...r, replayHash: digestOf({ ...r, replayHash: undefined }) });

describe('[X-605.AC03] the section 5 routing gate: thresholds', () => {
  test('the preregistered numbers are the PRD numbers', () => {
    assert.deepEqual({ ...ROUTING_MINIMUMS }, { pairedTasksOverall: 200, pairedTasksPerStratum: 30, developmentPerStratum: 10 });
    assert.deepEqual({ ...ROUTING_PROMOTION_TARGETS }, { qualityDifferenceLowerBound: -0.02, medianCostReduction: 0.20, qualityGain: 0.05, p95LatencyRatio: 1.2 });
  });

  test('equal quality at half the measured median cost passes, and the claim is limited to the promoted strata and model versions', async () => {
    const v = await judge(pairedScenario({ n: 240 }));
    assert.equal(v.status, 'pass');
    assert.equal(v.overall.criteria.advantage.costPath, true);
    assert.equal(v.claim.allowed, true);
    assert.deepEqual(v.claim.scope, v.promotedStrata);
    assert.deepEqual(v.testedModelVersions, [`${BASE}@1`, `${CAND}@1`]);
  });

  test('a cost reduction under 20% with no quality gain fails', async () => {
    const v = await judge(pairedScenario({ n: 240, cand: { acc: 0.8, costUsd: 0.09, latencyMs: 1000 } }));
    assert.equal(v.status, 'fail');
    assert.equal(v.overall.criteria.advantage.met, false);
    assert.equal(v.claim.allowed, false);
  });

  test('a quality gain of 0.05 or more at no higher median cost passes through the quality path', async () => {
    const v = await judge(pairedScenario({ n: 240, base: { acc: 0.75, costUsd: 0.1, latencyMs: 1000 }, cand: { acc: 0.88, costUsd: 0.098, latencyMs: 1000 } }));
    assert.equal(v.status, 'pass');
    assert.equal(v.overall.criteria.advantage.qualityPath, true);
    assert.equal(v.overall.criteria.advantage.costPath, false);
  });

  test('a quality gain at a HIGHER median cost does not pass', async () => {
    const v = await judge(pairedScenario({ n: 240, base: { acc: 0.75, costUsd: 0.1, latencyMs: 1000 }, cand: { acc: 0.88, costUsd: 0.13, latencyMs: 1000 } }));
    assert.equal(v.status, 'fail');
    assert.equal(v.overall.criteria.advantage.met, false);
  });

  test('a lower quality bound at or under -0.02 fails even when cost is far lower', async () => {
    const v = await judge(pairedScenario({ n: 240, base: { acc: 0.9, costUsd: 0.1, latencyMs: 1000 }, cand: { acc: 0.8, costUsd: 0.02, latencyMs: 1000 } }));
    assert.equal(v.status, 'fail');
    assert.equal(v.overall.criteria.qualityLowerBound.met, false);
    assert.ok(v.overall.quality.interval.low <= -0.02);
  });

  test('p95 latency above 1.2x the baseline fails', async () => {
    const v = await judge(pairedScenario({ n: 240, cand: { acc: 0.8, costUsd: 0.05, latencyMs: 1500 } }));
    assert.equal(v.status, 'fail');
    assert.equal(v.overall.criteria.p95Latency.met, false);
  });

  test('an unknown cost makes the cost criterion unmet; it is never treated as free', async () => {
    const v = await judge(pairedScenario({ n: 240, cand: { acc: 0.8, costUsd: null, latencyMs: 1000 } }));
    assert.equal(v.overall.cost.complete, false);
    assert.equal(v.overall.criteria.advantage.met, null);
    assert.notEqual(v.status, 'pass');
  });

  test('retries are inside the measured cost: a proposed arm that retried cannot hide the extra spend', async () => {
    // the outcome cost is the adapter's total (retries included); here the proposed total is higher than the baseline even though the unit price is lower
    const v = await judge(pairedScenario({ n: 240, cand: { acc: 0.8, costUsd: 0.11, latencyMs: 1000 } }));
    assert.ok(v.overall.cost.medianReduction < 0);
    assert.notEqual(v.status, 'pass');
    assert.equal(typeof v.overall.cost.retriesProposed, 'number');
  });
});

describe('[X-605.AC03] population: sufficient paired evidence is required', () => {
  test('fewer than 200 paired adjudicated tasks is insufficient-population however good the figures look', async () => {
    const v = await judge(pairedScenario({ n: 150 }));
    assert.equal(v.status, 'insufficient-population');
    assert.equal(v.claim.allowed, false);
    assert.equal(v.overall.adjudicated, 150);
  });

  test('a stratum under 30 paired adjudicated tasks is not promoted and stays visible with its reason', async () => {
    const s = pairedScenario({ n: 240 });
    // reassign 100 python tasks to javascript so python keeps 20 tasks
    const keepPy = new Set(s.tasks.filter((t) => t.language === 'python').slice(0, 20).map((t) => t.taskId));
    const tasks = s.tasks.map((t) => (t.language === 'python' && !keepPy.has(t.taskId) ? { ...t, stratum: t.stratum.replace('python', 'javascript') } : t));
    const f = freezeTaskSet(tasks).frozen;
    const records = s.shadowRecords.map((r) => ({ ...r, stratum: tasks.find((t) => t.taskId === r.taskId).stratum }));
    const replay = await replayPaired({ frozen: f, shadowRecords: records, outcomes: s.outcomes });
    const v = evaluatePromotion({ frozen: f, replay });
    const py = v.strata['repair|python|CWE-89|xs'];
    assert.equal(py.adjudicated, 20);
    assert.equal(py.promoted, false);
    assert.match(py.reason, /30 are required/);
    assert.equal(v.status, 'pass', 'the other stratum carries the gate');
    assert.deepEqual(v.claim.scope, ['repair|javascript|CWE-89|xs'], 'the claim never covers the under-sampled stratum');
  });

  test('a gate with no stratum at 30 is insufficient even with 200+ tasks overall', async () => {
    const s = pairedScenario({ n: 210 });
    const tasks = s.tasks.map((t, i) => ({ ...t, stratum: `repair|lang${i % 10}|CWE-89|xs` }));
    const f = freezeTaskSet(tasks).frozen;
    const records = s.shadowRecords.map((r, i) => ({ ...r, stratum: tasks[i].stratum }));
    const replay = await replayPaired({ frozen: f, shadowRecords: records, outcomes: s.outcomes });
    const v = evaluatePromotion({ frozen: f, replay });
    assert.equal(v.status, 'insufficient-population');
    assert.match(v.reason, /no stratum/);
  });

  test('a pair whose correctness is unknown is counted as unadjudicated, never imputed', async () => {
    const s = pairedScenario({ n: 240 });
    const unknown = new Set(s.tasks.slice(0, 5).map((t) => t.taskId));
    const swapped = s.outcomes.map((o) => (o.model === CAND && unknown.has(o.taskId) ? outcomeOf({ task: s.tasks.find((t) => t.taskId === o.taskId), model: CAND, correct: null, synthetic: false, group: o.group }) : o));
    const v = await judge(s, { outcomes: swapped });
    assert.equal(v.overall.unadjudicated, 5);
    assert.equal(v.overall.adjudicated, 235);
  });
});

describe('[X-605.AC03] synthetic evidence can never pass', () => {
  test('a synthetic population reads unmeasured, whatever the figures are', async () => {
    const v = await judge(pairedScenario({ n: 240, synthetic: true }));
    assert.equal(v.status, 'unmeasured');
    assert.equal(v.synthetic, true);
    assert.equal(v.claim.allowed, false);
    assert.equal(v.overall.criteria.all, true, 'the arithmetic is computed, and still not a pass');
  });
});

describe('[X-605.AC03] cherry-picked tasks, dropped failures and unbounded replay invalidate the gate', () => {
  test('removing the worst pairs from the replay after the fact is detected', async () => {
    const s = pairedScenario({ n: 240, failEvery: 4 });
    const v = await judge(s, { mutateReplay: (r) => ({ ...r, pairs: r.pairs.filter((p) => !(p.proposed.kind === 'failed')) }) });
    assert.equal(v.status, 'invalid');
    assert.ok(v.invalidations.some((i) => i.code === 'replay-edited'));
    assert.ok(v.invalidations.some((i) => i.code === 'dropped-tasks'));
  });

  test('even a re-hashed replay that omits tasks fails: the frozen set is the reference', async () => {
    const s = pairedScenario({ n: 240, failEvery: 4 });
    const v = await judge(s, { mutateReplay: (r) => rehash({ ...r, pairs: r.pairs.filter((p) => p.proposed.kind !== 'failed') }) });
    assert.equal(v.status, 'invalid');
    assert.ok(v.invalidations.some((i) => i.code === 'dropped-tasks'));
    assert.ok(!v.invalidations.some((i) => i.code === 'replay-edited'));
  });

  test('a replay built on a hand-picked subset of tasks is not the frozen set', async () => {
    const s = pairedScenario({ n: 240 });
    const subset = freezeTaskSet(s.tasks.slice(0, 220)).frozen; // the 20 least convenient tasks were left out before freezing
    const r = await replayPaired({ frozen: subset, shadowRecords: s.shadowRecords, outcomes: s.outcomes });
    const v = evaluatePromotion({ frozen: s.frozen, replay: r });
    assert.equal(v.status, 'invalid');
    assert.ok(v.invalidations.some((i) => i.code === 'cherry-picked'));
  });

  test('extra tasks outside the frozen set, or a task counted twice, are cherry-picking', async () => {
    const s = pairedScenario({ n: 240 });
    const extra = pairedScenario({ n: 245 }).tasks[244];
    const v1 = await judge(s, { mutateReplay: (r) => rehash({ ...r, pairs: [...r.pairs, { ...r.pairs[0], taskId: extra.taskId }] }) });
    assert.ok(v1.invalidations.some((i) => i.code === 'cherry-picked'));
    const v2 = await judge(s, { mutateReplay: (r) => rehash({ ...r, pairs: [...r.pairs, r.pairs[0]] }) });
    assert.ok(v2.invalidations.some((i) => i.code === 'cherry-picked'));
    assert.equal(v2.status, 'invalid');
  });

  test('a frozen task whose outcome was never recorded is dropped, and a gate with a dropped task is invalid', async () => {
    const s = pairedScenario({ n: 240, failEvery: 5 });
    const failed = new Set(s.outcomes.filter((o) => o.model === CAND && o.status === 'provider-error').map((o) => o.id));
    const v = await judge(s, { outcomes: s.outcomes.filter((o) => !failed.has(o.id)) });
    assert.equal(v.status, 'invalid');
    assert.ok(v.invalidations.some((i) => i.code === 'dropped-tasks' && /missing-outcome x48/.test(i.detail)));
  });

  test('failures that ARE recorded stay in the comparison as not-correct and are reported', async () => {
    const s = pairedScenario({ n: 240, failEvery: 5, base: { acc: 0.8, costUsd: 0.1, latencyMs: 1000 }, cand: { acc: 0.8, costUsd: 0.04, latencyMs: 1000 } });
    const v = await judge(s);
    assert.equal(v.overall.failures.proposed.failed, 48);
    assert.ok(v.overall.quality.proposed < v.overall.quality.baseline, 'failures lower the proposed quality');
    assert.equal(v.status, 'fail', 'enough failures drag the lower bound under -0.02 even at lower cost');
  });

  test('a task the proposed policy left unserved counts as not-correct, not as a dropped task', async () => {
    const s = pairedScenario({ n: 240, propose: (i) => (i % 4 === 0 ? null : CAND) });
    const v = await judge(s);
    assert.equal(v.overall.failures.proposed.unserved, 60);
    assert.ok(!v.invalidations.some((i) => i.code === 'dropped-tasks'));
    assert.equal(v.status, 'fail');
  });

  test('two valid outcomes for the same task and model are ambiguous and drop the task', async () => {
    const s = pairedScenario({ n: 240 });
    const second = outcomeOf({ task: s.tasks[0], model: CAND, runId: 'run-2', synthetic: false });
    const v = await judge(s, { outcomes: [...s.outcomes, second] });
    assert.equal(v.status, 'invalid');
    assert.ok(v.invalidations.some((i) => i.code === 'dropped-tasks' && /ambiguous-outcomes x1/.test(i.detail)));
  });

  test('a paid call without authorization, or past its bounds, invalidates the gate', async () => {
    const s = pairedScenario({ n: 240 });
    const unauthorized = await judge(s, { mutateReplay: (r) => rehash({ ...r, paidCalls: 3, replay: { ...r.replay, calls: 3, authorized: false } }) });
    assert.equal(unauthorized.status, 'invalid');
    assert.ok(unauthorized.invalidations.some((i) => i.code === 'unbounded-replay'));
    const over = await judge(s, { mutateReplay: (r) => rehash({ ...r, replay: { ...r.replay, calls: 9, authorized: true, bounds: { maxCalls: 5, maxUsd: 1, perCallUsdCeiling: 1 }, spentUsd: 2 } }) });
    assert.ok(over.invalidations.some((i) => i.code === 'unbounded-replay'));
  });

  test('a frozen set edited after the fact is invalid', async () => {
    const s = pairedScenario({ n: 240 });
    const v = await judge(s, { frozen: { ...s.frozen, tasks: s.frozen.tasks.slice(0, 239) } });
    assert.equal(v.status, 'invalid');
    assert.ok(v.invalidations.some((i) => i.code === 'frozen-set-edited'));
  });

  test('the verdict is written to the receipt chain with its invalidations', async () => {
    const log = createReceiptLog({ now: () => '2026-06-01T00:00:00Z' });
    const s = pairedScenario({ n: 240 });
    const v = await judge(s, { frozen: { ...s.frozen, tasks: s.frozen.tasks.slice(0, 239) }, log });
    const last = log.entries().at(-1);
    assert.equal(last.kind, 'promotion');
    assert.equal(last.body.status, 'invalid');
    assert.equal(last.body.verdictHash, v.verdictHash);
    assert.equal(verifyReceiptChain(log.entries()).ok, true);
  });
});
