// X-706: bounded scheduling, fairness and scoped cancellation. SYNTHETIC repositories only; no provider is called (routing uses
// injected, synthetic calibration), and the cancellation tests run real process trees on the supervised spawner.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { newStore, openStore, readStore, mutateStore, completeUnit, startUnit, planPortfolio, blockUnit } from '../../src/posture/portfolio/work-units.js';
import {
  validateBudgets, scheduleNext, selectUnit, runScheduled, readLedger, newLedger, settleAttempt, createCancelScope, routingBudgetFor, spendBoundOf, chargeModelSpend, DIMENSIONS, WEIGHT_RANGE, SKIP_CODES, LEDGER_SCHEMA,
} from '../../src/posture/portfolio/scheduler.js';
import { buildCalibration } from '../../src/posture/routing/calibration.js';
import { routeConstrained, candidateFromCatalog } from '../../src/posture/routing/decide.js';
import { priceBookFromCatalog } from '../../src/posture/routing/economics.js';
import { syntheticPopulation, taskOf, BASE_CONFIG } from '../helpers/routing-fixtures.js';
import { DEPS, EST, estimateOf, ok, manyUnitsPlan, BIG_BUDGETS, COMMIT } from './helpers.js';

const T = 1_000_000;
const clock = () => T;
const mk = (spec) => { const dir = mkTestTmp('sched-'); const file = path.join(dir, 'store.json'); openStore(file, manyUnitsPlan(spec)); return { dir, file }; };
const repoOf = (file) => { const s = readStore(file); return (id) => s.units[id].repository; };
const states = (file) => Object.fromEntries(Object.values(readStore(file).units).map((u) => [u.id, u.state]));
const countState = (file, st) => Object.values(readStore(file).units).filter((u) => u.state === st).length;
const run = (file, budgets, over = {}) => runScheduled({ file, budgets, estimateOf, executor: async (u) => ok(u), clock, workers: 1, ...over });
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred, ms = 8000) { const end = Date.now() + ms; while (Date.now() < end) { if (pred()) return true; await sleep(25); } return false; }

describe('[X-706.AC01] the scheduler enforces portfolio and per-repository limits before leasing additional work', () => {
  test('[X-706.AC01] budgets are validated: every portfolio limit is required, a repository limit may be partial, bad values are typed errors', () => {
    assert.equal(validateBudgets(BIG_BUDGETS()).ok, true);
    const missing = validateBudgets({ portfolio: { concurrency: 1, wallMs: 1 } });
    assert.equal(missing.ok, false);
    assert.ok(missing.errors.some((e) => e.path === 'portfolio.spendUsd'));
    assert.equal(validateBudgets({ portfolio: { ...BIG_BUDGETS().portfolio, spendUsd: -1 } }).ok, false);
    assert.equal(validateBudgets({ portfolio: { ...BIG_BUDGETS().portfolio, concurrency: 0 } }).ok, false);
    assert.equal(validateBudgets({ ...BIG_BUDGETS(), priorities: { a: WEIGHT_RANGE.max + 1 } }).ok, false);
    assert.equal(validateBudgets({ ...BIG_BUDGETS(), priorities: { a: WEIGHT_RANGE.min - 1 } }).ok, false);
    assert.equal(validateBudgets({ ...BIG_BUDGETS(), priorities: { a: WEIGHT_RANGE.max, b: WEIGHT_RANGE.min } }).ok, true);
    assert.equal(validateBudgets({ ...BIG_BUDGETS(), repositories: { a: { spendUsd: 'x' } } }).ok, false);
    assert.equal(validateBudgets(null).ok, false);
    const { file } = mk({ a: 1 });
    assert.throws(() => scheduleNext(file, { budgets: { portfolio: {} }, estimateOf, holder: 'w', now: T }), (e) => e.code === 'BAD_BUDGETS');
  });

  test('[X-706.AC01] portfolio concurrency: the lease beyond the limit is refused as at-capacity, and nothing was leased or recorded for it', () => {
    const { file } = mk({ a: 3 });
    const b = BIG_BUDGETS({ concurrency: 2 });
    const l1 = scheduleNext(file, { budgets: b, estimateOf, holder: 'w1', now: T });
    const l2 = scheduleNext(file, { budgets: b, estimateOf, holder: 'w2', now: T });
    assert.ok(l1.lease && l2.lease);
    const eventsBefore = JSON.stringify(Object.values(readStore(file).units).map((u) => u.events.length));
    const l3 = scheduleNext(file, { budgets: b, estimateOf, holder: 'w3', now: T });
    assert.equal(l3.lease, null);
    assert.equal(l3.waiting, true);
    assert.ok(l3.skipped.every((s) => s.code === 'at-capacity'));
    assert.ok(l3.skipped[0].refusals.some((r) => r.scope === 'portfolio' && r.dimension === 'concurrency'));
    assert.equal(JSON.stringify(Object.values(readStore(file).units).map((u) => u.events.length)), eventsBefore, 'a refusal changes no unit');
    assert.equal(countState(file, 'leased'), 2);
  });

  test('[X-706.AC01] per-repository concurrency: one repository at its cap does not stop another from being leased', () => {
    const { file } = mk({ a: 3, b: 3 });
    const b = { ...BIG_BUDGETS({ concurrency: 4 }), repositories: { default: { concurrency: 1 } } };
    const got = [1, 2, 3].map((i) => scheduleNext(file, { budgets: b, estimateOf, holder: `w${i}`, now: T }));
    assert.ok(got[0].lease && got[1].lease);
    assert.notEqual(got[0].lease.repository, got[1].lease.repository);
    assert.equal(got[2].lease, null, 'both repositories are at their cap of 1');
    assert.ok(got[2].skipped.every((s) => s.refusals.some((r) => r.scope === 'repository' && r.dimension === 'concurrency')));
  });

  for (const dim of DIMENSIONS) {
    test(`[X-706.AC01] portfolio ${dim}: exactly the units that fit are leased; the rest are refused as exhausted and stay pending`, async () => {
      const { file } = mk({ a: 5 });
      const r = await run(file, BIG_BUDGETS({ [dim]: EST[dim] * 3 }), { executor: async (u) => ({ ...ok(u), usage: { [dim]: EST[dim] } }) });
      assert.equal(r.progress.verified, 3);
      assert.equal(countState(file, 'pending'), 2);
      assert.equal(r.stopped, 'nothing-schedulable');
      assert.ok(r.skipped.every((s) => s.code === 'exhausted'));
      assert.ok(r.skipped[0].refusals.some((x) => x.scope === 'portfolio' && x.dimension === dim));
    });

    test(`[X-706.AC01] per-repository ${dim}: a repository over its own limit stops, while another repository continues to the end`, async () => {
      const { file } = mk({ a: 4, b: 4 });
      const budgets = { ...BIG_BUDGETS(), repositories: { a: { [dim]: EST[dim] * 2 } } };
      const r = await run(file, budgets, { executor: async (u) => ({ ...ok(u), usage: { [dim]: EST[dim] } }) });
      const ro = repoOf(file);
      const verified = Object.values(readStore(file).units).filter((u) => u.state === 'verified').map((u) => u.repository);
      assert.equal(verified.filter((x) => x === 'a').length, 2);
      assert.equal(verified.filter((x) => x === 'b').length, 4);
      assert.ok(r.skipped.some((s) => s.repository === 'a' && s.code === 'exhausted'));
      assert.ok(ro);
    });
  }

  test('[X-706.AC01] in-flight attempts hold a reservation: a unit that fits only once the first settles is at-capacity, then admitted after settlement', () => {
    const { file } = mk({ a: 2 });
    const budgets = BIG_BUDGETS({ concurrency: 4, spendUsd: 10 });
    const est = () => ({ ...EST, spendUsd: 6 });
    const l1 = scheduleNext(file, { budgets, estimateOf: est, holder: 'w1', now: T });
    assert.ok(l1.lease);
    const l2 = scheduleNext(file, { budgets, estimateOf: est, holder: 'w2', now: T });
    assert.equal(l2.lease, null);
    assert.equal(l2.waiting, true, 'it would fit if the first attempt settled, so this is a wait, not exhaustion');
    assert.equal(l2.skipped[0].code, 'at-capacity');
    // the first attempt settles having used 2 of its reserved 6
    mutateStore(file, (s) => { startUnit(s, { unitId: l1.lease.unitId, attemptId: l1.lease.attemptId, now: T }); });
    settleAttempt(file, { attemptId: l1.lease.attemptId, usage: { spendUsd: 2 } });
    mutateStore(file, (s) => completeUnit(s, { unitId: l1.lease.unitId, attemptId: l1.lease.attemptId, resultDigest: ok({ id: 'x' }).resultDigest, dependencies: DEPS, now: T }));
    assert.equal(readLedger(file).usage.portfolio.spendUsd, 2);
    const l3 = scheduleNext(file, { budgets, estimateOf: est, holder: 'w2', now: T });
    assert.ok(l3.lease, '2 used + 6 reserved fits in 10');
    // and a third can never fit alongside: 2 + 6 + 6 > 10 is a wait while the second is in flight
    assert.equal(scheduleNext(file, { budgets, estimateOf: est, holder: 'w3', now: T }).lease, null);
  });

  test('[X-706.AC01] a store with no ledger yet starts from the empty ledger, and every skip reason is one of the declared codes', () => {
    const { file } = mk({ a: 2 });
    assert.deepEqual(readLedger(file), newLedger());
    assert.equal(newLedger().schema, LEDGER_SCHEMA);
    const r = scheduleNext(file, { budgets: BIG_BUDGETS(), estimateOf: () => null, holder: 'w', now: T });
    assert.ok(r.skipped.length > 0 && r.skipped.every((s) => SKIP_CODES.includes(s.code)));
  });

  test('[X-706.AC01] a unit with no cost estimate is never leased: an unknown cost is not treated as zero', () => {
    const { file } = mk({ a: 2 });
    const r = scheduleNext(file, { budgets: BIG_BUDGETS(), estimateOf: () => null, holder: 'w', now: T });
    assert.equal(r.lease, null);
    assert.ok(r.skipped.every((s) => s.code === 'no-estimate'));
    const partial = scheduleNext(file, { budgets: BIG_BUDGETS(), estimateOf: () => ({ wallMs: 1000, spendUsd: 1 }), holder: 'w', now: T });
    assert.equal(partial.lease, null, 'an estimate missing a dimension is not an estimate');
    assert.equal(countState(file, 'pending'), 2);
  });

  test('[X-706.AC01] an attempt that fails or expires without a usage report is charged its whole reservation, a reported success only what it reported', async () => {
    const f1 = mk({ a: 1 }).file;
    await run(f1, BIG_BUDGETS(), { maxLeases: 1, executor: async () => { throw new Error('synthetic crash'); } });
    assert.equal(readLedger(f1).usage.portfolio.spendUsd, EST.spendUsd, 'a crash spent an unknown amount, so it is charged the reservation');
    const f2 = mk({ a: 1 }).file;
    await run(f2, BIG_BUDGETS(), { executor: async (u) => ({ ...ok(u), usage: { spendUsd: 0.25, requests: 1, storageBytes: 3 } }) });
    const u2 = readLedger(f2).usage.portfolio;
    assert.equal(u2.spendUsd, 0.25);
    assert.equal(u2.storageBytes, 3);
    // an expired lease is reconciled the same conservative way on the next scheduling call
    const f3 = mk({ a: 2 }).file;
    const l = scheduleNext(f3, { budgets: BIG_BUDGETS(), estimateOf, holder: 'dead', now: T, ttlMs: 1000 });
    assert.ok(l.lease);
    scheduleNext(f3, { budgets: BIG_BUDGETS(), estimateOf, holder: 'live', now: T + 5000, ttlMs: 1000 });
    assert.equal(readLedger(f3).usage.portfolio.spendUsd, EST.spendUsd, 'the dead worker\'s reservation was charged in full');
    assert.equal(readLedger(f3).settled[l.lease.attemptId], 'lease-ended');
  });

  test('[X-706.AC01] an overrun of the estimate is recorded and shrinks what remains; it is detected, not hidden', async () => {
    const { file } = mk({ a: 3 });
    const r = await run(file, BIG_BUDGETS({ spendUsd: 3 }), { executor: async (u) => ({ ...ok(u), usage: { spendUsd: 2.5 } }) });
    const led = readLedger(file);
    assert.equal(r.progress.verified, 1, 'the first unit used 2.5 of 3, so no second unit fits');
    assert.equal(led.overruns.length, 1);
    assert.deepEqual(led.overruns[0].dimensions, ['spendUsd']);
  });

  test('[X-706.AC01] wall time is also enforced while a unit runs: the executor is aborted at its wall estimate and the attempt fails, charged in full', async () => {
    const { file } = mk({ a: 1 });
    const r = await run(file, BIG_BUDGETS(), {
      maxLeases: 1, estimateOf: () => ({ ...EST, wallMs: 60 }),
      executor: (u, ctx) => new Promise((_, rej) => ctx.signal.addEventListener('abort', () => rej(ctx.signal.reason))),
    });
    const u = Object.values(readStore(file).units)[0];
    assert.equal(u.retryCount, 1);
    assert.equal(u.events.find((e) => e.type === 'failed').reason, 'wall-time budget reached');
    assert.equal(r.progress.verified, 0);
    assert.equal(readLedger(file).usage.portfolio.wallMs, 60);
  });

  test('[X-706.AC01] a duplicate lease request (same holder and request id) returns the same lease and reserves nothing twice', () => {
    const { file } = mk({ a: 2 });
    const b = BIG_BUDGETS({ concurrency: 4 });
    const a = scheduleNext(file, { budgets: b, estimateOf, holder: 'w', now: T, requestId: 'req-1' });
    const again = scheduleNext(file, { budgets: b, estimateOf, holder: 'w', now: T, requestId: 'req-1' });
    assert.equal(again.lease.duplicate, true);
    assert.equal(again.lease.attemptId, a.lease.attemptId);
    assert.equal(Object.keys(readLedger(file).reservations).length, 1);
    assert.equal(readLedger(file).grants[a.lease.repository], 1);
  });
});

describe('[X-706.AC01] spend is bounded by the routing decision policy (no provider is called)', () => {
  const HAIKU = 'claude-haiku-4-5'; const SONNET = 'claude-sonnet-4-6';
  const POP = syntheticPopulation({ dev: 60, held: 240, models: [{ id: HAIKU, version: '1', acc: 0.9, costUsd: 0.002, latencyMs: 2000 }, { id: SONNET, version: '1', acc: 0.93, costUsd: 0.02, latencyMs: 500 }] });
  const CAL = buildCalibration({ outcomes: POP.outcomes, config: { ...BASE_CONFIG, baselineModel: SONNET } }).artifact;
  const book = priceBookFromCatalog();
  const cands = () => [HAIKU, SONNET].map((id) => candidateFromCatalog({ id, provider: 'provider-a', modelVersion: '1', priceBook: book, capabilities: ['code-reasoning', 'tool-use', 'code-edit'], maxContextTokens: 200_000, endpoint: 'http://127.0.0.1:11434' }));
  const policyFor = (remainingUsd) => ({ version: 'p1', minQualityLower: 0.8, maxIntervalWidth: 0.2, maxEvidenceAgeDays: 90, objective: 'cost', budget: { remainingUsd }, expectedOutputTokens: 500 });
  const decide = (remainingUsd) => routeConstrained({ task: taskOf(1, { requiredCapabilities: ['code-reasoning', 'tool-use'] }), candidates: cands(), calibration: CAL, policy: policyFor(remainingUsd), now: '2026-06-01T00:00:00Z', baselineRoute: { model: SONNET }, egress: () => ({ allowed: true }), allowSynthetic: true });

  test('[X-706.AC01] the routing policy is given the smaller of the portfolio and repository remainders, less in-flight reservations', () => {
    const { file } = mk({ a: 1 });
    const budgets = { ...BIG_BUDGETS({ spendUsd: 10 }), repositories: { a: { spendUsd: 4 } } };
    assert.equal(routingBudgetFor({ budgets, ledger: readLedger(file), repository: 'a' }).remainingUsd, 4);
    const l = scheduleNext(file, { budgets, estimateOf: () => ({ ...EST, spendUsd: 1.5 }), holder: 'w', now: T });
    assert.ok(l.lease);
    assert.equal(routingBudgetFor({ budgets, ledger: readLedger(file), repository: 'a' }).remainingUsd, 2.5, 'the reservation is subtracted');
    assert.equal(routingBudgetFor({ budgets: BIG_BUDGETS({ spendUsd: 1 }), ledger: readLedger(file), repository: 'a' }).remainingUsd, 0, 'a smaller portfolio remainder wins; never negative');
  });

  test('[X-706.AC01] a decision within budget is charged at its upper cost bound, once per request, and refused beyond the unit reservation', () => {
    const { file } = mk({ a: 1 });
    const d = decide(5);
    assert.equal(d.status, 'routed');
    const bound = spendBoundOf(d);
    assert.ok(bound > 0);
    const l = scheduleNext(file, { budgets: BIG_BUDGETS(), estimateOf: () => ({ ...EST, spendUsd: bound * 1.5, requests: 5 }), holder: 'w', now: T });
    assert.deepEqual(chargeModelSpend(file, { attemptId: l.lease.attemptId, decision: d }), { ok: true, charged: bound });
    const second = chargeModelSpend(file, { attemptId: l.lease.attemptId, decision: d });
    assert.equal(second.ok, false);
    assert.equal(second.code, 'unit-spend-exceeded');
    const lim = scheduleNext(mk({ a: 1 }).file, { budgets: BIG_BUDGETS(), estimateOf: () => ({ ...EST, spendUsd: 100, requests: 1 }), holder: 'w', now: T });
    assert.equal(lim.lease.reservation.requests, 1);
  });

  test('[X-706.AC01] with no remaining budget the routing policy blocks, and a blocked or unbounded decision is never charged as free', () => {
    const { file } = mk({ a: 1 });
    const budgets = BIG_BUDGETS({ spendUsd: 0.0001 });
    assert.equal(routingBudgetFor({ budgets, ledger: readLedger(file), repository: 'a' }).remainingUsd, 0.0001);
    const blocked = decide(0);
    assert.equal(blocked.status, 'blocked');
    assert.equal(blocked.code, 'budget-exhausted');
    assert.equal(spendBoundOf(blocked), null);
    const l = scheduleNext(file, { budgets: BIG_BUDGETS(), estimateOf, holder: 'w', now: T });
    const refused = chargeModelSpend(file, { attemptId: l.lease.attemptId, decision: blocked });
    assert.equal(refused.ok, false);
    assert.equal(refused.code, 'no-spend-bound');
    assert.equal(chargeModelSpend(file, { attemptId: 'nope#0.1', decision: decide(5) }).code, 'no-reservation');
    assert.equal(spendBoundOf(null), null);
    assert.equal(readLedger(file).reservations[l.lease.attemptId].used.spendUsd, 0, 'nothing was charged');
  });

  test('[X-706.AC01] ctx.requestModel charges through the running attempt and the charge is what a reported success is settled at', async () => {
    const { file } = mk({ a: 1 });
    const d = decide(5);
    const bound = spendBoundOf(d);
    await run(file, BIG_BUDGETS(), { estimateOf: () => ({ ...EST, spendUsd: bound * 2, requests: 2 }), executor: async (u, ctx) => { const c = await ctx.requestModel(d); assert.equal(c.ok, true); return ok(u); } });
    assert.equal(readLedger(file).usage.portfolio.spendUsd, bound);
    assert.equal(readLedger(file).usage.portfolio.requests, 1);
  });
});

describe('[X-706.AC02] a blocked repository does not stall independent units, and priority and fairness rules are tested against starvation', () => {
  test('[X-706.AC02] a repository declared blocked is skipped with a reason while every independent repository runs to completion', async () => {
    const { file } = mk({ stuck: 3, free1: 3, free2: 2 });
    const r = await run(file, BIG_BUDGETS({ concurrency: 2 }), { workers: 2, blockedRepositories: ['stuck'] });
    assert.equal(r.progress.verified, 5);
    assert.equal(countState(file, 'pending'), 3);
    assert.ok(Object.values(readStore(file).units).filter((u) => u.repository === 'stuck').every((u) => u.state === 'pending'));
    assert.ok(r.skipped.some((s) => s.repository === 'stuck' && s.code === 'repository-blocked'));
    assert.equal(r.stopped, 'nothing-schedulable');
  });

  test('[X-706.AC02] units parked in the blocked state, and a repository whose every unit is blocked, do not hold anyone up', async () => {
    const { file } = mk({ parked: 2, free: 3 });
    mutateStore(file, (s) => { for (const u of Object.values(s.units)) if (u.repository === 'parked') blockUnit(s, { unitId: u.id, reason: 'missing input', now: T }); });
    const r = await run(file, BIG_BUDGETS());
    assert.equal(r.progress.verified, 3);
    assert.equal(r.progress.blocked, 2);
    assert.equal(r.stopped, 'drained');
  });

  test('[X-706.AC02] a repository over its own budget is skipped, and an unaffordable unit does not block a cheaper sibling', async () => {
    const { file } = mk({ a: 3, b: 2 });
    const big = new Set(Object.values(readStore(file).units).filter((u) => u.repository === 'a').map((u) => u.id).sort().slice(0, 1));
    const est = (u) => (big.has(u.id) ? { ...EST, spendUsd: 5 } : EST);
    const budgets = { ...BIG_BUDGETS(), repositories: { a: { spendUsd: 2 } } };
    const r = await run(file, budgets, { estimateOf: est });
    const st = readStore(file).units;
    assert.equal(Object.values(st).filter((u) => u.repository === 'a' && u.state === 'verified').length, 2, 'the two affordable siblings ran');
    assert.ok([...big].every((id) => st[id].state === 'pending'), 'the unaffordable one is left pending, with a reason');
    assert.equal(Object.values(st).filter((u) => u.repository === 'b' && u.state === 'verified').length, 2);
    assert.ok(r.skipped.some((s) => s.unitId && big.has(s.unitId) && s.code === 'exhausted'));
  });

  test('[X-706.AC02] adversarial: 120 units in one repository cannot starve a 3-unit and a 1-unit repository (equal weights)', async () => {
    const { file } = mk({ big: 120, few: 3, one: 1 });
    const ro = repoOf(file);
    const r = await run(file, BIG_BUDGETS(), { maxLeases: 14 });
    const seq = r.order.map(ro);
    assert.equal(seq.length, 14);
    assert.ok(seq.indexOf('one') <= 2, `the single-unit repository is served within its first turns, got ${seq.join(',')}`);
    assert.ok(seq.lastIndexOf('few') <= 6, `all three units of the small repository are served within the first 7 leases, got ${seq.join(',')}`);
    assert.equal(seq.filter((x) => x === 'few').length, 3);
    assert.equal(seq.filter((x) => x === 'one').length, 1);
    assert.ok(seq.filter((x) => x === 'big').length >= 7, 'the large repository still gets the remaining capacity');
  });

  test('[X-706.AC02] the same adversarial mix drains completely and every repository finishes', async () => {
    const { file } = mk({ big: 30, few: 3, one: 1 });
    const r = await run(file, BIG_BUDGETS());
    assert.equal(r.progress.verified, 34);
    assert.equal(r.stopped, 'drained');
  });

  test('[X-706.AC02] priority is a weight, not an order: a weight-8 repository gets about eight times the share and the weight-1 repository is still served', async () => {
    const { file } = mk({ hi: 60, lo: 10 });
    const ro = repoOf(file);
    const r = await run(file, { ...BIG_BUDGETS(), priorities: { hi: 8, lo: 1 } }, { maxLeases: 18 });
    const seq = r.order.map(ro);
    const lo = seq.filter((x) => x === 'lo').length;
    assert.ok(lo >= 2 && lo <= 3, `weight 1 against weight 8 is about 2 of 18, got ${lo}: ${seq.join(',')}`);
    assert.ok(seq.indexOf('lo') <= 1, 'the low-priority repository is served early, not after the high-priority one drains');
    assert.ok(seq.filter((x) => x === 'hi').length >= 14);
    const eq = mk({ hi: 60, lo: 10 });
    const r2 = await run(eq.file, BIG_BUDGETS(), { maxLeases: 18 });
    assert.equal(r2.order.map(repoOf(eq.file)).filter((x) => x === 'lo').length, 9, 'equal weights split the capacity evenly');
  });

  test('[X-706.AC02] a repository that was blocked for a long time is owed service and is served first when it becomes admissible again', async () => {
    const { file } = mk({ busy: 40, late: 3 });
    const ro = repoOf(file);
    await run(file, BIG_BUDGETS(), { maxLeases: 10, blockedRepositories: ['late'] });
    const r = await run(file, BIG_BUDGETS(), { maxLeases: 4 });
    const seq = r.order.map(ro);
    assert.deepEqual(seq, ['late', 'late', 'late', 'busy'], 'late is owed three turns before the busy repository is next');
  });

  test('[X-706.AC02] selection is deterministic: the same store and ledger always name the same next unit', () => {
    const { file } = mk({ a: 5, b: 5, c: 5 });
    const pick = () => { const s = readStore(file); const sel = selectUnit({ store: s, ledger: readLedger(file), budgets: BIG_BUDGETS(), estimateOf }); return sel.unit.id; };
    assert.equal(pick(), pick());
  });
});

describe('[X-706.AC03] cancellation terminates scoped descendants, releases or expires leases, and preserves verified receipts with a reasoned incomplete status', () => {
  const TREE = `
    const { spawn } = require('node:child_process'); const fs = require('node:fs');
    const pidFile = process.argv[1];
    fs.writeFileSync(pidFile + '.parent', String(process.pid));
    spawn(process.execPath, ['-e', 'require("node:fs").writeFileSync(process.argv[1], String(process.pid)); setInterval(() => {}, 1000)', pidFile], { stdio: 'ignore' });
    setInterval(() => {}, 1000);`;

  const twoRepoPlan = () => {
    const dir = mkTestTmp('cancel-'); const file = path.join(dir, 'store.json');
    const p = planPortfolio({ repositories: [{ name: 'victim', commit: COMMIT }, { name: 'bystander', commit: COMMIT }], authorized: ['victim', 'bystander'], taskTypes: ['sast-scan', 'boundary-graph'], synthetic: true });
    openStore(file, p.plan);
    return { dir, file };
  };

  test('[X-706.AC03] cancelling a repository kills its process tree (children and grandchildren), releases the lease and leaves other repositories untouched', async () => {
    const { dir, file } = twoRepoPlan();
    const scope = createCancelScope();
    const pidFile = path.join(dir, 'tree.pid');
    const executor = async (unit, ctx) => {
      if (unit.repository === 'victim' && unit.taskType === 'boundary-graph') { await ctx.spawn(process.execPath, ['-e', TREE, pidFile], { timeoutMs: 60_000, graceMs: 300 }); return null; }
      return ok(unit);
    };
    const running = runScheduled({ file, budgets: BIG_BUDGETS({ concurrency: 4 }), estimateOf, executor, clock, cancelScope: scope, workers: 4 });
    assert.ok(await waitFor(() => fs.existsSync(pidFile) && fs.existsSync(`${pidFile}.parent`)), 'the grandchild started');
    const parent = Number(fs.readFileSync(`${pidFile}.parent`, 'utf8')); const grand = Number(fs.readFileSync(pidFile, 'utf8'));
    assert.ok(alive(parent) && alive(grand));
    const report = await scope.cancel({ file, scope: { repository: 'victim' }, reason: 'operator stopped the victim repository', now: T, waitMs: 8000 });
    assert.equal(alive(parent), false, 'the direct child is gone');
    assert.equal(alive(grand), false, 'the grandchild is gone');
    await running;
    const st = readStore(file).units;
    const mine = Object.values(st).filter((u) => u.repository === 'victim');
    const victimGraph = mine.find((u) => u.taskType === 'boundary-graph');
    assert.equal(victimGraph.state, 'canceled');
    assert.equal(victimGraph.lease, null, 'the lease was released');
    assert.equal(report.leasesReleased.length, 1);
    assert.equal(report.leasesLeftToExpire.length, 0);
    assert.deepEqual(report.survivors, []);
    assert.ok(Object.values(st).filter((u) => u.repository === 'bystander').every((u) => u.state === 'verified'), 'an independent repository is not cancelled');
  });

  test('[X-706.AC03] verified units and their receipts survive a cancellation of their repository, and the report is incomplete with its reason', async () => {
    const { dir, file } = twoRepoPlan();
    const scope = createCancelScope();
    const pidFile = path.join(dir, 'tree2.pid');
    const executor = async (unit, ctx) => {
      if (unit.repository === 'victim' && unit.taskType === 'boundary-graph') { await ctx.spawn(process.execPath, ['-e', TREE, pidFile], { timeoutMs: 60_000, graceMs: 300 }); return null; }
      return ok(unit);
    };
    const running = runScheduled({ file, budgets: BIG_BUDGETS({ concurrency: 4 }), estimateOf, executor, clock, cancelScope: scope, workers: 4 });
    await waitFor(() => fs.existsSync(pidFile) && countState(file, 'verified') >= 3);
    const before = readStore(file).units;
    const verifiedBefore = Object.values(before).filter((u) => u.repository === 'victim' && u.state === 'verified');
    assert.equal(verifiedBefore.length, 1, 'the victim\'s other unit already verified');
    const receipt = JSON.stringify(verifiedBefore[0].result);
    const report = await scope.cancel({ file, scope: { repository: 'victim' }, reason: 'stop for review', now: T, waitMs: 8000 });
    await running;
    const after = readStore(file).units[verifiedBefore[0].id];
    assert.equal(after.state, 'verified');
    assert.equal(JSON.stringify(after.result), receipt, 'the receipt is byte-identical');
    assert.deepEqual(report.verifiedPreserved, [verifiedBefore[0].id]);
    assert.equal(report.status, 'incomplete');
    assert.equal(report.incomplete, true);
    assert.equal(report.reason, 'stop for review');
    const ev = readStore(file).units[Object.values(before).find((u) => u.repository === 'victim' && u.taskType === 'boundary-graph').id].events.at(-1);
    assert.equal(ev.type, 'canceled');
    assert.equal(ev.reason, 'stop for review');
  });

  test('[X-706.AC03] an attempt that does not settle is not released: its lease is left to expire (no other worker may start the unit), then it is cancelled, never re-leased', async () => {
    const { file } = twoRepoPlan();
    const scope = createCancelScope();
    const release = { go: null };
    const stuck = new Promise((r) => { release.go = r; });
    const executor = async (unit) => { if (unit.repository === 'victim' && unit.taskType === 'boundary-graph') { await stuck; return ok(unit); } return ok(unit); };
    const running = runScheduled({ file, budgets: BIG_BUDGETS({ concurrency: 4 }), estimateOf, executor, clock, cancelScope: scope, workers: 4, ttlMs: 60_000 });
    await waitFor(() => countState(file, 'running') === 1 && countState(file, 'verified') >= 3);
    const report = await scope.cancel({ file, scope: { repository: 'victim' }, reason: 'stop', now: T, waitMs: 150 });
    assert.equal(report.leasesReleased.length, 0);
    assert.equal(report.leasesLeftToExpire.length, 1);
    assert.match(report.leasesLeftToExpire[0].why, /did not settle/);
    const held = Object.values(readStore(file).units).find((u) => u.repository === 'victim' && u.taskType === 'boundary-graph');
    assert.equal(held.state, 'running', 'the lease is still held, so no other worker can begin this unit');
    assert.ok(held.lease);
    // time passes beyond the lease: the next scheduling call expires it and, because the scope is cancelled, cancels instead of re-leasing
    const later = scheduleNext(file, { budgets: BIG_BUDGETS({ concurrency: 4 }), estimateOf, holder: 'w2', now: T + 120_000 });
    assert.equal(later.lease, null);
    assert.equal(readStore(file).units[held.id].state, 'canceled');
    release.go();
    await running;
    assert.equal(readStore(file).units[held.id].state, 'canceled', 'a result arriving after cancellation is discarded');
    assert.equal(readLedger(file).settled[held.events.find((e) => e.type === 'leased').attemptId], 'lease-ended');
  });

  test('[X-706.AC03] the cancellation is recorded, so a scheduler that did not receive the call still leases nothing in that scope; unit and all scopes work', async () => {
    const { file } = mk({ a: 3, b: 2 });
    const scope = createCancelScope();
    const rep = await scope.cancel({ file, scope: { unitId: Object.values(readStore(file).units).find((u) => u.repository === 'a').id }, reason: 'one unit', now: T });
    assert.equal(rep.canceled.length, 1);
    const r = await run(file, BIG_BUDGETS());
    assert.equal(r.progress.verified, 4);
    assert.equal(countState(file, 'canceled'), 1);
    const all = await scope.cancel({ file, scope: { all: true }, reason: 'everything', now: T });
    assert.equal(all.verifiedPreserved.length, 4, 'every verified receipt is preserved by a cancel-all');
    assert.equal(countState(file, 'verified'), 4);
    const none = await scope.cancel({ file, scope: { repository: 'does-not-exist' }, reason: 'nothing here', now: T });
    assert.equal(none.status, 'nothing-to-cancel');
    assert.equal(none.incomplete, false);
  });

  test('[X-706.AC03] a cancellation needs a scope: an empty one is refused rather than read as cancel-all', async () => {
    const { file } = mk({ a: 1 });
    const scope = createCancelScope();
    await assert.rejects(() => scope.cancel({ file, scope: {}, reason: 'x', now: T }), (e) => e.code === 'BAD_SCOPE');
    await assert.rejects(() => scope.cancel({ file, scope: null, reason: 'x', now: T }), (e) => e.code === 'BAD_SCOPE');
    assert.equal(countState(file, 'pending'), 1);
  });
});
