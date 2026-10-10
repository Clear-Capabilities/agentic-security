// X-704: durable, leased portfolio work units. SYNTHETIC repositories only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  planPortfolio, newStore, verifyStore, leaseUnit, startUnit, completeUnit, failUnit, blockUnit, unblockUnit, cancelUnits, renewLease,
  recoverExpired, progressOf, scopedResults, openStore, mutateStore, readStore, runPortfolio, fullyVerifiedRepositories, UNIT_STATES, PORTFOLIO_LIMITS,
} from '../../src/posture/portfolio/work-units.js';
import { runFleet } from '../../src/posture/fleet.js';
import { sha, COMMIT } from './helpers.js';

const C2 = 'c'.repeat(40);
const REPOS = [{ name: 'alpha', commit: COMMIT }, { name: 'beta', commit: C2 }, { name: 'gamma', commit: 'd'.repeat(40) }];
const DEPS = Object.fromEntries(['code', 'policy', 'graph', 'invariant', 'oracle', 'toolchain'].map((d) => [d, sha(`dep-${d}`)]));
const mkPlan = (over = {}) => planPortfolio({ repositories: REPOS, authorized: ['alpha', 'beta', 'gamma'], taskTypes: ['sast-scan', 'boundary-graph'], requiredInputs: { 'sast-scan': ['source'], 'boundary-graph': ['deployment', 'source'] }, synthetic: true, ...over });
const T = 1_000_000;

describe('[X-704.AC01] a plan decomposes authorized repositories into stable work units bound to revisions, task types and inputs', () => {
  test('[X-704.AC01] one unit per authorized repository and task type, each bound to the exact commit and required inputs, with stable ids', () => {
    const a = mkPlan(), b = mkPlan();
    assert.equal(a.ok, true);
    assert.equal(a.plan.units.length, 6);
    assert.deepEqual(a.plan.units.map((u) => u.id), b.plan.units.map((u) => u.id));
    assert.equal(a.plan.id, b.plan.id);
    const u = a.plan.units.find((x) => x.repository === 'beta' && x.taskType === 'boundary-graph');
    assert.equal(u.commit, C2);
    assert.deepEqual(u.requiredInputs, ['deployment', 'source']);
    assert.match(u.id, /^wu:[0-9a-f]{16}$/);
    assert.equal(a.plan.synthetic, true);
    // reordering the input does not move any id
    const rev = mkPlan({ repositories: [...REPOS].reverse(), taskTypes: ['boundary-graph', 'sast-scan'] });
    assert.deepEqual(rev.plan.units.map((x) => x.id), a.plan.units.map((x) => x.id));
  });

  test('[X-704.AC01] a new commit gives a new unit id for that repository only', () => {
    const base = mkPlan().plan.units, moved = mkPlan({ repositories: [REPOS[0], { name: 'beta', commit: 'e'.repeat(40) }, REPOS[2]] }).plan.units;
    const same = base.filter((u) => moved.some((m) => m.id === u.id));
    assert.equal(same.length, 4);
    assert.ok(moved.filter((m) => m.repository === 'beta').every((m) => !base.some((u) => u.id === m.id)));
  });

  test('[X-704.AC01] negative: an unauthorized repository is excluded and disclosed, and an unpinned revision, unknown task and empty task list are rejected', () => {
    const p = planPortfolio({ repositories: REPOS, authorized: ['alpha'], taskTypes: ['sast-scan'] });
    assert.deepEqual(p.plan.units.map((u) => u.repository), ['alpha']);
    assert.deepEqual(p.plan.rejected.map((r) => r.repository), ['beta', 'gamma']);
    assert.equal(p.plan.rejected[0].reason, 'not-authorized');
    assert.equal(planPortfolio({ repositories: [{ name: 'alpha', commit: 'main' }], authorized: ['alpha'], taskTypes: ['sast-scan'] }).errors[0].code, 'UNBOUND_REVISION');
    assert.equal(planPortfolio({ repositories: REPOS, authorized: ['alpha'], taskTypes: ['made-up'] }).errors[0].code, 'UNKNOWN_TASK_TYPE');
    assert.equal(planPortfolio({ repositories: REPOS, authorized: ['alpha'], taskTypes: [] }).ok, false);
    assert.equal(planPortfolio({ repositories: [REPOS[0], REPOS[0]], authorized: ['alpha'], taskTypes: ['sast-scan'] }).errors[0].code, 'DUPLICATE_REPOSITORY');
  });
});

describe('[X-704.AC02] persistent units have seven states, lease expiry, retry count and immutable attempt records', () => {
  test('[X-704.AC02] a unit walks pending, leased, running, verified; the attempt chain records each step; a lease has an expiry', () => {
    const s = newStore(mkPlan().plan);
    assert.deepEqual(UNIT_STATES, ['pending', 'leased', 'running', 'verified', 'blocked', 'failed', 'canceled']);
    const l = leaseUnit(s, { holder: 'w1', now: T, ttlMs: 1000 });
    const u = s.units[l.unitId];
    assert.equal(u.state, 'leased');
    assert.equal(l.expiresAt, T + 1000);
    assert.equal(startUnit(s, { unitId: l.unitId, attemptId: l.attemptId, now: T + 1 }).ok, true);
    assert.equal(u.state, 'running');
    assert.equal(completeUnit(s, { unitId: l.unitId, attemptId: l.attemptId, resultDigest: sha('r'), dependencies: DEPS, now: T + 2 }).counted, true);
    assert.equal(u.state, 'verified');
    assert.deepEqual(u.events.map((e) => e.type), ['leased', 'started', 'verified']);
    assert.equal(verifyStore(s).ok, true);
  });

  test('[X-704.AC02] blocked, failed and canceled states: block parks without stalling others, retries are counted, exhaustion fails terminally, cancel keeps verified receipts', () => {
    const s = newStore(mkPlan().plan);
    const ids = Object.keys(s.units).sort();
    assert.equal(blockUnit(s, { unitId: ids[0], reason: 'input missing', now: T }).ok, true);
    const l = leaseUnit(s, { holder: 'w', now: T, ttlMs: 100 });
    assert.notEqual(l.unitId, ids[0], 'a blocked unit does not stall independent work');
    let a = l;
    for (let i = 0; i <= PORTFOLIO_LIMITS.defaultMaxRetries; i++) {
      failUnit(s, { unitId: a.unitId, attemptId: a.attemptId, reason: 'boom', now: T + i });
      if (i < PORTFOLIO_LIMITS.defaultMaxRetries) a = leaseUnit(s, { holder: 'w', now: T + i, ttlMs: 100, unitId: a.unitId });
    }
    assert.equal(s.units[l.unitId].state, 'failed');
    assert.equal(s.units[l.unitId].retryCount, PORTFOLIO_LIMITS.defaultMaxRetries + 1);
    const l2 = leaseUnit(s, { holder: 'w', now: T, ttlMs: 100 });
    completeUnit(s, { unitId: l2.unitId, attemptId: l2.attemptId, resultDigest: sha('r'), dependencies: DEPS, now: T });
    cancelUnits(s, { reason: 'operator stop', now: T + 10 });
    assert.equal(s.units[l2.unitId].state, 'verified', 'a verified receipt survives cancellation');
    assert.equal(s.units[ids[0]].state, 'canceled');
    assert.equal(s.units[l.unitId].state, 'failed', 'a terminal failure keeps its own status and record');
    assert.equal(unblockUnit(s, { unitId: ids[0], now: T }).ok, false);
    assert.ok(progressOf(s).canceled >= 1);
    assert.equal(verifyStore(s).ok, true);
  });

  test('[X-704.AC02] lease expiry: an expired lease is recovered to pending, costs a retry, and the old holder cannot complete', () => {
    const s = newStore(mkPlan().plan);
    const l = leaseUnit(s, { holder: 'w1', now: T, ttlMs: 500 });
    startUnit(s, { unitId: l.unitId, attemptId: l.attemptId, now: T });
    assert.deepEqual(recoverExpired(s, T + 499), []);
    assert.deepEqual(recoverExpired(s, T + 500), [l.unitId]);
    assert.equal(s.units[l.unitId].state, 'pending');
    assert.equal(s.units[l.unitId].retryCount, 1);
    const zombie = completeUnit(s, { unitId: l.unitId, attemptId: l.attemptId, resultDigest: sha('late'), dependencies: DEPS, now: T + 501 });
    assert.equal(zombie.ok, false);
    assert.equal(zombie.code, 'stale-attempt');
    const l2 = leaseUnit(s, { holder: 'w2', now: T + 600, ttlMs: 500, unitId: l.unitId });
    assert.notEqual(l2.attemptId, l.attemptId);
    assert.equal(renewLease(s, { unitId: l.unitId, attemptId: l2.attemptId, now: T + 700, ttlMs: 500 }).expiresAt, T + 1200);
    assert.equal(renewLease(s, { unitId: l.unitId, attemptId: l.attemptId, now: T + 700, ttlMs: 500 }).ok, false);
  });

  test('[X-704.AC02] attempt records are immutable: rewriting, reordering or dropping an event breaks the chain and verification rejects the store', () => {
    const s = newStore(mkPlan().plan);
    const l = leaseUnit(s, { holder: 'w', now: T, ttlMs: 100 });
    startUnit(s, { unitId: l.unitId, attemptId: l.attemptId, now: T });
    failUnit(s, { unitId: l.unitId, attemptId: l.attemptId, reason: 'x', now: T + 1 });
    const edits = [
      (u) => { u.events[0].holder = 'someone-else'; },
      (u) => { u.events.splice(1, 1); },
      (u) => { u.events.reverse(); },
      (u) => { u.events[2].reason = 'edited'; },
    ];
    for (const edit of edits) {
      const c = JSON.parse(JSON.stringify(s));
      edit(c.units[l.unitId]);
      assert.ok(verifyStore(c).errors.some((e) => e.code === 'EVENT_CHAIN_BROKEN'));
    }
    const forged = JSON.parse(JSON.stringify(s));
    forged.units[l.unitId].state = 'verified';
    assert.equal(verifyStore(forged).ok, false, 'a state flipped to verified without a result is rejected');
  });
});

describe('[X-704.AC03] restart and duplicate-delivery tests show idempotent recovery, and unfinished or duplicate attempts never count as verified progress', () => {
  test('[X-704.AC03] duplicate delivery: the same completion twice verifies once; the same lease request twice leases once; the same failure twice costs one retry', () => {
    const s = newStore(mkPlan().plan);
    const l1 = leaseUnit(s, { holder: 'w', now: T, ttlMs: 1000, requestId: 'req-1' });
    const l2 = leaseUnit(s, { holder: 'w', now: T + 1, ttlMs: 1000, requestId: 'req-1' });
    assert.equal(l2.duplicate, true);
    assert.equal(l2.unitId, l1.unitId);
    assert.equal(progressOf(s).leased, 1, 'one unit leased, not two');
    startUnit(s, { unitId: l1.unitId, attemptId: l1.attemptId, now: T });
    assert.equal(startUnit(s, { unitId: l1.unitId, attemptId: l1.attemptId, now: T }).duplicate, true);
    const c1 = completeUnit(s, { unitId: l1.unitId, attemptId: l1.attemptId, resultDigest: sha('r'), dependencies: DEPS, now: T + 2 });
    const c2 = completeUnit(s, { unitId: l1.unitId, attemptId: l1.attemptId, resultDigest: sha('r'), dependencies: DEPS, now: T + 3 });
    assert.deepEqual([c1.counted, c2.counted, c2.duplicate], [true, false, true]);
    assert.equal(progressOf(s).verified, 1);
    assert.equal(s.units[l1.unitId].events.filter((e) => e.type === 'verified').length, 1);
    const l3 = leaseUnit(s, { holder: 'w', now: T + 4, ttlMs: 1000 });
    failUnit(s, { unitId: l3.unitId, attemptId: l3.attemptId, reason: 'x', now: T + 5 });
    failUnit(s, { unitId: l3.unitId, attemptId: l3.attemptId, reason: 'x', now: T + 5 });
    assert.equal(s.units[l3.unitId].retryCount, 1);
  });

  test('[X-704.AC03] unfinished work is not progress: leased, running, failed-and-retrying and expired attempts all leave verified at zero', () => {
    const s = newStore(mkPlan().plan);
    const a = leaseUnit(s, { holder: 'w', now: T, ttlMs: 100 });
    const b = leaseUnit(s, { holder: 'w', now: T, ttlMs: 100 });
    startUnit(s, { unitId: b.unitId, attemptId: b.attemptId, now: T });
    const c = leaseUnit(s, { holder: 'w', now: T, ttlMs: 100 });
    failUnit(s, { unitId: c.unitId, attemptId: c.attemptId, reason: 'x', now: T });
    const p = progressOf(s);
    assert.deepEqual([p.verified, p.leased, p.running, p.pending, p.completed], [0, 1, 1, 4, 0]);
    recoverExpired(s, T + 100);
    assert.equal(progressOf(s).verified, 0);
    assert.deepEqual(scopedResults(s), {});
    assert.equal(progressOf(s).done, false);
    assert.ok(a.unitId);
  });

  test('[X-704.AC03] bad results are refused and do not count: no result digest, missing dependency digests, or a completion that was never leased', () => {
    const s = newStore(mkPlan().plan);
    const l = leaseUnit(s, { holder: 'w', now: T, ttlMs: 1000 });
    assert.equal(completeUnit(s, { unitId: l.unitId, attemptId: l.attemptId, resultDigest: 'nope', dependencies: DEPS, now: T }).code, 'bad-result');
    const partial = { ...DEPS }; delete partial.oracle;
    const r = completeUnit(s, { unitId: l.unitId, attemptId: l.attemptId, resultDigest: sha('r'), dependencies: partial, now: T });
    assert.equal(r.code, 'unbound-dependencies');
    assert.match(r.reason, /oracle/);
    assert.equal(completeUnit(s, { unitId: l.unitId, attemptId: 'wu:fake#0.1', resultDigest: sha('r'), dependencies: DEPS, now: T }).code, 'stale-attempt');
    assert.equal(progressOf(s).verified, 0);
  });

  test('[X-704.AC03] restart: a process that dies with units leased and running leaves a store that a new process reloads, recovers after expiry, and finishes', async () => {
    const file = path.join(mkTestTmp('x704-'), 'portfolio.json');
    const plan = mkPlan().plan;
    openStore(file, plan);
    // "process one": leases two units, starts one, completes none, then is gone
    mutateStore(file, (s) => {
      const a = leaseUnit(s, { holder: 'dead-worker', now: T, ttlMs: 1000 });
      startUnit(s, { unitId: a.unitId, attemptId: a.attemptId, now: T });
      leaseUnit(s, { holder: 'dead-worker', now: T, ttlMs: 1000 });
    });
    // "process two": reopens the same file; nothing counts yet
    assert.equal(openStore(file, plan).planId, plan.id);
    assert.equal(progressOf(readStore(file)).verified, 0);
    const exec = (u) => ({ resultDigest: sha(`result-${u.id}`), dependencies: DEPS });
    // before expiry the dead worker's units are not leasable, so a run can only finish the other four
    const early = await runPortfolio({ file, executor: exec, clock: () => T + 10, ttlMs: 1000, concurrency: 2 });
    assert.equal(early.verified, 4);
    assert.equal(early.leased + early.running, 2);
    const late = await runPortfolio({ file, executor: exec, clock: () => T + 5000, ttlMs: 1000, concurrency: 2 });
    assert.equal(late.verified, 6);
    assert.equal(late.done, true);
    const final = readStore(file);
    assert.equal(final.units[Object.keys(final.units)[0]].events.length > 0, true);
    assert.equal(Object.values(final.units).filter((u) => u.retryCount === 1).length, 2, 'exactly the two abandoned units paid one retry');
  });

  test('[X-704.AC03] a corrupt or foreign store is an error, never a silent reset', () => {
    const file = path.join(mkTestTmp('x704-'), 'portfolio.json');
    const plan = mkPlan().plan;
    openStore(file, plan);
    assert.throws(() => openStore(file, mkPlan({ authorized: ['alpha'] }).plan), (e) => e.code === 'PLAN_MISMATCH');
    fs.writeFileSync(file, '{"schema":"agentic-security/portfolio-store","version":1,"units":');
    assert.throws(() => readStore(file), (e) => e.code === 'STORE_CORRUPT');
    const s = newStore(plan); s.units[Object.keys(s.units)[0]].state = 'verified';
    fs.writeFileSync(file, JSON.stringify(s));
    assert.throws(() => readStore(file), (e) => e.code === 'STORE_CORRUPT');
  });

  test('[X-704.AC03] an executor that throws fails its unit and costs a retry without taking the run down; the portfolio store feeds the fleet skip list', async () => {
    const file = path.join(mkTestTmp('x704-'), 'portfolio.json');
    openStore(file, mkPlan().plan);
    let calls = 0;
    const flaky = (u) => { calls += 1; if (u.repository === 'beta' && calls < 3) throw new Error('flaky'); return { resultDigest: sha(u.id), dependencies: DEPS }; };
    const p = await runPortfolio({ file, executor: flaky, clock: () => T, ttlMs: 1000, concurrency: 1 });
    assert.equal(p.done, true);
    const store = readStore(file);
    assert.deepEqual(fullyVerifiedRepositories(store), ['alpha', 'beta', 'gamma']);
    const scanned = [];
    const out = await runFleet({ repos: ['alpha', 'delta'], portfolioVerified: fullyVerifiedRepositories(store), resume: false, runScan: async (r) => { scanned.push(r); return { scan: { findings: [] } }; } });
    assert.deepEqual(scanned, ['delta']);
    assert.deepEqual(out.skipped, ['alpha']);
    // not in the skip list: a repository with an unverified unit is scanned
    const half = readStore(file); half.units[Object.keys(half.units)[0]].state = 'pending'; half.units[Object.keys(half.units)[0]].result = null;
    assert.ok(!fullyVerifiedRepositories(half).includes(half.units[Object.keys(half.units)[0]].repository));
  });
});
