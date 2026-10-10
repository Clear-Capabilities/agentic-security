// X-705: dependency-aware resume and invalidation. SYNTHETIC repositories and a synthetic deployment graph only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  planPortfolio, newStore, openStore, mutateStore, readStore, runPortfolio, progressOf, scopedResults, leaseUnit, startUnit, completeUnit, verifyStore,
  DEPENDENCY_DIMENSIONS,
} from '../../src/posture/portfolio/work-units.js';
import { planResume, applyResume, assessClaims, inspectStale, codeDigestFromFiles, toolchainDigest, changedDimensions } from '../../src/posture/portfolio/resume.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { diffBoundaryGraphs, planRescan } from '../../src/lineage/deployment/drift.js';
import { node, edge, graphOf, SRC, FINDING } from '../deployment/path-helpers.js';
import { sha } from './helpers.js';

const T = 2_000_000;
const REPOS = [{ name: 'alpha', commit: 'a'.repeat(40) }, { name: 'beta', commit: 'b'.repeat(40) }, { name: 'gamma', commit: 'c'.repeat(40) }];
const mkPlan = () => planPortfolio({ repositories: REPOS, authorized: REPOS.map((r) => r.name), taskTypes: ['sast-scan', 'boundary-graph'], requiredInputs: {}, synthetic: true }).plan;

// ---- a synthetic deployment world (two independent deployments), as in the drift suite
const F = { ingress: SRC('k8s/ingress.yaml', 'ingress v1'), iam: SRC('iam/roles.yaml', 'iam v1'), mesh: SRC('k8s/mesh.yaml', 'mesh v1') };
function world({ extraGrant = false } = {}) {
  const route = node('route', 'edge/orders', { trustZone: 'public' });
  const api = node('service', 'shop/api');
  const ledger = node('service', 'shop/ledger');
  const ident = node('identity', 'sa/ledger');
  const db = node('resource', 'db/ledger', { trustZone: 'privileged' });
  const audit = node('resource', 'db/audit', { trustZone: 'privileged' });
  const broute = node('route', 'edge/billing', { trustZone: 'public' });
  const billing = node('service', 'bill/svc');
  const bident = node('identity', 'sa/billing');
  const bdb = node('resource', 'db/bill', { trustZone: 'privileged' });
  const nodes = [route, api, ledger, ident, db, audit, broute, billing, bident, bdb];
  const edges = [
    edge('routes-to', route, api, { source: F.ingress }), edge('routes-to', broute, billing, { source: F.ingress }),
    edge('calls', api, ledger, { source: F.mesh }), edge('assumes', ledger, ident, { source: F.iam }), edge('grants', ident, db, { effect: 'allow', attrs: { verbs: 'get' }, source: F.iam }),
    edge('assumes', billing, bident, { source: F.iam }), edge('grants', bident, bdb, { effect: 'allow', attrs: { verbs: 'get' }, source: F.iam }),
  ];
  if (extraGrant) edges.push(edge('grants', ident, audit, { effect: 'allow', attrs: { verbs: 'get' }, source: F.iam }));
  return graphOf({ nodes, edges, sources: [F.ingress, F.iam, F.mesh].map((s) => ({ ...s, bytes: 10 })) });
}
const BINDINGS = [{ pathPrefix: 'services/api/', service: 'shop/api' }, { pathPrefix: 'services/ledger/', service: 'shop/ledger' }, { pathPrefix: 'services/billing/', service: 'bill/svc' }];
const hyp = (n, d) => ({ hypothesisId: `h-${n}`, finding: { ...FINDING, id: `F-${n}`, stableId: `h-${n}`, file: `services/${d}/handler.js` } });
const HYPS = [hyp('api', 'api'), hyp('ledger', 'ledger'), hyp('billing', 'billing')];
const HYP_OF_REPO = { alpha: ['h-api'], beta: ['h-ledger'], gamma: ['h-billing'] };

// ---- the world a run executes against: code per repository, plus shared policy/graph/invariant/oracle/toolchain
function state(over = {}) {
  return {
    policy: 'policy-v1', graph: digestOf(world()), invariant: 'inv-v1', oracle: 'oracle-v1', toolchain: toolchainDigest({ engineVersion: '9.9.9', rulesetVersion: 'r1', bundleSha: 'x' }),
    ...over,
    code: { alpha: 'alpha-src-v1', beta: 'beta-src-v1', gamma: 'gamma-src-v1', ...(over.code ?? {}) },
  };
}
const depsFor = (st) => (u) => ({
  code: codeDigestFromFiles({ [u.repository]: st.code[u.repository] }), policy: sha(st.policy), graph: st.graph.startsWith('sha256:') ? st.graph : sha(st.graph),
  invariant: sha(st.invariant), oracle: sha(st.oracle), toolchain: st.toolchain,
});
const executorFor = (st, calls = []) => (u) => {
  calls.push(u.id);
  const dependencies = depsFor(st)(u);
  return { resultDigest: digestOf({ unit: u.id, output: `scan-of-${st.code[u.repository]}`, dependencies }), dependencies };
};
async function fullRun(st, file) {
  openStore(file, mkPlan());
  await runPortfolio({ file, executor: executorFor(st), clock: () => T, ttlMs: 10_000, concurrency: 2 });
  return readStore(file);
}
const fileIn = () => path.join(mkTestTmp('x705-'), 'portfolio.json');

describe('[X-705.AC01] resume reuses a verified unit only if code, policy, graph, invariant, oracle and toolchain digests match', () => {
  test('[X-705.AC01] unchanged inputs: every verified unit is reused and none is invalidated', async () => {
    const store = await fullRun(state(), fileIn());
    const plan = planResume(store, depsFor(state()));
    assert.equal(plan.reuse.length, 6);
    assert.deepEqual([plan.invalidate.length, plan.revalidate.length], [0, 0]);
  });

  test('[X-705.AC01] each of the six dimensions, changed alone, invalidates; a code change invalidates only that repository, a shared dimension invalidates all', async () => {
    const store = await fullRun(state(), fileIn());
    const changes = {
      code: state({ code: { beta: 'beta-src-v2' } }),
      policy: state({ policy: 'policy-v2' }),
      graph: state({ graph: 'graph-v2' }),
      invariant: state({ invariant: 'inv-v2' }),
      oracle: state({ oracle: 'oracle-v2' }),
      toolchain: state({ toolchain: toolchainDigest({ engineVersion: '9.9.10', rulesetVersion: 'r1', bundleSha: 'x' }) }),
    };
    assert.deepEqual(Object.keys(changes), [...DEPENDENCY_DIMENSIONS]);
    for (const [dim, st] of Object.entries(changes)) {
      const plan = planResume(store, depsFor(st));
      assert.ok(plan.invalidate.every((i) => i.changed.length === 1 && i.changed[0] === dim), dim);
      assert.equal(plan.invalidate.length, dim === 'code' ? 2 : 6, dim);
      if (dim === 'code') assert.ok(plan.invalidate.every((i) => store.units[i.unitId].repository === 'beta'));
    }
  });

  test('[X-705.AC01] negative: current digests that cannot be computed invalidate rather than reuse', async () => {
    const store = await fullRun(state(), fileIn());
    const plan = planResume(store, (u) => { const d = depsFor(state())(u); delete d.oracle; return d; });
    assert.equal(plan.reuse.length, 0);
    assert.ok(plan.invalidate.every((i) => i.changed.includes('oracle') && /unavailable/.test(i.reason)));
    assert.deepEqual(changedDimensions({ code: 'a' }, { code: 'a' }), ['policy', 'graph', 'invariant', 'oracle', 'toolchain'], 'a missing dimension never compares equal');
  });
});

describe('[X-705.AC02] changed inputs invalidate affected units and their dependent claims; stale results stay inspectable but never count', () => {
  test('[X-705.AC02] invalidation moves the old result to stale, returns the unit to pending in a new generation, drops it from progress and marks dependent claims stale', async () => {
    const file = fileIn();
    const store = await fullRun(state(), file);
    const before = progressOf(store);
    assert.equal(before.verified, 6);
    const oldBeta = Object.values(store.units).filter((u) => u.repository === 'beta').map((u) => ({ id: u.id, result: u.result.resultDigest }));
    const next = state({ code: { beta: 'beta-src-v2' } });
    const claims = [{ id: 'claim-alpha', unitIds: Object.values(store.units).filter((u) => u.repository === 'alpha').map((u) => u.id) }, { id: 'claim-beta', unitIds: oldBeta.map((b) => b.id) }];
    mutateStore(file, (s) => applyResume(s, planResume(s, depsFor(next)), T + 1));
    const after = readStore(file);
    const p = progressOf(after);
    assert.deepEqual([p.verified, p.pending, p.staleResults, p.done], [4, 2, 2, false]);
    const stale = inspectStale(after);
    assert.deepEqual(stale.map((s) => s.unitId).sort(), oldBeta.map((b) => b.id).sort());
    assert.ok(stale.every((s) => s.changedDimensions.join() === 'code' && oldBeta.some((b) => b.result === s.resultDigest)));
    assert.ok(Object.values(after.units).filter((u) => u.repository === 'beta').every((u) => u.generation === 1 && u.result === null && u.state === 'pending'));
    assert.equal(Object.keys(scopedResults(after)).length, 4, 'stale results are not scoped results');
    assert.deepEqual(assessClaims(after, claims).map((c) => [c.id, c.status]), [['claim-alpha', 'current'], ['claim-beta', 'stale']]);
    assert.equal(verifyStore(after).ok, true);
    assert.ok(after.units[oldBeta[0].id].events.some((e) => e.type === 'invalidated'), 'the invalidation is part of the chained record');
  });

  test('[X-705.AC02] a unit cannot complete against a stale generation: the old attempt id is refused after invalidation', async () => {
    const s = newStore(mkPlan());
    const l = leaseUnit(s, { holder: 'w', now: T, ttlMs: 10_000 });
    startUnit(s, { unitId: l.unitId, attemptId: l.attemptId, now: T });
    const deps = depsFor(state())(s.units[l.unitId]);
    completeUnit(s, { unitId: l.unitId, attemptId: l.attemptId, resultDigest: sha('r'), dependencies: deps, now: T });
    applyResume(s, planResume(s, depsFor(state({ policy: 'policy-v2' }))), T + 1);
    assert.equal(s.units[l.unitId].state, 'pending');
    // a late duplicate of the OLD completion must not resurrect the stale result
    const dup = completeUnit(s, { unitId: l.unitId, attemptId: l.attemptId, resultDigest: sha('r'), dependencies: deps, now: T + 2 });
    assert.equal(dup.ok, false);
    assert.equal(s.units[l.unitId].state, 'pending');
  });

  test('[X-705.AC02] graph-only change narrowed by the drift plan: unaffected units are reused (and re-stamped), affected ones are invalidated', async () => {
    const before = world(), after = world({ extraGrant: true });
    const file = fileIn();
    const store = await fullRun(state({ graph: digestOf(before) }), file);
    const { diff } = diffBoundaryGraphs(before, after);
    const plan = planRescan({ diff, before, after, hypotheses: HYPS, bindings: BINDINGS });
    assert.deepEqual(plan.rescan.map((r) => r.hypothesisId), ['h-api', 'h-ledger']);
    assert.equal(plan.status, 'complete');
    const hypothesesByUnit = Object.fromEntries(Object.values(store.units).map((u) => [u.id, HYP_OF_REPO[u.repository]]));
    const next = state({ graph: digestOf(after) });
    const rp = planResume(store, depsFor(next), { drift: { plan }, hypothesesByUnit });
    const repoOf = (id) => store.units[id].repository;
    assert.deepEqual(rp.revalidate.map((r) => repoOf(r.unitId)).sort(), ['gamma', 'gamma']);
    assert.deepEqual(rp.invalidate.map((r) => repoOf(r.unitId)).sort(), ['alpha', 'alpha', 'beta', 'beta']);
    mutateStore(file, (s) => applyResume(s, planResume(s, depsFor(next), { drift: { plan }, hypothesesByUnit }), T + 5));
    const done = readStore(file);
    assert.ok(Object.values(done.units).filter((u) => u.repository === 'gamma').every((u) => u.state === 'verified' && u.result.dependencies.graph === depsFor(next)(u).graph && u.events.some((e) => e.type === 'revalidated')));
    assert.equal(progressOf(done).verified, 2);
    // after the revalidation a second resume against the same inputs reuses the gamma units without needing the drift plan
    assert.equal(planResume(done, depsFor(next)).reuse.length, 2);
  });

  test('[X-705.AC02] negative: the narrowing fails closed for an incomplete plan, an unbound unit, and a unit whose code also changed', async () => {
    const before = world(), after = world({ extraGrant: true });
    const store = await fullRun(state({ graph: digestOf(before) }), fileIn());
    const { diff } = diffBoundaryGraphs(before, after);
    const plan = planRescan({ diff, before, after, hypotheses: HYPS, bindings: BINDINGS });
    const next = state({ graph: digestOf(after) });
    const hypothesesByUnit = Object.fromEntries(Object.values(store.units).map((u) => [u.id, HYP_OF_REPO[u.repository]]));
    const incomplete = planResume(store, depsFor(next), { drift: { plan: { ...plan, status: 'incomplete' } }, hypothesesByUnit });
    assert.equal(incomplete.invalidate.length, 6);
    const unbound = planResume(store, depsFor(next), { drift: { plan }, hypothesesByUnit: {} });
    assert.equal(unbound.invalidate.length, 6, 'a unit with no hypotheses cannot be shown independent of the diff');
    assert.match(unbound.invalidate[0].reason, /not bound to hypotheses/);
    const alsoCode = planResume(store, depsFor(state({ graph: digestOf(after), code: { gamma: 'gamma-src-v2' } })), { drift: { plan }, hypothesesByUnit });
    assert.ok(alsoCode.invalidate.filter((i) => store.units[i.unitId].repository === 'gamma').length === 2, 'code change is never narrowed by drift');
    assert.equal(planResume(store, depsFor(next), { hypothesesByUnit }).invalidate.length, 6, 'no drift plan at all means every graph change invalidates');
  });
});

describe('[X-705.AC03] interrupted and incremental execution converge to the same completed scoped results as a fresh full run', () => {
  test('[X-705.AC03] a run interrupted mid-way, abandoned with leases held, then resumed after expiry equals the fresh full run', async () => {
    const st = state();
    const fresh = scopedResults(await fullRun(st, fileIn()));
    const file = fileIn();
    openStore(file, mkPlan());
    const calls = [];
    // interrupted: only two units are started, then the process "dies" with a third leased and never finished
    await runPortfolio({ file, executor: executorFor(st, calls), clock: () => T, ttlMs: 1000, concurrency: 1, maxUnits: 2 });
    mutateStore(file, (s) => leaseUnit(s, { holder: 'dead', now: T, ttlMs: 1000 }));
    assert.equal(progressOf(readStore(file)).verified, 2);
    await runPortfolio({ file, executor: executorFor(st, calls), clock: () => T + 10_000, ttlMs: 1000, concurrency: 2 });
    const resumed = readStore(file);
    assert.deepEqual(scopedResults(resumed), fresh);
    assert.equal(progressOf(resumed).verified, 6);
    assert.equal(calls.length, 6, 'no unit executed twice: the abandoned lease never produced a result');
  });

  test('[X-705.AC03] incremental: after one repository changes, resume re-executes only its units and the results equal a fresh run on the new inputs', async () => {
    const file = fileIn();
    await fullRun(state(), file);
    const next = state({ code: { alpha: 'alpha-src-v2' } });
    const calls = [];
    mutateStore(file, (s) => applyResume(s, planResume(s, depsFor(next)), T + 1));
    await runPortfolio({ file, executor: executorFor(next, calls), clock: () => T + 2, ttlMs: 10_000, concurrency: 2 });
    const incremental = readStore(file);
    const freshNext = scopedResults(await fullRun(next, fileIn()));
    assert.deepEqual(scopedResults(incremental), freshNext);
    assert.equal(calls.length, 2, 'only the two alpha units re-ran');
    assert.ok(Object.values(incremental.units).filter((u) => u.repository !== 'alpha').every((u) => u.generation === 0), 'untouched units were reused, not re-run');
    assert.notDeepEqual(freshNext, scopedResults(await fullRun(state(), fileIn())), 'the change really changed the results (the comparison is not vacuous)');
  });

  test('[X-705.AC03] repeated resume with nothing changed is a no-op: same scoped results, zero executions, progress unchanged', async () => {
    const file = fileIn();
    const st = state();
    await fullRun(st, file);
    const before = scopedResults(readStore(file));
    const calls = [];
    mutateStore(file, (s) => applyResume(s, planResume(s, depsFor(st)), T + 1));
    const p = await runPortfolio({ file, executor: executorFor(st, calls), clock: () => T + 2, ttlMs: 1000, concurrency: 2 });
    assert.equal(calls.length, 0);
    assert.deepEqual(scopedResults(readStore(file)), before);
    assert.equal(p.verified, 6);
  });
});
