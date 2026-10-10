// X-403: bounded stateful scenario generation. Generation and gating are pure and run everywhere; the tests that EXECUTE a
// scenario go through the trust boundary and say SKIPPED, NOT PASSED where it cannot run. No Linux outcome is claimed.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateScenarios, runScenario, resolveBounds, HARD_BOUNDS, SCENARIO_KINDS, KINDS_BY_CLASS } from '../../src/posture/invariants/scenarios.js';
import { verifyInvariant } from '../../src/posture/invariants/run.js';
import { createInvariant } from '../../src/posture/invariants/schema.js';
import { runOracle } from '../../src/posture/oracles/oracle.js';
import { contract, APPS, fixtureOf, configWith, boundaryProbe, COMMIT } from '../helpers/invariant-fixtures.js';

let boundary = { ready: false, why: '' };
before(async () => { boundary = await boundaryProbe(); });
const needsBoundary = (fn) => (t) => (boundary.ready ? fn(t) : t.skip(boundary.why));

const clone = (o) => JSON.parse(JSON.stringify(o));
const gen = async (name, o = {}) => generateScenarios(contract(name), { fixture: fixtureOf(APPS.tenantFixed), config: await configWith('invariant-scenarios'), ...o });
const outcomes = async (name, app, over = {}) => {
  const r = await verifyInvariant({ invariant: contract(name), fixture: fixtureOf(APPS[app]), commit: COMMIT, config: await configWith('verification-oracles', 'invariant-scenarios'), ...over });
  return Object.fromEntries(r.results.map((x) => [x.kind, x.outcome]));
};
const opCount = (items) => items.reduce((n, it) => n + (it.parallel ? it.parallel.length : 1), 0);

describe('[X-403.AC01] scenarios contain actors, synthetic tenants, setup, action sequences, assertions and cleanup, with finite depth, request and time budgets', () => {
  test('[X-403.AC01] a scenario carries every element and pins the fixture and contract it was built from', async () => {
    const g = await gen('tenant');
    assert.equal(g.status, 'ok');
    assert.equal(g.scenarios.length, 1);
    const s = g.scenarios[0];
    assert.equal(s.kind, 'cross-tenant-access');
    assert.ok(s.inputs.actors.length >= 2 && s.inputs.actors.every((a) => a.id && a.tenant && a.role), 'actors');
    assert.deepEqual([...new Set(s.inputs.actors.map((a) => a.tenant))].sort(), ['acme', 'globex'], 'synthetic tenants');
    assert.ok(s.inputs.seed.length >= 2 && s.inputs.seed.every((r) => r.key && r.value.tenant), 'setup: seeded records owned by the synthetic tenants');
    assert.ok(s.inputs.control.length >= 1 && s.inputs.attack.length >= 1, 'action sequences');
    assert.ok(s.inputs.forbidden.length >= 1 && s.inputs.forbidden[0].op === 'cross-tenant-write', 'assertions');
    assert.deepEqual(s.inputs.cleanup, [{ action: 'discard-world' }], 'cleanup');
    assert.equal(s.invariant.id, contract('tenant').id);
    assert.match(s.fixtureDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(s.id, /^iscn:[0-9a-f]{16}$/);
    assert.ok(Number.isInteger(s.limits.depth) && s.limits.depth >= 1 && s.limits.requests >= 1 && s.limits.timeBudgetMs > 0 && s.limits.actors >= 1, 'finite budgets are recorded');
  });

  test('[X-403.AC01] the bounds are finite: depth and request counts are enforced on the generated sequence', async () => {
    const wide = createInvariant({ ...clone(contract('idempotency')), key: 'wide' });
    const g = generateScenarios(wide, { fixture: fixtureOf(APPS.idempotencyFixed), config: await configWith('invariant-scenarios'), bounds: { depth: 1, requests: 1 } });
    for (const s of g.scenarios) {
      assert.ok(s.inputs.attack.length <= 1, `${s.kind}: depth bound`);
      assert.ok(s.limits.requests <= 3, `${s.kind}: a single parallel group is the smallest unit, so the request bound is applied to whole items`);
    }
    const tight = await gen('workflow', { bounds: { depth: 1 } });
    assert.ok(tight.scenarios[0].inputs.control.length <= 1, 'control depth is bounded too');
    assert.equal(tight.scenarios[0].limits.truncated, true, 'a truncation is reported, not hidden');
    const full = await gen('workflow', { bounds: { depth: HARD_BOUNDS.depth } });
    assert.ok(full.scenarios[0].inputs.control.length >= 2);
    for (const s of [...g.scenarios, ...tight.scenarios, ...full.scenarios]) assert.ok(s.limits.requests <= HARD_BOUNDS.requests && opCount(s.inputs.attack) <= 16);
  });

  test('[X-403.AC01] a bound over its ceiling, a non-integer or an unknown bound is rejected, not silently clamped', async () => {
    for (const bad of [{ depth: HARD_BOUNDS.depth + 1 }, { requests: 0 }, { requests: 2.5 }, { timeBudgetMs: HARD_BOUNDS.timeBudgetMs + 1 }, { scenarios: -1 }, { bogus: 3 }, { depth: '4' }]) {
      assert.equal(resolveBounds(bad).ok, false, JSON.stringify(bad));
      assert.equal((await gen('tenant', { bounds: bad })).status, 'rejected', JSON.stringify(bad));
    }
    assert.equal(resolveBounds({}).ok, true);
    assert.equal(resolveBounds({ depth: HARD_BOUNDS.depth }).ok, true);
    assert.equal((await gen('tenant', { seed: 1.5 })).status, 'rejected');
    assert.equal((await gen('tenant', { seed: -1 })).status, 'rejected');
  });

  test('[X-403.AC01] the time budget becomes the run deadline, and the oracle never runs for longer than its ceiling', async () => {
    const g = await gen('tenant', { bounds: { timeBudgetMs: 1500 } });
    const s = g.scenarios[0];
    assert.equal(s.limits.timeBudgetMs, 1500);
    let seen = null;
    const spy = { runInBoundary: async (_argv, opts) => { seen = opts.timeoutMs; return { blocked: true, reasons: ['spy'] }; } };
    const r = await runScenario(s, { fixture: fixtureOf(APPS.tenantFixed), commit: COMMIT, config: await configWith('verification-oracles', 'invariant-scenarios'), runOptions: { deps: spy, probeEnv: { platform: process.platform, nodeMajor: 24, backend: 'userspace', hasPosixShell: true } } });
    assert.equal(seen, 1500, 'the scenario budget reached the boundary as its deadline');
    assert.equal(r.executed, false);
    const over = clone(s); over.limits.timeBudgetMs = 60_000;
    const r2 = await runScenario(over, { fixture: fixtureOf(APPS.tenantFixed), commit: COMMIT, config: await configWith('verification-oracles', 'invariant-scenarios'), runOptions: { deps: spy } });
    assert.equal(r2.status, 'rejected', 'a budget above the oracle ceiling is refused by the replay manifest');
  });
});

describe('[X-403.AC02] adversarial sequences cover cross-tenant access, privilege change, reordered workflows, duplicate requests and concurrent operations, with deterministic scheduling', () => {
  test('[X-403.AC02] the five families are generated from the right classes', async () => {
    assert.deepEqual([...SCENARIO_KINDS].sort(), ['concurrent-operations', 'cross-tenant-access', 'duplicate-request', 'privilege-change', 'reordered-workflow']);
    const byClass = { tenant: ['cross-tenant-access'], privilege: ['privilege-change'], workflow: ['reordered-workflow'], conservation: ['duplicate-request', 'concurrent-operations'], idempotency: ['duplicate-request', 'concurrent-operations'] };
    for (const [name, kinds] of Object.entries(byClass)) {
      const g = await gen(name);
      assert.deepEqual(g.scenarios.map((s) => s.kind), kinds, name);
      assert.deepEqual(KINDS_BY_CLASS[contract(name).class], kinds);
    }
    const priv = (await gen('privilege')).scenarios[0];
    assert.ok(priv.inputs.attack.every((st) => st.actor === 'carol'), 'the escalation is attempted by the unprivileged actor');
    assert.equal(priv.inputs.control[0].actor, 'root', 'and the legitimate flow by the privileged one');
    const wf = (await gen('workflow')).scenarios[0];
    assert.deepEqual(wf.inputs.control.map((st) => st.args[1].to), ['paid', 'shipped']);
    assert.equal(wf.inputs.attack[0].args[1].to, 'shipped', 'the attack skips the payment step');
    const dup = (await gen('idempotency')).scenarios.find((s) => s.kind === 'duplicate-request');
    assert.equal(dup.inputs.attack.length, 2);
    assert.equal(dup.inputs.attack[0].args[1].requestId, dup.inputs.attack[1].args[1].requestId, 'the same request is delivered twice');
    const cc = (await gen('idempotency')).scenarios.find((s) => s.kind === 'concurrent-operations');
    assert.ok(cc.inputs.attack[0].parallel.length >= 2 && cc.inputs.attack[0].parallel.length <= 4);
  });

  test('[X-403.AC02] generation is deterministic: the same seed gives byte-identical scenarios, and the seed changes only the schedule', async () => {
    const a = await gen('idempotency', { seed: 7 });
    const b = await gen('idempotency', { seed: 7 });
    assert.equal(JSON.stringify(a), JSON.stringify(b));
    const schedules = new Set();
    for (let seed = 0; seed < 40; seed++) {
      const g = await gen('idempotency', { seed });
      const cc = g.scenarios.find((s) => s.kind === 'concurrent-operations');
      const sched = cc.inputs.attack[0].schedule;
      assert.deepEqual([...sched].sort(), [0, 1, 2], 'a schedule is a permutation of the steps');
      assert.notDeepEqual(sched, [0, 1, 2], 'the schedule always differs from the declaration order');
      schedules.add(sched.join());
    }
    assert.ok(schedules.size > 1, 'different seeds explore different schedules');
    const x = await gen('idempotency', { seed: 1 });
    const y = await gen('idempotency', { seed: 2 });
    assert.notEqual(x.scenarios[0].id, y.scenarios[0].id, 'the seed is part of the scenario identity');
    assert.equal(x.scenarios.find((s) => s.kind === 'duplicate-request').determinism.scheduling, 'sequential');
    assert.equal(x.scenarios.find((s) => s.kind === 'concurrent-operations').determinism.scheduling, 'cooperative-fixed-start-order');
  });

  test('[X-403.AC02] each family finds the defect in a vulnerable application and stays quiet on the fixed one (executed in the trust boundary)', needsBoundary(async () => {
    const cases = [
      ['tenant', 'tenantVulnerable', 'tenantFixed', 'cross-tenant-access'],
      ['privilege', 'privilegeVulnerable', 'privilegeFixed', 'privilege-change'],
      ['workflow', 'workflowVulnerable', 'workflowFixed', 'reordered-workflow'],
      ['idempotency', 'idempotencyNoCheck', 'idempotencyFixed', 'duplicate-request'],
      ['idempotency', 'idempotencyVulnerable', 'idempotencyFixed', 'concurrent-operations'],
    ];
    for (const [name, bad, good, kind] of cases) {
      assert.equal((await outcomes(name, bad))[kind], 'confirmed', `${kind}: ${bad} is violated`);
      assert.equal((await outcomes(name, good))[kind], 'refuted', `${kind}: ${good} is not`);
    }
  }));

  test('[X-403.AC02] concurrency is what exposes a check-then-act race: sequential duplicates pass, a concurrent group does not', needsBoundary(async () => {
    const r = await outcomes('idempotency', 'idempotencyVulnerable');
    assert.equal(r['duplicate-request'], 'refuted', 'delivered one after the other, the handler deduplicates');
    assert.equal(r['concurrent-operations'], 'confirmed', 'started together, every delivery passes the check');
  }));

  test('[X-403.AC02] a deterministic schedule reproduces: two executions of the same scenario give the same outcome and the same record id', needsBoundary(async () => {
    const config = await configWith('verification-oracles', 'invariant-scenarios');
    const g = await gen('idempotency', { seed: 3, fixture: fixtureOf(APPS.idempotencyVulnerable) });
    const cc = g.scenarios.find((s) => s.kind === 'concurrent-operations');
    const fixture = fixtureOf(APPS.idempotencyVulnerable);
    const one = await runScenario(cc, { fixture, commit: COMMIT, config });
    const two = await runScenario(cc, { fixture, commit: COMMIT, config });
    assert.equal(one.outcome, 'confirmed');
    assert.equal(two.outcome, one.outcome);
    assert.equal(two.record.id, one.record.id);
    assert.equal(two.manifestId, one.manifestId);
  }));
});

describe('[X-403.AC03] generation is confined to authorized disposable fixtures; unavailable setup or nondeterministic scheduling is explicitly unsupported or inconclusive', () => {
  test('[X-403.AC03] with the feature off nothing is generated and nothing executes; the kill switch blocks it', async () => {
    const off = generateScenarios(contract('tenant'), { fixture: fixtureOf(APPS.tenantFixed), config: await configWith() });
    assert.equal(off.status, 'disabled');
    assert.deepEqual(off.scenarios, []);
    assert.match(off.reason, /invariant-scenarios/);
    const { resolveAssuranceConfig } = await import('../../src/posture/assurance/config.js');
    const killed = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_NO_INVARIANT_SCENARIOS: '1' }, overrides: { features: { 'invariant-scenarios': true } } });
    assert.equal(generateScenarios(contract('tenant'), { fixture: fixtureOf(APPS.tenantFixed), config: killed }).status, 'blocked');
    let ran = 0;
    const spy = { runInBoundary: async () => { ran++; return { blocked: true, reasons: ['spy'] }; } };
    const v = await verifyInvariant({ invariant: contract('tenant'), fixture: fixtureOf(APPS.tenantFixed), commit: COMMIT, config: await configWith('verification-oracles'), runOptions: { deps: spy } });
    assert.equal(v.status, 'disabled');
    assert.equal(ran, 0, 'no execution happened');
    assert.equal(v.report.gating, false);
  });

  test('[X-403.AC03] both features are required to execute: the oracle layer refuses a business-state run without invariant-scenarios', async () => {
    let ran = 0;
    const spy = { runInBoundary: async () => { ran++; return { blocked: true, reasons: ['spy'] }; } };
    const g = await gen('tenant');
    const s = g.scenarios[0];
    const request = { oracleId: 'business-state', hypothesisId: s.id, commit: COMMIT, files: { 'app.mjs': APPS.tenantFixed }, entry: 'app.mjs', inputs: s.inputs };
    const only = await runOracle(request, { config: await configWith('verification-oracles'), deps: spy });
    assert.equal(only.status, 'disabled');
    assert.equal(only.executed, false);
    assert.match(only.reason, /invariant-scenarios/);
    const other = await runOracle(request, { config: await configWith('invariant-scenarios'), deps: spy });
    assert.equal(other.status, 'disabled');
    assert.match(other.reason, /verification-oracles/);
    assert.equal(ran, 0);
  });

  test('[X-403.AC03] only disposable fixtures: a shared or production scope generates nothing, and so does missing setup', async () => {
    for (const environment of ['production', 'shared']) {
      const inv = createInvariant({ ...clone(contract('tenant')), scope: { ...contract('tenant').scope, environment } });
      const g = generateScenarios(inv, { fixture: fixtureOf(APPS.tenantFixed), config: await configWith('invariant-scenarios') });
      assert.equal(g.status, 'unsupported', environment);
      assert.deepEqual(g.scenarios, []);
      assert.match(g.reason, /disposable fixture/);
    }
    const cfg = await configWith('invariant-scenarios');
    for (const fixture of [undefined, {}, { files: {} }, { files: { 'other.mjs': 'x' } }]) {
      const g = generateScenarios(contract('tenant'), { fixture, config: cfg });
      assert.equal(g.status, 'unsupported', JSON.stringify(fixture));
      assert.match(g.reason, /setup is unavailable/);
    }
    assert.equal(generateScenarios(contract('tenant'), { fixture: { files: { 'app.mjs': 'x' }, digest: 'sha256:' + '0'.repeat(64) }, config: cfg }).status, 'rejected', 'a fixture that does not match its stated digest');
    assert.equal(generateScenarios({ not: 'an invariant' }, { fixture: fixtureOf('x'), config: cfg }).status, 'rejected');
  });

  test('[X-403.AC03] a scenario that cannot be built is listed as unsupported with its reason, not skipped', async () => {
    const oneTenant = createInvariant({
      ...clone(contract('tenant')), key: 'one-tenant', tenants: [{ id: 'acme' }],
      actors: [{ id: 'alice', tenant: 'acme', role: 'member' }], resources: [{ id: 'o-acme', kind: 'order', tenant: 'acme', key: 'orders/acme-1' }],
    });
    const g = generateScenarios(oneTenant, { fixture: fixtureOf(APPS.tenantFixed), config: await configWith('invariant-scenarios') });
    assert.equal(g.status, 'ok');
    assert.deepEqual(g.scenarios, []);
    assert.equal(g.unsupported.length, 1);
    assert.equal(g.unsupported[0].kind, 'cross-tenant-access');
    assert.match(g.unsupported[0].reason, /different tenant/);
    const noLow = createInvariant({ ...clone(contract('privilege')), key: 'all-admin', actors: [{ id: 'root', tenant: 'acme', role: 'admin' }] });
    assert.match(generateScenarios(noLow, { fixture: fixtureOf(APPS.privilegeFixed), config: await configWith('invariant-scenarios') }).unsupported[0].reason, /unprivileged actor/);
  });

  test('[X-403.AC03] a run is bound to its fixture and to an exact commit; a changed fixture or a missing commit is rejected before anything runs', async () => {
    const g = await gen('tenant');
    const s = g.scenarios[0];
    const config = await configWith('verification-oracles', 'invariant-scenarios');
    const swapped = await runScenario(s, { fixture: fixtureOf(APPS.tenantVulnerable), commit: COMMIT, config });
    assert.equal(swapped.status, 'rejected');
    assert.equal(swapped.errors[0].code, 'FIXTURE_MISMATCH');
    const noCommit = await runScenario(s, { fixture: fixtureOf(APPS.tenantFixed), commit: 'HEAD', config });
    assert.equal(noCommit.status, 'rejected');
    assert.equal(noCommit.errors[0].code, 'BAD_COMMIT');
    assert.equal((await runScenario({ schema: 'x' }, { fixture: fixtureOf('x'), commit: COMMIT, config })).status, 'rejected');
  });

  test('[X-403.AC03] a platform the oracle does not support is unsupported with nothing executed, never a pass', async () => {
    const g = await gen('tenant');
    let ran = 0;
    const spy = { runInBoundary: async () => { ran++; return { blocked: true, reasons: ['spy'] }; } };
    const r = await runScenario(g.scenarios[0], {
      fixture: fixtureOf(APPS.tenantFixed), commit: COMMIT, config: await configWith('verification-oracles', 'invariant-scenarios'),
      runOptions: { deps: spy, probeEnv: { platform: 'win32', nodeMajor: 24, backend: 'userspace', hasPosixShell: true } },
    });
    assert.equal(r.executed, false);
    assert.equal(r.outcome, 'unsupported');
    assert.equal(ran, 0);
    assert.equal(r.record.outcome, 'unsupported');
  });

  test('[X-403.AC03] nondeterministic behaviour is inconclusive and an application that never works proves nothing (executed in the trust boundary)', needsBoundary(async () => {
    const r = await verifyInvariant({ invariant: contract('tenant'), fixture: fixtureOf(APPS.nondeterministic), commit: COMMIT, config: await configWith('verification-oracles', 'invariant-scenarios') });
    assert.equal(r.results[0].outcome, 'inconclusive');
    assert.match(r.results[0].reason, /nondeterministic/);
    assert.equal(r.results[0].classification.kind, 'unverified');
    assert.equal(r.report.gating, false);
    const broken = await verifyInvariant({ invariant: contract('tenant'), fixture: fixtureOf(APPS.broken), commit: COMMIT, config: await configWith('verification-oracles', 'invariant-scenarios') });
    assert.equal(broken.results[0].outcome, 'inconclusive');
    assert.match(broken.results[0].reason, /did not show the application working/);
    assert.equal(broken.results[0].classification.kind, 'unverified', 'an unverified result is never read as clean');
  }));
});
