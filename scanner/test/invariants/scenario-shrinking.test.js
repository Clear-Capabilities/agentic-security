// X-405: dependency-aware scenario shrinking. Pure checks (the structural minimization check, the budget, the record links) run
// everywhere; the tests that EXECUTE scenarios go through the trust boundary and say SKIPPED, NOT PASSED where it cannot run.
// No Linux outcome is claimed.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { _resetKeyCacheForTests } from '../../src/posture/integrity.js';
import { createInvariant } from '../../src/posture/invariants/schema.js';
import { generateScenarios, deriveScenario, runScenario, exerciseOf } from '../../src/posture/invariants/scenarios.js';
import { shrinkScenario, judgeCandidate, checkMinimization, verifyShrinkRecord, resolveShrinkBudget, reproductionSignals, SHRINK_HARD_BUDGET } from '../../src/posture/invariants/shrink.js';
import { verifyInvariant } from '../../src/posture/invariants/run.js';
import { contract, APPS, fixtureOf, configWith, boundaryProbe, COMMIT } from '../helpers/invariant-fixtures.js';

const KEY_VAR = 'AGENTIC_SECURITY_HMAC_KEY';
let savedKey;
let boundary = { ready: false, why: '' };
let config;
before(async () => {
  savedKey = process.env[KEY_VAR];
  process.env[KEY_VAR] = 'ab'.repeat(32);
  _resetKeyCacheForTests();
  boundary = await boundaryProbe();
  config = await configWith('verification-oracles', 'invariant-scenarios');
});
after(() => {
  if (savedKey === undefined) delete process.env[KEY_VAR]; else process.env[KEY_VAR] = savedKey;
  _resetKeyCacheForTests();
});
const needsBoundary = (fn) => (t) => (boundary.ready ? fn(t) : t.skip(boundary.why));

const clone = (o) => JSON.parse(JSON.stringify(o));
const step = (actor, action, key, payload = {}) => ({ actor, action, args: [key, payload] });
const flat = (items) => items.flatMap((it) => (it.parallel ? it.parallel : [it]));
const label = (s) => `${s.actor}.${s.action}(${s.args[0]})`;

/** A generated scenario with redundant steps, control steps and a seed record added around the part that matters. */
function padded(name, app, edit) {
  const fixture = fixtureOf(APPS[app] ?? app);
  const base = generateScenarios(contract(name), { fixture, config }).scenarios[0];
  const inputs = clone(base.inputs);
  edit(inputs);
  return { fixture, base, scenario: deriveScenario(base, inputs) };
}

const noise = (i) => step('alice', 'updateOrder', 'orders/acme-1', { note: `n${i}`, requestId: `noise-${i}` });
const tenantPadded = () => padded('tenant', 'tenantVulnerable', (inp) => {
  inp.attack = [noise(1), ...inp.attack, noise(2), noise(3)];
  inp.control = [...inp.control, noise(4)];
  inp.seed = [...inp.seed, { key: 'orders/extra-1', value: { tenant: 'acme', note: 'x' } }];
});

let cachedTenant;
const tenantShrink = async () => {
  if (!cachedTenant) {
    const p = tenantPadded();
    cachedTenant = { ...p, result: await shrinkScenario(p.scenario, { fixture: p.fixture, commit: COMMIT, config }) };
  }
  return cachedTenant;
};

describe('[X-405.AC01] failed sequences are minimized within a fixed budget while preserving actor identity, setup dependencies and the same authoritative failing assertion', () => {
  test('[X-405.AC01] a padded tenant scenario shrinks to the one cross-tenant step, and every removal is listed', needsBoundary(async () => {
    const { scenario, result } = await tenantShrink();
    assert.equal(result.status, 'minimized', result.reason);
    assert.equal(flat(scenario.inputs.attack).length, 5);
    const left = flat(result.minimized.inputs.attack);
    assert.equal(left.length, 1);
    assert.equal(left[0].actor, 'bob', 'the surviving step is the other tenant\'s actor');
    assert.equal(left[0].args[0], 'orders/acme-1');
    assert.equal(result.minimized.inputs.control.length, 1, 'the control flow is reduced but never emptied');
    assert.ok(result.record.removed.seed.includes('seed orders/extra-1'), 'the unused seed record is removed and named');
    assert.equal(result.minimal, true);
    assert.equal(result.budget.exhausted, false);
    assert.ok(result.budget.runsUsed <= result.budget.maxRuns);
    // nothing vanishes silently: kept + removed accounts for every original unit
    const origOps = flat(scenario.inputs.attack).length + scenario.inputs.control.length + scenario.inputs.seed.length;
    const keptOps = left.length + result.minimized.inputs.control.length + result.minimized.inputs.seed.length;
    const removed = result.record.removed;
    assert.equal(origOps - keptOps, removed.attack.length + removed.control.length + removed.seed.length);
  }));

  test('[X-405.AC01] the same authoritative failing assertion is preserved, and a removal that swaps it for another is rejected', needsBoundary(async () => {
    const { result } = await tenantShrink();
    assert.deepEqual(result.preserved.assertion, { id: 'no-cross-tenant-write', phase: 'attack' });
    assert.deepEqual(result.record.original.assertion, result.record.minimized.assertion);

    // two different forbidden outcomes, each violated by a different step: removing the write step would leave only the leak
    const both = createInvariant({
      ...clone(contract('leak')), key: 'orders-write-and-read',
      forbidden: [{ id: 'no-cross-tenant-write', op: 'cross-tenant-write', prefix: 'orders/', bind: 'business-state' }, { id: 'no-cross-tenant-read', op: 'cross-tenant-read', bind: 'business-state' }],
    });
    const app = `export function createApp() { return { updateOrder(ctx, key, p) { const o = ctx.store.read(key); ctx.store.write(key, { ...o, note: p.note }); return { status: 200 }; },
      peekOrder(ctx, key) { const o = ctx.store.read(key); return { status: 200, order: o }; } }; }`;
    const fixture = fixtureOf(app);
    const base = generateScenarios(both, { fixture, config }).scenarios[0];
    const inputs = clone(base.inputs);
    inputs.attack = [step('bob', 'updateOrder', 'orders/acme-1', { note: 'x', requestId: 'w-1' }), step('bob', 'peekOrder', 'orders/acme-1')];
    const sc = deriveScenario(base, inputs);
    const r = await shrinkScenario(sc, { fixture, commit: COMMIT, config });
    assert.equal(r.status, 'minimized', r.reason);
    assert.deepEqual(r.preserved.assertion, { id: 'no-cross-tenant-write', phase: 'attack' }, 'the authoritative assertion is the first violated one in the contract\'s order');
    assert.deepEqual(flat(r.minimized.inputs.attack).map((s) => s.action), ['updateOrder']);
    const rejected = r.record.attempts.find((a) => a.decision === 'rejected' && /updateOrder/.test(a.unit));
    assert.ok(rejected, 'removing the write step was tried');
    assert.equal(rejected.code, 'assertion-changed', 'and rejected because it would leave a different assertion failing');
  }));

  test('[X-405.AC01] setup dependencies are kept: a step the violation needs survives, and guarded records are explained, not dropped', needsBoundary(async () => {
    const wf = (() => {
      const fixture = fixtureOf(APPS.workflowVulnerable);
      const base = generateScenarios(contract('workflow'), { fixture, config }).scenarios[0];
      const inputs = clone(base.inputs);
      // moving into paid is the setup the backwards move depends on; the repeated move into paid is noise
      inputs.attack = [step('alice', 'advance', 'orders/1', { to: 'paid', requestId: 'a-1' }), step('alice', 'advance', 'orders/1', { to: 'paid', requestId: 'a-2' }), step('alice', 'advance', 'orders/1', { to: 'new', requestId: 'a-3' })];
      return { fixture, scenario: deriveScenario(base, inputs) };
    })();
    const r = await shrinkScenario(wf.scenario, { fixture: wf.fixture, commit: COMMIT, config });
    assert.equal(r.status, 'minimized', r.reason);
    const left = flat(r.minimized.inputs.attack);
    assert.deepEqual(left.map((s) => s.args[1].to), ['paid', 'new'], 'the move into paid is the setup the backwards move depends on');
    const guarded = r.record.attempts.filter((a) => a.decision === 'guarded');
    assert.ok(guarded.length >= 1 && guarded.every((a) => a.code === 'required-precondition' && a.reason), 'every guarded unit says why it was never offered for removal');
    assert.ok(guarded.some((a) => a.unit.startsWith('seed orders/1')), 'the record the surviving steps address is a guarded setup dependency');
    assert.ok(r.minimized.inputs.seed.some((x) => x.key === 'orders/1'));
  }));

  test('[X-405.AC01] actor identity is untouched: the actor list is exactly the original\'s and every surviving step is one of the original steps', needsBoundary(async () => {
    const { scenario, result } = await tenantShrink();
    assert.deepEqual(result.minimized.inputs.actors, scenario.inputs.actors);
    const originals = new Set(flat([...scenario.inputs.attack, ...scenario.inputs.control]).map((s) => JSON.stringify(s)));
    for (const s of flat([...result.minimized.inputs.attack, ...result.minimized.inputs.control])) assert.ok(originals.has(JSON.stringify(s)), `${label(s)} is an original step, unedited`);
    assert.equal(checkMinimization(scenario, result.minimized).ok, true);
  }));

  test('[X-405.AC01] the budget is fixed: a small budget returns the best scenario so far and says it is not minimal; a budget over the ceiling is rejected', needsBoundary(async () => {
    const p = tenantPadded();
    const r = await shrinkScenario(p.scenario, { fixture: p.fixture, commit: COMMIT, config, budget: { maxRuns: 3 } });
    assert.equal(r.budget.exhausted, true);
    assert.equal(r.minimal, false, 'a shrink that ran out of budget never claims to be minimal');
    assert.ok(r.budget.runsUsed <= 3, `used ${r.budget.runsUsed} of 3`);
    assert.equal(r.status, 'minimized', 'what was found is still a valid reproduction');
    assert.ok(flat(r.minimized.inputs.attack).length < 5, 'progress was made within the budget');
    assert.ok(checkMinimization(p.scenario, r.minimized).ok);
    for (const bad of [{ maxRuns: SHRINK_HARD_BUDGET.maxRuns + 1 }, { maxRuns: 0 }, { timeBudgetMs: 1.5 }, { bogus: 1 }]) {
      assert.equal(resolveShrinkBudget(bad).ok, false, JSON.stringify(bad));
      assert.equal((await shrinkScenario(p.scenario, { fixture: p.fixture, commit: COMMIT, config, budget: bad })).status, 'rejected');
    }
    assert.equal(resolveShrinkBudget({}).ok, true);
  }));

  test('[X-405.AC01] the keep rule, one condition at a time: only a decided, fully preconditioned run with the same assertion is kept', () => {
    const want = { id: 'no-cross-tenant-write', phase: 'attack' };
    const pre = { controlRan: true, controlDurableEffect: true, controlClean: true, cleanedUp: true, deterministic: true };
    const run = (over = {}) => ({ status: 'completed', executed: true, outcome: 'confirmed', report: { preconditions: { ...pre, ...(over.pre || {}) }, assertions: over.assertions || [{ id: want.id, phase: 'attack', violated: true }] }, ...over.top });
    assert.deepEqual(judgeCandidate(run(), want), { kept: true, code: null, reason: null });
    const cases = [
      ['not executed', run({ top: { status: 'awaiting-prerequisites', executed: false } }), 'candidate-not-executable'],
      ['refuted', run({ top: { outcome: 'refuted' } }), 'verdict-lost'],
      ['inconclusive', run({ top: { outcome: 'inconclusive' } }), 'verdict-lost'],
      ['nondeterministic', run({ top: { outcome: 'inconclusive' }, pre: { deterministic: false } }), 'nondeterministic'],
      ['control did not work', run({ pre: { controlDurableEffect: false } }), 'precondition-lost'],
      ['control not clean', run({ pre: { controlClean: false } }), 'precondition-lost'],
      ['not cleaned up', run({ pre: { cleanedUp: false } }), 'precondition-lost'],
      ['attack not reproducible', run({ pre: { deterministic: false } }), 'precondition-lost'],
      ['other assertion', run({ assertions: [{ id: 'something-else', phase: 'attack', violated: true }] }), 'assertion-changed'],
      ['same assertion, other phase', run({ assertions: [{ id: want.id, phase: 'control', violated: true }] }), 'assertion-changed'],
      ['assertion no longer violated', run({ assertions: [{ id: want.id, phase: 'attack', violated: false }] }), 'assertion-changed'],
    ];
    for (const [name, r, code] of cases) {
      const j = judgeCandidate(r, want);
      assert.equal(j.kept, false, name);
      assert.equal(j.code, code, name);
      assert.ok(j.reason, `${name}: the rejection says why`);
    }
    assert.equal(judgeCandidate(null, want).kept, false);
  });

  test('[X-405.AC01] with the feature off nothing runs, and verifyInvariant without a shrink option returns exactly what it did before', async () => {
    const p = tenantPadded();
    const off = await shrinkScenario(p.scenario, { fixture: p.fixture, commit: COMMIT, config: await configWith('verification-oracles') });
    assert.equal(off.status, 'disabled');
    assert.equal(off.minimized, null);
    if (!boundary.ready) return;
    const plain = await verifyInvariant({ invariant: contract('tenant'), fixture: fixtureOf(APPS.tenantVulnerable), commit: COMMIT, config });
    assert.ok(plain.results.every((r) => !('shrink' in r)), 'no shrink field unless asked');
    const asked = await verifyInvariant({ invariant: contract('tenant'), fixture: fixtureOf(APPS.tenantVulnerable), commit: COMMIT, config, shrink: true });
    assert.equal(asked.results[0].shrink.status, 'minimized');
    assert.ok(Array.isArray(asked.results[0].exercise.attack) && asked.results[0].exercise.attack.length >= 1, 'results describe what they exercised');
  });
});

describe('[X-405.AC02] the minimized sequence replays on a pinned fixture and reports when concurrency or external dependencies prevent deterministic reproduction', () => {
  test('[X-405.AC02] the minimized scenario reproduces on its confirming replay, and only on the fixture it pins', needsBoundary(async () => {
    const { fixture, result } = await tenantShrink();
    assert.equal(result.reproducibility.reproduced, true);
    assert.deepEqual(result.reproducibility.blockedBy, []);
    assert.equal(result.record.minimized.outcome, 'confirmed');
    const again = await runScenario(result.minimized, { fixture, commit: COMMIT, config });
    assert.equal(again.outcome, 'confirmed', 'an independent replay agrees');
    const other = await runScenario(result.minimized, { fixture: fixtureOf(APPS.tenantFixed), commit: COMMIT, config });
    assert.equal(other.status, 'rejected', 'a different fixture is refused, not run');
    assert.equal(other.errors[0].code, 'FIXTURE_MISMATCH');
  }));

  test('[X-405.AC02] a reproducible concurrent defect shrinks and is labelled as cooperative scheduling, not parallel execution', needsBoundary(async () => {
    const fixture = fixtureOf(APPS.idempotencyVulnerable);
    const sc = generateScenarios(contract('idempotency'), { fixture, config }).scenarios.find((s) => s.kind === 'concurrent-operations');
    const r = await shrinkScenario(sc, { fixture, commit: COMMIT, config });
    assert.equal(r.status, 'minimized', r.reason);
    assert.equal(r.reproducibility.concurrency, true);
    assert.match(r.reproducibility.schedulingModel, /cooperative/);
    assert.equal(r.reproducibility.reproduced, true);
    assert.ok(r.minimized.inputs.attack[0].parallel.length >= 2, 'a group never shrinks below two members: it would stop being a concurrency scenario');
    const floor = r.record.attempts.filter((a) => a.decision === 'guarded' && /member/.test(a.unit));
    assert.ok(floor.length >= 1 && floor.every((a) => /at least two members/.test(a.reason)), 'a two-member group is never offered for member removal, and the attempt says why');
    assert.equal(flat(r.minimized.inputs.attack).length, 2, 'three concurrent duplicates shrink to the two that still race');
  }));

  test('[X-405.AC02] a concurrent scenario that does not reproduce itself is reported as blocked by concurrency, with no minimized scenario claimed', needsBoundary(async () => {
    // module-level state survives between the oracle\'s two fresh plays, so the two runs of the same attack disagree
    const app = `let n = 0; export function createApp() { return { async charge(ctx, key, p) { n++; await Promise.resolve(); if (n % 2 === 0) { ctx.store.write('seen/' + p.requestId + n, { done: true }); ctx.emit('charge', { key: p.requestId }); } return { status: 200 }; } }; }`;
    const fixture = fixtureOf(app);
    const sc = generateScenarios(contract('idempotency'), { fixture, config }).scenarios.find((s) => s.kind === 'concurrent-operations');
    const r = await shrinkScenario(sc, { fixture, commit: COMMIT, config });
    assert.equal(r.status, 'not-reproduced');
    assert.equal(r.minimized, null, 'nothing is minimized from a violation that does not reproduce');
    assert.ok(r.reproducibility.blockedBy.some((b) => b.code === 'concurrency'), JSON.stringify(r.reproducibility.blockedBy));
    assert.equal(r.reproducibility.reproduced, false);
  }));

  test('[X-405.AC02] an external dependency that a network-less replay cannot hold is reported, and a clean fixture reports none', needsBoundary(async () => {
    const app = `import left from 'left-pad-not-installed'; export function createApp() { return { updateOrder(ctx, key, p) { const o = ctx.store.read(key); ctx.store.write(key, { ...o, note: left(p.note) }); return { status: 200 }; } }; }`;
    const fixture = fixtureOf(app);
    const base = generateScenarios(contract('tenant'), { fixture, config }).scenarios[0];
    const r = await shrinkScenario(base, { fixture, commit: COMMIT, config });
    assert.equal(r.status, 'not-reproduced');
    assert.ok(r.reproducibility.blockedBy.some((b) => b.code === 'external-dependency'), JSON.stringify(r.reproducibility.blockedBy));
    assert.equal(reproductionSignals(fixtureOf(APPS.tenantVulnerable).files).external.length, 0);
    const sig = reproductionSignals({ 'a.mjs': 'const r = Math.random(); await fetch("http://x"); setTimeout(() => {}, 1); const e = process.env.X;' });
    assert.deepEqual([...new Set(sig.nondeterminism.map((s) => s.signal))].sort(), ['Math.random', 'timers']);
    assert.deepEqual([...new Set(sig.external.map((s) => s.signal))].sort(), ['fetch', 'process.env']);
  }));

  test('[X-405.AC02] a violation that never reproduced is not minimized at all', needsBoundary(async () => {
    const fixture = fixtureOf(APPS.tenantFixed);
    const base = generateScenarios(contract('tenant'), { fixture, config }).scenarios[0];
    const r = await shrinkScenario(base, { fixture, commit: COMMIT, config });
    assert.equal(r.status, 'not-reproduced');
    assert.equal(r.code, 'original-refuted');
    assert.equal(r.minimized, null);
    assert.equal(r.record, null);
  }));
});

describe('[X-405.AC03] original and minimized sequences retain linked hashes and receipts, and minimization cannot change the invariant or silently remove a required precondition', () => {
  test('[X-405.AC03] the record links both scenarios by digest, manifest, verification record and receipt, and the links recompute', needsBoundary(async () => {
    const { scenario, result } = await tenantShrink();
    for (const side of ['original', 'minimized']) {
      const s = result.record[side];
      assert.match(s.scenarioDigest, /^sha256:[0-9a-f]{64}$/);
      assert.match(s.receiptDigest, /^sha256:[0-9a-f]{64}$/, `${side} receipt digest`);
      assert.match(s.recordId, /^vrec:/);
      assert.match(s.manifestId, /^rpl:/);
    }
    assert.notEqual(result.record.original.receiptDigest, result.record.minimized.receiptDigest);
    assert.match(result.record.id, /^shrk:[0-9a-f]{16}$/);
    assert.deepEqual(verifyShrinkRecord({ record: result.record, original: scenario, minimized: result.minimized }), { ok: true, errors: [] });
    assert.ok(result.record.attempts.filter((a) => a.decision !== 'guarded').every((a) => /^sha256:/.test(a.receiptDigest) && a.candidateId), 'every executed attempt keeps its receipt');
  }));

  test('[X-405.AC03] a tampered record or a swapped scenario is detected', needsBoundary(async () => {
    const { scenario, result } = await tenantShrink();
    const rec = () => clone(result.record);
    const cases = [
      ['minimized digest', (r) => { r.minimized.scenarioDigest = r.original.scenarioDigest; }, 'minimized-link-broken'],
      ['original id', (r) => { r.original.scenarioId = 'iscn:0000000000000000'; }, 'id-link-broken'],
      ['removed list', (r) => { r.removed.attack = []; }, 'record-tampered'],
      ['receipt', (r) => { r.minimized.receiptDigest = 'nope'; }, 'receipt-missing'],
    ];
    for (const [name, mutate, code] of cases) {
      const r = rec(); mutate(r);
      const v = verifyShrinkRecord({ record: r, original: scenario, minimized: result.minimized });
      assert.equal(v.ok, false, name);
      assert.ok(v.errors.some((e) => e.code === code), `${name}: ${JSON.stringify(v.errors)}`);
    }
    const swapped = verifyShrinkRecord({ record: result.record, original: scenario, minimized: scenario });
    assert.equal(swapped.ok, false, 'presenting the original as the minimized scenario breaks the link');
  }));

  test('[X-405.AC03] checkMinimization: a faithful subset passes; each forbidden change is named', async () => {
    const p = tenantPadded();
    const orig = p.scenario;
    const good = deriveScenario(orig, { ...clone(orig.inputs), attack: [orig.inputs.attack[2]], control: [orig.inputs.control[0]], seed: orig.inputs.seed.slice(0, 2) });
    assert.deepEqual(checkMinimization(orig, good), { ok: true, errors: [] });

    const expectCode = (mutate, code) => {
      const m = clone(good); mutate(m);
      const c = checkMinimization(orig, m);
      assert.equal(c.ok, false, code);
      assert.ok(c.errors.some((e) => e.code === code), `${code}: ${JSON.stringify(c.errors)}`);
    };
    expectCode((m) => { m.invariant.id = 'inv:ffffffffffffffff'; }, 'invariant-changed');
    expectCode((m) => { m.inputs.invariant.revision = 9; }, 'invariant-changed');
    expectCode((m) => { m.inputs.actors[0].role = 'admin'; }, 'actor-changed');
    expectCode((m) => { m.inputs.actors.pop(); }, 'actor-changed');
    expectCode((m) => { m.inputs.forbidden[0].id = 'something-else'; }, 'assertion-changed');
    expectCode((m) => { m.fixtureDigest = 'sha256:' + '0'.repeat(64); }, 'fixture-changed');
    expectCode((m) => { m.inputs.attack.push(step('bob', 'updateOrder', 'orders/acme-1', { note: 'new', requestId: 'added' })); }, 'step-added');
    expectCode((m) => { m.inputs.attack[0].actor = 'alice'; }, 'step-added');
    expectCode((m) => { m.inputs.control = []; }, 'precondition-removed');
    expectCode((m) => { m.inputs.seed = m.inputs.seed.filter((r) => r.key !== 'orders/acme-1'); }, 'precondition-removed');
    expectCode((m) => { m.inputs.seed.push({ key: 'orders/new', value: { tenant: 'acme' } }); }, 'step-added');
    assert.equal(checkMinimization(null, good).ok, false);
    assert.equal(checkMinimization(orig, {}).ok, false);
  });

  test('[X-405.AC03] a real shrink always passes the structural check, and exerciseOf reports exactly the steps it ran', needsBoundary(async () => {
    const { scenario, result } = await tenantShrink();
    assert.equal(checkMinimization(scenario, result.minimized).ok, true);
    const ex = exerciseOf(result.minimized);
    assert.deepEqual(ex.attack.map((s) => `${s.actor}.${s.action}.${s.key}`), ['bob.updateOrder.orders/acme-1']);
    assert.equal(result.minimized.invariant.id, contract('tenant').id, 'the approved invariant is the one the minimized scenario asserts');
  }));
});
