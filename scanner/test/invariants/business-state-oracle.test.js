// X-404: the business-state oracle. It is a registered adapter, so it must satisfy the same adapter contract as every other
// (positive, negative and inconclusive fixtures, prerequisites, platforms with Linux unverified, boundary-only execution, receipts
// issued by the verifier domain). The tests that execute it go through the trust boundary and say SKIPPED, NOT PASSED where it
// cannot run.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runOracle, isIssuedReceipt, HARNESS_FILE } from '../../src/posture/oracles/oracle.js';
import { getOracle, oracleManifest } from '../../src/posture/oracles/registry.js';
import { checkAdapterContract, checkFixturePins } from '../../src/posture/oracles/conformance.js';
import { evaluateAssertions, sanitizeSnapshot, eventSequence, hasDurableEffect } from '../../src/posture/invariants/state-assertions.js';
import { generateScenarios, runScenario } from '../../src/posture/invariants/scenarios.js';
import { verifyInvariant } from '../../src/posture/invariants/run.js';
import { validateVerificationRecord } from '../../src/posture/assurance/verification-record.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { contract, APPS, fixtureOf, configWith, boundaryProbe, COMMIT } from '../helpers/invariant-fixtures.js';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
let boundary = { ready: false, why: '' };
before(async () => { boundary = await boundaryProbe(); });
const needsBoundary = (fn) => (t) => (boundary.ready ? fn(t) : t.skip(boundary.why));

const BOTH = ['verification-oracles', 'invariant-scenarios'];
const clone = (o) => JSON.parse(JSON.stringify(o));
async function scenarioFor(name, app, kind, over = {}) {
  const g = generateScenarios(contract(name), { fixture: fixtureOf(APPS[app]), config: await configWith('invariant-scenarios'), ...over });
  return g.scenarios.find((s) => s.kind === kind);
}
async function run(name, app, kind, over = {}) {
  const s = await scenarioFor(name, app, kind);
  return runScenario(s, { fixture: fixtureOf(APPS[app]), commit: COMMIT, config: await configWith(...BOTH), ...over });
}
const FIXTURES = [
  ['tenant', 'tenantVulnerable', 'tenantFixed', 'cross-tenant-access'],
  ['privilege', 'privilegeVulnerable', 'privilegeFixed', 'privilege-change'],
  ['conservation', 'conservationVulnerable', 'conservationFixed', 'duplicate-request'],
  ['workflow', 'workflowVulnerable', 'workflowFixed', 'reordered-workflow'],
  ['idempotency', 'idempotencyVulnerable', 'idempotencyFixed', 'concurrent-operations'],
];

// ---------------------------------------------------------------- pure evaluation (any host)

const op = (o) => ({ item: 0, op: 0, phase: 'attack', actor: 'bob', action: 'updateOrder', ok: true, status: 200, response: '{"status":200}', writes: [], events: [], ...o });
const log = (steps, initial = {}, final = {}) => ({ initial, steps, final, cleaned: true });
const ACTORS = { alice: { tenant: 'acme', role: 'member' }, bob: { tenant: 'globex', role: 'member' } };
const XT = [{ id: 'x', op: 'cross-tenant-write', bind: 'business-state' }];
const evalOne = (forbidden, phaseLog, extra = {}) => evaluateAssertions({ invariantId: 'inv:0000000000000001', forbidden, actors: ACTORS, phaseLog, ...extra });

describe('[X-404.AC01] trusted oracles evaluate durable state and permitted side effects rather than relying only on HTTP status codes or model descriptions', () => {
  test('[X-404.AC01] the verdict follows what was written, not the response status', () => {
    const wrote = { writes: [{ key: 'orders/acme-1', before: { tenant: 'acme', note: 'a' }, after: { tenant: 'acme', note: 'b' } }] };
    // forbidden write, answered 403: still a violation
    assert.equal(evalOne(XT, log([op({ ...wrote, status: 403, ok: true })]))[0].violated, true);
    assert.equal(evalOne(XT, log([op({ ...wrote, status: 200 })]))[0].violated, true);
    assert.equal(evalOne(XT, log([op({ ...wrote, status: null, ok: false })]))[0].violated, true, 'even an operation that threw after writing');
    // no write, answered 200: clean
    assert.equal(evalOne(XT, log([op({ status: 200 })]))[0].violated, false);
    assert.equal(evalOne(XT, log([op({ status: 500, ok: false })]))[0].violated, false);
    // the owner writing its own record is not a violation
    assert.equal(evalOne(XT, log([op({ actor: 'alice', ...wrote })]))[0].violated, false);
  });

  test('[X-404.AC01] each expression looks at durable effects: leaked content, role changes, totals, state moves and repeated side effects', () => {
    const markers = [{ tenant: 'acme', marker: 'ACME-ONLY' }];
    const read = [{ id: 'r', op: 'cross-tenant-read', bind: 'business-state' }];
    assert.equal(evalOne(read, log([op({ response: '{"order":{"note":"ACME-ONLY"}}' })]), { markers })[0].violated, true);
    assert.equal(evalOne(read, log([op({ actor: 'alice', response: '{"order":{"note":"ACME-ONLY"}}' })]), { markers })[0].violated, false, 'a tenant reading its own data');
    const role = [{ id: 'p', op: 'unauthorized-role-change', actions: ['setLimit'], allowedRoles: ['admin'], bind: 'business-state' }];
    const w = [{ key: 'settings/limit', before: { limit: 1 }, after: { limit: 9 } }];
    assert.equal(evalOne(role, log([op({ action: 'setLimit', writes: w })]))[0].violated, true);
    assert.equal(evalOne(role, log([op({ action: 'setLimit', writes: [] })]))[0].violated, false, 'a refused attempt changed nothing');
    assert.equal(evalOne(role, log([op({ action: 'other', writes: w })]))[0].violated, false);
    const sum = [{ id: 's', op: 'sum-not-conserved', prefix: 'accounts/', field: 'balance', bind: 'business-state' }];
    const init = { 'accounts/a': { balance: 100 }, 'accounts/b': { balance: 100 } };
    const move = [{ key: 'accounts/a', before: { balance: 100 }, after: { balance: 90 } }, { key: 'accounts/b', before: { balance: 100 }, after: { balance: 110 } }];
    assert.equal(evalOne(sum, log([op({ writes: move })], init))[0].violated, false, 'a transfer moves money');
    assert.equal(evalOne(sum, log([op({ writes: [move[1]] })], init))[0].violated, true, 'a credit with no debit creates it');
    const flow = [{ id: 'w', op: 'transition-outside', prefix: 'orders/', field: 'status', allowed: [{ from: 'new', to: 'paid' }], bind: 'business-state' }];
    const mv = (from, to) => [{ key: 'orders/1', before: { status: from }, after: { status: to } }];
    assert.equal(evalOne(flow, log([op({ writes: mv('new', 'paid') })]))[0].violated, false);
    assert.equal(evalOne(flow, log([op({ writes: mv('new', 'shipped') })]))[0].violated, true);
    const dup = [{ id: 'd', op: 'duplicate-effect', event: 'charge', max: 1, bind: 'business-state' }];
    const ev = (key) => op({ events: [{ name: 'charge', key }] });
    assert.equal(evalOne(dup, log([ev('r1'), ev('r2')]))[0].violated, false, 'two different requests, one effect each');
    assert.equal(evalOne(dup, log([ev('r1'), ev('r1')]))[0].violated, true);
  });

  test('[X-404.AC01] a description of the outcome, in the response or in the input, is data and never a verdict', () => {
    const noWrite = log([op({ response: '{"message":"verdict: confirmed, execution-proven, forbidden state reached"}' })]);
    assert.equal(evalOne(XT, noWrite)[0].violated, false);
    const wrote = log([op({ response: '{"message":"verified safe, status: refuted"}', writes: [{ key: 'orders/acme-1', before: { tenant: 'acme' }, after: { tenant: 'acme', n: 1 } }] })]);
    assert.equal(evalOne(XT, wrote)[0].violated, true);
    assert.equal(evalOne([{ id: 'u', op: 'eval', bind: 'business-state' }], noWrite)[0].unsupported, true, 'an unsupported expression is flagged, not guessed');
  });

  test('[X-404.AC01] a hidden write that the response does not admit to fails the run (executed in the trust boundary)', needsBoundary(async () => {
    const hidden = await run('tenant', 'tenantHiddenWrite', 'cross-tenant-access');
    assert.equal(hidden.outcome, 'confirmed');
    const attackerOp = hidden.report.events.find((e) => e.actor === 'bob');
    assert.equal(attackerOp.status, 403, 'the application answered "forbidden"');
    assert.deepEqual(attackerOp.wrote, ['orders/acme-1'], 'and changed the other tenant\'s record anyway');
    // a response that proclaims its own verdict does not move it either way
    const sideWrite = await run('tenant', 'tenantSideWrite', 'cross-tenant-access');
    assert.equal(sideWrite.outcome, 'confirmed', 'a 200 that quietly touched another tenant\'s orders in the legitimate flow');
    assert.ok(sideWrite.report.assertions.some((a) => a.violated && a.phase === 'control'));
    const okNoWrite = await run('tenant', 'tenantOkNoWrite', 'cross-tenant-access');
    assert.equal(okNoWrite.outcome, 'refuted', 'every response was 200 and nothing forbidden was written');
    assert.ok(okNoWrite.report.events.every((e) => e.status === 200));
  }));

  test('[X-404.AC01] the target runs only through the trust boundary: the adapter has no other way to execute code, and a refusal stops the run', async () => {
    const src = fs.readFileSync(path.join(SCANNER, 'src/posture/oracles/adapters.js'), 'utf8') + fs.readFileSync(path.join(SCANNER, 'src/posture/invariants/state-assertions.js'), 'utf8');
    assert.doesNotMatch(src, /child_process|node:vm|new Function|\beval\(|worker_threads/, 'neither the adapter nor the evaluator can execute code itself');
    const s = await scenarioFor('tenant', 'tenantFixed', 'cross-tenant-access');
    const calls = [];
    const spy = { runInBoundary: async (argv, opts) => { calls.push({ argv, opts }); return { blocked: true, reasons: ['spy refused'], backend: 'spy' }; } };
    const r = await runOracle({ oracleId: 'business-state', hypothesisId: s.id, commit: COMMIT, files: { 'app.mjs': APPS.tenantFixed }, entry: 'app.mjs', inputs: s.inputs }, {
      config: await configWith(...BOTH), deps: spy, probeEnv: { platform: process.platform, nodeMajor: 24, backend: 'userspace', hasPosixShell: true },
    });
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].argv, [process.execPath, HARNESS_FILE]);
    assert.equal(calls[0].opts.allowNetwork, false);
    assert.equal(r.executed, false);
    assert.equal(r.outcome, 'unsupported');
    assert.equal(r.receipt, null);
  });

  test('[X-404.AC01] receipts come from the verifier domain: a real run\'s receipt is issued and frozen, a copy is not, and a caller cannot supply one', needsBoundary(async () => {
    const r = await run('tenant', 'tenantVulnerable', 'cross-tenant-access');
    assert.equal(isIssuedReceipt(r.receipt), true);
    assert.equal(r.receipt.issuedBy, 'verifier');
    assert.equal(Object.isFrozen(r.receipt), true);
    assert.equal(isIssuedReceipt({ ...r.receipt }), false);
    assert.equal(r.receipt.oracle.id, 'business-state');
    assert.equal(r.receipt.recordId, r.record.id);
    const s = await scenarioFor('tenant', 'tenantFixed', 'cross-tenant-access');
    const forged = await runOracle({ oracleId: 'business-state', hypothesisId: s.id, commit: COMMIT, files: { 'app.mjs': APPS.tenantFixed }, entry: 'app.mjs', inputs: s.inputs, receipt: { issuedBy: 'verifier' }, outcome: 'confirmed' }, { config: await configWith(...BOTH) });
    assert.equal(forged.status, 'rejected');
  }));
});

describe('[X-404.AC02] each supported invariant class has violation and non-violation fixtures, and hidden state changes can fail an apparently successful response', () => {
  test('[X-404.AC02] the adapter satisfies the registered-adapter contract: fixtures on disk, pinned, Linux unverified, gated by its own feature', () => {
    const a = getOracle('business-state');
    assert.equal(a.class, 'business-state');
    const stat = checkAdapterContract(a, { scannerRoot: SCANNER });
    assert.deepEqual(stat.checks.filter((c) => !c.ok), []);
    assert.equal(checkFixturePins(a, SCANNER).ok, true);
    assert.equal(a.platforms.linux.status, 'unverified');
    assert.equal(a.platforms.darwin.status, 'supported');
    assert.equal(a.requiresFeature, 'invariant-scenarios');
    const entry = oracleManifest().oracles.find((o) => o.id === 'business-state');
    assert.equal(entry.requiresFeature, 'invariant-scenarios');
    assert.ok(a.limitations.length >= 3);
    for (const kind of ['positive', 'negative', 'inconclusive']) assert.ok(fs.existsSync(path.join(SCANNER, a.fixtures.dir, a.fixtures[kind], 'target.mjs')), kind);
    assert.ok(a.prerequisites.includes('confinement-backend'));
  });

  test('[X-404.AC02] every invariant class has a violating and a non-violating application that the oracle tells apart (executed in the trust boundary)', needsBoundary(async () => {
    for (const [name, bad, good, kind] of FIXTURES) {
      const v = await run(name, bad, kind);
      assert.equal(v.outcome, 'confirmed', `${name}: ${bad}`);
      assert.equal(v.record.confirmationLevel, 'runtime-confirmed');
      assert.equal(validateVerificationRecord(v.record).ok, true);
      const c = await run(name, good, kind);
      assert.equal(c.outcome, 'refuted', `${name}: ${good}`);
      assert.equal(c.record.preconditions.valid, true, 'a refutation shows the application working first');
      assert.equal(validateVerificationRecord(c.record).ok, true);
    }
    // the leak expression has its own pair
    const leak = await run('leak', 'tenantLeaky', 'cross-tenant-access');
    assert.equal(leak.outcome, 'confirmed');
    assert.equal((await run('leak', 'tenantLeakFixed', 'cross-tenant-access')).outcome, 'refuted');
  }));

  test('[X-404.AC02] the oracle\'s own fixtures run through the registered adapter: positive confirms, negative refutes, inconclusive stays open', needsBoundary(async () => {
    const a = getOracle('business-state');
    const dir = path.join(SCANNER, a.fixtures.dir);
    const inputs = JSON.parse(fs.readFileSync(path.join(dir, 'scenario.json'), 'utf8'));
    const out = {};
    for (const kind of ['positive', 'negative', 'inconclusive']) {
      const r = await runOracle({ oracleId: 'business-state', hypothesisId: `fx-${kind}`, commit: COMMIT, files: { 'target.mjs': fs.readFileSync(path.join(dir, kind, 'target.mjs'), 'utf8') }, entry: 'target.mjs', inputs }, { config: await configWith(...BOTH) });
      out[kind] = r.outcome;
    }
    assert.deepEqual(out, { positive: 'confirmed', negative: 'refuted', inconclusive: 'inconclusive' });
  }));
});

describe('[X-404.AC03] oracle records include preconditions, sanitized snapshots, event sequence and assertion results with stable evidence IDs', () => {
  test('[X-404.AC03] snapshots are sanitized: secret-looking fields are redacted, long strings cut, size bounded', () => {
    const s = sanitizeSnapshot({
      'orders/1': { tenant: 'acme', note: 'x'.repeat(500), apiToken: 'sk-live-123', password: 'hunter2', nested: { Authorization: 'Bearer abc', ok: 1 } },
      'secrets/db': { value: 'postgres://u:p@h/db' },
      ...Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`k${i}`, { n: i }])),
    });
    const text = JSON.stringify(s);
    assert.doesNotMatch(text, /sk-live-123|hunter2|Bearer abc|postgres:\/\//);
    assert.equal(s['orders/1'].apiToken, '[redacted]');
    assert.equal(s['orders/1'].nested.Authorization, '[redacted]');
    assert.ok(s['orders/1'].note.length < 100 && s['orders/1'].note.endsWith('...'));
    assert.equal(s['orders/1'].tenant, 'acme', 'ordinary fields survive');
    assert.ok(Object.keys(s).length <= 24);
    assert.deepEqual(sanitizeSnapshot(null), {});
  });

  test('[X-404.AC03] evidence ids are stable, content-derived and distinct per assertion and per observed behaviour', () => {
    const wrote = log([op({ writes: [{ key: 'orders/acme-1', before: { tenant: 'acme' }, after: { tenant: 'acme', n: 1 } }] })]);
    const a = evalOne(XT, wrote)[0];
    const b = evalOne(XT, clone(wrote))[0];
    assert.match(a.evidenceId, /^ievd:[0-9a-f]{16}$/);
    assert.equal(a.evidenceId, b.evidenceId, 'the same observation gives the same id');
    assert.notEqual(evalOne(XT, log([op({})]))[0].evidenceId, a.evidenceId, 'a different observation gives a different id');
    const other = log([op({ writes: [{ key: 'orders/acme-1', before: { tenant: 'acme' }, after: { tenant: 'acme', n: 2 } }] })]);
    assert.equal(evalOne(XT, other)[0].violated, true);
    assert.notEqual(evalOne(XT, other)[0].evidenceId, a.evidenceId, 'the same violation with different observed content is different evidence');
    assert.notEqual(evalOne(XT, wrote, {})[0].evidenceId, evaluateAssertions({ invariantId: 'inv:0000000000000002', forbidden: XT, actors: ACTORS, phaseLog: wrote })[0].evidenceId, 'the contract is part of the id');
    const two = evalOne([...XT, { id: 'y', op: 'cross-tenant-write', prefix: 'invoices/', bind: 'business-state' }], wrote);
    assert.notEqual(two[0].evidenceId, two[1].evidenceId, 'each assertion has its own id');
    assert.equal(eventSequence(wrote)[0].wrote[0], 'orders/acme-1');
    assert.equal(hasDurableEffect(log([op({})])), false);
    assert.equal(hasDurableEffect(wrote), true);
  });

  test('[X-404.AC03] a run reports preconditions, sanitized snapshots, the event sequence and per-assertion results bound into the record and receipt (executed in the trust boundary)', needsBoundary(async () => {
    const r = await run('tenant', 'tenantSecret', 'cross-tenant-access');
    assert.equal(r.outcome, 'confirmed');
    const rep = r.report;
    assert.equal(rep.schema, 'agentic-security/business-state-report');
    assert.deepEqual(Object.keys(rep.preconditions).sort(), ['cleanedUp', 'controlClean', 'controlDurableEffect', 'controlRan', 'deterministic']);
    assert.ok(Object.values(rep.preconditions).every((v) => v === true));
    assert.ok(rep.snapshots.initial && rep.snapshots.final);
    assert.equal(rep.snapshots.final['orders/acme-1'].apiToken, '[redacted]', 'the secret the application stored never reaches the report');
    assert.equal(rep.snapshots.final['orders/acme-1'].password, '[redacted]');
    const everything = JSON.stringify([rep, r.record, r.receipt]);
    assert.doesNotMatch(everything, /sk-live-0123456789|hunter2/);
    assert.deepEqual(rep.events.map((e) => [e.actor, e.action]), [['alice', 'updateOrder'], ['bob', 'updateOrder']], 'each actor tried the other tenant\'s record, in order');
    assert.equal(rep.assertions.length, 1);
    assert.equal(rep.assertions[0].violated, true);
    assert.match(rep.assertions[0].evidenceId, /^ievd:/);
    // the ids are in the verification record as evidence, and the report is bound by digest into the receipt
    const ids = new Set(r.record.evidence.map((e) => e.id));
    for (const a of rep.assertions) assert.ok(ids.has(a.evidenceId), 'assertion evidence is part of the record');
    assert.equal(r.receipt.reportDigest, digestOf(rep));
    assert.equal(r.receipt.observed.reportDigest, digestOf(rep));
    assert.equal(validateVerificationRecord(r.record).ok, true);
  }));

  test('[X-404.AC03] evidence ids and the record id are identical on a replay and change when the application changes (executed in the trust boundary)', needsBoundary(async () => {
    const one = await run('tenant', 'tenantVulnerable', 'cross-tenant-access');
    const two = await run('tenant', 'tenantVulnerable', 'cross-tenant-access');
    assert.deepEqual(two.report.assertions.map((a) => a.evidenceId), one.report.assertions.map((a) => a.evidenceId));
    assert.equal(two.record.id, one.record.id);
    const fixed = await run('tenant', 'tenantFixed', 'cross-tenant-access');
    assert.notEqual(fixed.report.assertions[0].evidenceId, one.report.assertions[0].evidenceId);
    assert.equal(fixed.report.assertions[0].violated, false);
    assert.equal(fixed.outcome, 'refuted');
    // the verifier-level entry point surfaces the same report
    const v = await verifyInvariant({ invariant: contract('tenant'), fixture: fixtureOf(APPS.tenantVulnerable), commit: COMMIT, config: await configWith(...BOTH) });
    assert.equal(v.results[0].report.assertions[0].evidenceId, one.report.assertions[0].evidenceId);
  }));

  test('[X-404.AC03] an oversize or malformed scenario is rejected or left inconclusive, never judged', async () => {
    const s = await scenarioFor('tenant', 'tenantFixed', 'cross-tenant-access');
    const bad = (mut) => { const i = clone(s.inputs); mut(i); return runOracle({ oracleId: 'business-state', hypothesisId: s.id, commit: COMMIT, files: { 'app.mjs': APPS.tenantFixed }, entry: 'app.mjs', inputs: i }, { config: configCache }); };
    const configCache = await configWith(...BOTH);
    assert.equal((await bad((i) => { i.forbidden = [{ id: 'x', op: 'eval', bind: 'business-state' }]; })).status, 'rejected');
    assert.equal((await bad((i) => { i.attack = []; })).status, 'rejected');
    assert.equal((await bad((i) => { i.attack[0].actor = 'ghost'; })).status, 'rejected');
    assert.equal((await bad((i) => { i.cleanup = []; })).status, 'rejected', 'cleanup is part of the scenario');
    assert.equal((await bad((i) => { i.seed = Array.from({ length: 17 }, (_, n) => ({ key: `k${n}`, value: { n } })); })).status, 'rejected');
    assert.equal((await bad((i) => { i.attack = Array.from({ length: 13 }, () => clone(i.attack[0])); })).status, 'rejected', 'depth is capped by the adapter as well');
    assert.equal((await bad((i) => { i.attack = [{ parallel: [clone(i.attack[0]), clone(i.attack[0])], schedule: [0, 0] }]; })).status, 'rejected', 'a schedule must be a permutation');
    assert.equal((await bad((i) => { i.export = 'x y'; })).status, 'rejected');
  });
});
