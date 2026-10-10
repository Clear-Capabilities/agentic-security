// X-407: bounded business coverage. The inventory, the exercised/untested accounting, the gaps and the additive report fields are
// pure and run everywhere; the tests that EXECUTE scenarios go through the trust boundary and say SKIPPED, NOT PASSED where it
// cannot run. No Linux outcome is claimed.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { _resetKeyCacheForTests } from '../../src/posture/integrity.js';
import { createInvariant, INVARIANT_CLASSES } from '../../src/posture/invariants/schema.js';
import { emptyLedger, recordTransition } from '../../src/posture/invariants/lifecycle.js';
import { verifyInvariant } from '../../src/posture/invariants/run.js';
import { businessCoverage, invariantCoverageFields, GAP_CODES, COVERAGE_SCHEMA } from '../../src/posture/invariants/coverage.js';
import { exportScenarios, verifyScenarioExport, findSecrets, findSecretsIn, NOT_EXHAUSTIVE, EXPORT_SCHEMA } from '../../src/posture/invariants/export.js';
import { runInvariantsCommand } from '../../src/posture/invariants/cli.js';
import { readFixtureDir, readJsonFile } from '../../src/posture/invariants/project-input.js';
import { toJSON, toCLI } from '../../src/report/index.js';
import { createServer } from '../../src/mcp/server.js';
import { ALL_TOOLS } from '../../src/mcp/tools.js';
import { META, scanInput } from '../fixtures/verification-compat/inputs.mjs';
import { contract, APPS, fixtureOf, configWith, boundaryProbe, COMMIT } from '../helpers/invariant-fixtures.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const FEATURE_ENV = 'AGENTIC_SECURITY_ASSURANCE_INVARIANT_SCENARIOS';
const KEY_VAR = 'AGENTIC_SECURITY_HMAC_KEY';
let savedKey; let savedFeature;
let boundary = { ready: false, why: '' };
let config; let onlyScenarios;
before(async () => {
  savedKey = process.env[KEY_VAR]; savedFeature = process.env[FEATURE_ENV];
  process.env[KEY_VAR] = 'ab'.repeat(32);
  delete process.env[FEATURE_ENV];
  _resetKeyCacheForTests();
  boundary = await boundaryProbe();
  config = await configWith('verification-oracles', 'invariant-scenarios');
  onlyScenarios = await configWith('invariant-scenarios');
});
after(() => {
  if (savedKey === undefined) delete process.env[KEY_VAR]; else process.env[KEY_VAR] = savedKey;
  if (savedFeature === undefined) delete process.env[FEATURE_ENV]; else process.env[FEATURE_ENV] = savedFeature;
  _resetKeyCacheForTests();
});
const needsBoundary = (fn) => (t) => (boundary.ready ? fn(t) : t.skip(boundary.why));
const clone = (o) => JSON.parse(JSON.stringify(o));
const POLICY = { id: 'local-1', reviewers: ['dana'] };

function ledgerOf({ approved = [], proposed = [] }) {
  let ledger = emptyLedger();
  for (const inv of [...approved, ...proposed]) ledger = recordTransition(ledger, { action: 'propose', invariant: inv, actor: { id: 'miner', kind: 'code' }, reason: 'mined' }).ledger;
  for (const inv of approved) ledger = recordTransition(ledger, { action: 'approve', invariantId: inv.id, actor: { id: 'dana', kind: 'human' }, reason: 'reviewed' }, { policy: POLICY }).ledger;
  return ledger;
}

const step = (actor, action, key, to = null) => ({ actor, action, key, to });
/** A fabricated `verifyInvariant` result: what a run reports, without executing anything. */
function fakeResult(over = []) {
  return {
    status: 'ok', unsupported: [],
    results: over.map((r) => ({
      kind: 'cross-tenant-access', status: 'completed', outcome: 'refuted', reason: null, limits: { actors: 2, depth: 2, requests: 3, timeBudgetMs: 5000, truncated: false },
      exercise: { control: [], attack: [] }, classification: { kind: 'no-violation-observed' }, ...r,
    })),
  };
}
const tenantExercise = { control: [step('alice', 'updateOrder', 'orders/acme-1')], attack: [step('bob', 'updateOrder', 'orders/acme-1'), step('alice', 'updateOrder', 'orders/globex-1')] };

describe('[X-407.AC01] reports list approved versus proposed invariants and which actors, states and transitions were exercised', () => {
  test('[X-407.AC01] the inventory comes from the VERIFIED ledger: approved, proposed and a document that only claims approval are kept apart', () => {
    const approved = contract('tenant');
    const proposed = contract('workflow');
    const claims = createInvariant({ ...clone(contract('privilege')), review: { state: 'approved', origin: 'authored' } });
    const ledger = ledgerOf({ approved: [approved], proposed: [proposed] });
    const cov = businessCoverage({ entries: [{ invariant: approved }, { invariant: proposed }, { invariant: claims }], ledger });
    assert.deepEqual(cov.inventory.approved.map((i) => i.key), ['orders-tenant-isolation']);
    assert.deepEqual(cov.inventory.proposed.map((i) => i.key), ['orders-follow-the-workflow']);
    assert.deepEqual(cov.inventory.unrecorded.map((i) => i.key), ['settings-admin-only']);
    assert.equal(cov.invariants.find((i) => i.key === 'settings-admin-only').claimsApproval, true, 'the claim is noted and not honoured');
    assert.deepEqual(cov.counts, { approved: 1, proposed: 1, rejected: 0, superseded: 0, unrecorded: 1 });
    assert.equal(cov.ledger.verified, true);

    // a ledger that does not verify approves nothing
    const forged = clone(ledger); forged.records[forged.records.length - 1].signature = 'forged';
    const bad = businessCoverage({ entries: [{ invariant: approved }], ledger: forged });
    assert.equal(bad.counts.approved, 0);
    assert.equal(bad.ledger.verified, false);
    assert.equal(businessCoverage({ entries: [{ invariant: approved }] }).counts.approved, 0, 'no ledger, no approved contract');
  });

  test('[X-407.AC01] exercised actors, states and transitions come only from scenarios that actually executed', () => {
    const inv = createInvariant({ ...clone(contract('tenant')), key: 'orders-two-transitions', transitions: [{ id: 'update-own', action: 'updateOrder', actors: ['alice'], resource: 'o-acme' }, { id: 'archive-own', action: 'archiveOrder', actors: ['alice'], resource: 'o-acme' }] });
    const ran = businessCoverage({ entries: [{ invariant: inv, result: fakeResult([{ exercise: tenantExercise }]) }], ledger: ledgerOf({ approved: [inv] }) });
    const v = ran.invariants[0];
    assert.deepEqual(v.exercised.actors, ['alice', 'bob']);
    assert.deepEqual(v.exercised.transitions, ['update-own'], 'only the transition a step drove');
    assert.deepEqual(v.exercised.states, ['o-acme', 'o-globex']);
    assert.deepEqual(v.declared.transitions, ['update-own', 'archive-own']);
    assert.deepEqual(ran.totals.transitions, { declared: 2, exercised: 1 });

    // the same contract whose scenario never executed exercised nothing, whatever the scenario would have done
    for (const status of ['rejected', 'awaiting-prerequisites']) {
      const none = businessCoverage({ entries: [{ invariant: inv, result: fakeResult([{ status, outcome: null, exercise: tenantExercise }]) }] });
      assert.deepEqual(none.invariants[0].exercised, { actors: [], transitions: [], states: [] }, status);
    }
    assert.equal(businessCoverage({ entries: [{ invariant: inv }] }).invariants[0].exercised.actors.length, 0);
  });

  test('[X-407.AC01] workflow states are the allowed-transition states, reached by moves the scenarios made', () => {
    const wf = contract('workflow');
    const cov = businessCoverage({ entries: [{ invariant: wf, result: fakeResult([{ kind: 'reordered-workflow', exercise: { control: [step('alice', 'advance', 'orders/1', 'paid')], attack: [step('alice', 'advance', 'orders/1', 'shipped')] } }]) }] });
    assert.deepEqual(cov.invariants[0].declared.states, ['new', 'paid', 'shipped']);
    assert.deepEqual(cov.invariants[0].exercised.states, ['new', 'paid', 'shipped']);
    const half = businessCoverage({ entries: [{ invariant: wf, result: fakeResult([{ kind: 'reordered-workflow', exercise: { control: [step('alice', 'advance', 'orders/1', 'paid')], attack: [] } }]) }] });
    assert.deepEqual(half.invariants[0].exercised.states, ['new', 'paid']);
    assert.ok(half.gaps.some((g) => g.code === 'untested-state' && g.state === 'shipped'));
  });

  test('[X-407.AC01] a real run is accounted from what it executed (trust boundary)', needsBoundary(async () => {
    const inv = contract('tenant');
    const result = await verifyInvariant({ invariant: inv, fixture: fixtureOf(APPS.tenantVulnerable), commit: COMMIT, config, ledger: ledgerOf({ approved: [inv] }) });
    const cov = businessCoverage({ entries: [{ invariant: inv, result }], ledger: ledgerOf({ approved: [inv] }) });
    assert.equal(cov.counts.approved, 1);
    assert.deepEqual(cov.invariants[0].exercised.actors, ['alice', 'bob']);
    assert.deepEqual(cov.invariants[0].exercised.transitions, ['update-own']);
    assert.equal(cov.invariants[0].violations.approved, 1, 'the violation of an approved contract is counted as such');
  }));
});

describe('[X-407.AC02] untested transitions, bounded sequence depth, unsupported races and absent contracts remain explicit coverage gaps', () => {
  const codes = (cov) => new Set(cov.gaps.map((g) => g.code));

  test('[X-407.AC02] a declared transition no scenario drove is a gap, and driving it removes the gap', () => {
    const inv = createInvariant({ ...clone(contract('tenant')), key: 'orders-two-transitions', transitions: [{ id: 'update-own', action: 'updateOrder', actors: ['alice'], resource: 'o-acme' }, { id: 'archive-own', action: 'archiveOrder', actors: ['alice'], resource: 'o-acme' }] });
    const partial = businessCoverage({ entries: [{ invariant: inv, result: fakeResult([{ exercise: tenantExercise }]) }] });
    const g = partial.gaps.find((x) => x.code === 'untested-transition');
    assert.equal(g.transition, 'archive-own');
    const driven = { control: [...tenantExercise.control, step('alice', 'archiveOrder', 'orders/acme-1')], attack: tenantExercise.attack };
    const full = businessCoverage({ entries: [{ invariant: inv, result: fakeResult([{ exercise: driven }]) }] });
    assert.equal(full.gaps.some((x) => x.code === 'untested-transition'), false);
    const unusedActor = businessCoverage({ entries: [{ invariant: inv, result: fakeResult([{ exercise: { control: tenantExercise.control, attack: [] } }]) }] });
    assert.ok(unusedActor.gaps.some((x) => x.code === 'untested-actor' && x.actor === 'bob'));
  });

  test('[X-407.AC02] the sequence depth the scenarios were bounded to is always reported, even for a fully exercised contract', () => {
    const inv = contract('tenant');
    const cov = businessCoverage({ entries: [{ invariant: inv, result: fakeResult([{ limits: { depth: 3, requests: 5, truncated: true }, exercise: tenantExercise }]) }] });
    const g = cov.gaps.find((x) => x.code === 'bounded-depth');
    assert.equal(g.maxDepth, 3);
    assert.equal(g.maxRequests, 5);
    assert.equal(g.truncated, 1);
    assert.match(g.detail, /longer sequences are not explored/);
    assert.equal(cov.bounds.hard.depth, 12);
    assert.equal(codes(businessCoverage({ entries: [{ invariant: inv }] })).has('bounded-depth'), false, 'nothing ran, so there is no depth to report: the gap is not-executed instead');
    assert.equal(codes(businessCoverage({ entries: [{ invariant: inv }] })).has('not-executed'), true);
  });

  test('[X-407.AC02] races: a class with no concurrent family, or a concurrent scenario that did not settle, is an unsupported-race gap', () => {
    const tenantCov = businessCoverage({ entries: [{ invariant: contract('tenant'), result: fakeResult([{ exercise: tenantExercise }]) }] });
    assert.ok(tenantCov.gaps.some((g) => g.code === 'unsupported-race' && /no concurrent-operations scenario exists for the 'tenant-isolation' class/.test(g.detail)));
    const idem = contract('idempotency');
    const noRace = businessCoverage({ entries: [{ invariant: idem, result: fakeResult([{ kind: 'duplicate-request' }]) }] });
    assert.ok(noRace.gaps.some((g) => g.code === 'unsupported-race' && /did not settle|no concurrent/.test(g.detail)));
    const stuck = businessCoverage({ entries: [{ invariant: idem, result: fakeResult([{ kind: 'concurrent-operations', outcome: 'inconclusive' }]) }] });
    assert.ok(stuck.gaps.some((g) => g.code === 'unsupported-race'));
    assert.ok(stuck.gaps.some((g) => g.code === 'unsettled-scenario'));
    const ran = businessCoverage({ entries: [{ invariant: idem, result: fakeResult([{ kind: 'concurrent-operations', outcome: 'confirmed' }]) }] });
    assert.equal(ran.gaps.some((g) => g.code === 'unsupported-race'), false);
    assert.ok(ran.gaps.some((g) => g.code === 'cooperative-scheduling' && /parallel execution/.test(g.detail)), 'even a settled race run states what cooperative scheduling does not cover');
  });

  test('[X-407.AC02] absent contracts are gaps: no contract at all, and every class with none', () => {
    const none = businessCoverage({ entries: [] });
    assert.ok(none.gaps.some((g) => g.code === 'absent-contract' && !g.class));
    const one = businessCoverage({ entries: [{ invariant: contract('tenant') }] });
    const absent = one.gaps.filter((g) => g.code === 'absent-contract').map((g) => g.class).sort();
    assert.deepEqual(absent, INVARIANT_CLASSES.filter((c) => c !== 'tenant-isolation').sort());
    const all = businessCoverage({ entries: ['tenant', 'privilege', 'conservation', 'workflow', 'idempotency'].map((n) => ({ invariant: contract(n) })) });
    assert.equal(all.gaps.some((g) => g.code === 'absent-contract'), false);
  });

  test('[X-407.AC02] unsupported and unsettled scenarios, and an unapproved contract, are gaps with their reasons; every gap code is a documented one', () => {
    const inv = contract('tenant');
    const result = { ...fakeResult([{ outcome: 'inconclusive', reason: 'the control flow did not show the application working', exercise: tenantExercise }]), unsupported: [{ kind: 'privilege-change', reason: 'needs an unprivileged actor' }] };
    const cov = businessCoverage({ entries: [{ invariant: inv, result }], ledger: ledgerOf({ proposed: [inv] }) });
    assert.ok(cov.gaps.some((g) => g.code === 'unsupported-scenario' && /needs an unprivileged actor/.test(g.detail)));
    assert.ok(cov.gaps.some((g) => g.code === 'unsettled-scenario' && /did not show the application working/.test(g.detail)));
    assert.ok(cov.gaps.some((g) => g.code === 'unapproved-contract'));
    for (const g of [...cov.gaps, ...businessCoverage({ entries: [] }).gaps]) assert.ok(GAP_CODES.includes(g.code), g.code);
  });

  test('[X-407.AC02] a clean, fully exercised run still never reads as exhaustive', () => {
    const inv = contract('tenant');
    const cov = businessCoverage({ entries: [{ invariant: inv, result: fakeResult([{ exercise: tenantExercise }]) }], ledger: ledgerOf({ approved: [inv] }) });
    assert.equal(cov.claims.exhaustive, false);
    assert.equal(cov.claims.statement, NOT_EXHAUSTIVE);
    assert.ok(cov.lines.some((l) => /not exhaustive/.test(l)));
    assert.ok(cov.gaps.length > 0, 'bounded depth, races and absent classes remain');
    assert.equal(JSON.stringify(cov).match(/\b(fully covered|complete coverage|no gaps|proves? correct|correct business logic)\b/i), null);
  });
});

describe('[X-407.AC03] CLI and MCP offer reproducible scenario export without exposing tenant secrets or claiming exhaustive business-logic correctness', () => {
  const fixtureFor = (app) => fixtureOf(app);

  test('[X-407.AC03] the export is gated: with the feature off nothing is built; on, it is reproducible and checks out', () => {
    const inv = contract('tenant');
    const off = exportScenarios({ invariant: inv, fixture: fixtureFor(APPS.tenantVulnerable), config: undefined });
    assert.equal(off.status, 'disabled');
    assert.equal(off.export, undefined);
    const on = exportScenarios({ invariant: inv, fixture: fixtureFor(APPS.tenantVulnerable), config: onlyScenarios, commit: COMMIT });
    assert.equal(on.status, 'ok');
    const e = on.export;
    assert.equal(e.schema, EXPORT_SCHEMA);
    assert.equal(e.scenarios.length, 1);
    assert.match(e.scenarios[0].digest, /^sha256:/);
    assert.match(e.scenarios[0].manifest.id, /^rpl:/, 'with a commit the replay manifest is included');
    assert.equal(e.scenarios[0].manifest.fixture.digest, e.fixture.digest);
    assert.deepEqual(verifyScenarioExport(e, { fixtureFiles: fixtureFor(APPS.tenantVulnerable).files }), { ok: true, errors: [] });
    // same inputs, same bytes
    const again = exportScenarios({ invariant: inv, fixture: fixtureFor(APPS.tenantVulnerable), config: onlyScenarios, commit: COMMIT });
    assert.equal(JSON.stringify(again.export), JSON.stringify(e));
    assert.equal(exportScenarios({ invariant: inv, fixture: fixtureFor(APPS.tenantVulnerable), config: onlyScenarios, commit: COMMIT, seed: 5 }).export.scenarios[0].scenario.seed, 5);
  });

  test('[X-407.AC03] an edited export, a different fixture or an overclaim is detected', () => {
    const fx = fixtureFor(APPS.tenantVulnerable);
    const e = exportScenarios({ invariant: contract('tenant'), fixture: fx, config: onlyScenarios, commit: COMMIT }).export;
    const check = (mutate, code, opts = { fixtureFiles: fx.files }) => { const m = clone(e); mutate(m); const v = verifyScenarioExport(m, opts); assert.equal(v.ok, false, code); assert.ok(v.errors.some((x) => x.code === code), `${code}: ${JSON.stringify(v.errors)}`); };
    check((m) => { m.scenarios[0].scenario.inputs.attack = []; }, 'scenario-tampered');
    check((m) => { m.fixture.digest = 'sha256:' + '1'.repeat(64); }, 'fixture-pin-mismatch');
    check((m) => { m.claims.exhaustive = true; }, 'overclaim');
    check((m) => { m.claims = {}; }, 'overclaim');
    check((m) => { m.fixture.included = true; }, 'fixture-included');
    check((m) => { m.secretsExported = true; }, 'secrets-flag');
    check(() => {}, 'fixture-mismatch', { fixtureFiles: fixtureFor(APPS.tenantFixed).files });
    assert.equal(verifyScenarioExport({}).ok, false);
  });

  test('[X-407.AC03] no tenant secret leaves: the fixture source is never included and a scenario holding a secret is withheld, naming where and never what', () => {
    const fx = fixtureFor(`${APPS.tenantVulnerable}\nconst creds = { password: "hunter2hunter2" }; // sk-live-0123456789abcdef\n`);
    const e = exportScenarios({ invariant: contract('tenant'), fixture: fx, config: onlyScenarios }).export;
    const text = JSON.stringify(e);
    assert.equal(text.includes('hunter2'), false);
    assert.equal(text.includes('sk-live'), false);
    assert.equal(text.includes('export function createApp'), false, 'the fixture source is not exported, only its digest');
    assert.equal(e.fixture.included, false);

    const secretMarker = createInvariant({ ...clone(contract('tenant')), key: 'orders-secret-marker', resources: [
      { id: 'o-acme', kind: 'order', tenant: 'acme', key: 'orders/acme-1', marker: 'sk-live-ABCDEFGHIJKLMNOP' }, { id: 'o-globex', kind: 'order', tenant: 'globex', key: 'orders/globex-1', marker: 'GLOBEX-ONLY-1' }] });
    const r = exportScenarios({ invariant: secretMarker, fixture: fixtureFor(APPS.tenantVulnerable), config: onlyScenarios });
    assert.equal(r.status, 'blocked');
    assert.equal(r.withheld.length, 1);
    assert.ok(r.withheld[0].where.every((w) => w.where && w.kind && !JSON.stringify(w).includes('ABCDEFGHIJKLMNOP')));
    assert.ok(findSecretsIn({ inputs: { seed: [{ value: { apiToken: 'x1' } }] } }).length === 1);
    assert.deepEqual(findSecretsIn({ a: { note: 'ordinary text', amount: 10 } }), []);
    assert.ok(findSecrets({ 'a.js': 'const k = "AKIAABCDEFGHIJKLMNOP";' }).length === 1);
    assert.deepEqual(findSecrets({ 'a.js': 'const x = 1;' }), []);
  });

  test('[X-407.AC03] a credential pasted into the contract name or key blocks the export, naming where and never what', () => {
    const named = createInvariant({ ...clone(contract('tenant')), key: 'orders-named-secret', name: 'Orders (sk-live-0123456789abcdef)' });
    const r = exportScenarios({ invariant: named, fixture: fixtureFor(APPS.tenantVulnerable), config: onlyScenarios });
    assert.equal(r.status, 'blocked');
    assert.equal(r.export, undefined);
    assert.deepEqual(r.withheld[0].where.map((w) => w.where), ['invariant.name']);
    assert.equal(JSON.stringify(r).includes('0123456789abcdef'), false);
  });

  test('[X-407.AC03] the export states it is a bounded sample and never claims exhaustive correctness', () => {
    const e = exportScenarios({ invariant: contract('tenant'), fixture: fixtureFor(APPS.tenantVulnerable), config: onlyScenarios }).export;
    assert.equal(e.claims.exhaustive, false);
    assert.equal(e.claims.statement, NOT_EXHAUSTIVE);
    assert.ok(e.bounds.hard.depth && e.bounds.applied.depth, 'the bounds that applied are listed');
    assert.ok(Array.isArray(e.notBuilt));
    assert.equal(e.approval.state, 'unrecorded');
    assert.equal(exportScenarios({ invariant: contract('tenant'), fixture: fixtureFor(APPS.tenantVulnerable), config: onlyScenarios, ledger: ledgerOf({ approved: [contract('tenant')] }) }).export.approval.state, 'approved');
  });

  function project(app = APPS.tenantVulnerable) {
    const dir = mkTestTmp('as-x407-');
    fs.mkdirSync(path.join(dir, 'fx'));
    fs.writeFileSync(path.join(dir, 'fx', 'app.mjs'), app);
    fs.writeFileSync(path.join(dir, 'inv.json'), JSON.stringify(contract('tenant')));
    return dir;
  }

  test('[X-407.AC03] the CLI exports to stdout or a file, refuses with the feature off, and rejects bad input (in-process and as a process)', async () => {
    const dir = project();
    const run = async (sub, flags, env, extra = []) => {
      let out = ''; let err = '';
      const code = await runInvariantsCommand({ _: ['invariants', sub, ...extra], flags }, { cwd: dir, env, out: (x) => { out += x; }, err: (x) => { err += x; } });
      return { code, out, err };
    };
    const on = { ...process.env, [FEATURE_ENV]: '1' };
    const ok = await run('export', { invariant: 'inv.json', fixture: 'fx', commit: COMMIT }, on);
    assert.equal(ok.code, 0, ok.err);
    const doc = JSON.parse(ok.out);
    assert.equal(verifyScenarioExport(doc, { fixtureFiles: fixtureFor(APPS.tenantVulnerable).files }).ok, true);
    const toFile = await run('export', { invariant: 'inv.json', fixture: 'fx', output: 'out.json' }, on);
    assert.equal(toFile.code, 0);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'out.json'), 'utf8')).claims.exhaustive, false);

    const off = await run('export', { invariant: 'inv.json', fixture: 'fx' }, { ...process.env, [FEATURE_ENV]: '0' });
    assert.equal(off.code, 1);
    assert.match(off.err, /disabled/);
    assert.equal(off.out, '');
    assert.equal((await run('export', { invariant: 'inv.json' }, on)).code, 2, 'usage error');
    assert.equal((await run('export', { invariant: 'missing.json', fixture: 'fx' }, on)).code, 1);
    assert.equal((await run('export', { invariant: 'inv.json', fixture: 'fx', commit: 'nothex' }, on)).code, 1);
    assert.equal((await run('bogus', {}, on)).code, 2);

    const spawned = spawnSync(process.execPath, [path.join(SCANNER, 'bin', 'agentic-security.js'), 'invariants', 'export', '--invariant', 'inv.json', '--fixture', 'fx'], { cwd: dir, env: on, encoding: 'utf8', timeout: 60000 });
    assert.equal(spawned.status, 0, spawned.stderr);
    assert.equal(JSON.parse(spawned.stdout).schema, EXPORT_SCHEMA);
    const spawnedOff = spawnSync(process.execPath, [path.join(SCANNER, 'bin', 'agentic-security.js'), 'invariants', 'export', '--invariant', 'inv.json', '--fixture', 'fx'], { cwd: dir, env: { ...process.env, [FEATURE_ENV]: '' }, encoding: 'utf8', timeout: 60000 });
    assert.equal(spawnedOff.status, 1);
  });

  test('[X-407.AC03] the CLI coverage report is the same bounded report, with every contract untested when nothing was run', async () => {
    const dir = project();
    let out = '';
    const code = await runInvariantsCommand({ _: ['invariants', 'coverage'], flags: { invariant: 'inv.json', json: true } }, { cwd: dir, out: (s) => { out += s; }, err: () => {} });
    assert.equal(code, 0);
    const cov = JSON.parse(out);
    assert.equal(cov.schema, COVERAGE_SCHEMA);
    assert.equal(cov.claims.exhaustive, false);
    assert.equal(cov.invariants[0].exercised.transitions.length, 0);
    assert.ok(cov.gaps.some((g) => g.code === 'not-executed'));
  });

  test('[X-407.AC03] the MCP tool is read-only, confined to the session root, gated by the feature and returns no secret', async () => {
    const tool = ALL_TOOLS.find((t) => t.name === 'invariant_scenario_export');
    assert.ok(tool, 'the tool is registered');
    assert.equal(tool.inputSchema.additionalProperties, false);
    const dir = project();
    const { handleRequest } = createServer({ sessionRoot: dir });
    const call = async (args) => JSON.parse((await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'invariant_scenario_export', arguments: args } })).result.content[0].text);
    const list = await handleRequest({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    assert.ok(list.result.tools.some((t) => t.name === 'invariant_scenario_export'));

    process.env[FEATURE_ENV] = '1';
    try {
      const ok = await call({ invariant_file: 'inv.json', fixture_dir: 'fx', commit: COMMIT });
      assert.equal(ok.ok, true, JSON.stringify(ok));
      assert.equal(ok._meta.untrusted_excerpts, true);
      assert.equal(ok.export.claims.exhaustive, false);
      assert.equal(JSON.stringify(ok).includes('export function createApp'), false);
      assert.equal(verifyScenarioExport(ok.export, { fixtureFiles: fixtureFor(APPS.tenantVulnerable).files }).ok, true);
      for (const args of [{ invariant_file: '../outside.json', fixture_dir: 'fx' }, { invariant_file: 'inv.json', fixture_dir: '/etc' }, { invariant_file: 'inv.json', fixture_dir: 'fx', ledger_file: '../../x' }]) {
        const r = await call(args);
        assert.equal(r.ok, false, JSON.stringify(args));
        assert.match(r.reason, /path refused|escapes|outside/);
      }
      // a secret shape the export's own scan does not know is still stopped by the server's redactor, which blocks rather than edits
      const tg = createInvariant({ ...clone(contract('tenant')), key: 'orders-telegram-marker', resources: [
        { id: 'o-acme', kind: 'order', tenant: 'acme', key: 'orders/acme-1', marker: '123456789:AAEhBP0av18F2xMGzOoa1Rzh2ddGIYNJkNQ' }, { id: 'o-globex', kind: 'order', tenant: 'globex', key: 'orders/globex-1', marker: 'GLOBEX-ONLY-1' }] });
      fs.writeFileSync(path.join(dir, 'tg.json'), JSON.stringify(tg));
      const direct = exportScenarios({ invariant: tg, fixture: fixtureFor(APPS.tenantVulnerable), config: onlyScenarios });
      assert.equal(direct.status, 'ok', 'the export-side scan does not know this shape');
      const blocked = await call({ invariant_file: 'tg.json', fixture_dir: 'fx' });
      assert.equal(blocked.ok, false);
      assert.equal(blocked.status, 'blocked');
      assert.equal(JSON.stringify(blocked).includes('AAEhBP0av18F2xMGzOoa1Rzh2ddGIYNJkNQ'), false);
      // a fixture holding a secret never reaches the response
      fs.writeFileSync(path.join(dir, 'fx', 'app.mjs'), `${APPS.tenantVulnerable}\n// sk-live-0123456789abcdef\n`);
      const leaky = await call({ invariant_file: 'inv.json', fixture_dir: 'fx' });
      assert.equal(JSON.stringify(leaky).includes('sk-live'), false);
    } finally { delete process.env[FEATURE_ENV]; }
    process.env[FEATURE_ENV] = '0';
    try {
      const off = await call({ invariant_file: 'inv.json', fixture_dir: 'fx' });
      assert.equal(off.ok, false);
      assert.equal(off.status, 'disabled');
    } finally { delete process.env[FEATURE_ENV]; }
  });

  test('[X-407.AC03] project input readers refuse links, oversize and non-text content', () => {
    const dir = mkTestTmp('as-x407-in-');
    fs.mkdirSync(path.join(dir, 'fx'));
    fs.writeFileSync(path.join(dir, 'fx', 'a.mjs'), 'ok');
    fs.writeFileSync(path.join(dir, 'secret.txt'), 'outside');
    fs.symlinkSync(path.join(dir, 'secret.txt'), path.join(dir, 'fx', 'link.mjs'));
    const r = readFixtureDir(path.join(dir, 'fx'));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /link\.mjs.*symbolic/.test(e)));
    assert.deepEqual(Object.keys(r.files), ['a.mjs']);
    fs.writeFileSync(path.join(dir, 'bin.dat'), Buffer.from([1, 0, 2]));
    fs.mkdirSync(path.join(dir, 'fx2')); fs.copyFileSync(path.join(dir, 'bin.dat'), path.join(dir, 'fx2', 'b.mjs'));
    assert.equal(readFixtureDir(path.join(dir, 'fx2')).ok, false);
    assert.equal(readFixtureDir(path.join(dir, 'nope')).ok, false);
    fs.symlinkSync(path.join(dir, 'secret.txt'), path.join(dir, 'l.json'));
    assert.equal(readJsonFile(path.join(dir, 'l.json')).ok, false);
    assert.equal(readJsonFile(path.join(dir, 'secret.txt')).ok, false, 'not JSON');
  });
});

describe('[X-407.AC03] additive report fields: pinned previous output is unchanged, and the feature flag gates the new key', () => {
  const pinned = (name) => fs.readFileSync(path.join(SCANNER, 'test', 'fixtures', 'invariant-compat', name), 'utf8');
  const coverage = () => businessCoverage({ entries: [{ invariant: contract('tenant'), result: fakeResult([{ exercise: tenantExercise }]) }] });

  test('[X-407.AC03] flag off (the default): the JSON and CLI reports are byte-identical to the pinned previous output, even with coverage supplied', () => {
    delete process.env[FEATURE_ENV];
    const plain = `${JSON.stringify(JSON.parse(JSON.stringify(toJSON(scanInput(), META))), null, 2)}\n`;
    assert.equal(plain, pinned('report-json.pre-x407.json'));
    assert.equal(`${toCLI(scanInput(), META)}\n`, pinned('report-cli.pre-x407.txt'));
    const supplied = { ...scanInput(), invariantCoverage: coverage() };
    assert.equal(`${JSON.stringify(JSON.parse(JSON.stringify(toJSON(supplied, META))), null, 2)}\n`, pinned('report-json.pre-x407.json'), 'supplying coverage with the flag off changes nothing');
    assert.equal(`${toCLI(supplied, META)}\n`, pinned('report-cli.pre-x407.txt'));
    assert.deepEqual(invariantCoverageFields(coverage(), { config: undefined }), {}, 'default config: off');
  });

  test('[X-407.AC03] flag on: every previous field is unchanged and the only addition is invariantCoverage; nothing is added without coverage', () => {
    process.env[FEATURE_ENV] = '1';
    try {
      const prev = JSON.parse(pinned('report-json.pre-x407.json'));
      const without = JSON.parse(JSON.stringify(toJSON(scanInput(), META)));
      assert.deepEqual(without, prev, 'flag on but nothing to report: unchanged');
      assert.equal(`${toCLI(scanInput(), META)}\n`, pinned('report-cli.pre-x407.txt'));
      const withCov = JSON.parse(JSON.stringify(toJSON({ ...scanInput(), invariantCoverage: coverage() }, META)));
      const { invariantCoverage, ...rest } = withCov;
      assert.deepEqual(rest, prev, 'all previous fields keep their values');
      assert.equal(invariantCoverage.schema, COVERAGE_SCHEMA);
      assert.equal(invariantCoverage.claims.exhaustive, false);
      const cli = toCLI({ ...scanInput(), invariantCoverage: coverage() }, META);
      assert.match(cli, /Business-logic coverage \(bounded sample, not exhaustive\)/);
      assert.ok(cli.startsWith(pinned('report-cli.pre-x407.txt').split('\n')[0]), 'the earlier lines are unchanged');
      // a foreign object under the key is not rendered
      assert.deepEqual(invariantCoverageFields({ schema: 'something-else' }), {});
      assert.deepEqual(invariantCoverageFields(null), {});
    } finally { delete process.env[FEATURE_ENV]; }
  });
});
