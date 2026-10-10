// X-406: verify repairs against invariants. A repair is verified-fix only when the violation is gone, the authorized workflows
// still work and every other APPROVED contract still holds, all by executed receipted runs. The pure checks (reason codes, the
// artifact's structure, tamper detection) run everywhere; the execution tests go through the trust boundary and say
// SKIPPED, NOT PASSED where it cannot run. No Linux outcome is claimed.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { _resetKeyCacheForTests } from '../../src/posture/integrity.js';
import { createInvariant } from '../../src/posture/invariants/schema.js';
import { generateScenarios } from '../../src/posture/invariants/scenarios.js';
import { emptyLedger, recordTransition } from '../../src/posture/invariants/lifecycle.js';
import { verifyInvariantRepair, runRegressionArtifact, validateRegressionArtifact, reasonCodeFor, REASON_CODES } from '../../src/posture/invariants/repair.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { promotePatch } from '../../src/posture/verification/patch-promotion.js';
import { contract, APPS, fixtureOf, configWith, boundaryProbe, COMMIT } from '../helpers/invariant-fixtures.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const KEY_VAR = 'AGENTIC_SECURITY_HMAC_KEY';
let savedKey;
let boundary = { ready: false, why: '' };
let config;
before(async () => {
  savedKey = process.env[KEY_VAR];
  process.env[KEY_VAR] = 'ab'.repeat(32);
  _resetKeyCacheForTests();
  boundary = await boundaryProbe();
  config = await configWith('verification-oracles', 'invariant-scenarios', 'patch-negative-verification');
});
after(() => {
  if (savedKey === undefined) delete process.env[KEY_VAR]; else process.env[KEY_VAR] = savedKey;
  _resetKeyCacheForTests();
});
const needsBoundary = (fn) => (t) => (boundary.ready ? fn(t) : t.skip(boundary.why));

const clone = (o) => JSON.parse(JSON.stringify(o));
const POLICY = { id: 'local-1', reviewers: ['dana'] };
const READ = 'const o = ctx.store.read(key); if (!o) return { status: 404 };';

function ledgerOf(approved, proposed = []) {
  let ledger = emptyLedger();
  for (const inv of [...approved, ...proposed]) ledger = recordTransition(ledger, { action: 'propose', invariant: inv, actor: { id: 'miner', kind: 'code' }, reason: 'mined' }).ledger;
  for (const inv of approved) ledger = recordTransition(ledger, { action: 'approve', invariantId: inv.id, actor: { id: 'dana', kind: 'human' }, reason: 'reviewed' }, { policy: POLICY }).ledger;
  return ledger;
}

// vulnerable: writes any tenant's order. also has viewOrder, an authorized read workflow
const VULN = `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} ctx.store.write(key, { ...o, note: p.note }); return { status: 200 }; },
  viewOrder(ctx, key) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403 }; return { status: 200, order: { id: key } }; } }; }`;
const FIXED = `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403 }; ctx.store.write(key, { ...o, note: p.note }); return { status: 200 }; },
  viewOrder(ctx, key) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403 }; return { status: 200, order: { id: key } }; } }; }`;
const NO_FIX = `${VULN}\n// formatting only\n`;
const BLOCK_ALL = `export function createApp() { return { updateOrder() { return { status: 403 }; }, viewOrder() { return { status: 403 }; } }; }`;
const DROPS_VIEW = `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403 }; ctx.store.write(key, { ...o, note: p.note }); return { status: 200 }; } }; }`;
// closes the write but now answers the other tenant WITH the record: the read contract the original satisfied now fails
const FIXED_BUT_LEAKS = `export function createApp() { return { updateOrder(ctx, key, p) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403, order: o }; ctx.store.write(key, { ...o, note: p.note }); return { status: 200 }; },
  viewOrder(ctx, key) { ${READ} if (o.tenant !== ctx.tenant) return { status: 403 }; return { status: 200, order: { id: key } }; } }; }`;

const tenant = () => contract('tenant');
const leak = () => contract('leak');

async function setup({ extraApproved = [], proposed = [], app = VULN } = {}) {
  const inv = tenant();
  const fixture = fixtureOf(app);
  const scenario = generateScenarios(inv, { fixture, config }).scenarios[0];
  return { inv, fixture, scenario, ledger: ledgerOf([inv, ...extraApproved], proposed) };
}
const repair = async (s, patchApp, over = {}, o = {}) => verifyInvariantRepair({
  invariant: s.inv, ledger: s.ledger, scenario: s.scenario, fixture: s.fixture, patch: { files: { 'app.mjs': patchApp } }, commit: COMMIT, ...over,
}, { config, ...o });

const cache = {};
const once = async (name, fn) => (cache[name] ??= await fn());
const good = () => once('good', async () => { const s = await setup(); return { s, r: await repair(s, FIXED, { workflows: [[{ actor: 'alice', action: 'viewOrder', args: ['orders/acme-1', {}] }]] }) }; });

describe('[X-406.AC01] a candidate repair must eliminate the original violation and preserve authorized workflows and existing approved invariants', () => {
  test('[X-406.AC01] a repair that closes the hole and keeps the workflows is verified-fix, with every leg executed', needsBoundary(async () => {
    const { r } = await good();
    assert.equal(r.status, 'verified-fix', JSON.stringify(r.blockers));
    assert.equal(r.verifiedFix, true);
    assert.deepEqual(r.blockers, []);
    const steps = Object.fromEntries(r.patchNegative.steps.map((x) => [x.step, x]));
    assert.equal(steps['original-positive'].outcome, 'confirmed', 'the violation reproduced on the original');
    assert.equal(steps['patched-negative'].outcome, 'refuted', 'and is gone on the patched revision');
    assert.equal(steps['functional-baseline'].outcome, 'refuted', 'the authorized workflows are clean on the original');
    assert.equal(steps['functional-regression'].outcome, 'refuted', 'and still clean on the patched revision');
    assert.equal(r.verificationRecord.repair.status, 'replay-verified');
    assert.match(r.summary, /^verified-fix: /);
  }));

  test('[X-406.AC01] promotion accepts the business-state behaviour check only when the proposal names it, and the default is unchanged', needsBoundary(async () => {
    const { s, r } = await good();
    const proposal = { hypothesisId: s.scenario.id, revision: COMMIT, originalFiles: s.fixture.files, patchFiles: { 'app.mjs': FIXED } };
    const receipts = r.patchNegative.receipts;
    assert.equal(promotePatch({ proposal: { ...proposal, functionalOracle: 'business-state' }, receipts }).ok, true);
    const dflt = promotePatch({ proposal, receipts });
    assert.equal(dflt.ok, false, 'a business-state functional receipt does not satisfy the default functional-regression requirement');
    assert.ok(dflt.reasons.some((x) => x.code === 'oracle-changed' && /functional-regression/.test(x.message)));
    const named = promotePatch({ proposal: { ...proposal, functionalOracle: 'functional-regression' }, receipts });
    assert.equal(named.ok, false);
    const bad = promotePatch({ proposal: { ...proposal, functionalOracle: 'injection-execution' }, receipts });
    assert.equal(bad.ok, false);
    assert.ok(bad.reasons.some((x) => x.code === 'bad-proposal'));
  }));

  test('[X-406.AC01] the behaviour check may be the functional-regression or business-state oracle and nothing else', async () => {
    const { verifyPatchNegative } = await import('../../src/posture/verification/patch-negative.js');
    const s = await setup();
    const req = (oracleId) => ({ hypothesisId: s.scenario.id, commit: COMMIT, original: { files: s.fixture.files, entry: 'app.mjs', oracleId: 'business-state', inputs: s.scenario.inputs }, patch: { files: { 'app.mjs': FIXED } }, functional: { oracleId, inputs: s.scenario.inputs } });
    for (const bad of ['injection-execution', 'nonexistent', 'authorization-decision']) {
      const r = await verifyPatchNegative(req(bad), { config });
      assert.equal(r.verifiedFix, false, bad);
      assert.equal(r.failureCode, 'bad-request', bad);
      assert.match(r.reason, /functional check oracle must be one of/);
    }
    assert.notEqual((await verifyPatchNegative(req('functional-regression'), { config })).failureCode, 'bad-request', 'the default oracle is still accepted');
  });

  test('[X-406.AC01] a repair that does not remove the violation is not verified', needsBoundary(async () => {
    const s = await setup();
    const r = await repair(s, NO_FIX);
    assert.equal(r.verifiedFix, false);
    assert.deepEqual(r.reasonCodes, ['violation-not-eliminated']);
    assert.equal(r.artifact, null, 'no regression artifact exists for an unverified repair');
    assert.equal(r.verificationRecord.repair.status, 'proposed', 'the record never reads replay-verified');
    assert.equal(r.repairRecords.at(-1).kind, 'rejected');
  }));

  test('[X-406.AC01] a repair that "fixes" the violation by blocking everyone breaks the authorized workflow and is not verified', needsBoundary(async () => {
    const s = await setup();
    const r = await repair(s, BLOCK_ALL);
    assert.equal(r.verifiedFix, false);
    assert.deepEqual(r.reasonCodes, ['authorized-workflow-broken']);
  }));

  test('[X-406.AC01] a declared authorized workflow that the repair removes blocks the fix', needsBoundary(async () => {
    const s = await setup();
    const wf = { workflows: [[{ actor: 'alice', action: 'viewOrder', args: ['orders/acme-1', {}] }]] };
    const ok = await repair(s, FIXED, wf);
    assert.equal(ok.verifiedFix, true, JSON.stringify(ok.blockers));
    const broken = await repair(s, DROPS_VIEW, wf);
    assert.equal(broken.verifiedFix, false);
    assert.ok(broken.reasonCodes.includes('authorized-workflow-broken'), JSON.stringify(broken.blockers));
    // without the declared workflow the same repair is accepted: only the declared workflows are checked, and the report says so
    assert.equal((await repair(s, DROPS_VIEW)).verifiedFix, true);
    assert.match(ok.summary, /Only the declared scenario, workflows/);
  }));

  test('[X-406.AC01] every other APPROVED invariant must still hold: a regression on one blocks, a proposed one is not required', needsBoundary(async () => {
    const withLeakApproved = await setup({ extraApproved: [leak()] });
    const keeps = await repair(withLeakApproved, FIXED, { others: [leak()] });
    assert.equal(keeps.verifiedFix, true, JSON.stringify(keeps.blockers));
    assert.equal(keeps.preservation.length, 1);
    assert.equal(keeps.preservation[0].status, 'preserved');
    assert.ok(keeps.preservation[0].legs.every((l) => l.baseline === 'refuted' && l.patched === 'refuted'));

    const regress = await repair(withLeakApproved, FIXED_BUT_LEAKS, { others: [leak()] });
    assert.equal(regress.verifiedFix, false);
    assert.deepEqual(regress.reasonCodes, ['invariant-regression']);
    assert.equal(regress.blockers[0].invariant, leak().id);
    assert.equal(regress.artifact, null);
    assert.equal(regress.repairRecords.at(-1).kind, 'rejected', 'a promoted patch that then fails preservation is recorded as rejected');
    assert.equal(regress.verificationRecord.repair.status, 'proposed');

    const proposedOnly = await setup({ proposed: [leak()] });
    const advisory = await repair(proposedOnly, FIXED_BUT_LEAKS, { others: [leak()] });
    assert.equal(advisory.verifiedFix, true, 'a proposed contract is advisory and does not block');
    assert.deepEqual(advisory.notRequired.map((n) => n.state), ['proposed']);
  }));

  test('[X-406.AC01] a repair of a candidate (unapproved) contract is never verified-fix, and nothing is executed for it', async () => {
    const inv = tenant();
    const fixture = fixtureOf(VULN);
    const scenario = generateScenarios(inv, { fixture, config }).scenarios[0];
    const proposedLedger = ledgerOf([], [inv]);
    let ran = false;
    const spy = { deps: { runInBoundary: async () => { ran = true; return { blocked: true, reasons: ['spy'] }; } } };
    for (const ledger of [proposedLedger, emptyLedger(), undefined, { ...clone(proposedLedger), records: clone(proposedLedger.records).map((r) => ({ ...r, signature: 'forged' })) }]) {
      const r = await verifyInvariantRepair({ invariant: inv, ledger, scenario, fixture, patch: { files: { 'app.mjs': FIXED } }, commit: COMMIT }, { config, runOptions: spy });
      assert.equal(r.verifiedFix, false);
      assert.deepEqual(r.reasonCodes, ['invariant-not-approved']);
    }
    assert.equal(ran, false, 'no scenario was run for a contract nobody approved');
  });
});

describe('[X-406.AC02] a regression artifact records the exact patch, invariant revision and replay manifest and can run independently of the original agent conversation', () => {
  test('[X-406.AC02] the artifact carries the exact patch, the invariant revision with its approval, and one pinned manifest per leg', needsBoundary(async () => {
    const { s, r } = await good();
    const a = r.artifact;
    assert.deepEqual(a.patch.files, { 'app.mjs': FIXED });
    assert.equal(a.patch.digest, digestOf({ 'app.mjs': FIXED }));
    assert.equal(a.invariant.revision, s.inv.revision);
    assert.equal(a.invariant.id, s.inv.id);
    assert.equal(a.invariant.document.id, s.inv.id, 'the full contract is inside the artifact');
    assert.equal(a.invariant.approval.state, 'approved');
    assert.ok(a.invariant.approval.transitionId && a.invariant.approval.reviewer === 'dana' && a.invariant.approval.ledgerHead);
    assert.equal(a.commit, COMMIT);
    assert.deepEqual(a.legs.map((l) => l.role), ['original-positive', 'patched-negative', 'workflow-baseline', 'workflow-preserved']);
    for (const l of a.legs) {
      assert.match(l.manifest.id, /^rpl:/);
      assert.equal(l.manifest.fixture.digest, a.fixture.digest);
      assert.equal(l.manifest.repository.commit, COMMIT);
      assert.equal(l.manifest.patch?.digest ?? null, l.patched ? a.patch.digest : null);
    }
    assert.deepEqual(a.legs.map((l) => l.expected), ['confirmed', 'refuted', 'refuted', 'refuted']);
    assert.deepEqual(validateRegressionArtifact(a), { ok: true, errors: [] });
    assert.equal(a.repair.ledger.at(-1).kind, 'promoted');
  }));

  test('[X-406.AC02] a JSON copy of the artifact re-executes every leg and passes; a fresh process does the same from the file alone', needsBoundary(async () => {
    const { r } = await good();
    const copy = JSON.parse(JSON.stringify(r.artifact));
    const run = await runRegressionArtifact(copy, { config });
    assert.equal(run.status, 'passed', run.summary);
    assert.equal(run.legs.length, 4);
    assert.ok(run.legs.every((l) => l.matched && /^sha256:/.test(l.receiptDigest)));

    const dir = mkTestTmp('as-x406-');
    const file = path.join(dir, 'artifact.json');
    fs.writeFileSync(file, JSON.stringify(r.artifact));
    const env = { ...process.env, AGENTIC_SECURITY_ASSURANCE_INVARIANT_SCENARIOS: '1', AGENTIC_SECURITY_ASSURANCE_VERIFICATION_ORACLES: '1' };
    const ok = spawnSync(process.execPath, [path.join(SCANNER, 'bin', 'agentic-security.js'), 'invariants', 'regress', file], { env, encoding: 'utf8', timeout: 120000 });
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.match(ok.stdout, /regression artifact: passed/);
    // the same file with the features off is NOT RUN (exit 3), never a pass
    const off = spawnSync(process.execPath, [path.join(SCANNER, 'bin', 'agentic-security.js'), 'invariants', 'regress', file], { env: { ...process.env, AGENTIC_SECURITY_ASSURANCE_INVARIANT_SCENARIOS: '', AGENTIC_SECURITY_ASSURANCE_VERIFICATION_ORACLES: '0' }, encoding: 'utf8', timeout: 120000 });
    assert.equal(off.status, 3, off.stdout + off.stderr);
  }));

  test('[X-406.AC02] an edited artifact is refused without running anything', needsBoundary(async () => {
    const { r } = await good();
    let ran = false;
    const spy = { deps: { runInBoundary: async () => { ran = true; return { blocked: true, reasons: ['spy'] }; } } };
    const edits = [
      ['patch content', (a) => { a.patch.files['app.mjs'] += '\n// edited'; }, 'patch-tampered'],
      ['fixture content', (a) => { a.fixture.files['app.mjs'] += '\n// edited'; }, 'fixture-tampered'],
      ['expected outcome', (a) => { a.legs[1].expected = 'confirmed'; }, 'artifact-tampered'],
      ['commit', (a) => { a.commit = 'f'.repeat(40); }, 'artifact-tampered'],
      ['invariant approval', (a) => { a.invariant.approval.state = 'proposed'; }, 'artifact-tampered'],
    ];
    for (const [name, edit, code] of edits) {
      const a = clone(r.artifact); edit(a);
      const run = await runRegressionArtifact(a, { config, runOptions: spy });
      assert.equal(run.status, 'invalid', name);
      assert.ok(run.reasonCodes.includes(code), `${name}: ${JSON.stringify(run.reasonCodes)}`);
    }
    assert.equal(ran, false);
  }));

  test('[X-406.AC02] a self-consistent forgery that swaps in a patch which does not fix fails on execution, not on trust', needsBoundary(async () => {
    const { r } = await good();
    const a = clone(r.artifact);
    // rewrite the patch and every pin consistently, as an attacker who understands the format would
    a.patch.files['app.mjs'] = NO_FIX;
    a.patch.digest = digestOf(a.patch.files);
    for (const l of a.legs) if (l.patched) l.manifest.patch.digest = a.patch.digest;
    // the manifest ids are content hashes: recompute through the real constructor
    const { createReplayManifest } = await import('../../src/posture/replay/replay.js');
    a.legs = a.legs.map((l) => ({ ...l, manifest: createReplayManifest({ hypothesisId: a.hypothesisId, commit: a.commit, fixtureFiles: a.fixture.files, patchFiles: l.patched ? a.patch.files : null, oracleId: 'business-state', entry: l.manifest.entry, inputs: l.manifest.inputs, budgets: { timeoutMs: l.manifest.budgets.timeoutMs }, expected: l.manifest.expected }) }));
    const { artifactDigest: _drop, ...rest } = a;
    a.artifactDigest = digestOf(rest);
    assert.equal(validateRegressionArtifact(a).ok, true, 'structurally valid, which is the point');
    const run = await runRegressionArtifact(a, { config });
    assert.equal(run.status, 'failed');
    assert.ok(run.reasonCodes.includes('violation-not-eliminated'));
    assert.equal(run.legs.find((l) => l.role === 'patched-negative').outcome, 'confirmed');
  }));

  test('[X-406.AC02] an artifact is not built from a fixture or patch that holds a credential', needsBoundary(async () => {
    const leaky = `${FIXED}\nconst apiKey = "sk-live-0123456789abcdef";\n`;
    const s = await setup();
    const r = await repair(s, leaky);
    assert.equal(r.verifiedFix, false);
    assert.deepEqual(r.reasonCodes, ['artifact-refused']);
    assert.ok(r.artifactErrors.every((e) => !JSON.stringify(e).includes('0123456789abcdef')), 'the report names where, never the value');
    assert.equal(r.artifact, null);
  }));
});

describe('[X-406.AC03] failed setup, unsupported checks or unrelated behavior regressions block verified-fix status with explicit reason codes', () => {
  test('[X-406.AC03] failed setup (the boundary cannot run) blocks with setup-failed, and a disabled feature blocks with feature-disabled', async () => {
    const s = await setup();
    const spy = { deps: { runInBoundary: async () => ({ blocked: true, reasons: ['spy'] }) } };
    const r = await repair(s, FIXED, {}, { runOptions: spy });
    assert.equal(r.verifiedFix, false);
    assert.deepEqual(r.reasonCodes, ['setup-failed']);
    assert.equal(r.blockers[0].underlying, 'prerequisite-unmet');
    assert.match(r.summary, /^NOT verified-fix: setup-failed/);

    for (const feature of ['invariant-scenarios', 'verification-oracles', 'patch-negative-verification']) {
      const names = ['verification-oracles', 'invariant-scenarios', 'patch-negative-verification'].filter((f) => f !== feature);
      const off = await verifyInvariantRepair({ invariant: s.inv, ledger: s.ledger, scenario: s.scenario, fixture: s.fixture, patch: { files: { 'app.mjs': FIXED } }, commit: COMMIT }, { config: await configWith(...names) });
      assert.equal(off.status, 'disabled', feature);
      assert.deepEqual(off.reasonCodes, ['feature-disabled']);
      assert.equal(off.verifiedFix, false);
    }
  });

  test('[X-406.AC03] an unsupported check blocks: an approved contract that cannot run on this fixture is preservation-unsupported, never skipped', needsBoundary(async () => {
    const elsewhere = createInvariant({ ...clone(leak()), key: 'orders-other-entry', scope: { application: 'shop', entry: 'other.mjs', factory: 'createApp', environment: 'disposable-fixture' } });
    const s = await setup({ extraApproved: [elsewhere] });
    const r = await repair(s, FIXED, { others: [elsewhere] });
    assert.equal(r.verifiedFix, false);
    assert.deepEqual(r.reasonCodes, ['preservation-unsupported']);
    assert.equal(r.preservation[0].status, 'unsupported');
  }));

  test('[X-406.AC03] unrelated behavior regressions block with a code that names them; malformed requests never execute', needsBoundary(async () => {
    const s = await setup({ extraApproved: [leak()] });
    const r = await repair(s, FIXED_BUT_LEAKS, { others: [leak()] });
    assert.deepEqual(r.reasonCodes, ['invariant-regression']);
    assert.match(r.blockers[0].reason, /approved contract/);
    let ran = false;
    const spy = { deps: { runInBoundary: async () => { ran = true; return { blocked: true, reasons: ['spy'] }; } } };
    const bad = [
      [{ patch: { files: {} } }, 'bad-request'],
      [{ commit: 'abc' }, 'revision-unbound'],
      [{ fixture: fixtureOf(FIXED) }, 'bad-request'],
      [{ workflows: [[{ actor: 'nobody', action: 'x' }]] }, 'bad-request'],
      [{ scenario: { ...clone(s.scenario), invariant: { ...s.scenario.invariant, id: 'inv:0000000000000000' } } }, 'bad-request'],
    ];
    for (const [over, code] of bad) {
      const out = await repair(s, FIXED, over, { runOptions: spy });
      assert.equal(out.verifiedFix, false);
      assert.equal(out.status, 'rejected');
      assert.deepEqual(out.reasonCodes, [code], JSON.stringify(over).slice(0, 80));
    }
    assert.equal(ran, false);
  }));

  test('[X-406.AC03] every patch-negative failure code maps to a documented reason code, and an unknown one can only map to setup-failed', () => {
    const known = ['original-not-reproduced', 'patched-still-exploitable', 'patched-build-broken', 'patched-negative-inconclusive', 'functional-omitted', 'functional-baseline-invalid',
      'functional-regression-detected', 'functional-inconclusive', 'oracle-changed', 'revision-unbound', 'prerequisite-unmet', 'environment-mismatch', 'promotion-refused', 'harness-error', 'manifest-rejected', 'content-hash-mismatch'];
    for (const code of known) assert.ok(REASON_CODES.includes(reasonCodeFor(code)), code);
    assert.equal(reasonCodeFor('something-new'), 'setup-failed', 'an unrecognised failure is never a pass');
    assert.equal(reasonCodeFor(undefined), 'setup-failed');
    assert.equal(reasonCodeFor('patched-still-exploitable'), 'violation-not-eliminated');
  });

  test('[X-406.AC03] a blocked result is never verified and always carries a coded blocker (across every failure above)', needsBoundary(async () => {
    const s = await setup({ extraApproved: [leak()] });
    const results = [await repair(s, NO_FIX), await repair(s, BLOCK_ALL), await repair(s, FIXED_BUT_LEAKS, { others: [leak()] }), await repair(s, FIXED, { commit: 'zz' })];
    for (const r of results) {
      assert.equal(r.verifiedFix, false);
      assert.notEqual(r.status, 'verified-fix');
      assert.ok(r.blockers.length >= 1 && r.blockers.every((b) => REASON_CODES.includes(b.code) && b.step && b.reason));
      assert.equal(r.artifact, null);
      assert.ok(r.verificationRecord === null || r.verificationRecord.repair.status !== 'replay-verified');
    }
  }));
});
