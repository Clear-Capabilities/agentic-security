// Threat-model PRD FR-02 (TM-01): the pilot workflow invariant "only an authorized reviewer moves a reviewed order to approved", checked
// through the existing scenario generator, business-state oracle and invariant repair verification. A guard that rejects only cancelled
// orders looks like protection to a lexical scan; the invariant shows it lets a pending order reach approved. The execution tests go
// through the trust boundary and say SKIPPED, NOT PASSED where it cannot run.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { _resetKeyCacheForTests } from '../../src/posture/integrity.js';
import { generateScenarios, runScenario } from '../../src/posture/invariants/scenarios.js';
import { emptyLedger, recordTransition } from '../../src/posture/invariants/lifecycle.js';
import { verifyInvariantRepair } from '../../src/posture/invariants/repair.js';
import { contract, fixtureOf, configWith, boundaryProbe, COMMIT } from '../helpers/invariant-fixtures.js';

const READ = 'const o = ctx.store.read(key); if (!o) return { status: 404 };';
const APP = {
  unguarded: `export function createApp() { return { advance(ctx, key, p) { ${READ} ctx.store.write(key, { ...o, status: p.to }); return { status: 200 }; } }; }`,
  // TM-01: the guard rejects cancelled orders only, so pending -> approved goes through
  wrongGuard: `export function createApp() { return { advance(ctx, key, p) { ${READ} if (p.to === 'approved' && o.status === 'cancelled') return { status: 409 }; ctx.store.write(key, { ...o, status: p.to }); return { status: 200 }; } }; }`,
  fixed: `export function createApp() { const next = { pending: 'reviewed', reviewed: 'approved' }; return { advance(ctx, key, p) { ${READ} if (next[o.status] !== p.to) return { status: 409 }; if (p.to === 'approved' && ctx.role !== 'reviewer') return { status: 403 }; ctx.store.write(key, { ...o, status: p.to }); return { status: 200 }; } }; }`,
  denyAll: `export function createApp() { return { advance() { return { status: 403 }; } }; }`,
};
// The versioned pilot invariant, approved by the service owner (the ledger records who approved the intended behaviour).
const invariant = () => contract('workflow', {
  key: 'orders-reviewed-before-approved', revision: 1, name: 'Only an authorized reviewer moves a reviewed order to approved',
  actors: [{ id: 'rita', tenant: 'acme', role: 'reviewer' }],
  transitions: [{ id: 'advance', action: 'advance', actors: ['rita'], resource: 'order' }],
  forbidden: [{ ...contract('workflow').forbidden[0], id: 'no-approval-before-review', allowed: [{ from: 'pending', to: 'reviewed' }, { from: 'reviewed', to: 'approved' }] }],
});
const POLICY = { id: 'pilot-owner', reviewers: ['service-owner'] };
function approvedLedger(inv) {
  let l = recordTransition(emptyLedger(), { action: 'propose', invariant: inv, actor: { id: 'appsec', kind: 'human' }, reason: 'pilot invariant' }).ledger;
  return recordTransition(l, { action: 'approve', invariantId: inv.id, actor: { id: 'service-owner', kind: 'human' }, reason: 'intended behaviour confirmed' }, { policy: POLICY }).ledger;
}
// The scenario's own control flow (pending -> reviewed -> approved by the reviewer) IS the legitimate approval, and the repair check
// runs it as an authorized workflow on both revisions; nothing extra is declared.
const LEGIT = [];

const KEY_VAR = 'AGENTIC_SECURITY_HMAC_KEY';
let saved; let boundary = { ready: false, why: '' }; let config;
before(async () => { saved = process.env[KEY_VAR]; process.env[KEY_VAR] = 'cd'.repeat(32); _resetKeyCacheForTests(); boundary = await boundaryProbe(); config = await configWith('verification-oracles', 'invariant-scenarios', 'patch-negative-verification'); });
after(() => { if (saved === undefined) delete process.env[KEY_VAR]; else process.env[KEY_VAR] = saved; _resetKeyCacheForTests(); });
const needsBoundary = (fn) => (t) => (boundary.ready ? fn(t) : t.skip(boundary.why));
const scenarioFor = (app) => generateScenarios(invariant(), { fixture: fixtureOf(APP[app]), config }).scenarios.find((s) => s.kind === 'reordered-workflow');
const outcome = async (app) => (await runScenario(scenarioFor(app), { fixture: fixtureOf(APP[app]), commit: COMMIT, config })).outcome;
const repair = (from, to, over = {}, o = {}) => { const inv = invariant(); return verifyInvariantRepair({ invariant: inv, ledger: approvedLedger(inv), scenario: scenarioFor(from), fixture: fixtureOf(APP[from]), patch: { files: { 'app.mjs': APP[to] } }, commit: COMMIT, workflows: LEGIT, ...over }, { config, ...o }); };

describe('threat-model FR-02: the approval workflow invariant', () => {
  test('AC-02A: the unguarded and the wrong-guard versions both let an unreviewed order reach approved', needsBoundary(async () => {
    assert.equal(await outcome('unguarded'), 'confirmed');
    assert.equal(await outcome('wrongGuard'), 'confirmed', 'TM-01: the guard that rejects only cancelled orders does not protect the transition');
  }));

  test('AC-02B: the repaired version refuses the skip, keeps the authorized approval, and is verified-fix through patch-negative', needsBoundary(async () => {
    assert.equal(await outcome('fixed'), 'refuted');
    const r = await repair('wrongGuard', 'fixed');
    assert.equal(r.status, 'verified-fix', JSON.stringify(r.blockers));
    const steps = Object.fromEntries(r.patchNegative.steps.map((x) => [x.step, x.outcome]));
    assert.deepEqual([steps['original-positive'], steps['patched-negative'], steps['functional-regression']], ['confirmed', 'refuted', 'refuted']);
    // a cancelled order is refused by the repair as well
    const mod = await import(`data:text/javascript,${encodeURIComponent(APP.fixed)}`);
    const store = new Map([['orders/1', { tenant: 'acme', status: 'cancelled' }]]);
    const ctx = { role: 'reviewer', store: { read: (k) => store.get(k), write: (k, v) => store.set(k, v) } };
    assert.equal(mod.createApp().advance(ctx, 'orders/1', { to: 'approved' }).status, 409);
    assert.equal(store.get('orders/1').status, 'cancelled');
  }));

  test('AC-02B: a patch that denies everyone fails the functional control and is not a verified repair', needsBoundary(async () => {
    const r = await repair('wrongGuard', 'denyAll');
    assert.notEqual(r.status, 'verified-fix');
    assert.equal(r.verifiedFix, false);
    assert.ok(r.blockers.length > 0, 'the blocker names the leg and the reason');
  }));

  test('AC-02C: with the oracle feature unavailable the repair is blocked and names why', async () => {
    const r = await repair('wrongGuard', 'fixed', {}, { config: await configWith('invariant-scenarios') });
    assert.notEqual(r.status, 'verified-fix');
    assert.ok(r.blockers.length > 0);
  });
});
