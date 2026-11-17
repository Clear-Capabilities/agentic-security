// Verified remediation M3-05: workflow and idempotency on the application adapters (FR-12). Every sequence runs on a fresh SQLite file and
// a fresh application instance; invariants are read by the verifier from each sequence's own file. Concurrency is cooperative interleaving
// in one process. A skip is not a pass.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planRepair, runRepair } from '../../src/repair/coordinator.js';
import { queueProposer } from '../../src/repair/candidates.js';
import { validateProfile } from '../../src/repair/profile.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'repair', 'order-workflow');
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });

let ready = false; let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const unmet = unmetControls(await probeControls({}), [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  ready = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the workflow execution tests are UNVERIFIED here`;
});
const needs = (fn) => async (t) => (ready ? fn(t) : t.skip(whyNot));

const setup = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-'));
  fs.cpSync(FIX, root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const p = planRepair({ root, finding: { findingId: 'wf:orders', file: 'src/app.mjs' }, family: 'workflow', profile, profileOrigin: 'repository-file' });
  assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
  return { root, plan: p.plan, profile, original: fs.readFileSync(path.join(root, 'src', 'app.mjs'), 'utf8') };
};
const PAY = '      const r = await provider.charge(order.amount);\n';
const SHIP = '    db.prepare("INSERT INTO events (order_id, kind, amount) VALUES (?, \'ship\', 0)").run(order.id);\n';
const rep = (t, a, b) => { assert.ok(t.includes(a), a.slice(0, 40)); return t.replace(a, () => b); };

describe('[M3-05] workflow contracts (no execution)', () => {
  test('replays and reorders are development attacks, concurrent double submissions are sealed, and every attack is judged by the invariants alone', () => {
    const { plan } = setup();
    const dev = plan.contract.obligations.find((o) => o.id === 'workflow-attacks-development').inputs.sequences.filter((s) => s.role === 'attack');
    assert.deepEqual(dev.map((s) => s.id).sort(), ['reorder_checkout_0', 'replay_checkout_0', 'replay_checkout_1']);
    assert.deepEqual(dev.find((s) => s.id === 'reorder_checkout_0').steps.map((r) => r.path), ['/orders/1/ship', '/orders/1/pay']);
    assert.ok(dev.every((s) => s.checks.every((c) => c.id.startsWith('inv_'))), 'an attack is judged by the invariants, not by its status codes');
    const sealed = plan.contract.obligations.find((o) => o.id === 'workflow-attacks-sealed').inputs.sequences.filter((s) => s.role === 'attack');
    assert.ok(sealed.every((s) => s.steps.filter((r) => r.concurrentGroup === 1).length === 2));
    const normal = plan.contract.obligations.find((o) => o.id === 'workflow-normal').inputs.sequences;
    assert.deepEqual(normal.map((s) => s.role), ['control']);
  });

  test('a workflow profile needs declared invariants, operations that say whether they mutate, and steps that name operations', () => {
    const { profile } = setup();
    const w = (over) => validateProfile({ ...profile, workflow: { ...profile.workflow, ...over } }).join(' ');
    assert.match(w({ invariants: [] }), /invariants must hold 1 to 12/);
    assert.match(w({ normal: [{ id: 'x', steps: ['refund'] }] }), /declared operation ids/);
    assert.match(w({ operations: [{ ...profile.workflow.operations[0], mutating: undefined }, profile.workflow.operations[1]] }), /must say whether the operation changes durable state/);
  });
});

describe('[M3-05] workflow repair, executed', () => {
  test('a payment check alone is defeated by shipping first; checks without atomicity are caught only by a concurrent double payment; denying payment breaks checkout; an atomic claim is verified', needs(async () => {
    const s = setup();
    const payCheck = "      if (order.status !== 'new') return send(res, 409, { error: 'already paid' });\n";
    const shipCheck = "    if (order.status !== 'paid') return send(res, 409, { error: 'not paid' });\n";
    const atomic = "      const claim = db.prepare(\"UPDATE orders SET status = 'paying' WHERE id = ? AND status = 'new'\").run(order.id);\n      if (claim.changes !== 1) return send(res, 409, { error: 'already paid' });\n";
    const v = {
      payOnly: rep(s.original, PAY, payCheck + PAY),
      nonAtomic: rep(rep(s.original, PAY, payCheck + PAY), SHIP, shipCheck + SHIP),
      denyPay: rep(s.original, PAY, "      return send(res, 409, { error: 'payments disabled' });\n" + PAY),
      atomic: rep(rep(s.original, PAY, atomic + PAY), SHIP, shipCheck + SHIP),
    };
    const items = [['payOnly', 1], ['nonAtomic', 1], ['denyPay', 2], ['atomic', 3]].map(([k, round]) => ({ round, strategy: k, files: { 'src/app.mjs': v[k] } }));
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer(items)], policy: { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 3 } } });
    const orig = r.record.obligationResults.filter((o) => o.revision === 'original');
    assert.equal(orig.find((o) => o.obligation === 'workflow-attacks-development').observed, 'confirmed', 'the original double-charges on a replay and ships unpaid when reordered');
    assert.equal(orig.find((o) => o.obligation === 'workflow-attacks-sealed').observed, 'confirmed', 'and double-charges on a concurrent submission');
    const by = Object.fromEntries(r.record.candidates.map((c) => [c.strategy, c]));
    const st = (k, ob) => by[k].results.find((x) => x.obligation === ob)?.status;
    assert.equal(st('payOnly', 'workflow-attacks-development'), 'failed');
    const cx = r.record.counterexamples.find((x) => x.candidateId === by.payOnly.candidateId);
    assert.equal(cx.property, 'workflow-invariant');
    assert.deepEqual(cx.sequence.steps, ['POST /orders/1/ship', 'POST /orders/1/pay']);
    assert.deepEqual(cx.brokenInvariants, ['inv_nothing_shipped_before_payment']);
    assert.equal(st('nonAtomic', 'workflow-attacks-development'), 'passed');
    assert.equal(st('nonAtomic', 'workflow-attacks-sealed'), 'failed', 'the concurrent double payment is held out and still caught');
    assert.equal(st('denyPay', 'workflow-normal'), 'failed');
    assert.equal(by.atomic.status, 'verified-for-contract', r.record.reasons.join('; '));
    assert.ok(r.record.regressionGuards.some((g) => g.id === 'replay_checkout_1'), 'a replayed shipment the original already tolerates stays as a regression guard');
  }));
});
