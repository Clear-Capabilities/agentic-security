// X-506: policy recovery is explicit. A denial names what is missing and proposes
// a change for a human to review; only an operator-signed, bound, single-use grant
// turns a proposal into a new policy version; repeated denials stop for good.
//
// Policy level; runs on every platform. The runner cases stop before any backend
// is touched (a denial happens before execution), so no execution gate is needed.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import { DOMAINS } from '../../src/sandbox/trust-domains.js';
import { canonicalJson } from '../../src/posture/evidence-bundle.js';
import { decide } from '../../src/capabilities/decide.js';
import { requiredControlsFor } from '../../src/capabilities/probes.js';
import {
  proposeChange, mediate, createDenialGuard, signPolicyGrant, applyPolicyChange, applyChangeToManifest, createPolicyLedger,
  verifyLedgerEntries, DEFAULT_RETRY_LIMIT, MAX_GRANT_TTL_MS,
} from '../../src/capabilities/recovery.js';
import { createServer } from '../../src/mcp/server.js';
import { receiptsFromRun, signReceiptChain, verifyReceiptEnvelope } from '../../src/capabilities/receipts.js';
import { bind, ctxFor, run, tmp } from './helpers.js';

function keypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) };
}
const NOW = new Date('2026-10-09T12:00:00Z');
const allProved = (manifest) => ({ controls: Object.fromEntries(requiredControlsFor(manifest).map((n) => [n, { state: 'proved' }])), probeDigest: 'sha256:' + '1'.repeat(64) });

describe('[X-506.AC01] a denial returns blocked with the missing capability and a reviewable proposed change; the worker cannot grant its own exception', () => {
  test('each kind of denial names the missing capability and proposes the narrowest addition', () => {
    const w = tmp('rec-w-');
    const bound = bind({ filesystem: { write: [w] } });
    const ctx = ctxFor(bound);
    const cases = [
      [{ kind: 'command', executable: '/bin/echo', args: ['hi'] }, 'command-not-listed', (c) => c.add.commands[0].args.mode === 'exact' && c.add.commands[0].args.values[0] === 'hi'],
      [{ kind: 'command', executable: '/bin/sh', args: ['-c', 'true'] }, 'command-not-listed', (c) => !!c.add.commands],
      [{ kind: 'filesystem-read', path: '/usr/share/dict' }, 'outside-roots', (c) => c.add.filesystem.read[0] === '/usr/share/dict'],
      [{ kind: 'filesystem-write', path: '/var/tmp/x' }, 'outside-roots', (c) => c.add.filesystem.write[0] === '/var/tmp/x'],
      [{ kind: 'network', host: 'api.example.com', port: 443, scheme: 'https' }, 'destination-not-declared', (c) => c.add.network[0].host === 'api.example.com'],
      [{ kind: 'tool', tool: 'query_taint' }, 'tool-not-declared', (c) => c.add.tools[0] === 'query_taint'],
      [{ kind: 'delegation', depth: 0 }, 'delegation-not-allowed', (c) => c.add.delegation.allow === true],
    ];
    for (const [action, code, check] of cases) {
      const m = mediate(bound, action, ctx);
      assert.equal(m.status, 'blocked', code);
      assert.equal(m.decision.code, code);
      assert.equal(m.missing.capability, action.kind);
      assert.equal(m.proposal.proposable, true, code);
      assert.ok(check(m.proposal.change), `${code}: the proposal covers exactly the request`);
      assert.equal(m.proposal.selfGrantable, false);
      assert.equal(m.proposal.requiresOperatorGrant, true);
      assert.equal(m.proposal.nextPolicyVersion, 2);
      assert.match(m.proposal.review, /policy version 2/);
      assert.ok(Object.isFrozen(m.proposal) && Object.isFrozen(m.proposal.change), 'the worker cannot edit the proposal');
    }
  });

  test('a proposed change, once applied, would allow exactly the denied action and nothing wider', () => {
    const w = tmp('rec-w-');
    const bound = bind({ filesystem: { write: [w] } });
    const action = { kind: 'network', host: 'api.example.com', port: 443, scheme: 'https' };
    const m = mediate(bound, action, ctxFor(bound));
    const applied = applyChangeToManifest(bound.manifest, m.proposal.change);
    assert.equal(applied.ok, true);
    assert.equal(decide(applied.bound, action, { binding: applied.bound.binding }).decision, 'allow');
    assert.equal(decide(applied.bound, { ...action, host: 'other.example.com' }, { binding: applied.bound.binding }).decision, 'deny');
    assert.equal(decide(applied.bound, { ...action, port: 8443 }, { binding: applied.bound.binding }).decision, 'deny');
  });

  test('refusals that guard keys, links and secrets propose nothing', () => {
    const w = tmp('rec-w-');
    const bound = bind({ filesystem: { write: [w] }, commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    const ctx = ctxFor(bound, { protectedPaths: ['/tmp/sealed'] });
    for (const action of [
      { kind: 'filesystem-read', path: `${w}/../x` },
      { kind: 'filesystem-read', path: '/tmp/sealed/labels.json' },
      { kind: 'filesystem-write', path: 'relative/path' },
      { kind: 'command', executable: '/bin/echo', args: [`ghp_${'A1b2C3d4E5'.repeat(4)}`] },
      { kind: 'network', host: '169.254.169.254', port: 80, scheme: 'http' },
      { kind: 'tool', tool: 'not_a_real_tool' },
      { kind: 'bogus' },
    ]) {
      const m = mediate(bound, action, ctx);
      assert.equal(m.status, 'blocked');
      assert.equal(m.proposal.proposable, false, JSON.stringify(action).slice(0, 60));
      assert.equal(m.proposal.change, null);
      assert.equal(m.proposal.requiresOperatorGrant, true);
    }
  });

  test('a policy proposal never contains the secret that caused the denial', () => {
    const bound = bind({ commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    const secret = `ghp_${'A1b2C3d4E5'.repeat(4)}`;
    const m = mediate(bound, { kind: 'command', executable: '/bin/echo', args: [secret] }, ctxFor(bound));
    assert.ok(!JSON.stringify(m).includes(secret));
  });

  test('the runner denial carries the same missing capability and proposal', async () => {
    const w = tmp('rec-run-');
    const bound = bind({ filesystem: { write: [w] } });
    const r = await run(bound, { executable: '/bin/echo', args: ['hi'] });
    assert.equal(r.status, 'blocked');
    assert.equal(r.code, 'capability-denied');
    assert.equal(r.executed, false);
    assert.equal(r.missing.capability, 'command');
    assert.equal(r.proposal.proposable, true);
    assert.equal(r.proposal.change.add.commands[0].executable, '/bin/echo');
  });

  test('the MCP tool denial carries the proposal as data for the operator', async () => {
    const root = tmp('rec-mcp-');
    const bound = bind({ filesystem: { write: [root] } });
    const server = createServer({ sessionRoot: root, capabilityPolicy: { bound, binding: bound.binding } });
    const res = await server.handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'apply_fix', arguments: { finding_id: 'x', confirm: true } } });
    const out = JSON.parse(res.result.content[0].text);
    assert.equal(out.blocked, true);
    assert.equal(out.missing.capability, 'tool');
    assert.deepEqual(out.proposedChange.change.add.tools, ['apply_fix']);
    assert.equal(out.proposedChange.requiresOperatorGrant, true);
  });

  test('the worker cannot grant itself an exception: no signing for worker domains, forged and altered grants are refused', async () => {
    const w = tmp('rec-self-');
    const bound = bind({ filesystem: { write: [w] } });
    const operator = keypair(); const attacker = keypair();
    const m = mediate(bound, { kind: 'tool', tool: 'apply_fix' }, ctxFor(bound));
    const change = m.proposal.change;
    for (const domain of [DOMAINS.WORKER, DOMAINS.TARGET, DOMAINS.VERIFIER, undefined, 'admin']) {
      assert.throws(() => signPolicyGrant({ domain, privateKeyPem: attacker.privateKeyPem, bound, change, operator: 'x', reason: 'y', now: NOW }), (e) => e.code === 'domain-denied', String(domain));
    }
    const ledger = createPolicyLedger();
    const apply = (grant, ch = change) => applyPolicyChange({ bound, change: ch, grant, publicKeyPem: operator.publicKeyPem, ledger, now: NOW, probeReport: allProved(bound.manifest) });
    // signed with the wrong key (a worker generating its own)
    const forged = signPolicyGrant({ domain: DOMAINS.SIGNER, privateKeyPem: attacker.privateKeyPem, bound, change, operator: 'worker', reason: 'please', now: NOW });
    assert.equal((await apply(forged)).code, 'grant-signature-invalid');
    // an operator grant whose payload was edited afterwards
    const good = signPolicyGrant({ domain: DOMAINS.SIGNER, privateKeyPem: operator.privateKeyPem, bound, change, operator: 'ross', reason: 'needed', now: NOW });
    const edited = JSON.parse(JSON.stringify(good)); edited.payload.expiresAt = '2099-01-01T00:00:00Z';
    assert.equal((await apply(edited)).code, 'grant-signature-invalid');
    // an unsigned grant, a grant with extra fields, nothing at all
    assert.equal((await apply({ payload: good.payload })).code, 'grant-invalid');
    assert.equal((await apply({ ...good, extra: 1 })).code, 'grant-invalid');
    assert.equal((await apply(undefined)).code, 'grant-invalid');
    // a real operator grant for ONE change cannot be used for a wider one
    const wider = { add: { tools: ['apply_fix', 'apply_sca_upgrade'] } };
    assert.equal((await apply(good, wider)).code, 'grant-change-mismatch');
    assert.equal((await apply(good, { add: { tools: ['apply_fix'] }, evil: 1 })).code, 'change-invalid');
    assert.equal(ledger.entries().length, 0, 'every refusal left the ledger untouched');
    const ok = await apply(good);
    assert.equal(ok.ok, true);
  });
});

describe('[X-506.AC02] an authorized policy change creates a new version, reruns preflight and invalidates incompatible receipts', () => {
  async function setup(over = {}) {
    const w = tmp('rec-v-');
    const bound = bind({ filesystem: { write: [w] }, ...over });
    const operator = keypair();
    const ledger = createPolicyLedger({ maxChanges: over.maxChanges ?? 3 });
    const action = { kind: 'tool', tool: 'apply_fix' };
    const change = mediate(bound, action, ctxFor(bound)).proposal.change;
    const grant = (o = {}) => signPolicyGrant({ domain: DOMAINS.SIGNER, privateKeyPem: operator.privateKeyPem, bound, change, operator: 'ross', reason: 'apply fixes', now: NOW, ...o });
    const apply = (g, o = {}) => applyPolicyChange({ bound, change, grant: g, publicKeyPem: operator.publicKeyPem, ledger, now: NOW, deniedAction: action, probeReport: allProved(bound.manifest), ...o });
    return { w, bound, operator, ledger, action, change, grant, apply };
  }

  test('an operator-signed grant yields policy version 2 with a new digest, recorded in the ledger', async () => {
    const s = await setup();
    const r = await s.apply(s.grant());
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.bound.binding.policyVersion, 2);
    assert.notEqual(r.bound.binding.digest, s.bound.binding.digest);
    assert.equal(r.bound.binding.taskId, s.bound.binding.taskId);
    assert.deepEqual(r.bound.manifest.tools, ['apply_fix']);
    assert.deepEqual(s.bound.manifest.tools, [], 'the old manifest object is untouched');
    assert.equal(r.entry.fromPolicyVersion, 1); assert.equal(r.entry.toPolicyVersion, 2);
    assert.equal(r.entry.operator, 'ross');
    assert.equal(s.ledger.entries().length, 1);
    assert.equal(s.ledger.verify().ok, true);
    assert.ok(s.ledger.isCurrent(r.bound.binding) && !s.ledger.isCurrent(s.bound.binding));
  });

  test('preflight is rerun: the new manifest, its required controls and the previously denied action', async () => {
    const s = await setup();
    const r = await s.apply(s.grant());
    assert.equal(r.preflight.manifestValid, true);
    assert.deepEqual(r.preflight.unmet, []);
    assert.deepEqual(r.preflight.redecision, { decision: 'allow', code: 'allowed' });
    assert.equal(r.preflight.ready, true);
    // a control that is not proved keeps the task unready even though the policy changed
    const s2 = await setup();
    const partial = allProved(s2.bound.manifest); partial.controls['fs-read-confinement'] = { state: 'not-proved', reason: 'fixture' };
    const r2 = await s2.apply(s2.grant(), { probeReport: partial });
    assert.equal(r2.ok, true);
    assert.equal(r2.preflight.ready, false);
    assert.deepEqual(r2.preflight.unmet.map((u) => u.control), ['fs-read-confinement']);
    // a change that does not cover the denied action does not make the task ready
    const s3 = await setup();
    const r3 = await s3.apply(s3.grant(), { deniedAction: { kind: 'tool', tool: 'verify_fix' } });
    assert.equal(r3.preflight.redecision.decision, 'deny');
    assert.equal(r3.preflight.ready, false);
  });

  test('after the change the old binding is stale in both directions', async () => {
    const s = await setup();
    const r = await s.apply(s.grant());
    const act = { kind: 'tool', tool: 'apply_fix' };
    assert.equal(decide(r.bound, act, { binding: r.bound.binding }).decision, 'allow');
    assert.equal(decide(r.bound, act, { binding: s.bound.binding }).code, 'binding-mismatch', 'old identity against the new policy');
    assert.equal(decide(s.bound, act, { binding: r.bound.binding }).code, 'binding-mismatch', 'new identity against the old policy');
    assert.equal(decide(s.bound, act, { binding: s.bound.binding }).code, 'tool-not-declared', 'the old policy never gained the tool');
  });

  test('receipts issued under the old policy are superseded; receipts for the new one are current', async () => {
    const s = await setup();
    const keys = keypair();
    const synthetic = (bnd) => ({ status: 'blocked', code: 'capability-denied', outcome: 'not-run', executed: false, decisions: [decide(bnd, { kind: 'tool', tool: 'apply_fix' }, { binding: bnd.binding })] });
    const oldEnv = signReceiptChain(receiptsFromRun({ domain: DOMAINS.VERIFIER, bound: s.bound, result: synthetic(s.bound) }), { domain: DOMAINS.SIGNER, privateKeyPem: keys.privateKeyPem });
    const r = await s.apply(s.grant());
    const newEnv = signReceiptChain(receiptsFromRun({ domain: DOMAINS.VERIFIER, bound: r.bound, result: synthetic(r.bound) }), { domain: DOMAINS.SIGNER, privateKeyPem: keys.privateKeyPem });
    const expected = { binding: { taskId: r.bound.binding.taskId, policyVersion: r.bound.binding.policyVersion, digest: r.bound.binding.digest } };
    const vOld = verifyReceiptEnvelope(oldEnv, keys.publicKeyPem, expected);
    assert.equal(vOld.ok, true, 'still authentic');
    assert.equal(vOld.current, false);
    assert.equal(vOld.label, 'superseded-policy');
    assert.ok(vOld.reasons.includes('superseded-policy'));
    assert.equal(vOld.fullyEnforced, false);
    const vNew = verifyReceiptEnvelope(newEnv, keys.publicKeyPem, expected);
    assert.equal(vNew.current, true);
    assert.notEqual(vNew.label, 'superseded-policy');
  });

  test('a grant is bounded: expiry, a future start, a long window, a replay, another task, a stale base, a change limit', async () => {
    const s = await setup();
    assert.equal((await s.apply(s.grant({ now: new Date(NOW.getTime() - 20 * 60_000) }))).code, 'grant-expired', 'a 15 minute grant is dead after 20');
    assert.equal((await s.apply(s.grant({ now: new Date(NOW.getTime() + 60 * 60_000) }))).code, 'grant-not-yet-valid');
    // a hand-signed grant with a window longer than the ceiling
    const g = s.grant();
    const p = { ...g.payload, expiresAt: new Date(Date.parse(g.payload.issuedAt) + MAX_GRANT_TTL_MS + 1000).toISOString() };
    const longSig = crypto.sign(null, Buffer.from(canonicalJson({ payload: p, issuance: g.issuance }), 'utf8'), s.operator.privateKeyPem).toString('base64');
    assert.equal((await s.apply({ payload: p, issuance: g.issuance, signature: { algorithm: 'ed25519', value: longSig } })).code, 'grant-window-invalid');
    // ttl is clamped when signing
    const clamped = s.grant({ ttlMs: 10 * MAX_GRANT_TTL_MS });
    assert.ok(Date.parse(clamped.payload.expiresAt) - Date.parse(clamped.payload.issuedAt) <= MAX_GRANT_TTL_MS);
    // wrong task
    const other = bind({ taskId: 'other-task', filesystem: { write: [s.w] } });
    const otherGrant = signPolicyGrant({ domain: DOMAINS.SIGNER, privateKeyPem: s.operator.privateKeyPem, bound: other, change: s.change, operator: 'ross', reason: 'x', now: NOW });
    assert.equal((await s.apply(otherGrant)).code, 'grant-wrong-task');
    // success, then replay and stale
    const first = s.grant();
    assert.equal((await s.apply(first)).ok, true);
    assert.equal((await s.apply(first)).code, 'grant-stale', 'the base policy is no longer current');
    const ledger2 = createPolicyLedger();
    const s2 = await setup();
    const fresh = s2.grant({ nonce: 'n-1' });
    assert.equal((await applyPolicyChange({ bound: s2.bound, change: s2.change, grant: fresh, publicKeyPem: s2.operator.publicKeyPem, ledger: ledger2, now: NOW, probeReport: allProved(s2.bound.manifest) })).ok, true);
    assert.equal((await applyPolicyChange({ bound: s2.bound, change: s2.change, grant: fresh, publicKeyPem: s2.operator.publicKeyPem, ledger: ledger2, now: NOW, probeReport: allProved(s2.bound.manifest) })).code, 'grant-stale');
  });

  test('a task can only be re-authorized a finite number of times', async () => {
    const w = tmp('rec-lim-');
    let bound = bind({ filesystem: { write: [w] } });
    const operator = keypair();
    const ledger = createPolicyLedger({ maxChanges: 2 });
    const tools = ['query_taint', 'verify_fix', 'apply_fix'];
    const outcomes = [];
    for (const t of tools) {
      const change = { add: { tools: [t] } };
      const grant = signPolicyGrant({ domain: DOMAINS.SIGNER, privateKeyPem: operator.privateKeyPem, bound, change, operator: 'ross', reason: 'step', now: NOW });
      const r = await applyPolicyChange({ bound, change, grant, publicKeyPem: operator.publicKeyPem, ledger, now: NOW, probeReport: allProved(bound.manifest) });
      outcomes.push(r.ok ? 'ok' : r.code);
      if (r.ok) bound = r.bound;
    }
    assert.deepEqual(outcomes, ['ok', 'ok', 'change-limit']);
    assert.equal(bound.binding.policyVersion, 3);
  });

  test('the ledger is hash-chained: an edited, removed or reordered entry is detected', async () => {
    const w = tmp('rec-led-');
    let bound = bind({ filesystem: { write: [w] } });
    const operator = keypair();
    const ledger = createPolicyLedger({ maxChanges: 5 });
    for (const t of ['query_taint', 'verify_fix', 'apply_fix']) {
      const change = { add: { tools: [t] } };
      const grant = signPolicyGrant({ domain: DOMAINS.SIGNER, privateKeyPem: operator.privateKeyPem, bound, change, operator: 'ross', reason: 'step', now: NOW });
      bound = (await applyPolicyChange({ bound, change, grant, publicKeyPem: operator.publicKeyPem, ledger, now: NOW, probeReport: allProved(bound.manifest) })).bound;
    }
    const entries = ledger.entries();
    assert.equal(verifyLedgerEntries(entries).ok, true);
    const edited = entries.map((e) => ({ ...e })); edited[1].operator = 'mallory';
    assert.deepEqual(verifyLedgerEntries(edited), { ok: false, breakAt: 1 });
    assert.equal(verifyLedgerEntries([entries[0], entries[2]]).ok, false);
    assert.equal(verifyLedgerEntries([entries[1], entries[0], entries[2]]).ok, false);
  });
});

describe('[X-506.AC03] repeated denials hit a finite limit and stay blocked; nothing loops or falls back to unrestricted execution', () => {
  test('the same action stops being evaluated after the limit and keeps the same refusal', () => {
    const bound = bind({});
    const ctx = ctxFor(bound);
    const guard = createDenialGuard();
    assert.equal(guard.retryLimit, DEFAULT_RETRY_LIMIT);
    const act = { kind: 'tool', tool: 'apply_fix' };
    const seen = [];
    for (let i = 0; i < 8; i++) { const m = mediate(bound, act, ctx, { guard }); seen.push([m.status, m.decision.code, m.attemptsRemaining]); }
    assert.deepEqual(seen.slice(0, 3).map((x) => x[1]), ['tool-not-declared', 'tool-not-declared', 'tool-not-declared']);
    assert.deepEqual(seen.slice(0, 3).map((x) => x[2]), [2, 1, 0]);
    for (const x of seen.slice(3)) { assert.equal(x[0], 'blocked'); assert.equal(x[1], 'retry-limit'); }
    assert.ok(seen.every((x) => x[0] === 'blocked'), 'there is no attempt that ends in an allow');
  });

  test('the proposal is withdrawn once the limit is reached: a loop gets no new offer', () => {
    const bound = bind({});
    const guard = createDenialGuard({ retryLimit: 2 });
    const act = { kind: 'tool', tool: 'apply_fix' };
    assert.equal(mediate(bound, act, ctxFor(bound), { guard }).proposal.proposable, true);
    const last = mediate(bound, act, ctxFor(bound), { guard });
    assert.equal(last.exhausted, true);
    assert.equal(last.proposal.proposable, false);
  });

  test('a changed request is a different action, but the whole task has a denial budget', () => {
    const bound = bind({});
    const ctx = ctxFor(bound);
    const guard = createDenialGuard({ retryLimit: 2, taskBudget: 4 });
    const codes = [];
    for (let i = 0; i < 6; i++) codes.push(mediate(bound, { kind: 'tool', tool: `tool_${i}` }, ctx, { guard }).decision.code);
    assert.deepEqual(codes, ['tool-not-declared', 'tool-not-declared', 'tool-not-declared', 'tool-not-declared', 'task-halted', 'task-halted']);
  });

  test('a halted task stays halted even for an action that the policy allows: no fallback to unrestricted work', () => {
    const w = tmp('rec-halt-');
    const bound = bind({ tools: ['query_taint'], filesystem: { write: [w] } });
    const ctx = ctxFor(bound);
    const guard = createDenialGuard({ retryLimit: 1, taskBudget: 2 });
    mediate(bound, { kind: 'tool', tool: 'a_tool' }, ctx, { guard });
    mediate(bound, { kind: 'tool', tool: 'b_tool' }, ctx, { guard });
    const allowedBefore = decide(bound, { kind: 'tool', tool: 'query_taint' }, ctx).decision;
    assert.equal(allowedBefore, 'allow', 'the policy itself would allow it');
    const m = mediate(bound, { kind: 'tool', tool: 'query_taint' }, ctx, { guard });
    assert.equal(m.status, 'blocked');
    assert.equal(m.decision.code, 'task-halted');
  });

  test('a new policy version is a new request: the count starts again only because an operator changed the policy', () => {
    const bound = bind({});
    const guard = createDenialGuard({ retryLimit: 1 });
    const act = { kind: 'tool', tool: 'apply_fix' };
    assert.equal(mediate(bound, act, ctxFor(bound), { guard }).decision.code, 'tool-not-declared');
    assert.equal(mediate(bound, act, ctxFor(bound), { guard }).decision.code, 'retry-limit');
    const v2 = applyChangeToManifest(bound.manifest, { add: { tools: ['query_taint'] } }).bound;
    assert.equal(guard.admit(v2.binding, act).admit, true, 'a different policy version is admitted for evaluation');
    assert.equal(mediate(v2, act, ctxFor(v2), { guard }).decision.code, 'tool-not-declared');
  });

  test('limits are clamped to a ceiling and invalid limits fall back to the defaults, never to unlimited', () => {
    const g = createDenialGuard({ retryLimit: 10_000, taskBudget: 10_000 });
    assert.ok(g.retryLimit <= 10 && g.taskBudget <= 100);
    const d = createDenialGuard({ retryLimit: 0, taskBudget: -5 });
    assert.equal(d.retryLimit, DEFAULT_RETRY_LIMIT);
    assert.ok(Number.isFinite(d.taskBudget) && d.taskBudget > 0);
    const n = createDenialGuard({ retryLimit: Infinity, taskBudget: NaN });
    assert.ok(Number.isFinite(n.retryLimit) && Number.isFinite(n.taskBudget));
  });

  test('the runner honours the guard: repeated denied runs end in retry-limit without executing anything', async () => {
    const w = tmp('rec-runner-');
    const bound = bind({ filesystem: { write: [w] } });
    const guard = createDenialGuard({ retryLimit: 2 });
    const codes = [];
    for (let i = 0; i < 4; i++) {
      const r = await run(bound, { executable: '/bin/echo', args: ['x'] }, { denialGuard: guard });
      assert.equal(r.status, 'blocked'); assert.equal(r.executed, false);
      codes.push(r.policyCode);
    }
    assert.deepEqual(codes, ['command-not-listed', 'command-not-listed', 'retry-limit', 'retry-limit']);
  });
});
