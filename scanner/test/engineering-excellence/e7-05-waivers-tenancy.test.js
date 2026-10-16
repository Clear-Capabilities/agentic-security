// E7-05: waivers record who, why, until when and under which policy; an expired or out-of-scope waiver cannot silently suppress anything; another tenant's
// evidence is out of reach; erasure and legal hold keep their meaning; nothing in the log is personal data.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  AccessDenied, DEFAULT_POLICY, applyWaivers, buildWaiver, createAuditLog, createTenantStore, evaluateWaiver, signWaiver, validateWaiver, verifyAuditLog,
} from '../../src/posture/assurance/waiver.js';
import { keyFingerprint } from '../../src/posture/evidence-bundle.js';

const NOW = Date.parse('2026-06-01T00:00:00Z');
const iso = (days) => new Date(NOW + days * 86400000).toISOString().replace('.000Z', 'Z');
const mk = (over = {}) => buildWaiver({
  tenant: 'acme', environment: 'production', scope: { kind: 'finding', value: 'sf-1' }, actor: { id: 'user-a1', role: 'engineer' }, approvals: [{ id: 'user-b2', role: 'security-lead' }],
  justification: 'The route is behind the internal gateway until the Q3 migration completes.', compensatingControl: 'WAF rule 4432 blocks the vulnerable parameter', createdAt: iso(-1), expiresAt: iso(30), policyVersion: 1, ...over,
});
const CTX = { now: NOW, tenant: 'acme', environment: 'production' };
const finding = (over = {}) => ({ id: 'f-1', stableId: 'sf-1', vuln: 'SQL Injection', family: 'sql-injection', cwe: 'CWE-89', file: 'src/a.js', severity: 'high', ...over });
const codes = (r) => r.errors.map((e) => `${e.code}:${e.path}`);

test('a well-formed waiver validates, has a content-derived id, and every required field is enforced', () => {
  const w = mk(); assert.deepEqual(validateWaiver(w), { ok: true, errors: [] }); assert.match(w.id, /^wvr:[0-9a-f]{16}$/);
  assert.equal(mk().id, w.id, 'deterministic');
  assert.notEqual(mk({ expiresAt: iso(31) }).id, w.id);
  for (const k of ['tenant', 'environment', 'scope', 'actor', 'approvals', 'justification', 'createdAt', 'expiresAt', 'policyVersion']) { const x = { ...w }; delete x[k]; assert.equal(validateWaiver(x).ok, false, k); }
  assert.equal(validateWaiver({ ...w, extra: 1 }).ok, false); assert.equal(validateWaiver(null).ok, false); assert.equal(validateWaiver({ ...w, id: 'wvr:0000000000000000' }).ok, false);
  assert.equal(validateWaiver({ ...w, scope: { kind: 'path', value: '**' } }).ok, false, 'a waiver for every path is not a scoped waiver');
  assert.equal(validateWaiver({ ...w, scope: { kind: 'galaxy', value: 'x' } }).ok, false);
});

test('PEOPLE are opaque ids: an e-mail, a name field, a self-approval and a duplicate approver are each refused', () => {
  assert.ok(codes(validateWaiver(mk({ actor: { id: 'jane.doe@example.com', role: 'engineer' } }))).some((c) => c.startsWith('BAD_ID:actor.id')));
  assert.ok(codes(validateWaiver(mk({ actor: { id: 'user-a1', role: 'engineer', name: 'Jane Doe' } }))).some((c) => c.startsWith('UNKNOWN_FIELD:actor.name')));
  assert.ok(codes(validateWaiver(mk({ approvals: [{ id: 'user-a1', role: 'x' }] }))).some((c) => /approvals\[0\]/.test(c)), 'cannot approve one\'s own waiver');
  assert.equal(validateWaiver(mk({ approvals: [{ id: 'user-b2', role: 'a' }, { id: 'user-b2', role: 'a' }] })).ok, false);
  assert.equal(validateWaiver(mk({ approvals: [] })).ok, false); assert.equal(validateWaiver(mk({ approvals: [] }), { ...DEFAULT_POLICY, requiredApprovals: 0 }).ok, true);
  assert.equal(validateWaiver(mk({ approvals: [{ id: 'user-b2', role: 'a' }] }), { ...DEFAULT_POLICY, requiredApprovals: 2 }).ok, false, 'two-person rule when the policy asks for it');
});

test('JUSTIFICATION: too short, a secret, personal data, and a missing compensating control are refused', () => {
  assert.equal(validateWaiver(mk({ justification: 'later' })).ok, false);
  assert.ok(codes(validateWaiver(mk({ justification: 'Customer jane.doe@example.com asked us to wait for the migration to finish' }))).some((c) => /justification/.test(c)));
  assert.ok(codes(validateWaiver(mk({ justification: 'Use the key AKIAIOSFODNN7EXAMPLE to check the route until the migration' }))).some((c) => /justification/.test(c)));
  assert.ok(codes(validateWaiver(mk({ justification: 'password = "hunter2hunter2" is set on the test box until the Q3 migration' }))).some((c) => /justification/.test(c)));
  assert.equal(validateWaiver(mk({ compensatingControl: undefined })).ok, false); assert.equal(validateWaiver(mk({ compensatingControl: 'later' })).ok, false);
});

test('LIFETIME: a waiver has an expiry, after its creation, within the policy maximum', () => {
  assert.equal(validateWaiver(mk({ expiresAt: iso(-2) })).ok, false);
  assert.equal(validateWaiver(mk({ expiresAt: iso(200) })).ok, false); assert.equal(validateWaiver(mk({ expiresAt: iso(200) }), { ...DEFAULT_POLICY, maxLifetimeDays: 365 }).ok, true);
  assert.equal(validateWaiver(mk({ expiresAt: 'next year' })).ok, false); assert.equal(validateWaiver(mk({ policyVersion: 0 })).ok, false);
});

test('HONOURED: a valid, in-scope, in-date waiver moves the finding to `waived` with the waiver attached; nothing is dropped silently', () => {
  const w = mk(); const f = [finding(), finding({ id: 'f-2', stableId: 'sf-2' })];
  const r = applyWaivers(f, [w], CTX);
  assert.deepEqual(r.waived.map((x) => [x.finding.stableId, x.waiverId]), [['sf-1', w.id]]); assert.deepEqual(r.open.map((x) => x.stableId), ['sf-2']);
  assert.equal(r.open.length + r.waived.length, f.length, 'every finding is accounted for'); assert.deepEqual(r.summary, { findings: 2, open: 1, waived: 1, refusedMatches: 0, expiredWaivers: 0, reopenedByExpiry: 0 });
  // scope kinds
  const rule = applyWaivers(f, [mk({ scope: { kind: 'rule', value: 'CWE-89' } })], CTX); assert.equal(rule.waived.length, 2);
  const glob = applyWaivers([finding({ file: 'src/legacy/x.js' }), finding({ id: 'f-3', stableId: 'sf-3', file: 'src/new/y.js' })], [mk({ scope: { kind: 'path', value: 'src/legacy/**' } })], CTX);
  assert.deepEqual(glob.waived.map((x) => x.finding.file), ['src/legacy/x.js']);
});

test('EXPIRED waivers cannot suppress: the finding stays open, the waiver is listed as refused with the reason, and the summary counts it', () => {
  const w = mk({ createdAt: iso(-40), expiresAt: iso(-1) });
  const r = applyWaivers([finding()], [w], CTX);
  assert.equal(r.open.length, 1); assert.equal(r.waived.length, 0);
  assert.deepEqual(r.refused, [{ waiverId: w.id, findingId: 'sf-1', reasons: ['expired'] }]);
  assert.equal(r.summary.expiredWaivers, 1); assert.equal(r.summary.reopenedByExpiry, 1);
  const unused = applyWaivers([finding({ stableId: 'other', id: 'o' })], [w], CTX); assert.equal(unused.summary.expiredWaivers, 1, 'an expired waiver that matches nothing is still reported');
  // the boundary: at the instant of expiry it is already expired
  assert.deepEqual(evaluateWaiver(mk({ expiresAt: new Date(NOW).toISOString().replace('.000Z', 'Z'), createdAt: iso(-1) }), CTX).reasons, ['expired']);
  assert.equal(evaluateWaiver(w, { ...CTX, now: NOW - 40 * 86400000 + 1000 }).honoured, true, 'but it was valid in its own time');
});

test('BOUNDARIES: another tenant, another environment, a superseded policy, an unsigned or badly signed waiver where signatures are required, and a future waiver are each refused', () => {
  const w = mk();
  assert.deepEqual(evaluateWaiver(w, { ...CTX, tenant: 'globex' }).reasons, ['tenant-mismatch']);
  assert.deepEqual(evaluateWaiver(w, { ...CTX, environment: 'staging' }).reasons, ['environment-mismatch']);
  assert.deepEqual(evaluateWaiver(w, { ...CTX, policy: { minPolicyVersion: 2 } }).reasons, ['policy-version-superseded']);
  assert.deepEqual(evaluateWaiver(mk({ createdAt: iso(2), expiresAt: iso(30) }), CTX).reasons, ['not-yet-valid']);
  assert.deepEqual(evaluateWaiver(w, { ...CTX, policy: { requireSignature: true } }).reasons, ['unsigned']);
  const k = crypto.generateKeyPairSync('ed25519'); const priv = k.privateKey.export({ type: 'pkcs8', format: 'pem' }); const pub = k.publicKey.export({ type: 'spki', format: 'pem' });
  const signed = signWaiver(w, priv); const trusted = { [keyFingerprint(pub)]: pub };
  assert.equal(evaluateWaiver(signed, { ...CTX, policy: { requireSignature: true }, trustedKeys: trusted }).honoured, true);
  assert.deepEqual(evaluateWaiver({ ...signed, justification: 'A different justification written after the waiver was signed by someone else.' }, { ...CTX, policy: { requireSignature: true }, trustedKeys: trusted }).reasons, ['bad-signature'], 'editing the record after signing breaks the signature');
  assert.deepEqual(evaluateWaiver({ ...signed, expiresAt: iso(60) }, { ...CTX, policy: { requireSignature: true, maxLifetimeDays: 365 }, trustedKeys: trusted }).reasons, ['invalid'], 'and extending the expiry breaks the id, which covers it');
  assert.deepEqual(evaluateWaiver(signed, { ...CTX, trustedKeys: {} }).reasons, ['untrusted-key']);
  const other = crypto.generateKeyPairSync('ed25519'); const forged = signWaiver(w, other.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  assert.deepEqual(evaluateWaiver(forged, { ...CTX, trustedKeys: trusted }).reasons, ['untrusted-key'], 'signed by a key nobody trusts');
  // tightened policy: a waiver written under looser rules stops being honoured
  assert.deepEqual(evaluateWaiver(mk({ expiresAt: iso(80) }), { ...CTX, policy: { maxLifetimeDays: 30 } }).reasons, ['invalid']);
  assert.equal(evaluateWaiver({ not: 'a waiver' }, CTX).honoured, false);
  const r = applyWaivers([finding()], [w], { ...CTX, tenant: 'globex' }); assert.equal(r.open.length, 1); assert.equal(r.refused[0].reasons[0], 'tenant-mismatch');
});

test('AUDIT LOG: hash-chained, ids and reason codes only; a removed, edited or reordered entry is detected; personal data is refused', () => {
  const log = createAuditLog({ now: () => NOW });
  const w = mk(); const r = applyWaivers([finding()], [w, mk({ createdAt: iso(-40), expiresAt: iso(-1), scope: { kind: 'rule', value: 'CWE-89' } })], CTX, log);
  assert.deepEqual(log.entries.map((e) => e.event), ['waiver.applied']);
  assert.equal(r.waived.length, 1);
  const log2 = createAuditLog({ now: () => NOW });
  applyWaivers([finding()], [mk({ createdAt: iso(-40), expiresAt: iso(-1) })], CTX, log2);
  assert.deepEqual(log2.entries.map((e) => [e.event, e.reasons]), [['waiver.refused', ['expired']]]);
  for (let i = 0; i < 3; i++) log2.append({ event: 'note', tenant: 'acme', code: `c${i}` });
  assert.deepEqual(verifyAuditLog(log2.entries), { ok: true, brokenAt: null });
  const copy = () => JSON.parse(JSON.stringify(log2.entries));
  const removed = copy(); removed.splice(1, 1); assert.equal(verifyAuditLog(removed).ok, false);
  const edited = copy(); edited[0].reasons = []; assert.equal(verifyAuditLog(edited).brokenAt, 1);
  const reordered = copy(); [reordered[1], reordered[2]] = [reordered[2], reordered[1]]; assert.equal(verifyAuditLog(reordered).ok, false);
  const tail = copy(); tail.pop(); assert.equal(verifyAuditLog(tail).ok, true, 'a log cut off at the end is a shorter valid log: the length is what a reader compares');
  assert.throws(() => log2.append({ event: 'x', justification: 'free text' }), /does not record "justification"/);
  assert.throws(() => log2.append({ event: 'x', code: 'jane.doe@example.com' }), /personal data/);
  assert.throws(() => log2.append({ event: 'x', code: 'AKIAIOSFODNN7EXAMPLE' }), /personal data or a secret/);
  const text = JSON.stringify(log2.entries); assert.ok(!text.includes('justification'));
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-05-log-')), 'audit.jsonl');
  try { const fl = createAuditLog({ file, now: () => NOW }); fl.append({ event: 'a', tenant: 'acme' }); fl.append({ event: 'b', tenant: 'acme' }); const rows = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l)); assert.deepEqual(verifyAuditLog(rows), { ok: true, brokenAt: null }); } finally { fs.rmSync(path.dirname(file), { recursive: true, force: true }); }
});

test('TENANT ISOLATION: a tenant reads and writes only its own evidence; every other attempt is denied and logged; names cannot walk out of the store', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-05-'));
  try {
    const log = createAuditLog({ now: () => NOW }); const store = createTenantStore(root, { auditLog: log, now: () => NOW });
    store.put('acme', 'acme', 'scan.json', Buffer.from('acme evidence')); store.put('globex', 'globex', 'scan.json', Buffer.from('globex evidence'));
    assert.equal(store.get('acme', 'acme', 'scan.json').toString(), 'acme evidence'); assert.deepEqual(store.list('acme', 'acme'), ['scan.json']);
    const denied = (fn) => assert.throws(fn, (e) => e instanceof AccessDenied && e.code === 'ACCESS_DENIED');
    denied(() => store.get('acme', 'globex', 'scan.json')); denied(() => store.list('acme', 'globex')); denied(() => store.put('acme', 'globex', 'x.json', Buffer.from('x'))); denied(() => store.erase('acme', 'globex'));
    denied(() => store.get('acme', '../globex', 'scan.json')); denied(() => store.get('acme', 'acme', '../globex/scan.json')); denied(() => store.get('acme', 'acme', '..')); denied(() => store.get('acme', 'acme', '/etc/passwd'));
    denied(() => store.get('..', '..', 'x')); denied(() => store.get(undefined, 'acme', 'scan.json')); denied(() => store.get('acme', 'acme', 'a/b')); denied(() => store.put('acme', 'acme', 'x\0y', Buffer.from('x')));
    assert.equal(fs.readFileSync(path.join(root, 'tenants', 'globex', 'scan.json'), 'utf8'), 'globex evidence', 'untouched');
    const denials = log.entries.filter((e) => e.event === 'access.denied'); assert.ok(denials.length >= 10); assert.ok(denials.every((e) => e.code && !/evidence/.test(JSON.stringify(e))));
    assert.deepEqual(verifyAuditLog(log.entries), { ok: true, brokenAt: null });
    // a symlink planted inside the tenant's own directory is not followed
    fs.symlinkSync(path.join(root, 'tenants', 'globex', 'scan.json'), path.join(root, 'tenants', 'acme', 'link.json'));
    denied(() => store.get('acme', 'acme', 'link.json')); denied(() => store.put('acme', 'acme', 'link.json', Buffer.from('overwrite')));
    assert.equal(fs.readFileSync(path.join(root, 'tenants', 'globex', 'scan.json'), 'utf8'), 'globex evidence', 'the write through the link was refused');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('ERASURE and LEGAL HOLD: erasing removes the tenant\'s evidence and leaves a tombstone; a legal hold blocks it until the hold lifts or expires', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-05-er-'));
  try {
    const log = createAuditLog({ now: () => NOW }); let holds = [{ artifact: 'tenant:acme', owner: 'legal-1', reason: 'litigation matter 42', expires_at: null }]; let t = NOW;
    const store = createTenantStore(root, { auditLog: log, holds: () => holds, now: () => t });
    store.put('acme', 'acme', 'a.json', Buffer.from('1')); store.put('acme', 'acme', 'b.json', Buffer.from('2')); store.put('globex', 'globex', 'a.json', Buffer.from('3'));
    assert.deepEqual(store.erase('acme', 'acme'), { erased: false, reason: 'legal-hold' }); assert.deepEqual(store.list('acme', 'acme'), ['a.json', 'b.json'], 'nothing was removed under the hold');
    holds = [{ artifact: 'tenant:acme', owner: 'legal-1', reason: 'matter closed', expires_at: new Date(NOW + 1000).toISOString() }]; t = NOW + 5000;
    assert.deepEqual(store.erase('acme', 'acme', { reason: 'customer-request' }), { erased: true, files: 2 }, 'a hold that has expired no longer blocks erasure');
    assert.deepEqual(store.list('acme', 'acme'), []); assert.deepEqual(store.list('globex', 'globex'), ['a.json'], 'another tenant is untouched');
    assert.deepEqual(log.entries.filter((e) => e.event.startsWith('erasure')).map((e) => [e.event, e.code]), [['erasure.refused', 'legal-hold'], ['erasure.done', 'customer-request']]);
    assert.ok(!JSON.stringify(log.entries).includes('litigation'), 'the hold\'s reason is not copied into the log');
    holds = [{ artifact: 'tenant:globex', owner: 'x', reason: 'y', expires_at: null }];
    assert.equal(store.erase('acme', 'acme').erased, true, 'a hold on another tenant does not matter'); assert.equal(store.erase('globex', 'globex').erased, false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
