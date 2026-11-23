// Epic A of the contract-driven verification programme: the service contract is closed-world data with a content identity, its
// readable companion is bound by digest and reconciled rather than interpreted, and its approval lives in the one signed ledger.
// Acceptance: A-AC01 (one identity through every stage: the ref is a pure function of content), A-AC02 (proposed, edited, expired,
// revoked, forged and wrong-scope approvals satisfy nothing), A-AC03 (identical inputs give identical identities), A-AC04 (a pack and
// contract disagreement is a diagnostic with both sources), A-AC06 (bindings stay distinct; a missing binding is a gap).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateContract, contractDigest, contractRef, invariantRef, parseContractRef, bindingView, createContract, CONTRACT_SCHEMA } from '../../src/contracts/schema.js';
import { reconcilePack, parsePack, packDigest } from '../../src/contracts/pack.js';
import { approvalState, proposeContract, approveContract, revokeContract, contractSubjectId, APPROVAL_STATES } from '../../src/contracts/approval.js';
import { emptyLedger, verifyLedger, recordTransition } from '../../src/posture/invariants/lifecycle.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.join(HERE, '..', 'fixtures', 'contract-slice', 'security', 'contracts', 'invoices-service');
const load = () => JSON.parse(fs.readFileSync(path.join(DIR, 'contract.json'), 'utf8'));
const pack = () => fs.readFileSync(path.join(DIR, 'threat-pack.md'), 'utf8');
const clone = (v) => JSON.parse(JSON.stringify(v));
const lax = { sign: () => 'ff', verify: () => true };
const REVIEWER = { id: 'dana', kind: 'human' };
const POLICY = { id: 'slice-policy', reviewers: ['dana'] };

test('the slice contract validates, has one ref that is a pure function of its content, and parses back', () => {
  const c = load();
  assert.deepEqual(validateContract(c), { ok: true, errors: [] });
  const ref = contractRef(c);
  assert.match(ref, /^invoices-service@1\.0\.0#[0-9a-f]{16}$/);
  assert.equal(contractRef(clone(c)), ref, 'A-AC03: identical content, identical identity');
  assert.equal(contractDigest({ ...c, review: { state: 'approved', origin: 'authored' }, createdAt: 'later' }), contractDigest(c), 'the review claim and the stamp are not content');
  assert.notEqual(contractRef({ ...c, summary: c.summary + '.' }), ref, 'any content change is a new ref');
  assert.deepEqual(parseContractRef(invariantRef(c, 'TENANT-ISOLATION-001')), { id: 'invoices-service', version: '1.0.0', digest16: ref.split('#')[1], invariantId: 'TENANT-ISOLATION-001' });
  assert.equal(parseContractRef('nonsense'), null);
});

test('closed world and refusals: placeholders, credentials, commands, host paths, unknown fields, dangling refs, non-commit revisions', () => {
  const c = load();
  const codes = (doc) => validateContract(doc).errors.map((e) => `${e.code}:${e.path}`);
  assert.deepEqual(codes({ ...c, scope: { ...c.scope, repositories: [{ id: 'invoices-api', revision: 'REPLACE_WITH_EXACT_COMMIT' }] } }), ['RULE_VIOLATION:scope.repositories[0].revision']);
  assert.deepEqual(codes({ ...c, scope: { ...c.scope, repositories: [{ id: 'invoices-api', revision: 'main' }] } }), ['BAD_TYPE:scope.repositories[0].revision']);
  assert.deepEqual(codes({ ...c, summary: 'token: ghp_abcdefghijklmnopqrstuvwxyz0123456789' }), ['RULE_VIOLATION:summary']);
  assert.deepEqual(codes({ ...c, owner: 'ops $(curl evil)' }), ['RULE_VIOLATION:owner']);
  assert.deepEqual(codes({ ...c, controls: [{ ...c.controls[0], provenance: { file: '/Users/someone/app.js' } }] }), ['RULE_VIOLATION:controls[0].provenance.file']);
  assert.deepEqual(codes({ ...c, roots: ['/srv/app'] }), ['UNKNOWN_FIELD:roots']);
  assert.deepEqual(codes({ ...c, scope: { ...c.scope, repositories: [{ id: 'invoices-api', revision: c.scope.repositories[0].revision, credentials: 'x' }] } }), ['UNKNOWN_FIELD:scope.repositories[0].credentials']);
  const dangling = clone(c); dangling.invariants[0].controlRefs = ['no-such-control'];
  assert.deepEqual(codes(dangling), ['DANGLING_REF:invariants[0].controlRefs[0]']);
  const observed = clone(c); observed.controls[0].source = 'observed';
  assert.deepEqual(codes(observed), ['RULE_VIOLATION:controls[0].evidenceRefs'], 'an observed control names its evidence');
  const badEv = clone(c); badEv.invariants[0].requiredEvidence = ['vibes'];
  assert.deepEqual(codes(badEv), ['UNKNOWN_ENUM:invariants[0].requiredEvidence[0]']);
  assert.equal(validateContract(null).ok, false);
  assert.equal(validateContract({ ...c, schema: 'other' }).errors[0].code, 'SCHEMA_MISMATCH');
  assert.equal(createContract({ id: 'x' }).schema, CONTRACT_SCHEMA);
});

test('A-AC06: bindings are kept distinct and a missing or unsupported binding is a visible gap, never a satisfied check', () => {
  const view = bindingView(load());
  assert.deepEqual(view[0], { invariantId: 'TENANT-ISOLATION-001', bindings: { static: 'declared', scenario: 'declared', runtime: 'missing', preservation: 'missing' }, gaps: ['runtime', 'preservation'], checkable: true });
  assert.deepEqual(view[1].gaps, ['scenario', 'runtime', 'preservation']);
  const noRuntime = bindingView(load(), { available: ['static'] });
  assert.equal(noRuntime[0].bindings.scenario, 'unsupported');
});

test('A-AC04: the pack is bound by digest and reconciled; a disagreement names both sources and nothing is rewritten', () => {
  const c = load(); const p = pack();
  const r = reconcilePack(c, p);
  assert.deepEqual(r.issues, []);
  assert.equal(c.threatPack.digest, packDigest(p));
  assert.deepEqual(parsePack(p).invariantIds, ['AUTHN-REQUIRED-001', 'TENANT-ISOLATION-001']);
  const edited = p + '\n- RATE-LIMIT-001: no principal exceeds 100 requests a minute.\n';
  const r2 = reconcilePack(c, edited);
  assert.deepEqual(r2.issues.map((i) => i.code).sort(), ['pack-digest-mismatch', 'pack-names-undeclared-invariant']);
  assert.equal(r2.issues.find((i) => i.code === 'pack-digest-mismatch').contract, c.threatPack.digest);
  const narrower = clone(c); narrower.invariants.pop();
  assert.deepEqual(reconcilePack(narrower, p).issues.map((i) => i.code), ['pack-names-undeclared-invariant']);
  assert.equal(reconcilePack(c, null).issues[0].code, 'pack-unreadable');
});

test('A-AC02: approval lives only in the signed ledger; proposed, edited, revoked, expired, forged and wrong-scope approvals satisfy nothing', () => {
  const c = load();
  assert.equal(approvalState(c, null).state, 'not-recorded');
  const p = proposeContract(null, c, { actor: { id: 'drafter', kind: 'model' }, reason: 'drafted from the context build', signer: lax });
  assert.equal(p.ok, true, JSON.stringify(p.errors));
  assert.equal(p.record.subjectKind, 'service-contract');
  assert.equal(p.record.invariantId, contractSubjectId(c));
  assert.equal(approvalState(c, p.ledger, { signer: lax, now: '2026-11-22' }).state, 'proposed');

  // a document that claims approval, a model that approves, a ledger head copied into the document: none is approval
  const claims = clone(c); claims.review.state = 'approved';
  assert.equal(approvalState(claims, p.ledger, { signer: lax, now: '2026-11-22' }).state, 'proposed', 'the review claim is not content: the document with the claim is the same contract, and it is still only proposed');
  const modelApproval = approveContract(p.ledger, c, { actor: { id: 'drafter', kind: 'model' }, reason: 'looks right', policy: POLICY, signer: lax });
  assert.equal(modelApproval.ok, false); assert.equal(modelApproval.errors[0].code, 'not-a-human-reviewer');
  const stranger = approveContract(p.ledger, c, { actor: { id: 'mallory', kind: 'human' }, reason: 'approve', policy: POLICY, signer: lax });
  assert.equal(stranger.errors[0].code, 'unauthorized-reviewer');
  const noPolicy = approveContract(p.ledger, c, { actor: REVIEWER, reason: 'approve', signer: lax });
  assert.equal(noPolicy.errors[0].code, 'no-authorized-policy');

  const a = approveContract(p.ledger, c, { actor: REVIEWER, reason: 'reviewed with the owner', policy: POLICY, signer: lax });
  assert.equal(a.ok, true, JSON.stringify(a.errors));
  const ok = approvalState(c, a.ledger, { signer: lax, policy: POLICY, now: '2026-11-22' });
  assert.equal(ok.state, 'approved'); assert.equal(ok.current, true); assert.equal(ok.reviewer, 'dana'); assert.equal(ok.transitionId, a.record.id);

  // edited after review: same id and version, different content -> wrong-scope, with both digests
  const edited = clone(c); edited.invariants[0].statement += ' Except operators.';
  const ws = approvalState(edited, a.ledger, { signer: lax, policy: POLICY, now: '2026-11-22' });
  assert.equal(ws.state, 'wrong-scope'); assert.match(ws.reasons[0], /changed after review/);
  // the approval binds to the version too: a re-versioned copy of the same content is not approved
  const bumped = clone(c); bumped.version = '1.1.0';
  assert.equal(approvalState(bumped, a.ledger, { signer: lax, policy: POLICY, now: '2026-11-22' }).state, 'not-recorded');
  // expiry by the review policy and by the hard date, both leave the record visible
  assert.equal(approvalState(c, a.ledger, { signer: lax, policy: POLICY, now: '2027-11-22' }).state, 'expired');
  const dated = clone(c); dated.expiry.expiresAt = '2026-12-01';
  const pd = proposeContract(null, dated, { actor: { id: 'drafter', kind: 'code' }, reason: 'x', signer: lax });
  const ad = approveContract(pd.ledger, dated, { actor: REVIEWER, reason: 'ok', policy: POLICY, signer: lax });
  assert.equal(approvalState(dated, ad.ledger, { signer: lax, policy: POLICY, now: '2026-12-02' }).state, 'expired');
  // forged: a record appended under a name the current policy does not list fails verification as a whole
  const forged = clone(a.ledger); forged.records[1].actor = { id: 'mallory', kind: 'human' }; forged.records[1].id = a.record.id;
  const f = approvalState(c, forged, { signer: lax, policy: POLICY, now: '2026-11-22' });
  assert.equal(f.state, 'approval-unverifiable'); assert.ok(f.reasons.some((r) => /id-mismatch|reviewer-not-authorized-now/.test(r)));
  // a reviewer dropped from the policy since: the recorded approval no longer verifies under the current policy
  const dropped = approvalState(c, a.ledger, { signer: lax, policy: { id: 'p2', reviewers: ['erin'] }, now: '2026-11-22' });
  assert.equal(dropped.state, 'approval-unverifiable'); assert.match(dropped.reasons[0], /reviewer-not-authorized-now/);
  // revoked: visible, not current
  const r = revokeContract(a.ledger, c, { actor: REVIEWER, reason: 'the service changed hands', policy: POLICY, signer: lax });
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  const rv = approvalState(c, r.ledger, { signer: lax, policy: POLICY, now: '2026-11-22' });
  assert.equal(rv.state, 'revoked'); assert.equal(rv.current, false);
  assert.equal(recordTransition(r.ledger, { action: 'approve', invariantId: contractSubjectId(c), actor: REVIEWER, reason: 'again' }, { policy: POLICY, signer: lax }).errors[0].code, 'illegal-transition', 'a revoked approval is not re-approved in place; a new revision is proposed');
  assert.ok(APPROVAL_STATES.includes('revoked'));
  // the same ledger still verifies with executable invariants beside the contract (one authority, not two)
  assert.equal(verifyLedger(r.ledger, { signer: lax }).ok, true);
  assert.equal(recordTransition(emptyLedger(), { action: 'propose', contract: { ...c, schema: 'x' }, actor: { id: 'd', kind: 'code' }, reason: 'r' }, { signer: lax }).errors[0].code, 'invalid-contract');
});
