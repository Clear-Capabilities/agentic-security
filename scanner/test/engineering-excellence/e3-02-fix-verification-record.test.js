// E3-02: the patch-level verification record. Honesty is a property of the validator, so each rule is pinned in both directions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { COMPLETENESS, LEG_NAMES, LEG_STATUSES, buildFixVerificationRecord, deriveCompleteness, deriveVerifiedFull, evidenceItem, fixRecordId, leg, legacyViewOf, validateFixVerificationRecord } from '../../src/fix/verification-record.js';

const H = (c) => 'sha256:' + c.repeat(64);
const ev = (n) => evidenceItem({ kind: 'log', mediaType: 'text/plain', sha256: String(n).repeat(64).slice(0, 64) });
const E1 = ev('a'); const E2 = ev('b'); const E3 = ev('c');
const passed = (...ids) => leg('passed', { evidenceIds: ids });

function full(over = {}) {
  return buildFixVerificationRecord({
    findingId: 'F1', findingStableId: 'stable-1', mode: 'apply', route: 'cli-apply', preCommit: 'a'.repeat(40), preTreeHash: H('1'), postPatchHash: H('2'), patchHash: H('3'),
    affectedFiles: ['src/a.js', 'src/b.js'],
    securityBefore: passed(E1.id), securityAfter: passed(E2.id), exploitProofBefore: passed(E1.id), exploitProofAfter: passed(E2.id), newFindingDelta: passed(E2.id),
    behaviorPreservation: passed(E3.id), behaviorTests: passed(E3.id), regressionTests: passed(E3.id), lint: leg('not_applicable', { reason: 'no linter configured' }), typecheck: leg('not_applicable', { reason: 'no type checker configured' }), dependencyChecks: leg('not_applicable', { reason: 'no dependency changed' }),
    requiredLegs: ['securityAfter', 'exploitProofAfter', 'newFindingDelta', 'behaviorPreservation', 'behaviorTests'],
    evidence: [E1, E2, E3], tools: { engineVersion: '1.0.0', verifier: 'test' }, residualRisk: { level: 'low', notes: [] }, confidence: { level: 'proven', policy: 'exploit-replay-v1', evidenceIds: [E2.id] },
    timestamps: { startedAt: '2026-01-01T00:00:00Z', completedAt: '2026-01-01T00:00:05Z' }, ...over,
  });
}
const ok = (r) => validateFixVerificationRecord(r);
const codes = (r) => ok(r).errors.map((e) => `${e.code}:${e.path}`);

test('a fully verified record is valid, derived as full, and carries every leg the PRD names', () => {
  const r = full();
  assert.deepEqual(ok(r), { ok: true, errors: [] });
  assert.equal(r.verifiedFull, true);
  assert.deepEqual(r.degradedLegs, []);
  assert.equal(r.fixCompleteness, 'FULL');
  for (const n of ['securityBefore', 'securityAfter', 'exploitProofBefore', 'exploitProofAfter', 'behaviorTests', 'lint', 'typecheck', 'dependencyChecks', 'newFindingDelta', 'regressionTests']) assert.ok(LEG_NAMES.includes(n), n);
  for (const f of ['findingId', 'preCommit', 'postPatchHash', 'patchHash', 'affectedFiles', 'degradedLegs', 'verifiedFull', 'fixCompleteness', 'residualRisk', 'confidence', 'tools', 'failures', 'evidence', 'timestamps']) assert.ok(f in r, f);
  assert.deepEqual([...LEG_STATUSES], ['passed', 'failed', 'blocked', 'not_run', 'not_applicable']);
  assert.match(r.id, /^fvrec:[0-9a-f]{16}$/);
});

test('a leg that did not run is degraded, never passed: the record is not verifiedFull and says which leg and why', () => {
  const r = full({ behaviorTests: leg('not_run', { reason: 'no test command was detected' }) });
  assert.equal(ok(r).ok, true);
  assert.equal(r.verifiedFull, false);
  assert.deepEqual(r.degradedLegs, ['behaviorTests: not_run (no test command was detected)']);
  assert.equal(r.fixCompleteness, 'MITIGATION');
  assert.equal(r.coverage.notRun, 1);
  assert.equal(legacyViewOf(r).verifiedFull, false);
});

test('a missing leg defaults to not_run, so a route that did less produces a record with more not_run, not a shorter record', () => {
  const r = buildFixVerificationRecord({ findingId: 'F2', mode: 'verify', route: 'mcp-verify', patchHash: H('3'), affectedFiles: ['a.js'], securityAfter: passed(E1.id), requiredLegs: ['securityAfter', 'behaviorTests'], evidence: [E1] });
  assert.equal(ok(r).ok, true);
  assert.equal(r.behaviorTests.status, 'not_run');
  assert.equal(r.exploitProofAfter.status, 'not_run');
  assert.equal(r.verifiedFull, false);
  assert.equal(r.fixCompleteness, 'MITIGATION');
});

test('not_run, blocked and not_applicable are never read as passed', () => {
  for (const status of ['not_run', 'blocked', 'not_applicable']) {
    const r = full({ lint: leg(status, { reason: 'because' }), requiredLegs: ['securityAfter', 'lint'] });
    if (status === 'not_applicable') { assert.ok(codes(r).includes('RULE_VIOLATION:lint'), 'a required leg cannot be not_applicable'); continue; }
    assert.equal(r.verifiedFull, false, status);
    assert.ok(r.degradedLegs.some((d) => d.startsWith('lint:')), status);
  }
});

test('a leg that is not passed must say why; a leg that passed must cite evidence', () => {
  const bad = structuredClone(full());
  bad.lint = { status: 'not_run', evidenceIds: [], reason: null };
  assert.ok(codes(bad).includes('RULE_VIOLATION:lint.reason'));
  const noEv = structuredClone(full());
  noEv.behaviorTests = { status: 'passed', evidenceIds: [], reason: null };
  assert.ok(codes(noEv).includes('RULE_VIOLATION:behaviorTests.evidenceIds'));
});

test('verifiedFull is derived: forging it, or forging the degraded list or the tier, is refused', () => {
  const r = full({ behaviorTests: leg('not_run', { reason: 'no runner' }) });
  const forged = { ...structuredClone(r), verifiedFull: true };
  assert.ok(codes(forged).includes('RULE_VIOLATION:verifiedFull'));
  const noList = { ...structuredClone(r), degradedLegs: [] };
  assert.ok(codes(noList).includes('RULE_VIOLATION:degradedLegs'));
  const tier = { ...structuredClone(r), fixCompleteness: 'FULL' };
  assert.ok(codes(tier).includes('RULE_VIOLATION:fixCompleteness'));
});

test('a failed leg makes the record unverified and a recorded failure blocks it, whatever else passed', () => {
  const failed = full({ newFindingDelta: leg('failed', { reason: 'the patch introduced a new high finding' }) });
  assert.equal(failed.verifiedFull, false);
  assert.equal(failed.fixCompleteness, 'unverified');
  assert.equal(legacyViewOf(failed).ok, false);
  const blocked = full({ failures: [{ leg: 'behaviorTests', reason: 'the test run crashed' }] });
  assert.equal(blocked.verifiedFull, false);
  assert.equal(blocked.fixCompleteness, 'blocked');
  assert.equal(ok(blocked).ok, true);
  const claimedBlocked = full({ behaviorTests: leg('blocked', { reason: 'sandbox unavailable' }) });
  assert.equal(claimedBlocked.fixCompleteness, 'blocked');
});

test('securityAfter is always required, and a tier above unverified needs it to have passed', () => {
  const r = full({ requiredLegs: ['behaviorTests'] });
  assert.ok(codes(r).includes('RULE_VIOLATION:requiredLegs'));
  const noSecurity = full({ securityAfter: leg('not_run', { reason: 'rescan did not run' }) });
  assert.equal(noSecurity.fixCompleteness, 'unverified');
  const lie = { ...structuredClone(noSecurity), fixCompleteness: 'MITIGATION' };
  assert.ok(codes(lie).includes('RULE_VIOLATION:fixCompleteness'));
});

test('the workaround tier is available to a route that knows the cause remains, but still needs the weakness shown gone', () => {
  const w = full({ workaround: true });
  assert.equal(w.fixCompleteness, 'WORKAROUND');
  assert.equal(ok(w).ok, true);
  assert.equal(deriveCompleteness(full({ securityAfter: leg('not_run', { reason: 'x' }) }), { workaround: true }), 'unverified');
  assert.ok(COMPLETENESS.includes('unverified') && COMPLETENESS.includes('blocked'));
});

test('evidence is addressed by digest: a dangling reference, a duplicate id, a bad digest and a credential in a location are refused', () => {
  const dangling = structuredClone(full());
  dangling.behaviorTests.evidenceIds = ['ev:0000000000000000'];
  assert.ok(codes(dangling).includes('DANGLING_REF:behaviorTests.evidenceIds'));
  const dup = structuredClone(full());
  dup.evidence = [dup.evidence[0], dup.evidence[0]];
  assert.ok(codes(dup).some((c) => c.startsWith('DUPLICATE_ID:evidence')));
  const badDigest = structuredClone(full());
  badDigest.evidence[0].sha256 = 'not-a-digest';
  assert.ok(codes(badDigest).some((c) => c.startsWith('BAD_DIGEST:evidence')));
  const uri = structuredClone(full());
  uri.evidence[0].uri = 'https://user:secret@host/x';
  assert.ok(codes(uri).some((c) => c.startsWith('RULE_VIOLATION:evidence') && c.endsWith('.uri')));
  assert.equal(evidenceItem({ kind: 'log', sha256: 'a'.repeat(64) }).id, evidenceItem({ kind: 'log', sha256: 'a'.repeat(64) }).id, 'the id follows the content');
  assert.notEqual(evidenceItem({ kind: 'log', sha256: 'a'.repeat(64) }).id, evidenceItem({ kind: 'log', sha256: 'b'.repeat(64) }).id);
});

test('proven confidence needs a named policy, evidence that is in the record, and a passed exploit replay on the patched code', () => {
  assert.equal(ok(full()).ok, true);
  const noPolicy = full({ confidence: { level: 'proven', policy: null, evidenceIds: [E2.id] } });
  assert.ok(codes(noPolicy).includes('RULE_VIOLATION:confidence.policy'));
  const noEv = full({ confidence: { level: 'proven', policy: 'p', evidenceIds: [] } });
  assert.ok(codes(noEv).includes('RULE_VIOLATION:confidence.evidenceIds'));
  const noReplay = full({ exploitProofAfter: leg('not_run', { reason: 'no exploit available' }), confidence: { level: 'proven', policy: 'p', evidenceIds: [E2.id] } });
  assert.ok(codes(noReplay).includes('RULE_VIOLATION:confidence.level'));
  assert.equal(ok(full({ confidence: { level: 'inferred', policy: null, evidenceIds: [] } })).ok, true);
});

test('the id follows the content and not the clock or the route: timestamps, evidence order and route do not change it, any semantic field does', () => {
  const a = full();
  const b = full({ timestamps: { startedAt: '2030-01-01T00:00:00Z', completedAt: '2030-01-01T00:09:00Z' }, evidence: [E3, E1, E2], tools: { engineVersion: '9.9.9', verifier: 'other' } });
  assert.equal(a.id, b.id);
  assert.notEqual(a.id, full({ patchHash: H('4') }).id);
  assert.equal(a.id, full({ route: 'mcp-apply-fix', mode: 'preview' }).id, 'who asked is recorded but is not identity');
  assert.notEqual(a.id, full({ behaviorTests: leg('not_run', { reason: 'x' }) }).id);
  const tampered = { ...structuredClone(a), patchHash: H('9') };
  assert.ok(codes(tampered).includes('ID_MISMATCH:id'));
  assert.equal(fixRecordId(a), a.id);
});

test('hostile and malformed input is refused without throwing', () => {
  for (const bad of [null, undefined, 3, 'x', [], {}, { schema: 'something-else' }, { ...full(), schemaVersion: '9.0.0' }]) {
    const r = validateFixVerificationRecord(bad);
    assert.equal(r.ok, false);
    assert.ok(r.errors.length > 0);
  }
  const extra = { ...structuredClone(full()), sneaky: true };
  assert.ok(codes(extra).includes('UNKNOWN_FIELD:sneaky'));
  const escape = structuredClone(full());
  escape.affectedFiles = ['../../etc/passwd'];
  assert.ok(codes(escape).includes('BAD_TYPE:affectedFiles'));
  assert.ok(codes({ ...structuredClone(full()), lint: 'passed' }).includes('BAD_TYPE:lint'));
});

test('the legacy view gives existing consumers the fields they read and the new tier beside them', () => {
  const v = legacyViewOf(full());
  assert.deepEqual(v, { ok: true, verified: true, verifiedFull: true, degradedLegs: [], completeness: 'FULL' });
  const d = legacyViewOf(full({ regressionTests: leg('not_run', { reason: 'no suite' }), requiredLegs: ['securityAfter', 'regressionTests'] }));
  assert.equal(d.ok, true);
  assert.equal(d.verifiedFull, false);
  assert.deepEqual(d.degradedLegs, ['regressionTests: not_run (no suite)']);
  assert.equal(deriveVerifiedFull(full()), true);
});

// ---- adapters ------------------------------------------------------------------------------------------------------------------
import { patchHashOf, recordFromVerifyFix, treeHashOf } from '../../src/fix/verification-adapters.js';

const verifyResult = (over = {}) => ({
  ok: true, rescan: { ok: true, reason: 'verified', introduced: [] }, lint: { ok: true, runner: 'none' },
  tests: { status: 'passed', passed: true, skipped: false, reason: null }, testedPrePatch: false, honesty: null, poc: { status: 'not-requested', reason: null, tier: null }, ...over,
});
const ctx = { finding: { id: 'F9', stableId: 's9' }, files: { 'a.js': 'x' }, route: 'mcp-verify-fix', mode: 'verify', findingPresent: true };

test('adapter: a verifyFix result that ran tests before the patch is recorded as not_run for the patched tree', () => {
  const r = recordFromVerifyFix(verifyResult({ testedPrePatch: true }), ctx);
  assert.equal(validateFixVerificationRecord(r).ok, true, JSON.stringify(validateFixVerificationRecord(r).errors));
  assert.equal(r.behaviorTests.status, 'not_run');
  assert.match(r.behaviorTests.reason, /BEFORE the patch/);
  assert.equal(r.verifiedFull, false);
  assert.ok(r.degradedLegs.some((d) => d.startsWith('behaviorTests:')));
});

test('adapter: a clean result with tests on the patched tree is verifiedFull only for the legs the route requires', () => {
  const r = recordFromVerifyFix(verifyResult(), ctx);
  assert.equal(validateFixVerificationRecord(r).ok, true);
  assert.equal(r.verifiedFull, true);
  assert.equal(r.exploitProofAfter.status, 'not_run', 'the route requested no replay, and the record says so');
  assert.equal(r.behaviorPreservation.status, 'not_run');
});

test('adapter: still-present finding, introduced findings, failing tests and a surviving exploit each fail their own leg', () => {
  assert.equal(recordFromVerifyFix(verifyResult({ rescan: { ok: false, reason: 'still-present', introduced: [] } }), ctx).securityAfter.status, 'failed');
  assert.equal(recordFromVerifyFix(verifyResult({ rescan: { ok: true, reason: 'verified', introduced: [{ id: 'n' }] } }), ctx).newFindingDelta.status, 'failed');
  assert.equal(recordFromVerifyFix(verifyResult({ tests: { passed: false, skipped: false } }), ctx).behaviorTests.status, 'failed');
  const p = recordFromVerifyFix(verifyResult({ poc: { status: 'still-exploitable', reason: 'r', tier: 't' } }), ctx);
  assert.equal(p.exploitProofAfter.status, 'failed');
  assert.equal(p.fixCompleteness, 'unverified');
  for (const r of [p]) assert.equal(validateFixVerificationRecord(r).ok, true);
});

test('adapter: skipped tests and absent results are not_run with a reason, never passed', () => {
  const r = recordFromVerifyFix(verifyResult({ tests: { skipped: true, reason: 'no test command' }, lint: undefined }), ctx);
  assert.equal(r.behaviorTests.status, 'not_run'); assert.match(r.behaviorTests.reason, /no test command/);
  assert.equal(r.lint.status, 'not_run');
  assert.equal(validateFixVerificationRecord(r).ok, true);
});

test('adapter: patch and tree digests are stable, order independent and sensitive to content', () => {
  assert.equal(patchHashOf({ a: '1', b: '2' }), patchHashOf({ b: '2', a: '1' }));
  assert.notEqual(patchHashOf({ a: '1' }), patchHashOf({ a: '2' }));
  assert.equal(treeHashOf(['a'], () => 'x'), treeHashOf(['a'], () => 'x'));
  assert.notEqual(treeHashOf(['a'], () => 'x'), treeHashOf(['a'], () => null));
});
