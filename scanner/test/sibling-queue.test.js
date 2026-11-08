// Threat-model PRD FR-05.3 and AC-05C: a confirmed root cause becomes a bounded sibling queue whose states never blur detector
// coverage, a candidate, a confirmation, a repair and a verified repair; a corrected sibling's record cannot close another.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sweepRootCauses } from '../src/posture/root-cause-sweep.js';
import { buildSiblingQueue, siblingId } from '../src/posture/sibling-queue.js';
import { buildVerificationRecord } from '../src/posture/assurance/verification-record.js';
import { digestOf } from '../src/posture/assurance/identity.js';

const FILES = {
  'src/a.js': 'const r = db.query("SELECT * FROM t WHERE id = " + req.query.id);\n',
  'src/b.js': 'function list(req) {\n  return db.query("SELECT * FROM u WHERE id = " + req.params.id);\n}\n',
  'src/c.js': 'const helper = (req) => db.query("SELECT * FROM v WHERE id = " + req.query.id);\nmodule.exports = helper;\n',
  'src/d.js': 'const z = db.query("SELECT * FROM w WHERE id = " + req.body.id);\n',
};
const CONFIRMED = { id: 'F-root', file: 'src/a.js', line: 1, cwe: 'CWE-89', vuln: 'SQL injection', snippet: FILES['src/a.js'].trim(), proofTier: 'execution-proven', confirmed: true, verdict: 'confirmed', severity: 'high' };
const DETECTOR_HIT = { id: 'F-d', file: 'src/d.js', line: 1, cwe: 'CWE-89', vuln: 'SQL injection', severity: 'high' };
const sweep = () => sweepRootCauses([CONFIRMED, DETECTOR_HIT], FILES, { confirmedOnly: false }).sweeps.find((s) => s.fromFindingId === 'F-root');
const verifiedRecord = (hypothesisId) => buildVerificationRecord({
  hypothesisId, commit: 'a1'.repeat(20), detectorOrigin: { detector: 'SQL injection', family: 'injection', parser: 'SAST' }, attempt: 1,
  reason: 'patched-negative replay', scope: { description: 'sibling repair', platform: process.platform, backend: 'userspace' }, preconditions: { valid: true },
  oracle: { id: 'injection-execution', kind: 'runtime-replay', version: '1' }, outcome: 'refuted',
  evidence: [{ id: 'replay', kind: 'trusted-runtime-proof', producer: 'trusted-runner', digest: digestOf('replay'), source: 'oracle:injection-execution@1' }],
  repair: { status: 'replay-verified', patchDigest: digestOf('patch'), replayRecordId: 'vrec:0000000000000001' },
});

test('AC-05C: a detector-reported sibling, a wrapper candidate and an independently verified repair occupy distinct states', () => {
  const s = sweep();
  assert.ok(s && s.found >= 3, JSON.stringify(s));
  const q0 = buildSiblingQueue(s);
  const at = (q, file) => q.items.find((i) => i.file === file);
  assert.equal(at(q0, 'src/d.js').state, 'detector-reported', 'the legacy mitigated count is detector coverage, not a repair');
  assert.equal(at(q0, 'src/c.js').state, 'candidate', 'a sibling through a wrapper parameter is a candidate');
  assert.ok(at(q0, 'src/c.js').discovery.sinkPattern, 'each item carries the predicate that found it');
  const b = at(q0, 'src/b.js'); const c = at(q0, 'src/c.js');
  const q = buildSiblingQueue(s, { producer: 'detector:SAST', evidence: [
    { siblingId: b.id, kind: 'confirmation', by: 'appsec-reviewer' },
    { siblingId: b.id, kind: 'repair', by: 'dev' },
    { siblingId: b.id, kind: 'verification', record: verifiedRecord(b.id) },
    { siblingId: c.id, kind: 'confirmation', by: 'detector:SAST' },
  ] });
  assert.equal(at(q, 'src/b.js').state, 'verified');
  assert.equal(at(q, 'src/c.js').state, 'candidate', 'the producer cannot confirm its own sibling');
  assert.equal(at(q, 'src/c.js').rejected[0].reason, 'a confirmation must come from a party other than the producer');
  assert.equal(q.totals.byState.verified, 1);
});

test('AC-05C: replaying a corrected sibling cannot close an untested one, and a non-replay record does not verify', () => {
  const s = sweep();
  const q0 = buildSiblingQueue(s);
  const b = q0.items.find((i) => i.file === 'src/b.js'); const c = q0.items.find((i) => i.file === 'src/c.js');
  const q = buildSiblingQueue(s, { evidence: [{ siblingId: c.id, kind: 'verification', record: verifiedRecord(b.id) }] });
  const cq = q.items.find((i) => i.id === c.id);
  assert.equal(cq.state, 'candidate'); assert.equal(cq.rejected[0].reason, 'the record verifies another sibling');
  const edited = { ...verifiedRecord(c.id), reason: 'edited' };
  assert.equal(buildSiblingQueue(s, { evidence: [{ siblingId: c.id, kind: 'verification', record: edited }] }).items.find((i) => i.id === c.id).state, 'candidate');
  assert.equal(siblingId('src/c.js', 1, 'x'), siblingId('src/c.js', 1, 'x'));
  assert.notEqual(siblingId('src/c.js', 1, 'x'), siblingId('src/c.js', 2, 'x'));
});

test('AC-05C: counts reconcile when the sweep sample is capped', () => {
  const files = {}; for (let i = 0; i < 130; i++) files[`src/f${i}.js`] = 'const r = db.query("SELECT * FROM t WHERE id = " + req.query.id);\n';
  const s = sweepRootCauses([{ ...CONFIRMED, file: 'src/f0.js' }], files, { confirmedOnly: false }).sweeps[0];
  const q = buildSiblingQueue(s);
  assert.equal(s.instancesTruncated, true);
  assert.equal(q.totals.found, s.found);
  assert.equal(q.totals.sampled + q.totals.unsampled, q.totals.found, 'sampled plus unsampled is the exact total');
  assert.equal(Object.values(q.totals.byState).reduce((a, b) => a + b, 0), q.totals.sampled);
});
