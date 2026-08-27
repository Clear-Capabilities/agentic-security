// FR-PROV-016 (M2): controlRefs + derivedProvenance on compliance evaluator
// output. See docs/superpowers/specs/2026-08-27-finding-provenance-m2-m3-m4-design.md §2.1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateFramework, deriveComplianceProvenance } from '../src/posture/auditor-walkthrough.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../src/posture/provenance/schema.js';

function fw(controlOverrides = {}) {
  return {
    id: 'test-fw',
    name: 'Test Framework',
    controls: [{
      id: 'TF-1', function: 'Test', category: 'Test', summary: 'A test control',
      codeTestable: 'yes', mapsTo: ['family:sql-injection'],
      ...controlOverrides,
    }],
  };
}

test('deriveComplianceProvenance: empty input resolves unknown/null, never fabricates', () => {
  const d = deriveComplianceProvenance([]);
  assert.equal(d.earliestOrigin, null);
  assert.equal(d.confidence, 'unknown');
  assert.deepEqual(d.derivedFrom, []);
});

test('deriveComplianceProvenance: prefers the OLDEST complete-status origin among several findings', () => {
  const older = { id: 'f-old', findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'aaa1111', authorDate: '2025-01-01T00:00:00Z', authorName: 'A' } }) };
  const newer = { id: 'f-new', findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'bbb2222', authorDate: '2026-01-01T00:00:00Z', authorName: 'B' } }) };
  const d = deriveComplianceProvenance([newer, older]);
  assert.equal(d.earliestOrigin.commit, 'aaa1111');
  assert.equal(d.confidence, 'high');
});

test('deriveComplianceProvenance: compares authorDate as an instant, not a lexical string (timezone-safe)', () => {
  // A: 2026-06-01T23:30:00-08:00 = 2026-06-02T07:30:00Z (chronologically LATER)
  // B: 2026-06-02T01:00:00+00:00 = 2026-06-02T01:00:00Z (chronologically EARLIER — the true earliest)
  // Raw ISO strings sort 'A' < 'B' lexically (the wrong direction: a naive
  // string comparison would pick A as "earliest") because authorDate
  // preserves the author's local UTC offset rather than being normalized
  // to Z — see git-evidence.js's commitMeta.
  const A = { id: 'f-a', findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'aaa0000', authorDate: '2026-06-01T23:30:00-08:00', authorName: 'A' } }) };
  const B = { id: 'f-b', findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'bbb0000', authorDate: '2026-06-02T01:00:00+00:00', authorName: 'B' } }) };
  assert.ok('2026-06-01T23:30:00-08:00' < '2026-06-02T01:00:00+00:00', 'precondition: raw strings sort in the wrong chronological direction');
  assert.ok(Date.parse('2026-06-01T23:30:00-08:00') > Date.parse('2026-06-02T01:00:00+00:00'), 'precondition: A is chronologically later than B');
  const d = deriveComplianceProvenance([A, B]);
  assert.equal(d.earliestOrigin.commit, 'bbb0000');
});

test('deriveComplianceProvenance: falls back to partial-status origin when nothing resolved complete', () => {
  const p = { id: 'f-p', findingProvenance: emptyProvenance(PROVENANCE_STATUS.PARTIAL, { findingOrigin: { commit: 'ccc3333', authorDate: '2026-02-01T00:00:00Z', authorName: 'C' } }) };
  const na = { id: 'f-na', findingProvenance: emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE) };
  const d = deriveComplianceProvenance([p, na]);
  assert.equal(d.earliestOrigin.commit, 'ccc3333');
  assert.equal(d.confidence, 'low');
});

test('evaluateFramework: an absent control carries controlRefs naming the open finding(s) and a derivedProvenance', () => {
  const finding = {
    id: 'sast-1', family: 'sql-injection', severity: 'high',
    findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'ddd4444', authorDate: '2026-03-01T00:00:00Z', authorName: 'D' } }),
  };
  const [result] = evaluateFramework('/tmp/does-not-need-to-exist', fw(), { findings: [finding] });
  assert.equal(result.status, 'absent');
  assert.deepEqual(result.controlRefs, ['sast-1']);
  assert.equal(result.derivedProvenance.earliestOrigin.commit, 'ddd4444');
  assert.equal(result.derivedProvenance.confidence, 'high');
});

test('evaluateFramework: a present control (no open findings) carries an empty controlRefs', () => {
  const [result] = evaluateFramework('/tmp/does-not-need-to-exist', fw(), { findings: [] });
  assert.equal(result.status, 'present');
  assert.deepEqual(result.controlRefs, []);
  assert.equal(result.derivedProvenance.earliestOrigin, null);
});

test('evaluateFramework: a manual control (codeTestable:no, no mapping) carries an empty controlRefs', () => {
  const [result] = evaluateFramework('/tmp/does-not-need-to-exist', fw({ mapsTo: [], codeTestable: 'no' }), { findings: [] });
  assert.equal(result.status, 'manual');
  assert.deepEqual(result.controlRefs, []);
});
