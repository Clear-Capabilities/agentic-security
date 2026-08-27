import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessConfidence } from '../../src/posture/provenance/confidence.js';

test('assessConfidence: full verified boundary is HIGH', () => {
  const c = assessConfidence({ parentBoundaryVerified: true, historyComplete: true, detectorCompatible: true, renameAmbiguous: false, shallow: false });
  assert.equal(c.level, 'high');
  assert.ok(c.reasons.includes('parent_absence_verified'));
});

test('assessConfidence: no parent to test is MEDIUM (PRD confidence table)', () => {
  const c = assessConfidence({ parentBoundaryVerified: false, historyComplete: true, detectorCompatible: true, renameAmbiguous: false, shallow: false });
  assert.equal(c.level, 'medium');
});

test('assessConfidence: shallow history is LOW', () => {
  const c = assessConfidence({ parentBoundaryVerified: false, historyComplete: false, detectorCompatible: true, renameAmbiguous: false, shallow: true });
  assert.equal(c.level, 'low');
  assert.ok(c.reasons.includes('shallow_history'));
});

test('assessConfidence: budget exhausted is UNKNOWN', () => {
  const c = assessConfidence({ budgetExhausted: true });
  assert.equal(c.level, 'unknown');
});
