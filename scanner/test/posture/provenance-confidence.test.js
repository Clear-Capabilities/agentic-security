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

// Second independent Finding Provenance PRD audit (Task 3): confirms
// `renameAmbiguous` itself is real, correct logic — the audit's "dead code"
// finding was about the ONE production caller (coordinator.js) hardcoding
// `false` for it, never that this branch was wrong. Otherwise-HIGH-eligible
// inputs (verified parent boundary, complete history, compatible detector)
// still degrade to LOW when renameAmbiguous is true, with the reason named.
test('assessConfidence: an otherwise-HIGH-eligible result degrades to LOW when renameAmbiguous is true', () => {
  const c = assessConfidence({
    parentBoundaryVerified: true, historyComplete: true, detectorCompatible: true,
    renameAmbiguous: true, shallow: false,
  });
  assert.equal(c.level, 'low');
  assert.ok(c.reasons.includes('rename_ambiguous'));
});
