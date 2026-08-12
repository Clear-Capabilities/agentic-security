// Stage 1 correctness audit: annotateConfidence's `if (f.unvalidated) conf
// *= 0.85` penalty could never apply in the real pipeline — annotateConfidence
// runs (~engine.js:8111) before f.unvalidated exists on any finding
// (set by llm-validator/index.js, invoked hundreds of lines later at
// ~engine.js:8587). Worse, annotateConfidence only computes from scratch
// when f.confidence is still null (so hand-tuned detector confidences
// survive untouched) — so simply calling it a second time after validation
// is a no-op once confidence is already set. applyUnvalidatedPenalty is the
// real fix: a separate, idempotent post-validation pass that retroactively
// adjusts an already-computed confidence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { annotateConfidence, applyUnvalidatedPenalty } from '../src/posture/confidence.js';

test('annotateConfidence computes a confidence + tier from severity', () => {
  const f = { severity: 'critical' };
  annotateConfidence([f]);
  assert.equal(typeof f.confidence, 'number');
  assert.equal(f.confidenceTier, 'high');
});

test('annotateConfidence preserves a hand-tuned confidence, only normalizes the tier', () => {
  const f = { severity: 'low', confidence: 0.95 };
  annotateConfidence([f]);
  assert.equal(f.confidence, 0.95);
  assert.equal(f.confidenceTier, 'high');
});

test('annotateConfidence alone does not apply the unvalidated penalty when unvalidated is set after confidence already exists', () => {
  // Simulates the real pipeline: confidence computed first (no unvalidated
  // yet), THEN unvalidated is set by the validator, THEN annotateConfidence
  // is (hypothetically) called again — proving a second call is a no-op.
  const f = { severity: 'high' };
  annotateConfidence([f]);
  const before = f.confidence;
  f.unvalidated = true;
  annotateConfidence([f]);
  assert.equal(f.confidence, before, 'a second annotateConfidence call must not touch an already-set confidence');
});

test('applyUnvalidatedPenalty retroactively applies the 0.85x penalty', () => {
  const f = { severity: 'high' };
  annotateConfidence([f]);
  const before = f.confidence;
  f.unvalidated = true;
  applyUnvalidatedPenalty([f]);
  assert.ok(f.confidence < before, `expected confidence to drop from ${before}, got ${f.confidence}`);
  assert.equal(f.confidence, Math.round(before * 0.85 * 1000) / 1000);
});

test('applyUnvalidatedPenalty is idempotent — a second call does not double-apply the penalty', () => {
  const f = { severity: 'high', unvalidated: true };
  annotateConfidence([f]);
  applyUnvalidatedPenalty([f]);
  const once = f.confidence;
  applyUnvalidatedPenalty([f]);
  assert.equal(f.confidence, once, 'a second call must not re-multiply the penalty');
});

test('applyUnvalidatedPenalty leaves validated findings untouched', () => {
  const f = { severity: 'high' };
  annotateConfidence([f]);
  const before = f.confidence;
  applyUnvalidatedPenalty([f]);
  assert.equal(f.confidence, before, 'a finding with no unvalidated flag must not be adjusted');
});

test('applyUnvalidatedPenalty never throws on garbage input', () => {
  assert.doesNotThrow(() => applyUnvalidatedPenalty(null));
  assert.doesNotThrow(() => applyUnvalidatedPenalty([null, {}, { unvalidated: true }]));
});
