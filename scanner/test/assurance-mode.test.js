// FR-204: "Add assurance modes: advisory, standard, and strict | Strict
// mode fails when a required analyzer fails, times out, is unavailable, or
// is silently skipped."
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAssuranceMode, ASSURANCE_MODES, DEFAULT_ASSURANCE_MODE } from '../src/pipeline/assurance-mode.js';
import { computeScanHealth, applyFreshness } from '../src/pipeline/scan-health.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../src/posture/provenance/schema.js';

const CLEAN = { status: 'complete', conditions: [], analyzers: { expected: 10, completed: 10, failed: 0, timedOut: 0, skippedByPolicy: 0 } };
const FAILED = { status: 'partial', conditions: ['1 analyzer(s) threw on at least one file'], analyzers: { expected: 10, completed: 9, failed: 1, timedOut: 0, skippedByPolicy: 0 } };
const TIMED_OUT = { status: 'partial', conditions: ['1 file(s) exceeded the per-file analysis timeout'], analyzers: { expected: 10, completed: 9, failed: 0, timedOut: 1, skippedByPolicy: 0 } };
const SKIPPED = { status: 'complete', conditions: [], analyzers: { expected: 10, completed: 9, failed: 0, timedOut: 0, skippedByPolicy: 1 } };
const ANNOTATOR_ERROR = { status: 'partial', conditions: ['1 annotator(s) threw and were skipped: why-fired'], analyzers: { expected: 10, completed: 10, failed: 0, timedOut: 0, skippedByPolicy: 0 } };

test('advisory mode: always ok, even on a genuinely broken scan', () => {
  for (const health of [CLEAN, FAILED, TIMED_OUT, ANNOTATOR_ERROR]) {
    const v = evaluateAssuranceMode('advisory', health);
    assert.equal(v.ok, true);
    assert.equal(v.mode, 'advisory');
  }
});

test('standard mode: always ok, same as advisory — the default does not independently gate', () => {
  for (const health of [CLEAN, FAILED, TIMED_OUT, ANNOTATOR_ERROR]) {
    const v = evaluateAssuranceMode('standard', health);
    assert.equal(v.ok, true);
  }
});

test('strict mode: a clean, fully-complete scan is ok', () => {
  const v = evaluateAssuranceMode('strict', CLEAN);
  assert.equal(v.ok, true);
});

test('strict mode: a failed analyzer fails the gate, naming the count', () => {
  const v = evaluateAssuranceMode('strict', FAILED);
  assert.equal(v.ok, false);
  assert.match(v.reason, /1 analyzer\(s\) failed/);
});

test('strict mode: a timed-out analyzer fails the gate', () => {
  const v = evaluateAssuranceMode('strict', TIMED_OUT);
  assert.equal(v.ok, false);
  assert.match(v.reason, /timed out/);
});

test('strict mode: an annotator error (not a detector/analyzer failure) still fails — strict cares about overall scan completeness, not just the coverage ledger', () => {
  const v = evaluateAssuranceMode('strict', ANNOTATOR_ERROR);
  assert.equal(v.ok, false);
});

test('strict mode: scanHealth.status "complete" but with a nonzero skippedByPolicy count — still ok under strict, since a policy skip is an operator\'s deliberate choice, not silent failure, and does not demote status', () => {
  // SKIPPED fixture has status:'complete' (matches scan-health.js's own
  // design: skippedByPolicy alone does not demote status). Strict mode
  // reads scanHealth.status as its primary signal, so this must pass.
  const v = evaluateAssuranceMode('strict', SKIPPED);
  assert.equal(v.ok, true);
});

test('strict mode: null/missing scanHealth is NOT ok — strict cannot vouch for a scan it has no health data for', () => {
  const v = evaluateAssuranceMode('strict', null);
  assert.equal(v.ok, false);
});

test('an invalid/unknown mode string degrades to the default (standard), never throws, never silently becomes strict', () => {
  const v = evaluateAssuranceMode('bogus-mode', FAILED);
  assert.equal(v.mode, DEFAULT_ASSURANCE_MODE);
  assert.equal(v.ok, true, 'must degrade to standard\'s (non-gating) behavior, not fail closed as if it were strict');
});

test('a missing mode (undefined) also degrades to the default', () => {
  const v = evaluateAssuranceMode(undefined, FAILED);
  assert.equal(v.mode, DEFAULT_ASSURANCE_MODE);
});

test('ASSURANCE_MODES names exactly the three PRD-specified modes, in a stable order', () => {
  assert.deepEqual(ASSURANCE_MODES, ['advisory', 'standard', 'strict']);
});

// FR-207 x FR-204 integration: a stale vulnerability feed/calibration table/
// ruleset/policy is exactly the kind of "silently degraded assurance" this
// PRD's E2 epic exists to make visible -- prove the two features actually
// compose, using the real computeScanHealth()/applyFreshness() pipeline
// (not a hand-built scanHealth object), not just assurance-mode.js's own
// pure evaluator in isolation.
test('strict mode: a stale KEV catalog (FR-207) genuinely fails the gate through the real scanHealth pipeline', () => {
  const clean = computeScanHealth({ scanMeta: { filesScanned: 5, filesTimedOut: 0 }, annotatorErrors: [] });
  assert.equal(evaluateAssuranceMode('strict', clean).ok, true, 'sanity: the pre-freshness scan is clean');
  const withStaleFeed = applyFreshness(clean, { kev: { stale: true, ageDays: 30 } });
  const v = evaluateAssuranceMode('strict', withStaleFeed);
  assert.equal(v.ok, false);
  assert.match(v.reason, /scanHealth\.status is 'partial'/);
  assert.ok(v.conditions.some(c => /KEV catalog is stale/.test(c)), `expected the KEV condition surfaced on the verdict, got ${JSON.stringify(v.conditions)}`);
});

test('advisory/standard modes: the same stale-feed scan never gates, matching every other FR-204 condition', () => {
  const clean = computeScanHealth({ scanMeta: { filesScanned: 5, filesTimedOut: 0 }, annotatorErrors: [] });
  const withStaleFeed = applyFreshness(clean, { calibration: { stale: true, ageDays: 400 } });
  assert.equal(evaluateAssuranceMode('advisory', withStaleFeed).ok, true);
  assert.equal(evaluateAssuranceMode('standard', withStaleFeed).ok, true);
});

test('strict mode: a finding with findingProvenance.status "complete" passes the provenance check', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'a', authorDate: '2026-01-01T00:00:00Z' } });
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1', findingProvenance: fp }]);
  assert.equal(v.ok, true);
});

test('strict mode: a finding with findingProvenance.status "uncommitted" passes the provenance check', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.UNCOMMITTED);
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1', findingProvenance: fp }]);
  assert.equal(v.ok, true);
});

test('strict mode: a finding with findingProvenance.status "not_available" fails the gate, naming the count', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE);
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1', findingProvenance: fp }]);
  assert.equal(v.ok, false);
  assert.match(v.reason, /1 finding\(s\) have status outside \[complete, uncommitted\]/);
});

test('strict mode: a finding with NO findingProvenance at all also fails the gate', () => {
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1' }]);
  assert.equal(v.ok, false);
});

test('strict mode: an empty/missing findings array never fails the gate on its own (backward compatible)', () => {
  assert.equal(evaluateAssuranceMode('strict', CLEAN).ok, true);
  assert.equal(evaluateAssuranceMode('strict', CLEAN, []).ok, true);
});

test('advisory/standard modes: bad provenance never gates, matching every other FR-204 condition', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE);
  assert.equal(evaluateAssuranceMode('advisory', CLEAN, [{ id: 'f1', findingProvenance: fp }]).ok, true);
  assert.equal(evaluateAssuranceMode('standard', CLEAN, [{ id: 'f1', findingProvenance: fp }]).ok, true);
});
