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

// ── A real user hit this ────────────────────────────────────────────────────
// `agentic-security ci <a GitHub "Download ZIP" extraction, no .git> --assurance
// strict` failed with only "1210 finding(s) have status outside [complete,
// uncommitted]" — no indication all 1210 failed for the exact same, simple,
// fixable reason coordinator.js already knows and records
// (finding.findingProvenance.limitations[0] = 'not a Git repository'), which
// never reached this message. These pin the fix.

test('strict mode: when every bad finding shares the "not a Git repository" reason, the message names it and tells the user how to fix it', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['not a Git repository'] });
  const findings = Array.from({ length: 1210 }, (_, i) => ({ id: `f${i}`, findingProvenance: fp }));
  const v = evaluateAssuranceMode('strict', CLEAN, findings);
  assert.equal(v.ok, false);
  assert.match(v.reason, /1210\/1210 finding\(s\) have status outside \[complete, uncommitted\]/);
  assert.match(v.reason, /"not a Git repository"/);
  assert.match(v.reason, /git init/);
  assert.match(v.reason, /--assurance strict/);
});

test('strict mode: "repository state unavailable" gets the same specific, actionable message as "not a Git repository"', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['repository state unavailable'] });
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1', findingProvenance: fp }]);
  assert.equal(v.ok, false);
  assert.match(v.reason, /"repository state unavailable"/);
  assert.match(v.reason, /git init/);
});

test('strict mode: a single shared non-git-repo reason is still named even when it is something else entirely', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['provenance disabled via --no-provenance'] });
  const findings = [
    { id: 'f1', findingProvenance: fp },
    { id: 'f2', findingProvenance: fp },
  ];
  const v = evaluateAssuranceMode('strict', CLEAN, findings);
  assert.equal(v.ok, false);
  assert.match(v.reason, /all 2 share the same reason: "provenance disabled via --no-provenance"/);
});

test('strict mode: mixed reasons across bad findings render as a ranked breakdown, not a bare count', () => {
  const gitFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['a category error, never resolvable'] });
  const otherFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['budget exhausted'] });
  const findings = [
    { id: 'f1', findingProvenance: gitFp },
    { id: 'f2', findingProvenance: gitFp },
    { id: 'f3', findingProvenance: gitFp },
    { id: 'f4', findingProvenance: otherFp },
  ];
  const v = evaluateAssuranceMode('strict', CLEAN, findings);
  assert.equal(v.ok, false);
  assert.match(v.reason, /3× "a category error, never resolvable"/);
  assert.match(v.reason, /1× "budget exhausted"/);
});

test('strict mode: a finding with no findingProvenance at all falls back to its status, never throws building the message', () => {
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1' }, { id: 'f2' }]);
  assert.equal(v.ok, false);
  assert.doesNotThrow(() => v.reason);
  assert.match(v.reason, /2\/2 finding\(s\)/);
});

test('strict mode: unpinned-dependency/no-lockfile provenance gaps get their own specific, honest "this is permanent" message', () => {
  const unpinnedFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
    limitations: ['origin resolution does not apply to a unpinned_dep supply-chain entry'],
  });
  const noLockFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
    limitations: ['origin resolution does not apply to a no_lockfile supply-chain entry'],
  });
  const findings = [
    { id: 'f1', findingProvenance: unpinnedFp },
    { id: 'f2', findingProvenance: unpinnedFp },
    { id: 'f3', findingProvenance: noLockFp },
  ];
  const v = evaluateAssuranceMode('strict', CLEAN, findings);
  assert.equal(v.ok, false);
  assert.match(v.reason, /3 of them describe an ABSENT dependency declaration/);
  assert.match(v.reason, /known, permanent limitation/);
  assert.match(v.reason, /--assurance standard\/advisory/);
});

// ── R1/R2 (adversarial premortem re-run, 2026-09-07) ────────────────────────
// The first fix silently dropped every reason except the single largest
// bucket. On a real non-git project with unpinned dependencies -- the
// COMMON case, not an edge case -- that meant only the git-repo message
// ever appeared, and the equally-real, equally-permanent supply-chain
// limitation was never mentioned; a user would "fix" git, rerun, and hit a
// wall the tool had full information about on the very first run.

test('strict mode: BOTH "not a Git repository" and permanent supply-chain reasons present at once are BOTH reported, not just the larger bucket', () => {
  const gitFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['not a Git repository'] });
  const supplyFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['origin resolution does not apply to a unpinned_dep supply-chain entry'] });
  const findings = [
    ...Array.from({ length: 100 }, (_, i) => ({ id: `sast${i}`, findingProvenance: gitFp })),
    ...Array.from({ length: 5 }, (_, i) => ({ id: `sca${i}`, findingProvenance: supplyFp })),
  ];
  const v = evaluateAssuranceMode('strict', CLEAN, findings);
  assert.equal(v.ok, false);
  // The larger bucket (git, 100) must still be reported...
  assert.match(v.reason, /100 of them are "not a Git repository"/);
  assert.match(v.reason, /git init/);
  // ...and the smaller bucket (supply-chain, 5) must NOT be silently dropped.
  assert.match(v.reason, /5 of them describe an ABSENT dependency declaration/);
  assert.match(v.reason, /known, permanent limitation/);
  assert.match(v.reason, /fixing only one will surface the next/);
});

test('strict mode: all three of git + supply-chain + an unrelated reason are reported together', () => {
  const gitFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['not a Git repository'] });
  const supplyFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['origin resolution does not apply to a no_lockfile supply-chain entry'] });
  const otherFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['budget exhausted'] });
  const findings = [
    { id: 'f1', findingProvenance: gitFp },
    { id: 'f2', findingProvenance: supplyFp },
    { id: 'f3', findingProvenance: otherFp },
  ];
  const v = evaluateAssuranceMode('strict', CLEAN, findings);
  assert.equal(v.ok, false);
  assert.match(v.reason, /1 of them are "not a Git repository"/);
  assert.match(v.reason, /1 of them describe an ABSENT dependency declaration/);
  assert.match(v.reason, /1 share the reason "budget exhausted"/);
});

// R2: cdn_no_integrity/dynamic_require carry a real file:line (an ordinary,
// fixable coverage gap) and must NOT be told they are a "permanent,
// by-design limitation" -- that claim is true only for unpinned_dep/
// no_lockfile, which describe an absent declaration with no commit to point
// to. Conflating the two told a user a fixable gap was unfixable.

test('strict mode: cdn_no_integrity/dynamic_require provenance gaps do NOT get the "permanent limitation" message', () => {
  const cdnFp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
    limitations: ['origin resolution is not yet wired for a cdn_no_integrity supply-chain entry (this describes a real source location, not an absent declaration — resolvable in principle, just not implemented today)'],
  });
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1', findingProvenance: cdnFp }]);
  assert.equal(v.ok, false);
  assert.doesNotMatch(v.reason, /known, permanent limitation/);
  assert.doesNotMatch(v.reason, /ABSENT dependency declaration/);
  // It still gets SOME real, specific text, not a bare count.
  assert.match(v.reason, /resolvable in principle/);
});
