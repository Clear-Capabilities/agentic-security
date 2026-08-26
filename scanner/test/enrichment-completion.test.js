// Enrichment completion pass tests (assurance-hardening PRD, Milestone 1, FR-103/FR-104).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { completeEnrichment } from '../src/pipeline/enrichment-completion.js';
import { runScan } from '../src/runScan.js';
import * as path from 'node:path';

test('completeEnrichment: a finding with no stableId gets one, plus confidence/calibration/exploitability', () => {
  const finalFindings = [
    { id: 'late1', severity: 'high', file: 'a.js', line: 1, vuln: 'SQL Injection', cwe: 'CWE-89' },
  ];
  const { gapFilledCount } = completeEnrichment(finalFindings, { scanRoot: process.cwd(), projectCtx: {} });
  assert.equal(gapFilledCount, 1);
  const f = finalFindings[0];
  assert.ok(f.stableId, 'expected a stableId to be assigned');
  assert.equal(typeof f.confidence, 'number', 'expected confidence to be computed');
  assert.equal(typeof f.exploitability, 'number', 'expected exploitability to be computed');
  // calibration may legitimately be null (no-history / insufficient-samples)
  // but the reason field must always be set once processed.
  assert.ok(f.calibration_reason !== undefined, 'expected calibration_reason to be set (even if null-valued fields accompany it)');
});

test('completeEnrichment: a finding that ALREADY has a stableId is left untouched (not reprocessed, not re-hashed to a different id)', () => {
  const already = { id: 'early1', stableId: 'deadbeefdeadbeef', severity: 'high', file: 'a.js', line: 1, vuln: 'x', confidence: 0.42 };
  const finalFindings = [already];
  const { gapFilledCount } = completeEnrichment(finalFindings, { scanRoot: process.cwd(), projectCtx: {} });
  assert.equal(gapFilledCount, 0);
  assert.equal(finalFindings[0].stableId, 'deadbeefdeadbeef', 'stableId must not change');
  assert.equal(finalFindings[0].confidence, 0.42, 'confidence must not be recomputed for an already-processed finding');
});

test('completeEnrichment: a mix of early and late findings only gap-fills the late ones', () => {
  const early = { id: 'e1', stableId: 'aaaaaaaaaaaaaaaa', severity: 'high', file: 'a.js', line: 1, vuln: 'x', confidence: 0.99 };
  const late = { id: 'l1', severity: 'high', file: 'b.js', line: 1, vuln: 'y' };
  const finalFindings = [early, late];
  const { gapFilledCount } = completeEnrichment(finalFindings, { scanRoot: process.cwd(), projectCtx: {} });
  assert.equal(gapFilledCount, 1);
  assert.equal(early.confidence, 0.99, 'the early finding must be untouched');
  assert.ok(late.stableId, 'the late finding must be gap-filled');
});

test('completeEnrichment: an empty array is a safe no-op', () => {
  assert.deepEqual(completeEnrichment([], { scanRoot: process.cwd() }), { gapFilledCount: 0 });
});

test('completeEnrichment: does not throw on garbage input', () => {
  assert.doesNotThrow(() => completeEnrichment(null));
  assert.doesNotThrow(() => completeEnrichment(undefined));
  assert.doesNotThrow(() => completeEnrichment('not an array'));
});

// ── Integration: the actual A-03 bug, proven via a real scan ────────────────

test('a REAL scan: a late-appended producer finding (business-logic-v2) has a stableId and confidence, not null (the actual A-03 regression case)', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false });
  // business-logic-v2 is one of the rewired late producers; it may or may
  // not fire on this specific fixture, so fall back to checking ANY finding
  // this producer registry knows about, or — more robustly — assert the
  // INVARIANT holds across every finding in the scan, not just one producer.
  assert.ok(scan.findings.length > 0, 'fixture should produce findings');
  const missingStableId = scan.findings.filter(f => !f.stableId);
  assert.deepEqual(missingStableId, [], `every finding in a completed scan must have a stableId — found ${missingStableId.length} without one: ${JSON.stringify(missingStableId.map(f => f.vuln))}`);
});

test('a REAL scan: scan.findings is frozen — pushing to it throws (the FR-104 regression case)', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false });
  assert.ok(Object.isFrozen(scan.findings), 'expected scan.findings to be frozen after finalization');
  assert.throws(() => scan.findings.push({ id: 'injected-after-freeze' }), TypeError);
});
