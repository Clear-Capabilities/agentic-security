// Scan health tests (assurance-hardening PRD, Milestone 0, FR-206).
//
// Covers the pure computeScanHealth() function directly, plus the two S7-style
// passthrough directions in report/index.js's toJSON: carried through when the
// engine computed one, defaulted to null when it did not (see
// test/annotator-errors.test.js for the established pattern this mirrors).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeScanHealth, applyFreshness, SCAN_HEALTH_SCHEMA_VERSION } from '../src/pipeline/scan-health.js';
import { toJSON } from '../src/report/index.js';
import { runScan } from '../src/runScan.js';
import * as path from 'node:path';

test('computeScanHealth: clean scan with no signals reports complete', () => {
  const h = computeScanHealth({
    scanMeta: { filesScanned: 10, filesSkipped: 0, filesDenseSkipped: 0, filesTimedOut: 0, checkpoint: { total: 10 } },
    annotatorErrors: [],
    engineErrors: { cppDataflowParseErrors: 0 },
    deepStatus: { requested: true, enabled: true, inCi: false, ciOverrideAllowed: false, reason: null, failure: null },
  });
  assert.equal(h.schemaVersion, SCAN_HEALTH_SCHEMA_VERSION);
  assert.equal(h.status, 'complete');
  assert.deepEqual(h.conditions, []);
  assert.equal(h.files.scanned, 10);
  assert.equal(h.files.timedOut, 0);
  assert.equal(h.deepAnalysis.enabled, true);
  assert.equal(h.annotatorErrorCount, 0);
});

test('computeScanHealth: annotator error demotes status to partial with a named condition', () => {
  const h = computeScanHealth({
    scanMeta: { filesScanned: 5, filesTimedOut: 0 },
    annotatorErrors: [{ phase: 'annotateConfidence', err: 'boom' }],
  });
  assert.equal(h.status, 'partial');
  assert.equal(h.annotatorErrorCount, 1);
  assert.ok(h.conditions.some(c => c.includes('annotateConfidence')), `expected a condition naming the phase, got: ${JSON.stringify(h.conditions)}`);
});

test('computeScanHealth: timed-out files demote status to partial', () => {
  const h = computeScanHealth({ scanMeta: { filesScanned: 5, filesTimedOut: 2 } });
  assert.equal(h.status, 'partial');
  assert.equal(h.files.timedOut, 2);
  assert.ok(h.conditions.some(c => c.includes('per-file analysis timeout')));
});

test('computeScanHealth: deep analysis requested but not enabled is a partial condition', () => {
  const h = computeScanHealth({
    scanMeta: { filesScanned: 5, filesTimedOut: 0 },
    deepStatus: { requested: true, enabled: false, inCi: true, ciOverrideAllowed: false, reason: 'requested, but running in CI without AGENTIC_SECURITY_DEEP_IN_CI=1', failure: null },
  });
  assert.equal(h.status, 'partial');
  assert.equal(h.deepAnalysis.requested, true);
  assert.equal(h.deepAnalysis.enabled, false);
  assert.ok(h.conditions.some(c => c.includes('deep analysis was requested but did not run')));
});

test('computeScanHealth: deep analysis never requested is not itself a partial condition', () => {
  const h = computeScanHealth({
    scanMeta: { filesScanned: 5, filesTimedOut: 0 },
    deepStatus: { requested: false, enabled: false, inCi: true, ciOverrideAllowed: false, reason: 'not requested (deep analysis defaults to off in CI)', failure: null },
  });
  assert.equal(h.status, 'complete');
  assert.equal(h.deepAnalysis.requested, false);
});

test('computeScanHealth: deep-mode failure is reported without being fabricated as a clean skip', () => {
  const h = computeScanHealth({
    scanMeta: { filesScanned: 5, filesTimedOut: 0 },
    deepStatus: { requested: true, enabled: true, inCi: false, ciOverrideAllowed: false, reason: null, failure: 'parser blew up on foo.ts' },
  });
  assert.equal(h.status, 'partial');
  assert.equal(h.deepAnalysis.failure, 'parser blew up on foo.ts');
  assert.ok(h.conditions.some(c => c.includes('fell back to pattern-only results')));
});

test('computeScanHealth: analyzers field is honestly null, not fabricated per-analyzer counts, when the caller does not supply a real coverage summary', () => {
  const h = computeScanHealth({});
  assert.equal(h.analyzers, null);
});

// FR-203: once coverage-ledger.js exists, computeScanHealth can compute
// `analyzers` for real instead of hardcoding null — these tests prove the
// wiring, not the ledger's own logic (covered in coverage-ledger.test.js).
test('computeScanHealth (FR-203): a real analyzerCoverage summary is reflected verbatim in the analyzers field', () => {
  const coverage = { expected: 121, completed: 121, failed: 0, timedOut: 0, skippedByPolicy: 0 };
  const h = computeScanHealth({ analyzerCoverage: coverage });
  assert.deepEqual(h.analyzers, coverage);
  assert.equal(h.status, 'complete');
});

test('computeScanHealth (FR-203): an analyzer that failed on at least one file demotes status to partial, distinct from an annotator error', () => {
  const coverage = { expected: 121, completed: 120, failed: 1, timedOut: 0, skippedByPolicy: 0 };
  const h = computeScanHealth({ analyzerCoverage: coverage });
  assert.equal(h.status, 'partial');
  assert.ok(h.conditions.some(c => /1 analyzer\(s\) threw/.test(c)));
});

test('computeScanHealth (FR-203): zero failed/timedOut analyzers does not itself demote status, even with a nonzero skippedByPolicy (policy skips are intentional, not a health problem)', () => {
  const coverage = { expected: 121, completed: 112, failed: 0, timedOut: 0, skippedByPolicy: 9 };
  const h = computeScanHealth({ analyzerCoverage: coverage });
  assert.equal(h.status, 'complete');
});

test('toJSON carries scan.scanHealth through when the engine computed one', () => {
  const fakeScan = {
    findings: [], routes: [], components: [], suppressions: [],
    scanHealth: { schemaVersion: 1, status: 'complete', files: {}, analyzers: null, deepAnalysis: null, annotatorErrorCount: 0, conditions: [] },
  };
  const out = toJSON(fakeScan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.deepEqual(out.scanHealth, fakeScan.scanHealth);
});

test('toJSON defaults scanHealth to null when the engine did not compute one', () => {
  const out = toJSON({ findings: [], routes: [], components: [], suppressions: [] },
    { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.equal(out.scanHealth, null);
});

test('a real clean scan reports scanHealth.status === "complete"', async () => {
  // FR-207: this assertion is about the SAST/detector dimension of "clean",
  // not the (now real) feed-freshness dimension -- a developer machine or CI
  // runner with a genuinely aged local KEV/EPSS disk cache would otherwise
  // make this test's outcome depend on how long it's been since something
  // else on the same machine last scanned, rather than on this codebase.
  // AGENTIC_SECURITY_OFFLINE=1 keeps kevCatalogMeta()/epssLiveMeta() at
  // their inert not-loaded state (stale:null, never true) so the assertion
  // stays deterministic.
  const prevOffline = process.env.AGENTIC_SECURITY_OFFLINE;
  process.env.AGENTIC_SECURITY_OFFLINE = '1';
  let out;
  try {
    const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
    const { scan, meta } = await runScan(root, { network: false });
    out = toJSON(scan, meta);
  } finally {
    if (prevOffline === undefined) delete process.env.AGENTIC_SECURITY_OFFLINE; else process.env.AGENTIC_SECURITY_OFFLINE = prevOffline;
  }
  assert.ok(out.scanHealth, 'expected scanHealth to be present on a real scan');
  assert.equal(out.scanHealth.schemaVersion, SCAN_HEALTH_SCHEMA_VERSION);
  assert.equal(out.scanHealth.status, 'complete', `expected complete, got conditions: ${JSON.stringify(out.scanHealth.conditions)}`);
  assert.equal(out.scanHealth.deepAnalysis.requested, false, 'deep mode should not be requested by default in an in-process test call');
});

// FR-203, real end-to-end: a genuine scan through the actual engine (not a
// hand-built fixture) must produce a real, non-null analyzers summary and a
// real per-file coverage ledger — proving the wiring reaches all the way
// from engine.js's real per-file loop, not just the pure function tested
// above.
test('a real scan produces a genuine, non-fabricated scanHealth.analyzers summary and scan.coverageLedger (FR-203 end-to-end)', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false });
  assert.ok(scan.scanHealth.analyzers, 'a real scan must compute a real analyzers summary, not null');
  assert.ok(scan.scanHealth.analyzers.expected > 100, `expected 100+ analyzers to have run, got ${scan.scanHealth.analyzers.expected}`);
  assert.equal(scan.scanHealth.analyzers.failed, 0, 'a genuinely clean fixture scan should have zero failed analyzers');

  assert.ok(scan.coverageLedger, 'expected the full per-file ledger on the scan result');
  const files = Object.keys(scan.coverageLedger.byFile);
  assert.ok(files.length > 0);
  for (const file of files) {
    const row = scan.coverageLedger.byFile[file];
    // Every analyzer entry in a clean scan's row must be a real, single
    // terminal status string — never undefined, never an array, never both
    // "completed" and "failed" for the same (file, analyzer) pair.
    for (const status of Object.values(row)) {
      assert.equal(typeof status, 'string');
      assert.ok(['completed', 'failed', 'timed_out', 'skipped_by_policy'].includes(status));
    }
  }
});

// FR-207: applyFreshness — stale vulnerability feeds/calibration/rulesets/
// policies must become a real scanHealth condition, not a silently-ignored
// extra field, so --assurance strict (FR-204) can actually fail on them.

test('applyFreshness (FR-207): a fresh scan with no stale legs stays complete and unconditioned', () => {
  const base = computeScanHealth({ scanMeta: { filesScanned: 5 }, annotatorErrors: [] });
  const out = applyFreshness(base, {
    kev: { stale: false, ageDays: 1 },
    epss: { stale: false, ageDays: 1 },
    calibration: { stale: false, ageDays: 10 },
    compliance: { stale: 0 },
  });
  assert.equal(out.status, 'complete');
  assert.deepEqual(out.conditions, []);
  assert.equal(out.freshness.kev.stale, false);
});

test('applyFreshness (FR-207): a stale KEV catalog downgrades a complete scan to partial with a real condition', () => {
  const base = computeScanHealth({ scanMeta: { filesScanned: 5 }, annotatorErrors: [] });
  assert.equal(base.status, 'complete');
  const out = applyFreshness(base, { kev: { stale: true, ageDays: 42 } });
  assert.equal(out.status, 'partial');
  assert.ok(out.conditions.some(c => /KEV catalog is stale/.test(c) && /42/.test(c)), `expected a KEV staleness condition, got ${JSON.stringify(out.conditions)}`);
});

test('applyFreshness (FR-207): each of the five freshness legs produces its own distinct condition', () => {
  const base = computeScanHealth({ scanMeta: { filesScanned: 5 }, annotatorErrors: [] });
  const out = applyFreshness(base, {
    kev: { stale: true, ageDays: 10 },
    epss: { stale: true, ageDays: 11 },
    calibration: { stale: true, ageDays: 200, generatedAt: '2026-01-01T00:00:00Z' },
    customRules: { stale: true, staleFiles: [{ file: 'a.yml' }, { file: 'b.yml' }] },
    compliance: { stale: 3 },
  });
  assert.equal(out.status, 'partial');
  assert.equal(out.conditions.length, 5, `expected exactly 5 conditions, got ${JSON.stringify(out.conditions)}`);
  assert.ok(out.conditions.some(c => /KEV/.test(c)));
  assert.ok(out.conditions.some(c => /EPSS/.test(c)));
  assert.ok(out.conditions.some(c => /calibration data is stale/.test(c) && /2026-01-01/.test(c)));
  assert.ok(out.conditions.some(c => /2 custom rule file/.test(c)));
  assert.ok(out.conditions.some(c => /3 compliance control/.test(c)));
});

test('applyFreshness (FR-207): an already-partial scan stays partial, never regresses to a worse or better status label', () => {
  const base = computeScanHealth({ scanMeta: { filesScanned: 5 }, annotatorErrors: [{ phase: 'x', err: 'boom' }] });
  assert.equal(base.status, 'partial');
  const out = applyFreshness(base, { kev: { stale: true, ageDays: 8 } });
  assert.equal(out.status, 'partial');
  assert.equal(out.conditions.length, 2, 'the pre-existing condition must survive alongside the new freshness condition');
});

test('applyFreshness (FR-207): merges incrementally — a second call (the bin/agentic-security.js custom-rules patch pattern) adds to, not replaces, the first call\'s freshness object', () => {
  const base = computeScanHealth({ scanMeta: { filesScanned: 5 }, annotatorErrors: [] });
  const afterEngine = applyFreshness(base, { kev: { stale: false, ageDays: 1 }, epss: { stale: false, ageDays: 1 } });
  const afterBin = applyFreshness(afterEngine, { customRules: { stale: true, staleFiles: [{ file: 'x.yml' }] } });
  assert.equal(afterBin.freshness.kev.stale, false, 'the engine-computed kev leg must survive the later bin.js patch');
  assert.equal(afterBin.freshness.customRules.stale, true);
  assert.equal(afterBin.status, 'partial');
  assert.equal(afterBin.conditions.length, 1);
});

test('applyFreshness (FR-207): a null/missing freshness partial is a true no-op', () => {
  const base = computeScanHealth({ scanMeta: { filesScanned: 5 }, annotatorErrors: [] });
  assert.deepEqual(applyFreshness(base, null), base);
  assert.deepEqual(applyFreshness(null, { kev: { stale: true } }), null);
});

// FR-207 real end-to-end: a genuine scan through the actual engine must
// compute real kev/epss/calibration freshness legs on scan.scanHealth.freshness
// -- not just the pure applyFreshness() unit proven above.
test('a real scan produces genuine kev/calibration freshness legs on scan.scanHealth.freshness (FR-207 end-to-end)', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false });
  assert.ok(scan.scanHealth.freshness, 'expected a real freshness object, not null');
  assert.ok(scan.scanHealth.freshness.kev, 'kev catalog freshness must be computed for every scan');
  assert.equal(typeof scan.scanHealth.freshness.kev.stale, 'boolean');
  assert.ok(scan.scanHealth.freshness.calibration, 'calibration freshness must be computed for every scan');
  assert.equal(typeof scan.scanHealth.freshness.calibration.stale, 'boolean');
});
