// FR-203: "Produce per-file and per-analyzer coverage ledgers | Every
// in-scope file has exactly one terminal coverage status for every
// applicable required analyzer."
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeCoverageLedger, summarizeCoverageForScanHealth, isAnalyzerApplicable,
  ANALYZER_NAMES, EXTENSION_GATED_ANALYZERS, POLICY_GATED_ANALYZERS, POLICY_GATED_OUTER_FLAG,
} from '../src/pipeline/coverage-ledger.js';

test('isAnalyzerApplicable: an always-applicable analyzer applies to any file', () => {
  assert.equal(isAnalyzerApplicable('scanSecretConcat', 'app.js'), true);
  assert.equal(isAnalyzerApplicable('scanSecretConcat', 'app.py'), true);
});

test('isAnalyzerApplicable: an extension-gated analyzer only applies to matching files', () => {
  assert.equal(isAnalyzerApplicable('scanRegexReDoS', 'App.java'), true);
  assert.equal(isAnalyzerApplicable('scanRegexReDoS', 'app.js'), false);
  assert.equal(isAnalyzerApplicable('scanGraphQL', 'schema.graphql'), true);
  assert.equal(isAnalyzerApplicable('scanGraphQL', 'app.js'), false);
});

test('isAnalyzerApplicable: a policy-gated analyzer is still "applicable" everywhere — policy affects STATUS, not scope', () => {
  assert.equal(isAnalyzerApplicable('scanWeb3Advanced', 'app.js'), true);
});

test('computeCoverageLedger: a genuinely clean file gets "completed" for every applicable analyzer, and every analyzer gets exactly one status', () => {
  const files = ['app.js'];
  const ledger = computeCoverageLedger({ files, detectorErrors: [], timedOutFiles: [], env: {} });
  const row = ledger.byFile['app.js'];
  // Every ALWAYS-applicable analyzer must have exactly one status.
  for (const name of ANALYZER_NAMES) {
    if (EXTENSION_GATED_ANALYZERS[name]) { assert.ok(!(name in row), `${name} is extension-gated and app.js doesn't match — must be excluded, not defaulted`); continue; }
    assert.equal(typeof row[name], 'string', `${name} must have exactly one terminal status`);
  }
  assert.equal(row.scanSecretConcat, 'completed');
});

test('computeCoverageLedger: an extension-gated analyzer is excluded from a non-matching file\'s row entirely (not "skipped", not "not-applicable" — absent)', () => {
  const ledger = computeCoverageLedger({ files: ['app.js'], detectorErrors: [], timedOutFiles: [] });
  assert.ok(!('scanRegexReDoS' in ledger.byFile['app.js']));
  assert.ok(!('scanGraphQL' in ledger.byFile['app.js']));
  assert.equal(ledger.byAnalyzer.scanRegexReDoS.filesExpected, 0, 'no .java/.py/etc file was scanned, so this analyzer had zero expected files');
});

test('computeCoverageLedger: an extension-gated analyzer IS included, and completed, for a matching file', () => {
  const ledger = computeCoverageLedger({ files: ['App.java'], detectorErrors: [], timedOutFiles: [] });
  assert.equal(ledger.byFile['App.java'].scanRegexReDoS, 'completed');
  assert.equal(ledger.byAnalyzer.scanRegexReDoS.filesExpected, 1);
  assert.equal(ledger.byAnalyzer.scanRegexReDoS.filesCompleted, 1);
});

test('computeCoverageLedger: a captured detectorError becomes "failed" for exactly that (file, analyzer) pair, not others', () => {
  const files = ['app.js', 'other.js'];
  const detectorErrors = [{ file: 'app.js', analyzer: 'scanSecretConcat', err: 'boom' }];
  const ledger = computeCoverageLedger({ files, detectorErrors, timedOutFiles: [] });
  assert.equal(ledger.byFile['app.js'].scanSecretConcat, 'failed');
  assert.equal(ledger.byFile['other.js'].scanSecretConcat, 'completed', 'a failure on one file must not contaminate another file\'s status for the same analyzer');
  assert.equal(ledger.byFile['app.js'].scanRoutes, 'completed', 'a failure in one analyzer must not contaminate another analyzer on the SAME file');
  assert.equal(ledger.byAnalyzer.scanSecretConcat.filesFailed, 1);
  assert.equal(ledger.byAnalyzer.scanSecretConcat.filesCompleted, 1);
});

test('computeCoverageLedger: a timed-out file marks EVERY applicable analyzer as timed_out, not just one — a preemptive kill has no per-analyzer partial credit', () => {
  const ledger = computeCoverageLedger({ files: ['huge.js'], detectorErrors: [], timedOutFiles: ['huge.js'] });
  const row = ledger.byFile['huge.js'];
  const statuses = new Set(Object.values(row));
  assert.deepEqual([...statuses], ['timed_out'], `expected every applicable analyzer to be timed_out, got a mix: ${[...statuses]}`);
});

test('computeCoverageLedger: timed_out takes priority over a captured error for the same (file, analyzer) — the kill is the more severe, more recent truth', () => {
  const ledger = computeCoverageLedger({
    files: ['huge.js'],
    detectorErrors: [{ file: 'huge.js', analyzer: 'scanSecretConcat', err: 'boom' }],
    timedOutFiles: ['huge.js'],
  });
  assert.equal(ledger.byFile['huge.js'].scanSecretConcat, 'timed_out');
});

test('computeCoverageLedger: a policy-gated analyzer is "skipped_by_policy" for every file when its individual env flag is set', () => {
  const ledger = computeCoverageLedger({ files: ['app.js'], env: { AGENTIC_SECURITY_NO_WEB3_ADV: '1' } });
  assert.equal(ledger.byFile['app.js'].scanWeb3Advanced, 'skipped_by_policy');
  assert.equal(ledger.byAnalyzer.scanWeb3Advanced.filesSkippedByPolicy, 1);
  assert.equal(ledger.byAnalyzer.scanWeb3Advanced.filesCompleted, 0);
});

test('computeCoverageLedger: the shared outer AGENTIC_SECURITY_NO_INTEGRATION flag disables ALL 9 policy-gated analyzers at once', () => {
  const ledger = computeCoverageLedger({ files: ['app.js'], env: { [POLICY_GATED_OUTER_FLAG]: '1' } });
  for (const name of Object.keys(POLICY_GATED_ANALYZERS)) {
    assert.equal(ledger.byFile['app.js'][name], 'skipped_by_policy', `${name} should be skipped_by_policy under the outer flag`);
  }
  assert.equal(ledger.byFile['app.js'].scanSecretConcat, 'completed', 'the outer flag must not affect always-applicable analyzers');
});

test('computeCoverageLedger: with no env vars set, every policy-gated analyzer completes normally (opt-out, not opt-in)', () => {
  const ledger = computeCoverageLedger({ files: ['app.js'], env: {} });
  for (const name of Object.keys(POLICY_GATED_ANALYZERS)) {
    assert.equal(ledger.byFile['app.js'][name], 'completed');
  }
});

test('computeCoverageLedger: a file never in `files` (e.g. skipped for size) gets no ledger row at all — no fabricated coverage claim', () => {
  const ledger = computeCoverageLedger({ files: ['app.js'] });
  assert.ok(!('huge-skipped.js' in ledger.byFile));
});

test('summarizeCoverageForScanHealth: a fully clean multi-file scan reports every EXPECTED analyzer as completed', () => {
  const ledger = computeCoverageLedger({ files: ['a.js', 'b.js'], detectorErrors: [], timedOutFiles: [] });
  const summary = summarizeCoverageForScanHealth(ledger);
  assert.equal(summary.failed, 0);
  assert.equal(summary.timedOut, 0);
  assert.equal(summary.skippedByPolicy, 0);
  assert.ok(summary.completed > 0);
  assert.equal(summary.expected, summary.completed, 'every analyzer that ran anywhere in this scan completed cleanly everywhere');
});

test('summarizeCoverageForScanHealth: an analyzer that failed on even one file out of many is counted under failed, not completed', () => {
  const ledger = computeCoverageLedger({
    files: ['a.js', 'b.js', 'c.js'],
    detectorErrors: [{ file: 'b.js', analyzer: 'scanSecretConcat', err: 'boom' }],
  });
  const summary = summarizeCoverageForScanHealth(ledger);
  assert.ok(summary.failed >= 1);
});

test('summarizeCoverageForScanHealth: an analyzer with zero expected files (e.g. no matching-extension file scanned) is excluded from the summary entirely', () => {
  const ledger = computeCoverageLedger({ files: ['app.js'] }); // no .java/.graphql file at all
  const summary = summarizeCoverageForScanHealth(ledger);
  assert.equal(summary.expected, ANALYZER_NAMES.length - Object.keys(EXTENSION_GATED_ANALYZERS).length,
    'the 2 extension-gated analyzers had zero matching files, so they must not inflate `expected`');
});
