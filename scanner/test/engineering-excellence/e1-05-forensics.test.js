// E1-05: miss forensics. Every false negative is named for the earliest stage that lost it, mapped to the PRD's categories, with evidence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CATEGORIES, buildForensics, categoryOf, classifyIndependentMiss, renderMarkdown } from '../../../bench/independent/forensics.mjs';

const ENTRY = { id: 'GHSA-m1', cwe: 'CWE-89', language: 'python', repo: 'org/r' };
const LOC = { file: 'app/db.py', startLine: 20, endLine: 22, family: 'sql-injection' };
const classify = (over = {}) => classifyIndependentMiss({ entry: ENTRY, location: LOC, preFindings: [], diagnostics: { suppressions: [], sources: [], sinks: [], ir: {} }, ...over });

test('every stage and reason lands in exactly one of the ten categories', () => {
  const table = [
    [{ stage: 'scan-execution', reason: 'scan-timeout' }, 'tool_or_setup_incomplete'],
    [{ stage: 'parser-ir', reason: 'ir-parse-failure' }, 'parse_ir_gap'],
    [{ stage: 'parser-ir', reason: 'no-function-lowered' }, 'parse_ir_gap'],
    [{ stage: 'source-modelling', reason: 'no-source-recognized' }, 'missing_source_or_sink'],
    [{ stage: 'sink-modelling', reason: 'no-sink-recognized-near-defect' }, 'missing_source_or_sink'],
    [{ stage: 'sink-modelling', reason: 'no-detector-rule-fired' }, 'no_detector_candidate'],
    [{ stage: 'propagation', reason: 'source-and-sink-recognized-no-flow' }, 'alias_or_callgraph_gap'],
    [{ stage: 'filters', reason: 'sanitized:escapeHtml' }, 'sanitizer_misclassification'],
    [{ stage: 'filters', reason: 'guard-recognized:auth' }, 'guard_or_suppression'],
    [{ stage: 'filters', reason: 'unreachable-code-demoted' }, 'reachability_demotion'],
    [{ stage: 'suppression', reason: 'inline-pragma' }, 'guard_or_suppression'],
    [{ stage: 'suppression', reason: 'reachability-demoted' }, 'reachability_demotion'],
    [{ stage: 'deduplication', reason: 'collapsed-into-winner-at-other-location' }, 'wrong_file_or_cwe'],
    [{ stage: 'attribution', reason: 'right-file-and-family-wrong-line' }, 'wrong_file_or_cwe'],
    [{ stage: 'unknown', reason: 'no-diagnostic-evidence' }, 'unlabelled_ambiguity'],
    [{ stage: 'something-new', reason: 'x' }, 'unlabelled_ambiguity'],
  ];
  for (const [c, want] of table) assert.equal(categoryOf(c), want, JSON.stringify(c));
  assert.equal(CATEGORIES.length, 10);
  assert.equal(new Set(table.map(([, w]) => w)).size, 10 - 0, 'every category is reachable');
});

test('a scan that never completed is a tool or setup limitation, not a detection gap', () => {
  const c = classify({ scanStatus: 'timeout', failureReason: 'no result within 600000 ms', diagnostics: null });
  assert.equal(c.category, 'tool_or_setup_incomplete');
  assert.equal(c.stage, 'scan-execution');
  assert.match(c.evidence.failureReason, /600000/);
});

test('without diagnostics the answer is unlabelled ambiguity, never a plausible-sounding stage', () => {
  const c = classify({ diagnostics: null });
  assert.equal(c.category, 'unlabelled_ambiguity');
  assert.equal(c.reason, 'no-diagnostic-evidence');
});

test('a finding with the right CWE in the right file but far from the defect is a wrong-location report', () => {
  const c = classify({ preFindings: [{ file: 'app/db.py', line: 300, family: 'sql-injection', cwe: 'CWE-89' }] });
  assert.equal(c.category, 'wrong_file_or_cwe');
  assert.equal(c.stage, 'attribution');
  assert.equal(c.evidence.reported.line, 300);
});

test('a candidate dropped by a recorded reason is named by that reason', () => {
  const sup = (reason) => classify({ diagnostics: { suppressions: [{ file: 'app/db.py', line: 21, family: 'sql-injection', cwe: 'CWE-89', reason }], sources: [], sinks: [], ir: {} } });
  assert.equal(sup('sanitized:escape').category, 'sanitizer_misclassification');
  assert.equal(sup('inline-pragma:agentic-security-ignore').category, 'guard_or_suppression');
  assert.equal(sup('guard-recognized:parameterized').category, 'guard_or_suppression');
  const c = sup('sanitized:escape');
  assert.equal(c.evidence.ledger.line, 21);
});

test('a parse failure in the defect file is a parse or IR gap', () => {
  const c = classify({ diagnostics: { suppressions: [], sources: [], sinks: [], ir: { parseFailures: { byLanguage: { py: 2 }, first: 'x' }, files: {} } } });
  assert.equal(c.category, 'parse_ir_gap');
});

test('no recognised source, then no sink, then no joining flow: three different categories', () => {
  const diag = (sources, sinks) => ({ suppressions: [], sources, sinks, ir: {} });
  assert.equal(classify({ diagnostics: diag([], []) }).category, 'missing_source_or_sink');
  assert.equal(classify({ diagnostics: diag([{ file: 'app/db.py', line: 5 }], []) }).reason, 'no-sink-recognized-near-defect');
  const flow = classify({ diagnostics: diag([{ file: 'app/db.py', line: 5 }], [{ file: 'app/db.py', line: 21 }]) });
  assert.equal(flow.category, 'alias_or_callgraph_gap');
  assert.equal(flow.evidence.sourcesInFile, 1);
});

test('a pattern-only family with no rule that fired is "no detector candidate"', () => {
  const c = classifyIndependentMiss({ entry: { ...ENTRY, cwe: 'CWE-327' }, location: { ...LOC, family: 'weak-crypto' }, preFindings: [], diagnostics: { suppressions: [], sources: [], sinks: [], ir: {} } });
  assert.equal(c.category, 'no_detector_candidate');
});

// ---- totals ---------------------------------------------------------------------------------------------------------------------

const row = (id, local, extra = {}) => ({ id, tpLocal: local ? 1 : 0, fnLocal: local ? 0 : 1, ...extra });
const cls = (entryId, category, stage = 'propagation', reason = 'r', extra = {}) => ({ entryId, language: 'python', cwe: 'CWE-89', stage, reason, category, evidence: {}, ...extra });

test('the totals reconcile: scored = localized true positives + localized false negatives, each miss classified once', () => {
  const rows = [row('a', true), row('b', false), row('c', false), row('d', false)];
  const f = buildForensics({ rows, classified: [cls('b', 'alias_or_callgraph_gap'), cls('c', 'alias_or_callgraph_gap'), cls('d', 'parse_ir_gap', 'parser-ir', 'ir-parse-failure')], runId: 'run1' });
  assert.equal(f.reconciliation.reconciles, true);
  assert.deepEqual([f.reconciliation.scored, f.reconciliation.localizedTruePositives, f.reconciliation.localizedFalseNegatives, f.reconciliation.classified], [4, 1, 3, 3]);
  assert.equal(f.byCategory.alias_or_callgraph_gap, 2);
  assert.equal(f.byCategory.parse_ir_gap, 1);
  assert.equal(Object.values(f.byCategory).reduce((s, n) => s + n, 0), 3);
});

test('an unclassified miss, a classification of a hit and a duplicate each stop the totals reconciling', () => {
  const rows = [row('a', true), row('b', false), row('c', false)];
  const f1 = buildForensics({ rows, classified: [cls('b', 'parse_ir_gap')] });
  assert.equal(f1.reconciliation.reconciles, false);
  assert.deepEqual(f1.reconciliation.unclassified, ['c']);
  const f2 = buildForensics({ rows, classified: [cls('b', 'parse_ir_gap'), cls('c', 'parse_ir_gap'), cls('a', 'parse_ir_gap')] });
  assert.deepEqual(f2.reconciliation.classifiedButNotAMiss, ['a']);
  const f3 = buildForensics({ rows, classified: [cls('b', 'parse_ir_gap'), cls('c', 'parse_ir_gap'), cls('c', 'parse_ir_gap')] });
  assert.deepEqual(f3.reconciliation.duplicateClassifications, ['c']);
  assert.equal(f3.reconciliation.reconciles, false);
});

test('clusters are ranked by size with deterministic sample ids, and shares add up', () => {
  const ids = Array.from({ length: 12 }, (_, i) => `e${String(i).padStart(2, '0')}`);
  const rows = ids.map((id) => row(id, false));
  const classified = ids.map((id, i) => (i < 8 ? cls(id, 'alias_or_callgraph_gap', 'propagation', 'no-flow', { language: i % 2 ? 'go' : 'python' }) : cls(id, 'wrong_file_or_cwe', 'attribution', 'wrong-line')));
  const f = buildForensics({ rows, classified: [...classified].reverse() });
  assert.equal(f.clusters[0].category, 'alias_or_callgraph_gap');
  assert.equal(f.clusters[0].count, 8);
  assert.deepEqual(f.clusters[0].sampleIds, ['e00', 'e01', 'e02', 'e03', 'e04'], 'sorted, capped at five, independent of input order');
  assert.ok(Math.abs(f.clusters.reduce((s, c) => s + c.share, 0) - 1) < 1e-12);
  assert.deepEqual(f.clusters[0].languages, { python: 4, go: 4 });
  const again = buildForensics({ rows, classified });
  assert.deepEqual(again.clusters, f.clusters, 'order of arrival does not change the report');
});

test('entries that were never scored are reported by cause and are not misses', () => {
  const f = buildForensics({ rows: [row('a', true)], classified: [], unscored: [{ id: 'x', class: 'acquisition' }, { id: 'y', class: 'acquisition' }, { id: 'z', class: 'timeout' }] });
  assert.equal(f.reconciliation.reconciles, true);
  assert.deepEqual(f.unscored.byClass, { acquisition: 2, timeout: 1 });
  assert.equal(f.reconciliation.localizedFalseNegatives, 0);
});

test('the markdown names the run, the category table, the ranked clusters and how to reproduce', () => {
  const rows = [row('a', false)];
  const md = renderMarkdown(buildForensics({ rows, classified: [cls('a', 'parse_ir_gap', 'parser-ir', 'ir-parse-failure')], runId: 'R9', command: 'node bench/independent/forensics.mjs --run R9' }));
  assert.match(md, /Run `R9`/);
  assert.match(md, /\| parse_ir_gap \| 1 \|/);
  assert.match(md, /Ranked clusters/);
  assert.match(md, /Reproduce: `node bench\/independent\/forensics\.mjs --run R9`/);
});
