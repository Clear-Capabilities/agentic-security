// why-missed.mjs — unit tests for the pure suppression-classification logic.
//
// The I/O half (re-scanning an entry, running it twice for the guard-window
// diff) is proven by hand against known entries, per this repo's own
// convention for bench/independent/ (see independent-population.test.js's
// header). This file pins the part that can be wrong silently: matching a
// suppressed finding's vuln name back to the advisory's labelled CWE family.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifySuppressions } from '../../bench/independent/why-missed.mjs';

const entry = { cwe: 'CWE-89', files: ['src/db/query.js'] };

test('a suppression on an advisory file, matching CWE family, is flagged ignore-pragma', () => {
  const suppressions = [
    { vuln: 'SQL Injection', file: 'src/db/query.js', line: 12, snippet: '', reason: 'inline pragma: agentic-security-ignore' },
  ];
  const out = classifySuppressions(suppressions, entry, (shape) => shape.cwe ? 'sql-injection' : 'sql-injection');
  assert.equal(out.length, 1);
  assert.equal(out[0].mechanism, 'ignore-pragma');
  assert.equal(out[0].familyMatch, true);
});

test('a suppression on an unrelated file is excluded entirely', () => {
  const suppressions = [
    { vuln: 'SQL Injection', file: 'src/unrelated/other.js', line: 3, snippet: '', reason: 'inline pragma: agentic-security-ignore' },
  ];
  assert.deepEqual(classifySuppressions(suppressions, entry), []);
});

test('mechanism is derived correctly for sanitized, custom-rule, bench-shape, and unknown reasons', () => {
  const base = { file: 'src/db/query.js', line: 1, vuln: 'SQL Injection', snippet: '' };
  const out = classifySuppressions([
    { ...base, reason: 'sanitized:parameterized-query' },
    { ...base, reason: 'custom-rule:team-approved' },
    { ...base, reason: 'bench-category-mismatch:xss!=sql-injection' },
    { ...base, reason: 'context-mismatch:comment' },
  ], entry);
  assert.deepEqual(out.map(o => o.mechanism), ['sanitized', 'custom-rule', 'bench-shape', 'other']);
});

test('familyMatch is false when the suppressed finding is a different vuln class', () => {
  const suppressions = [
    { vuln: 'Cross-Site Scripting', file: 'src/db/query.js', line: 5, snippet: '', reason: 'sanitized:html-escape' },
  ];
  const out = classifySuppressions(suppressions, entry, (shape) => shape.cwe ? 'sql-injection' : 'xss');
  assert.equal(out[0].familyMatch, false);
});

test('familyMatch is null, not true, when both sides are unknown families', () => {
  // Regression: CWE-59 has no _CWE_FAMILY entry, and an unrelated DoS finding's
  // vuln text doesn't match any _KEYWORD_FAMILY pattern either — both infer to
  // null. null === null must not read as a match. Found by hand while sanity-
  // checking against GHSA-22p9-r2f5-22mf (Plan Task 3): every suppression on
  // that CWE-59 entry was an unrelated DoS/rate-limit finding, yet the buggy
  // version reported familyMatch:true for most of them.
  const unknownCweEntry = { cwe: 'CWE-59', files: ['send_base_mode.py'] };
  const suppressions = [
    { vuln: 'Missing Timeout on Outbound HTTP Request (DoS)', file: 'send_base_mode.py', line: 0, snippet: '', reason: 'context-mismatch:cli' },
  ];
  const inferFamilySync = (shape) => (shape.cwe ? null : null); // neither side known
  const out = classifySuppressions(suppressions, unknownCweEntry, inferFamilySync);
  assert.equal(out[0].familyMatch, null);
});

test('familyMatch is null when no inference function is supplied', () => {
  const suppressions = [
    { vuln: 'SQL Injection', file: 'src/db/query.js', line: 5, snippet: '', reason: 'sanitized:x' },
  ];
  const out = classifySuppressions(suppressions, entry);
  assert.equal(out[0].familyMatch, null);
});

test('an entry with no files never matches anything (localiseToAdvisory contract)', () => {
  const suppressions = [
    { vuln: 'SQL Injection', file: 'src/db/query.js', line: 1, snippet: '', reason: 'sanitized:x' },
  ];
  assert.deepEqual(classifySuppressions(suppressions, { cwe: 'CWE-89', files: [] }), []);
});

// FR-905: the aggregate summary this script always printed to stderr is now
// ALSO persisted to a committed file, so accuracy-scorecard.js can publish
// it — this is the real caller-facing behavior the PRD item asks for, so
// prove it through the real script (a subprocess), not by re-testing
// classifySuppressions again. Uses 2 real, already-fetched population
// entries (small, fast) rather than mocking scanDirRaw — a mock could
// silently drift from what whyMissed() actually does.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { entryComplete } from '../../bench/independent/fetch.mjs';

const HERE2 = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE2, '..', '..');
const WHY_MISSED_SCRIPT = path.join(REPO_ROOT, 'bench', 'independent', 'why-missed.mjs');
const SUMMARY_FILE = path.join(REPO_ROOT, 'bench', 'independent', 'why-missed-summary.json');
const MANIFEST_FILE = path.join(REPO_ROOT, 'bench', 'independent', 'manifest.json');

function firstFetchedIds(n) {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_FILE, 'utf8'));
  return manifest.entries.filter(entryComplete).slice(0, n).map((e) => e.id);
}

test('why-missed.mjs (real subprocess, FR-905): persists a schema-tagged summary with scope, not just stderr', { skip: !fs.existsSync(MANIFEST_FILE) }, () => {
  const ids = firstFetchedIds(2);
  if (ids.length < 2) { return; } // no fetched population in this environment — nothing to diagnose
  const before = fs.existsSync(SUMMARY_FILE) ? fs.readFileSync(SUMMARY_FILE, 'utf8') : null;
  try {
    const r = spawnSync(process.execPath, [WHY_MISSED_SCRIPT, ...ids], { encoding: 'utf8', timeout: 60_000 });
    assert.equal(r.status, 0, `expected why-missed.mjs to exit 0: ${r.stderr}`);
    assert.ok(fs.existsSync(SUMMARY_FILE), 'expected why-missed-summary.json to be written');
    const summary = JSON.parse(fs.readFileSync(SUMMARY_FILE, 'utf8'));
    assert.equal(summary.schema, 'agentic-security/why-missed-summary@1');
    assert.ok(summary.measuredAt);
    assert.deepEqual(summary.scope, { mode: 'explicit-ids', requested: 2 });
    assert.equal(summary.total + summary.skipped, 2);
    assert.equal(typeof summary.byBucket, 'object');
    assert.match(r.stderr, /summary persisted to/);
  } finally {
    // Restore whatever was there before — this test must not leave the
    // repo's committed-shaped summary file mutated by a 2-entry smoke run.
    if (before !== null) fs.writeFileSync(SUMMARY_FILE, before);
    else { try { fs.unlinkSync(SUMMARY_FILE); } catch { /* never existed */ } }
  }
});
