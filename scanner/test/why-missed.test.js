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
