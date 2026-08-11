// Unit tests for the sanitizer gate's family matching.
//
// The gate is pure — findings in, labels out — so the family lattice is
// testable directly, without driving a scan. The flow-level integration is
// covered by sanitizer-typed-flow.test.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applySanitizerGate, familyOfFinding } from '../src/dataflow/sanitizer-gate.js';

const finding = (over = {}) => ({ id: 'f1', cwe: 'CWE-89', vuln: 'SQL Injection', ...over });

test('a universal (*) sanitizer covers every family', () => {
  // 17 catalog entries are tagged appliesTo:['*'] — type coercions such as
  // parseInt/intval/Atoi that neutralise every injection family by making the
  // value non-stringy. Matching them literally against the finding's family
  // ('sql') never succeeds, so before this the whole wildcard tier was inert.
  const f = finding();
  applySanitizerGate([f], { sanitizersOnPath: { f1: ['parseInt'] } });
  assert.equal(f.sanitized, true, 'parseInt (appliesTo *) must cover the sql family');
  assert.equal(f.sanitizerProof.family, 'sql');
});

test('a wrong-family sanitizer is not upgraded by the wildcard change', () => {
  // Guard on the change above: broadening '*' must not broaden anything else.
  const f = finding();
  applySanitizerGate([f], { sanitizersOnPath: { f1: ['escapeHtml'] } });
  assert.notEqual(f.sanitized, true, 'escapeHtml is xss-only and must not clear a SQL finding');
});

test('a matching named family still labels', () => {
  const f = finding({ cwe: 'CWE-79', vuln: 'DOM XSS' });
  applySanitizerGate([f], { sanitizersOnPath: { f1: ['escapeHtml'] } });
  assert.equal(f.sanitized, true);
  assert.equal(f.sanitizerProof.family, 'xss');
});

test('no sanitizersOnPath leaves the gate a no-op', () => {
  const f = finding();
  applySanitizerGate([f], {});
  assert.equal(f.sanitized, undefined);
});

test('familyOfFinding prefers the CWE over the human-authored vuln text', () => {
  assert.equal(familyOfFinding({ cwe: 'CWE-89', vuln: 'looks like xss' }), 'sql');
});
