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

// Stage 3 correctness audit (detection depth): CWE-22/918/601 all collapsed
// to the catalog's 'url' family. Two real consequences: (a) CWE-22's real
// containment sanitizers (py-pathlib-resolve/cs-path-getfullpath/
// kt-path-canonical, all appliesTo:['path']) could never match a CWE-22
// finding at all, since the finding was mapped to 'url' not 'path' — the
// gate was permanently inert for path traversal; (b) a url-family
// URL-percent-encoder (encodeURIComponent etc.) satisfied the family check
// for CWE-918 (SSRF) and CWE-601 (open redirect) findings, even though
// percent-encoding a hostname does nothing to stop either — both are
// host/scheme allow-list problems, not encoding problems. A live-exploitable
// SSRF (encodeURIComponent(req.query.host) used directly as a fetch target)
// would have been marked "proven clean" by this gate.
test('a url-family encoder does NOT clear an SSRF (CWE-918) finding', () => {
  const f = finding({ cwe: 'CWE-918', vuln: 'Server-Side Request Forgery' });
  applySanitizerGate([f], { sanitizersOnPath: { f1: ['encodeURIComponent'] } });
  assert.notEqual(f.sanitized, true,
    'URL-percent-encoding a hostname does not neutralize SSRF — this must not be marked sanitized');
});

test('a url-family encoder does NOT clear an open-redirect (CWE-601) finding', () => {
  const f = finding({ cwe: 'CWE-601', vuln: 'Open Redirect' });
  applySanitizerGate([f], { sanitizersOnPath: { f1: ['encodeURIComponent'] } });
  assert.notEqual(f.sanitized, true);
});

test('a real path-containment sanitizer DOES clear a CWE-22 (path traversal) finding', () => {
  const f = finding({ cwe: 'CWE-22', vuln: 'Path Traversal' });
  applySanitizerGate([f], { sanitizersOnPath: { f1: ['resolve'] } }); // py-pathlib-resolve, appliesTo:['path']
  assert.equal(f.sanitized, true, 'a real path-family sanitizer must clear a CWE-22 finding');
  assert.equal(f.sanitizerProof.family, 'path');
});

test('a url-family encoder does NOT clear a CWE-22 (path traversal) finding', () => {
  const f = finding({ cwe: 'CWE-22', vuln: 'Path Traversal' });
  applySanitizerGate([f], { sanitizersOnPath: { f1: ['encodeURIComponent'] } });
  assert.notEqual(f.sanitized, true, 'URL-encoding does not contain a path traversal');
});
