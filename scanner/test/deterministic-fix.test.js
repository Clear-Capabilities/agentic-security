// Unit tests for posture/deterministic-fix.js (#1) — the safe, context-independent
// literal-swap fix synthesizer. Every patch it produces is still gated by
// verify_fix in apply_fix, so these tests assert only that the swap is correct
// and that it never claims a fix it didn't make.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { synthesizeDeterministicPatch } from '../src/posture/deterministic-fix.js';

// Verified-remediation PRD FR-01: the swap is chosen by the PURPOSE of the one operation. A non-password integrity digest is swapped at that
// call site; the same call with no visible purpose is refused (needs-review), because a context-free swap breaks passwords and
// compatibility-sensitive digests alike. test/repair/deterministic-purpose.test.js covers password storage and mixed files.
test('weak-hash: md5 → sha256 for an integrity digest (JS createHash)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'a.js', line: 2, cwe: 'CWE-328', family: 'crypto-weak-hash' },
    "const crypto = require('crypto');\nfunction checksum(buf) { return crypto.createHash('md5').update(buf).digest('hex'); }\n",
  );
  assert.ok(r);
  assert.equal(r.ruleId, 'weak-hash-sha256');
  assert.equal(r.purpose, 'non-password-integrity');
  assert.match(r.patch['a.js'], /createHash\('sha256'\)/);
  assert.doesNotMatch(r.patch['a.js'], /md5/);
});

test('weak-hash: a bare md5 with no visible purpose is refused, not swapped', () => {
  assert.equal(synthesizeDeterministicPatch({ file: 'a.js', cwe: 'CWE-328', family: 'crypto-weak-hash' }, "const h = require('crypto').createHash('md5');\n"), null);
  assert.equal(synthesizeDeterministicPatch({ file: 'a.py', cwe: 'CWE-327' }, 'import hashlib\nd = hashlib.sha1(x).hexdigest()\n'), null);
  assert.equal(synthesizeDeterministicPatch({ file: 'A.java', cwe: 'CWE-328' }, 'MessageDigest md = MessageDigest.getInstance("MD5");\n'), null);
});

test('weak-hash: sha1 → sha256 for a content fingerprint (Python hashlib)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'a.py', line: 3, cwe: 'CWE-327', family: 'weak-hash' },
    'import hashlib\ndef fingerprint(data):\n    return hashlib.sha1(data).hexdigest()\n',
  );
  assert.ok(r);
  assert.match(r.patch['a.py'], /hashlib\.sha256\(/);
});

// SARD_AGENTIC_SECURITY_PRD.md Phase 8: this rule's `applies()` matched Java CWE-327/328 findings, but `transform()` had no Java branch.
test('weak-hash: MD5 → SHA-256 for a checksum method (Java MessageDigest)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'A.java', line: 2, cwe: 'CWE-328', family: 'weak-crypto' },
    'class A {\n  public static byte[] checksum(byte[] data) throws Exception { MessageDigest md = MessageDigest.getInstance("MD5"); return md.digest(data); }\n}\n',
  );
  assert.ok(r);
  assert.equal(r.ruleId, 'weak-hash-sha256');
  assert.match(r.patch['A.java'], /MessageDigest\.getInstance\("SHA-256"\)/);
  assert.doesNotMatch(r.patch['A.java'], /"MD5"/);
});

test('weak-hash: SHA1 → SHA-256 for a checksum method (Java MessageDigest)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'A.java', line: 2, cwe: 'CWE-327', family: 'weak-crypto' },
    'class A {\n  byte[] checksum(byte[] d) throws Exception { MessageDigest md = MessageDigest.getInstance("SHA1"); return md.digest(d); }\n}\n',
  );
  assert.ok(r);
  assert.match(r.patch['A.java'], /MessageDigest\.getInstance\("SHA-256"\)/);
});

test('weak-hash: a Java file with no weak digest present yields null (never claims a fix it did not make)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'A.java', cwe: 'CWE-328', family: 'weak-crypto' },
    'MessageDigest md = MessageDigest.getInstance("SHA-256");\n',
  );
  assert.equal(r, null);
});

test('tls: rejectUnauthorized false → true (JS)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'a.js', cwe: 'CWE-295', family: 'crypto-tls-no-verify' },
    'const agent = new https.Agent({ rejectUnauthorized: false });\n',
  );
  assert.ok(r);
  assert.match(r.patch['a.js'], /rejectUnauthorized:\s*true/);
});

test('tls: verify=False → True (Python requests)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'a.py', cwe: 'CWE-295', family: 'crypto-tls-no-verify' },
    'r = requests.get(url, verify=False)\n',
  );
  assert.ok(r);
  assert.match(r.patch['a.py'], /verify=True/);
});

test('no fix for an unrelated CWE', () => {
  assert.equal(synthesizeDeterministicPatch({ file: 'a.js', cwe: 'CWE-89' }, 'db.query(x)'), null);
});

test('right CWE but token absent → null (never claims a fix it did not make)', () => {
  assert.equal(synthesizeDeterministicPatch({ file: 'a.js', cwe: 'CWE-328' }, 'const x = 1;\n'), null);
});

test('defensive: bad inputs → null, never throws', () => {
  assert.equal(synthesizeDeterministicPatch(null, 'x'), null);
  assert.equal(synthesizeDeterministicPatch({ file: 'a.js', cwe: 'CWE-328' }, null), null);
  assert.equal(synthesizeDeterministicPatch({ cwe: 'CWE-328' }, "createHash('md5')"), null); // no file
});
