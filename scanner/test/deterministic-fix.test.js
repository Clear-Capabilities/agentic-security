// Unit tests for posture/deterministic-fix.js (#1) — the safe, context-independent
// literal-swap fix synthesizer. Every patch it produces is still gated by
// verify_fix in apply_fix, so these tests assert only that the swap is correct
// and that it never claims a fix it didn't make.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { synthesizeDeterministicPatch } from '../src/posture/deterministic-fix.js';

test('weak-hash: md5 → sha256 (JS createHash)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'a.js', cwe: 'CWE-328', family: 'crypto-weak-hash' },
    "const h = require('crypto').createHash('md5');\n",
  );
  assert.ok(r);
  assert.equal(r.ruleId, 'weak-hash-sha256');
  assert.match(r.patch['a.js'], /createHash\('sha256'\)/);
  assert.doesNotMatch(r.patch['a.js'], /md5/);
});

test('weak-hash: sha1 → sha256 (Python hashlib)', () => {
  const r = synthesizeDeterministicPatch(
    { file: 'a.py', cwe: 'CWE-327', family: 'weak-hash' },
    'import hashlib\nd = hashlib.sha1(x).hexdigest()\n',
  );
  assert.ok(r);
  assert.match(r.patch['a.py'], /hashlib\.sha256\(/);
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
