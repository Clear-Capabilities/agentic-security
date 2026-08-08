// R16 — specialist audit classes: constant-time comparison and zeroization.
//
// A specialist rule earns its place by being narrow. These tests spend most of
// their effort on the things that must NOT fire, because a noisy specialist
// rule is worse than no specialist rule: it trains people to ignore the class.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  scanTimingUnsafeComparison, scanMissingZeroization, scanCryptoSpecialist,
} from '../src/sast/crypto-specialist.js';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'crypto-specialist');
const read = (tier, f) => fs.readFileSync(path.join(FIXTURES, tier, f), 'utf8');

// ---------------------------------------------------------- fixtures

test('the vulnerable fixtures fire and the clean ones do not', () => {
  for (const f of ['verify.js', 'Login.java', 'wipe.c']) {
    assert.ok(scanCryptoSpecialist(f, read('vulnerable', f)).length > 0, `${f} should fire`);
    assert.equal(scanCryptoSpecialist(f, read('clean', f)).length, 0, `clean ${f} must stay silent`);
  }
});

// ---------------------------------------------------------- CWE-208

test('a secret compared with === is flagged', () => {
  const r = scanTimingUnsafeComparison('a.js', 'if (signature === expectedHmac) { ok(); }');
  assert.equal(r.length, 1);
  assert.equal(r[0].cwe, 'CWE-208');
  assert.match(r[0].remediation, /timingSafeEqual/);
});

test('the constant-time form on the same line never fires', () => {
  for (const [file, src] of [
    ['a.js', 'if (crypto.timingSafeEqual(signature, expectedHmac)) ok();'],
    ['a.py', 'if hmac.compare_digest(signature, expected_hmac): ok()'],
    ['a.go', 'if subtle.ConstantTimeCompare(signature, expectedMac) == 1 {'],
    ['a.php', 'if (hash_equals($expected_hmac, $signature)) {'],
    ['A.java', 'if (MessageDigest.isEqual(macBytes, signatureBytes)) {'],
    ['a.cs', 'if (CryptographicOperations.FixedTimeEquals(mac, signature)) {'],
  ]) {
    assert.equal(scanTimingUnsafeComparison(file, src).length, 0, `false positive in ${file}`);
  }
});

test('ordinary comparisons of non-secrets do not fire', () => {
  for (const src of [
    'if (a === b) return;',
    'if (userId === ownerId) allow();',
    'if (status === 200) ok();',
    'if (name.equals(other)) {}',
    'if (memcmp(buf, other, n) == 0) {}',
  ]) {
    assert.equal(scanTimingUnsafeComparison('a.js', src).length, 0, `false positive: ${src}`);
    assert.equal(scanTimingUnsafeComparison('a.c', src).length, 0, `false positive: ${src}`);
  }
});

test('a length check on a secret is not a secret comparison', () => {
  // Comparing lengths leaks nothing an attacker cannot already measure, and
  // flagging it would fire on the correct guard that precedes timingSafeEqual.
  for (const src of [
    'if (signature.length !== expectedHmac.length) return false;',
    'if (len(signature) != len(expected_hmac): return False',
    'if (sig.size() == mac.size()) {}',
  ]) {
    assert.equal(scanTimingUnsafeComparison('a.js', src).length, 0, `false positive: ${src}`);
  }
});

test('a presence check against a sentinel is not a secret comparison', () => {
  for (const src of [
    'if (apiKey === null) throw new Error();',
    'if (password == undefined) return;',
    "if (authToken === '') return;",
  ]) {
    assert.equal(scanTimingUnsafeComparison('a.js', src).length, 0, `false positive: ${src}`);
  }
});

test('comments cannot produce a finding', () => {
  const src = '// if (signature === expectedHmac) { legacy(); }\nreturn true;\n';
  assert.equal(scanTimingUnsafeComparison('a.js', src).length, 0);
});

test('memcmp on secret material is flagged for C', () => {
  const r = scanTimingUnsafeComparison('a.c', 'if (memcmp(mac, expected_hmac, 32) == 0) { ok(); }');
  assert.equal(r.length, 1);
  assert.match(r[0].remediation, /CRYPTO_memcmp|sodium_memcmp/);
});

test('one line yields at most one finding', () => {
  // The same line can match several patterns; reporting it twice would make the
  // class look noisier than it is.
  const r = scanTimingUnsafeComparison('a.js', 'if (signature === expectedHmac && signature !== otherSecret) {}');
  assert.equal(r.length, 1);
});

// ---------------------------------------------------------- CWE-316

test('a Java String holding a secret is flagged', () => {
  const r = scanMissingZeroization('A.java', 'String password = System.getenv("PW");');
  assert.equal(r.length, 1);
  assert.equal(r[0].cwe, 'CWE-316');
  assert.match(r[0].remediation, /char\[\]/);
});

test('an ordinary Java String is not flagged', () => {
  for (const src of ['String name = "bob";', 'String url = cfg.get("url");', 'String message = e.getMessage();']) {
    assert.equal(scanMissingZeroization('A.java', src).length, 0, `false positive: ${src}`);
  }
});

test('memset on a secret is flagged as removable', () => {
  const r = scanMissingZeroization('a.c', 'memset(secret, 0, sizeof(secret));');
  assert.equal(r.length, 1);
  assert.match(r[0].description, /dead store/);
  assert.match(r[0].remediation, /explicit_bzero/);
});

test('a file already using a guaranteed wipe is silent', () => {
  // Presence of the correct API anywhere in the file means the author knows
  // the hazard; flagging a nearby memset would be second-guessing them.
  const src = 'memset(secret, 0, 32);\nexplicit_bzero(other_secret, 32);\n';
  assert.equal(scanMissingZeroization('a.c', src).length, 0);
});

test('memset on a non-secret buffer is not flagged', () => {
  assert.equal(scanMissingZeroization('a.c', 'memset(buffer, 0, sizeof(buffer));').length, 0);
});

// ---------------------------------------------------------- shape

test('findings carry the required schema fields', () => {
  for (const f of scanCryptoSpecialist('verify.js', read('vulnerable', 'verify.js'))) {
    for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'family', 'parser']) {
      assert.ok(f[k], `finding is missing ${k}`);
    }
    assert.ok(['low', 'medium', 'high'].includes(f.severity),
      'a specialist hygiene rule must not claim critical severity');
  }
});

test('unknown languages and malformed input are ignored', () => {
  assert.deepEqual(scanCryptoSpecialist('a.txt', 'signature === expectedHmac'), []);
  assert.deepEqual(scanCryptoSpecialist('a.js', null), []);
  assert.deepEqual(scanCryptoSpecialist('a.js', undefined), []);
});

test('line numbers survive comment blanking', () => {
  const src = '// leading comment\n\n/* block\n   comment */\nif (signature === expectedHmac) {}\n';
  const r = scanTimingUnsafeComparison('a.js', src);
  assert.equal(r.length, 1);
  assert.equal(r[0].line, 5, 'comment stripping must preserve line numbers');
});
