// Tests for crypto-protocol.js — TLS/mTLS/cipher/JOSE coverage.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanCryptoProtocol } from '../src/sast/crypto-protocol.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIX = path.join(__dirname, 'fixtures', 'crypto-protocol');
const read = (p) => fs.readFileSync(p, 'utf8');

test('crypto-proto: rejectUnauthorized: false flagged critical', () => {
  const out = scanCryptoProtocol('tls-config.js', read(path.join(FIX, 'vulnerable/tls-config.js')));
  const f = out.find(x => x.family === 'crypto-tls-no-verify');
  assert.ok(f, `expected crypto-tls-no-verify; got ${out.map(x => x.family).join(',')}`);
  assert.equal(f.severity, 'critical');
});

test('crypto-proto: TLSv1 minVersion flagged', () => {
  const out = scanCryptoProtocol('tls-config.js', read(path.join(FIX, 'vulnerable/tls-config.js')));
  assert.ok(out.some(f => f.family === 'crypto-tls-version'));
});

test('crypto-proto: jwt.verify without algorithms allowlist flagged', () => {
  const out = scanCryptoProtocol('tls-config.js', read(path.join(FIX, 'vulnerable/tls-config.js')));
  assert.ok(out.some(f => f.family === 'crypto-jwt-key-confusion'),
    `expected jwt-key-confusion; got ${out.map(f => f.family).join(',')}`);
});

// Weak RNG detection (Math.random) is handled by sast/weak-randomness.js —
// not duplicated in crypto-protocol.

test('crypto-proto: Python — md5/sha1, verify=False, DES, ECB, PBKDF2 low iter, PyJWT none', () => {
  const out = scanCryptoProtocol('cipher-py.py', read(path.join(FIX, 'vulnerable/cipher-py.py')));
  const fams = new Set(out.map(f => f.family));
  assert.ok(fams.has('crypto-weak-hash'), 'md5/sha1');
  assert.ok(fams.has('crypto-tls-no-verify'), 'verify=False');
  assert.ok(fams.has('crypto-weak-cipher'), 'DES');
  assert.ok(fams.has('crypto-ecb'), 'ECB');
  assert.ok(fams.has('crypto-kdf-weak'), 'PBKDF2');
  assert.ok(fams.has('crypto-jwt-none'), 'jwt none alg');
});

test('crypto-proto: pyca/cryptography zero IV (iv = b\'\\x00\' * 16) flagged static-IV', () => {
  const src = "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\ndef enc(plain, key):\n    iv = b'\\x00' * 16\n    c = Cipher(algorithms.AES(key), modes.CBC(iv))\n    return c.encryptor().update(plain)\n";
  const out = scanCryptoProtocol('enc.py', src);
  assert.ok(out.some(f => f.family === 'crypto-static-iv' && f.cwe === 'CWE-329'), 'zero IV flagged');
});

test('crypto-proto: Go InsecureSkipVerify + TLS 1.0 flagged', () => {
  const out = scanCryptoProtocol('insecure.go', read(path.join(FIX, 'vulnerable/insecure.go')));
  assert.ok(out.some(f => f.family === 'crypto-tls-no-verify'));
  assert.ok(out.some(f => f.family === 'crypto-tls-version'));
});

test('crypto-proto: Java MD5 + DES + AES/ECB all fire', () => {
  const out = scanCryptoProtocol('Cipher.java', read(path.join(FIX, 'vulnerable/Cipher.java')));
  const fams = new Set(out.map(f => f.family));
  assert.ok(fams.has('crypto-weak-hash'));
  assert.ok(fams.has('crypto-weak-cipher'));
  assert.ok(fams.has('crypto-ecb'));
});

test('crypto-proto: clean fixture only fires jwt-key-confusion guard at most once', () => {
  const out = scanCryptoProtocol('safe.js', read(path.join(FIX, 'clean/safe.js')));
  // Clean fixture has jwt.verify with algorithms pinned — should NOT trigger
  // jwt-key-confusion. May still fire other low-noise; we assert specifically.
  assert.equal(out.filter(f => f.family === 'crypto-jwt-none').length, 0);
  assert.equal(out.filter(f => f.family === 'crypto-tls-no-verify').length, 0);
  assert.equal(out.filter(f => f.family === 'crypto-weak-hash').length, 0);
  assert.equal(out.filter(f => f.family === 'crypto-weak-cipher').length, 0);
  // jwt.verify(token, key, { algorithms: [...] }) has 3 args, so the
  // "no-algs-allowlist" 2-arg pattern should not match.
  assert.equal(out.filter(f => f.family === 'crypto-jwt-key-confusion').length, 0,
    `unexpected jwt-key-confusion on clean fixture`);
});

test('crypto-proto: NO_CRYPTO_PROTO disables detector', () => {
  process.env.AGENTIC_SECURITY_NO_CRYPTO_PROTO = '1';
  try {
    const out = scanCryptoProtocol('tls-config.js', read(path.join(FIX, 'vulnerable/tls-config.js')));
    assert.equal(out.length, 0);
  } finally { delete process.env.AGENTIC_SECURITY_NO_CRYPTO_PROTO; }
});

test('crypto-proto: non-crypto file is silent', () => {
  const out = scanCryptoProtocol('plain.js', 'function add(a, b) { return a + b; }\n');
  assert.equal(out.length, 0);
});
