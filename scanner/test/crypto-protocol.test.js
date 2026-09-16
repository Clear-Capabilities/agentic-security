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

// Juliet's OWN canonical Java CWE-329 shape (confirmed via the public
// Juliet Java mirror this project's SARD manifest pins,
// CWE329_Not_Using_Random_IV_with_CBC_Mode__basic_01.java): a hardcoded
// byte-array literal declared as a NAMED VARIABLE, then passed to
// IvParameterSpec BY NAME — a different shape from the already-covered
// inline `new IvParameterSpec(new byte[16])` form, which structurally
// cannot match a declare-then-pass indirection at all.
test('crypto-proto: Java IvParameterSpec fed a named hardcoded byte-array variable flags static-IV', () => {
  const src = `
    public class C {
      public void bad() throws Throwable {
        byte[] initializationVector = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
      }
    }`;
  const out = scanCryptoProtocol('C.java', src);
  assert.ok(out.some(f => f.family === 'crypto-static-iv' && f.cwe === 'CWE-329'),
    'hardcoded byte-array IV passed by name should be flagged');
});

test('crypto-proto: Java IvParameterSpec fed a SecureRandom-filled array does NOT fire', () => {
  const src = `
    public class C {
      public void good() throws Throwable {
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
      }
    }`;
  const out = scanCryptoProtocol('C.java', src);
  assert.ok(!out.some(f => f.family === 'crypto-static-iv' && f.cwe === 'CWE-329'),
    'a SecureRandom-filled IV must not fire — no brace-literal initializer to match');
});

test('crypto-proto: cross-language weak cipher — Go/PHP/Ruby DES/RC4/BF fire; AES clean', () => {
  const fires = (fp, code) => scanCryptoProtocol(fp, code).some(f => f.cwe === 'CWE-327' && f.family === 'crypto-weak-cipher');
  const clean = (fp, code) => scanCryptoProtocol(fp, code).every(f => f.family !== 'crypto-weak-cipher');
  // Go crypto/des + crypto/rc4
  assert.ok(fires('c.go', 'package main\nimport "crypto/des"\nfunc e(k []byte){ des.NewCipher(k) }'));
  assert.ok(fires('c.go', 'package main\nimport "crypto/rc4"\nfunc e(k []byte){ rc4.NewCipher(k) }'));
  assert.ok(clean('c.go', 'package main\nimport "crypto/aes"\nfunc e(k []byte){ aes.NewCipher(k) }'));
  // PHP openssl_encrypt + mcrypt
  assert.ok(fires('c.php', '<?php $x = openssl_encrypt($d, "DES-ECB", $k);'));
  assert.ok(fires('c.php', '<?php $x = mcrypt_encrypt(MCRYPT_DES, $k, $d, MCRYPT_MODE_ECB);'));
  assert.ok(clean('c.php', '<?php $x = openssl_encrypt($d, "aes-256-gcm", $k);'));
  // Ruby OpenSSL::Cipher
  assert.ok(fires('c.rb', 'require "openssl"\ndef e; OpenSSL::Cipher.new("DES-ECB"); end'));
  assert.ok(fires('c.rb', 'require "openssl"\ndef e; OpenSSL::Cipher.new("bf-cbc"); end'));
  assert.ok(clean('c.rb', 'require "openssl"\ndef e; OpenSSL::Cipher.new("aes-256-gcm"); end'));
});

test('crypto-proto: cross-language static-IV — JVM/Go/PHP/Ruby/C# fire; CSPRNG clean', () => {
  const fires = (fp, code) => scanCryptoProtocol(fp, code).some(f => f.cwe === 'CWE-329');
  const clean = (fp, code) => scanCryptoProtocol(fp, code).every(f => f.cwe !== 'CWE-329');
  // Java / Kotlin IvParameterSpec from a zero array
  assert.ok(fires('C.java', 'import javax.crypto.spec.IvParameterSpec;\nclass C { IvParameterSpec iv(){ return new IvParameterSpec(new byte[16]); } }'));
  assert.ok(clean('C.java', 'import javax.crypto.spec.IvParameterSpec;\nimport java.security.SecureRandom;\nclass C { IvParameterSpec iv(){ byte[] b = new byte[16]; new SecureRandom().nextBytes(b); return new IvParameterSpec(b); } }'));
  assert.ok(fires('C.kt', 'import javax.crypto.spec.IvParameterSpec\nclass C { fun iv() = IvParameterSpec(ByteArray(16)) }'));
  // C# zero IV assignment / CreateEncryptor
  assert.ok(fires('C.cs', 'using System.Security.Cryptography;\nclass C { void e(Aes aes){ aes.IV = new byte[16]; } }'));
  // PHP openssl_encrypt with str_repeat / empty IV
  assert.ok(fires('c.php', '<?php $iv = str_repeat("\\0", 16); openssl_encrypt($d, "aes-128-cbc", $k, 0, $iv);'));
  assert.ok(clean('c.php', '<?php $iv = random_bytes(16); openssl_encrypt($d, "aes-128-cbc", $k, 0, $iv);'));
  // Ruby cipher.iv = zero literal
  assert.ok(fires('c.rb', 'require "openssl"\ndef e(d,k)\n  c = OpenSSL::Cipher.new("aes-128-cbc"); c.encrypt; c.key = k\n  c.iv = "\\x00" * 16\n  c.update(d)\nend\n'));
  assert.ok(clean('c.rb', 'require "openssl"\ndef e(d,k)\n  c = OpenSSL::Cipher.new("aes-128-cbc"); c.encrypt; c.key = k\n  c.iv = c.random_iv\n  c.update(d)\nend\n'));
  // Go: zero make([]byte) IV fires; rand.Read-filled clean
  assert.ok(fires('c.go', 'package main\nimport ("crypto/aes";"crypto/cipher")\nfunc e(k,d []byte){ b,_ := aes.NewCipher(k); iv := make([]byte, aes.BlockSize); m := cipher.NewCBCEncrypter(b, iv); _ = m }'));
  assert.ok(clean('c.go', 'package main\nimport ("crypto/aes";"crypto/cipher";"crypto/rand")\nfunc e(k,d []byte){ b,_ := aes.NewCipher(k); iv := make([]byte, aes.BlockSize); rand.Read(iv); m := cipher.NewCBCEncrypter(b, iv); _ = m }'));
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
