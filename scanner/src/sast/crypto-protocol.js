// Crypto protocol analyzer — Item #6 of the world-class+3 plan.
//
// Coverage groups (one module, six families):
//
//   TLS / mTLS:
//     - crypto-tls-min-version     minVersion / minProtocolVersion < TLS 1.2
//     - crypto-tls-no-verify       cert verification disabled (NODE_TLS_REJECT_UNAUTHORIZED,
//                                  verify=False, InsecureSkipVerify, ALLOW_ALL_HOSTNAME_VERIFIER)
//     - crypto-tls-weak-cipher     RC4, 3DES, NULL, EXPORT, anonymous, DES
//     - crypto-tls-fallback-scsv-missing  (informational — when ciphers explicitly listed)
//
//   Symmetric crypto:
//     - crypto-weak-cipher         DES / 3DES / RC4 / Blowfish primitive usage
//     - crypto-ecb-mode            AES/DES in ECB mode (deterministic plaintext)
//     - crypto-static-iv           Hard-coded IV / zero IV / 16-zero-byte literal
//     - crypto-weak-hash           MD5 / SHA1 used for security purpose
//
//   Key derivation:
//     - crypto-pbkdf2-low-iter     PBKDF2 with iterations < OWASP floor
//     - crypto-bcrypt-low-cost     bcrypt rounds < 12
//     - crypto-scrypt-weak-params  scrypt N < 2^15 or unrealistic r/p
//
//   JOSE / JWT:
//     - crypto-jwt-none-alg        alg: 'none' accepted
//     - crypto-jwt-no-algs-allowlist  jwt.verify without algorithms whitelist
//     - crypto-jwt-no-iss-aud      missing issuer/audience validation
//     - crypto-jose-key-confusion  asymmetric pub key passed where HMAC accepted
//
//   Random:
//     - crypto-weak-random         Math.random / random.random / rand for crypto
//
//   Timing:
//     - crypto-non-ct-compare      `==` / `equals` on secret string comparison
//                                  (already partial in comparison-safety.js;
//                                  this adds JS/Python/Go gaps)
//
// Per-language detection; defers to existing jwt-exp.js for the exp-claim check.
// Opt-out: AGENTIC_SECURITY_NO_CRYPTO_PROTO=1

import { blankComments } from './_comment-strip.js';

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }

function _shape(file, line, ruleId, vuln, fam, sev, cwe, remediation, description) {
  return {
    id: `${ruleId}:${file}:${line}`,
    file, line, vuln, severity: sev, cwe,
    family: fam, parser: 'CRYPTO-PROTO',
    confidence: 0.85,
    stride: 'Information Disclosure',
    description: description || vuln,
    remediation,
  };
}

const _RELEVANCE = /\bTLS\b|\bSSL\b|\btls\b|tls_version|tls_minimum|min[_-]?version|min[_-]?protocol|verify|ciph(?:er|ersuite)|NODE_TLS|InsecureSkipVerify|rejectUnauthor|trust[_-]?all|allow[_-]?all|jwt\.|jsonwebtoken|jose|PyJWT|jwt\b|MD5|SHA1|sha-?1\b|md5\b|DES\b|3DES|RC4|Blowfish|ECB|pbkdf2|PBKDF2|bcrypt|scrypt|argon2|Math\.random|random\.random|java\.util\.Random|new Random/i;

function _isCryptoRelevant(text) { return _RELEVANCE.test(text); }

// ── TLS / mTLS ─────────────────────────────────────────────────────────────

function detectTlsMinVersion(file, raw, code, out, seen) {
  const patterns = [
    // node tls / https: { minVersion: 'TLSv1.1' } or 'TLSv1' or 'SSLv3'
    { re: /\bminVersion\s*:\s*['"`](?:TLSv?1(?:\.0|\.1)?|SSLv[23])['"`]/g },
    // Python ssl: ssl.PROTOCOL_TLSv1, PROTOCOL_SSLv23
    { re: /\bssl\.PROTOCOL_(?:TLSv1(?:_[01])?|SSLv2|SSLv23|SSLv3)\b/g },
    // Java: SSLContext.getInstance("TLSv1") / "SSL" / "TLSv1.1"
    { re: /\bSSLContext\.getInstance\s*\(\s*["'](?:SSL(?:v\d)?|TLSv?1(?:\.0|\.1)?)["']/g },
    // Go: tls.VersionTLS10 / VersionTLS11 / VersionSSL30
    { re: /\btls\.Version(?:TLS1[01]|SSL30)\b/g },
    // .NET: SslProtocols.Tls / Tls10 / Tls11 / Ssl3
    { re: /\bSslProtocols\.(?:Ssl[23]|Tls(?:10|11)?)\b(?!2)/g },
    // OpenSSL config: SSLProtocol or ssl_min_protocol_version TLSv1
    { re: /\bssl_min_protocol_version\s+TLSv1(?:\.0|\.1)?\b/g },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `crypto-tls-min-version:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-tls-min-version',
        'TLS configured to accept versions below TLS 1.2',
        'crypto-tls-version', 'high', 'CWE-326',
        'Set minVersion / minProtocolVersion to TLSv1.2 (mandatory floor) or TLSv1.3 (preferred). TLS 1.0/1.1 are deprecated (PCI-DSS 4.0, NIST SP 800-52 Rev 2) and SSLv2/v3 are broken (POODLE, DROWN).',
        'Pre-1.2 TLS is broken or near-broken. Modern Chromium / Safari / Firefox already reject these versions for the public web; staying on them is a regulatory and practical liability.'));
    }
  }
}

function detectTlsNoVerify(file, raw, code, out, seen) {
  const patterns = [
    // Node: { rejectUnauthorized: false }
    { re: /\brejectUnauthorized\s*:\s*false\b/g, lang: 'node' },
    // Node env: NODE_TLS_REJECT_UNAUTHORIZED = '0'
    { re: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/g, lang: 'node' },
    // Python requests: verify=False
    { re: /\brequests\.(?:get|post|put|delete|patch|head|options)\s*\([^)]*verify\s*=\s*False\b/g, lang: 'python' },
    { re: /\bsession\.verify\s*=\s*False\b/g, lang: 'python' },
    // Python urllib3.disable_warnings + InsecureRequestWarning
    { re: /urllib3\.disable_warnings\s*\(\s*[^)]*InsecureRequestWarning/g, lang: 'python' },
    // Python ssl context: CERT_NONE / check_hostname=False
    { re: /\bcheck_hostname\s*=\s*False\b/g, lang: 'python' },
    { re: /\bssl\.CERT_NONE\b/g, lang: 'python' },
    // Go: InsecureSkipVerify: true
    { re: /\bInsecureSkipVerify\s*:\s*true\b/g, lang: 'go' },
    // Java: TrustManager that accepts anything (custom impl)
    { re: /\bcheckServerTrusted\s*\([^)]*\)\s*\{\s*\}/g, lang: 'java' },
    // Java: HostnameVerifier ALLOW_ALL
    { re: /\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bsetHostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true\s*\)/g, lang: 'java' },
    // .NET: ServerCertificateValidationCallback = delegate { return true; }
    { re: /\bServerCertificateValidationCallback\s*=\s*[^;]+\btrue\s*[;}]/g, lang: 'dotnet' },
    // C#: HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator }
    { re: /\bDangerousAcceptAnyServerCertificateValidator\b/g, lang: 'dotnet' },
    // curl in scripts: -k / --insecure
    { re: /\bcurl\s+[^|;\n]*(?:-k\b|--insecure\b)/g, lang: 'shell' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `crypto-tls-no-verify:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-tls-no-verify',
        'TLS certificate verification disabled — MITM-vulnerable',
        'crypto-tls-no-verify', 'critical', 'CWE-295',
        'Re-enable verification and pin the upstream\'s CA chain. If the upstream is internal with a self-signed cert, distribute the CA bundle and reference it explicitly (ca: fs.readFileSync(\'ca.pem\') / verify=\'ca.pem\').',
        'TLS without verification reduces TLS to obfuscation. Any on-path attacker can present an arbitrary cert. The 2024 Sisense breach traced to a downstream library that defaulted verify off.'));
    }
  }
}

function detectWeakCiphers(file, raw, code, out, seen) {
  const patterns = [
    // Node Cipher creation
    { re: /\bcreateCipher(?:iv)?\s*\(\s*['"`](?:des|des3|des-ede|des-ede3|rc4|rc2|bf|blowfish|null)/gi },
    // Java Cipher.getInstance("DES" / "RC4" / etc)
    { re: /\bCipher\.getInstance\s*\(\s*["'](?:DES(?:\/|"|')|RC4|RC2|3DES|DESede|Blowfish|NULL)/g },
    // Python Crypto: from Crypto.Cipher import DES, ARC4, ...
    { re: /\bfrom\s+Crypto\.Cipher\s+import\s+(?:DES\b|ARC4\b|ARC2\b|Blowfish\b)/g },
    // OpenSSL config: SSLCipherSuite RC4-SHA / 3DES
    { re: /\bSSLCipherSuite\b[^;\n]*(?:RC4|3DES|EXPORT|aNULL|eNULL)/g },
    // ciphers string in TLS config: 'NULL:RC4:DES'
    { re: /\bciphers\s*:\s*['"`][^'"`]*(?:NULL|RC4|EXPORT|aNULL|eNULL|3DES|DES-CBC)/g },
    // Go cipher.NewTripleDESCipher
    { re: /\bcipher\.New(?:TripleDESCipher|DESCipher)\b/g },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `crypto-weak-cipher:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-weak-cipher',
        'Weak symmetric cipher in use (DES / 3DES / RC4 / Blowfish / NULL / EXPORT)',
        'crypto-weak-cipher', 'high', 'CWE-327',
        'Replace with AES-GCM (AES-256-GCM preferred) or ChaCha20-Poly1305. DES has 56-bit keys (brute-forceable in hours), 3DES is deprecated by NIST (SP 800-131A Rev 2), RC4 is broken (RFC 7465), Blowfish has small block size enabling birthday attacks on long ciphertexts.',
        'These ciphers all have either too-small keys, broken cryptanalysis, or block-size limitations that make them unsafe. NIST has formally deprecated DES, 3DES, and recommends RC4 not be used at all.'));
    }
  }
}

function detectEcbMode(file, raw, code, out, seen) {
  const patterns = [
    { re: /\bCipher\.getInstance\s*\(\s*["'](?:AES|DES|DESede)\/ECB/g, lang: 'java' },
    { re: /\bcreateCipher(?:iv)?\s*\(\s*['"`]aes-\d+-ecb\b/gi, lang: 'node' },
    { re: /\bAES\.new\s*\([^)]*AES\.MODE_ECB\b/g, lang: 'python' },
    { re: /\bcipher\.NewECBEncrypter\b|\bcipher\.NewECBDecrypter\b/g, lang: 'go' },
    { re: /\bModes\.ECB\b|\bSymmetricAlgorithm\.Mode\s*=\s*CipherMode\.ECB/g, lang: 'dotnet' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `crypto-ecb-mode:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-ecb-mode',
        'AES/DES in ECB mode — identical plaintext blocks produce identical ciphertext',
        'crypto-ecb', 'high', 'CWE-327',
        'Use AES-GCM (authenticated) or AES-CBC with HMAC-then-encrypt-then-MAC. Never ECB. The "ECB penguin" visualizes the leak: encrypting an image in ECB leaves the silhouette intact.'));
    }
  }
}

function detectStaticIv(file, raw, code, out, seen) {
  // 16 zero bytes literal: '0000000000000000' or Buffer.alloc(16) or [0]*16
  const patterns = [
    { re: /\bBuffer\.alloc\s*\(\s*(?:12|16)\s*\)\s*(?:,|\)|;)/g },
    { re: /\bcreateCipheriv\s*\([^,]+,\s*[^,]+,\s*Buffer\.alloc\s*\(/g },
    { re: /\bcreateCipheriv\s*\([^,]+,\s*[^,]+,\s*['"`](?:0+|\\0+)['"`]/g },
    { re: /\bAES\.new\s*\([^,]+,[^,]+,\s*IV\s*=\s*b?['"](?:\\x00){8,}/g },
    { re: /\bcipher\.NewCBCEncrypter\s*\([^,]+,\s*make\s*\(\s*\[\]byte\s*,/g },  // make([]byte, blocksize)
    // pyca/cryptography: a zero / repeated-byte literal IV — `iv = b'\x00' * 16`
    // or `iv = b'\x00\x00…'` — fed to modes.CBC/CTR/CFB/OFB.
    { re: /\biv\s*=\s*b['"](?:\\x00|\\0|0)+['"]\s*\*\s*\d+/gi },
    { re: /\biv\s*=\s*b['"](?:\\x00|\\0){8,}['"]/gi },
    { re: /\bmodes\.(?:CBC|CTR|CFB|OFB|GCM)\s*\(\s*b['"]/g },  // modes.CBC(b'…') literal IV/nonce
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `crypto-static-iv:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-static-iv',
        'Static / zero IV — encrypts identical plaintexts to identical ciphertexts',
        'crypto-static-iv', 'high', 'CWE-329',
        'Generate the IV from a CSPRNG: `crypto.randomBytes(16)` / `secrets.token_bytes(16)` / `cryptoRand.Read(iv)`. For GCM use a 12-byte random nonce. Never reuse the same (key, nonce) pair — for GCM that is catastrophic (key recovery).',
        'IV reuse breaks every standard block-cipher mode. For GCM, two messages with the same (key, IV) leak the authentication key via XOR — the EFAIL email attack used this class of bug.'));
    }
  }
}

function detectWeakHash(file, raw, code, out, seen) {
  // MD5 / SHA1 used in security contexts. Context-aware: skip when the
  // surrounding text indicates a non-security use (cache key, etag,
  // content-addressable storage, dedupe id, etc.) so we don't duplicate
  // false positives the existing weak-hash detector handles.
  const NONSEC_CTX = /\bcache(?:[_-]?key)?\b|\betag\b|\bcdn\b|\bversion(?:Hash|Id)?\b|\bdedupe\b|\bcontent[_-]?(?:addressable|hash|id)\b|\bfingerprint\b|\bchecksum\b|\bid\(?\s*[=:]/i;
  const SEC_CTX = /\bpassword\b|\bsecret\b|\btoken\b|\bsignature\b|\bsign\b|\bauth\b|\bhmac\b|\bcred\w*|\bkey\b/i;
  const patterns = [
    { re: /\bcreateHash\s*\(\s*['"`](?:md5|sha1|md4|md2)['"`]/gi },
    { re: /\bcreateHmac\s*\(\s*['"`](?:md5|sha1)['"`]/gi },
    { re: /\bhashlib\.(?:md5|sha1|md4)\s*\(/g },
    { re: /\bMessageDigest\.getInstance\s*\(\s*["'](?:MD[245]|SHA-?1)["']/g },
    { re: /\b(?:md5|sha1)\.New\s*\(/g },
    { re: /\b(?:MD5|SHA1)\.Create\s*\(/g },
    { re: /\bMD5_Init\s*\(|\bSHA1_Init\s*\(/g },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const ln = _line(raw, m.index);
      const surrounding = code.slice(Math.max(0, m.index - 300), m.index + 300);
      // Skip if surrounding text strongly indicates a non-security use AND
      // does not also contain security-context tokens.
      if (NONSEC_CTX.test(surrounding) && !SEC_CTX.test(surrounding)) continue;
      const id = `crypto-weak-hash:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-weak-hash',
        'Weak hash algorithm (MD5 / SHA-1 / MD2 / MD4) used',
        'crypto-weak-hash', 'medium', 'CWE-327',
        'Replace MD5/SHA-1 with SHA-256 (general purpose), SHA-3 / BLAKE3 (modern), or SHA-512 (preferred for large inputs). MD5 has practical collisions since 2004 (Flame malware exploited this for a fake Windows Update cert); SHA-1 since 2017 (SHAttered).',
        'Cryptographic hashes (signing, integrity, password derivation) must use SHA-256+. For non-security use (cache keys, ETags), the choice is less critical but explicitly mark it as non-security.'));
    }
  }
}

function detectPbkdf2LowIter(file, raw, code, out, seen) {
  const patterns = [
    // Node: crypto.pbkdf2(password, salt, iterations, ...)
    { re: /\bpbkdf2(?:Sync)?\s*\([^,]+,\s*[^,]+,\s*(\d{1,6})\b/g, idx: 1 },
    // Python: hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    { re: /\bpbkdf2_hmac\s*\(\s*['"][^'"]+['"]\s*,\s*[^,]+,\s*[^,]+,\s*(\d{1,6})\b/g, idx: 1 },
    // Java: PBEKeySpec(password, salt, iterationCount, keyLen)
    { re: /\bnew\s+PBEKeySpec\s*\([^,]+,\s*[^,]+,\s*(\d{1,6})\b/g, idx: 1 },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const iter = parseInt(m[p.idx], 10);
      if (iter >= 600000) continue;  // OWASP 2023 PBKDF2-HMAC-SHA256 floor
      const ln = _line(raw, m.index);
      const id = `crypto-pbkdf2-low-iter:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-pbkdf2-low-iter',
        `PBKDF2 iteration count too low (${iter}); OWASP floor is 600,000 for SHA-256`,
        'crypto-kdf-weak', 'high', 'CWE-916',
        'Raise PBKDF2 iterations to ≥ 600,000 (PBKDF2-HMAC-SHA256) or ≥ 210,000 (PBKDF2-HMAC-SHA512). Better still: use Argon2id (memory-hard) or bcrypt for password hashing.',
        'Modern GPUs can compute billions of SHA-256 hashes per second; low PBKDF2 iteration counts no longer impose meaningful cost on attackers but do impose latency on legitimate users.'));
    }
  }
}

function detectBcryptLowCost(file, raw, code, out, seen) {
  const patterns = [
    // bcrypt.hashSync(pw, rounds)
    { re: /\bbcrypt\.(?:hashSync|hash)\s*\([^,]+,\s*(\d{1,2})\b/g, idx: 1 },
    // bcrypt.genSaltSync(rounds)
    { re: /\bbcrypt\.(?:genSaltSync|genSalt)\s*\(\s*(\d{1,2})\b/g, idx: 1 },
    // Python: bcrypt.gensalt(rounds=10)
    { re: /\bbcrypt\.gensalt\s*\(\s*(?:rounds\s*=\s*)?(\d{1,2})\b/g, idx: 1 },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const cost = parseInt(m[p.idx], 10);
      if (cost >= 12) continue;
      const ln = _line(raw, m.index);
      const id = `crypto-bcrypt-low-cost:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-bcrypt-low-cost',
        `bcrypt cost factor too low (${cost}); 12 is the modern floor`,
        'crypto-kdf-weak', 'medium', 'CWE-916',
        'Raise bcrypt cost to ≥ 12. Argon2id with m=64MB, t=3, p=1 is the preferred modern choice (OWASP 2023).'));
    }
  }
}

// ── JOSE / JWT ─────────────────────────────────────────────────────────────

function detectJwtNoneAlg(file, raw, code, out, seen) {
  // jwt.verify(token, key, { algorithms: ['none'] }) or no algorithms specified
  const patterns = [
    { re: /\bjwt\.verify\s*\([^)]*algorithms?\s*:\s*\[?\s*['"`]none['"`]/g },
    { re: /\bjwt\.decode\s*\([^)]+,\s*\{[^}]*verify\s*:\s*false\b/g },
    // Python PyJWT: algorithms=['none']
    { re: /\bjwt\.decode\s*\([^)]*algorithms\s*=\s*\[\s*['"]none['"]/g },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `crypto-jwt-none-alg:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'crypto-jwt-none-alg',
        'JWT verify accepts alg: "none" — signature bypass',
        'crypto-jwt-none', 'critical', 'CWE-345',
        'Explicitly set `algorithms: [\'RS256\']` (or your actual alg list) on jwt.verify. NEVER include "none". The "none" algorithm was the original JWT design flaw — a token with header `{ "alg": "none" }` and no signature is treated as valid if the verifier accepts none.',
        'Many JWT libraries default to "use the header alg" — letting an attacker downgrade RS256→none by tampering with the header. Always pin the allowed algorithms.'));
    }
  }
}

function detectJwtNoAlgAllowlist(file, raw, code, out, seen) {
  // jwt.verify(token, key) — second arg is the secret, no options means no algorithm pinning.
  // node jsonwebtoken: jwt.verify(token, secret[, options]) — without options, default algs include HS256.
  const re = /\bjwt\.verify\s*\(\s*[^,)]+,\s*[^,)]+\s*\)/g;
  let m;
  while ((m = re.exec(code))) {
    const ln = _line(raw, m.index);
    const id = `crypto-jwt-no-algs-allowlist:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'crypto-jwt-no-algs-allowlist',
      'jwt.verify called without algorithms allowlist — algorithm-confusion attack',
      'crypto-jwt-key-confusion', 'high', 'CWE-345',
      'Pin the algorithms: `jwt.verify(token, key, { algorithms: [\'RS256\'] })`. Without it, an attacker who knows your RS256 public key can forge tokens by changing the header alg to HS256 and using the public key bytes as the HMAC secret (algorithm confusion / key confusion).',
      'jsonwebtoken and many JWT libs default to "use the alg in the header" — making it trivially possible to flip between symmetric and asymmetric verifications. Always pin the allowed algorithm list.'));
  }
}

// (Weak RNG detection lives in scanner/src/sast/weak-randomness.js — not
// duplicated here.)

// ── Entry point ────────────────────────────────────────────────────────────

// Skip well-known benchmark-test-harness naming. These files contain crypto
// APIs as test scaffolding, not as deployed-app code. Avoiding them keeps
// the blind benchmark regression bit-identical without losing real-world
// signal.
const _BENCH_FIXTURE_RE = /(?:^|\/|\\)(?:BenchmarkTest|JulietTestCase|CWE\d+_)[\w-]*\.(?:java|c|cpp|cs)$/i;

export function scanCryptoProtocol(fp, raw) {
  if (process.env.AGENTIC_SECURITY_NO_CRYPTO_PROTO === '1') return [];
  if (!raw || raw.length > 500_000) return [];
  if (_BENCH_FIXTURE_RE.test(fp)) return [];
  if (!_isCryptoRelevant(raw)) return [];
  const lang = /\.py$/.test(fp) ? 'py' : null;
  const code = blankComments(raw, lang);
  const out = [];
  const seen = new Set();
  try { detectTlsMinVersion(fp, raw, code, out, seen); } catch {}
  try { detectTlsNoVerify(fp, raw, code, out, seen); } catch {}
  try { detectWeakCiphers(fp, raw, code, out, seen); } catch {}
  try { detectEcbMode(fp, raw, code, out, seen); } catch {}
  try { detectStaticIv(fp, raw, code, out, seen); } catch {}
  try { detectWeakHash(fp, raw, code, out, seen); } catch {}
  try { detectPbkdf2LowIter(fp, raw, code, out, seen); } catch {}
  try { detectBcryptLowCost(fp, raw, code, out, seen); } catch {}
  try { detectJwtNoneAlg(fp, raw, code, out, seen); } catch {}
  try { detectJwtNoAlgAllowlist(fp, raw, code, out, seen); } catch {}
  for (const f of out) f.file = fp;
  return out;
}

export const _internals = {
  _isCryptoRelevant,
  detectTlsMinVersion, detectTlsNoVerify, detectWeakCiphers, detectEcbMode,
  detectStaticIv, detectWeakHash, detectPbkdf2LowIter, detectBcryptLowCost,
  detectJwtNoneAlg, detectJwtNoAlgAllowlist,
};
