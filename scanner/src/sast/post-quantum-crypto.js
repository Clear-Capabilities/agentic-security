// Post-quantum cryptography migration scanner — Recommendation #2 of the
// world-class+3 plan.
//
// NIST finalized the first PQC standards in 2024 (FIPS 203 ML-KEM, FIPS 204
// ML-DSA, FIPS 205 SLH-DSA). The Harvest-Now-Decrypt-Later (HNDL) threat is
// already real: traffic encrypted with RSA/ECDH today can be stored and
// decrypted by a future cryptographically-relevant quantum computer (CRQC).
// Federal mandates target full migration by 2035; private-sector exposure
// runs through long-lived signing keys (code-signing, TLS, JWT), data at
// rest, and authenticated key exchange.
//
// This module catalogs every pre-quantum asymmetric primitive used in the
// codebase and emits a migration finding with:
//
//   - Algorithm family (RSA, ECDSA, ECDH, DSA, DH, X25519/Ed25519)
//   - Use case (signing, encryption, KEX, key generation)
//   - Recommended PQC replacement (ML-KEM, ML-DSA, SLH-DSA, hybrid)
//   - Migration tier (LONG_LIVED_KEY, SIGNING, KEX, EPHEMERAL)
//   - Sensitivity context (HNDL-relevant when wrapping PII / secrets)
//
// Findings live under family 'pqc-migration' with subfamily strings:
//   pqc-rsa-keygen     RSA key generation (signing or encryption)
//   pqc-rsa-encrypt    RSA encryption of data (HNDL-critical)
//   pqc-rsa-sign       RSA signing (degrades when CRQC arrives)
//   pqc-ecdsa-sign     ECDSA signing (curve agnostic)
//   pqc-ecdh-kex       ECDH key exchange (HNDL-critical)
//   pqc-dh-kex         Classical Diffie-Hellman
//   pqc-dsa            DSA (already weak; PQ migration is acute)
//   pqc-x25519         X25519 KEM-style use (HNDL-critical when long-lived)
//   pqc-ed25519        Ed25519 signing (PQ-vulnerable but well-studied)
//   pqc-tls-config     TLS configuration not allowing PQ hybrid groups
//   pqc-jwt-classical  JWT signed with RS256/ES256 (long-lived tokens are HNDL surfaces)
//
// Detection runs over the comment-stripped source. Recognizes:
//   JavaScript/TypeScript — node crypto, jsencrypt, node-forge, jsonwebtoken
//   Python                — cryptography, pycryptodome, paramiko, PyJWT
//   Java                  — KeyPairGenerator, Signature, KeyAgreement
//   Go                    — crypto/rsa, crypto/ecdsa, crypto/ecdh, crypto/dsa
//   C#                    — RSACryptoServiceProvider, RSA.Create, ECDsa.Create
//   C/C++ (OpenSSL)       — RSA_generate_key, EVP_PKEY_RSA, EC_KEY_new_by_curve
//
// HNDL severity bumps: a hit inside a routine handling PII / secrets / TLS
// is upgraded to high. A naked RSA keygen in a CLI demo stays medium.
//
// Opt-out: AGENTIC_SECURITY_NO_PQC=1 disables the module entirely.

import { blankComments } from './_comment-strip.js';

const _CRYPTO_RELEVANCE = [
  /\bcrypto\b/, /\bRSA\b/, /\bECDSA\b/, /\bECDH\b/, /\bEd25519\b/, /\bX25519\b/,
  /\bDiffie[-_]?Hellman\b/i, /\bDH\b/, /\bDSA\b/,
  /\bjsonwebtoken\b/, /\bPyJWT\b/, /\bjwt\b/i,
  /\bcryptography\b/, /\bpycryptodome\b/, /\bparamiko\b/,
  /\bKeyPairGenerator\b/, /\bSignature\b/, /\bKeyAgreement\b/,
  /\bOpenSSL\b/i, /\bEVP_PKEY\b/, /\bRSA_generate\b/, /\bEC_KEY_\b/,
  /\bRSACryptoServiceProvider\b/, /\bECDsa\b/,
];

function _isCryptoRelevant(text) {
  return _CRYPTO_RELEVANCE.some(re => re.test(text));
}

const _HNDL_HINTS = [
  /\bpii\b/i, /\bpersonal\b/i, /\bssn\b/i, /\bemail\b/i, /\bpassword\b/i,
  /\bsecret\b/i, /\bcredential\b/i, /\btoken\b/i, /\bsession\b/i,
  /\bencrypt(?:ed|ing)?\b/i, /\bwrap(?:ped)?\b/i, /\btls\b/i, /\bhttps?\b/i,
  /\bcustomer\b/i, /\bmedical\b/i, /\bphi\b/i, /\bhipaa\b/i, /\bgdpr\b/i,
];

function _hndlContext(rawSlice) {
  return _HNDL_HINTS.some(re => re.test(rawSlice));
}

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }
function _context(raw, line, half = 8) {
  const lines = raw.split('\n');
  const start = Math.max(0, line - 1 - half);
  const end = Math.min(lines.length, line - 1 + half);
  return lines.slice(start, end).join('\n');
}

const PQC_REPLACEMENTS = {
  'rsa-encrypt':  { primary: 'ML-KEM-768', alt: 'ML-KEM-1024 (192-bit security)', hybrid: 'X25519+ML-KEM-768 (CNSA 2.0 transitional)' },
  'rsa-sign':     { primary: 'ML-DSA-65',  alt: 'ML-DSA-87 / SLH-DSA-SHA2-128s (stateless hash-based)', hybrid: 'RSA-3072 + ML-DSA-65 (composite signature)' },
  'ecdsa-sign':   { primary: 'ML-DSA-65',  alt: 'FALCON-512 (smaller signatures) / SLH-DSA (conservative)', hybrid: 'ECDSA-P256 + ML-DSA-65' },
  'ecdh-kex':     { primary: 'ML-KEM-768', alt: 'ML-KEM-1024', hybrid: 'X25519 + ML-KEM-768 (RFC 9794)' },
  'dh-kex':       { primary: 'ML-KEM-768', alt: 'ML-KEM-1024', hybrid: 'ML-KEM-768 only — classical DH is end-of-life' },
  'dsa':          { primary: 'ML-DSA-65',  alt: 'SLH-DSA', hybrid: 'no hybrid — DSA is already deprecated' },
  'x25519':       { primary: 'ML-KEM-768', alt: 'ML-KEM-1024', hybrid: 'X25519 + ML-KEM-768' },
  'ed25519':      { primary: 'ML-DSA-65',  alt: 'FALCON-512', hybrid: 'Ed25519 + ML-DSA-65 (composite)' },
};

function _findingShape(file, raw, line, ruleId, subfamily, useCase, family, isHndl) {
  const replacement = PQC_REPLACEMENTS[useCase] || { primary: 'ML-KEM/ML-DSA', alt: '—', hybrid: '—' };
  return {
    id: `${ruleId}:${file}:${line}`,
    file, line,
    severity: isHndl ? 'high' : 'medium',
    confidence: 0.85,
    stride: 'Information Disclosure',
    snippet: _snip(raw, line),
    parser: 'PQC',
    family: 'pqc-migration',
    subfamily,
    cwe: 'CWE-327',
    vuln: `Pre-quantum ${family.toUpperCase()} (${useCase}) — replace with ${replacement.primary} before CRQC arrives`,
    description: isHndl
      ? `${family.toUpperCase()} appears alongside PII / secrets / TLS context. HNDL exposure: any traffic captured today is decryptable when a cryptographically-relevant quantum computer arrives. NIST recommends migration complete by 2035; federal mandates set 2030 for high-impact systems.`
      : `${family.toUpperCase()} is vulnerable to Shor's algorithm. Schedule migration to post-quantum primitives. NIST finalized FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) in 2024.`,
    remediation: [
      `Recommended replacement: **${replacement.primary}**`,
      `Alternative: ${replacement.alt}`,
      `Hybrid (transitional): ${replacement.hybrid}`,
      'See NIST IR 8547 (migration to PQC) and CNSA 2.0 timeline. Open-source libraries: liboqs (C), open-quantum-safe/oqs-provider (OpenSSL 3 provider), pq-crystals (reference impls).',
    ].join('\n'),
    pqcRecommendation: replacement,
    hndlCritical: isHndl,
  };
}

// ── Detectors ──────────────────────────────────────────────────────────────

function detectJavaScript(file, raw, code, out, seen) {
  const patterns = [
    // node crypto: generateKeyPair('rsa', ...) / generateKeyPairSync('rsa')
    { re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"`]rsa['"`]/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"`]ec['"`]/g, sub: 'pqc-ecdh-kex', use: 'ecdh-kex', fam: 'ec' },
    { re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"`]dsa['"`]/g, sub: 'pqc-dsa', use: 'dsa', fam: 'dsa' },
    { re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"`]dh['"`]/g, sub: 'pqc-dh-kex', use: 'dh-kex', fam: 'dh' },
    { re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"`]x25519['"`]/g, sub: 'pqc-x25519', use: 'x25519', fam: 'x25519' },
    { re: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"`]ed25519['"`]/g, sub: 'pqc-ed25519', use: 'ed25519', fam: 'ed25519' },
    // createSign('RSA-SHA*') / createVerify
    { re: /\bcreate(?:Sign|Verify)\s*\(\s*['"`]RSA-SHA/g, sub: 'pqc-rsa-sign', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bcreate(?:Sign|Verify)\s*\(\s*['"`]ecdsa/gi, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    // publicEncrypt / privateDecrypt (RSA encryption path)
    { re: /\bpublicEncrypt\s*\(|\bprivateDecrypt\s*\(/g, sub: 'pqc-rsa-encrypt', use: 'rsa-encrypt', fam: 'rsa' },
    // diffieHellman
    { re: /\bcreateDiffieHellman\s*\(|\bcreateECDH\s*\(/g, sub: 'pqc-dh-kex', use: 'dh-kex', fam: 'dh' },
    // jsonwebtoken algorithms (HNDL-relevant for long-lived JWTs)
    { re: /algorithm\s*:\s*['"`](?:RS|PS)256['"`]/g, sub: 'pqc-jwt-classical', use: 'rsa-sign', fam: 'rsa' },
    { re: /algorithm\s*:\s*['"`]ES256['"`]/g, sub: 'pqc-jwt-classical', use: 'ecdsa-sign', fam: 'ecdsa' },
    // node-forge / jsencrypt
    { re: /\bforge\.pki\.rsa\.generateKeyPair\b/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bnew\s+JSEncrypt\s*\(/g, sub: 'pqc-rsa-encrypt', use: 'rsa-encrypt', fam: 'rsa' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const line = _lineOf(raw, m.index);
      const id = `${p.sub}:${file}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const isHndl = _hndlContext(_context(raw, line));
      out.push(_findingShape(file, raw, line, p.sub, p.sub, p.use, p.fam, isHndl));
    }
  }
}

function detectPython(file, raw, code, out, seen) {
  const patterns = [
    { re: /\brsa\.generate_private_key\s*\(/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bec\.generate_private_key\s*\(/g, sub: 'pqc-ecdh-kex', use: 'ecdh-kex', fam: 'ec' },
    { re: /\bdsa\.generate_private_key\s*\(/g, sub: 'pqc-dsa', use: 'dsa', fam: 'dsa' },
    { re: /\bdh\.generate_parameters\s*\(/g, sub: 'pqc-dh-kex', use: 'dh-kex', fam: 'dh' },
    // pycryptodome
    { re: /\bRSA\.generate\s*\(/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bECC\.generate\s*\(/g, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    { re: /\bDSA\.generate\s*\(/g, sub: 'pqc-dsa', use: 'dsa', fam: 'dsa' },
    // paramiko
    { re: /\bparamiko\.RSAKey\b/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bparamiko\.ECDSAKey\b/g, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    { re: /\bparamiko\.Ed25519Key\b/g, sub: 'pqc-ed25519', use: 'ed25519', fam: 'ed25519' },
    // PyJWT
    { re: /\bjwt\.encode\s*\([^)]*algorithm\s*=\s*['"](?:RS|PS)256['"]/g, sub: 'pqc-jwt-classical', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bjwt\.encode\s*\([^)]*algorithm\s*=\s*['"]ES256['"]/g, sub: 'pqc-jwt-classical', use: 'ecdsa-sign', fam: 'ecdsa' },
    // cryptography hazmat encryption
    { re: /\bpadding\.OAEP\s*\(/g, sub: 'pqc-rsa-encrypt', use: 'rsa-encrypt', fam: 'rsa' },
    { re: /\bpadding\.PKCS1v15\s*\(/g, sub: 'pqc-rsa-sign', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bX25519PrivateKey\.generate\s*\(/g, sub: 'pqc-x25519', use: 'x25519', fam: 'x25519' },
    { re: /\bEd25519PrivateKey\.generate\s*\(/g, sub: 'pqc-ed25519', use: 'ed25519', fam: 'ed25519' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const line = _lineOf(raw, m.index);
      const id = `${p.sub}:${file}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const isHndl = _hndlContext(_context(raw, line));
      out.push(_findingShape(file, raw, line, p.sub, p.sub, p.use, p.fam, isHndl));
    }
  }
}

function detectJava(file, raw, code, out, seen) {
  const patterns = [
    { re: /\bKeyPairGenerator\.getInstance\s*\(\s*"RSA"/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bKeyPairGenerator\.getInstance\s*\(\s*"EC(?:DSA)?"/g, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    { re: /\bKeyPairGenerator\.getInstance\s*\(\s*"DSA"/g, sub: 'pqc-dsa', use: 'dsa', fam: 'dsa' },
    { re: /\bKeyPairGenerator\.getInstance\s*\(\s*"DH"/g, sub: 'pqc-dh-kex', use: 'dh-kex', fam: 'dh' },
    { re: /\bSignature\.getInstance\s*\(\s*"[A-Za-z0-9]+with(?:RSA|RSAandMGF1)"/g, sub: 'pqc-rsa-sign', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bSignature\.getInstance\s*\(\s*"[A-Za-z0-9]+withECDSA"/g, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    { re: /\bSignature\.getInstance\s*\(\s*"Ed25519"/g, sub: 'pqc-ed25519', use: 'ed25519', fam: 'ed25519' },
    { re: /\bKeyAgreement\.getInstance\s*\(\s*"ECDH"/g, sub: 'pqc-ecdh-kex', use: 'ecdh-kex', fam: 'ecdh' },
    { re: /\bKeyAgreement\.getInstance\s*\(\s*"DH"/g, sub: 'pqc-dh-kex', use: 'dh-kex', fam: 'dh' },
    { re: /\bKeyAgreement\.getInstance\s*\(\s*"XDH"/g, sub: 'pqc-x25519', use: 'x25519', fam: 'x25519' },
    { re: /\bCipher\.getInstance\s*\(\s*"RSA[^"]*"/g, sub: 'pqc-rsa-encrypt', use: 'rsa-encrypt', fam: 'rsa' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const line = _lineOf(raw, m.index);
      const id = `${p.sub}:${file}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const isHndl = _hndlContext(_context(raw, line));
      out.push(_findingShape(file, raw, line, p.sub, p.sub, p.use, p.fam, isHndl));
    }
  }
}

function detectGo(file, raw, code, out, seen) {
  const patterns = [
    { re: /\brsa\.GenerateKey\s*\(/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bcrypto\/rsa\b/g, sub: 'pqc-rsa-sign', use: 'rsa-sign', fam: 'rsa' },
    { re: /\becdsa\.GenerateKey\s*\(/g, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    { re: /\bcrypto\/ecdh\b/g, sub: 'pqc-ecdh-kex', use: 'ecdh-kex', fam: 'ecdh' },
    { re: /\bdsa\.GenerateParameters\s*\(/g, sub: 'pqc-dsa', use: 'dsa', fam: 'dsa' },
    { re: /\bed25519\.GenerateKey\s*\(/g, sub: 'pqc-ed25519', use: 'ed25519', fam: 'ed25519' },
    { re: /\brsa\.EncryptOAEP\s*\(|\brsa\.EncryptPKCS1v15\s*\(/g, sub: 'pqc-rsa-encrypt', use: 'rsa-encrypt', fam: 'rsa' },
    { re: /\brsa\.SignPKCS1v15\s*\(|\brsa\.SignPSS\s*\(/g, sub: 'pqc-rsa-sign', use: 'rsa-sign', fam: 'rsa' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const line = _lineOf(raw, m.index);
      const id = `${p.sub}:${file}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const isHndl = _hndlContext(_context(raw, line));
      out.push(_findingShape(file, raw, line, p.sub, p.sub, p.use, p.fam, isHndl));
    }
  }
}

function detectCSharp(file, raw, code, out, seen) {
  const patterns = [
    { re: /\bnew\s+RSACryptoServiceProvider\s*\(/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bRSA\.Create\s*\(/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bECDsa\.Create\s*\(/g, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    { re: /\bECDiffieHellman\.Create\s*\(/g, sub: 'pqc-ecdh-kex', use: 'ecdh-kex', fam: 'ecdh' },
    { re: /\bnew\s+DSACryptoServiceProvider\s*\(/g, sub: 'pqc-dsa', use: 'dsa', fam: 'dsa' },
    { re: /\bRSA\.Create\s*\([^)]*\)\.Encrypt\s*\(/g, sub: 'pqc-rsa-encrypt', use: 'rsa-encrypt', fam: 'rsa' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const line = _lineOf(raw, m.index);
      const id = `${p.sub}:${file}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const isHndl = _hndlContext(_context(raw, line));
      out.push(_findingShape(file, raw, line, p.sub, p.sub, p.use, p.fam, isHndl));
    }
  }
}

function detectCpp(file, raw, code, out, seen) {
  const patterns = [
    { re: /\bRSA_generate_key(?:_ex)?\s*\(/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bEVP_PKEY_keygen\s*\(/g, sub: 'pqc-rsa-keygen', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bEC_KEY_new_by_curve_name\s*\(/g, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    { re: /\bEVP_PKEY_RSA\b|\bEVP_PKEY_RSA_PSS\b/g, sub: 'pqc-rsa-sign', use: 'rsa-sign', fam: 'rsa' },
    { re: /\bEVP_PKEY_EC\b/g, sub: 'pqc-ecdsa-sign', use: 'ecdsa-sign', fam: 'ecdsa' },
    { re: /\bDH_generate_parameters\s*\(|\bDH_generate_key\s*\(/g, sub: 'pqc-dh-kex', use: 'dh-kex', fam: 'dh' },
    { re: /\bEVP_PKEY_X25519\b/g, sub: 'pqc-x25519', use: 'x25519', fam: 'x25519' },
    { re: /\bEVP_PKEY_ED25519\b/g, sub: 'pqc-ed25519', use: 'ed25519', fam: 'ed25519' },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const line = _lineOf(raw, m.index);
      const id = `${p.sub}:${file}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const isHndl = _hndlContext(_context(raw, line));
      out.push(_findingShape(file, raw, line, p.sub, p.sub, p.use, p.fam, isHndl));
    }
  }
}

function detectTlsConfig(file, raw, code, out, seen) {
  // Detect TLS configs that limit groups/curves to classical ones only —
  // a missed opportunity to enable PQ hybrid (x25519_kyber768, etc).
  // Pattern: setEnabledCurves / honorCipherOrder / minProtocolVersion etc.
  const patterns = [
    { re: /\bsetEnabledProtocols\s*\(\s*new\s+String\[\]\s*\{\s*"TLSv1\.[0-2]"/g },
    { re: /\bssl_min_version\s*=\s*['"]TLSv?1\.[0-2]['"]/g },
    { re: /\bgroups?\s*[:=]\s*['"]\s*(?:secp256r1|secp384r1|x25519)[\s'",]*['"]?\s*$/gm },
  ];
  for (const p of patterns) {
    let m;
    while ((m = p.re.exec(code))) {
      const line = _lineOf(raw, m.index);
      const id = `pqc-tls-config:${file}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({
        id, file, line,
        severity: 'medium', confidence: 0.7,
        stride: 'Information Disclosure',
        snippet: _snip(raw, line),
        parser: 'PQC', family: 'pqc-migration',
        subfamily: 'pqc-tls-config',
        cwe: 'CWE-327',
        vuln: 'TLS configuration restricted to classical curves/groups — no PQ-hybrid available',
        description: 'Modern TLS stacks (OpenSSL 3.2+, BoringSSL, Rustls 0.23+) support hybrid PQ key exchange groups such as X25519MLKEM768 (RFC 9794). Restricting groups to classical curves only forecloses negotiating PQ-safe sessions even when the peer supports them — extending HNDL exposure unnecessarily.',
        remediation: 'Enable hybrid PQ groups in TLS configuration. Example: append "X25519MLKEM768" / "P256MLKEM768" to the curves list. See draft-ietf-tls-hybrid-design and oqs-provider docs for ALPN-compatible deployment.',
      });
    }
  }
}

// ── Entry point ────────────────────────────────────────────────────────────

export function scanPqc(fp, raw) {
  if (process.env.AGENTIC_SECURITY_NO_PQC === '1') return [];
  if (!raw || raw.length > 500_000) return [];
  if (!_isCryptoRelevant(raw)) return [];
  const lang = /\.py$/.test(fp) ? 'py' : null;
  const code = blankComments(raw, lang);
  const out = [];
  const seen = new Set();
  try { detectJavaScript(fp, raw, code, out, seen); } catch {}
  try { detectPython(fp, raw, code, out, seen); } catch {}
  try { detectJava(fp, raw, code, out, seen); } catch {}
  try { detectGo(fp, raw, code, out, seen); } catch {}
  try { detectCSharp(fp, raw, code, out, seen); } catch {}
  try { detectCpp(fp, raw, code, out, seen); } catch {}
  try { detectTlsConfig(fp, raw, code, out, seen); } catch {}
  for (const f of out) f.file = fp;
  return out;
}

export const _internals = {
  PQC_REPLACEMENTS, _CRYPTO_RELEVANCE, _isCryptoRelevant, _hndlContext, _HNDL_HINTS,
};
