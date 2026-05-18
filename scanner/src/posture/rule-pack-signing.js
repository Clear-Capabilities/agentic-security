// Signed rule-pack verification (Sentinel-parity PRD FR-DSL-2).
//
// Threat model: a malicious PR drops a `.agentic-security/rules/foo.yml`
// into the repo. The next scanner run loads it and:
//   - The rule's regex contains a ReDoS payload → hangs CI.
//   - The rule fires custom-rule findings with attacker-controlled fix
//     replacement strings → potential supply-chain attack via /fix.
//   - The rule's llm_validate prompt exfiltrates context to an attacker
//     endpoint (if the operator wires the LLM endpoint env vars to an
//     attacker URL).
//
// Defense: every rule file must be Ed25519-signed by a trusted key, and
// the signature must be present at `<rulefile>.sig` (binary 64 bytes).
//
// Trusted keys live at `.agentic-security/trusted-keys.json`:
//
//   {
//     "keys": [
//       { "id": "official-2026", "alg": "ed25519", "publicKey": "<base64>" },
//       ...
//     ]
//   }
//
// Unsigned packs are REFUSED unless the operator sets
// AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1 (an audit signal — every such
// load logs a warning and stamps `_unsigned: true` on every emitted finding
// so downstream filtering can identify them).

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const TRUSTED_KEYS_FILE = '.agentic-security/trusted-keys.json';

function _trustedKeysPath(scanRoot) {
  return path.join(scanRoot || process.cwd(), TRUSTED_KEYS_FILE);
}

// Load the trusted-keys file. Returns [] if missing.
export function loadTrustedKeys(scanRoot) {
  const fp = _trustedKeysPath(scanRoot);
  if (!fs.existsSync(fp)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(fp, 'utf8'));
    if (!Array.isArray(data.keys)) return [];
    return data.keys.filter(k => k && k.publicKey && k.alg === 'ed25519');
  } catch { return []; }
}

// Verify a rule-pack file. Returns one of:
//   { ok: true, keyId: '<id>' }                            // signature valid
//   { ok: false, reason: 'unsigned', allowUnsigned: bool } // no sig file
//   { ok: false, reason: 'bad-signature' }                 // sig present but invalid
//   { ok: false, reason: 'no-trusted-keys' }                // no keys configured
//
// When reason='unsigned' AND AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1, the
// caller may load the rule pack but should mark findings _unsigned=true.
export function verifyRulePack(rulePackPath, trustedKeys) {
  const sigPath = rulePackPath + '.sig';
  if (!fs.existsSync(sigPath)) {
    return { ok: false, reason: 'unsigned', allowUnsigned: process.env.AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS === '1' };
  }
  if (!Array.isArray(trustedKeys) || trustedKeys.length === 0) {
    return { ok: false, reason: 'no-trusted-keys' };
  }
  let body, sig;
  try {
    body = fs.readFileSync(rulePackPath);
    sig = fs.readFileSync(sigPath);
  } catch { return { ok: false, reason: 'read-error' }; }
  // Try each trusted key.
  for (const k of trustedKeys) {
    try {
      // The publicKey is base64-encoded raw 32-byte Ed25519 public key.
      const keyBytes = Buffer.from(k.publicKey, 'base64');
      if (keyBytes.length !== 32) continue;
      // Node's crypto.verify requires a KeyObject in DER/PEM. Build via
      // crypto.createPublicKey from the raw 32-byte spki-wrapped DER.
      // Trick: use jwk import — cleaner than ASN.1 hand-rolling.
      const keyObj = crypto.createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: keyBytes.toString('base64url') },
        format: 'jwk',
      });
      const valid = crypto.verify(null, body, keyObj, sig);
      if (valid) return { ok: true, keyId: k.id || '(unnamed)' };
    } catch { /* try next key */ }
  }
  return { ok: false, reason: 'bad-signature' };
}

// CLI helper — generate a key pair. NOT auto-installed; operators run
// `node -e "require(...).keygen()"` and add the result to trusted-keys.json
// themselves.
export function keygen() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ format: 'jwk' }).x;     // base64url
  const privRaw = privateKey.export({ format: 'jwk' }).d;   // base64url
  return {
    publicKey:  Buffer.from(pubRaw, 'base64url').toString('base64'),
    privateKey: Buffer.from(privRaw, 'base64url').toString('base64'),
  };
}

// Sign a rule-pack file. Writes <path>.sig as binary 64 bytes.
export function signRulePack(rulePackPath, privateKeyB64) {
  const body = fs.readFileSync(rulePackPath);
  const privBytes = Buffer.from(privateKeyB64, 'base64');
  if (privBytes.length !== 32) throw new Error('private key must be 32 bytes (raw ed25519)');
  const keyObj = crypto.createPrivateKey({
    key: { kty: 'OKP', crv: 'Ed25519', d: privBytes.toString('base64url') },
    format: 'jwk',
  });
  const sig = crypto.sign(null, body, keyObj);
  fs.writeFileSync(rulePackPath + '.sig', sig);
  return sig;
}
