// Signed rule-pack verification (Sentinel-parity PRD FR-DSL-2; hardened in
// premortems R3.1, 2R3.1, 2R3.2).
//
// Threat model: a malicious PR drops a `.agentic-security/rules/foo.yml`
// into the repo. The next scanner run loads it and:
//   - The rule's regex contains a ReDoS payload → hangs CI.
//   - The rule fires custom-rule findings with attacker-controlled fix
//     replacement strings → potential supply-chain attack via /fix.
//   - The rule's llm_validate prompt exfiltrates context to an attacker
//     endpoint.
//
// Defense (multi-layer):
//
//   1. Every rule file must be Ed25519-signed; the signature lives at
//      `<rulefile>.sig` (raw 64 bytes).
//
//   2. The TRUST ROOT is bundled with the scanner code (BUNDLED_OFFICIAL_KEYS
//      below), NOT read from the project tree by default. An attacker who
//      can drop a `.agentic-security/trusted-keys.json` cannot bootstrap
//      their own key into trust. Project-local keys are honored ONLY when
//      AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1 (audit-logged).
//
//   3. Keys carry an optional `revokedAt` timestamp. A signature is rejected
//      when the rule-file's mtime postdates the revocation, OR the signature's
//      SHA-256 hash appears in the project's `crl[]` array.
//
//   4. Unsigned packs refused unless AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1
//      (audit-logged + findings tagged `_unsigned: true`).

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { statePath } from './state-dir.js';

// Built-in trust root. These are the keys the maintainers of agentic-security
// use to sign official rule packs. Production deployment requires the
// maintainers to generate a real keypair, distribute the private key offline,
// and ship the corresponding public key here on a release. Until then the
// effective behavior is "no official keys, unsigned-only via the opt-in env."
export const BUNDLED_OFFICIAL_KEYS = [
  // {
  //   id: 'agentic-security-official-2026-q1',
  //   alg: 'ed25519',
  //   publicKey: '<base64-32-bytes>',
  //   issuedAt: '2026-01-01T00:00:00Z',
  //   revokedAt: null,
  // },
];

function _trustedKeysPath(scanRoot) {
  return statePath(scanRoot, 'trusted-keys.json');
}

// Load the EFFECTIVE trusted-key set. Composition:
//   1. Always: BUNDLED_OFFICIAL_KEYS (built into the scanner code).
//   2. When AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1: union with
//      .agentic-security/trusted-keys.json from the project tree (logged).
//
// CRL: trusted-keys.json may also carry a top-level `crl` array of revoked
// signature hashes (sha256 of the signature bytes). These apply project-
// locally regardless of opt-in.
export function loadTrustedKeys(scanRoot) {
  const keys = [...BUNDLED_OFFICIAL_KEYS];
  let projectCrl = [];
  const fp = _trustedKeysPath(scanRoot);
  if (fs.existsSync(fp)) {
    let data;
    try { data = JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { data = null; }
    if (data && Array.isArray(data.crl)) projectCrl = data.crl.filter(x => typeof x === 'string');
    if (data && Array.isArray(data.keys)) {
      if (process.env.AGENTIC_SECURITY_ALLOW_PROJECT_KEYS === '1') {
        console.error('agentic-security: WARNING — project-local trusted-keys.json honored (AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1). An attacker who can write to .agentic-security/ can bypass signing — use only on trusted workstations.');
        for (const k of data.keys) {
          if (k && k.publicKey && k.alg === 'ed25519') keys.push(k);
        }
      } else if (data.keys.length > 0) {
        console.error('agentic-security: ignoring project-local trusted-keys.json (set AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1 to honor; audit-logged).');
      }
    }
  }
  Object.defineProperty(keys, '_crl', { value: projectCrl, enumerable: false });
  return keys;
}

// Pass-through warning issued at most once per process.
let _passThroughWarned = false;

// Verify a rule-pack file. Returns one of:
//   { ok: true, keyId: '<id>' }                              // signature valid
//   { ok: true, passThrough: true }                          // bundled trust root empty AND no project keys — pass-through (premortem 3R3.1)
//   { ok: false, reason: 'unsigned', allowUnsigned: bool }   // no sig file
//   { ok: false, reason: 'bad-signature' }                   // sig present but invalid
//   { ok: false, reason: 'no-trusted-keys' }                  // no keys configured (no bundled, no project)
//   { ok: false, reason: 'revoked-key', keyId }               // key revoked + rule mtime > revokedAt
//   { ok: false, reason: 'revoked-signature' }                // signature SHA in project CRL
//   { ok: false, reason: 'read-error' }
//
// PREMORTEM 3R3.1 — pass-through mode. When BUNDLED_OFFICIAL_KEYS is empty
// (today's reality during product bring-up) AND the operator has not opted
// into project-local keys, REFUSING every rule pack trains operators to set
// AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1 permanently — which recreates the
// exact threat model signing was supposed to defend. Instead we accept
// rule packs in pass-through mode with a one-time warning + a _passThrough
// flag on each accepted rule. Operators get visibility AND the gate doesn't
// train them to bypass.
export function verifyRulePack(rulePackPath, trustedKeys) {
  const sigPath = rulePackPath + '.sig';
  if (!fs.existsSync(sigPath)) {
    return { ok: false, reason: 'unsigned', allowUnsigned: process.env.AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS === '1' };
  }
  if (!Array.isArray(trustedKeys) || trustedKeys.length === 0) {
    // Pass-through mode: empty bundled trust root + no project keys.
    // Issue ONE warning per process, then accept with passThrough flag.
    //
    // Premortem 4R-1: CI mode is fail-closed. CI environments are the place
    // where supply-chain compromise gets weaponized, and the per-session stderr
    // warning is invisible there. So when CI=true (or any common CI env-var is
    // set), refuse pass-through entirely. Operators can opt-in by setting
    // AGENTIC_SECURITY_ALLOW_PASSTHROUGH_IN_CI=1 — making the bypass an
    // intentional, auditable decision rather than the silent default.
    const inCi = !!(
      process.env.CI ||
      process.env.GITHUB_ACTIONS ||
      process.env.GITLAB_CI ||
      process.env.BUILDKITE ||
      process.env.CIRCLECI ||
      process.env.JENKINS_URL ||
      process.env.TF_BUILD
    );
    const allowPassThroughInCi = process.env.AGENTIC_SECURITY_ALLOW_PASSTHROUGH_IN_CI === '1';
    if (BUNDLED_OFFICIAL_KEYS.length === 0 && process.env.AGENTIC_SECURITY_STRICT_SIGNING !== '1') {
      if (inCi && !allowPassThroughInCi) {
        return {
          ok: false,
          reason: 'pass-through-disabled-in-ci',
          remediation: 'CI run detected with no signing keys configured. Either (a) set AGENTIC_SECURITY_ALLOW_PASSTHROUGH_IN_CI=1 to accept unsigned rule packs in this CI run, or (b) configure project keys in .agentic-security/trusted-keys.json and set AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1.',
        };
      }
      if (!_passThroughWarned) {
        _passThroughWarned = true;
        console.error('agentic-security: signed-rule-pack defense in PASS-THROUGH mode.');
        console.error('  · No bundled official keys are baked into this release.');
        console.error('  · Rule packs will be ACCEPTED, tagged _passThroughSigning:true.');
        console.error('  · To switch to refuse-mode set AGENTIC_SECURITY_STRICT_SIGNING=1.');
        console.error('  · To honor project-local trusted-keys.json, set AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1.');
      }
      return { ok: true, passThrough: true };
    }
    return { ok: false, reason: 'no-trusted-keys' };
  }
  let body, sig, ruleMtime;
  try {
    body = fs.readFileSync(rulePackPath);
    sig  = fs.readFileSync(sigPath);
    ruleMtime = fs.statSync(rulePackPath).mtime;
  } catch { return { ok: false, reason: 'read-error' }; }
  // CRL check first — independent of which key signed.
  const sigHash = crypto.createHash('sha256').update(sig).digest('hex');
  const crl = trustedKeys._crl || [];
  if (crl.includes(sigHash)) return { ok: false, reason: 'revoked-signature' };
  for (const k of trustedKeys) {
    try {
      const keyBytes = Buffer.from(k.publicKey, 'base64');
      if (keyBytes.length !== 32) continue;
      const keyObj = crypto.createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: keyBytes.toString('base64url') },
        format: 'jwk',
      });
      const valid = crypto.verify(null, body, keyObj, sig);
      if (!valid) continue;
      // Signature is valid by this key. Check revocation.
      if (k.revokedAt) {
        const revokedAt = new Date(k.revokedAt);
        if (Number.isFinite(revokedAt.getTime()) && ruleMtime > revokedAt) {
          return { ok: false, reason: 'revoked-key', keyId: k.id || '(unnamed)' };
        }
      }
      return { ok: true, keyId: k.id || '(unnamed)' };
    } catch { /* try next key */ }
  }
  return { ok: false, reason: 'bad-signature' };
}

// CLI helper — generate an Ed25519 key pair. Returns { publicKey, privateKey }
// as base64 strings.
export function keygen() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubRaw  = publicKey.export({ format: 'jwk' }).x;     // base64url
  const privRaw = privateKey.export({ format: 'jwk' }).d;    // base64url
  return {
    publicKey:  Buffer.from(pubRaw, 'base64url').toString('base64'),
    privateKey: Buffer.from(privRaw, 'base64url').toString('base64'),
  };
}

// Sign a rule-pack file. Writes <path>.sig as raw 64 bytes.
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
