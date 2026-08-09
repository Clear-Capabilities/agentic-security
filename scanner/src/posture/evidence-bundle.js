// Per-finding evidence bundles, signed so a THIRD PARTY can verify them.
// PRD Phase 2 / D2.
//
// WHAT WAS MISSING
// ----------------
// `attestation.js` already turns a run into a checkable digest, and it is
// explicit about its own ceiling: the signature is a per-install SYMMETRIC HMAC,
// so it is "tamper-evidence for the operator, not third-party non-repudiation."
// Anyone who can verify it can also forge it. That is fine for detecting local
// corruption and useless for handing a finding to somebody else.
//
// This module closes that gap for the artefact that actually travels: a single
// finding plus the evidence behind it. A buyer, an auditor, or a downstream
// consumer can check the bundle with the PUBLIC key alone, having never had
// access to ours.
//
// WHY A SEPARATE MODULE RATHER THAN EXTENDING attestation.js
// ----------------------------------------------------------
// They answer different questions and must not be conflated. A run attestation
// says "this set of findings came from this engine, ruleset and bundle". An
// evidence bundle says "THIS finding is backed by THIS evidence, and here is
// proof the claim was not edited after the fact." One is about reproducibility,
// the other about portability. Merging them would produce an artefact that is
// worse at both.
//
// WHAT A BUNDLE PROVES, AND WHAT IT DOES NOT
// -------------------------------------------
// PROVES — the bundle's contents are exactly what the holder of the signing key
// attested, unmodified. Nothing in it has been added, removed, or edited since.
//
// DOES NOT PROVE — that the finding is real. A signature is an integrity claim,
// never a correctness claim. An `unproven` finding in a signed bundle is still
// an unproven finding; the signature only stops someone silently upgrading the
// word `unproven` to `execution-proven` in transit. Both statements are carried
// INSIDE the bundle so they travel with it and cannot be dropped by a
// summariser.
//
// The evidence chain is deliberately the honest one this engine already
// computes: the proof tier, what the sandbox observed, which backend ran it, the
// taint path if there is one. A bundle for a regex finding says so plainly
// rather than dressing it up.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

export const BUNDLE_SCHEMA = 'agentic-security/finding-evidence@1';

/** Where the Ed25519 signing key lives. Mirrors integrity.js's key handling. */
function keyDir() {
  const xdg = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(xdg, 'agentic-security');
}
const PRIVATE_KEY_FILE = 'attest-key.pem';
const PUBLIC_KEY_FILE = 'attest-key.pub.pem';

export function keyPaths(dir = keyDir()) {
  return {
    privateKey: path.join(dir, PRIVATE_KEY_FILE),
    publicKey: path.join(dir, PUBLIC_KEY_FILE),
  };
}

/**
 * Load the signing key pair, generating one on first use.
 *
 * Ed25519 from node:crypto — no new dependency, and deliberately not a
 * transparency-log scheme: those need a network round trip, and this project
 * does not make runtime cloud calls. A log-backed option can layer on later
 * without changing the bundle format.
 */
export function ensureKeyPair(dir = keyDir()) {
  const p = keyPaths(dir);

  // NO existsSync-then-read. This project's own scanner flagged the first
  // version of this function for TOCTOU (CWE-367) and it was right: between an
  // existence check and the read, an attacker who can write this directory can
  // swap the file, and the thing being swapped is a SIGNING KEY. Winning that
  // race means we sign with a key the attacker controls, which defeats the
  // entire point of the module. Read first and treat absence as the exceptional
  // case — there is then no window between the check and the use, because there
  // is no check.
  try {
    const privateKeyPem = fs.readFileSync(p.privateKey, 'utf8');
    const publicKeyPem = fs.readFileSync(p.publicKey, 'utf8');
    if (privateKeyPem && publicKeyPem) {
      return { privateKeyPem, publicKeyPem, created: false, ...p };
    }
  } catch { /* missing or unreadable — fall through and generate */ }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  // `wx` — exclusive create. If another process generated a key between our
  // failed read and this write, we must NOT clobber it: every bundle already
  // signed with that key would silently stop verifying. On collision, re-read
  // and use the winner's key.
  try {
    fs.writeFileSync(p.privateKey, privateKeyPem, { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(p.publicKey, publicKeyPem, { mode: 0o644, flag: 'w' });
    return { privateKeyPem, publicKeyPem, created: true, ...p };
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
    return {
      privateKeyPem: fs.readFileSync(p.privateKey, 'utf8'),
      publicKeyPem: fs.readFileSync(p.publicKey, 'utf8'),
      created: false,
      ...p,
    };
  }
}

/**
 * Canonical bytes for signing.
 *
 * An ALLOWLIST, exactly as attestation.js canonicalises: a field that is not
 * named here is not signed, so a future addition cannot silently enter the
 * signed surface. Sorted keys, so serialisation order cannot change the
 * signature.
 */
export function canonicalBytes(bundle) {
  const signed = {
    schema: bundle.schema,
    finding: bundle.finding,
    evidence: bundle.evidence,
    engine: bundle.engine,
    proves: bundle.proves,
    doesNotProve: bundle.doesNotProve,
  };
  return Buffer.from(canonicalJson(signed), 'utf8');
}

/**
 * Deterministic JSON: keys sorted at EVERY level, arrays order-preserving.
 *
 * Written by hand rather than using JSON.stringify's replacer argument, and the
 * reason matters. The first version of this function did
 * `JSON.stringify(signed, Object.keys(signed).sort())`, believing the array
 * argument was a top-level field allowlist. It is not — a replacer ARRAY is a
 * key filter applied at every nesting depth, so every nested object serialised
 * as `{}` and the signature covered nothing but the two prose strings. A bundle
 * whose severity was edited from `high` to `critical` verified as authentic.
 *
 * That is the worst possible failure for this module: a security feature that
 * appears to work, produces a valid-looking signature, and protects nothing. It
 * was caught by tampering with a bundle and expecting verification to fail —
 * which is why the tamper cases in the test file are not optional extras.
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

const PROVES =
  'The contents of this bundle are exactly what the signer attested, unmodified.';
const DOES_NOT_PROVE =
  'That the finding is real. A signature is an integrity claim, never a correctness ' +
  'claim — read `evidence.proofTier` for how well-supported the finding actually is. ' +
  'An unproven finding in a signed bundle is still an unproven finding.';

/**
 * Build an unsigned bundle from a finding.
 *
 * Everything here is copied from what the engine already computed. Nothing is
 * inferred, and a missing field stays missing rather than being defaulted into
 * something more confident-looking than the truth.
 */
export function buildEvidenceBundle(finding, { engineVersion, rulesetVersion, bundleSha, commit } = {}) {
  if (!finding || typeof finding !== 'object') return null;
  return {
    schema: BUNDLE_SCHEMA,
    finding: {
      id: finding.id ?? null,
      stableId: finding.stableId ?? null,
      severity: finding.severity ?? null,
      file: finding.file ?? null,
      line: finding.line ?? null,
      vuln: finding.vuln ?? null,
      cwe: finding.cwe ?? null,
      family: finding.family ?? null,
      parser: finding.parser ?? null,
    },
    evidence: {
      // The honest chain, in the vocabulary the engine already uses.
      proofTier: finding.proofTier ?? null,
      proofEvidence: finding.proofEvidence ?? null,
      confidence: finding.confidence ?? null,
      exploitability: finding.exploitability ?? null,
      unreachable: finding.unreachable ?? null,
      // Present only for the layers that produce them; absent means absent.
      taintPath: finding.pathSteps ?? finding.exampleFlows ?? null,
      discovery: finding.discovery ?? null,
    },
    engine: {
      engineVersion: engineVersion ?? null,
      rulesetVersion: rulesetVersion ?? null,
      bundleSha: bundleSha ?? null,
      commit: commit ?? null,
    },
    proves: PROVES,
    doesNotProve: DOES_NOT_PROVE,
  };
}

/** Sign a bundle. Returns a new object; the input is not mutated. */
export function signEvidenceBundle(bundle, privateKeyPem) {
  const sig = crypto.sign(null, canonicalBytes(bundle), privateKeyPem);
  return {
    ...bundle,
    signature: {
      algorithm: 'ed25519',
      canonicalisation: BUNDLE_SCHEMA,
      value: sig.toString('base64'),
    },
  };
}

/**
 * Verify a bundle with a PUBLIC key. This is the whole point: the verifier
 * never needs, and never had, the signing key.
 *
 * Returns {ok, reason}. Never throws — a malformed bundle from an untrusted
 * source is an expected input, not an exceptional one.
 */
export function verifyEvidenceBundle(bundle, publicKeyPem) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  if (bundle.schema !== BUNDLE_SCHEMA) return { ok: false, reason: `unrecognised schema: ${bundle.schema}` };
  const sig = bundle.signature;
  if (!sig?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  let ok = false;
  try {
    ok = crypto.verify(null, canonicalBytes(bundle), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  return ok
    ? { ok: true, reason: null }
    : { ok: false, reason: 'signature does not match the bundle contents — it was modified after signing' };
}
