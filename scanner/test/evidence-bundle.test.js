// Per-finding evidence bundles — third-party-verifiable signing (PRD D2).
//
// THE TAMPER CASES BELOW ARE NOT OPTIONAL EXTRAS. The first implementation of
// `canonicalBytes` used `JSON.stringify(obj, Object.keys(obj).sort())`, believing
// the array argument was a top-level field allowlist. It is not: a replacer
// ARRAY filters keys at EVERY nesting depth, so every nested object serialised
// as `{}` and the signature covered nothing but two prose strings. A bundle
// whose severity had been edited from `high` to `critical` verified as
// authentic.
//
// A security feature that produces a valid-looking signature and protects
// nothing is worse than no feature at all, and only a tamper test finds it. Do
// not delete these.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  ensureKeyPair, buildEvidenceBundle, signEvidenceBundle, verifyEvidenceBundle,
  canonicalJson, BUNDLE_SCHEMA,
} from '../src/posture/evidence-bundle.js';

const tmpKeyDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'attest-'));

const FINDING = {
  id: 'f1', stableId: 's1', severity: 'high', file: 'app.js', line: 42,
  vuln: 'SQL Injection', cwe: 'CWE-89', family: 'injection', parser: 'IR-TAINT',
  proofTier: 'execution-proven',
  proofEvidence: { ran: true, observed: 'PROVEN', backend: 'userspace' },
};

function signed(dir) {
  const kp = ensureKeyPair(dir);
  const bundle = signEvidenceBundle(
    buildEvidenceBundle(FINDING, { engineVersion: '0.134.0', bundleSha: 'abc' }),
    kp.privateKeyPem,
  );
  return { kp, bundle };
}

// ------------------------------------------------------- canonicalisation
test('canonicalJson sorts keys at EVERY level, not just the top', () => {
  // This is the regression test for the bug described in the header.
  const a = canonicalJson({ b: { z: 1, a: 2 }, a: 3 });
  const b = canonicalJson({ a: 3, b: { a: 2, z: 1 } });
  assert.equal(a, b, 'key order must not change the bytes');
  assert.match(a, /"z":1/, 'nested values must actually appear in the output');
  assert.match(a, /"a":2/);
});

test('canonicalJson preserves array order', () => {
  // Order is meaningful in a taint path; sorting it would destroy the evidence.
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
});

// --------------------------------------------------------------- signing
test('a genuine bundle verifies with the PUBLIC key alone', () => {
  const dir = tmpKeyDir();
  const { kp, bundle } = signed(dir);
  const r = verifyEvidenceBundle(bundle, kp.publicKeyPem);
  assert.equal(r.ok, true, r.reason);
});

test('the private key is written 0600 and the pair is reused, not regenerated', () => {
  const dir = tmpKeyDir();
  const first = ensureKeyPair(dir);
  assert.equal(first.created, true);
  assert.equal(fs.statSync(first.privateKey).mode & 0o777, 0o600);
  const second = ensureKeyPair(dir);
  assert.equal(second.created, false);
  assert.equal(second.publicKeyPem, first.publicKeyPem, 'a regenerated key would invalidate every prior bundle');
});

// --------------------------------------------------------------- tampering
test('editing ANY signed field is detected', () => {
  const dir = tmpKeyDir();
  const { kp, bundle } = signed(dir);
  const mutations = {
    'severity': b => { b.finding.severity = 'critical'; },
    'file': b => { b.finding.file = 'elsewhere.js'; },
    'line': b => { b.finding.line = 1; },
    'cwe': b => { b.finding.cwe = 'CWE-79'; },
    'parser': b => { b.finding.parser = 'REGEX'; },
    'proof evidence': b => { b.evidence.proofEvidence.ran = false; },
    'engine version': b => { b.engine.engineVersion = '9.9.9'; },
    'the doesNotProve disclaimer': b => { delete b.doesNotProve; },
    'the whole evidence block': b => { b.evidence = {}; },
  };
  for (const [what, mutate] of Object.entries(mutations)) {
    const t = JSON.parse(JSON.stringify(bundle));
    mutate(t);
    const r = verifyEvidenceBundle(t, kp.publicKeyPem);
    assert.equal(r.ok, false, `editing ${what} must be detected`);
    assert.match(r.reason, /modified after signing/);
  }
});

test('the proof-tier upgrade attack is detected', () => {
  // The realistic abuse: take an unproven finding and promote it in transit so
  // it reads as demonstrated. This is the single most valuable thing the
  // signature buys.
  const dir = tmpKeyDir();
  const kp = ensureKeyPair(dir);
  const weak = { ...FINDING, proofTier: 'unproven', proofEvidence: null, parser: 'REGEX' };
  const bundle = signEvidenceBundle(buildEvidenceBundle(weak, {}), kp.privateKeyPem);
  assert.equal(verifyEvidenceBundle(bundle, kp.publicKeyPem).ok, true);

  const forged = JSON.parse(JSON.stringify(bundle));
  forged.evidence.proofTier = 'execution-proven';
  assert.equal(verifyEvidenceBundle(forged, kp.publicKeyPem).ok, false);
});

test('a different key cannot verify the bundle', () => {
  const { bundle } = signed(tmpKeyDir());
  const stranger = ensureKeyPair(tmpKeyDir());
  assert.equal(verifyEvidenceBundle(bundle, stranger.publicKeyPem).ok, false);
});

// ------------------------------------------------------------ malformed input
test('malformed bundles are rejected with a reason, never thrown on', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  const cases = [
    [null, /not an object/],
    [{}, /unrecognised schema/],
    [{ schema: BUNDLE_SCHEMA }, /unsigned/],
    [{ schema: BUNDLE_SCHEMA, signature: { algorithm: 'rsa', value: 'x' } }, /unsupported algorithm/],
    [{ schema: BUNDLE_SCHEMA, signature: { algorithm: 'ed25519', value: '!!not base64!!' } }, /does not match|verification error/],
  ];
  for (const [input, expected] of cases) {
    const r = verifyEvidenceBundle(input, kp.publicKeyPem);
    assert.equal(r.ok, false);
    assert.match(r.reason, expected);
  }
});

test('verification without a public key fails rather than passing', () => {
  const { bundle } = signed(tmpKeyDir());
  const r = verifyEvidenceBundle(bundle, null);
  assert.equal(r.ok, false);
  assert.match(r.reason, /no public key/);
});

// ------------------------------------------------------------ honest claims
test('the bundle carries what it does and does NOT prove, and both are signed', () => {
  // Both statements travel inside the bundle so a summariser cannot drop the
  // inconvenient one, and both are covered by the signature so neither can be
  // edited into something more flattering.
  const { bundle } = signed(tmpKeyDir());
  assert.match(bundle.proves, /exactly what the signer attested/);
  assert.match(bundle.doesNotProve, /never a correctness claim/);
});

test('an unproven finding stays unproven in its bundle', () => {
  const b = buildEvidenceBundle({ ...FINDING, proofTier: 'unproven', proofEvidence: null }, {});
  assert.equal(b.evidence.proofTier, 'unproven');
  assert.equal(b.evidence.proofEvidence, null, 'a missing field must stay missing, not be defaulted');
});

// ------------------------------------------------------------ injected-key attack
// EA-03 (Stage-0 capability audit, 2026). `canonicalBytes` signs an ALLOWLIST of
// top-level keys (schema/finding/evidence/engine/proves/doesNotProve). The
// tamper tests above only ever EDIT a key already on that allowlist — none of
// them ADD a brand-new top-level key. `verifyEvidenceBundle` never checked for
// unrecognised keys, so a key outside the allowlist is invisible to the
// signature and a bundle can be verified with the attacker's own fabricated
// key stapled on. Reproduced live: `{...bundle, verdict:'CONFIRMED
// EXPLOITABLE', proofLevel:'PROVEN'}` verified {ok:true} against the ORIGINAL
// signature.
test('an injected top-level key outside the signed allowlist is detected, not silently accepted', () => {
  const dir = tmpKeyDir();
  const { kp, bundle } = signed(dir);
  const injected = { ...bundle, verdict: 'CONFIRMED EXPLOITABLE', proofLevel: 'PROVEN' };
  const r = verifyEvidenceBundle(injected, kp.publicKeyPem);
  assert.equal(r.ok, false,
    'a bundle carrying an unsigned, attacker-added top-level key must not verify as authentic');
});

test('a bundle with only the legitimate keys still verifies (guard against over-tightening)', () => {
  const { kp, bundle } = signed(tmpKeyDir());
  const r = verifyEvidenceBundle(bundle, kp.publicKeyPem);
  assert.equal(r.ok, true, r.reason);
});
