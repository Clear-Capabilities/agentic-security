// R4 — determinism as a contract.
//
// The four directions the deliverable requires, each executed:
//   1. same set, shuffled order            -> identical digest
//   2. one finding's severity changed      -> different digest
//   3. one finding removed                 -> different digest
//   4. timestamps / durations differ       -> identical digest
//
// Plus the negative cases that stop the digest from being independent of
// things that ARE real differences (file, line, rule id), and the honest
// limits of what the attestation proves.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  computeRunAttestation,
  verifyRunAttestation,
  ATTESTATION_CANONICALISATION,
} from '../src/posture/attestation.js';

const META = { engineVersion: '9.9.9', rulesetVersion: '9.9.9', bundleSha: 'abc123' };

function corpus() {
  return [
    { id: 'SQLI-1', severity: 'high', file: 'src/db.js', line: 12, vuln: 'SQL Injection', cwe: 'CWE-89',
      scanId: 'run-a', detectedAt: '2026-01-01T00:00:00Z', durationMs: 41 },
    { id: 'CMDI-1', severity: 'critical', file: 'src/exec.js', line: 7, vuln: 'Command Injection', cwe: 'CWE-78',
      scanId: 'run-a', detectedAt: '2026-01-01T00:00:00Z', durationMs: 3 },
    { id: 'MD5-1', severity: 'medium', file: 'src/hash.js', line: 44, vuln: 'Weak Hash', cwe: 'CWE-327',
      scanId: 'run-a', detectedAt: '2026-01-01T00:00:00Z', durationMs: 9 },
  ];
}
const digest = (findings, extra = {}) =>
  computeRunAttestation({ findings, ...META, ...extra }).digest;

// ── direction 1: order independence ─────────────────────────────────────────

test('1. same finding set in shuffled order produces an identical digest', () => {
  const a = corpus();
  const shuffled = [a[2], a[0], a[1]];
  assert.equal(digest(shuffled), digest(a));
  assert.equal(digest([a[1], a[2], a[0]]), digest(a));
});

// ── direction 2: a real difference changes the digest ───────────────────────

test('2. changing one finding severity changes the digest', () => {
  const a = corpus();
  const b = corpus();
  b[0].severity = 'critical';
  assert.notEqual(digest(b), digest(a));
});

test('2b. changing a file, a line, or a rule id each changes the digest', () => {
  const base = digest(corpus());
  const f1 = corpus(); f1[1].file = 'src/other.js';
  const f2 = corpus(); f2[1].line = 8;
  const f3 = corpus(); f3[1].id = 'CMDI-2';
  const f4 = corpus(); f4[1].cwe = 'CWE-77';
  assert.notEqual(digest(f1), base, 'file must matter');
  assert.notEqual(digest(f2), base, 'line must matter');
  assert.notEqual(digest(f3), base, 'rule id must matter');
  assert.notEqual(digest(f4), base, 'cwe must matter');
});

// ── direction 3: appearance / disappearance ─────────────────────────────────

test('3. removing one finding changes the digest', () => {
  const a = corpus();
  const b = corpus().slice(0, 2);
  assert.notEqual(digest(b), digest(a));
  assert.equal(computeRunAttestation({ findings: b, ...META }).findingCount, 2);
});

test('3b. adding a finding changes the digest', () => {
  const a = corpus();
  const b = corpus();
  b.push({ id: 'XSS-1', severity: 'low', file: 'src/v.js', line: 1, vuln: 'XSS', cwe: 'CWE-79' });
  assert.notEqual(digest(b), digest(a));
});

test('3c. a duplicate finding is a real difference, not collapsed away', () => {
  const a = corpus();
  const b = corpus();
  b.push({ ...corpus()[0] });
  assert.notEqual(digest(b), digest(a));
});

// ── direction 4: non-deterministic fields are excluded ──────────────────────

test('4. differing timestamps, durations, scan ids and absolute paths leave the digest identical', () => {
  const a = corpus();
  const b = corpus().map((f, i) => ({
    ...f,
    scanId: 'run-b',
    detectedAt: '2026-07-27T11:22:33Z',
    durationMs: 1000 + i,
    scannedAt: Date.now(),
    elapsed: 1.234,
  }));
  assert.equal(digest(b), digest(a));
});

test('4b. an absolute path relativised against the scan root matches the relative form', () => {
  const rel = corpus();
  const abs = corpus().map(f => ({ ...f, file: `/Users/someone/proj/${f.file}` }));
  assert.equal(
    digest(abs, { root: '/Users/someone/proj' }),
    digest(rel),
  );
  // Windows-style separators normalise to the same canonical form.
  const win = corpus().map(f => ({ ...f, file: f.file.replace(/\//g, '\\') }));
  assert.equal(digest(win), digest(rel));
});

// ── attestation shape + metadata binding ────────────────────────────────────

test('the attestation carries the binding metadata and its canonicalisation id', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META });
  assert.equal(att.algorithm, 'sha256');
  assert.equal(att.findingCount, 3);
  assert.equal(att.engineVersion, '9.9.9');
  assert.equal(att.rulesetVersion, '9.9.9');
  assert.equal(att.bundleSha, 'abc123');
  assert.equal(att.canonicalisation, ATTESTATION_CANONICALISATION);
  assert.match(att.digest, /^[0-9a-f]{64}$/);
});

test('the digest is bound to the engine and ruleset that produced it', () => {
  const base = computeRunAttestation({ findings: corpus(), ...META }).digest;
  assert.notEqual(computeRunAttestation({ findings: corpus(), ...META, engineVersion: '9.9.10' }).digest, base);
  assert.notEqual(computeRunAttestation({ findings: corpus(), ...META, rulesetVersion: '1.0.0' }).digest, base);
  assert.notEqual(computeRunAttestation({ findings: corpus(), ...META, bundleSha: 'def456' }).digest, base);
});

// ── verification ────────────────────────────────────────────────────────────

test('verifyRunAttestation accepts the run it was computed over, in any order', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META });
  const a = corpus();
  const res = verifyRunAttestation(att, { findings: [a[1], a[2], a[0]], ...META });
  assert.equal(res.ok, true, res.reason);
});

test('verifyRunAttestation rejects a mutated finding set and says why', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META });
  const tampered = corpus();
  tampered[0].severity = 'low';
  const res = verifyRunAttestation(att, { findings: tampered, ...META });
  assert.equal(res.ok, false);
  assert.match(res.reason, /digest/i);
});

test('verifyRunAttestation rejects a count mismatch and a version mismatch distinctly', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META });
  const short = verifyRunAttestation(att, { findings: corpus().slice(0, 2), ...META });
  assert.equal(short.ok, false);
  assert.match(short.reason, /count/i);
  const wrongEngine = verifyRunAttestation(att, { findings: corpus(), ...META, engineVersion: '0.0.1' });
  assert.equal(wrongEngine.ok, false);
  assert.match(wrongEngine.reason, /engineVersion/);
});

test('verifyRunAttestation rejects a foreign canonicalisation rather than guessing', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META });
  const res = verifyRunAttestation({ ...att, canonicalisation: 'someone-elses-v2' }, { findings: corpus(), ...META });
  assert.equal(res.ok, false);
  assert.match(res.reason, /canonicalisation/i);
});

test('verifyRunAttestation refuses malformed input instead of throwing', () => {
  assert.equal(verifyRunAttestation(null, { findings: [] }).ok, false);
  assert.equal(verifyRunAttestation({}, { findings: [] }).ok, false);
  assert.doesNotThrow(() => computeRunAttestation({ findings: null }));
  assert.equal(computeRunAttestation({ findings: null }).findingCount, 0);
  assert.doesNotThrow(() => computeRunAttestation({ findings: [null, undefined, {}] }));
});

// ── optional signature (per-install HMAC, reused from integrity.js) ─────────

test('a signed attestation verifies on this install and fails on a tampered digest', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META, sign: true });
  assert.match(att.signature, /^[0-9a-f]{64}$/);
  assert.equal(att.signatureScope, 'per-install-hmac');
  assert.equal(verifyRunAttestation(att, { findings: corpus(), ...META }).ok, true);
  const forged = { ...att, digest: 'f'.repeat(64) };
  const res = verifyRunAttestation(forged, { findings: corpus(), ...META });
  assert.equal(res.ok, false);
});

test('an unsigned attestation still verifies structurally (signature is optional)', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META });
  assert.equal(att.signature, undefined);
  assert.equal(verifyRunAttestation(att, { findings: corpus(), ...META }).ok, true);
});

// ── the honest limit ────────────────────────────────────────────────────────

test('the attestation states what it does NOT prove', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META });
  assert.ok(typeof att.proves === 'string' && att.proves.length > 0);
  assert.ok(typeof att.doesNotProve === 'string' && att.doesNotProve.length > 0);
  assert.match(att.doesNotProve, /machine/i);
});
