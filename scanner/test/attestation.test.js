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

// Stage 5 correctness audit: integrity.js's _readOrGenerateKey has no
// exclusivity on its key-file write (plain fs.writeFileSync, default 'w').
// On first use (no key file yet), concurrent processes each generate their
// OWN random key in memory, then race to persist it — the last writer wins
// on disk, but every OTHER process keeps signing with the key it generated
// and lost, which now exists nowhere. Every signature made under a lost key
// fails verification forever after, indistinguishable from real tampering.
// evidence-bundle.js's ensureKeyPair() already guards against the identical
// race for its own (Ed25519) key material via exclusive-create ('wx') +
// re-read-on-EEXIST; that fix was never applied to this (HMAC) twin. Real
// concurrency, not a mock: N processes are held at a synchronization
// barrier so they all reach key generation at (as close to) the same
// instant, forcing the actual race window.
test('concurrent first-use does not produce signatures that fail to verify later', async () => {
  const { spawn } = await import('node:child_process');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const tmpConfig = fs.mkdtempSync(path.join(os.tmpdir(), 'integrity-race-'));
  const barrierDir = fs.mkdtempSync(path.join(os.tmpdir(), 'integrity-race-barrier-'));
  const childScript = path.join(barrierDir, 'child.mjs');
  const N = 8;
  const findings = corpus();
  fs.writeFileSync(childScript, `
import * as fs from 'node:fs';
const [,, outFile, barrierDir, n] = process.argv;
fs.writeFileSync(barrierDir + '/ready-' + process.pid, '1');
while (fs.readdirSync(barrierDir).filter(f => f.startsWith('ready-')).length < Number(n)) { /* busy-wait */ }
const { computeRunAttestation } = await import(${JSON.stringify(path.join(process.cwd(), 'src/posture/attestation.js'))});
const att = computeRunAttestation({ findings: ${JSON.stringify(findings)}, ...${JSON.stringify(META)}, sign: true });
fs.writeFileSync(outFile, JSON.stringify(att));
`);
  const outFiles = Array.from({ length: N }, (_, i) => path.join(tmpConfig, `att-${i}.json`));
  await Promise.all(outFiles.map(out => new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [childScript, out, barrierDir, String(N)], {
      env: { ...process.env, XDG_CONFIG_HOME: tmpConfig, AGENTIC_SECURITY_HMAC_KEY: '' },
    });
    let err = '';
    p.stderr.on('data', (d) => { err += d; });
    p.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`exit ${code}: ${err}`)));
    p.on('error', reject);
  })));
  // Verify in a FRESH subprocess with the same isolated XDG_CONFIG_HOME —
  // not in this test-file's own process, whose integrity.js module-level
  // key cache may already hold this machine's real per-install key from an
  // earlier test in this same file (module state is cached per-process,
  // not per-test), which would read the wrong key file regardless of
  // whether the source fix works.
  const verifyScript = path.join(barrierDir, 'verify.mjs');
  fs.writeFileSync(verifyScript, `
import * as fs from 'node:fs';
const { verifyRunAttestation } = await import(${JSON.stringify(path.join(process.cwd(), 'src/posture/attestation.js'))});
const findings = ${JSON.stringify(findings)};
const results = ${JSON.stringify(outFiles)}.map((out) => {
  const att = JSON.parse(fs.readFileSync(out, 'utf8'));
  const v = verifyRunAttestation(att, { findings, ...${JSON.stringify(META)} });
  return { file: out, ok: v.ok, reason: v.reason };
});
process.stdout.write(JSON.stringify(results));
`);
  const verifyOut = await new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [verifyScript], {
      env: { ...process.env, XDG_CONFIG_HOME: tmpConfig, AGENTIC_SECURITY_HMAC_KEY: '' },
    });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('exit', (code) => code === 0 ? resolve(out) : reject(new Error(`verify exit ${code}: ${err}`)));
    p.on('error', reject);
  });
  const results = JSON.parse(verifyOut);
  const failures = results.filter(r => !r.ok);
  assert.equal(failures.length, 0,
    `expected all ${N} concurrently-generated signatures to verify; ${failures.length} failed:\n${JSON.stringify(failures, null, 2)}`);
});

// ── the honest limit ────────────────────────────────────────────────────────

test('the attestation states what it does NOT prove', () => {
  const att = computeRunAttestation({ findings: corpus(), ...META });
  assert.ok(typeof att.proves === 'string' && att.proves.length > 0);
  assert.ok(typeof att.doesNotProve === 'string' && att.doesNotProve.length > 0);
  assert.match(att.doesNotProve, /machine/i);
});
