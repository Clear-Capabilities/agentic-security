// FR-505 (assurance-hardening PRD): "Sign evidence manifests when signing
// is configured | Signature verification detects altered findings, scope,
// policy, or evidence references."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ensureKeyPair } from '../src/posture/evidence-bundle.js';
import {
  signComplianceEvidence, verifyComplianceEvidence, canonicalComplianceEvidenceBytes,
  loadSigningKeyIfConfigured, COMPLIANCE_EVIDENCE_SCHEMA,
} from '../src/posture/compliance-evidence-signing.js';
import { loadPolicy, verifyPolicy, emitEvidenceJsonLd } from '../src/posture/compliance-policy.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'scanner', 'bin', 'agentic-security.js');

function tmpKeyDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-sign-key-'));
}

function sampleDoc(overrides = {}) {
  return {
    '@context': { '@vocab': 'x', schema: 'y' },
    '@type': 'ComplianceEvidence',
    framework: 'SOC2-light',
    version: '1.0',
    generatedAt: '2026-08-25T00:00:00.000Z',
    disclaimer: 'automated technical assessment only',
    provenance: { engineVersion: '0.143.0' },
    evidenceDigest: 'a'.repeat(64),
    summary: { total: 1, compliant: 1, nonCompliant: 0, notApplicable: 0, stale: 0, gap: 0 },
    controls: [{ '@type': 'Control', id: 'CC6.1', title: 'x', status: 'compliant', checks: [], narrative_evidence: [] }],
    ...overrides,
  };
}

// ── sign + verify round trip ─────────────────────────────────────────────

test('signComplianceEvidence + verifyComplianceEvidence: a genuine document verifies', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  const signed = signComplianceEvidence(sampleDoc(), kp.privateKeyPem);
  const r = verifyComplianceEvidence(signed, kp.publicKeyPem);
  assert.equal(r.ok, true, r.reason);
});

test('verifyComplianceEvidence: signed with a DIFFERENT key fails', () => {
  const signer = ensureKeyPair(tmpKeyDir());
  const other = ensureKeyPair(tmpKeyDir());
  const signed = signComplianceEvidence(sampleDoc(), signer.privateKeyPem);
  assert.equal(verifyComplianceEvidence(signed, other.publicKeyPem).ok, false);
});

test('verifyComplianceEvidence (tamper): editing a control status after signing is detected', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  const signed = signComplianceEvidence(sampleDoc(), kp.privateKeyPem);
  const tampered = { ...signed, controls: [{ ...signed.controls[0], status: 'non-compliant' }] };
  const r = verifyComplianceEvidence(tampered, kp.publicKeyPem);
  assert.equal(r.ok, false);
  assert.match(r.reason, /modified after signing/);
});

test('verifyComplianceEvidence (tamper): editing a check reason or narrative evidence (NOT covered by evidenceDigest alone) is still detected', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  const doc = sampleDoc({ controls: [{ '@type': 'Control', id: 'CC6.1', title: 'x', status: 'compliant', checks: [{ '@type': 'Check', rule: { 'file-exists': 'x' }, passed: true, reason: 'x exists' }], narrative_evidence: ['policy doc present'] }] });
  const signed = signComplianceEvidence(doc, kp.privateKeyPem);
  const tampered = { ...signed, controls: [{ ...signed.controls[0], narrative_evidence: ['policy doc present', 'FABRICATED extra claim'] }] };
  const r = verifyComplianceEvidence(tampered, kp.publicKeyPem);
  assert.equal(r.ok, false, 'narrative_evidence must be covered by the signature, not just the FR-504 digest');
});

test('verifyComplianceEvidence (EA-03 discipline): a field stapled on AFTER signing is rejected', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  const signed = signComplianceEvidence(sampleDoc(), kp.privateKeyPem);
  const stapled = { ...signed, extraClaim: 'trust me' };
  const r = verifyComplianceEvidence(stapled, kp.publicKeyPem);
  assert.equal(r.ok, false);
  assert.match(r.reason, /unrecognised top-level key/);
});

test('verifyComplianceEvidence: an unsigned document is rejected', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  assert.equal(verifyComplianceEvidence(sampleDoc(), kp.publicKeyPem).ok, false);
});

test('verifyComplianceEvidence: no public key supplied is rejected, not thrown', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  const signed = signComplianceEvidence(sampleDoc(), kp.privateKeyPem);
  assert.doesNotThrow(() => verifyComplianceEvidence(signed, null));
  assert.equal(verifyComplianceEvidence(signed, null).ok, false);
});

test('canonicalComplianceEvidenceBytes: key order does not change the canonical bytes', () => {
  const a = sampleDoc();
  const b = { controls: a.controls, summary: a.summary, ...a }; // same content, different insertion order
  assert.deepEqual(canonicalComplianceEvidenceBytes(a), canonicalComplianceEvidenceBytes(b));
});

// ── loadSigningKeyIfConfigured: the opt-in check ─────────────────────────

test('loadSigningKeyIfConfigured: no key present returns null, never throws', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-sign-nohome-'));
  const prev = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = home;
  try {
    assert.doesNotThrow(() => loadSigningKeyIfConfigured());
    assert.equal(loadSigningKeyIfConfigured(), null);
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('loadSigningKeyIfConfigured: a pre-existing key (e.g. from a prior `attest` run) is picked up', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-sign-home-'));
  const prev = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = home;
  try {
    ensureKeyPair(); // generates at the default (now redirected) location
    const kp = loadSigningKeyIfConfigured();
    assert.ok(kp, 'expected a configured key to be found');
    assert.ok(kp.privateKeyPem.includes('PRIVATE KEY'));
    assert.ok(kp.publicKeyPem.includes('PUBLIC KEY'));
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ── real end-to-end through emitEvidenceJsonLd + the real CLI ───────────

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'compliance-sign-session-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: async () => fsp.rm(dir, { recursive: true, force: true }) };
}

test('emitEvidenceJsonLd: no signing key configured emits an UNSIGNED document — unchanged, backward-compatible default', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-sign-emit-nohome-'));
  const prev = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = home;
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    requires:
      - finding-family: "hardcoded-secret"
        must-be: zero
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    const jsonld = emitEvidenceJsonLd(report, sess.dir);
    assert.equal(jsonld.signature, undefined);
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
    await sess.cleanup();
  }
});

test('emitEvidenceJsonLd: a configured signing key produces a SIGNED, self-verifying document', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-sign-emit-home-'));
  const prev = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = home;
  const sess = await mkSession();
  try {
    const kp = ensureKeyPair();
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'compliance.policy.yml'), `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    requires:
      - finding-family: "hardcoded-secret"
        must-be: zero
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    const jsonld = emitEvidenceJsonLd(report, sess.dir);
    assert.ok(jsonld.signature, 'expected a signature once a key is configured');
    assert.equal(verifyComplianceEvidence(jsonld, kp.publicKeyPem).ok, true);
    // The persisted artifact on disk must be the SIGNED version, not the pre-signature one.
    const onDisk = JSON.parse(await fsp.readFile(path.join(sess.dir, '.agentic-security', 'compliance-evidence.json'), 'utf8'));
    assert.ok(onDisk.signature);
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
    await sess.cleanup();
  }
});

test('verify-attestation (real CLI): auto-detects and verifies a signed compliance evidence manifest', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-sign-cli-home-'));
  const sess = await mkSession();
  try {
    const kp = ensureKeyPair(path.join(home, 'agentic-security'));
    const doc = sampleDoc();
    const signed = signComplianceEvidence(doc, kp.privateKeyPem);
    const docFile = path.join(sess.dir, 'compliance-evidence.json');
    await fsp.writeFile(docFile, JSON.stringify(signed, null, 2));
    const pubKeyFile = path.join(sess.dir, 'pub.pem');
    await fsp.writeFile(pubKeyFile, kp.publicKeyPem);

    const r = spawnSync(process.execPath, [CLI, 'verify-attestation', docFile, '--public-key', pubKeyFile], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 30_000 });
    assert.equal(r.status, 0, `expected exit 0: ${r.stderr}`);
    assert.match(r.stdout, /VALID — the compliance evidence manifest/);
    assert.match(r.stdout, /framework: SOC2-light/);

    // Tamper, re-verify — must fail.
    const tampered = { ...signed, summary: { ...signed.summary, compliant: 999 } };
    await fsp.writeFile(docFile, JSON.stringify(tampered, null, 2));
    const r2 = spawnSync(process.execPath, [CLI, 'verify-attestation', docFile, '--public-key', pubKeyFile], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 30_000 });
    assert.notEqual(r2.status, 0);
    assert.match(r2.stderr, /INVALID/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    await sess.cleanup();
  }
});

// FR-508: schemaVersion/statusSemantics/policySource are real, signed
// fields — the allowlist in this module was updated alongside the DSL
// change that introduced them (its own header says this must stay in
// sync); prove that by tampering with each and confirming detection,
// exactly the same way FR-505's own fields are already covered.

test('verifyComplianceEvidence (FR-508): tampering with schemaVersion is detected', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  const signed = signComplianceEvidence(sampleDoc({ schemaVersion: 1 }), kp.privateKeyPem);
  const tampered = { ...signed, schemaVersion: 999 };
  assert.equal(verifyComplianceEvidence(tampered, kp.publicKeyPem).ok, false);
});

test('verifyComplianceEvidence (FR-508): tampering with statusSemantics is detected', () => {
  const kp = ensureKeyPair(tmpKeyDir());
  const doc = sampleDoc({ statusSemantics: { compliant: 'real definition' } });
  const signed = signComplianceEvidence(doc, kp.privateKeyPem);
  const tampered = { ...signed, statusSemantics: { compliant: 'a falsified, softer definition' } };
  assert.equal(verifyComplianceEvidence(tampered, kp.publicKeyPem).ok, false);
});
