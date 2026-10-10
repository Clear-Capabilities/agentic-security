#!/usr/bin/env node
// A local, offline assurance review walk-through (DOC-003.AC02, DOC-003.AC03).
//
//   node scripts/assurance-review-example.mjs
//
// A SYNTHETIC release manifest (flagged `synthetic: true`, describing no real release) is exported as a portable bundle, signed
// with a throwaway local key in the signer domain, and then reviewed the way a reviewer with only the bundle, the claim and a
// trust-root policy would review it. Each step prints what the verifier says:
//
//   1. a valid claim: what the signature shows (the manifest is unmodified) and what it does not (independent certification);
//   2. incomplete scope: the headline says so and the gap is named, the signature stays valid;
//   3. a waiver: the waiver, its reason and its approver are in the statement;
//   4. a modified evidence blob, an edited claim, an unknown key and a revoked key are each rejected with a typed code;
//   5. what a claim does NOT carry: there is no validity period in a signed claim in this build;
//   6. a worker or verifier domain asking to sign is refused before any key is used.
//
// Nothing touches a network, a provider or the machine's real signing key: the key pair is generated in memory and the bundle
// lives in a disposable folder that is removed at the end. No step reads from a terminal.
//
// Exit: 0 every step behaved as described / 1 one did not.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { signAssuranceClaim, verifyAssuranceClaim, buildTrustPolicy } from '../scanner/src/posture/portfolio/signing.js';
import { assuranceStatement } from '../scanner/src/posture/portfolio/wording.js';
import { INDEX_FILE, BLOB_DIR } from '../scanner/src/posture/portfolio/bundle.js';
import { DOMAINS } from '../scanner/src/sandbox/trust-domains.js';
import { exportSynthetic, syntheticManifest, manifestFacts } from '../scanner/test/portfolio/helpers.js';

let failed = 0;
const check = (ok, what) => { console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) failed++; };
const say = (s) => console.log(s);
const keys = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) };
};
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'assurance-example-'));
const SIGNER = 'release-signer@example.test';
function release(name, manifest) {
  const dir = path.join(work, name);
  exportSynthetic(dir, manifest ? { manifest } : {});
  const k = keys();
  const policy = buildTrustPolicy({ roots: [{ publicKeyPem: k.publicKeyPem, signerId: SIGNER }] });
  const envelope = signAssuranceClaim({ domain: DOMAINS.SIGNER, bundleDir: dir, privateKeyPem: k.privateKeyPem, signerId: SIGNER });
  return { dir, k, policy, envelope };
}
const indent = (t) => String(t).split('\n').map((l) => `    | ${l}`).join('\n');

try {
  say('1. a valid claim (the synthetic manifest has one incomplete mandatory check, so its scope is not full)');
  const a = release('valid');
  const v = verifyAssuranceClaim({ envelope: a.envelope, trustPolicy: a.policy, bundleDir: a.dir });
  check(v.ok === true && v.trustBasis === 'self-issued-local-key' && v.independentlyCertified === false, `verified offline; trust basis ${v.trustBasis}; independentlyCertified ${v.independentlyCertified}`);
  const manifest = JSON.parse(fs.readFileSync(path.join(a.dir, BLOB_DIR, JSON.parse(fs.readFileSync(path.join(a.dir, INDEX_FILE), 'utf8')).entries.find((e) => e.role === 'manifest').digest.slice(7)), 'utf8'));
  say(indent(assuranceStatement(manifest, { signature: v }).text));

  say('\n2. incomplete scope is the headline, not a footnote');
  check(/not fully covered/.test(assuranceStatement(manifest).headline), `headline: ${assuranceStatement(manifest).headline}`);
  check(v.ok === true, 'the signature is still valid: a signature says the manifest is unmodified, not that the scope is full');

  say('\n3. a waiver names who approved it and why');
  const waived = syntheticManifest({ checks: { ...manifestFacts().checks, incomplete: [], waived: [{ id: 'replay', statement: 'runtime replay', evidenceRefs: [], reason: 'no confinement backend on this host (synthetic)', approvedBy: 'reviewer@example.test' }] } });
  check(waived.ok !== false, 'the manifest with a waiver validates');
  const w = assuranceStatement(waived.manifest ?? waived);
  say(indent(w.gaps.join('\n')));
  check(w.gaps.some((g) => /waived: replay/.test(g) && /reviewer@example.test/.test(g)), 'the waiver, its reason and its approver appear in the gaps');

  say('\n4. tamper, unknown key and revoked key are each rejected');
  const t = release('tamper');
  const idx = JSON.parse(fs.readFileSync(path.join(t.dir, INDEX_FILE), 'utf8'));
  fs.appendFileSync(path.join(t.dir, BLOB_DIR, idx.entries.find((e) => e.name === 'findings.json').digest.slice(7)), ' ');
  const r1 = verifyAssuranceClaim({ envelope: t.envelope, trustPolicy: t.policy, bundleDir: t.dir });
  check(r1.ok === false && r1.code === 'BUNDLE_INVALID', `a modified evidence blob: ${r1.code}`);
  const edited = JSON.parse(JSON.stringify(a.envelope)); edited.claim.headline = 'Safe to deploy';
  const r2 = verifyAssuranceClaim({ envelope: edited, trustPolicy: a.policy, bundleDir: a.dir });
  check(r2.code === 'SIGNATURE_INVALID', `an edited claim: ${r2.code}`);
  const r3 = verifyAssuranceClaim({ envelope: a.envelope, trustPolicy: buildTrustPolicy({ roots: [{ publicKeyPem: keys().publicKeyPem, signerId: 'someone-else' }] }), bundleDir: a.dir });
  check(r3.code === 'UNKNOWN_TRUST_ROOT', `a key the reviewer does not trust: ${r3.code}`);
  const revoked = buildTrustPolicy({ roots: [{ publicKeyPem: a.k.publicKeyPem, signerId: SIGNER }], revoked: [{ keyId: a.envelope.signer.keyId, reason: 'key retired (synthetic)' }] });
  const r4 = verifyAssuranceClaim({ envelope: a.envelope, trustPolicy: revoked, bundleDir: a.dir });
  check(r4.code === 'REVOKED_TRUST_ROOT', `a revoked key: ${r4.code}`);
  const r5 = verifyAssuranceClaim({ envelope: a.envelope, trustPolicy: null, bundleDir: a.dir });
  check(r5.code === 'NO_TRUST_POLICY', `no trust policy at all: ${r5.code}`);

  say('\n5. what a claim does not carry');
  const carried = Object.keys(a.envelope.claim).sort();
  check(!carried.some((k) => /expir|valid|notAfter|until/i.test(k)), `claim fields: ${carried.join(', ')} (no validity period, so the reviewer applies their own freshness rule)`);

  say('\n6. only the signer domain may sign');
  for (const domain of [DOMAINS.WORKER, DOMAINS.TARGET, DOMAINS.VERIFIER]) {
    let code = null;
    try { signAssuranceClaim({ domain, bundleDir: a.dir, privateKeyPem: a.k.privateKeyPem, signerId: SIGNER }); } catch (e) { code = e.code; }
    check(code === 'SIGNER_NOT_AUTHORIZED', `${domain}: ${code}`);
  }
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
say(failed ? `\n${failed} step(s) did not behave as described` : '\nevery step behaved as described; the disposable bundles were removed');
process.exit(failed ? 1 : 0);
