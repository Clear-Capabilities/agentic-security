// X-703: bounded assurance claims, signed in an independent domain with an explicit trust-root policy. SYNTHETIC fixtures only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  signAssuranceClaim, verifyAssuranceClaim, buildTrustPolicy, ensureAssuranceKeys, assuranceKeyDirectory, SIGNING_DIR_NAME,
} from '../../src/posture/portfolio/signing.js';
import { assuranceStatement, HEADLINE, portfolioAssuranceEnabled, scanVerdictWording } from '../../src/posture/portfolio/wording.js';
import { keyFingerprint } from '../../src/posture/evidence-bundle.js';
import { DOMAINS } from '../../src/sandbox/trust-domains.js';
import { toShipVerdict } from '../../src/report/index.js';
import { buildSlackDigest } from '../../src/integrations/index.js';
import { INDEX_FILE, BLOB_DIR } from '../../src/posture/portfolio/bundle.js';
import { exportSynthetic, keyPair, syntheticManifest, manifestFacts } from './helpers.js';
import { buildManifest } from '../../src/posture/portfolio/manifest.js';

function setup() {
  const dir = path.join(mkTestTmp('x703-'), 'b');
  exportSynthetic(dir);
  const keys = keyPair();
  const policy = buildTrustPolicy({ roots: [{ publicKeyPem: keys.publicKeyPem, signerId: 'release-signer@example.test' }] });
  const env = signAssuranceClaim({ domain: DOMAINS.SIGNER, bundleDir: dir, privateKeyPem: keys.privateKeyPem, signerId: 'release-signer@example.test' });
  return { dir, keys, policy, env };
}
const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

describe('[X-703.AC01] an authorized signer outside candidate-worker reach signs the manifest digest and records identity, key id and policy', () => {
  test('[X-703.AC01] the signer domain signs; the claim names the manifest digest, signer id, key id and the assurance policy', () => {
    const { env, keys } = setup();
    assert.match(env.claim.manifestDigest, /^sha256:/);
    assert.equal(env.signer.id, 'release-signer@example.test');
    assert.equal(env.signer.keyId, keyFingerprint(keys.publicKeyPem));
    assert.equal(env.assurancePolicy.id, 'bounded-claim-v1');
    assert.equal(env.claim.blockingPolicy.id, 'policy-v1');
    assert.equal(env.claim.synthetic, true);
    assert.equal(env.signature.algorithm, 'ed25519');
  });

  test('[X-703.AC01] negative: worker, target and verifier domains (and an unknown one) are refused before any key is used', () => {
    const { dir, keys } = setup();
    for (const domain of [DOMAINS.WORKER, DOMAINS.TARGET, DOMAINS.VERIFIER, 'nobody', undefined]) {
      assert.throws(() => signAssuranceClaim({ domain, bundleDir: dir, privateKeyPem: keys.privateKeyPem, signerId: 's' }), (e) => e.code === 'SIGNER_NOT_AUTHORIZED');
      assert.throws(() => ensureAssuranceKeys({ domain, dir: path.join(mkTestTmp('x703-'), 'k') }), (e) => e.code === 'SIGNER_NOT_AUTHORIZED');
    }
  });

  test('[X-703.AC01] the assurance key lives in its own directory and is refused if it equals the evidence key it must stay independent of', () => {
    const base = mkTestTmp('x703-');
    const k = ensureAssuranceKeys({ domain: DOMAINS.SIGNER, dir: path.join(base, SIGNING_DIR_NAME) });
    assert.equal(k.keyId, keyFingerprint(k.publicKeyPem));
    assert.equal(path.basename(assuranceKeyDirectory({ XDG_CONFIG_HOME: base })), SIGNING_DIR_NAME);
    const dir = path.join(mkTestTmp('x703-'), 'b'); exportSynthetic(dir);
    assert.throws(() => signAssuranceClaim({ domain: DOMAINS.SIGNER, bundleDir: dir, privateKeyPem: k.privateKeyPem, signerId: 's', independentOfKeyId: k.keyId }), (e) => e.code === 'KEY_NOT_INDEPENDENT');
    assert.equal(signAssuranceClaim({ domain: DOMAINS.SIGNER, bundleDir: dir, privateKeyPem: k.privateKeyPem, signerId: 's', independentOfKeyId: 'f'.repeat(64) }).signer.keyId, k.keyId);
    const mode = fs.statSync(path.join(base, SIGNING_DIR_NAME)).mode & 0o077;
    assert.equal(mode, 0, 'key directory is not group or world accessible');
  });

  test('[X-703.AC01] the signer refuses to sign a bundle that does not verify, and an anonymous signer', () => {
    const { dir, keys } = setup();
    fs.rmSync(path.join(dir, BLOB_DIR), { recursive: true });
    assert.throws(() => signAssuranceClaim({ domain: DOMAINS.SIGNER, bundleDir: dir, privateKeyPem: keys.privateKeyPem, signerId: 's' }), (e) => e.code === 'BUNDLE_INVALID');
    const ok = setup();
    assert.throws(() => signAssuranceClaim({ domain: DOMAINS.SIGNER, bundleDir: ok.dir, privateKeyPem: ok.keys.privateKeyPem, signerId: ' ' }), (e) => e.code === 'SIGNER_ID_REQUIRED');
  });
});

describe('[X-703.AC02] offline validation detects tampering, unknown or revoked roots and mismatched evidence; private keys never appear', () => {
  test('[X-703.AC02] a valid claim verifies against the trust policy and the bundle, with self-issued basis and independentlyCertified false', () => {
    const { dir, policy, env } = setup();
    const v = verifyAssuranceClaim({ envelope: env, trustPolicy: policy, bundleDir: dir });
    assert.equal(v.ok, true, JSON.stringify(v));
    assert.equal(v.trustBasis, 'self-issued-local-key');
    assert.equal(v.independentlyCertified, false);
    assert.match(v.statement, /not independent certification/);
    assert.equal(v.replay.attempted, false);
  });

  test('[X-703.AC02] tampering with the claim, the signature or the headline fails SIGNATURE_INVALID', () => {
    const { dir, policy, env } = setup();
    const edits = [
      (e) => { e.claim.blockingFindings = 7; },
      (e) => { e.claim.headline = 'Safe to deploy'; },
      (e) => { e.signer.id = 'someone-else'; },
      (e) => { e.assurancePolicy.id = 'weaker'; },
      (e) => { e.signature.value = Buffer.alloc(64).toString('base64'); },
    ];
    for (const edit of edits) {
      const e = JSON.parse(JSON.stringify(env)); edit(e);
      assert.equal(verifyAssuranceClaim({ envelope: e, trustPolicy: policy, bundleDir: dir }).code, 'SIGNATURE_INVALID');
    }
  });

  test('[X-703.AC02] unknown root, revoked root, no policy and a basis this build cannot verify are each rejected', () => {
    const { dir, policy, env, keys } = setup();
    const other = buildTrustPolicy({ roots: [{ publicKeyPem: keyPair().publicKeyPem, signerId: 'x' }] });
    assert.equal(verifyAssuranceClaim({ envelope: env, trustPolicy: other, bundleDir: dir }).code, 'UNKNOWN_TRUST_ROOT');
    const revoked = buildTrustPolicy({ roots: [{ publicKeyPem: keys.publicKeyPem, signerId: 's' }], revoked: [{ keyId: env.signer.keyId, reason: 'key compromised (synthetic)' }] });
    const rv = verifyAssuranceClaim({ envelope: env, trustPolicy: revoked, bundleDir: dir });
    assert.equal(rv.code, 'REVOKED_TRUST_ROOT');
    assert.match(rv.reason, /compromised/);
    assert.equal(verifyAssuranceClaim({ envelope: env, trustPolicy: null, bundleDir: dir }).code, 'NO_TRUST_POLICY');
    const thirdParty = buildTrustPolicy({ roots: [{ publicKeyPem: keys.publicKeyPem, signerId: 's', basis: 'third-party-certified' }] });
    assert.equal(verifyAssuranceClaim({ envelope: env, trustPolicy: thirdParty, bundleDir: dir }).code, 'UNSUPPORTED_BASIS');
    assert.equal(verifyAssuranceClaim({ envelope: env, trustPolicy: policy, bundleDir: dir }).ok, true);
  });

  test('[X-703.AC02] a trust root whose public key does not match its key id is rejected', () => {
    const { dir, policy, env } = setup();
    const bent = JSON.parse(JSON.stringify(policy));
    bent.roots[0].publicKeyPem = keyPair().publicKeyPem;
    assert.equal(verifyAssuranceClaim({ envelope: env, trustPolicy: bent, bundleDir: dir }).code, 'BAD_TRUST_ROOT');
  });

  test('[X-703.AC02] mismatched or tampered evidence: a modified blob, a missing blob and a different valid bundle all fail', () => {
    const a = setup();
    const idx = JSON.parse(fs.readFileSync(path.join(a.dir, INDEX_FILE), 'utf8'));
    const f = idx.entries.find((e) => e.name === 'findings.json');
    fs.appendFileSync(path.join(a.dir, BLOB_DIR, f.digest.slice(7)), ' ');
    assert.equal(verifyAssuranceClaim({ envelope: a.env, trustPolicy: a.policy, bundleDir: a.dir }).code, 'BUNDLE_INVALID');
    const b = setup();
    const bi = JSON.parse(fs.readFileSync(path.join(b.dir, INDEX_FILE), 'utf8'));
    fs.rmSync(path.join(b.dir, BLOB_DIR, bi.entries.find((e) => e.role === 'toolchain').digest.slice(7)));
    const r = verifyAssuranceClaim({ envelope: b.env, trustPolicy: b.policy, bundleDir: b.dir });
    assert.equal(r.code, 'BUNDLE_INVALID');
    assert.ok(r.errors.some((e) => e.code === 'MISSING_BLOB'));
    // a different, internally valid bundle under the same signature
    const c = setup();
    const other = path.join(mkTestTmp('x703-'), 'b');
    exportSynthetic(other, { manifest: syntheticManifest({ findings: { total: 9, blocking: 0 } }) });
    const m = verifyAssuranceClaim({ envelope: c.env, trustPolicy: c.policy, bundleDir: other });
    assert.equal(m.code, 'EVIDENCE_MISMATCH');
    assert.ok(m.mismatch.includes('bundleDigest'));
  });

  test('[X-703.AC02] private key material is never in the envelope, the trust policy, a thrown error or the verifier output', () => {
    const { dir, keys, policy, env } = setup();
    const pem = keys.privateKeyPem.split('\n').filter((l) => l && !l.startsWith('-----')).join('');
    const v = verifyAssuranceClaim({ envelope: env, trustPolicy: policy, bundleDir: dir });
    for (const blob of [JSON.stringify(env), JSON.stringify(policy), JSON.stringify(v)]) {
      assert.equal(blob.includes('PRIVATE KEY'), false);
      assert.equal(blob.includes(pem.slice(0, 40)), false);
    }
    let msg = '';
    try { signAssuranceClaim({ domain: DOMAINS.SIGNER, bundleDir: dir, privateKeyPem: keys.privateKeyPem.slice(0, 60), signerId: 's' }); } catch (e) { msg = e.message; }
    assert.match(msg, /could not be parsed/);
    assert.equal(msg.includes(pem.slice(0, 20)), false);
    for (const f of fs.readdirSync(dir, { recursive: true })) {
      const p = path.join(dir, f);
      if (fs.statSync(p).isFile()) assert.equal(fs.readFileSync(p, 'utf8').includes('PRIVATE KEY'), false);
    }
  });
});

describe('[X-703.AC03] user-facing wording is bounded: no blocking findings in completed supported checks, with scope and gaps; signing is not certification', () => {
  test('[X-703.AC03] the statement leads with the bounded headline, then scope, then gaps, and never says safe or certified', () => {
    const { dir, policy, env } = setup();
    const v = verifyAssuranceClaim({ envelope: env, trustPolicy: policy, bundleDir: dir });
    const s = assuranceStatement(syntheticManifest(), { signature: { ok: true, trustBasis: v.trustBasis, signer: v.signer } });
    const lines = s.text.split('\n');
    assert.ok(lines[0].startsWith(HEADLINE));
    assert.match(lines[1], /^Scope: 2 of 3 mandatory checks completed/);
    assert.match(lines[2], /^Gaps: incomplete: replay \(no confinement backend/);
    assert.match(s.text, /residual risk: rr-1/);
    assert.match(s.text, /not independent certification/);
    assert.match(s.text, /Synthetic fixture/);
    assert.doesNotMatch(s.text, /\bsafe to deploy\b/i);
    assert.doesNotMatch(s.text.replace(/not (?:the software is )?safe or free of vulnerabilities/i, ''), /\b(?:certified|guarantee[ds]?)\b(?! )/);
  });

  test('[X-703.AC03] a blocking finding changes the headline, and an invalid signature is stated as unverified', () => {
    const blocked = assuranceStatement(buildManifest(manifestFacts({ findings: { total: 3, blocking: 2 } })));
    assert.match(blocked.headline, /^Blocking findings present in completed supported checks: 2/);
    assert.equal(blocked.headline.startsWith(HEADLINE), false);
    const bad = assuranceStatement(syntheticManifest(), { signature: { ok: false, reason: 'tampered' } });
    assert.match(bad.text, /NOT valid \(tampered\)/);
  });

  test('[X-703.AC03] the one-screen verdict: flag off keeps the pinned wording; flag on gives the bounded headline with scope and gaps', () => {
    const clean = { findings: [] };
    const off = strip(toShipVerdict(clean, { color: false, portfolioAssurance: false }));
    assert.match(off, /Safe to deploy/);
    const on = strip(toShipVerdict(clean, { color: false, portfolioAssurance: true }));
    assert.match(on, /No blocking findings in completed supported checks/);
    assert.match(on, /Scope: completed supported checks only/);
    assert.doesNotMatch(on, /Safe to deploy/);
    const partial = strip(toShipVerdict({ findings: [], scanHealth: { status: 'partial', conditions: ['1 annotator(s) threw'] } }, { color: false, portfolioAssurance: true }));
    assert.match(partial, /did not complete/);
    assert.match(partial, /gaps listed below/);
    assert.match(partial, /1 annotator\(s\) threw/);
    const blocked = strip(toShipVerdict({ findings: [{ severity: 'critical', vuln: 'A', confidence: 0.95, file: 'a.js', line: 1, cwe: 'CWE-89' }] }, { color: false, portfolioAssurance: true }));
    assert.match(blocked, /Blocking findings present in completed supported checks: 1/);
    assert.doesNotMatch(blocked, /Not safe to deploy/);
  });

  test('[X-703.AC03] the flag resolves through the assurance configuration: off by default, on by env, killed by the kill switch', () => {
    assert.equal(portfolioAssuranceEnabled({ env: {} }), false);
    assert.equal(portfolioAssuranceEnabled({ env: { AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE: '1' } }), true);
    assert.equal(portfolioAssuranceEnabled({ env: { AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE: '1', AGENTIC_SECURITY_NO_ASSURANCE: '1' } }), false);
    assert.equal(portfolioAssuranceEnabled({ option: true, env: {} }), true);
    assert.equal(scanVerdictWording({ clean: false, scanIncomplete: true, actionableCount: 0 }).tier, 'incomplete');
  });

  test('[X-703.AC03] the chat digest keeps its wording off and uses the bounded wording on', () => {
    const summary = { critical: 0, high: 0, medium: 1 };
    assert.match(buildSlackDigest([], summary, { portfolioAssurance: false }).text, /safe to deploy/);
    const on = buildSlackDigest([], summary, { portfolioAssurance: true }).text;
    assert.match(on, /No blocking findings in completed supported checks/);
    assert.doesNotMatch(on, /safe to deploy/);
  });
});
