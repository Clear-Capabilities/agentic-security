// CORE-003.AC03: signing records name their issuer and trust basis, local
// evidence is labelled self-issued, old bundles stay verifiable, and no signing
// material reaches a worker.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  ensureKeyPair, buildEvidenceBundle, signEvidenceBundle, verifyEvidenceBundle, canonicalBytes,
  keyFingerprint, keyPermissionIssues, TRUST_BASES, keyPaths,
} from '../src/posture/evidence-bundle.js';
import { computeRunAttestation } from '../src/posture/attestation.js';
import { detectBackend } from '../src/sandbox/capabilities.js';
import { runInBoundary } from '../src/sandbox/trust-boundary.js';
import { mkTestTmp } from './helpers/tmp.js';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const FINDING = {
  id: 'f1', stableId: 's1', severity: 'high', file: 'app.js', line: 42, vuln: 'SQL Injection',
  cwe: 'CWE-89', family: 'injection', parser: 'IR-TAINT', proofTier: 'unproven',
};

function fresh() {
  const dir = mkTestTmp('issuer-');
  const kp = ensureKeyPair(dir);
  const bundle = signEvidenceBundle(buildEvidenceBundle(FINDING, { engineVersion: '9.9.9' }), kp.privateKeyPem);
  return { dir, kp, bundle };
}
// Re-sign arbitrary content with the real key, to reach verifier branches that
// the signature check would otherwise short-circuit.
function resign(kp, bundle) {
  const { signature, ...rest } = bundle;
  return { ...rest, signature: { ...signature, value: crypto.sign(null, canonicalBytes(rest), kp.privateKeyPem).toString('base64') } };
}

describe('[CORE-003.AC03] issuer and trust basis are recorded and signed', () => {
  test('a freshly signed bundle names its issuer and is labelled self-issued, not independently certified', () => {
    const { kp, bundle } = fresh();
    assert.equal(bundle.issuance.trustBasis, 'self-issued-local-key');
    assert.equal(bundle.issuance.independentlyCertified, false);
    assert.equal(bundle.issuance.issuer.keyFingerprint, keyFingerprint(kp.publicKeyPem));
    assert.match(bundle.issuance.statement, /NOT independent third-party certification/);
    const v = verifyEvidenceBundle(bundle, kp.publicKeyPem);
    assert.equal(v.ok, true, v.reason);
    assert.equal(v.trustBasis, 'self-issued-local-key');
    assert.equal(v.independentlyCertified, false);
    assert.equal(v.issuer.id, bundle.issuance.issuer.id);
    assert.deepEqual(Object.keys(TRUST_BASES), ['self-issued-local-key']);
  });

  test('the label cannot be dropped or softened in transit', () => {
    const { kp, bundle } = fresh();
    const { issuance, ...dropped } = bundle;
    assert.equal(verifyEvidenceBundle(dropped, kp.publicKeyPem).ok, false, 'dropping issuance must break the signature');
    const softened = { ...bundle, issuance: { ...bundle.issuance, statement: 'Independently certified.' } };
    assert.equal(verifyEvidenceBundle(softened, kp.publicKeyPem).ok, false);
    const upgraded = { ...bundle, issuance: { ...bundle.issuance, independentlyCertified: true } };
    assert.equal(verifyEvidenceBundle(upgraded, kp.publicKeyPem).ok, false);
  });

  test('even a validly re-signed bundle cannot claim independent certification or an unknown basis', () => {
    const { kp, bundle } = fresh();
    const claim = resign(kp, { ...bundle, issuance: { ...bundle.issuance, independentlyCertified: true } });
    const r1 = verifyEvidenceBundle(claim, kp.publicKeyPem);
    assert.equal(r1.ok, false);
    assert.match(r1.reason, /may not claim independent certification/);
    const basis = resign(kp, { ...bundle, issuance: { ...bundle.issuance, trustBasis: 'independent-third-party' } });
    const r2 = verifyEvidenceBundle(basis, kp.publicKeyPem);
    assert.equal(r2.ok, false);
    assert.match(r2.reason, /unsupported trust basis/);
  });

  test('a declared issuer key that is not the verifying key is rejected', () => {
    const { kp, bundle } = fresh();
    const other = ensureKeyPair(mkTestTmp('issuer-other-'));
    const liar = resign(kp, { ...bundle, issuance: { ...bundle.issuance, issuer: { ...bundle.issuance.issuer, keyFingerprint: keyFingerprint(other.publicKeyPem) } } });
    const r = verifyEvidenceBundle(liar, kp.publicKeyPem);
    assert.equal(r.ok, false);
    assert.match(r.reason, /does not match the key/);
  });

  test('BACKWARD COMPATIBLE: a bundle signed before issuance existed still verifies, reported as no declared basis', () => {
    const { kp } = fresh();
    const legacy = buildEvidenceBundle(FINDING, { engineVersion: '0.134.0' });
    const sig = crypto.sign(null, canonicalBytes(legacy), kp.privateKeyPem);
    const old = { ...legacy, signature: { algorithm: 'ed25519', canonicalisation: legacy.schema, value: sig.toString('base64') } };
    assert.equal('issuance' in old, false);
    const r = verifyEvidenceBundle(old, kp.publicKeyPem);
    assert.equal(r.ok, true, r.reason);
    assert.equal(r.trustBasis, 'none-declared');
    assert.equal(r.independentlyCertified, false);
    assert.equal(r.issuer, null);
    assert.match(r.trustNote, /no trust basis is declared/);
  });

  test('a signed run attestation is labelled self-issued too; an unsigned one makes no claim', () => {
    const args = { findings: [], engineVersion: '1', rulesetVersion: '1', bundleSha: 'x' };
    const prev = process.env.AGENTIC_SECURITY_HMAC_KEY;
    process.env.AGENTIC_SECURITY_HMAC_KEY = 'ab'.repeat(32);
    try {
      const s = computeRunAttestation({ ...args, sign: true });
      assert.equal(s.trustBasis, 'self-issued-local-key');
      assert.equal(s.independentlyCertified, false);
      const u = computeRunAttestation({ ...args, sign: false });
      assert.equal(u.trustBasis, undefined);
    } finally { if (prev === undefined) delete process.env.AGENTIC_SECURITY_HMAC_KEY; else process.env.AGENTIC_SECURITY_HMAC_KEY = prev; }
  });
});

describe('[CORE-003.AC03] verify-attestation keeps its exit codes and reports the trust basis', () => {
  function cli(file, pub) {
    return spawnSync(process.execPath, [CLI, 'verify-attestation', file, '--public-key', pub], { encoding: 'utf8' });
  }
  test('new bundle: exit 0 and a self-issued line', () => {
    const { dir, kp, bundle } = fresh();
    const f = path.join(dir, 'b.json');
    fs.writeFileSync(f, JSON.stringify(bundle));
    const r = cli(f, kp.publicKey);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /trust basis:\s+self-issued-local-key/);
    assert.match(r.stdout, /NOT independent third-party certification/);
  });
  test('legacy bundle: still exit 0, reported as no declared trust basis', () => {
    const { dir, kp } = fresh();
    const legacy = buildEvidenceBundle(FINDING, {});
    const sig = crypto.sign(null, canonicalBytes(legacy), kp.privateKeyPem).toString('base64');
    const f = path.join(dir, 'old.json');
    fs.writeFileSync(f, JSON.stringify({ ...legacy, signature: { algorithm: 'ed25519', canonicalisation: legacy.schema, value: sig } }));
    const r = cli(f, kp.publicKey);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /trust basis:\s+none-declared/);
  });
  test('tampered bundle: exit 1 as before', () => {
    const { dir, kp, bundle } = fresh();
    const f = path.join(dir, 't.json');
    fs.writeFileSync(f, JSON.stringify({ ...bundle, finding: { ...bundle.finding, severity: 'critical' } }));
    const r = cli(f, kp.publicKey);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /INVALID/);
  });
});

describe('[CORE-003.AC03] no signing material is exposed to workers', () => {
  test('key files are created owner-only, and group/world access is reported as an issue', () => {
    const dir = path.join(mkTestTmp('issuer-perm-'), 'cfg');
    ensureKeyPair(dir);
    assert.deepEqual(keyPermissionIssues(dir), []);
    assert.equal(fs.statSync(keyPaths(dir).privateKey).mode & 0o777, 0o600);
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
    fs.chmodSync(keyPaths(dir).privateKey, 0o644);
    const issues = keyPermissionIssues(dir);
    assert.equal(issues.length, 1);
    assert.match(issues[0], /accessible to group\/other/);
  });

  test('an environment carrying key material is refused for a worker, and nothing runs', async () => {
    const root = mkTestTmp('issuer-env-');
    const r = await runInBoundary(['/bin/sh', '-c', `echo ran > "$ROOT/marker"`], {
      root, env: { ATTEST_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' },
    });
    assert.equal(r.blocked, true);
    assert.equal(fs.existsSync(path.join(root, 'marker')), false);
  });

  const BACKEND = detectBackend();
  test('a confined target cannot read the real signing key at its DEFAULT location',
    { skip: (BACKEND === 'userspace' || BACKEND === 'namespace') ? false : `SKIPPED, NOT PASSED: needs a probed userspace or namespace backend (selected '${BACKEND}')` },
    async () => {
      const xdg = mkTestTmp('issuer-xdg-');
      const prev = process.env.XDG_CONFIG_HOME;
      process.env.XDG_CONFIG_HOME = xdg;
      try {
        const kp = ensureKeyPair(); // default location, under the temp XDG dir
        assert.ok(kp.privateKey.startsWith(fs.realpathSync(xdg)) || kp.privateKey.startsWith(xdg));
        const root = mkTestTmp('issuer-root-');
        const needle = kp.privateKeyPem.split('\n')[1];
        const r = await runInBoundary(['/bin/sh', '-c', `cat '${kp.privateKey}' 2>&1; cat '${path.dirname(kp.privateKey)}'/* 2>&1; true`], { root });
        assert.equal(r.executed, true, r.reasons.join('|'));
        assert.ok(!r.targetOutput.stdout.includes(needle), 'the private key body leaked to the target');
        assert.ok(!r.targetOutput.stdout.includes('BEGIN PRIVATE KEY'));
        // and the same command run WITHOUT the boundary does read it (the probe is sensitive)
        const naked = spawnSync('/bin/sh', ['-c', `cat '${kp.privateKey}'`], { encoding: 'utf8' });
        assert.ok(naked.stdout.includes(needle));
      } finally { if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev; }
    });
});
