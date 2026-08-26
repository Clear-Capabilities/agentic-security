// FR-1001 (assurance-hardening PRD): "Support signed portable policy
// bundles with organization, repository, and environment inheritance" |
// "Tampered or expired policy is rejected; effective policy is
// explainable."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildPolicyBundle, signPolicyBundle, verifyPolicyBundle, canonicalPolicyBytes,
  resolveEffectivePolicy, loadPolicyBundles, loadPolicyPublicKey, SCOPES, POLICY_BUNDLE_SCHEMA,
} from '../src/posture/policy-bundle.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: SCANNER, encoding: 'utf8', timeout: 30_000, ...opts });
}

function mkProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-policy-bundle-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture"}\n');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  return root;
}

function keypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

const FUTURE = '2099-01-01T00:00:00.000Z';
const PAST = '2020-01-01T00:00:00.000Z';

// ── buildPolicyBundle ────────────────────────────────────────────────────────

test('buildPolicyBundle: builds a well-formed unsigned bundle', () => {
  const b = buildPolicyBundle('organization', { severityFloor: 'high' }, { expiresAt: FUTURE });
  assert.equal(b.schema, POLICY_BUNDLE_SCHEMA);
  assert.equal(b.scope, 'organization');
  assert.deepEqual(b.policy, { severityFloor: 'high' });
  assert.equal(b.expiresAt, FUTURE);
});

test('buildPolicyBundle: rejects an unrecognised scope', () => {
  assert.equal(buildPolicyBundle('planet', {}), null);
});

test('buildPolicyBundle: rejects a non-object policy', () => {
  assert.equal(buildPolicyBundle('organization', null), null);
  assert.equal(buildPolicyBundle('organization', 'x'), null);
  assert.equal(buildPolicyBundle('organization', ['a']), null);
});

// ── sign + verify round trip ─────────────────────────────────────────────────

test('signPolicyBundle + verifyPolicyBundle: a genuine, unexpired bundle verifies', () => {
  const { privateKeyPem, publicKeyPem } = keypair();
  const bundle = signPolicyBundle(buildPolicyBundle('organization', { a: 1 }, { expiresAt: FUTURE }), privateKeyPem);
  const r = verifyPolicyBundle(bundle, publicKeyPem);
  assert.equal(r.ok, true, r.reason);
});

test('verifyPolicyBundle: a bundle signed with a DIFFERENT key fails verification', () => {
  const signer = keypair();
  const other = keypair();
  const bundle = signPolicyBundle(buildPolicyBundle('organization', { a: 1 }, { expiresAt: FUTURE }), signer.privateKeyPem);
  const r = verifyPolicyBundle(bundle, other.publicKeyPem);
  assert.equal(r.ok, false);
});

test('verifyPolicyBundle (tamper): editing the policy after signing is detected', () => {
  const { privateKeyPem, publicKeyPem } = keypair();
  const bundle = signPolicyBundle(buildPolicyBundle('organization', { severityFloor: 'high' }, { expiresAt: FUTURE }), privateKeyPem);
  const tampered = { ...bundle, policy: { severityFloor: 'low' } };
  const r = verifyPolicyBundle(tampered, publicKeyPem);
  assert.equal(r.ok, false);
  assert.match(r.reason, /modified after signing/);
});

test('verifyPolicyBundle (EA-03 discipline): a field stapled on AFTER signing, outside the canonical allowlist, is rejected', () => {
  const { privateKeyPem, publicKeyPem } = keypair();
  const bundle = signPolicyBundle(buildPolicyBundle('organization', { a: 1 }, { expiresAt: FUTURE }), privateKeyPem);
  const stapled = { ...bundle, extraClaim: 'trust me' };
  const r = verifyPolicyBundle(stapled, publicKeyPem);
  assert.equal(r.ok, false);
  assert.match(r.reason, /unrecognised top-level key/);
});

test('verifyPolicyBundle (FR-1001): an EXPIRED bundle is rejected even with a valid signature', () => {
  const { privateKeyPem, publicKeyPem } = keypair();
  const bundle = signPolicyBundle(buildPolicyBundle('organization', { a: 1 }, { expiresAt: PAST }), privateKeyPem);
  const r = verifyPolicyBundle(bundle, publicKeyPem);
  assert.equal(r.ok, false);
  assert.match(r.reason, /expired/);
});

test('verifyPolicyBundle: a bundle with no expiresAt (null) never expires', () => {
  const { privateKeyPem, publicKeyPem } = keypair();
  const bundle = signPolicyBundle(buildPolicyBundle('organization', { a: 1 }), privateKeyPem);
  const r = verifyPolicyBundle(bundle, publicKeyPem);
  assert.equal(r.ok, true, r.reason);
});

test('verifyPolicyBundle: no public key supplied is rejected, not thrown', () => {
  const { privateKeyPem } = keypair();
  const bundle = signPolicyBundle(buildPolicyBundle('organization', { a: 1 }, { expiresAt: FUTURE }), privateKeyPem);
  assert.doesNotThrow(() => verifyPolicyBundle(bundle, null));
  assert.equal(verifyPolicyBundle(bundle, null).ok, false);
});

test('verifyPolicyBundle: an unsigned bundle is rejected', () => {
  const { publicKeyPem } = keypair();
  const r = verifyPolicyBundle(buildPolicyBundle('organization', { a: 1 }), publicKeyPem);
  assert.equal(r.ok, false);
  assert.match(r.reason, /unsigned/);
});

test('canonicalPolicyBytes: identical bundles produce identical bytes regardless of key insertion order', () => {
  const b1 = { schema: POLICY_BUNDLE_SCHEMA, scope: 'organization', policy: { a: 1, b: 2 }, issuedAt: 'x', expiresAt: null };
  const b2 = { expiresAt: null, policy: { b: 2, a: 1 }, issuedAt: 'x', scope: 'organization', schema: POLICY_BUNDLE_SCHEMA };
  assert.deepEqual(canonicalPolicyBytes(b1), canonicalPolicyBytes(b2));
});

// ── resolveEffectivePolicy: inheritance, precedence, provenance ─────────────

test('resolveEffectivePolicy: organization -> repository -> environment, most specific wins per key', () => {
  const { privateKeyPem, publicKeyPem } = keypair();
  const org = signPolicyBundle(buildPolicyBundle('organization', { severityFloor: 'high', a: 'org' }, { expiresAt: FUTURE }), privateKeyPem);
  const repo = signPolicyBundle(buildPolicyBundle('repository', { severityFloor: 'medium', b: 'repo' }, { expiresAt: FUTURE }), privateKeyPem);
  const env = signPolicyBundle(buildPolicyBundle('environment', { severityFloor: 'critical' }, { expiresAt: FUTURE }), privateKeyPem);
  const { effective, provenance, accepted, rejected } = resolveEffectivePolicy(
    [{ scope: 'organization', bundle: org }, { scope: 'repository', bundle: repo }, { scope: 'environment', bundle: env }],
    publicKeyPem,
  );
  assert.deepEqual(accepted, ['organization', 'repository', 'environment']);
  assert.equal(rejected.length, 0);
  assert.equal(effective.severityFloor, 'critical', 'environment (most specific) must win the shared key');
  assert.equal(effective.a, 'org');
  assert.equal(effective.b, 'repo');
  assert.equal(provenance.severityFloor, 'environment', 'provenance must name which scope last set the key — this is the "explainable" half');
  assert.equal(provenance.a, 'organization');
  assert.equal(provenance.b, 'repository');
});

test('resolveEffectivePolicy: a TAMPERED bundle among the three is excluded from the merge and reported, others still apply', () => {
  const { privateKeyPem, publicKeyPem } = keypair();
  const org = signPolicyBundle(buildPolicyBundle('organization', { severityFloor: 'high' }, { expiresAt: FUTURE }), privateKeyPem);
  const repoSigned = signPolicyBundle(buildPolicyBundle('repository', { severityFloor: 'low' }, { expiresAt: FUTURE }), privateKeyPem);
  const repoTampered = { ...repoSigned, policy: { severityFloor: 'critical' } }; // edited after signing
  const { effective, provenance, accepted, rejected } = resolveEffectivePolicy(
    [{ scope: 'organization', bundle: org }, { scope: 'repository', bundle: repoTampered }],
    publicKeyPem,
  );
  assert.deepEqual(accepted, ['organization']);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].scope, 'repository');
  assert.match(rejected[0].reason, /modified after signing/);
  assert.equal(effective.severityFloor, 'high', 'the tampered override must never apply — the organization value must survive');
  assert.equal(provenance.severityFloor, 'organization');
});

test('resolveEffectivePolicy: an EXPIRED bundle is excluded and reported by scope+reason', () => {
  const { privateKeyPem, publicKeyPem } = keypair();
  const org = signPolicyBundle(buildPolicyBundle('organization', { a: 1 }, { expiresAt: FUTURE }), privateKeyPem);
  const env = signPolicyBundle(buildPolicyBundle('environment', { a: 2 }, { expiresAt: PAST }), privateKeyPem);
  const { effective, accepted, rejected } = resolveEffectivePolicy(
    [{ scope: 'organization', bundle: org }, { scope: 'environment', bundle: env }],
    publicKeyPem,
  );
  assert.deepEqual(accepted, ['organization']);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].scope, 'environment');
  assert.match(rejected[0].reason, /expired/);
  assert.equal(effective.a, 1, 'the expired override must never apply');
});

test('resolveEffectivePolicy: no entries returns an empty, well-formed result — never throws', () => {
  const r = resolveEffectivePolicy([], null);
  assert.deepEqual(r.effective, {});
  assert.deepEqual(r.provenance, {});
  assert.deepEqual(r.accepted, []);
  assert.deepEqual(r.rejected, []);
});

// ── loadPolicyBundles / loadPolicyPublicKey ─────────────────────────────────

test('loadPolicyBundles: no policy-bundles directory returns an empty array, never throws', () => {
  const root = mkProject();
  try { assert.deepEqual(loadPolicyBundles(root), []); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('loadPolicyBundles: loads whichever of the 3 scope files exist, skips malformed ones', () => {
  const root = mkProject();
  try {
    const dir = path.join(root, '.agentic-security', 'policy-bundles');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'organization.json'), JSON.stringify({ schema: POLICY_BUNDLE_SCHEMA, scope: 'organization', policy: {}, issuedAt: 'x', expiresAt: null }));
    fs.writeFileSync(path.join(dir, 'repository.json'), 'not json{{{');
    // environment.json intentionally absent
    const entries = loadPolicyBundles(root);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].scope, 'organization');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('loadPolicyPublicKey: absent file returns null, never throws', () => {
  const root = mkProject();
  try { assert.equal(loadPolicyPublicKey(root), null); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── Real end-to-end through the CLI (D-0024's own lesson: prove the real entry point) ──

test('policy-explain (real CLI): prints the effective policy with per-key provenance, and names a rejected tampered bundle', () => {
  const root = mkProject();
  try {
    const { privateKeyPem, publicKeyPem } = keypair();
    const dir = path.join(root, '.agentic-security', 'policy-bundles');
    fs.mkdirSync(dir, { recursive: true });

    const org = signPolicyBundle(buildPolicyBundle('organization', { severityFloor: 'high' }, { expiresAt: FUTURE }), privateKeyPem);
    fs.writeFileSync(path.join(dir, 'organization.json'), JSON.stringify(org));

    const repoSigned = signPolicyBundle(buildPolicyBundle('repository', { severityFloor: 'low' }, { expiresAt: FUTURE }), privateKeyPem);
    const repoTampered = { ...repoSigned, policy: { severityFloor: 'critical' } };
    fs.writeFileSync(path.join(dir, 'repository.json'), JSON.stringify(repoTampered));

    fs.writeFileSync(path.join(root, '.agentic-security', 'policy-bundle-public-key.pem'), publicKeyPem);

    const r = run(['policy-explain', '--root', root]);
    assert.equal(r.status, 0, `expected exit 0: ${r.stderr}`);
    assert.match(r.stdout, /Accepted \(1\): organization/);
    assert.match(r.stdout, /Rejected \(1\)/);
    assert.match(r.stdout, /repository: .*modified after signing/);
    assert.match(r.stdout, /severityFloor = "high"/);
    assert.match(r.stdout, /\[from: organization\]/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('policy-explain (real CLI): no bundles present prints a clear message and exits 0', () => {
  const root = mkProject();
  try {
    const r = run(['policy-explain', '--root', root]);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /No policy bundles found/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('policy-sign + policy-explain (real CLI, round trip): a bundle signed by the real CLI verifies through the real CLI', () => {
  const root = mkProject();
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'as-policy-sign-home-'));
  try {
    const policyFile = path.join(root, 'org-policy.json');
    fs.writeFileSync(policyFile, JSON.stringify({ severityFloor: 'high' }));
    const outFile = path.join(root, '.agentic-security', 'policy-bundles', 'organization.json');
    fs.mkdirSync(path.dirname(outFile), { recursive: true });

    const signResult = run(['policy-sign', '--scope', 'organization', '--policy', policyFile, '--out', outFile], { env: { ...process.env, XDG_CONFIG_HOME: home } });
    assert.equal(signResult.status, 0, `expected policy-sign to succeed: ${signResult.stderr}`);
    assert.match(signResult.stdout, /signed organization policy bundle written/);
    assert.ok(fs.existsSync(outFile), 'the signed bundle must actually be written');

    // The public key policy-sign generated must be installed for the operator
    // to verify with — a real org would distribute it; here we read the exact
    // path from policy-sign's own printed output (not a guessed filename),
    // proving the full loop: sign -> distribute -> verify -> explain.
    const pubKeyMatch = signResult.stdout.match(/public key for verification: (.+)/);
    assert.ok(pubKeyMatch, `expected policy-sign to print the public key path: ${signResult.stdout}`);
    const pubKeyPath = pubKeyMatch[1].trim();
    assert.ok(fs.existsSync(pubKeyPath), `expected a generated public key at ${pubKeyPath}`);
    fs.copyFileSync(pubKeyPath, path.join(root, '.agentic-security', 'policy-bundle-public-key.pem'));

    const explainResult = run(['policy-explain', '--root', root]);
    assert.equal(explainResult.status, 0, `expected policy-explain to succeed: ${explainResult.stderr}`);
    assert.match(explainResult.stdout, /Accepted \(1\): organization/);
    assert.match(explainResult.stdout, /severityFloor = "high"/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});
