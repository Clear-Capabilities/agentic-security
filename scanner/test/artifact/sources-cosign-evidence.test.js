// Local container-engine input, cosign delegation and the signed image evidence bundle (PRD 5). The engine and cosign are STAND-INS
// (test/fixtures/proof-fabric/fake-engine/docker, test/fixtures/artifact/fake-cosign/cosign): they prove how this code calls the tools and
// how it reads their answers, including every way they fail. They do not prove a real daemon's or a real cosign's behaviour.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { buildDockerArchive } from '../helpers/build-tar-fixture.js';
import { saveFromEngine, EngineError } from '../../src/artifact/engine-source.js';
import { verifyWithCosign } from '../../src/artifact/cosign.js';
import { buildArtifactEvidenceBundle, signArtifactEvidenceBundle, verifyArtifactEvidenceBundle, ARTIFACT_BUNDLE_SCHEMA } from '../../src/artifact/artifact-evidence.js';
import { parseImageArchive } from '../../src/artifact/image-archive.js';
import { generateKeyPairSync } from 'node:crypto';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_DIR = path.join(HERE, '../fixtures/proof-fabric/fake-engine');
const COSIGN_DIR = path.join(HERE, '../fixtures/artifact/fake-cosign');
const withEnv = async (vars, fn) => {
  const saved = {}; for (const k of Object.keys(vars)) saved[k] = process.env[k];
  Object.assign(process.env, vars);
  try { return await fn(); } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
};
const withPath = (dir) => `${dir}${path.delimiter}${process.env.PATH}`;
const tmpExports = () => fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('engine-save-')).length;
const DIGEST = `sha256:${'a'.repeat(64)}`;

test('engine input: docker save output is returned, parses like any archive, and nothing is left on disk', async () => {
  const tar = buildDockerArchive({ config: { labels: { x: '1' } }, layers: [{ files: [{ name: 'a.txt', content: 'hi' }] }] });
  const f = path.join(mkTestTmp('engine-fixture-'), 'image.tar'); fs.writeFileSync(f, tar);
  const before = tmpExports();
  await withEnv({ PATH: withPath(ENGINE_DIR), AS_FAKE_SAVE_FILE: f }, async () => {
    const r = await saveFromEngine('myorg/app:1.0', { runtime: 'docker' });
    assert.ok(r.tar.equals(tar)); assert.deepEqual(r.source, { kind: 'engine', runtime: 'docker', reference: 'myorg/app:1.0', bytes: tar.length });
    assert.equal(parseImageArchive(r.tar).format, 'docker-archive');
  });
  assert.equal(tmpExports(), before, 'the temporary export is removed');
});

test('engine input: every failure is typed, bounded and cleaned up', async () => {
  const before = tmpExports();
  await withEnv({ PATH: withPath(ENGINE_DIR) }, async () => {
    await withEnv({ AS_FAKE_SAVE_FAIL: '1' }, () => assert.rejects(() => saveFromEngine('nope/none'), (e) => e instanceof EngineError && e.code === 'not_found' && /No such image/.test(e.message)));
    await withEnv({ AS_FAKE_SAVE_HANG: '1' }, () => assert.rejects(() => saveFromEngine('a/b', { limits: { timeoutMs: 700 } }), (e) => e.code === 'timeout'));
    await withEnv({ AS_FAKE_SAVE_ENDLESS: '1' }, () => assert.rejects(() => saveFromEngine('a/b', { limits: { maxBytes: 1024 * 1024 } }), (e) => e.code === 'too_large'));
    const ac = new AbortController(); setTimeout(() => ac.abort(), 200);
    await withEnv({ AS_FAKE_SAVE_HANG: '1' }, () => assert.rejects(() => saveFromEngine('a/b', { signal: ac.signal }), (e) => e.code === 'cancelled'));
  });
  assert.equal(tmpExports(), before, 'no export is left behind on any failure');
  await assert.rejects(() => saveFromEngine('a/b', { runtime: 'podman', pathEnv: '/nonexistent' }), (e) => e.code === 'engine_unavailable' && /nothing was read/.test(e.message));
  await assert.rejects(() => saveFromEngine('a/b', { runtime: 'rm' }), (e) => e.code === 'bad_runtime');
  for (const bad of ['', '-rf', '--help', 'a b', 'a;b', '../x', 'a/../b', 'a\nb', 'x'.repeat(300)]) await assert.rejects(() => saveFromEngine(bad), (e) => e.code === 'bad_reference', JSON.stringify(bad));
});

const KEY = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
const cosign = (mode, extra = {}, vars = {}) => withEnv({ AS_FAKE_COSIGN_MODE: mode, ...vars }, () => verifyWithCosign({ repository: 'ghcr.io/acme/app', digest: DIGEST, publicKeyPem: KEY, pathEnv: withPath(COSIGN_DIR), timeoutMs: 4000, ...extra }));

test('cosign: verified only when cosign succeeds AND names this exact digest; everything else is invalid, missing or unavailable', async () => {
  const ok = await cosign('ok-match');
  assert.equal(ok.state, 'verified'); assert.equal(ok.via, 'cosign'); assert.equal(ok.mode, 'key'); assert.equal(ok.signatures, 1);
  const other = await cosign('ok-other');
  assert.equal(other.state, 'invalid'); assert.match(other.reason, /none of the verified signatures names this image digest/);
  assert.equal((await cosign('ok-garbage')).state, 'invalid', 'a success exit with no signature payload is not a verification');
  assert.equal((await cosign('missing')).state, 'missing');
  assert.equal((await cosign('invalid')).state, 'invalid');
  const net = await cosign('netfail');
  assert.equal(net.state, 'unavailable'); assert.match(net.reason, /could not complete the check/);
  const slow = await cosign('hang', { timeoutMs: 600 });
  assert.equal(slow.state, 'unavailable'); assert.match(slow.reason, /did not answer in time/);
  assert.equal((await cosign('crash')).state, 'unavailable', 'an unknown failure is a check that did not run, not a verdict');
});

test('cosign: no tool, no material, conflicting material and bad inputs are all unavailable, never verified', async () => {
  const none = await verifyWithCosign({ repository: 'ghcr.io/acme/app', digest: DIGEST, publicKeyPem: KEY, pathEnv: '/nonexistent' });
  assert.equal(none.state, 'unavailable'); assert.match(none.reason, /cosign is not installed; nothing was verified/);
  const p = withPath(COSIGN_DIR);
  assert.match((await verifyWithCosign({ repository: 'ghcr.io/acme/app', digest: DIGEST, pathEnv: p })).reason, /no verification material/);
  assert.match((await verifyWithCosign({ repository: 'ghcr.io/acme/app', digest: DIGEST, publicKeyPem: KEY, certificateIdentity: 'a', certificateOidcIssuer: 'b', pathEnv: p })).reason, /either a public key or a keyless identity/);
  assert.match((await verifyWithCosign({ repository: 'ghcr.io/acme/app', digest: 'latest', publicKeyPem: KEY, pathEnv: p })).reason, /no sha256 image digest/);
  for (const bad of ['', '-x', '../a', 'a b']) assert.match((await verifyWithCosign({ repository: bad, digest: DIGEST, publicKeyPem: KEY, pathEnv: p })).reason, /repository name is not valid/, JSON.stringify(bad));
});

test('cosign: the check is bound to the digest, the key is a private temporary file that is removed, and secrets in the environment are not passed on', async () => {
  const log = path.join(mkTestTmp('cosign-log-'), 'calls.log');
  const r = await withEnv({ AS_FAKE_COSIGN_LOG: log, REGISTRY_PASSWORD: 'hunter2', SOME_API_KEY: 'k' }, () => cosign('ok-match', {}, { AS_FAKE_COSIGN_LOG: log, REGISTRY_PASSWORD: 'hunter2', SOME_API_KEY: 'k' }));
  assert.equal(r.state, 'verified');
  const call = JSON.parse(fs.readFileSync(log, 'utf8').trim().split('\n')[0]);
  assert.equal(call.argv.at(-1), `ghcr.io/acme/app@${DIGEST}`, 'a digest, never a tag');
  assert.equal(call.keyFileExistedAtCall, true); assert.equal(call.keyMode, '600');
  assert.equal(fs.existsSync(call.argv[call.argv.indexOf('--key') + 1]), false, 'the key file is gone afterwards');
  assert.deepEqual(call.envNames, [], 'credential-looking variables were not passed to cosign');
  const keyless = await cosign('ok-match', { publicKeyPem: null, certificateIdentity: 'ci@acme.test', certificateOidcIssuer: 'https://issuer.example' });
  assert.equal(keyless.state, 'verified'); assert.equal(keyless.mode, 'keyless'); assert.equal(keyless.identity, 'ci@acme.test');
});

const record = () => ({
  scannedAt: '2026-10-18T00:00:00Z',
  inventory: { digest: DIGEST, digestKind: 'manifest', format: 'oci-archive', os: 'linux', architecture: 'amd64', buildLabels: { revision: 'abc' }, osPackages: [{}, {}], appPackages: [{}], materializationTruncated: false },
  vulnerabilities: [{ type: 'vulnerable_dep', id: 'GHSA-xxxx', package: 'lodash', version: '4.17.4', severity: 'high', cve: 'CVE-2019-10744', kev: false }, { type: 'other' }],
  secrets: { deletedButRecoverable: [{ layerIndex: 2, path: 'app/.env', kind: 'generic-secret', value: 'SUPER-SECRET-VALUE', masked: 'SU****' }] },
});

test('image evidence bundle: signed, verifiable with only the public key, carries no secret value, and refuses tampering and stapled-on keys', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'pem' }); const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const b = buildArtifactEvidenceBundle(record(), { engineVersion: '9.9.9', source: { kind: 'registry', registry: 'ghcr.io', repository: 'acme/app', reference: 'v1' }, signatureResult: { state: 'verified', via: 'cosign' } });
  assert.equal(b.schema, ARTIFACT_BUNDLE_SCHEMA);
  assert.equal(b.scan.vulnerabilities.length, 1); assert.equal(b.scan.secrets[0].path, 'app/.env'); assert.equal(b.scan.truncated.secretsTotal, 1);
  assert.doesNotMatch(JSON.stringify(b), /SUPER-SECRET-VALUE|SU\*\*\*\*/, 'a secret finding is reported by layer, path and kind, never by value');
  const signed = signArtifactEvidenceBundle(b, priv);
  assert.deepEqual(verifyArtifactEvidenceBundle(signed, pub), { ok: true, reason: null });
  const edited = structuredClone(signed); edited.scan.vulnerabilities[0].severity = 'low';
  assert.equal(verifyArtifactEvidenceBundle(edited, pub).ok, false);
  const stapled = { ...signed, verdict: 'clean' };
  assert.match(verifyArtifactEvidenceBundle(stapled, pub).reason, /not covered by the signature/);
  assert.equal(verifyArtifactEvidenceBundle({ ...signed, attestation: undefined }, pub).reason, 'bundle is unsigned');
  assert.equal(verifyArtifactEvidenceBundle(signed, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' })).ok, false, 'a different key does not verify');
  assert.equal(verifyArtifactEvidenceBundle(null, pub).ok, false);
  assert.equal(buildArtifactEvidenceBundle({ inventory: {} }), null, 'nothing to attest without a digest');
  const unchecked = buildArtifactEvidenceBundle(record(), {});
  assert.equal(unchecked.signature.state, 'not-checked');
});
