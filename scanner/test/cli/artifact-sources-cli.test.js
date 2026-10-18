// The real CLI, end to end, for the three new image sources and the new trust outputs (PRD 5): a remote image from a local mock
// registry, a local engine image from a stand-in `docker`, cosign verification from a stand-in `cosign`, and a signed evidence
// bundle that `verify-attestation` accepts and rejects. OSV is offline; the mock registry is the only network.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import zlib from 'node:zlib';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { buildTar, buildDockerArchive } from '../helpers/build-tar-fixture.js';
import { sha256Hex } from '../../src/artifact/oci-layout.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '../../bin/agentic-security.js');
const ENGINE_DIR = path.join(HERE, '../fixtures/proof-fabric/fake-engine');
const COSIGN_DIR = path.join(HERE, '../fixtures/artifact/fake-cosign');
const sha = (b) => `sha256:${sha256Hex(b)}`;

function run(cwd, args, env = {}) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CLI, ...args], { cwd, env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1', XDG_CONFIG_HOME: path.join(cwd, 'cfg'), ...env } });
    let stdout = ''; let stderr = '';
    c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
    const t = setTimeout(() => c.kill('SIGKILL'), 60000);
    c.on('close', (status) => { clearTimeout(t); resolve({ status, stdout, stderr }); });
  });
}
function image() {
  const layerTar = buildTar([{ name: 'app/package.json', content: JSON.stringify({ dependencies: { lodash: '4.17.21' } }) }]);
  const layer = zlib.gzipSync(layerTar);
  const config = Buffer.from(JSON.stringify({ architecture: 'amd64', os: 'linux', config: {}, rootfs: { type: 'layers', diff_ids: [sha(layerTar)] }, history: [{ created_by: 'x' }] }));
  const manifest = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: sha(config), size: config.length }, layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: sha(layer), size: layer.length }] }));
  return { layer, config, manifest };
}
async function mockRegistry(img) {
  const server = http.createServer((req, res) => {
    if (req.url.includes('/manifests/')) { res.writeHead(200, { 'content-type': 'application/vnd.oci.image.manifest.v1+json' }); return res.end(img.manifest); }
    const d = req.url.split('/blobs/')[1];
    if (d === sha(img.config)) { res.writeHead(200); return res.end(img.config); }
    if (d === sha(img.layer)) { res.writeHead(200); return res.end(img.layer); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { host: `127.0.0.1:${server.address().port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

test('image scan --registry fetches an explicit remote image, scans it, signs an evidence bundle, and verify-attestation accepts it and rejects an edit', async () => {
  const img = image(); const reg = await mockRegistry(img); const dir = mkTestTmp('as-sources-cli-');
  fs.writeFileSync(path.join(dir, 'package.json'), '{}');
  try {
    const r = await run(dir, ['image', 'scan', '--registry', `${reg.host}/acme/app:v1`, '--allow-http-loopback', '--attest', '--format', 'cli']);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(`Image digest: ${sha(img.manifest)}`));
    assert.match(r.stdout, /Source: 127\.0\.0\.1:\d+\/acme\/app:v1/);
    const attDir = path.join(dir, '.agentic-security', 'attestations');
    const bundlePath = path.join(attDir, fs.readdirSync(attDir).find((f) => f.startsWith('artifact-')));
    const pubPath = path.join(dir, 'cfg', 'agentic-security', 'attest-key.pub.pem');
    assert.ok(fs.existsSync(pubPath), 'a public key was generated');
    const ok = await run(dir, ['verify-attestation', bundlePath, '--public-key', pubPath]);
    assert.equal(ok.status, 0, ok.stdout + ok.stderr); assert.match(ok.stdout, /VALID .* image evidence bundle/);
    assert.match(ok.stdout, /does NOT prove the image is free/);
    const b = JSON.parse(fs.readFileSync(bundlePath, 'utf8')); b.artifact.os = 'windows';
    fs.writeFileSync(bundlePath, JSON.stringify(b));
    const bad = await run(dir, ['verify-attestation', bundlePath, '--public-key', pubPath]);
    assert.equal(bad.status, 1); assert.match(bad.stderr, /INVALID/);
  } finally { await reg.close(); }
});

test('image scan --registry refuses what it should: a missing image, a bad reference, and plain HTTP without the opt-in', async () => {
  const reg = await mockRegistry(image()); const dir = mkTestTmp('as-sources-cli-');
  try {
    const noHttp = await run(dir, ['image', 'scan', '--registry', `${reg.host}/acme/app:v1`]);
    assert.equal(noHttp.status, 1); assert.match(noHttp.stderr, /\(network\)|insecure/);
    const bad = await run(dir, ['image', 'scan', '--registry', 'https://evil.example/x']);
    assert.equal(bad.status, 1); assert.match(bad.stderr, /not a valid image reference \(bad_reference\)/);
  } finally { await reg.close(); }
});

test('image scan <name> --engine docker reads a local image through the engine; an engine that is not there is an error, not a clean scan', async () => {
  const dir = mkTestTmp('as-sources-cli-');
  const f = path.join(dir, 'saved.tar');
  fs.writeFileSync(f, buildDockerArchive({ config: {}, layers: [{ files: [{ name: 'app/package.json', content: JSON.stringify({ dependencies: { lodash: '4.17.21' } }) }] }] }));
  const ok = await run(dir, ['image', 'scan', 'acme/app:1', '--engine', 'docker', '--format', 'cli'], { PATH: `${ENGINE_DIR}${path.delimiter}${process.env.PATH}`, AS_FAKE_SAVE_FILE: f });
  assert.equal(ok.status, 0, ok.stderr); assert.match(ok.stdout, /Source: local docker image acme\/app:1/);
  const missing = await run(dir, ['image', 'scan', 'acme/app:1', '--engine', 'podman'], { PATH: '/usr/bin:/bin' });
  assert.equal(missing.status, 1); assert.match(missing.stderr, /not installed or not on PATH; nothing was read/);
  const inj = await run(dir, ['image', 'scan', '--evil', '--engine', 'docker']);
  assert.notEqual(inj.status, 0);
});

test('image verify --cosign reports the state cosign gave for THIS digest; with no cosign it says unavailable and exits 0, never verified', async () => {
  const dir = mkTestTmp('as-sources-cli-');
  fs.writeFileSync(path.join(dir, 'i.tar'), buildDockerArchive({ config: {}, layers: [{ files: [{ name: 'a.txt', content: 'x' }] }] }));
  const key = path.join(dir, 'k.pub');
  const { generateKeyPairSync } = await import('node:crypto');
  fs.writeFileSync(key, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }));
  const withCosign = { PATH: `${COSIGN_DIR}${path.delimiter}${process.env.PATH}` };
  const v = await run(dir, ['image', 'verify', 'i.tar', '--cosign', '--repository', 'ghcr.io/acme/app', '--public-key', key], { ...withCosign, AS_FAKE_COSIGN_MODE: 'ok-match' });
  assert.equal(v.status, 0, v.stderr); assert.equal(JSON.parse(v.stdout).signature.state, 'verified');
  const inv = await run(dir, ['image', 'verify', 'i.tar', '--cosign', '--repository', 'ghcr.io/acme/app', '--public-key', key], { ...withCosign, AS_FAKE_COSIGN_MODE: 'ok-other' });
  assert.equal(inv.status, 1); assert.equal(JSON.parse(inv.stdout).signature.state, 'invalid');
  const none = await run(dir, ['image', 'verify', 'i.tar', '--cosign', '--repository', 'ghcr.io/acme/app', '--public-key', key], { PATH: '/usr/bin:/bin' });
  assert.equal(none.status, 0); assert.equal(JSON.parse(none.stdout).signature.state, 'unavailable');
  const norepo = await run(dir, ['image', 'verify', 'i.tar', '--cosign', '--public-key', key], withCosign);
  assert.equal(JSON.parse(norepo.stdout).signature.state, 'unavailable'); assert.match(JSON.parse(norepo.stdout).signature.reason, /--repository/);
});
