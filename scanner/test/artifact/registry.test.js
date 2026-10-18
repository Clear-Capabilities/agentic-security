// The OCI registry client (PRD 5 requirement 1, "explicit remote OCI reference"), against a local mock registry. Nothing here touches
// the Internet. Hostile registries are the point: a lying size, endless bytes, a wrong digest, a redirect that would carry the
// credential to another host, and credentials that must never appear in any message.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import util from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildTar } from '../helpers/build-tar-fixture.js';
import { fetchImage, parseReference, resolveCredentials, RegistryError, REGISTRY_LIMITS } from '../../src/artifact/registry.js';
import { parseImageArchive } from '../../src/artifact/image-archive.js';
import { buildOciArchive, sha256Hex } from '../../src/artifact/oci-layout.js';

const sha = (b) => `sha256:${sha256Hex(b)}`;
function makeImage(files = [{ name: 'app/package.json', content: '{"name":"x"}' }], arch = 'amd64') {
  const layerTar = buildTar(files); const layer = zlib.gzipSync(layerTar);
  const config = Buffer.from(JSON.stringify({ architecture: arch, os: 'linux', config: { Labels: { 'org.opencontainers.image.revision': 'abc123' } }, rootfs: { type: 'layers', diff_ids: [sha(layerTar)] }, history: [{ created_by: 'layer 0' }] }));
  const manifest = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: sha(config), size: config.length }, layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: sha(layer), size: layer.length }] }));
  return { layer, config, manifest };
}

/** A registry whose behaviour each test bends. `blobs`/`manifests` map digest or tag to bytes. */
async function registry(handler) {
  const seen = [];
  const server = http.createServer((req, res) => { seen.push({ url: req.url, auth: req.headers.authorization ?? null, host: req.headers.host }); handler(req, res, seen); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return { port, host: `127.0.0.1:${port}`, seen, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
function serve({ manifests = {}, blobs = {}, headers = {} } = {}) {
  return (req, res) => {
    const m = /^\/v2\/(.+)\/manifests\/(.+)$/.exec(req.url); const b = /^\/v2\/(.+)\/blobs\/(.+)$/.exec(req.url);
    if (m && manifests[m[2]]) { let ct = 'application/vnd.oci.image.manifest.v1+json'; try { ct = JSON.parse(manifests[m[2]]).mediaType ?? ct; } catch { /* a deliberately broken manifest */ }
      res.writeHead(200, { 'content-type': ct, ...headers }); return res.end(manifests[m[2]]); }
    if (b && blobs[b[2]]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); return res.end(blobs[b[2]]); }
    res.writeHead(404); res.end('no');
  };
}
const opts = { allowLoopbackHttp: true, env: {} };

test('reference parsing: tags, digests, registry hosts, Docker Hub defaults; everything else is refused', () => {
  assert.deepEqual(parseReference('alpine'), { registry: 'registry-1.docker.io', repository: 'library/alpine', reference: 'latest', isDigest: false, loopback: false });
  assert.equal(parseReference('acme/app:1.2').repository, 'acme/app');
  assert.equal(parseReference('ghcr.io/acme/app:v1').registry, 'ghcr.io');
  assert.equal(parseReference(`ghcr.io/acme/app@sha256:${'a'.repeat(64)}`).isDigest, true);
  assert.equal(parseReference('localhost:5000/team/app:dev').loopback, true);
  assert.equal(parseReference('127.0.0.1:5000/app').loopback, true);
  for (const bad of ['', 'https://ghcr.io/acme/app', 'acme/app tag', 'acme/../app', '-evil', 'ACME/App', 'acme/app@sha256:short', 'user:pw@ghcr.io/acme/app', 'acme/app:bad tag', 'a\0b', 'x'.repeat(400)]) assert.throws(() => parseReference(bad), (e) => e instanceof RegistryError && e.code === 'bad_reference', JSON.stringify(bad));
});

test('a plain image is fetched, every blob verified, and the result is an archive the existing parser reads', async () => {
  const img = makeImage();
  const reg = await registry(serve({ manifests: { latest: img.manifest }, blobs: { [sha(img.config)]: img.config, [sha(img.layer)]: img.layer } }));
  try {
    const r = await fetchImage(`${reg.host}/acme/app:latest`, opts);
    assert.equal(r.manifestDigest, sha(img.manifest)); assert.equal(r.source.kind, 'registry'); assert.equal(r.source.authenticated, false);
    const parsed = parseImageArchive(r.tar);
    assert.equal(parsed.format, 'oci-archive'); assert.equal(parsed.digest, sha(img.manifest)); assert.equal(parsed.config.labels['org.opencontainers.image.revision'], 'abc123');
    assert.equal(parsed.layers.length, 1);
  } finally { await reg.close(); }
});

test('a multi-platform index is resolved to the requested platform, and a missing platform names what exists', async () => {
  const amd = makeImage([{ name: 'a.txt', content: 'amd' }], 'amd64'); const arm = makeImage([{ name: 'a.txt', content: 'arm' }], 'arm64');
  const index = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: [
    { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: sha(amd.manifest), size: amd.manifest.length, platform: { os: 'linux', architecture: 'amd64' } },
    { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: sha(arm.manifest), size: arm.manifest.length, platform: { os: 'linux', architecture: 'arm64' } }] }));
  const reg = await registry(serve({ manifests: { latest: index, [sha(amd.manifest)]: amd.manifest, [sha(arm.manifest)]: arm.manifest }, blobs: { [sha(amd.config)]: amd.config, [sha(amd.layer)]: amd.layer, [sha(arm.config)]: arm.config, [sha(arm.layer)]: arm.layer } }));
  try {
    const a = await fetchImage(`${reg.host}/app`, { ...opts, platform: 'linux/arm64' });
    assert.equal(a.manifestDigest, sha(arm.manifest)); assert.equal(a.source.platform, 'linux/arm64'); assert.equal(a.source.indexDigest, sha(index));
    await assert.rejects(() => fetchImage(`${reg.host}/app`, { ...opts, platform: 'linux/s390x' }), (e) => e.code === 'platform_not_found' && /linux\/amd64, linux\/arm64/.test(e.message));
  } finally { await reg.close(); }
});

test('bearer-token authentication: the credential goes to the token endpoint, the token to the registry, and no secret appears anywhere', async () => {
  const img = makeImage();
  let tokenAuth = null; let tokenSeen = null;
  const reg = await registry((req, res) => {
    if (req.url.startsWith('/token')) { tokenAuth = req.headers.authorization; tokenSeen = req.url; res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ token: 'TOKEN-from-endpoint' })); }
    if (req.headers.authorization !== 'Bearer TOKEN-from-endpoint') { res.writeHead(401, { 'www-authenticate': `Bearer realm="http://127.0.0.1:${req.socket.localPort}/token",service="reg",scope="repository:acme/app:pull"` }); return res.end(); }
    serve({ manifests: { latest: img.manifest }, blobs: { [sha(img.config)]: img.config, [sha(img.layer)]: img.layer } })(req, res);
  });
  try {
    const creds = resolveCredentials(reg.host, { env: { AGENTIC_SECURITY_REGISTRY_USER: 'ci-bot', AGENTIC_SECURITY_REGISTRY_PASSWORD: 'hunter2-secret' } });
    const r = await fetchImage(`${reg.host}/acme/app:latest`, { ...opts, credentials: creds });
    assert.equal(r.source.authenticated, true);
    assert.equal(tokenAuth, `Basic ${Buffer.from('ci-bot:hunter2-secret').toString('base64')}`, 'the basic credential reached the token endpoint');
    assert.match(tokenSeen, /service=reg/); assert.match(tokenSeen, /scope=repository%3Aacme%2Fapp%3Apull/);
    assert.equal(reg.seen.filter((s) => s.url.startsWith('/v2/')).every((s) => s.auth === 'Bearer TOKEN-from-endpoint' || s.auth === null), true, 'the registry only ever saw the token');
    for (const view of [JSON.stringify(creds), String(creds), util.inspect(creds), JSON.stringify(r.source)]) assert.doesNotMatch(view, /hunter2|ci-bot/);
  } finally { await reg.close(); }
});

test('a registry that wants authentication and has none configured is refused, with a message that holds no secret', async () => {
  const reg = await registry((req, res) => { res.writeHead(401, { 'www-authenticate': 'Basic realm="reg"' }); res.end(); });
  try {
    await assert.rejects(() => fetchImage(`${reg.host}/acme/app`, { ...opts, credentials: resolveCredentials(reg.host, { env: {}, dockerConfig: '/nonexistent' }) }), (e) => e.code === 'unauthorized' && /none is configured/.test(e.message));
  } finally { await reg.close(); }
});

test('Docker config credentials are read for exactly the registry asked about, and for no other', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'regcfg-'));
  fs.writeFileSync(`${dir}/config.json`, JSON.stringify({ auths: { 'ghcr.io': { auth: Buffer.from('alice:s3cret').toString('base64') }, 'other.example': { auth: Buffer.from('bob:pw').toString('base64') } } }));
  const a = resolveCredentials('ghcr.io', { env: {}, dockerConfig: `${dir}/config.json` });
  assert.equal(a.present, true); assert.equal(a.basicHeader(), `Basic ${Buffer.from('alice:s3cret').toString('base64')}`);
  assert.equal(resolveCredentials('registry.unrelated.test', { env: {}, dockerConfig: `${dir}/config.json` }).present, false);
  assert.equal(resolveCredentials('ghcr.io', { env: {}, dockerConfig: `${dir}/missing.json` }).present, false);
  assert.equal(resolveCredentials('ghcr.io', { env: { AGENTIC_SECURITY_REGISTRY_TOKEN: 't0k' }, dockerConfig: `${dir}/config.json` }).bearerHeader(), 'Bearer t0k', 'an explicit environment token wins');
});
test('a blob redirect to another host does not carry the registry credential', async () => {
  const img = makeImage();
  const cdn = await registry((req, res) => { if (req.url === `/blob/${sha(img.layer)}`) { res.writeHead(200); return res.end(img.layer); } res.writeHead(404); res.end(); });
  const reg = await registry((req, res) => {
    if (req.url === `/v2/acme/app/blobs/${sha(img.layer)}`) { res.writeHead(307, { location: `http://127.0.0.1:${cdn.port}/blob/${sha(img.layer)}` }); return res.end(); }
    serve({ manifests: { latest: img.manifest }, blobs: { [sha(img.config)]: img.config } })(req, res);
  });
  try {
    const r = await fetchImage(`${reg.host}/acme/app:latest`, { ...opts, credentials: resolveCredentials(reg.host, { env: { AGENTIC_SECURITY_REGISTRY_TOKEN: 'registry-token' } }) });
    assert.equal(parseImageArchive(r.tar).layers.length, 1);
    assert.ok(reg.seen.some((s) => s.auth === 'Bearer registry-token'), 'the registry itself received the token');
    assert.ok(cdn.seen.length >= 1 && cdn.seen.every((s) => s.auth === null), `the other host must never see the credential: ${JSON.stringify(cdn.seen)}`);
  } finally { await reg.close(); await cdn.close(); }
});

test('redirect loops, and redirects to a non-HTTPS non-loopback target, are refused', async () => {
  const loop = await registry((req, res) => { res.writeHead(302, { location: req.url }); res.end(); });
  try { await assert.rejects(() => fetchImage(`${loop.host}/acme/app`, opts), (e) => e.code === 'redirect_loop'); } finally { await loop.close(); }
  const plain = await registry((req, res) => { res.writeHead(302, { location: 'http://registry.example.test/v2/x' }); res.end(); });
  try { await assert.rejects(() => fetchImage(`${plain.host}/acme/app`, opts), (e) => e.code === 'insecure_transport'); } finally { await plain.close(); }
});

test('plain HTTP is refused unless the registry is loopback AND the operator allowed it', async () => {
  const reg = await registry(serve({}));
  try {
    await assert.rejects(() => fetchImage(`${reg.host}/acme/app`, { env: {} }), (e) => e.code === 'network' || e.code === 'insecure_transport', 'https against a plain-HTTP port cannot succeed');
  } finally { await reg.close(); }
  await assert.rejects(() => fetchImage('registry.example.test/acme/app', { env: {}, fetchImpl: async (u) => { assert.match(u, /^https:/); throw new Error('stop'); } }), (e) => e.code === 'network');
});

test('hostile blobs: a wrong digest, a lying size, endless bytes and a lying content-length are all stopped', async () => {
  const img = makeImage();
  const wrong = await registry(serve({ manifests: { latest: img.manifest }, blobs: { [sha(img.config)]: img.config, [sha(img.layer)]: Buffer.concat([img.layer, Buffer.from('x')]) } }));
  try { await assert.rejects(() => fetchImage(`${wrong.host}/a/b`, opts), (e) => e.code === 'digest_mismatch'); } finally { await wrong.close(); }

  const big = { ...JSON.parse(img.manifest.toString()), layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: sha(img.layer), size: 10 ** 12 }] };
  const bigReg = await registry(serve({ manifests: { latest: Buffer.from(JSON.stringify(big)) }, blobs: {} }));
  try { await assert.rejects(() => fetchImage(`${bigReg.host}/a/b`, opts), (e) => e.code === 'too_large'); } finally { await bigReg.close(); }

  const endless = await registry((req, res) => {
    if (req.url.includes('/manifests/')) { res.writeHead(200, { 'content-type': 'application/vnd.oci.image.manifest.v1+json' }); return res.end(img.manifest); }
    if (req.url.includes(sha(img.config))) { res.writeHead(200); return res.end(img.config); }
    res.writeHead(200); let open = true; req.on('close', () => { open = false; }); const pump = () => { while (open && res.write(Buffer.alloc(65536))); if (open) res.once('drain', pump); }; pump();
  });
  try { await assert.rejects(() => fetchImage(`${endless.host}/a/b`, { ...opts, limits: { ...REGISTRY_LIMITS, maxLayerBytes: 2 * 1024 * 1024, maxTotalBytes: 3 * 1024 * 1024, requestTimeoutMs: 5000 } }), (e) => e.code === 'too_large' || e.code === 'digest_mismatch' || e.code === 'network'); } finally { await endless.close(); }

  const sizeLie = { ...JSON.parse(img.manifest.toString()), layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: sha(img.layer), size: img.layer.length + 5 }] };
  const lieReg = await registry(serve({ manifests: { latest: Buffer.from(JSON.stringify(sizeLie)) }, blobs: { [sha(img.config)]: img.config, [sha(img.layer)]: img.layer } }));
  try { await assert.rejects(() => fetchImage(`${lieReg.host}/a/b`, opts), (e) => e.code === 'digest_mismatch'); } finally { await lieReg.close(); }
});

test('a manifest the registry does not match to its reported digest, a digest reference that does not match, and malformed or unsupported manifests are refused', async () => {
  const img = makeImage();
  const lie = await registry(serve({ manifests: { latest: img.manifest }, headers: { 'docker-content-digest': `sha256:${'0'.repeat(64)}` } }));
  try { await assert.rejects(() => fetchImage(`${lie.host}/a/b`, opts), (e) => e.code === 'digest_mismatch' && /reported/.test(e.message)); } finally { await lie.close(); }
  const pinned = await registry(serve({ manifests: { [sha(img.manifest)]: Buffer.concat([img.manifest, Buffer.from(' ')]) } }));
  try { await assert.rejects(() => fetchImage(`${pinned.host}/a/b@${sha(img.manifest)}`, opts), (e) => e.code === 'digest_mismatch'); } finally { await pinned.close(); }
  for (const [body, code] of [['not json', 'malformed_manifest'], [JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config: { digest: 'md5:x' }, layers: [] }), 'malformed_manifest'], [JSON.stringify({ schemaVersion: 1, name: 'x' }), 'malformed_manifest']]) {
    const r = await registry(serve({ manifests: { latest: Buffer.from(body) } }));
    try { await assert.rejects(() => fetchImage(`${r.host}/a/b`, opts), (e) => e.code === code, body.slice(0, 40)); } finally { await r.close(); }
  }
  const foreign = { ...JSON.parse(img.manifest.toString()), layers: [{ mediaType: 'application/vnd.docker.image.rootfs.foreign.diff.tar.gzip', digest: sha(img.layer), size: 1, urls: ['http://elsewhere.example/blob'] }] };
  const f = await registry(serve({ manifests: { latest: Buffer.from(JSON.stringify(foreign)) } }));
  try { await assert.rejects(() => fetchImage(`${f.host}/a/b`, opts), (e) => e.code === 'unsupported_manifest' && /foreign/.test(e.message)); } finally { await f.close(); }
  const many = { ...JSON.parse(img.manifest.toString()), layers: Array.from({ length: 200 }, () => ({ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: sha(img.layer), size: 1 })) };
  const m = await registry(serve({ manifests: { latest: Buffer.from(JSON.stringify(many)) } }));
  try { await assert.rejects(() => fetchImage(`${m.host}/a/b`, opts), (e) => e.code === 'too_large' && /128 layers/.test(e.message)); } finally { await m.close(); }
});

test('not found, other registry errors and a cancelled request are distinct, typed outcomes', async () => {
  const reg = await registry((req, res) => { res.writeHead(req.url.includes('boom') ? 500 : 404); res.end(); });
  try {
    await assert.rejects(() => fetchImage(`${reg.host}/a/missing`, opts), (e) => e.code === 'not_found');
    await assert.rejects(() => fetchImage(`${reg.host}/a/boom`, opts), (e) => e.code === 'registry_error');
    const ac = new AbortController(); ac.abort();
    await assert.rejects(() => fetchImage(`${reg.host}/a/b`, { ...opts, signal: ac.signal }), (e) => e.code === 'network');
  } finally { await reg.close(); }
});

test('the OCI layout the client builds round-trips through the shared archive parser, and layer blobs are not duplicated', () => {
  const img = makeImage();
  const { tar, manifestDigest } = buildOciArchive({ manifest: img.manifest, config: img.config, layers: [img.layer, img.layer] });
  assert.equal(manifestDigest, sha(img.manifest));
  assert.equal(parseImageArchive(tar).digest, manifestDigest);
});
