// Minimal tar WRITER for building synthetic OCI/Docker image archives in
// tests and fixtures. Production code never writes tar (it only reads
// untrusted ones, via src/artifact/safe-tar.js); this is test-only, mirroring
// build-git-fixture.js's role for the lineage/deployment suites.
import zlib from 'node:zlib';
import crypto from 'node:crypto';

const BLOCK = 512;

function pad(buf, to) {
  const out = Buffer.alloc(to);
  buf.copy(out);
  return out;
}

function octal(n, len) {
  return pad(Buffer.from(n.toString(8).padStart(len - 1, '0') + '\0', 'ascii'), len);
}

function header({ name, size = 0, typeflag = '0', linkname = '' }) {
  const h = Buffer.alloc(BLOCK);
  pad(Buffer.from(name, 'utf8'), 100).copy(h, 0);
  pad(Buffer.from('0000644\0', 'ascii'), 8).copy(h, 100); // mode
  pad(Buffer.from('0000000\0', 'ascii'), 8).copy(h, 108); // uid
  pad(Buffer.from('0000000\0', 'ascii'), 8).copy(h, 116); // gid
  octal(size, 12).copy(h, 124);
  octal(0, 12).copy(h, 136); // mtime
  Buffer.from('        ', 'ascii').copy(h, 148); // checksum placeholder (spaces)
  h[156] = typeflag.charCodeAt(0);
  pad(Buffer.from(linkname, 'utf8'), 100).copy(h, 157);
  pad(Buffer.from('ustar\0', 'ascii'), 8).copy(h, 257);
  let sum = 0;
  for (const b of h) sum += b;
  octal(sum, 8).copy(h, 148);
  h[155] = 0; // keep null terminator inside the 8-byte checksum field's trailing byte
  return h;
}

function entryBlocks(name, content, opts = {}) {
  const data = content == null ? Buffer.alloc(0) : Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
  const h = header({ name, size: data.length, ...opts });
  const dataPadded = Buffer.alloc(Math.ceil(data.length / BLOCK) * BLOCK);
  data.copy(dataPadded);
  return Buffer.concat([h, dataPadded]);
}

/**
 * Builds an uncompressed tar from `entries`: an array of
 *   { name, content } for a regular file, or
 *   { name, typeflag: '5' } for a directory, or
 *   { name, whiteout: true } to emit a `.wh.<basename>` deletion marker.
 */
export function buildTar(entries) {
  const parts = [];
  for (const e of entries) {
    if (e.whiteout) {
      const segs = e.name.split('/');
      const base = segs.pop();
      parts.push(entryBlocks([...segs, `.wh.${base}`].join('/'), null));
      continue;
    }
    parts.push(entryBlocks(e.name, e.content ?? null, { typeflag: e.typeflag || '0' }));
  }
  parts.push(Buffer.alloc(BLOCK * 2)); // end-of-archive marker
  return Buffer.concat(parts);
}

export function gzipTar(entries) {
  return zlib.gzipSync(buildTar(entries));
}

/**
 * Builds a complete synthetic `docker save`-shaped archive (classic Docker
 * Image Spec v1.2): manifest.json + a config blob + one layer.tar per entry
 * in `layers`. Each layer is a plain tar (uncompressed, matching real
 * `docker save` output) built from `buildTar(layer.files)`.
 */
export function buildDockerArchive({ config, layers, repoTags = ['example:latest'] }) {
  const layerTars = layers.map((l) => buildTar(l.files));
  const diffIds = layerTars.map((t) => 'sha256:' + crypto.createHash('sha256').update(t).digest('hex'));
  const configObj = {
    architecture: config.architecture || 'amd64',
    os: config.os || 'linux',
    config: {
      Labels: config.labels || {},
      Entrypoint: config.entrypoint || null,
      Cmd: config.cmd || null,
    },
    history: layers.map((l, i) => ({ created_by: l.createdBy || `layer ${i}` })),
    rootfs: { type: 'layers', diff_ids: diffIds },
  };
  const configBuf = Buffer.from(JSON.stringify(configObj), 'utf8');
  const configHash = crypto.createHash('sha256').update(configBuf).digest('hex');
  const manifest = [
    {
      Config: `${configHash}.json`,
      RepoTags: repoTags,
      Layers: layers.map((_, i) => `layer${i}/layer.tar`),
    },
  ];
  const outerEntries = [
    { name: 'manifest.json', content: JSON.stringify(manifest) },
    { name: `${configHash}.json`, content: configBuf },
  ];
  for (let i = 0; i < layerTars.length; i++) {
    outerEntries.push({ name: `layer${i}/layer.tar`, content: layerTars[i] });
  }
  return buildTar(outerEntries);
}

/**
 * Builds a synthetic OCI-layout archive: oci-layout + index.json + blobs/sha256/*.
 * Layers are gzip-compressed tars (matching real oci-archive output).
 */
export function buildOciArchive({ config, layers, mediaType = 'application/vnd.oci.image.layer.v1.tar+gzip' }) {
  const layerBlobs = layers.map((l) => zlib.gzipSync(buildTar(l.files)));
  const layerDigests = layerBlobs.map((b) => crypto.createHash('sha256').update(b).digest('hex'));
  const diffIds = layers.map((l) => 'sha256:' + crypto.createHash('sha256').update(buildTar(l.files)).digest('hex'));
  const configObj = {
    architecture: config.architecture || 'amd64',
    os: config.os || 'linux',
    config: {
      Labels: config.labels || {},
      Entrypoint: config.entrypoint || null,
      Cmd: config.cmd || null,
    },
    history: layers.map((l, i) => ({ created_by: l.createdBy || `layer ${i}` })),
    rootfs: { type: 'layers', diff_ids: diffIds },
  };
  const configBuf = Buffer.from(JSON.stringify(configObj), 'utf8');
  const configDigest = crypto.createHash('sha256').update(configBuf).digest('hex');
  const manifestObj = {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: `sha256:${configDigest}`, size: configBuf.length },
    layers: layerBlobs.map((b, i) => ({ mediaType, digest: `sha256:${layerDigests[i]}`, size: b.length })),
  };
  const manifestBuf = Buffer.from(JSON.stringify(manifestObj), 'utf8');
  const manifestDigest = crypto.createHash('sha256').update(manifestBuf).digest('hex');
  const indexObj = {
    schemaVersion: 2,
    manifests: [{ mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: `sha256:${manifestDigest}`, size: manifestBuf.length }],
  };
  const entries = [
    { name: 'oci-layout', content: JSON.stringify({ imageLayoutVersion: '1.0.0' }) },
    { name: 'index.json', content: JSON.stringify(indexObj) },
    { name: `blobs/sha256/${manifestDigest}`, content: manifestBuf },
    { name: `blobs/sha256/${configDigest}`, content: configBuf },
  ];
  for (let i = 0; i < layerBlobs.length; i++) {
    entries.push({ name: `blobs/sha256/${layerDigests[i]}`, content: layerBlobs[i] });
  }
  return buildTar(entries);
}
