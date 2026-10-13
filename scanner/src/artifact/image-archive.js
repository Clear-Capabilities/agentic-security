// Parses a Docker-save ("docker-archive") or OCI-layout ("oci-archive") tar
// into one normalized shape, without executing or daemon-mounting the image
// (PRD 5 Safety Requirements: "OCI inspection should not require executing
// the image"). Built entirely on `safe-tar.js` — every byte read here passes
// through the same entry-count/size/path/decompression guards.
import crypto from 'node:crypto';
import { readTarEntries, decompressIfGzip, DEFAULT_LIMITS } from './safe-tar.js';

export class ImageArchiveError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'ImageArchiveError';
    this.code = code;
  }
}

function safeJsonParse(buf, what) {
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch (err) {
    throw new ImageArchiveError(`${what} is not valid JSON: ${err.message}`, 'malformed_manifest');
  }
}

function readOuterEntries(buf, limits) {
  const outer = decompressIfGzip(buf, limits);
  const byName = new Map();
  const unsafeEntries = [];
  for (const e of readTarEntries(outer, limits)) {
    if (e.unsafe) {
      unsafeEntries.push({ name: e.name });
      continue;
    }
    byName.set(e.name, e);
  }
  return { byName, unsafeEntries };
}

function extractConfigShape(configObj) {
  const cfg = (configObj && configObj.config) || {};
  return {
    architecture: configObj.architecture || null,
    os: configObj.os || null,
    labels: (cfg.Labels && typeof cfg.Labels === 'object') ? { ...cfg.Labels } : {},
    entrypoint: Array.isArray(cfg.Entrypoint) ? [...cfg.Entrypoint] : null,
    cmd: Array.isArray(cfg.Cmd) ? [...cfg.Cmd] : null,
    history: Array.isArray(configObj.history)
      ? configObj.history.map((h) => ({ createdBy: h.created_by || null, created: h.created || null, emptyLayer: !!h.empty_layer }))
      : [],
    rootfsDiffIds: (configObj.rootfs && Array.isArray(configObj.rootfs.diff_ids)) ? [...configObj.rootfs.diff_ids] : [],
  };
}

function parseDockerArchive(byName, outerUnsafe, limits) {
  const manifestEntry = byName.get('manifest.json');
  const manifestArr = safeJsonParse(manifestEntry.data, 'manifest.json');
  if (!Array.isArray(manifestArr) || manifestArr.length === 0) {
    throw new ImageArchiveError('manifest.json contains no images', 'empty_manifest');
  }
  if (manifestArr.length > 1) {
    throw new ImageArchiveError(`manifest.json describes ${manifestArr.length} images; image scan expects exactly one`, 'multi_image_archive');
  }
  const m = manifestArr[0];
  if (typeof m.Config !== 'string' || !Array.isArray(m.Layers)) {
    throw new ImageArchiveError('manifest.json entry is missing Config or Layers', 'malformed_manifest');
  }
  const configEntry = byName.get(m.Config);
  if (!configEntry) throw new ImageArchiveError(`manifest.json references missing config "${m.Config}"`, 'missing_blob');
  const configObj = safeJsonParse(configEntry.data, m.Config);
  const configDigest = `sha256:${crypto.createHash('sha256').update(configEntry.data).digest('hex')}`;

  const layers = [];
  for (let i = 0; i < m.Layers.length; i++) {
    const layerPath = m.Layers[i];
    const entry = byName.get(layerPath);
    if (!entry) throw new ImageArchiveError(`manifest.json references missing layer "${layerPath}"`, 'missing_blob');
    const tar = decompressIfGzip(entry.data, limits);
    layers.push({ index: i, path: layerPath, diffId: configObj?.rootfs?.diff_ids?.[i] || null, tar, sizeBytes: entry.size });
  }

  return {
    format: 'docker-archive',
    digest: configDigest,
    digestKind: 'config',
    repoTags: Array.isArray(m.RepoTags) ? m.RepoTags : [],
    config: extractConfigShape(configObj),
    layers,
    unsafeEntries: outerUnsafe,
  };
}

function parseOciArchive(byName, outerUnsafe, limits) {
  const indexObj = safeJsonParse(byName.get('index.json').data, 'index.json');
  const manifests = Array.isArray(indexObj.manifests) ? indexObj.manifests : [];
  if (manifests.length === 0) throw new ImageArchiveError('index.json lists no manifests', 'empty_manifest');
  if (manifests.length > 1) {
    throw new ImageArchiveError(`index.json describes ${manifests.length} manifests; image scan expects exactly one`, 'multi_image_archive');
  }
  const manifestDigest = manifests[0].digest;
  if (typeof manifestDigest !== 'string' || !manifestDigest.startsWith('sha256:')) {
    throw new ImageArchiveError('index.json manifest entry has no sha256 digest', 'malformed_manifest');
  }
  const manifestBlobPath = `blobs/sha256/${manifestDigest.slice('sha256:'.length)}`;
  const manifestEntry = byName.get(manifestBlobPath);
  if (!manifestEntry) throw new ImageArchiveError(`index.json references missing manifest blob "${manifestBlobPath}"`, 'missing_blob');
  const manifestObj = safeJsonParse(manifestEntry.data, manifestBlobPath);

  const configDigest = manifestObj.config && manifestObj.config.digest;
  if (typeof configDigest !== 'string' || !configDigest.startsWith('sha256:')) {
    throw new ImageArchiveError('image manifest has no config digest', 'malformed_manifest');
  }
  const configBlobPath = `blobs/sha256/${configDigest.slice('sha256:'.length)}`;
  const configEntry = byName.get(configBlobPath);
  if (!configEntry) throw new ImageArchiveError(`manifest references missing config blob "${configBlobPath}"`, 'missing_blob');
  const configObj = safeJsonParse(configEntry.data, configBlobPath);

  const layerDescs = Array.isArray(manifestObj.layers) ? manifestObj.layers : [];
  const layers = [];
  for (let i = 0; i < layerDescs.length; i++) {
    const d = layerDescs[i];
    if (typeof d.digest !== 'string' || !d.digest.startsWith('sha256:')) {
      throw new ImageArchiveError(`layer ${i} has no sha256 digest`, 'malformed_manifest');
    }
    const blobPath = `blobs/sha256/${d.digest.slice('sha256:'.length)}`;
    const entry = byName.get(blobPath);
    if (!entry) throw new ImageArchiveError(`manifest references missing layer blob "${blobPath}"`, 'missing_blob');
    const tar = decompressIfGzip(entry.data, limits);
    layers.push({ index: i, path: blobPath, diffId: d.digest, mediaType: d.mediaType || null, tar, sizeBytes: entry.size });
  }

  return {
    format: 'oci-archive',
    digest: manifestDigest,
    digestKind: 'manifest',
    repoTags: [],
    config: extractConfigShape(configObj),
    layers,
    unsafeEntries: outerUnsafe,
  };
}

/**
 * Parses an in-memory tar buffer (already read from disk/stdin by the
 * caller — this module never touches the filesystem or network) as either a
 * `docker save`-shaped archive or an OCI-layout archive. Throws
 * ImageArchiveError for anything it cannot recognize or whose manifest
 * references a blob that isn't present — never guesses or substitutes a
 * default.
 */
export function parseImageArchive(buf, limits = DEFAULT_LIMITS) {
  if (!Buffer.isBuffer(buf)) throw new ImageArchiveError('image archive input must be a Buffer', 'bad_input');
  const { byName, unsafeEntries } = readOuterEntries(buf, limits);
  if (byName.has('manifest.json')) return parseDockerArchive(byName, unsafeEntries, limits);
  if (byName.has('index.json') && byName.has('oci-layout')) return parseOciArchive(byName, unsafeEntries, limits);
  throw new ImageArchiveError(
    'archive is neither a docker-archive (manifest.json) nor an oci-archive (oci-layout + index.json)',
    'unrecognized_format',
  );
}
