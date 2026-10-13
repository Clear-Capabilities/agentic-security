// PRD 5 P0 §1-2 — OCI image scanning + inventory. Ties image-archive.js
// (manifest/config/layer parsing) and filesystem.js (whiteout-aware layer
// merge) into the single inventory shape the PRD names: digest, OS, OS
// packages, application packages, architecture, base image, layers,
// entrypoint, build labels.
import { parseImageArchive } from './image-archive.js';
import { readLayers, mergeLayers, DEFAULT_FS_LIMITS } from './filesystem.js';
import { extractImagePackages } from '../sca/image-packages.js';
import { DEFAULT_LIMITS as DEFAULT_TAR_LIMITS } from './safe-tar.js';

// Buildkit/Docker provenance convention — not an OCI spec requirement, so
// its absence is reported as "not declared", never guessed from layer
// heuristics (no base-image fingerprint table exists in this codebase, and
// inventing one would produce a confident-looking wrong answer, which is the
// one failure mode PRD 5's own Safety Requirements single out by name for
// signature state — the same discipline applies here).
const BASE_IMAGE_NAME_LABEL = 'org.opencontainers.image.base.name';
const BASE_IMAGE_DIGEST_LABEL = 'org.opencontainers.image.base.digest';

/**
 * `buf` is an already-read image archive buffer (tar, optionally
 * gzip-wrapped). `manifestParser` is the engine's existing
 * `parseManifests(allFileContents)` (injected, mirroring
 * `src/posture/secret-history.js`'s detectFn injection, so this module never
 * imports `engine.js` directly and `src/sca/index.js` stays the one seam).
 * Returns `{ image, inventory }` where `image` is the raw parsed archive
 * (image-archive.js's shape, kept for callers that need layer tars — vuln
 * correlation, signature verification) and `inventory` is the PRD-named
 * report.
 */
export function buildImageInventory(buf, { manifestParser, tarLimits = DEFAULT_TAR_LIMITS, fsLimits = DEFAULT_FS_LIMITS } = {}) {
  if (typeof manifestParser !== 'function') throw new TypeError('buildImageInventory requires manifestParser(allFileContents)');
  const image = parseImageArchive(buf, tarLimits);
  const rl = readLayers(image.layers, tarLimits);
  const merged = mergeLayers(rl, fsLimits);

  const osPackages = extractImagePackages(merged.fileContents);
  let appPackages = [];
  try {
    appPackages = manifestParser(merged.fileContents) || [];
  } catch {
    appPackages = []; // a parser failure on hostile layer content must never abort inventory extraction
  }

  const labels = image.config.labels || {};
  const baseImage = labels[BASE_IMAGE_NAME_LABEL]
    ? { name: labels[BASE_IMAGE_NAME_LABEL], digest: labels[BASE_IMAGE_DIGEST_LABEL] || null, source: 'label' }
    : null;

  const inventory = {
    digest: image.digest,
    digestKind: image.digestKind,
    repoTags: image.repoTags,
    os: image.config.os,
    architecture: image.config.architecture,
    baseImage,
    osPackages,
    appPackages,
    layers: image.layers.map((l) => ({ index: l.index, sizeBytes: l.sizeBytes, diffId: l.diffId || null })),
    entrypoint: image.config.entrypoint,
    cmd: image.config.cmd,
    buildLabels: { ...labels },
    history: image.config.history,
    unsafeEntries: [...image.unsafeEntries, ...rl.unsafeEntries],
    materializationTruncated: merged.materializationTruncated,
  };

  return { image, inventory, mergedFilesystem: merged, readLayersResult: rl };
}
