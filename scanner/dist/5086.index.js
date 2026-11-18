export const id = 5086;
export const ids = [5086,7055,642,3415];
export const modules = {

/***/ 57055:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ImageArchiveError: () => (/* binding */ ImageArchiveError),
/* harmony export */   t: () => (/* binding */ parseImageArchive)
/* harmony export */ });
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var _safe_tar_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(90642);
// Parses a Docker-save ("docker-archive") or OCI-layout ("oci-archive") tar
// into one normalized shape, without executing or daemon-mounting the image
// (PRD 5 Safety Requirements: "OCI inspection should not require executing
// the image"). Built entirely on `safe-tar.js` — every byte read here passes
// through the same entry-count/size/path/decompression guards.



class ImageArchiveError extends Error {
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
  const outer = (0,_safe_tar_js__WEBPACK_IMPORTED_MODULE_1__/* .decompressIfGzip */ .zr)(buf, limits);
  const byName = new Map();
  const unsafeEntries = [];
  for (const e of (0,_safe_tar_js__WEBPACK_IMPORTED_MODULE_1__/* .readTarEntries */ .ET)(outer, limits)) {
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
  const configDigest = `sha256:${node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(configEntry.data).digest('hex')}`;

  const layers = [];
  for (let i = 0; i < m.Layers.length; i++) {
    const layerPath = m.Layers[i];
    const entry = byName.get(layerPath);
    if (!entry) throw new ImageArchiveError(`manifest.json references missing layer "${layerPath}"`, 'missing_blob');
    const tar = (0,_safe_tar_js__WEBPACK_IMPORTED_MODULE_1__/* .decompressIfGzip */ .zr)(entry.data, limits);
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
    const tar = (0,_safe_tar_js__WEBPACK_IMPORTED_MODULE_1__/* .decompressIfGzip */ .zr)(entry.data, limits);
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
function parseImageArchive(buf, limits = _safe_tar_js__WEBPACK_IMPORTED_MODULE_1__/* .DEFAULT_LIMITS */ .dR) {
  if (!Buffer.isBuffer(buf)) throw new ImageArchiveError('image archive input must be a Buffer', 'bad_input');
  const { byName, unsafeEntries } = readOuterEntries(buf, limits);
  if (byName.has('manifest.json')) return parseDockerArchive(byName, unsafeEntries, limits);
  if (byName.has('index.json') && byName.has('oci-layout')) return parseOciArchive(byName, unsafeEntries, limits);
  throw new ImageArchiveError(
    'archive is neither a docker-archive (manifest.json) nor an oci-archive (oci-layout + index.json)',
    'unrecognized_format',
  );
}


/***/ }),

/***/ 55086:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  buildImageInventory: () => (/* binding */ buildImageInventory)
});

// EXTERNAL MODULE: ./src/artifact/image-archive.js
var image_archive = __webpack_require__(57055);
// EXTERNAL MODULE: ./src/artifact/safe-tar.js
var safe_tar = __webpack_require__(90642);
;// CONCATENATED MODULE: ./src/artifact/filesystem.js
// Merges an image's layers (in order) into one virtual filesystem view,
// applying AUFS/overlay whiteout semantics (`.wh.<name>` deletes a file,
// `.wh..wh..opq` makes a directory opaque to everything below it in earlier
// layers). Nothing here ever writes to a real filesystem path — the merged
// view is an in-memory Map keyed by the tar entry's (already path-safety-
// checked) name, which is what makes this immune to zip-slip by construction
// rather than by convention.


const DEFAULT_FS_LIMITS = Object.freeze({
  maxFileBytes: 1 * 1024 * 1024, // per-file materialization cap
  maxMaterializedTotalBytes: 256 * 1024 * 1024, // total content kept in memory
});

/**
 * Reads every layer's tar into per-layer entry lists (bounded by the same
 * safe-tar limits as the outer archive) without merging — the raw, ordered
 * per-layer view that layer-secrets.js needs to see what a LATER layer
 * deleted while it was still present in an EARLIER one.
 */
function readLayers(layers, tarLimits = safe_tar/* DEFAULT_LIMITS */.dR) {
  const result = [];
  const unsafeEntries = [];
  for (const layer of layers) {
    const entries = [];
    for (const e of (0,safe_tar/* readTarEntries */.ET)(layer.tar, tarLimits)) {
      if (e.unsafe) {
        unsafeEntries.push({ layerIndex: layer.index, name: e.name });
        continue;
      }
      entries.push(e);
    }
    result.push({ layerIndex: layer.index, entries });
  }
  return { layers: result, unsafeEntries };
}

/**
 * Merges the per-layer entry lists (from readLayers) into one final
 * filesystem view, applying whiteouts in layer order. Returns:
 *   - `files`: Map<path, { sizeBytes, sourceLayerIndex, typeflag }> — every
 *     surviving path, metadata only.
 *   - `fileContents`: { path: string } — decoded text content, capped per
 *     file and in total (see DEFAULT_FS_LIMITS); large/binary files are
 *     present in `files` but absent here.
 *   - `deletedPaths`: [{ path, deletedAtLayer, opaque }] — every whiteout
 *     seen, in order, regardless of whether the path ever existed.
 *   - `materializationTruncated`: true once the total content cap was hit —
 *     disclosed, not silent.
 */
function mergeLayers(readLayersResult, fsLimits = DEFAULT_FS_LIMITS) {
  const files = new Map(); // path -> { sizeBytes, sourceLayerIndex, typeflag, data }
  const deletedPaths = [];
  let materializedTotal = 0;
  let materializationTruncated = false;

  for (const { layerIndex, entries } of readLayersResult.layers) {
    const opaqueDirs = [];
    for (const e of entries) {
      if ((0,safe_tar/* isWhiteoutName */.l0)(e.name)) {
        const wh = (0,safe_tar/* whiteoutTarget */.Jn)(e.name);
        if (wh.opaque) {
          opaqueDirs.push(wh.dir);
          deletedPaths.push({ path: wh.dir, deletedAtLayer: layerIndex, opaque: true });
          for (const existing of [...files.keys()]) {
            if (existing === wh.dir || existing.startsWith(`${wh.dir}/`)) files.delete(existing);
          }
        } else {
          deletedPaths.push({ path: wh.path, deletedAtLayer: layerIndex, opaque: false });
          files.delete(wh.path);
        }
        continue;
      }
      // An opaque marker earlier in THIS layer hides any further entry in
      // this same layer that would resurrect something under that dir —
      // real overlay semantics scope opaque to "everything from layers
      // BELOW this one", so same-layer adds after the marker still apply.
      files.set(e.name, { sizeBytes: e.size, sourceLayerIndex: layerIndex, typeflag: e.typeflag, data: e.data });
    }
  }

  const fileContents = {};
  for (const [path, meta] of files) {
    if (meta.typeflag !== '0' && meta.typeflag !== '') continue; // only regular files get content
    if (meta.sizeBytes > fsLimits.maxFileBytes) continue;
    if (materializedTotal + meta.sizeBytes > fsLimits.maxMaterializedTotalBytes) {
      materializationTruncated = true;
      continue;
    }
    fileContents[path] = meta.data.toString('utf8');
    materializedTotal += meta.sizeBytes;
  }

  const fileMeta = new Map();
  for (const [path, meta] of files) {
    fileMeta.set(path, { sizeBytes: meta.sizeBytes, sourceLayerIndex: meta.sourceLayerIndex, typeflag: meta.typeflag });
  }

  return { files: fileMeta, fileContents, deletedPaths, materializationTruncated };
}

// EXTERNAL MODULE: ./src/sca/image-packages.js
var image_packages = __webpack_require__(13415);
;// CONCATENATED MODULE: ./src/artifact/inventory.js
// PRD 5 P0 §1-2 — OCI image scanning + inventory. Ties image-archive.js
// (manifest/config/layer parsing) and filesystem.js (whiteout-aware layer
// merge) into the single inventory shape the PRD names: digest, OS, OS
// packages, application packages, architecture, base image, layers,
// entrypoint, build labels.





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
function buildImageInventory(buf, { manifestParser, tarLimits = safe_tar/* DEFAULT_LIMITS */.dR, fsLimits = DEFAULT_FS_LIMITS } = {}) {
  if (typeof manifestParser !== 'function') throw new TypeError('buildImageInventory requires manifestParser(allFileContents)');
  const image = (0,image_archive/* parseImageArchive */.t)(buf, tarLimits);
  const rl = readLayers(image.layers, tarLimits);
  const merged = mergeLayers(rl, fsLimits);

  const osPackages = (0,image_packages.extractImagePackages)(merged.fileContents);
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


/***/ }),

/***/ 90642:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ET: () => (/* binding */ readTarEntries),
/* harmony export */   Jn: () => (/* binding */ whiteoutTarget),
/* harmony export */   TarSafetyError: () => (/* binding */ TarSafetyError),
/* harmony export */   dR: () => (/* binding */ DEFAULT_LIMITS),
/* harmony export */   l0: () => (/* binding */ isWhiteoutName),
/* harmony export */   zr: () => (/* binding */ decompressIfGzip)
/* harmony export */ });
/* unused harmony export isSafeEntryName */
/* harmony import */ var node_zlib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(38522);
// Hand-rolled, hardened POSIX/GNU tar reader for OCI/Docker image archives.
//
// Why hand-rolled instead of a dependency: this repo has no tar library (see
// `src/artifact/CLAUDE.md`), and PRD 5's own Safety Requirements ask for exact
// control over the failure modes a generic tar library treats as implementation
// detail: malicious entry paths, decompression bombs, giant layers, oversized
// archives. Rolling it ourselves means every one of those limits is a named,
// tested constant in this file rather than a library default we'd have to audit.
//
// Scope: ustar + GNU longname ('L' typeflag) + base-256 size fields. PAX extended
// headers ('x'/'g') and GNU longlink ('K') are structurally skipped (their data
// block is consumed so offsets stay correct, but their content is not applied) —
// a disclosed limitation, not a silent one. Real docker-save/oci-archive output
// from Go's archive/tar for images in this size/complexity class essentially
// never needs them; synthetic fixtures in this codebase never emit them either.


const BLOCK = 512;

const DEFAULT_LIMITS = Object.freeze({
  maxEntries: 200_000,
  maxEntrySize: 512 * 1024 * 1024, // 512MB per tar entry
  maxTotalSize: 4 * 1024 * 1024 * 1024, // 4GB per archive (sum of entry sizes)
  maxGunzipOutput: 4 * 1024 * 1024 * 1024, // decompression-bomb guard
});

class TarSafetyError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'TarSafetyError';
    this.code = code;
  }
}

function parseSizeField(buf) {
  if (buf[0] & 0x80) {
    // GNU base-256 extension for sizes that don't fit in octal-ASCII.
    let n = 0n;
    for (let i = 1; i < buf.length; i++) n = (n << 8n) | BigInt(buf[i]);
    return Number(n);
  }
  const s = buf.toString('ascii').replace(/\0.*$/, '').trim();
  if (!s) return 0;
  const n = parseInt(s, 8);
  return Number.isFinite(n) ? n : 0;
}

function cstr(buf) {
  return buf.toString('utf8').replace(/\0.*$/, '');
}

// A tar entry name is unsafe when it would escape a virtual extraction root:
// absolute paths, `..` segments, embedded NULs, or an unreasonable length.
// Because this module never writes to a real filesystem path (every caller
// keeps extracted content in an in-memory Map keyed by this string), the
// classic zip-slip *write* vulnerability cannot occur here — but a hostile
// name must still never be silently treated as an ordinary path by downstream
// manifest/package-DB matching, so unsafe entries are flagged, never dropped
// silently and never accepted as-is.
function isSafeEntryName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 4096) return false;
  if (name.includes('\0')) return false;
  const norm = name.replace(/\\/g, '/');
  if (norm.startsWith('/')) return false;
  if (norm.split('/').some((p) => p === '..')) return false;
  return true;
}

function isWhiteoutName(name) {
  return (name.split('/').pop() || '').startsWith('.wh.');
}

// Resolves a whiteout entry name to what it deletes. `.wh..wh..opq` marks a
// directory as "opaque" (everything from earlier layers under it is hidden,
// not individually deleted) — reported distinctly so callers don't conflate
// it with a single-file deletion.
function whiteoutTarget(name) {
  const parts = name.split('/');
  const base = parts.pop();
  if (base === '.wh..wh..opq') return { opaque: true, dir: parts.join('/') };
  return { opaque: false, path: [...parts, base.slice(4)].join('/') };
}

// Decompresses a gzip member with a hard output-size cap (Node's native
// ERR_BUFFER_TOO_LARGE on overflow — no custom streaming counter needed).
// Returns the input unchanged when it isn't gzip-magic (plain tar).
function decompressIfGzip(buf, limits = DEFAULT_LIMITS) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      return node_zlib__WEBPACK_IMPORTED_MODULE_0__.gunzipSync(buf, { maxOutputLength: limits.maxGunzipOutput });
    } catch (err) {
      if (err && err.code === 'ERR_BUFFER_TOO_LARGE') {
        throw new TarSafetyError('decompressed layer exceeds the decompression-bomb guard', 'gunzip_too_large');
      }
      throw new TarSafetyError(`gzip stream is malformed: ${err.message}`, 'gunzip_malformed');
    }
  }
  return buf;
}

/**
 * Reads a decompressed tar buffer and yields one record per entry:
 *   { name, size, typeflag, linkname, data, unsafe }
 * `data` is a Buffer view into `buf` (never copied) for safe entries, `null`
 * for unsafe ones. Throws TarSafetyError (never returns a partial result) the
 * moment any configured limit is exceeded.
 */
function* readTarEntries(buf, limits = DEFAULT_LIMITS) {
  if (!Buffer.isBuffer(buf)) throw new TarSafetyError('tar input must be a Buffer', 'bad_input');
  let offset = 0;
  let count = 0;
  let totalSize = 0;
  let pendingLongName = null;

  while (offset + BLOCK <= buf.length) {
    const header = buf.subarray(offset, offset + BLOCK);
    if (header.every((b) => b === 0)) {
      offset += BLOCK;
      continue; // end-of-archive zero-fill padding
    }

    count += 1;
    if (count > limits.maxEntries) {
      throw new TarSafetyError(`tar archive has more than ${limits.maxEntries} entries`, 'too_many_entries');
    }

    let name = cstr(header.subarray(0, 100));
    const typeflag = String.fromCharCode(header[156] || 0);
    const linkname = cstr(header.subarray(157, 257));
    const magic = header.subarray(257, 263).toString('ascii');
    const prefix = magic.startsWith('ustar') ? cstr(header.subarray(345, 500)) : '';
    if (prefix) name = `${prefix}/${name}`;
    const size = parseSizeField(header.subarray(124, 136));

    offset += BLOCK;

    if (size < 0 || !Number.isFinite(size)) {
      throw new TarSafetyError(`tar entry "${name}" has an invalid size field`, 'bad_size');
    }
    if (size > limits.maxEntrySize) {
      throw new TarSafetyError(`tar entry "${name}" (${size} bytes) exceeds the per-entry size limit`, 'entry_too_large');
    }
    totalSize += size;
    if (totalSize > limits.maxTotalSize) {
      throw new TarSafetyError('tar archive exceeds the total-size limit', 'archive_too_large');
    }

    const dataBlocks = Math.ceil(size / BLOCK);
    if (offset + size > buf.length) {
      throw new TarSafetyError(`tar entry "${name}" claims more data than the archive contains`, 'truncated');
    }
    const data = size > 0 ? buf.subarray(offset, offset + size) : Buffer.alloc(0);
    offset += dataBlocks * BLOCK;

    const resolvedName = pendingLongName ? pendingLongName : name;
    pendingLongName = null;

    if (typeflag === 'L') {
      // GNU longname: this entry's data IS the next entry's real name.
      pendingLongName = cstr(data);
      continue;
    }
    if (typeflag === 'K' || typeflag === 'x' || typeflag === 'g') {
      // GNU longlink / PAX extended header — structurally skipped (see header comment).
      continue;
    }

    if (!isSafeEntryName(resolvedName)) {
      yield { name: resolvedName, size, typeflag, linkname, data: null, unsafe: true };
      continue;
    }

    yield { name: resolvedName.replace(/\\/g, '/'), size, typeflag, linkname, data, unsafe: false };
  }
}


/***/ }),

/***/ 13415:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   extractImagePackages: () => (/* binding */ extractImagePackages)
/* harmony export */ });
/* unused harmony exports parseDpkgStatus, parseApkInstalled */
// R8 (PRD §5) — container-image OS-package inventory.
//
// container.js reads the Dockerfile (FROM + apt/apk install lines). This reads
// the ACTUAL installed-package databases from an extracted image filesystem
// (or the host), catching packages baked into the base image that the
// Dockerfile never names. Components flow into the existing OSV pipeline + SBOM.
//
// Pure parsers (unit-tested) + a path-matching extractor. No daemon; reads the
// package-DB files that appear when an image layer/tarball is unpacked.

// Debian/Ubuntu: /var/lib/dpkg/status — RFC822-style blocks separated by blank
// lines. Only "install ok installed" entries count (not removed/config-files).
function parseDpkgStatus(text) {
  const out = [];
  for (const block of String(text || '').split(/\n\s*\n/)) {
    const name = (block.match(/^Package:\s*(.+)$/m) || [])[1];
    const version = (block.match(/^Version:\s*(.+)$/m) || [])[1];
    const status = (block.match(/^Status:\s*(.+)$/m) || [])[1] || '';
    if (!name || !version) continue;
    if (!/\binstalled\b/.test(status)) continue;
    out.push({ name: name.trim(), version: version.trim(), ecosystem: 'Debian' });
  }
  return out;
}

// Alpine: /lib/apk/db/installed — blocks separated by blank lines; P:=name V:=version.
function parseApkInstalled(text) {
  const out = [];
  for (const block of String(text || '').split(/\n\s*\n/)) {
    const name = (block.match(/^P:(.+)$/m) || [])[1];
    const version = (block.match(/^V:(.+)$/m) || [])[1];
    if (!name || !version) continue;
    out.push({ name: name.trim(), version: version.trim(), ecosystem: 'Alpine' });
  }
  return out;
}

const _PURL = { Debian: (n, v) => `pkg:deb/debian/${n}@${v}`, Alpine: (n, v) => `pkg:apk/alpine/${n}@${v}` };

// File-path tells for an unpacked image. Match on path suffix so it works
// whether the scan root is the rootfs or a subdirectory of it.
function _dbKind(path) {
  const p = path.replace(/\\/g, '/');
  if (/(?:^|\/)var\/lib\/dpkg\/status$/.test(p)) return 'dpkg';
  if (/(?:^|\/)lib\/apk\/db\/installed$/.test(p)) return 'apk';
  return null;
}

/**
 * Extract OS-package components from any image package-DBs present in the scanned
 * files. Returns components in the engine's component shape so they ride the
 * existing OSV/SBOM pipeline. De-dups by ecosystem:name:version.
 */
function extractImagePackages(fileContents) {
  const comps = [];
  const seen = new Set();
  for (const [file, content] of Object.entries(fileContents || {})) {
    const kind = _dbKind(file);
    if (!kind) continue;
    const pkgs = kind === 'dpkg' ? parseDpkgStatus(content) : parseApkInstalled(content);
    for (const p of pkgs) {
      const key = `${p.ecosystem}:${p.name}:${p.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      comps.push({
        name: p.name, version: p.version, group: '', ecosystem: p.ecosystem,
        purl: (_PURL[p.ecosystem] || (() => null))(p.name, p.version),
        filePath: file, isUnpinned: false, isTransitive: false, isOsPackage: true,
        scope: 'required', reachable: true,
      });
    }
  }
  return comps;
}


/***/ })

};
