export const id = 7055;
export const ids = [7055,642];
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


/***/ })

};
