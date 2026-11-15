export const id = 7952;
export const ids = [7952,642];
export const modules = {

/***/ 47952:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   analyzeLayerSecrets: () => (/* binding */ analyzeLayerSecrets)
/* harmony export */ });
/* unused harmony export DEFAULT_SECRET_SCAN_LIMITS */
/* harmony import */ var _safe_tar_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(90642);
// PRD 5 P0 §3 — Layer Secret Analysis: a secret added in one layer and later
// deleted (via an overlay whiteout) is still sitting in that earlier layer's
// raw tar bytes inside the image archive — recoverable by anyone who has the
// archive, even though it is invisible in `docker run`'s final filesystem.
//
// The actual credential detection is INJECTED as `detectFn` (the exact
// `(filePath, rawText) -> Finding[]` shape `src/posture/secret-history.js`
// already uses for the git-history analog of this same idea), so this module
// never imports `engine.js` and stays a pure, independently-testable
// transform over the layer data `filesystem.js` already extracted. The
// injected detector (`scanCredentials`) already returns only redacted/masked
// values (`masked`, a redacted `snippet`) — this module never re-touches raw
// file content once a finding exists, so there is no second place a value
// could leak back in.


const DEFAULT_SECRET_SCAN_LIMITS = Object.freeze({
  maxFileBytes: 512 * 1024,
});

/**
 * `readLayersResult` is `filesystem.js#readLayers`'s output (ordered,
 * per-layer, pre-merge entries — the only shape that preserves "this path
 * existed in layer 3" even after a later layer's whiteout removes it from
 * the merged view). `deletedPaths` is `mergeLayers`'s output.
 *
 * Returns `{ findings, deletedButRecoverable, materializationSkipped }`:
 *   - `findings`: every detector hit across every layer's added files, each
 *     tagged with `path`/`layerIndex` and the detector's own (already
 *     redacted) finding fields — this is the full history sweep, not just
 *     the deleted-but-recoverable subset.
 *   - `deletedButRecoverable`: the subset of `findings` whose `path` was
 *     later removed by a whiteout in a LATER layer — PRD 5's named scenario.
 *   - `materializationSkipped`: paths whose content was too large to scan
 *     (disclosed, never silently treated as "no secret found").
 */
function analyzeLayerSecrets({ readLayersResult, deletedPaths, detectFn, limits = DEFAULT_SECRET_SCAN_LIMITS }) {
  if (typeof detectFn !== 'function') throw new TypeError('analyzeLayerSecrets requires a detectFn(filePath, rawText) -> Finding[]');
  if (!readLayersResult || !Array.isArray(readLayersResult.layers)) throw new TypeError('analyzeLayerSecrets requires filesystem.js#readLayers output');

  const deletedAtByPath = new Map(); // path -> earliest layer index that deleted it
  for (const d of deletedPaths || []) {
    if (d.opaque) continue; // opaque-directory deletions are reported separately below
    if (!deletedAtByPath.has(d.path) || d.deletedAtLayer < deletedAtByPath.get(d.path)) {
      deletedAtByPath.set(d.path, d.deletedAtLayer);
    }
  }
  const opaqueDirs = (deletedPaths || []).filter((d) => d.opaque);

  const findings = [];
  const materializationSkipped = [];

  for (const { layerIndex, entries } of readLayersResult.layers) {
    for (const e of entries) {
      if ((0,_safe_tar_js__WEBPACK_IMPORTED_MODULE_0__/* .isWhiteoutName */ .l0)(e.name)) continue;
      if (e.typeflag !== '0' && e.typeflag !== '') continue; // regular files only
      if (e.size > limits.maxFileBytes) {
        materializationSkipped.push({ path: e.name, layerIndex, sizeBytes: e.size });
        continue;
      }
      let text;
      try {
        text = e.data.toString('utf8');
      } catch {
        continue; // not decodable as text — not a candidate for a text-pattern secret scan
      }
      let hits;
      try {
        hits = detectFn(e.name, text) || [];
      } catch {
        hits = []; // a detector failure on hostile/malformed content must never abort the sweep
      }
      for (const hit of hits) {
        const deletedAtLayer = deletedAtByPath.has(e.name) && deletedAtByPath.get(e.name) > layerIndex
          ? deletedAtByPath.get(e.name)
          : null;
        const underOpaqueDir = opaqueDirs.some((d) => d.deletedAtLayer > layerIndex && (e.name === d.path || e.name.startsWith(`${d.path}/`)));
        findings.push({
          ...hit,
          path: e.name,
          addedAtLayer: layerIndex,
          deletedAtLayer: deletedAtLayer ?? (underOpaqueDir ? opaqueDirs.find((d) => d.deletedAtLayer > layerIndex && (e.name === d.path || e.name.startsWith(`${d.path}/`))).deletedAtLayer : null),
          recoverable: deletedAtLayer != null || underOpaqueDir,
        });
      }
    }
  }

  const deletedButRecoverable = findings.filter((f) => f.recoverable);

  return { findings, deletedButRecoverable, materializationSkipped };
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
