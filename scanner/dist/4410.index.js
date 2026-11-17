export const id = 4410;
export const ids = [4410,3415];
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

/***/ 24410:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   artifactVerdict: () => (/* binding */ artifactVerdict),
/* harmony export */   compareArtifact: () => (/* binding */ compareArtifact),
/* harmony export */   readImage: () => (/* binding */ readImage),
/* harmony export */   rerunOnArtifact: () => (/* binding */ rerunOnArtifact)
/* harmony export */ });
/* harmony import */ var _artifact_inventory_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(55086);
/* harmony import */ var _posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(41877);
/* harmony import */ var _dependencies_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(74178);
/* harmony import */ var _lab_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(73633);
/* harmony import */ var _counterexamples_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(68941);
// Source-to-artifact verification of a repair (verified-remediation PRD FR-16, M4-06): does the built artifact contain the verified
// repair, and does it still meet the contract?
//
// The image is read through the hardened archive reader (`src/artifact/`: `docker save` or OCI-layout tar, whiteout-aware layer merge;
// nothing is written to disk from the image). Three checks, all required for `artifact-verified`:
//
//   1. content   every file of the verified patch is in the image under the declared application directory with its PATCHED digest. A
//                file with its PRE-PATCH digest means the image was built from unpatched source (AC-16.1); a missing or different file
//                is a mismatch too.
//   2. packages  for a dependency repair, every package the verified lockfile resolves is in the image at that version, and no copy of
//                the advisory's package in the vulnerable range is anywhere under the application directory (AC-16.2).
//   3. behaviour the contract's oracle obligations are run again against the image's own files (the application and its node_modules as
//                the image ships them), through the trust boundary like any run. Each must meet its patched expectation.
//
// A signature, a label or a deployment receipt never sets any of this (AC-16.6): only these executed comparisons do. Staging and
// deployment are not observed here: the record's `environment` stays `not-checked`.






const norm = (d) => String(d || '').replace(/^\/+|\/+$/g, '');

/** Read an image archive into its merged file view. Throws on an archive the reader refuses. */
function readImage(buf) {
  const { inventory, mergedFilesystem } = (0,_artifact_inventory_js__WEBPACK_IMPORTED_MODULE_0__.buildImageInventory)(buf, { manifestParser: () => [] });
  return { digest: inventory.digest, files: mergedFilesystem.fileContents, truncated: !!inventory.materializationTruncated, unsafe: inventory.unsafeEntries.length };
}

/** The content and package checks. Pure over the image's file view. */
function compareArtifact({ record, plan, image, appDir }) {
  const base = norm(appDir);
  const at = (rel) => image.files[base ? `${base}/${rel}` : rel];
  const files = [];
  const patch = record.exactPatch || { files: {}, beforeDigests: {}, afterDigests: {} };
  for (const rel of Object.keys(patch.afterDigests || {})) {
    const text = at(rel);
    const after = patch.afterDigests[rel]; const before = patch.beforeDigests?.[rel] ?? null;
    if (after === null) { files.push({ file: rel, state: text === undefined ? 'removed' : 'still-present' }); continue; }
    if (text === undefined) { files.push({ file: rel, state: 'absent' }); continue; }
    const d = (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_1__/* .digestOf */ .ol)(text);
    files.push({ file: rel, state: d === after ? 'patched' : d === before ? 'unpatched' : 'different' });
  }
  const problems = files.filter((f) => !['patched', 'removed'].includes(f.state)).map((f) => (f.state === 'unpatched' ? `${f.file} is the pre-patch version: the image was built from unpatched source` : `${f.file}: ${f.state}`));
  const packages = [];
  const dep = plan.contract.obligations.find((o) => o.kind === 'dependency-resolved')?.inputs;
  if (dep) {
    let lock = null;
    try { lock = JSON.parse(patch.files?.['package-lock.json'] ?? ''); } catch { /* the lockfile was not part of the patch */ }
    for (const [p, e] of Object.entries(lock?.packages || {})) {
      if (!p) continue;
      let meta = null;
      try { meta = JSON.parse(at(`${p}/package.json`) ?? 'null'); } catch { /* unreadable */ }
      const state = !meta ? 'absent' : meta.version === e.version ? 'present' : `version ${meta.version}`;
      packages.push({ path: p, version: e.version, state });
      if (state !== 'present') problems.push(`${p}@${e.version} is ${state === 'absent' ? 'absent from' : `${state} in`} the image`);
    }
    const prefix = base ? `${base}/` : '';
    for (const [file, text] of Object.entries(image.files)) {
      if (!file.startsWith(prefix) || !file.endsWith(`node_modules/${dep.package}/package.json`)) continue;
      let v = null; try { v = JSON.parse(text).version; } catch { /* unreadable */ }
      if (v && (0,_dependencies_js__WEBPACK_IMPORTED_MODULE_2__/* .satisfies */ .ib)(v, dep.vulnerable)) problems.push(`the image ships ${dep.package}@${v} at ${file.slice(prefix.length, -'/package.json'.length)}, in the vulnerable range ${dep.vulnerable}`);
    }
  }
  return { files, packages, problems };
}

/**
 * Run the contract's oracle obligations against the image's files. `config` must enable execution. Returns one result per obligation.
 */
async function rerunOnArtifact({ record, plan, image, appDir, config, deps = {} }) {
  const base = norm(appDir);
  const prefix = base ? `${base}/` : '';
  const app = {};
  for (const rel of plan.contract.profile.application.files) { const t = image.files[`${prefix}${rel}`]; if (t !== undefined) app[rel] = t; }
  for (const [file, text] of Object.entries(image.files)) if (file.startsWith(`${prefix}node_modules/`)) app[file.slice(prefix.length)] = text;
  const q = record.quarantined || [];
  const out = [];
  for (const ob of plan.contract.obligations.filter((o) => o.oracleId)) {
    const inputs = (0,_counterexamples_js__WEBPACK_IMPORTED_MODULE_4__/* .withoutQuarantined */ .h4)(ob.inputs, q.filter((x) => x.obligation === ob.id));
    const res = await (0,_lab_js__WEBPACK_IMPORTED_MODULE_3__/* .runObligation */ .SX)(ob, app, { config, entry: plan.entry, hypothesisId: `${plan.contract.contractId}:${ob.id}:artifact`, inputs, ...deps });
    out.push({ obligation: ob.id, kind: ob.kind, observed: res.observed, status: (0,_lab_js__WEBPACK_IMPORTED_MODULE_3__/* .judge */ .S4)(res.observed, ob.patchedExpectation), reason: String(res.reason || '').slice(0, 300), receiptDigest: res.receipt ? (0,_posture_assurance_identity_js__WEBPACK_IMPORTED_MODULE_1__/* .digestOf */ .ol)(res.receipt.recordId || res.receipt) : null });
  }
  return out;
}

/** The artifact state and the record's `source` block from the three checks. */
function artifactVerdict({ image, appDir, comparison, checks }) {
  const failedChecks = (checks || []).filter((c) => c.status !== 'passed');
  const executed = Array.isArray(checks) && checks.length > 0 && checks.every((c) => !['unavailable', 'invalid'].includes(c.status));
  let artifact;
  if (comparison.problems.length || failedChecks.some((c) => c.status === 'failed')) artifact = 'artifact-mismatch';
  else if (!executed || failedChecks.length) artifact = 'unavailable';
  else artifact = 'artifact-verified';
  return {
    artifact,
    source: { artifactDigest: image.digest, appDir: norm(appDir), files: comparison.files, packages: comparison.packages, checks: checks || [], problems: [...comparison.problems, ...failedChecks.map((c) => `${c.obligation} on the artifact: ${c.status} (${c.reason})`)].slice(0, 40), note: 'content and behaviour of this image only; nothing about staging or deployment' },
  };
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
