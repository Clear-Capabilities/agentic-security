export const id = 2584;
export const ids = [2584,2199,818,642];
export const modules = {

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

/***/ 52584:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdEval: () => (/* binding */ cmdEval),
  cmdModelsLab: () => (/* binding */ cmdModelsLab)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/util/yaml.js + 1 modules
var yaml = __webpack_require__(82340);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
;// CONCATENATED MODULE: ./src/posture/evaluation/lab/dataset.js
// Dataset manifest for the Eval Lab (PRD 6, requirements 1, 3 and 4).
//
// A dataset is the thing a model is measured on, so everything that could make a score meaningless is a validation error here,
// not a default:
//   * `leakagePolicy.mode` must be `enforce`. There is no `off`; a dataset cannot opt out of the leakage controls.
//   * a real-code dataset (`git-pairs`) must name a license that permits use. An unknown license refuses the dataset.
//   * every vulnerable entry carries the exact span the defect occupies (`expectedSpan`), so detection is scored on LOCATION, not
//     on "a finding of the right class exists somewhere in the file".
//   * every hard negative says what it resembles and which kind of safe code it is (sanitization, authorization, ...), because a
//     negative that does not look like a vulnerability measures nothing.
//
// Labels (kind, cwe, span, category, reproducer) live in the manifest and are NEVER written into a workspace an arm can read.
// A workspace reference is a directory inside the manifest's own folder, or a revision of a local git repository.
//
// Pure except `loadDatasetFile`, which reads one bounded file.





const DATASET_SCHEMA = 'agentic-security/eval-dataset';
const SPLITS = Object.freeze(['dev', 'validation', 'sealed']);
const ENTRY_KINDS = Object.freeze(['vulnerable', 'fixed', 'hard-negative']);
const HARD_NEGATIVE_CATEGORIES = Object.freeze(['sanitization', 'authorization', 'parameterization', 'bounds-check', 'correct-crypto', 'safe-wrapper']);
const SOURCE_KINDS = Object.freeze(['directory', 'git-pairs']);
const PERMITTED_LICENSES = Object.freeze(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0', '0BSD', 'Unlicense', 'CC0-1.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later', 'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later', 'AGPL-3.0-only', 'AGPL-3.0-or-later']);
const MAX_MANIFEST_BYTES = 5 * 1024 * 1024;
const MAX_ENTRIES = 20000;
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,79}$/;
const CWE_RE = /^CWE-\d{1,5}$/;
const REV_RE = /^[0-9a-f]{7,64}$/i;

const normalizeCwe = (c) => { const m = /(\d{1,5})/.exec(String(c ?? '')); return m ? `CWE-${Number(m[1])}` : null; };

function spanErrors(span, where) {
  const errs = [];
  if (!span || typeof span !== 'object') return [`${where} is required`];
  if (typeof span.file !== 'string' || !span.file || span.file.includes('\0') || span.file.startsWith('/') || span.file.split(/[\\/]/).includes('..')) errs.push(`${where}.file must be a relative path inside the workspace`);
  if (!Number.isInteger(span.startLine) || span.startLine < 1) errs.push(`${where}.startLine must be a positive integer`);
  if (!Number.isInteger(span.endLine) || span.endLine < span.startLine) errs.push(`${where}.endLine must be an integer at or after startLine`);
  return errs;
}

const argvOk = (a) => Array.isArray(a) && a.length > 0 && a.length <= 64 && a.every((x) => typeof x === 'string' && x.length < 2000 && !x.includes('\0'));

/** @returns {{ok: boolean, errors: string[]}} */
function validateDatasetManifest(m) {
  const errors = [];
  const bad = (msg) => errors.push(msg);
  if (!m || typeof m !== 'object' || Array.isArray(m)) return { ok: false, errors: ['manifest must be an object'] };
  const d = m.dataset;
  if (!d || typeof d !== 'object') return { ok: false, errors: ['manifest needs a "dataset" object'] };
  if (typeof d.id !== 'string' || !ID_RE.test(d.id)) bad('dataset.id must be a lower-case identifier');
  if (typeof d.version !== 'string' || !/^[0-9A-Za-z][0-9A-Za-z._+-]{0,39}$/.test(d.version)) bad('dataset.version is required');
  const langs = Array.isArray(d.language) ? d.language : [d.language];
  if (!langs.length || !langs.every((l) => typeof l === 'string' && /^[a-z][a-z0-9+#-]{0,19}$/.test(l))) bad('dataset.language must name one or more languages');
  if (!d.source || typeof d.source !== 'object' || !SOURCE_KINDS.includes(d.source.kind)) bad(`dataset.source.kind must be one of ${SOURCE_KINDS.join(', ')}`);
  if (!SPLITS.includes(d.split)) bad(`dataset.split must be one of ${SPLITS.join(', ')}`);
  if (typeof d.license !== 'string' || !d.license.trim()) bad('dataset.license is required');
  else if (d.source?.kind === 'git-pairs' && !PERMITTED_LICENSES.includes(d.license)) bad(`a real-code dataset needs a license that permits use (one of ${PERMITTED_LICENSES.slice(0, 6).join(', ')}, ...); "${d.license}" is not accepted`);
  if (!Array.isArray(d.cwe) || !d.cwe.length || !d.cwe.every((c) => CWE_RE.test(String(c)))) bad('dataset.cwe must list CWE ids such as CWE-89');
  const lp = d.leakagePolicy;
  if (!lp || typeof lp !== 'object') bad('dataset.leakagePolicy is required');
  else {
    if (lp.mode !== 'enforce') bad('dataset.leakagePolicy.mode must be "enforce"; a dataset cannot turn the leakage controls off');
    for (const k of ['stripComments', 'renameFiles']) if (lp[k] !== undefined && typeof lp[k] !== 'boolean') bad(`dataset.leakagePolicy.${k} must be a boolean`);
    if (lp.removePaths !== undefined && !(Array.isArray(lp.removePaths) && lp.removePaths.every((g) => typeof g === 'string' && g.length >= 1 && g.length <= 120 && !g.includes('\0')))) bad('dataset.leakagePolicy.removePaths must be a list of simple globs');
    if (lp.protectedTerms !== undefined && !(Array.isArray(lp.protectedTerms) && lp.protectedTerms.every((t) => typeof t === 'string' && t.length >= 4 && t.length <= 200))) bad('dataset.leakagePolicy.protectedTerms must be a list of strings of at least 4 characters');
  }
  if (d.build !== undefined && !argvOk(d.build)) bad('dataset.build must be an argv array');
  if (d.test !== undefined && !argvOk(d.test)) bad('dataset.test must be an argv array');

  const entries = m.entries;
  if (!Array.isArray(entries) || !entries.length) bad('entries must be a non-empty list');
  else if (entries.length > MAX_ENTRIES) bad(`entries is limited to ${MAX_ENTRIES}`);
  else {
    const seen = new Set();
    entries.forEach((e, i) => {
      const w = `entries[${i}]`;
      if (!e || typeof e !== 'object') { bad(`${w} must be an object`); return; }
      if (typeof e.id !== 'string' || !ID_RE.test(e.id)) bad(`${w}.id must be a lower-case identifier`);
      else if (seen.has(e.id)) bad(`${w}.id "${e.id}" is duplicated`);
      else seen.add(e.id);
      if (!ENTRY_KINDS.includes(e.kind)) bad(`${w}.kind must be one of ${ENTRY_KINDS.join(', ')}`);
      if (!e.workspace || typeof e.workspace !== 'object') bad(`${w}.workspace is required`);
      else if (typeof e.workspace.dir === 'string') {
        if (e.workspace.dir.startsWith('/') || e.workspace.dir.includes('\0') || e.workspace.dir.split(/[\\/]/).includes('..')) bad(`${w}.workspace.dir must stay inside the manifest folder`);
      } else if (e.workspace.git && typeof e.workspace.git === 'object') {
        if (typeof e.workspace.git.repo !== 'string' || !e.workspace.git.repo) bad(`${w}.workspace.git.repo is required`);
        if (typeof e.workspace.git.rev !== 'string' || !REV_RE.test(e.workspace.git.rev)) bad(`${w}.workspace.git.rev must be a commit id (a moving ref such as a branch is not reproducible)`);
      } else bad(`${w}.workspace needs "dir" or "git"`);
      if (e.kind === 'vulnerable') {
        if (!CWE_RE.test(String(e.cwe))) bad(`${w}.cwe is required for a vulnerable entry`);
        errors.push(...spanErrors(e.expectedSpan, `${w}.expectedSpan`));
        if (e.category !== undefined || e.lookalikeSpan !== undefined) bad(`${w}: category and lookalikeSpan belong to negative entries`);
      } else if (e.kind === 'hard-negative') {
        if (!HARD_NEGATIVE_CATEGORIES.includes(e.category)) bad(`${w}.category must be one of ${HARD_NEGATIVE_CATEGORIES.join(', ')}`);
        if (!CWE_RE.test(String(e.resemblesCwe))) bad(`${w}.resemblesCwe must name the weakness it looks like`);
        errors.push(...spanErrors(e.lookalikeSpan, `${w}.lookalikeSpan`));
        if (e.expectedSpan !== undefined) bad(`${w}: a hard negative has no expectedSpan; it is not vulnerable`);
      } else if (e.kind === 'fixed') {
        if (!CWE_RE.test(String(e.resemblesCwe ?? e.cwe))) bad(`${w}.resemblesCwe must name the weakness that was fixed`);
        if (e.lookalikeSpan !== undefined) errors.push(...spanErrors(e.lookalikeSpan, `${w}.lookalikeSpan`));
      }
      if (e.reproducer !== undefined && (typeof e.reproducer !== 'string' || e.reproducer.startsWith('/') || e.reproducer.split(/[\\/]/).includes('..'))) bad(`${w}.reproducer must be a relative path inside the manifest folder`);
      if (e.test !== undefined && !argvOk(e.test)) bad(`${w}.test must be an argv array`);
    });
    if (!entries.some((e) => e?.kind === 'vulnerable')) bad('a dataset needs at least one vulnerable entry');
    if (!entries.some((e) => e?.kind === 'hard-negative' || e?.kind === 'fixed')) bad('a dataset needs at least one negative entry (fixed or hard-negative); without one, precision cannot be measured');
  }
  return { ok: errors.length === 0, errors };
}

/** Content hash of everything that defines what is measured. Key order does not matter. */
const datasetHash = (m) => (0,identity/* digestOf */.ol)({ dataset: m.dataset, entries: m.entries });

/** Read and validate a manifest (JSON or YAML), bounded. Entry paths resolve against the manifest's own folder. */
function loadDatasetFile(file) {
  let st;
  try { st = external_node_fs_.statSync(file); } catch { return { ok: false, errors: [`cannot read ${file}`] }; }
  if (!st.isFile() || st.size > MAX_MANIFEST_BYTES) return { ok: false, errors: [`${file} is not a regular file under ${MAX_MANIFEST_BYTES} bytes`] };
  let doc;
  try {
    const text = external_node_fs_.readFileSync(file, 'utf8');
    doc = /\.json$/i.test(file) ? JSON.parse(text) : (0,yaml/* load */.Hh)(text);
  } catch (e) { return { ok: false, errors: [`cannot parse ${external_node_path_.basename(file)}: ${String(e.message).split('\n')[0]}`] }; }
  const v = validateDatasetManifest(doc);
  if (!v.ok) return { ok: false, errors: v.errors };
  return { ok: true, manifest: doc, baseDir: external_node_path_.dirname(external_node_path_.resolve(file)), hash: datasetHash(doc) };
}

/** Resolve a manifest-relative path and confirm it did not escape (symlinks included). Returns null when it did. */
function resolveInside(baseDir, rel) {
  const target = external_node_path_.resolve(baseDir, rel);
  let real;
  try { real = external_node_fs_.realpathSync(target); } catch { return null; }
  const root = external_node_fs_.realpathSync(baseDir);
  return real === root || real.startsWith(root + external_node_path_.sep) ? real : null;
}

// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(48161);
// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(31421);
// EXTERNAL MODULE: external "node:module"
var external_node_module_ = __webpack_require__(98995);
// EXTERNAL MODULE: ./src/sandbox/trust-domains.js
var trust_domains = __webpack_require__(38832);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/posture/assurance/schema-kit.js
var schema_kit = __webpack_require__(53353);
// EXTERNAL MODULE: ./src/posture/assurance/verification-record.js
var verification_record = __webpack_require__(29668);
;// CONCATENATED MODULE: ./src/posture/evaluation/labels.js
// Adjudicated defect labels, reviewed negatives and finding-to-label matching
// (QA-002.AC01, QA-002.AC02).
//
// Advisory records are CANDIDATE ground truth. A label becomes scoreable only
// after adjudication: at least two distinct reviewers other than whoever
// proposed it, with evidence produced by a human or an independent verifier. A
// CWE alone never identifies a defect: a label needs a reviewed location range,
// and a finding matches only by location (plus family or CWE agreement).
//
// This module can validate that a label SAYS it was independently adjudicated.
// It cannot establish that it was. `synthetic: true` labels are accepted for
// tooling tests and are excluded from every real-code population count
// (`populationCounts`, gates.js).
//
// Pure: no fs, no clock, no network.





const DEFECT_LABEL_SCHEMA = 'agentic-security/adjudicated-defect-label';
const NEGATIVE_LABEL_SCHEMA = 'agentic-security/adjudicated-negative';
const ADJUDICATION_STATUSES = Object.freeze(['candidate', 'adjudicated', 'disputed', 'rejected']);
const NEGATIVE_KINDS = Object.freeze(['safe-real', 'patched', 'near-miss']);
const VARIANTS = Object.freeze(['pre', 'post']);
const INDEPENDENT_PRODUCERS = (/* unused pure expression or super */ null && (['human', 'independent-verifier']));

const DEFECT_ID_FIELDS = Object.freeze(['targetId', 'rootCauseId', 'language', 'family', 'location', 'affected']);
const NEGATIVE_ID_FIELDS = Object.freeze(['targetId', 'variant', 'kind', 'language', 'family', 'scope', 'pairedDefectId']);

const defectLabelId = (l) => semanticId('dlab', l, DEFECT_ID_FIELDS);
const negativeLabelId = (l) => semanticId('nlab', l, NEGATIVE_ID_FIELDS);

const DL_ALLOWED = (/* unused pure expression or super */ null && (['schema', 'schemaVersion', 'id', 'targetId', 'rootCauseId', 'affected', 'language', 'family', 'cwe', 'location', 'evidence', 'adjudication', 'proposedBy', 'advisoryRefs', 'synthetic', 'createdAt']));
const DL_REQUIRED = (/* unused pure expression or super */ null && (['schema', 'schemaVersion', 'id', 'targetId', 'rootCauseId', 'affected', 'language', 'family', 'location', 'evidence', 'adjudication', 'proposedBy', 'synthetic']));
const NL_ALLOWED = (/* unused pure expression or super */ null && (['schema', 'schemaVersion', 'id', 'targetId', 'variant', 'kind', 'language', 'family', 'scope', 'pairedDefectId', 'rationale', 'adjudication', 'proposedBy', 'synthetic', 'createdAt']));
const NL_REQUIRED = (/* unused pure expression or super */ null && (['schema', 'schemaVersion', 'id', 'targetId', 'variant', 'kind', 'language', 'family', 'scope', 'rationale', 'adjudication', 'proposedBy', 'synthetic']));

function checkAdjudication(ctx, label) {
  const a = label.adjudication;
  if (!isPlainObject(a)) { ctx.err('BAD_TYPE', 'adjudication', 'must be an object'); return; }
  if (!checkEnum(ctx, 'adjudication.status', a.status, ADJUDICATION_STATUSES)) return;
  if (!Array.isArray(a.reviewers)) { ctx.err('BAD_TYPE', 'adjudication.reviewers', 'must be an array'); return; }
  if (a.status !== 'adjudicated') return;
  const ids = new Set();
  a.reviewers.forEach((r, i) => {
    if (!isPlainObject(r) || !r.reviewerId) { ctx.err('BAD_TYPE', `adjudication.reviewers[${i}]`, 'a reviewer record names reviewerId and verdict'); return; }
    ids.add(r.reviewerId);
    if (r.verdict !== 'confirmed') ctx.err('RULE_VIOLATION', `adjudication.reviewers[${i}].verdict`, 'an adjudicated label needs every reviewer verdict to be confirmed');
    if (isPlainObject(label.proposedBy) && r.reviewerId === label.proposedBy.id) ctx.err('RULE_VIOLATION', `adjudication.reviewers[${i}]`, 'a proposer cannot adjudicate its own label');
  });
  if (ids.size < 2) ctx.err('RULE_VIOLATION', 'adjudication.reviewers', 'an adjudicated label needs at least two distinct reviewers');
  if (a.independent !== true) ctx.err('RULE_VIOLATION', 'adjudication.independent', 'adjudication must be recorded as independent of the label proposer and the detector authors');
}

function checkEvidence(ctx, label) {
  if (!Array.isArray(label.evidence)) { ctx.err('BAD_TYPE', 'evidence', 'must be an array'); return; }
  label.evidence.forEach((e, i) => {
    if (!isPlainObject(e)) { ctx.err('BAD_TYPE', `evidence[${i}]`, 'must be an object'); return; }
    checkString(ctx, `evidence[${i}].ref`, e.ref);
    checkEnum(ctx, `evidence[${i}].producer`, e.producer, EVIDENCE_PRODUCERS);
  });
  if (label.adjudication?.status === 'adjudicated' && !label.evidence.some((e) => INDEPENDENT_PRODUCERS.includes(e?.producer))) {
    ctx.err('RULE_VIOLATION', 'evidence', 'an adjudicated label needs evidence produced by a human or an independent verifier; model output alone is not adjudication');
  }
}

function labels_validateDefectLabel(l) {
  const g = guardObject(l);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, l, DEFECT_LABEL_SCHEMA)) return result(ctx);
  checkFields(ctx, l, DL_ALLOWED, DL_REQUIRED);
  checkString(ctx, 'targetId', l.targetId);
  checkString(ctx, 'rootCauseId', l.rootCauseId);
  checkString(ctx, 'language', l.language);
  checkString(ctx, 'family', l.family);
  if (typeof l.synthetic !== 'boolean') ctx.err('BAD_TYPE', 'synthetic', 'must be a boolean');
  if (!isPlainObject(l.affected)) ctx.err('BAD_TYPE', 'affected', 'must name the affected build/commit');
  else checkCommit(ctx, 'affected.commit', l.affected.commit, { nullable: false });
  // The reviewed vulnerable location is mandatory: a CWE-only label cannot exist.
  const loc = l.location;
  if (!isPlainObject(loc)) ctx.err('MISSING_FIELD', 'location', 'a reviewed vulnerable location range is required; a CWE alone does not identify a defect');
  else {
    checkString(ctx, 'location.file', loc.file);
    if (!Number.isInteger(loc.startLine) || !Number.isInteger(loc.endLine) || loc.startLine < 1 || loc.endLine < loc.startLine) {
      ctx.err('BAD_TYPE', 'location', 'startLine/endLine must be positive integers with endLine >= startLine');
    }
  }
  checkAdjudication(ctx, l);
  checkEvidence(ctx, l);
  if (!isPlainObject(l.proposedBy) || !l.proposedBy.id) ctx.err('MISSING_FIELD', 'proposedBy', 'the proposer must be recorded');
  checkId(ctx, l, defectLabelId(l));
  return result(ctx);
}

function labels_validateNegativeLabel(l) {
  const g = guardObject(l);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, l, NEGATIVE_LABEL_SCHEMA)) return result(ctx);
  checkFields(ctx, l, NL_ALLOWED, NL_REQUIRED);
  checkString(ctx, 'targetId', l.targetId);
  checkString(ctx, 'language', l.language);
  checkString(ctx, 'family', l.family);
  checkString(ctx, 'rationale', l.rationale);
  checkEnum(ctx, 'variant', l.variant, VARIANTS);
  const kindOk = checkEnum(ctx, 'kind', l.kind, NEGATIVE_KINDS);
  if (typeof l.synthetic !== 'boolean') ctx.err('BAD_TYPE', 'synthetic', 'must be a boolean');
  if (!isPlainObject(l.scope) || !Array.isArray(l.scope.files) || l.scope.files.length === 0) ctx.err('MISSING_FIELD', 'scope', 'a negative must name the files it is negative for');
  if (kindOk && l.kind === 'patched') {
    if (l.variant !== 'post') ctx.err('RULE_VIOLATION', 'variant', 'a patched negative is the fixed (post) variant');
    checkString(ctx, 'pairedDefectId', l.pairedDefectId);
  }
  checkAdjudication(ctx, l);
  if (!isPlainObject(l.proposedBy) || !l.proposedBy.id) ctx.err('MISSING_FIELD', 'proposedBy', 'the proposer must be recorded');
  checkId(ctx, l, negativeLabelId(l));
  return result(ctx);
}

function buildDefectLabel(fields) {
  const l = { schema: DEFECT_LABEL_SCHEMA, schemaVersion: SCHEMA_VERSION, synthetic: false, evidence: [], ...fields };
  l.id = defectLabelId(l);
  return l;
}
function buildNegativeLabel(fields) {
  const l = { schema: NEGATIVE_LABEL_SCHEMA, schemaVersion: SCHEMA_VERSION, synthetic: false, ...fields };
  l.id = negativeLabelId(l);
  return l;
}

/** Scoreable = structurally valid AND adjudicated. A candidate (advisory-only) label is never scored. */
function isScoreable(label) {
  return !!label && label.adjudication?.status === 'adjudicated' && validateAny(label).ok;
}

function validateAny(label) {
  return label?.schema === NEGATIVE_LABEL_SCHEMA ? labels_validateNegativeLabel(label) : labels_validateDefectLabel(label);
}

// ---------------------------------------------------------------- matching

const norm = (p) => String(p || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');

/**
 * Does a finding identify the labelled defect? It must (1) sit in the labelled
 * file, (2) carry a line inside the reviewed range widened by `lineWindow`, and
 * (3) agree on family or CWE. CWE agreement alone, a right-file-wrong-line
 * finding and a finding with no line all fail, each with a distinct reason.
 */
function matchFinding(finding, label, policy) {
  const lineWindow = Number.isInteger(policy?.lineWindow) ? policy.lineWindow : 3;
  const sameFile = norm(finding?.file) === norm(label?.location?.file);
  const familyOk = !!finding?.family && finding.family === label?.family;
  const cweOk = !!finding?.cwe && !!label?.cwe && String(finding.cwe).toUpperCase() === String(label.cwe).toUpperCase();
  if (!sameFile) return { matched: false, reason: cweOk ? 'cwe-only' : 'wrong-file' };
  const line = Number(finding.line);
  if (!Number.isFinite(line) || line <= 0) return { matched: false, reason: 'no-line' };
  const { startLine, endLine } = label.location;
  if (line < startLine - lineWindow || line > endLine + lineWindow) return { matched: false, reason: cweOk || familyOk ? 'outside-range' : 'wrong-location' };
  if (!familyOk && !cweOk) return { matched: false, reason: 'family-mismatch' };
  return { matched: true, reason: 'location-and-family' };
}

/** Does a finding fall in a negative's scope for the family it is negative for? */
function matchNegative(finding, negative) {
  const inScope = (negative?.scope?.files || []).map(norm).includes(norm(finding?.file));
  if (!inScope) return { matched: false, reason: 'out-of-scope' };
  if (!finding?.family || finding.family !== negative.family) return { matched: false, reason: 'other-family' };
  return { matched: true, reason: 'family-in-negative-scope' };
}

/**
 * Findings on a target that no adjudicated label accounts for. These are NOT
 * false positives: a genuine, previously unlabelled defect would be hiding
 * among them. They go to a review queue and stay out of precision.
 */
function reviewQueue(entries) {
  return entries.map((e) => ({ targetId: e.targetId, variant: e.variant, findingId: e.finding?.id || null, file: e.finding?.file || null, line: e.finding?.line ?? null, family: e.finding?.family || null, status: 'needs-adjudication', reason: e.reason }));
}

/** Counts of scoreable, real (non-synthetic) labels by language and family, for population gates. */
function populationCounts(defects, negatives) {
  const out = { positivesByLanguage: {}, negativesByLanguage: {}, positivesByFamily: {}, syntheticPositives: 0, syntheticNegatives: 0, unadjudicated: 0 };
  for (const l of defects || []) {
    if (!isScoreable(l)) { out.unadjudicated++; continue; }
    if (l.synthetic) { out.syntheticPositives++; continue; }
    out.positivesByLanguage[l.language] = (out.positivesByLanguage[l.language] || 0) + 1;
    out.positivesByFamily[l.family] = (out.positivesByFamily[l.family] || 0) + 1;
  }
  for (const n of negatives || []) {
    if (!isScoreable(n)) { out.unadjudicated++; continue; }
    if (n.synthetic) { out.syntheticNegatives++; continue; }
    out.negativesByLanguage[n.language] = (out.negativesByLanguage[n.language] || 0) + 1;
  }
  return out;
}

;// CONCATENATED MODULE: ./src/posture/evaluation/custody.js
// Label custody and leakage controls (QA-002.AC03).
//
// Two trust domains meet here. The CUSTODIAN (verifier domain) holds adjudicated
// labels. The engine under test, and any worker or model prompt, is on the other
// side and must never see an answer key. This module provides the custodian's
// store, the workspace staging that builds what the engine is allowed to read,
// and the audits that fail a run when anything label-shaped crosses over.
//
// Enforcement, honestly stated:
//   - role checks use the existing trust-domain policy (`mayDo`): workers and
//     targets are denied sealed-label read AND write;
//   - staging and prompt audits are PATTERN checks over known protected terms and
//     file names. They catch planted and accidental leaks of the kinds listed in
//     `leakFixtures`; they are not a proof that no paraphrase gets through;
//   - process-level read denial of the label directory is the sandbox trust
//     boundary's job (`runInBoundary({ labelDirs })`), which this module only
//     feeds. Where no backend proves that control the boundary reports `blocked`.








const LABEL_FILE = 'adjudicated-labels.json';

// File names that look like an answer key. Regexes, not literals, so this file
// is not itself a reference to any particular key file.
const LEAK_FILENAME_PATTERNS = Object.freeze([
  /(^|\/)(labels?|answers?|expected|ground[-_]?truth|answer[-_]?key|adjudicat\w*|oracle)[^/]*\.(json|jsonl|ya?ml|csv|txt)$/i,
  /(^|\/)result\.json$/i,
  /(^|\/)corpus-baseline[^/]*$/i,
  /(^|\/)(advisory|advisories|ghsa|osv)[^/]*\.(json|md|txt|ya?ml)$/i,
]);

const BENCHMARK_NAMES = Object.freeze(['owasp benchmark', 'juliet', 'sard test', 'cve-replay', 'corpus-baseline', 'answer key', 'ground truth']);
const ADVISORY_ID = /\b(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b/i;
const MIN_TERM = 8;

/**
 * Terms that must never reach the engine or a prompt: reviewer evidence refs and
 * rationale, advisory ids and prose, root-cause ids, and fixed-source hints.
 */
function protectedTermsFrom({ defects = [], negatives = [], advisoryText = [], fixedSourceHints = [], benchmarkNames = BENCHMARK_NAMES } = {}) {
  const terms = new Set();
  const add = (s) => { if (typeof s === 'string' && s.trim().length >= MIN_TERM) terms.add(s.trim().toLowerCase()); };
  for (const d of defects) {
    add(d.rootCauseId);
    for (const e of d.evidence || []) add(e.ref);
    for (const a of d.advisoryRefs || []) add(a);
  }
  for (const n of negatives) add(n.rationale);
  for (const s of [...advisoryText, ...fixedSourceHints, ...benchmarkNames]) add(s);
  return [...terms].sort();
}

/** Leaks in a piece of text (a prompt, a file body). */
function auditText(text, terms, { strictAdvisoryIds = true } = {}) {
  const hay = String(text ?? '');
  const lower = hay.toLowerCase();
  const leaks = [];
  for (const t of terms || []) if (lower.includes(t)) leaks.push({ kind: 'protected-term', detail: t.length > 60 ? `${t.slice(0, 57)}...` : t });
  if (strictAdvisoryIds) {
    const m = ADVISORY_ID.exec(hay);
    if (m) leaks.push({ kind: 'advisory-id', detail: m[1] });
  }
  return leaks;
}

/** Gate a model/scanner prompt. `ok:false` means the call must not be made. */
function guardPrompt(prompt, terms, opts) {
  const leaks = auditText(prompt, terms, opts);
  return { ok: leaks.length === 0, leaks };
}

const SKIP_DIRS = new Set(['.git', state_dir/* STATE_DIR_NAME */.Ky, 'node_modules']);

/**
 * Audit a directory the engine may read: no answer-key file names, no symlinks
 * (which could point outside it), no protected term or advisory id in content.
 * Bounded so a hostile tree cannot make the audit itself the problem.
 */
function auditWorkspace(dir, terms, { strictAdvisoryIds = true, maxFiles = 20000, maxFileBytes = 2 * 1024 * 1024 } = {}) {
  const leaks = [];
  let scanned = 0; let skippedLarge = 0; let truncated = false;
  const walk = (d, rel) => {
    let entries = [];
    try { entries = external_node_fs_.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (truncated) return;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { leaks.push({ kind: 'symlink', file: r, detail: 'symlinks are refused in an engine workspace' }); continue; }
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(external_node_path_.join(d, e.name), r); continue; }
      if (!e.isFile()) continue;
      if (++scanned > maxFiles) { truncated = true; leaks.push({ kind: 'audit-truncated', file: r, detail: `more than ${maxFiles} files; the audit cannot vouch for the rest` }); return; }
      if (LEAK_FILENAME_PATTERNS.some((re) => re.test(r))) { leaks.push({ kind: 'answer-key-file', file: r, detail: 'file name looks like a label, answer key or advisory record' }); continue; }
      let st; try { st = external_node_fs_.statSync(external_node_path_.join(d, e.name)); } catch { continue; }
      if (st.size > maxFileBytes) { skippedLarge++; continue; }
      let body; try { body = external_node_fs_.readFileSync(external_node_path_.join(d, e.name), 'utf8'); } catch { continue; }
      for (const l of auditText(body, terms, { strictAdvisoryIds })) leaks.push({ ...l, file: r });
    }
  };
  walk(dir, '');
  return { ok: leaks.length === 0, leaks, scannedFiles: scanned, skippedLargeFiles: skippedLarge };
}

/**
 * Copy a target tree into a fresh workspace for the engine, then audit it. On any
 * leak the workspace is removed and the target is reported quarantined; the run
 * must record that as a failure, never silently scan the tree anyway.
 */
function custody_stageWorkspace({ srcDir, destDir, terms, strictAdvisoryIds = true }) {
  fs.rmSync(destDir, { recursive: true, force: true });
  fs.cpSync(srcDir, destDir, {
    recursive: true, dereference: false,
    filter: (s) => !SKIP_DIRS.has(path.basename(s)) || s === srcDir,
  });
  const audit = auditWorkspace(destDir, terms, { strictAdvisoryIds });
  if (!audit.ok) {
    fs.rmSync(destDir, { recursive: true, force: true });
    return { ok: false, quarantined: true, leaks: audit.leaks, destDir: null };
  }
  return { ok: true, quarantined: false, leaks: [], destDir };
}

// ---------------------------------------------------------------- the custodian's store

/** Content hash binding a label set: key-order independent, order independent. */
function sealLabels(defects, negatives) {
  const sortById = (xs) => [...xs].sort((a, b) => String(a.id).localeCompare(String(b.id)));
  return digestOf({ kind: 'evaluation-labels', defects: sortById(defects || []), negatives: sortById(negatives || []) });
}

const isCustodian = (actor) => actor?.domain === DOMAINS.VERIFIER && actor?.role === 'custodian' && !isUntrusted(actor.domain);

function denied(code, message) { return { ok: false, errors: [{ code, path: '', message }] }; }

/**
 * Write the label set. Only the custodian may; a worker or the target is denied
 * by the trust-domain policy. Every label is validated first: one invalid label
 * rejects the whole write.
 */
function custodianWriteLabels(labelDir, actor, { defects = [], negatives = [] } = {}) {
  if (!isCustodian(actor)) return denied('CUSTODY_DENIED', `domain '${actor?.domain}' role '${actor?.role}' may not write sealed labels`);
  const errors = [];
  for (const d of defects) { const v = validateDefectLabel(d); if (!v.ok) errors.push(...v.errors.map((e) => ({ ...e, path: `${d?.id}.${e.path}` }))); }
  for (const n of negatives) { const v = validateNegativeLabel(n); if (!v.ok) errors.push(...v.errors.map((e) => ({ ...e, path: `${n?.id}.${e.path}` }))); }
  if (errors.length) return { ok: false, errors };
  fs.mkdirSync(labelDir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(labelDir, 0o700); } catch { /* best effort */ }
  const file = path.join(labelDir, LABEL_FILE);
  fs.writeFileSync(file, JSON.stringify({ defects, negatives }), { mode: 0o600 });
  return { ok: true, errors: [], labelsHash: sealLabels(defects, negatives), count: { defects: defects.length, negatives: negatives.length } };
}

/** Read the label set. Allowed only where the policy grants sealed-label read, and only if it still matches the sealed hash. */
function custodianReadLabels(labelDir, actor, { expectedHash } = {}) {
  if (!mayDo(actor?.domain, RESOURCES.SEALED_LABELS, 'read')) return denied('CUSTODY_DENIED', `domain '${actor?.domain}' may not read sealed labels`);
  let data;
  try { data = JSON.parse(fs.readFileSync(path.join(labelDir, LABEL_FILE), 'utf8')); } catch (e) { return denied('LABELS_UNREADABLE', `cannot read labels: ${e.code || e.message}`); }
  const defects = Array.isArray(data?.defects) ? data.defects : []; const negatives = Array.isArray(data?.negatives) ? data.negatives : [];
  const labelsHash = sealLabels(defects, negatives);
  if (expectedHash && labelsHash !== expectedHash) return denied('LABELS_HASH_MISMATCH', 'labels changed after they were sealed');
  return { ok: true, errors: [], defects, negatives, labelsHash };
}

// realpath of the nearest existing ancestor plus the not-yet-existing remainder, so a path that does not exist
// yet still compares correctly against one reached through a symlinked parent (macOS /var -> /private/var).
function real(p) {
  let cur = path.resolve(p); const rest = [];
  for (;;) {
    try { return path.join(fs.realpathSync(cur), ...rest.reverse()); } catch { /* climb */ }
    const parent = path.dirname(cur);
    if (parent === cur) return path.resolve(p);
    rest.push(path.basename(cur)); cur = parent;
  }
}

/** A workspace that contains, or sits inside, the label directory would hand the engine the answer key by construction. */
function assertCustodyIsolation(labelDir, workspaceDir) {
  const a = real(labelDir); const b = real(workspaceDir);
  if (a === b || a.startsWith(b + path.sep) || b.startsWith(a + path.sep)) {
    return denied('CUSTODY_OVERLAP', `workspace ${workspaceDir} overlaps the label directory ${labelDir}`);
  }
  return { ok: true, errors: [] };
}

/** Environment for the engine under test: secret-looking variables, evaluation variables and anything naming the label directory are removed. */
function custody_engineEnvironment(base, { labelDir } = {}) {
  const scrubbed = scrubEnv(base || {});
  const out = {};
  const labelReal = labelDir ? real(labelDir) : null;
  for (const [k, v] of Object.entries(scrubbed)) {
    if (/^AGENTIC_(SECURITY_)?EVAL/i.test(k)) continue;
    if (labelDir && typeof v === 'string' && (v.includes(labelDir) || v.includes(labelReal))) continue;
    out[k] = v;
  }
  return out;
}

// EXTERNAL MODULE: ./src/sandbox/supervise.js
var supervise = __webpack_require__(74676);
// EXTERNAL MODULE: ./src/posture/proof-fabric/orchestrator.js
var orchestrator = __webpack_require__(3740);
// EXTERNAL MODULE: ./src/posture/proof-fabric/fix-proof.js
var fix_proof = __webpack_require__(818);
// EXTERNAL MODULE: ./src/posture/proof-fabric/reproducer.js
var reproducer = __webpack_require__(37055);
// EXTERNAL MODULE: ./src/artifact/safe-tar.js
var safe_tar = __webpack_require__(90642);
;// CONCATENATED MODULE: ./src/posture/evaluation/lab/materialize.js
// Turn a dataset entry's workspace reference into a directory of files (PRD 6, requirement 3: vulnerable commit -> fixing commit).
// Two sources: a folder inside the manifest's own directory, or a revision of a LOCAL git repository read with `git archive`
// (so no checkout, no hooks and no working tree are involved) and unpacked through the hardened tar reader. Nothing is fetched
// from the network, a moving ref is refused at validation time, and every limit is a typed failure rather than a truncation.






const MATERIALIZE_LIMITS = Object.freeze({ gitTimeoutMs: 120_000, maxArchiveBytes: 512 * 1024 * 1024, maxFiles: 50_000, maxFileBytes: 16 * 1024 * 1024 });

function materializeEntry(entry, { baseDir, destDir, limits = MATERIALIZE_LIMITS } = {}) {
  external_node_fs_.rmSync(destDir, { recursive: true, force: true });
  external_node_fs_.mkdirSync(destDir, { recursive: true });
  const ws = entry.workspace;
  if (ws.dir !== undefined) {
    const src = resolveInside(baseDir, ws.dir);
    if (!src || !external_node_fs_.statSync(src).isDirectory()) return { ok: false, reason: 'workspace directory is missing or outside the manifest folder' };
    external_node_fs_.cpSync(src, destDir, { recursive: true, dereference: false, filter: (s) => !['.git', 'node_modules'].includes(external_node_path_.basename(s)) });
    return { ok: true, source: 'directory' };
  }
  const repo = resolveInside(baseDir, ws.git.repo) ?? (external_node_path_.isAbsolute(ws.git.repo) && external_node_fs_.existsSync(ws.git.repo) ? external_node_fs_.realpathSync(ws.git.repo) : null);
  if (!repo) return { ok: false, reason: 'git repository not found' };
  const r = (0,external_node_child_process_.spawnSync)('git', ['-C', repo, 'archive', '--format=tar', ws.git.rev], { timeout: limits.gitTimeoutMs, killSignal: 'SIGKILL', maxBuffer: limits.maxArchiveBytes, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' } });
  if (r.error) return { ok: false, reason: r.error.code === 'ETIMEDOUT' ? 'git archive timed out' : r.error.code === 'ENOBUFS' ? 'archive exceeds the size limit' : `git archive failed: ${r.error.code || r.error.message}` };
  if (r.status !== 0) return { ok: false, reason: `git archive failed: ${String(r.stderr).split('\n')[0].slice(0, 160)}` };
  let files = 0;
  try {
    for (const e of (0,safe_tar/* readTarEntries */.ET)(r.stdout)) {
      if (e.unsafe) return { ok: false, reason: `unsafe path in the archive: ${String(e.name).slice(0, 80)}` };
      if (e.typeflag !== '0' && e.typeflag !== '\0') continue; // directories are implied; links and devices are never created
      if (++files > limits.maxFiles) return { ok: false, reason: `more than ${limits.maxFiles} files` };
      if (e.size > limits.maxFileBytes) return { ok: false, reason: `a file exceeds ${limits.maxFileBytes} bytes` };
      const target = external_node_path_.resolve(destDir, e.name);
      if (target !== destDir && !target.startsWith(destDir + external_node_path_.sep)) return { ok: false, reason: 'archive path escapes the workspace' };
      external_node_fs_.mkdirSync(external_node_path_.dirname(target), { recursive: true });
      external_node_fs_.writeFileSync(target, e.data);
    }
  } catch (err) {
    return { ok: false, reason: err instanceof safe_tar.TarSafetyError ? `archive refused: ${err.message}` : `archive unreadable: ${err.message}` };
  }
  return { ok: true, source: 'git', files };
}

;// CONCATENATED MODULE: ./src/posture/evaluation/lab/neutralize.js
// Workspace neutralization and the leakage gate (PRD 6, benchmark integrity).
//
// A model must be scored on whether it can find the defect, not on whether it can read the answer. Before any arm sees a
// workspace this module (1) copies it, (2) strips comments while keeping every line number (so a span still points at the same
// code), (3) renames files whose NAME carries the weakness class, and (4) runs the existing custody audit
// (`custody.auditWorkspace`: answer-key file names, symlinks, protected terms, advisory ids) plus three checks of its own:
// a weakness id anywhere in the content, a vulnerability-describing comment that was left in, and a weakness-bearing file name
// that the policy did not rename. Any hit quarantines the workspace: the entry is recorded as quarantined and is NOT scanned.
//
// What this is not: a proof that no paraphrase gets through. Comment stripping is best effort (a regular expression literal
// containing `//` can be mis-read), and an identifier that happens to describe the bug stays. The audit result is recorded on
// every run so a reader can see exactly what was checked.





const C_LIKE = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.java', '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.go', '.rs', '.kt', '.kts', '.swift', '.scala', '.php']);
const HASH_LIKE = new Set(['.py', '.rb', '.sh', '.bash', '.pl', '.yaml', '.yml', '.tf', '.toml']);
const HASH_AND_C = new Set(['.php']);
// languages where a single quote opens a string of any length; elsewhere it is a short character literal (or a Rust lifetime)
const SQ_STRING = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.php']);
const SKIP = new Set(['.git', 'node_modules', state_dir/* STATE_DIR_NAME */.Ky]);
const CWE_NAME = /cwe[-_]?\d{1,5}/i;
const CWE_CONTENT = /\bcwe[-_ ]?\d{2,5}\b/i;
const DESCRIPTIVE_COMMENT = /\b(vulnerab\w*|insecure|exploit\w*|potential flaw|flaw:|fixed by|should be (?:sanitized|escaped|validated)|\bBAD\b|\bGOOD\b|sink|taint\w*)\b/i;

/** Remove comments, keeping newlines. String-aware for ' " and ` quotes; best effort, see the file header. */
function stripComments(text, ext) {
  const cLike = C_LIKE.has(ext);
  const hash = HASH_LIKE.has(ext) || HASH_AND_C.has(ext);
  if (!cLike && !hash) return text;
  const s = String(text);
  let out = '';
  let i = 0;
  const n = s.length;
  while (i < n) {
    const c = s[i];
    const two = s.substr(i, 2);
    if (cLike && two === '//') { while (i < n && s[i] !== '\n') i++; continue; }
    if (cLike && two === '/*') { i += 2; while (i < n && s.substr(i, 2) !== '*/') { if (s[i] === '\n') out += '\n'; i++; } i += 2; continue; }
    if (hash && c === '#' && !(ext === '.php' && s[i + 1] === '[')) { while (i < n && s[i] !== '\n') i++; continue; }
    if (c === '"' || c === '`' || (c === "'" && (hash || SQ_STRING.has(ext) || /^'(?:\\.|[^'\\\n]){1,12}'/.test(s.slice(i, i + 16))))) {
      const triple = (hash && ext === '.py' && s.substr(i, 3) === c.repeat(3)) ? c.repeat(3) : null;
      const q = triple || c;
      out += q; i += q.length;
      while (i < n) {
        if (s[i] === '\\') { out += s.substr(i, 2); i += 2; continue; }
        if (s.substr(i, q.length) === q) { out += q; i += q.length; break; }
        if (!triple && q !== '`' && s[i] === '\n') break; // an unterminated string ends at the line
        out += s[i]; i++;
      }
      continue;
    }
    out += c; i++;
  }
  return out;
}

/** `*` matches within a path segment, `**` across segments; everything else is literal. */
function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') { re += '.*'; i++; if (glob[i + 1] === '/') i++; } else if (c === '*') re += '[^/]*'; else re += c.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`, 'i');
}

const isText = (buf) => !buf.subarray(0, 4096).includes(0);

function copyTree(src, dest, files = []) {
  external_node_fs_.mkdirSync(dest, { recursive: true });
  for (const e of external_node_fs_.readdirSync(src, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (SKIP.has(e.name)) continue;
    const s = external_node_path_.join(src, e.name); const d = external_node_path_.join(dest, e.name);
    if (e.isSymbolicLink()) { files.push({ rel: external_node_path_.relative(dest, d), symlink: true }); external_node_fs_.symlinkSync(external_node_fs_.readlinkSync(s), d); continue; }
    if (e.isDirectory()) { copyTree(s, d, files); continue; }
    if (e.isFile()) external_node_fs_.copyFileSync(s, d);
  }
  return files;
}

function listFiles(root, rel = '', out = []) {
  for (const e of external_node_fs_.readdirSync(external_node_path_.join(root, rel), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) listFiles(root, r, out); else if (e.isFile()) out.push(r);
  }
  return out;
}

/**
 * @returns {{ok: boolean, quarantined: boolean, destDir: string|null, fileMap: Record<string,string>, leaks: object[], audit: object}}
 * `fileMap` maps original relative paths to staged ones, so a label's span can be located without telling the arm.
 */
function stageNeutralized({ srcDir, destDir, policy = {}, terms = [] }) {
  external_node_fs_.rmSync(destDir, { recursive: true, force: true });
  copyTree(srcDir, destDir);
  const leaks = [];
  const fileMap = {};
  const renamedStems = [];
  let n = 0;
  // 0. remove files the policy names (change logs, advisories and the like) before anything is judged
  if (Array.isArray(policy.removePaths) && policy.removePaths.length) {
    const res = policy.removePaths.map(globToRegExp);
    for (const rel of listFiles(destDir)) if (res.some((re) => re.test(rel))) external_node_fs_.rmSync(external_node_path_.join(destDir, rel), { force: true });
  }
  // 1. rename weakness-bearing file names (and note the stem so class/module references can follow)
  for (const rel of listFiles(destDir)) {
    const base = external_node_path_.basename(rel);
    if (!CWE_NAME.test(rel)) { fileMap[rel] = rel; continue; }
    if (!policy.renameFiles) { fileMap[rel] = rel; leaks.push({ kind: 'weakness-in-file-name', file: rel, detail: 'the file name states the weakness class and the policy does not rename files' }); continue; }
    const ext = external_node_path_.extname(base);
    const stem = base.slice(0, base.length - ext.length);
    const next = `case${String(++n).padStart(4, '0')}${ext}`;
    const relNext = external_node_path_.posix.join(external_node_path_.posix.dirname(rel) === '.' ? '' : external_node_path_.posix.dirname(rel).replace(CWE_NAME, 'dir'), next);
    external_node_fs_.mkdirSync(external_node_path_.dirname(external_node_path_.join(destDir, relNext)), { recursive: true });
    external_node_fs_.renameSync(external_node_path_.join(destDir, rel), external_node_path_.join(destDir, relNext));
    fileMap[rel] = relNext;
    renamedStems.push([stem, next.slice(0, next.length - ext.length)]);
  }
  for (const d of external_node_fs_.readdirSync(destDir, { withFileTypes: true })) if (d.isDirectory()) { try { external_node_fs_.rmdirSync(external_node_path_.join(destDir, d.name)); } catch { /* not empty */ } }
  // 2. strip comments, follow renamed stems in text
  for (const rel of listFiles(destDir)) {
    const p = external_node_path_.join(destDir, rel);
    let buf; try { buf = external_node_fs_.readFileSync(p); } catch { continue; }
    if (!isText(buf)) continue;
    let text = buf.toString('utf8');
    const original = text;
    if (policy.stripComments) text = stripComments(text, external_node_path_.extname(rel).toLowerCase());
    else {
      const cm = text.split('\n').findIndex((l) => /(?:\/\/|\/\*|\*|#)/.test(l) && DESCRIPTIVE_COMMENT.test(l));
      if (cm !== -1) leaks.push({ kind: 'descriptive-comment', file: rel, line: cm + 1, detail: 'a comment describes the weakness; set leakagePolicy.stripComments' });
    }
    for (const [from, to] of renamedStems) text = text.split(from).join(to);
    if (CWE_CONTENT.test(text)) leaks.push({ kind: 'weakness-id-in-content', file: rel, detail: 'the content names a CWE id' });
    if (text !== original) external_node_fs_.writeFileSync(p, text);
  }
  // 3. the existing custody audit (answer-key names, symlinks, protected terms, advisory ids)
  const audit = auditWorkspace(destDir, terms);
  for (const l of audit.leaks) leaks.push(l);
  if (leaks.length) { external_node_fs_.rmSync(destDir, { recursive: true, force: true }); return { ok: false, quarantined: true, destDir: null, fileMap, leaks, audit: { scannedFiles: audit.scannedFiles, leaks: leaks.length } }; }
  return { ok: true, quarantined: false, destDir, fileMap, leaks: [], audit: { scannedFiles: audit.scannedFiles, leaks: 0 } };
}

// EXTERNAL MODULE: ./src/egress/policy.js
var egress_policy = __webpack_require__(45712);
// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
// EXTERNAL MODULE: external "node:url"
var external_node_url_ = __webpack_require__(73136);
;// CONCATENATED MODULE: ./src/posture/evaluation/grouping.js
// Leakage-safe grouping and splitting (QA-001.AC02).
//
// Related samples must land on the same side of the development/sealed line, or
// the sealed set is not independent of what detector work already saw. Two
// samples are related when they share any of: a vulnerable/fixed pair, an
// upstream project (a fork resolves to its parent), an advisory id (duplicate
// advisories), a commit, or a near-identical template fingerprint. Relations are
// transitive (union-find), so a chain A~B~C is one group.
//
// Pure and deterministic: group ids and split assignment depend only on the
// targets and an explicit salt, never on iteration order or a clock.



/** `https://GitHub.com/Org/Repo.git/` and `git@github.com:org/repo` normalise to `github.com/org/repo`. */
function normalizeUpstream(url) {
  if (typeof url !== 'string' || !url.trim()) return null;
  let u = url.trim().toLowerCase();
  u = u.replace(/^[a-z+]+:\/\//, '').replace(/^git@/, '').replace(/^[^@/]+@/, '');
  u = u.replace(':', '/').replace(/\/+$/, '').replace(/\.git$/, '');
  return u || null;
}

class UnionFind {
  constructor(ids) { this.parent = new Map(ids.map((i) => [i, i])); }
  find(x) { let r = x; while (this.parent.get(r) !== r) r = this.parent.get(r); this.parent.set(x, r); return r; }
  union(a, b) { const ra = this.find(a); const rb = this.find(b); if (ra !== rb) this.parent.set(ra < rb ? rb : ra, ra < rb ? ra : rb); }
}

const KEYS = (t) => {
  const k = [];
  if (t.pairId) k.push(['pair', t.pairId]);
  const up = normalizeUpstream(t.upstream);
  if (up) k.push(['upstream', up]);
  const fork = normalizeUpstream(t.forkOf);
  if (fork) k.push(['upstream', fork]);
  for (const a of t.advisoryIds || []) k.push(['advisory', String(a).toUpperCase()]);
  for (const c of [t.preCommit, t.postCommit]) if (c) k.push(['commit', c]);
  if (t.templateFingerprint) k.push(['template', t.templateFingerprint]);
  return k;
};

/**
 * Group targets by every relation above. Returns `{ groups, groupOf }` where each
 * group is `{ groupId, members[], reasons[] }`, members sorted, groups sorted.
 */
function grouping_groupTargets(targets) {
  const list = (targets || []).filter((t) => t && t.id);
  const uf = new UnionFind(list.map((t) => t.id));
  const byKey = new Map();
  for (const t of list) {
    for (const [kind, val] of KEYS(t)) {
      const key = `${kind}:${val}`;
      if (byKey.has(key)) uf.union(byKey.get(key).id, t.id);
      else byKey.set(key, t);
    }
  }
  const members = new Map();
  for (const t of list) { const r = uf.find(t.id); if (!members.has(r)) members.set(r, []); members.get(r).push(t.id); }
  // Which relation kinds actually linked two or more members of each group.
  const kindCount = new Map();
  for (const t of list) {
    for (const [kind, val] of KEYS(t)) {
      const gk = `${uf.find(t.id)}|${kind}:${val}`;
      kindCount.set(gk, (kindCount.get(gk) || 0) + 1);
    }
  }
  const groups = [];
  const groupOf = {};
  for (const [root, ids] of members) {
    ids.sort();
    const reasons = new Set();
    for (const [gk, n] of kindCount) if (n > 1 && gk.startsWith(`${root}|`)) reasons.add(gk.slice(root.length + 1).split(':')[0]);
    const groupId = `grp:${crypto.createHash('sha256').update(ids.join('\n')).digest('hex').slice(0, 16)}`;
    groups.push({ groupId, members: ids, reasons: [...reasons].sort() });
    for (const id of ids) groupOf[id] = groupId;
  }
  groups.sort((a, b) => a.groupId.localeCompare(b.groupId));
  return { groups, groupOf };
}

/**
 * Deterministically assign whole groups to development or sealed. A group's side
 * is a function of its id and the salt only, so adding an unrelated target never
 * moves an existing group, and no group can straddle the line.
 */
function assignSplits(groups, { sealedFraction = 0.3, salt = '' } = {}) {
  const dev = []; const sealed = [];
  for (const g of groups) {
    const h = crypto.createHash('sha256').update(`${salt}|${g.groupId}`).digest();
    const u = h.readUInt32BE(0) / 0x100000000;
    (u < sealedFraction ? sealed : dev).push(...g.members);
  }
  return { dev: dev.sort(), sealed: sealed.sort() };
}

/** Groups whose members are spread over both sides. Empty means the split is leakage-safe. */
function grouping_splitStraddles(groups, splits) {
  const dev = new Set(splits?.dev || []); const sealed = new Set(splits?.sealed || []);
  return (groups || []).filter((g) => g.members.some((m) => dev.has(m)) && g.members.some((m) => sealed.has(m)));
}

;// CONCATENATED MODULE: ./src/posture/evaluation/protocol.js
// Frozen current-engine evaluation protocol (QA-001).
//
// A protocol is the thing registered BEFORE any result is looked at: dataset
// scope, thresholds, matching rules, budgets and split membership. Its hash is
// computed over every semantic field, so a changed threshold or a moved target
// is a different protocol, never an edit of the old one.
//
// What this module does NOT do: it creates no population, no labels and no
// results. A protocol marked `synthetic` can exercise the machinery and can
// never satisfy a real-code gate (gates.js enforces that).
//
// Pure: no fs, no clock, no network. Validators return `{ ok, errors }` with the
// same error shape the assurance schema kit uses.





const PROTOCOL_SCHEMA = 'agentic-security/evaluation-protocol';

// The nine advertised core languages (docs/POSITIONING.md, PRD section 3).
const CORE_LANGUAGES = Object.freeze([
  'javascript', 'python', 'java', 'kotlin', 'go', 'ruby', 'php', 'csharp', 'rust',
]);

// PRD section 5. These are release TARGETS registered in advance, not claims
// about current performance. They live in code so a protocol that omits or
// loosens one is detectable (`validateProtocol` compares against this floor).
const PREREGISTERED_THRESHOLDS = Object.freeze({
  perLanguageF1: 0.80,
  overallMicroF1: 0.80,
  overallMacroF1: 0.80,
  pooledPrecision: 0.90,
  pooledRecall: 0.75,
  perLanguageF1LowerBound: 0.70,
  completion: 0.95,
  minPositivesPerCoreLanguage: 100,
  minNegativesPerCoreLanguage: 100,
  minPositivesPerFamily: 30,
  intervalMethod: 'grouped-bootstrap-95',
});

const DEFAULT_MATCHING = Object.freeze({
  policy: 'root-cause-location',
  lineWindow: 3,
  requireFamilyOrCwe: true,
  cweAloneSufficient: false,
  lineLessFindingsMatch: false,
});

const FIELDS = [
  'schema', 'schemaVersion', 'protocolVersion', 'supersedes', 'synthetic', 'engine', 'measurement', 'tools', 'models',
  'datasetLicenses', 'scope', 'matching', 'limits', 'thresholds', 'targets', 'originalTargetIds', 'retired', 'splits',
  'grouping', 'comparability', 'protocolHash', 'createdAt',
];
const REQUIRED = (/* unused pure expression or super */ null && ([
  'schema', 'schemaVersion', 'protocolVersion', 'synthetic', 'engine', 'measurement', 'tools', 'models', 'datasetLicenses',
  'scope', 'matching', 'limits', 'thresholds', 'targets', 'originalTargetIds', 'splits', 'protocolHash',
]));
// Everything except the hash itself and the informational clock.
const HASHED = FIELDS.filter((f) => f !== 'protocolHash' && f !== 'createdAt');

function protocolHashOf(p) {
  const material = {};
  for (const f of HASHED) material[f] = p?.[f] === undefined ? null : p[f];
  return digestOf({ kind: 'evaluation-protocol', material });
}

function deepFreeze(v) {
  if (v && typeof v === 'object' && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const k of Object.keys(v)) deepFreeze(v[k]);
  }
  return v;
}

const clone = (v) => JSON.parse(JSON.stringify(v));

/**
 * Validate a protocol, frozen or not. A protocol whose hash does not match its
 * content fails with HASH_MISMATCH: that is what "immutable" means here.
 */
function protocol_validateProtocol(p) {
  const g = guardObject(p);
  const ctx = g.ctx;
  if (!g.ok) return result(ctx);
  if (!checkHeader(ctx, p, PROTOCOL_SCHEMA)) return result(ctx);
  checkFields(ctx, p, FIELDS, REQUIRED);

  if (!Number.isInteger(p.protocolVersion) || p.protocolVersion < 1) ctx.err('BAD_TYPE', 'protocolVersion', 'must be a positive integer');
  if (typeof p.synthetic !== 'boolean') ctx.err('BAD_TYPE', 'synthetic', 'must be a boolean');

  // AC01: pinned versions, digests and a clean measurement tree.
  if (!isPlainObject(p.engine)) ctx.err('BAD_TYPE', 'engine', 'must be an object');
  else { checkString(ctx, 'engine.version', p.engine.version); checkDigest(ctx, 'engine.bundleDigest', p.engine.bundleDigest); }
  if (!isPlainObject(p.measurement)) ctx.err('BAD_TYPE', 'measurement', 'must be an object');
  else {
    checkCommit(ctx, 'measurement.commit', p.measurement.commit, { nullable: false });
    if (p.measurement.cleanTree !== true) ctx.err('RULE_VIOLATION', 'measurement.cleanTree', 'the measurement tree must be clean; a dirty tree cannot be pinned');
  }
  if (!isPlainObject(p.tools) || Object.keys(p.tools).length === 0) ctx.err('MISSING_FIELD', 'tools', 'tool versions must be pinned');
  if (!Array.isArray(p.models)) ctx.err('BAD_TYPE', 'models', 'must be an array (empty when no model is used)');
  else p.models.forEach((m, i) => { if (!isPlainObject(m) || !m.provider || !m.model || !m.version) ctx.err('BAD_TYPE', `models[${i}]`, 'must name provider, model and version'); });
  if (!isPlainObject(p.datasetLicenses) || Object.keys(p.datasetLicenses).length === 0) ctx.err('MISSING_FIELD', 'datasetLicenses', 'dataset licenses must be declared');

  if (!isPlainObject(p.scope) || !Array.isArray(p.scope.languages) || !p.scope.languages.length || !Array.isArray(p.scope.families) || !p.scope.families.length) {
    ctx.err('MISSING_FIELD', 'scope', 'scope must declare languages[] and families[]');
  }
  if (!isPlainObject(p.matching)) ctx.err('BAD_TYPE', 'matching', 'must be an object');
  else if (p.matching.cweAloneSufficient !== false) ctx.err('RULE_VIOLATION', 'matching.cweAloneSufficient', 'CWE agreement alone can never make a true positive');
  if (!isPlainObject(p.limits)) ctx.err('BAD_TYPE', 'limits', 'must be an object');
  else {
    for (const k of ['perTargetTimeoutMs', 'spendCeilingUsd', 'replicates']) {
      if (typeof p.limits[k] !== 'number' || !(p.limits[k] >= 0)) ctx.err('BAD_TYPE', `limits.${k}`, 'must be a non-negative number');
    }
  }

  // Thresholds may be stricter than the floor, never looser or missing.
  if (!isPlainObject(p.thresholds)) ctx.err('BAD_TYPE', 'thresholds', 'must be an object');
  else {
    for (const [k, floor] of Object.entries(PREREGISTERED_THRESHOLDS)) {
      const v = p.thresholds[k];
      if (typeof floor === 'string') { if (v !== floor) ctx.err('RULE_VIOLATION', `thresholds.${k}`, `must be '${floor}'`); continue; }
      if (typeof v !== 'number') { ctx.err('MISSING_FIELD', `thresholds.${k}`, 'preregistered threshold is missing'); continue; }
      if (v < floor) ctx.err('RULE_VIOLATION', `thresholds.${k}`, `${v} is looser than the preregistered ${floor}`);
    }
  }

  // Targets: pairs, licenses, commits, digests.
  const ids = new Set();
  if (!Array.isArray(p.targets) || p.targets.length === 0) ctx.err('MISSING_FIELD', 'targets', 'a protocol needs at least one target');
  else {
    p.targets.forEach((t, i) => {
      const at = `targets[${i}]`;
      if (!isPlainObject(t)) { ctx.err('BAD_TYPE', at, 'must be an object'); return; }
      if (!checkString(ctx, `${at}.id`, t.id)) return;
      if (ids.has(t.id)) ctx.err('DUPLICATE_ID', `${at}.id`, `duplicate target id ${t.id}`);
      ids.add(t.id);
      checkString(ctx, `${at}.language`, t.language);
      checkString(ctx, `${at}.license`, t.license);
      checkCommit(ctx, `${at}.preCommit`, t.preCommit, { nullable: false });
      checkCommit(ctx, `${at}.postCommit`, t.postCommit, { nullable: true });
      checkDigest(ctx, `${at}.digest`, t.digest);
      if (isPlainObject(p.datasetLicenses) && t.license && !(t.license in p.datasetLicenses)) ctx.err('RULE_VIOLATION', `${at}.license`, `license ${t.license} is not declared in datasetLicenses`);
      if (isPlainObject(p.scope) && Array.isArray(p.scope.languages) && t.language && !p.scope.languages.includes(t.language)) ctx.err('RULE_VIOLATION', `${at}.language`, `${t.language} is outside the declared scope`);
    });
  }

  // AC03: nothing silently disappears from the original denominator.
  const retired = Array.isArray(p.retired) ? p.retired : [];
  const retiredIds = new Set();
  retired.forEach((r, i) => {
    if (!isPlainObject(r) || !r.id || !r.reason) ctx.err('BAD_TYPE', `retired[${i}]`, 'a retired target must name id and reason');
    else retiredIds.add(r.id);
  });
  if (!Array.isArray(p.originalTargetIds)) ctx.err('BAD_TYPE', 'originalTargetIds', 'must be an array');
  else {
    for (const id of p.originalTargetIds) {
      if (!ids.has(id) && !retiredIds.has(id)) ctx.err('RULE_VIOLATION', 'originalTargetIds', `target ${id} left the population without a disclosed retirement`);
    }
  }

  // Splits: immutable membership, a partition of the targets, no group straddling it.
  if (!isPlainObject(p.splits) || !Array.isArray(p.splits.dev) || !Array.isArray(p.splits.sealed)) ctx.err('BAD_TYPE', 'splits', 'must be {dev[], sealed[]}');
  else {
    const dev = new Set(p.splits.dev); const sealed = new Set(p.splits.sealed);
    for (const id of dev) if (sealed.has(id)) ctx.err('RULE_VIOLATION', 'splits', `target ${id} is in both development and sealed`);
    for (const id of ids) if (!dev.has(id) && !sealed.has(id)) ctx.err('RULE_VIOLATION', 'splits', `target ${id} is in no split`);
    for (const id of [...dev, ...sealed]) if (!ids.has(id)) ctx.err('DANGLING_REF', 'splits', `split names unknown target ${id}`);
    if (Array.isArray(p.targets) && ctx.errors.length === 0) {
      for (const grp of splitStraddles(groupTargets(p.targets).groups, p.splits)) {
        ctx.err('RULE_VIOLATION', 'splits', `related samples ${grp.members.join(', ')} (${grp.reasons.join('; ')}) straddle development and sealed`);
      }
    }
  }

  if (typeof p.protocolHash !== 'string' || !isDigest(p.protocolHash)) ctx.err('BAD_DIGEST', 'protocolHash', 'must be a sha256 digest');
  else if (ctx.errors.length === 0 && p.protocolHash !== protocolHashOf(p)) {
    ctx.err('HASH_MISMATCH', 'protocolHash', 'content does not match protocolHash: the protocol was changed after it was frozen');
  }
  return result(ctx);
}

/**
 * Freeze a draft. The draft must already carry its splits; use `assignSplits`
 * (grouping.js) to produce them. Returns `{ ok, errors, protocol }`; on success
 * the protocol is deeply frozen and carries its hash.
 */
function freezeProtocol(draft) {
  const p = clone(draft || {});
  p.schema = PROTOCOL_SCHEMA;
  p.schemaVersion = SCHEMA_VERSION;
  p.protocolVersion = Number.isInteger(p.protocolVersion) ? p.protocolVersion : 1;
  if (p.supersedes === undefined) p.supersedes = null;
  if (p.thresholds === undefined) p.thresholds = { ...PREREGISTERED_THRESHOLDS };
  if (p.matching === undefined) p.matching = { ...DEFAULT_MATCHING };
  if (!Array.isArray(p.originalTargetIds)) p.originalTargetIds = (p.targets || []).map((t) => t.id).sort();
  if (!Array.isArray(p.retired)) p.retired = [];
  if (p.comparability === undefined) p.comparability = { comparableWith: [] };
  p.protocolHash = protocolHashOf(p);
  const v = protocol_validateProtocol(p);
  if (!v.ok) return { ok: false, errors: v.errors, protocol: null };
  return { ok: true, errors: [], protocol: deepFreeze(p) };
}

// ---------------------------------------------------------------- versioned diff

function flatten(v, prefix, out) {
  if (Array.isArray(v) || !isPlainObject(v)) { out[prefix] = digestOf(v === undefined ? null : v) + ':' + JSON.stringify(v ?? null).slice(0, 200); return; }
  for (const k of Object.keys(v).sort()) flatten(v[k], prefix ? `${prefix}.${k}` : k, out);
}

/** Field-level diff of two protocols' hashed content. Empty `changes` means identical content. */
function diffProtocols(a, b) {
  const fa = {}; const fb = {};
  for (const f of HASHED) { flatten(a?.[f], f, fa); flatten(b?.[f], f, fb); }
  const paths = [...new Set([...Object.keys(fa), ...Object.keys(fb)])].sort();
  const changes = [];
  for (const path of paths) if (fa[path] !== fb[path]) changes.push({ path, change: !(path in fa) ? 'added' : !(path in fb) ? 'removed' : 'modified' });
  return { from: a?.protocolHash || null, to: b?.protocolHash || null, changes, identical: changes.length === 0 };
}

// Fields that define the measurement. Once a result exists they can never be
// edited in place, only superseded by a new protocol and a new measurement.
const MEASUREMENT_DEFINING = (/* unused pure expression or super */ null && (['thresholds', 'matching', 'scope', 'limits', 'targets', 'originalTargetIds', 'retired', 'splits', 'engine', 'measurement', 'tools', 'models', 'datasetLicenses', 'grouping']));

/**
 * Amend a frozen protocol BEFORE any result was observed for it. The result is a
 * new versioned protocol that names what it supersedes, carries the field diff,
 * and is comparable with nothing earlier. A removed target must be disclosed as
 * retired with a reason; it stays in `originalTargetIds`.
 *
 * `observedResults` is the list of result records known to the caller. If any is
 * bound to this protocol's hash the amendment is refused with POST_RESULT_CHANGE:
 * a threshold, matching rule or denominator cannot move once results exist. The
 * only route forward is `deriveSuccessorProtocol`, which needs a fresh sealed set.
 */
function amendProtocol(frozen, patch, { observedResults = [], reason } = {}) {
  const base = protocol_validateProtocol(frozen);
  if (!base.ok) return { ok: false, errors: base.errors, protocol: null, diff: null };
  const bound = (observedResults || []).filter((r) => r && r.protocolHash === frozen.protocolHash);
  if (bound.length > 0) {
    return {
      ok: false, protocol: null, diff: null,
      errors: [{ code: 'POST_RESULT_CHANGE', path: '', message: `${bound.length} result(s) already exist for protocol ${frozen.protocolHash}; its thresholds, matching rules, scope and denominator cannot change in place` }],
    };
  }
  if (!reason || typeof reason !== 'string') return { ok: false, protocol: null, diff: null, errors: [{ code: 'MISSING_FIELD', path: 'reason', message: 'an amendment must state its reason' }] };
  const next = clone(frozen);
  for (const [k, v] of Object.entries(patch || {})) {
    if (!MEASUREMENT_DEFINING.includes(k)) return { ok: false, protocol: null, diff: null, errors: [{ code: 'UNKNOWN_FIELD', path: k, message: `'${k}' is not an amendable protocol field` }] };
    next[k] = clone(v);
  }
  // Removed targets are retired, never dropped.
  const keep = new Set((next.targets || []).map((t) => t.id));
  const retired = Array.isArray(next.retired) ? next.retired : [];
  const known = new Set(retired.map((r) => r.id));
  for (const t of frozen.targets) if (!keep.has(t.id) && !known.has(t.id)) retired.push({ id: t.id, reason: `removed by amendment: ${reason}`, retiredInVersion: frozen.protocolVersion + 1 });
  next.retired = retired;
  next.protocolVersion = frozen.protocolVersion + 1;
  next.supersedes = frozen.protocolHash;
  next.comparability = { comparableWith: [], invalidates: [frozen.protocolHash], reason };
  next.protocolHash = protocolHashOf(next);
  const v = protocol_validateProtocol(next);
  if (!v.ok) return { ok: false, errors: v.errors, protocol: null, diff: null };
  return { ok: true, errors: [], protocol: deepFreeze(next), diff: diffProtocols(frozen, next) };
}

/**
 * After results exist, the only legal change is a SUCCESSOR protocol with a new
 * measurement. Its sealed set must not overlap any sealed target already
 * consumed by an observed result, so a consumed holdout is never reused.
 */
function deriveSuccessorProtocol(frozen, draft, { observedResults = [], consumedSealedIds = [] } = {}) {
  const consumed = new Set(consumedSealedIds);
  for (const r of observedResults || []) for (const id of r?.sealedTargetIds || []) consumed.add(id);
  if (consumed.size === 0 && (observedResults || []).some((r) => r?.protocolHash === frozen?.protocolHash)) {
    for (const id of frozen.splits.sealed) consumed.add(id);
  }
  const reused = (draft?.splits?.sealed || []).filter((id) => consumed.has(id));
  if (reused.length) {
    return { ok: false, protocol: null, errors: [{ code: 'SEALED_REUSE', path: 'splits.sealed', message: `sealed target(s) ${reused.join(', ')} were already consumed by an observed result; a successor needs a fresh sealed population` }] };
  }
  const r = freezeProtocol({
    ...draft,
    protocolVersion: (frozen?.protocolVersion || 0) + 1,
    supersedes: frozen?.protocolHash || null,
    comparability: { comparableWith: [], invalidates: [frozen?.protocolHash].filter(Boolean), reason: 'successor protocol with a new measurement' },
  });
  return { ...r, diff: r.ok ? diffProtocols(frozen, r.protocol) : null };
}

/**
 * Does a result or run record belong to this exact protocol? A record produced
 * under any other hash (or under a hash that no longer matches the protocol's
 * content) is rejected: it cannot be re-scored under changed rules.
 */
function assertBoundToProtocol(record, protocol) {
  const v = protocol_validateProtocol(protocol);
  if (!v.ok) return { ok: false, errors: v.errors };
  if (!record || record.protocolHash !== protocol.protocolHash) {
    return { ok: false, errors: [{ code: 'PROTOCOL_MISMATCH', path: 'protocolHash', message: `record is bound to ${record?.protocolHash || 'no protocol'}, not ${protocol.protocolHash}` }] };
  }
  return { ok: true, errors: [] };
}

;// CONCATENATED MODULE: ./src/posture/evaluation/scan-child.js
// Child-process entry for ONE engine scan inside an evaluation run (QA-003).
//
// `node scan-child.js <workspace> <layer-config>` where the layer config is one
// of the ablation names in runner.js. It exists as a separate process so that:
//   - a timeout can KILL the scan (an in-process scan cannot be interrupted);
//   - the environment is exactly what the runner passed, with no label paths;
//   - state writes cannot touch the host's scan state.
//
// A third argument `diagnose` adds a `diagnostics` block to the result (why-missed.js): the suppression ledger with its
// identities, the filter and dedupe stage evidence, the sources and sinks the engine recognised, and how the intermediate
// representation fared on the files named in AGENTIC_SECURITY_DIAG_FILES. Diagnose mode only OBSERVES; the findings it returns are
// the same findings the plain mode returns (pinned by test).
//
// It reads only the staged workspace. Exit codes: 0 ok (JSON on stdout between
// the markers), 3 the requested layer is unavailable here (a model-assisted run
// with no configured endpoint), 1 anything else.




const RESULT_BEGIN = '@@EVAL-RESULT-BEGIN@@';
const RESULT_END = '@@EVAL-RESULT-END@@';

const LAYER_ENV = {
  'deterministic-only': { AGENTIC_SECURITY_DEEP: '0', AGENTIC_SECURITY_LLM_VALIDATE: '0' },
  'deep-taint': { AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_LLM_VALIDATE: '0' },
  'model-assisted': { AGENTIC_SECURITY_DEEP: '1' },
};

async function diagnosticsOf(scan) {
  const slim = (x) => ({ file: x.file ?? null, line: Number.isInteger(x.line) ? x.line : null, vuln: x.vuln ?? x.label ?? null, category: x.category ?? null });
  const diag = {
    suppressions: (scan.suppressions || []).map((x) => ({ vuln: x.vuln ?? null, file: x.file ?? null, line: Number.isInteger(x.line) ? x.line : null, reason: String(x.reason ?? ''), id: x.id ?? null, cwe: x.cwe ?? null, family: x.family ?? null })),
    stageEvidence: scan.stageEvidence || { dedupe: [], guard: [] },
    sources: (scan.sources || []).map(slim), sinks: (scan.sinks || []).map(slim),
    ir: { files: {}, parseFailures: [] },
  };
  let wanted = [];
  try { wanted = JSON.parse(process.env.AGENTIC_SECURITY_DIAG_FILES || '[]'); } catch { wanted = []; }
  if (wanted.length) {
    try {
      const irMod = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 28149));
      irMod._resetIrParseFailures();
      const ir = await irMod.buildProjectIRAsync(Object.fromEntries(wanted.filter((f) => scan.fc && typeof scan.fc[f] === 'string').map((f) => [f, scan.fc[f]])));
      for (const f of wanted) {
        const entry = ir.perFile?.[f];
        diag.ir.files[f] = entry ? { lowered: true, functions: (entry.functions || []).map((fn) => ({ line: fn.line, name: fn.name })) } : { lowered: false, functions: [] };
      }
      diag.ir.parseFailures = irMod.irParseFailures();
    } catch (e) { diag.ir.error = String(e?.message || e).slice(0, 200); }
  }
  return diag;
}

async function main() {
  const [dir, layer, mode] = process.argv.slice(2);
  if (!dir || !LAYER_ENV[layer]) { process.stderr.write(`usage: scan-child <workspace> <${Object.keys(LAYER_ENV).join('|')}>\n`); process.exit(1); }
  if (layer === 'model-assisted' && !process.env.AGENTIC_SECURITY_LLM_ENDPOINT) {
    process.stderr.write('model-assisted requires AGENTIC_SECURITY_LLM_ENDPOINT; none is configured\n');
    process.exit(3);
  }
  Object.assign(process.env, LAYER_ENV[layer]);
  if (mode === 'diagnose') process.env.AGENTIC_SECURITY_STAGE_EVIDENCE = '1';
  const { setStateWritesEnabled } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 31174));
  setStateWritesEnabled(false);
  const { runScan } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 45950));
  const { scan } = await runScan(external_node_path_.resolve(dir), { deep: layer !== 'deterministic-only' });
  const findings = (scan.findings || []).map((f) => ({
    id: f.id ?? null, file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null,
    family: f.family ?? null, cwe: f.cwe ?? null, severity: f.severity ?? null, parser: f.parser ?? null, vuln: f.vuln ?? null,
  }));
  const result = { findings };
  if (mode === 'diagnose') result.diagnostics = await diagnosticsOf(scan);
  // The parent reads this through a pipe. A pipe holds about 64 KB, and `process.exit()` right after a larger write drops what has not been read, so the
  // parent saw "no result block" for any scan with a big diagnostics payload (62 of 272 forensics re-scans). Wait until the write has been handed over.
  await new Promise((resolve, reject) => process.stdout.write(`${RESULT_BEGIN}${JSON.stringify(result)}${RESULT_END}\n`, (err) => (err ? reject(err) : resolve())));
}

// Only when run as a script: runner.js imports the markers and must not start a scan.
if (process.argv[1] && import.meta.url === (0,external_node_url_.pathToFileURL)(process.argv[1]).href) {
  main().then(() => process.exit(0), (e) => { process.stderr.write(`${e?.stack || e}\n`); process.exit(1); });
}

;// CONCATENATED MODULE: ./src/posture/evaluation/runner.js
// Reproducible evaluation runs and layer ablations (QA-003).
//
// A run executes the engine over the protocol's pinned targets and records, for
// every target and variant, the outcome (completed / timeout / error /
// unavailable / quarantined), its findings, timing, cost, failure reason and the
// hashes of what went in and what came out. Nothing is dropped: a target that
// timed out is a recorded outcome, and scoring (score.js) counts it as a MISS
// when a known positive sat behind it.
//
// Run identity covers everything that can change a result: protocol hash, engine
// and bundle, layer configuration, provider/model/settings/cache, budget, seed,
// replicate, split, and the digests of the targets themselves. Change any one and
// the id changes, so two runs are never confused or silently merged.
//
// The engine never sees labels: this module receives workspace directories only,
// stages them through custody.js (which audits and quarantines), and runs the
// scan in a child process under a scrubbed environment.














const RUN_SCHEMA = 'agentic-security/evaluation-run';
const ABLATION_LAYERS = Object.freeze(Object.keys(LAYER_ENV));
const OUTCOME_STATUSES = Object.freeze(['completed', 'timeout', 'error', 'unavailable', 'quarantined']);
const SCAN_CHILD = external_node_path_.join(external_node_path_.dirname((0,external_node_url_.fileURLToPath)(import.meta.url)), 'scan-child.js');
const runner_SKIP = new Set(['.git', state_dir/* STATE_DIR_NAME */.Ky, 'node_modules']);

/** Content digest of a directory tree: sorted relative paths plus bytes. Symlinks are hashed by target, never followed. */
function digestTree(dir, { maxFiles = 50000 } = {}) {
  const h = crypto.createHash('sha256');
  let n = 0;
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      const full = path.join(d, e.name);
      if (e.isSymbolicLink()) { h.update(`L:${r}:${fs.readlinkSync(full)}\n`); continue; }
      if (e.isDirectory()) { if (!runner_SKIP.has(e.name)) walk(full, r); continue; }
      if (!e.isFile()) continue;
      if (++n > maxFiles) throw new Error(`digestTree: more than ${maxFiles} files`);
      h.update(`F:${r}:${fs.statSync(full).size}\n`);
      h.update(fs.readFileSync(full));
    }
  };
  walk(dir, '');
  return `sha256:${h.digest('hex')}`;
}

/** The digest a protocol pins for one target: both variants' trees. */
function targetDigestOf({ pre, post }) { return digestOf({ pre: pre ?? null, post: post ?? null }); }

const keyOf = (o) => digestOf(o);

/** Everything that can change a run's results. Labels are deliberately absent: the engine never sees them. */
function runIdentityMaterial({ protocol, config, budget, split, replicate = 0, targetDigests }) {
  return {
    protocolHash: protocol.protocolHash,
    engine: protocol.engine,
    config: {
      layer: config.layer, provider: config.provider ?? null, model: config.model ?? null,
      settings: config.settings ?? {}, cache: config.cache ?? { mode: 'none' }, seed: config.seed ?? null,
    },
    budget, split, replicate,
    targets: Object.fromEntries(Object.entries(targetDigests).sort(([a], [b]) => a.localeCompare(b))),
  };
}
const runIdentity = (m) => `erun:${keyOf({ kind: 'evaluation-run', ...runIdentityMaterial(m) }).slice('sha256:'.length, 'sha256:'.length + 20)}`;
/** Same as the run id but with the replicate left out: the id of the experiment replicates belong to. */
const experimentIdentity = (m) => `eexp:${keyOf({ kind: 'evaluation-experiment', ...runIdentityMaterial({ ...m, replicate: 0 }) }).slice('sha256:'.length, 'sha256:'.length + 20)}`;

// ---------------------------------------------------------------- the default scan function

/**
 * Run one engine scan in a child process. The child is killed (whole process
 * group) when the timeout expires. Returns `{ findings }` or throws an Error whose
 * `code` is TIMEOUT, UNAVAILABLE or ERROR.
 */
function defaultScanFn(workspaceDir, { layer, timeoutMs, env, diagnose = false, childPath = SCAN_CHILD }) {
  return new Promise((resolve, reject) => {
    const child = (0,external_node_child_process_.spawn)(process.execPath, [childPath, workspaceDir, layer, ...(diagnose ? ['diagnose'] : [])], { env, cwd: workspaceDir, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; let err = ''; let done = false;
    const cap = 64 * 1024 * 1024;
    const fail = (code, message) => { if (done) return; done = true; clearTimeout(timer); const e = new Error(message); e.code = code; reject(e); };
    const timer = setTimeout(() => {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } }
      fail('TIMEOUT', `no result within ${timeoutMs} ms`);
    }, timeoutMs);
    child.stdout.on('data', (b) => { if (out.length < cap) out += b; });
    child.stderr.on('data', (b) => { if (err.length < 65536) err += b; });
    child.on('error', (e) => fail('ERROR', e.message));
    child.on('close', (code) => {
      if (done) return;
      if (code === 3) return fail('UNAVAILABLE', err.trim().slice(0, 300) || 'layer unavailable');
      if (code !== 0) return fail('ERROR', `scan exited ${code}: ${err.trim().slice(-300)}`);
      const a = out.indexOf(RESULT_BEGIN); const b = out.indexOf(RESULT_END);
      if (a < 0 || b < a) return fail('ERROR', 'scan produced no result block');
      try { done = true; clearTimeout(timer); resolve(JSON.parse(out.slice(a + RESULT_BEGIN.length, b))); } catch (e) { done = false; fail('ERROR', `unreadable result: ${e.message}`); }
    });
  });
}

const sortFindings = (fs_) => [...fs_].sort((x, y) => `${x.file}|${x.line}|${x.family}|${x.cwe}|${x.id}`.localeCompare(`${y.file}|${y.line}|${y.family}|${y.cwe}|${y.id}`));

function emptyOutcome(targetId, variant, status, failureReason, extra = {}) {
  return { targetId, variant, status, findings: [], durationMs: 0, costUsd: null, costSource: 'unmeasured', failureReason, inputHash: null, outputHash: digestOf([]), cached: false, ...extra };
}

/**
 * Execute one configuration over the protocol's targets.
 *
 * @param {object}   o
 * @param {object}   o.protocol        a frozen, valid protocol
 * @param {object}   o.config          { layer, provider?, model?, settings?, cache?, seed? }
 * @param {Function} o.resolveTarget   (target, variant) => { dir } | { unavailable: reason }
 * @param {Function} [o.scanFn]        (workspace, { layer, timeoutMs, seed, env }) => { findings, costUsd? }
 * @param {string[]} [o.protectedTerms] terms that must not appear in an engine workspace
 * @param {'dev'|'sealed'|'all'} [o.split]
 * @param {boolean}  [o.allowSealed]   required to touch sealed targets (the custodian's call)
 * @param {Map}      [o.cache]         outcome cache, keyed by every semantically relevant input
 */
async function runEvaluation(o) {
  const { protocol, config, resolveTarget, scanFn = defaultScanFn, protectedTerms = [], split = 'dev', allowSealed = false, cache = null, replicate = 0, workRoot, now = Date.now } = o;
  const v = validateProtocol(protocol);
  if (!v.ok) return { ok: false, errors: v.errors, run: null };
  if (!ABLATION_LAYERS.includes(config?.layer)) return { ok: false, errors: [{ code: 'UNKNOWN_ENUM', path: 'config.layer', message: `layer must be one of ${ABLATION_LAYERS.join(', ')}` }], run: null };
  if ((split === 'sealed' || split === 'all') && !allowSealed) {
    return { ok: false, errors: [{ code: 'SEALED_ACCESS', path: 'split', message: 'only the evaluation custodian may run the sealed split (allowSealed)' }], run: null };
  }
  const wanted = new Set(split === 'all' ? [...protocol.splits.dev, ...protocol.splits.sealed] : protocol.splits[split] || []);
  const targets = protocol.targets.filter((t) => wanted.has(t.id)).sort((a, b) => a.id.localeCompare(b.id));
  const budget = { perTargetTimeoutMs: protocol.limits.perTargetTimeoutMs, spendCeilingUsd: protocol.limits.spendCeilingUsd };
  const cfg = { ...config, seed: config.seed ?? null };

  const ownRoot = !workRoot;
  const root = workRoot || fs.mkdtempSync(path.join(os.tmpdir(), 'eval-run-'));
  const outcomes = []; const targetDigests = {};
  let spent = 0;
  try {
    for (const t of targets) {
      const variants = t.postCommit ? ['pre', 'post'] : ['pre'];
      const resolved = {}; const digests = {};
      for (const variant of variants) {
        const r = await resolveTarget(t, variant);
        resolved[variant] = r;
        if (r?.dir) { try { digests[variant] = digestTree(r.dir); } catch (e) { resolved[variant] = { unavailable: `digest failed: ${e.message}` }; } }
      }
      const allResolved = variants.every((vn) => resolved[vn]?.dir);
      const combined = allResolved ? targetDigestOf({ pre: digests.pre, post: digests.post ?? null }) : null;
      // `targetDigests` carries the pinned digest even when the tree is unavailable, so identity is stable.
      targetDigests[t.id] = combined || t.digest;
      for (const variant of variants) {
        const base = { targetId: t.id, variant };
        if (!resolved[variant]?.dir) { outcomes.push(emptyOutcome(t.id, variant, 'unavailable', resolved[variant]?.unavailable || 'target could not be resolved')); continue; }
        if (combined !== t.digest) { outcomes.push(emptyOutcome(t.id, variant, 'unavailable', 'target-digest-mismatch: the tree does not match the digest pinned in the protocol')); continue; }
        const inputHash = digestOf({ digest: digests[variant], layer: cfg.layer, budget, seed: cfg.seed, replicate, engine: protocol.engine, provider: cfg.provider ?? null, model: cfg.model ?? null, settings: cfg.settings ?? {}, cache: cfg.cache ?? { mode: 'none' } });
        if (cache && cfg.cache?.mode === 'enabled' && cache.has(inputHash)) { outcomes.push({ ...cache.get(inputHash), ...base, cached: true }); continue; }
        if (spent >= budget.spendCeilingUsd && budget.spendCeilingUsd > 0 && cfg.layer === 'model-assisted') {
          outcomes.push(emptyOutcome(t.id, variant, 'error', 'spend-ceiling-reached', { inputHash })); continue;
        }
        const staged = stageWorkspace({ srcDir: resolved[variant].dir, destDir: path.join(root, `${t.id}-${variant}`.replace(/[^\w.-]/g, '_')), terms: protectedTerms });
        if (!staged.ok) { outcomes.push(emptyOutcome(t.id, variant, 'quarantined', `leakage control: ${staged.leaks.map((l) => `${l.kind}${l.file ? `@${l.file}` : ''}`).join(', ')}`, { inputHash })); continue; }
        const env = engineEnvironment({ PATH: process.env.PATH, LANG: 'C', HOME: root, ...(cfg.layer === 'model-assisted' ? pickLlmEnv(process.env) : {}) });
        const t0 = now();
        try {
          const res = await scanFn(staged.destDir, { layer: cfg.layer, timeoutMs: budget.perTargetTimeoutMs, seed: cfg.seed, env });
          const findings = sortFindings(res?.findings || []);
          const cost = typeof res?.costUsd === 'number' ? res.costUsd : null;
          if (cost) spent += cost;
          const oc = { ...base, status: 'completed', findings, durationMs: now() - t0, costUsd: cost, costSource: cost === null ? 'unmeasured' : 'reported-by-scan', failureReason: null, inputHash, outputHash: digestOf(findings), cached: false };
          if (cache && cfg.cache?.mode === 'enabled') cache.set(inputHash, oc);
          outcomes.push(oc);
        } catch (e) {
          const status = e?.code === 'TIMEOUT' ? 'timeout' : e?.code === 'UNAVAILABLE' ? 'unavailable' : 'error';
          outcomes.push(emptyOutcome(t.id, variant, status, String(e?.message || e).slice(0, 400), { durationMs: now() - t0, inputHash }));
        } finally {
          fs.rmSync(staged.destDir, { recursive: true, force: true });
        }
      }
    }
  } finally {
    if (ownRoot) fs.rmSync(root, { recursive: true, force: true });
  }
  const material = { protocol, config: cfg, budget, split, replicate, targetDigests };
  const totals = Object.fromEntries(OUTCOME_STATUSES.map((s) => [s, outcomes.filter((x) => x.status === s).length]));
  const run = {
    schema: RUN_SCHEMA, schemaVersion: SCHEMA_VERSION,
    runId: runIdentity(material), experimentId: experimentIdentity(material),
    protocolHash: protocol.protocolHash, engine: protocol.engine, split, replicate,
    config: runIdentityMaterial(material).config, budget,
    targetSetDigest: digestOf(runIdentityMaterial(material).targets),
    sealedTargetIds: split === 'dev' ? [] : targets.filter((t) => protocol.splits.sealed.includes(t.id)).map((t) => t.id),
    outcomes, totals, totalCostUsd: outcomes.reduce((s, x) => s + (x.costUsd || 0), 0),
    rawHash: digestOf(outcomes.map((x) => ({ t: x.targetId, v: x.variant, s: x.status, o: x.outputHash }))),
  };
  return { ok: true, errors: [], run };
}

function pickLlmEnv(env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) if (/^AGENTIC_SECURITY_LLM_/.test(k)) out[k] = v;
  return out;
}

/**
 * Replicates of one configuration. Deterministic layers must reproduce their
 * output hashes exactly; the model-assisted layer is stochastic and needs at
 * least three replicates with recorded seeds, or the result is invalid.
 */
async function runReplicates({ n = 1, seedSupported = false, ...rest }) {
  const stochastic = rest.config?.layer === 'model-assisted';
  const runs = [];
  for (let i = 0; i < n; i++) {
    const config = { ...rest.config, seed: seedSupported ? (rest.config.seed ?? 0) + i : (rest.config.seed ?? null) };
    const r = await runEvaluation({ ...rest, config, replicate: i });
    if (!r.ok) return { ok: false, errors: r.errors, runs, valid: false, reasons: ['run rejected'] };
    runs.push(r.run);
  }
  const reasons = [];
  if (stochastic && n < 3) reasons.push(`a stochastic configuration needs at least 3 measured replicates, got ${n}`);
  if (stochastic && !seedSupported) reasons.push('seeds are not supported by this provider; replicate variance is recorded without a seed');
  const differing = [];
  if (n >= 2) {
    const first = runs[0];
    for (const o of first.outcomes) {
      const hashes = runs.map((r) => r.outcomes.find((x) => x.targetId === o.targetId && x.variant === o.variant)?.outputHash);
      if (new Set(hashes).size > 1) differing.push(`${o.targetId}/${o.variant}`);
    }
  }
  const determinism = n < 2 ? { checked: false, identical: null, differing: [] } : { checked: true, identical: differing.length === 0, differing };
  if (!stochastic && determinism.checked && !determinism.identical) reasons.push(`deterministic configuration produced different output across replicates: ${differing.join(', ')}`);
  return { ok: true, errors: [], runs, stochastic, determinism, valid: reasons.filter((x) => !x.startsWith('seeds are not supported')).length === 0, reasons };
}

/**
 * Run every layer over identical targets, matching policy and ceilings. Only the
 * layer differs between configurations; anything else that differs is refused.
 */
async function runAblations({ layers = ABLATION_LAYERS, config = {}, ...rest }) {
  const runs = [];
  for (const layer of layers) {
    const r = await runEvaluation({ ...rest, config: { ...config, layer } });
    if (!r.ok) return { ok: false, errors: r.errors, runs };
    runs.push(r.run);
  }
  const cmp = assertAblationComparable(runs);
  return { ok: cmp.ok, errors: cmp.errors, runs, comparable: cmp.ok };
}

/** Ablations are comparable only if protocol, split, target set and budget are identical and only the layer differs. */
function assertAblationComparable(runs) {
  const errors = [];
  const [a, ...others] = runs || [];
  if (!a) return { ok: false, errors: [{ code: 'MISSING_FIELD', path: 'runs', message: 'no runs to compare' }] };
  for (const r of others) {
    for (const [field, same] of [
      ['protocolHash', r.protocolHash === a.protocolHash], ['split', r.split === a.split],
      ['targetSetDigest', r.targetSetDigest === a.targetSetDigest], ['budget', digestOf(r.budget) === digestOf(a.budget)],
      ['config.provider', r.config.provider === a.config.provider], ['config.model', r.config.model === a.config.model],
      ['config.settings', digestOf(r.config.settings) === digestOf(a.config.settings)], ['config.cache', digestOf(r.config.cache) === digestOf(a.config.cache)],
    ]) if (!same) errors.push({ code: 'ABLATION_MISMATCH', path: field, message: `${r.config.layer} differs from ${a.config.layer} in ${field}; ablations may differ only in layer` });
    if (r.runId === a.runId) errors.push({ code: 'DUPLICATE_ID', path: 'runId', message: 'two ablations share a run identity' });
  }
  return { ok: errors.length === 0, errors };
}

// EXTERNAL MODULE: ./src/llm-validator/ollama-provider.js
var ollama_provider = __webpack_require__(23837);
// EXTERNAL MODULE: ./src/llm-validator/local-endpoint.js
var local_endpoint = __webpack_require__(894);
;// CONCATENATED MODULE: ./src/posture/evaluation/lab/arm-ollama.js
// A built-in model arm for a LOCAL Ollama server (PRD 6: "model adapters"). It reuses the repository's own Ollama provider
// (`llm-validator/ollama-provider.js`): loopback is enforced there, a failure is a typed error, and nothing here ever falls back to
// another provider. The lab adds what an evaluation needs on top: the request is built from the already neutralised, already audited
// workspace, passed through the leakage guard, and the model's JSON answer goes through the same validation as a command arm's.
//
// Only loopback hosts are accepted by this adapter. A remote or cloud model is reached through the `command` adapter, where the
// egress policy decides before anything leaves the machine.
//
// What this proves and does not: against a stand-in Ollama server (test/fixtures/eval-lab/fake-ollama.mjs) it proves the request shape,
// the leakage guard, the timeout and error mapping, the answer validation and the usage accounting. It says nothing about how any
// real model performs; that is what running the lab with a real model measures.






const MAX_FILES = 12;
const MAX_FILE_BYTES = 12 * 1024;
const MAX_PROMPT_BYTES = 96 * 1024;
const CODE_EXT = /\.(?:js|mjs|cjs|jsx|ts|tsx|py|java|go|rb|php|c|h|cc|cpp|cs|rs|kt|swift|sh)$/i;

function listSources(dir, limit = 400) {
  const out = []; const stack = [''];
  while (stack.length && out.length < limit) {
    const rel = stack.pop();
    let ents; try { ents = external_node_fs_.readdirSync(external_node_path_.join(dir, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.isSymbolicLink() || e.name.startsWith('.') || e.name === 'node_modules') continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) stack.push(r); else if (e.isFile() && CODE_EXT.test(e.name)) out.push(r);
    }
  }
  return out.sort();
}

/** Numbered source for the files a task needs: the target file whole (bounded) for single-target tasks, else the first few files. */
function sourceBlock(workspaceDir, wanted) {
  const files = wanted?.length ? wanted : listSources(workspaceDir).slice(0, MAX_FILES);
  const parts = [];
  for (const f of files.slice(0, MAX_FILES)) {
    const abs = external_node_path_.resolve(workspaceDir, f);
    if (!abs.startsWith(external_node_path_.resolve(workspaceDir) + external_node_path_.sep)) continue;
    let text; try { text = external_node_fs_.readFileSync(abs, 'utf8'); } catch { continue; }
    const clipped = text.length > MAX_FILE_BYTES ? `${text.slice(0, MAX_FILE_BYTES)}\n/* truncated */` : text;
    parts.push(`### ${f}\n${clipped.split('\n').map((l, i) => `${String(i + 1).padStart(4)}| ${l}`).join('\n')}`);
  }
  return parts.join('\n\n');
}

const SCHEMAS = {
  detect: { type: 'object', required: ['findings'], properties: { findings: { type: 'array', items: { type: 'object', required: ['file', 'line', 'cwe'], properties: { file: { type: 'string' }, line: { type: 'integer' }, cwe: { type: 'string' }, confidence: { type: 'number' } } } } } },
  falsify: { type: 'object', required: ['verdicts'], properties: { verdicts: { type: 'object', additionalProperties: { type: 'string', enum: ['confirmed', 'refuted', 'uncertain'] } } } },
  exploit: { type: 'object', required: ['reproducer'], properties: { reproducer: { type: 'object' } } },
  patch: { type: 'object', required: ['files'], properties: { files: { type: 'object', additionalProperties: { type: 'string' } } } },
};

function promptFor(task, request, workspaceDir) {
  const t = request.target;
  const code = sourceBlock(workspaceDir, t?.file ? [t.file] : request.candidates?.map((c) => c.file).filter(Boolean));
  const head = 'You are a security analyst. Answer with ONE JSON object and nothing else. Do not explain.';
  if (task === 'detect') return `${head}\nFind security vulnerabilities in the code below. Report each as {"file","line","cwe","confidence"} (cwe like "CWE-89"; confidence 0 to 1). Report only what you can point to a line for. If there are none, return {"findings":[]}.\n\n${code}`;
  if (task === 'falsify') return `${head}\nFor each candidate, decide whether it is a real vulnerability: "confirmed", "refuted" or "uncertain". Return {"verdicts":{"<id>":"<verdict>"}}.\nCandidates: ${JSON.stringify(request.candidates)}\n\n${code}`;
  if (task === 'exploit') return `${head}\nWrite a minimal reproducer for the ${t.cwe ?? 'vulnerability'} at ${t.file}:${t.line}. Return {"reproducer":{"schema":"agentic-security/reproducer","version":1,"findingId":"eval","lang":"javascript","files":{"<name>":"<source>"},"run":["{{NODE}}","<name>","{{CANARY:command}}"],"oracle":{"type":"command_execution","params":{"canary":"command"}}}}. The program must perform the dangerous action only if the vulnerability is real.\n\n${code}`;
  return `${head}\nFix the vulnerability at ${t.file}:${t.line} (${t.cwe ?? 'unspecified'}). Return {"files":{"<path>":"<the complete new file contents>"}} containing only the files you change.\n\n${code}`;
}

/**
 * @returns {Promise<{status: 'completed'|'timeout'|'error'|'blocked'|'unavailable', reason?: string, body?: object, reported?: object}>}
 */
async function runOllamaArm({ arm, task, request, workspaceDir, terms = [], timeoutMs = 120_000, signal, callChat = ollama_provider/* callOllamaChat */.L5 }) {
  const host = String(arm.adapter.host ?? arm.model.endpoint ?? ollama_provider.DEFAULT_OLLAMA_HOST).replace(/\/+$/, '');
  if (!(0,local_endpoint/* isLoopbackUrl */.tE)(host)) return { status: 'blocked', reason: 'the ollama adapter only talks to a loopback server; reach a remote model through the command adapter so the egress policy decides' };
  const prompt = promptFor(task, request, workspaceDir);
  if (Buffer.byteLength(prompt) > MAX_PROMPT_BYTES) return { status: 'error', reason: 'the task needs more source than the adapter sends in one prompt' };
  const guard = guardPrompt(prompt, terms);
  if (!guard.ok) return { status: 'blocked', reason: `leakage guard: the prompt contained a protected term (${guard.leaks[0]?.kind})` };
  if (signal?.aborted) return { status: 'error', reason: 'cancelled' };
  const r = await Promise.race([
    callChat({ host, model: arm.model.id, messages: [{ role: 'user', content: prompt }], maxTokens: arm.adapter.maxTokens ?? 2048, schema: SCHEMAS[task], timeouts: { connectTimeoutMs: 3000, requestTimeoutMs: arm.adapter.timeoutMs ?? timeoutMs } }),
    new Promise((resolve) => signal?.addEventListener('abort', () => resolve({ ok: false, code: 'cancelled', reason: 'cancelled' }), { once: true })),
  ]);
  if (!r.ok) return { status: r.code === 'ollama-timeout' ? 'timeout' : r.code === 'ollama-unreachable' || r.code === 'ollama-model-not-installed' ? 'unavailable' : 'error', reason: `${r.code}: ${String(r.reason).slice(0, 160)}` };
  let body;
  try { body = JSON.parse(r.result.text); } catch { return { status: 'error', reason: 'invalid-response: the model did not return JSON', reported: r.result.usage }; }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { status: 'error', reason: 'invalid-response: expected a JSON object', reported: r.result.usage };
  return { status: 'ok', body: { ...body, usage: r.result.usage ?? undefined } };
}

;// CONCATENATED MODULE: ./src/posture/evaluation/lab/arms.js
// Arms: the things the Eval Lab measures (PRD 6). An arm is the deterministic scanner, or a model reached through a small
// operator-supplied command, or a LOCAL Ollama server through the repository's own provider. There is deliberately no built-in client
// for a remote model: provider calls in this repository go through the feature gate, the egress policy, redaction and the audit chain,
// and the lab must not become a second path around them.
// An arm whose model is not local is therefore checked against the egress policy BEFORE it runs, and a denial is recorded as
// `blocked`, not as a score.
//
// Honesty rules enforced here:
//   * `local` is declared, never inferred, and a "local" arm that names a non-loopback endpoint is refused as a lie;
//   * there is no fallback from one arm to another, so a local model can never silently become a cloud call;
//   * the command receives its request in a FILE and answers on stdout; it never reads stdin, and it runs with a scrubbed
//     environment, a wall-clock timeout and cleanup of its whole process tree (`superviseSpawn`);
//   * everything the lab sends is passed through the leakage guard first, and a hit blocks the call;
//   * token and dollar usage are whatever the arm reports and are labelled `reported`; absent usage is `unknown`, never zero.











const TASKS = Object.freeze(['detect', 'falsify', 'exploit', 'patch']);
const ARM_KINDS = Object.freeze(['deterministic', 'model']);
const arms_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const LOOPBACK = /^(?:https?:\/\/)?(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(?:\/|$)/i;

function validateArm(a) {
  const errors = [];
  const bad = (m) => errors.push(m);
  if (!a || typeof a !== 'object') return { ok: false, errors: ['arm must be an object'] };
  if (typeof a.id !== 'string' || !arms_ID_RE.test(a.id)) bad('arm.id must be a lower-case identifier');
  if (!ARM_KINDS.includes(a.kind)) bad(`arm.kind must be one of ${ARM_KINDS.join(', ')}`);
  if (!Array.isArray(a.tasks) || !a.tasks.length || !a.tasks.every((t) => TASKS.includes(t))) bad(`arm.tasks must list some of ${TASKS.join(', ')}`);
  const ad = a.adapter;
  if (!ad || typeof ad !== 'object') bad('arm.adapter is required');
  else if (ad.type === 'builtin-scanner') {
    if (a.kind !== 'deterministic') bad('the builtin-scanner adapter is the deterministic arm');
    if (a.tasks?.some((t) => t !== 'detect')) bad('the deterministic scanner only performs the detect task');
    if (ad.layer !== undefined && !['deterministic-only', 'deep-taint'].includes(ad.layer)) bad('adapter.layer must be deterministic-only or deep-taint (a model layer is a model arm)');
  } else if (ad.type === 'command') {
    if (!Array.isArray(ad.argv) || !ad.argv.length || !ad.argv.every((x) => typeof x === 'string' && x.length < 2000 && !x.includes('\0'))) bad('adapter.argv must be a non-empty array of strings (no shell string)');
    if (ad.timeoutMs !== undefined && !(Number.isInteger(ad.timeoutMs) && ad.timeoutMs >= 1000 && ad.timeoutMs <= 3_600_000)) bad('adapter.timeoutMs must be between 1000 and 3600000');
  } else if (ad.type === 'ollama') {
    if (a.kind !== 'model') bad('the ollama adapter is a model arm');
    if (a.model?.local !== true) bad('the ollama adapter talks to a local server, so model.local must be true');
    if (ad.host !== undefined && !LOOPBACK.test(String(ad.host))) bad('adapter.host must be a loopback address; use the command adapter for a remote model');
    if (ad.timeoutMs !== undefined && !(Number.isInteger(ad.timeoutMs) && ad.timeoutMs >= 1000 && ad.timeoutMs <= 3_600_000)) bad('adapter.timeoutMs must be between 1000 and 3600000');
  } else bad('adapter.type must be builtin-scanner, command or ollama');
  if (a.kind === 'model') {
    const m = a.model;
    if (!m || typeof m.id !== 'string' || !m.id || typeof m.provider !== 'string' || !m.provider) bad('a model arm needs model.id and model.provider');
    else {
      if (typeof m.local !== 'boolean') bad('model.local must be true or false; it is declared, never inferred');
      if (m.local === true && m.endpoint && !LOOPBACK.test(String(m.endpoint))) bad('model.local is true but model.endpoint is not a loopback address');
      if (m.local === false && (typeof m.endpoint !== 'string' || !m.endpoint)) bad('a non-local model arm must name its endpoint so the egress policy can judge it');
    }
    if (a.kind === 'model' && ad?.type === 'builtin-scanner') bad('a model arm needs a command or ollama adapter');
  }
  if (a.price !== undefined) {
    const p = a.price;
    if (!p || !(Number.isFinite(p.inputPerMTok) && p.inputPerMTok >= 0 && Number.isFinite(p.outputPerMTok) && p.outputPerMTok >= 0)) bad('arm.price needs non-negative inputPerMTok and outputPerMTok');
  }
  return { ok: errors.length === 0, errors };
}

/** Dollars from reported tokens and a declared price, or the arm's own reported figure. `unknown` is null, never zero. */
function usageOf(arm, reported, latencyMs) {
  const u = reported && typeof reported === 'object' ? reported : {};
  const num = (x) => (Number.isFinite(x) && x >= 0 ? x : null);
  const inputTokens = num(u.inputTokens); const outputTokens = num(u.outputTokens);
  let usd = num(u.usd); let source = usd != null ? 'reported' : 'unknown';
  if (usd == null && arm.price && inputTokens != null && outputTokens != null) {
    usd = (inputTokens * arm.price.inputPerMTok + outputTokens * arm.price.outputPerMTok) / 1e6; source = 'computed-from-reported-tokens';
  }
  if (arm.kind === 'deterministic') { usd = 0; source = 'no-model'; }
  return { inputTokens, outputTokens, usd, usdSource: source, latencyMs };
}

const normalizeFinding = (f) => ({ file: String(f.file ?? ''), line: Number.isInteger(f.line) ? f.line : null, cwe: f.cwe ?? null, confidence: typeof f.confidence === 'number' ? f.confidence : null });

/** Turn an arm's parsed JSON answer into the task's output, or an `error` result. Shared by every adapter, so a model gets no softer validation than a command. */
function shapeBody(task, body, done) {
  const out = {};
  if (task === 'detect') { if (!Array.isArray(body.findings)) return done('error', { reason: 'invalid-response: detect needs "findings"', reported: body.usage }); out.findings = body.findings.slice(0, 5000).filter((f) => f && typeof f === 'object').map(normalizeFinding); }
  else if (task === 'falsify') { if (!body.verdicts || typeof body.verdicts !== 'object') return done('error', { reason: 'invalid-response: falsify needs "verdicts"', reported: body.usage }); out.verdicts = Object.fromEntries(Object.entries(body.verdicts).slice(0, 5000).map(([k, v]) => [k, ['confirmed', 'refuted', 'uncertain'].includes(v) ? v : 'uncertain'])); }
  else if (task === 'exploit') { if (!body.reproducer || typeof body.reproducer !== 'object') return done('completed', { output: { reproducer: null }, reported: body.usage }); out.reproducer = body.reproducer; }
  else if (task === 'patch') { if (!body.files || typeof body.files !== 'object' || Array.isArray(body.files)) return done('completed', { output: { files: null }, reported: body.usage }); out.files = Object.fromEntries(Object.entries(body.files).slice(0, 64).filter(([k, v]) => typeof k === 'string' && typeof v === 'string' && v.length < 1_000_000)); }
  return done('completed', { output: out, reported: body.usage });
}

/**
 * Run one task for one arm. Never throws, never returns a score: it returns what happened.
 * @returns {{status: 'completed'|'timeout'|'error'|'blocked'|'unavailable', reason?: string, output?: object, usage: object}}
 */
async function runArmTask({ arm, task, request, workspaceDir, terms = [], scanRoot, signal, timeoutMs = 120_000, egress = egress_policy/* evaluateEgress */.nn, scanFn = defaultScanFn }) {
  const t0 = Date.now();
  const done = (status, extra = {}) => ({ status, usage: usageOf(arm, extra.reported, Date.now() - t0), ...extra, reported: undefined });
  if (!arm.tasks.includes(task)) return done('unavailable', { reason: `arm does not perform ${task}` });
  if (arm.adapter.type === 'builtin-scanner') {
    const layer = arm.adapter.layer ?? 'deep-taint';
    try {
      const res = await scanFn(workspaceDir, { layer, timeoutMs, env: { ...(0,trust_domains/* scrubEnv */.LK)(process.env), ...LAYER_ENV[layer] } });
      return done('completed', { output: { findings: (res.findings || []).map(normalizeFinding) } });
    } catch (e) {
      return done(e.code === 'TIMEOUT' ? 'timeout' : e.code === 'UNAVAILABLE' ? 'unavailable' : 'error', { reason: String(e.message).slice(0, 200) });
    }
  }
  // model arm through the command or ollama adapter
  if (arm.model.local === false) {
    const d = egress({ scanRoot, purpose: 'eval-lab', endpoint: arm.model.endpoint, model: arm.model.id, provider: arm.model.provider, role: `eval-${task}`, dataClass: 'source-code' });
    if (!d.allowed) return done('blocked', { reason: `egress policy: ${d.reason}` });
  }
  if (arm.adapter.type === 'ollama') {
    const o = await runOllamaArm({ arm, task, request, workspaceDir, terms, timeoutMs, signal });
    if (o.status !== 'ok') return done(o.status, { reason: o.reason, reported: o.reported });
    return shapeBody(task, o.body, done);
  }
  const guard = guardPrompt(JSON.stringify(request), terms);
  if (!guard.ok) return done('blocked', { reason: `leakage guard: the request contained a protected term (${guard.leaks[0]?.kind})` });
  const dir = external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'eval-arm-'));
  try {
    const reqFile = external_node_path_.join(dir, 'request.json');
    external_node_fs_.writeFileSync(reqFile, JSON.stringify(request));
    const argv = arm.adapter.argv.map((x) => x.split('{{REQUEST}}').join(reqFile));
    const env = { ...(0,trust_domains/* scrubEnv */.LK)(process.env), AGENTIC_EVAL_REQUEST: reqFile, AGENTIC_EVAL_TASK: task };
    const r = await (0,supervise/* superviseSpawn */.u)(argv[0], argv.slice(1), { cwd: dir, env, timeoutMs: arm.adapter.timeoutMs ?? timeoutMs, signal, maxOutputBytes: MAX_RESPONSE_BYTES });
    if (r.spawnError) return done('error', { reason: `could not start the arm: ${r.spawnError}` });
    if (r.timedOut) return done('timeout', { reason: 'the arm did not answer within its time limit' });
    if (r.cancelled) return done('error', { reason: 'cancelled' });
    if (r.outputCapped) return done('error', { reason: 'the arm answered with more output than allowed' });
    if (r.exitCode !== 0) return done('error', { reason: `the arm exited ${r.exitCode}${r.exitSignal ? ` (${r.exitSignal})` : ''}` });
    let body;
    try { body = JSON.parse(r.stdout); } catch { return done('error', { reason: 'invalid-response: the arm did not print JSON' }); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return done('error', { reason: 'invalid-response: expected a JSON object' });
    return shapeBody(task, body, done);
  } finally { external_node_fs_.rmSync(dir, { recursive: true, force: true }); }
}

;// CONCATENATED MODULE: ./src/posture/evaluation/lab/stats.js
// Small, dependency-free statistics for repeated runs (PRD 6, requirement 6: never publish one lucky run as representative).
// Pure: no fs, no clock. A summary of fewer than MIN_REPRESENTATIVE_RUNS values carries `representative: false` and says why,
// so no consumer can print its mean as a headline without also printing that.

const MIN_REPRESENTATIVE_RUNS = 3;

// two-sided 95% Student-t critical values for 1..30 degrees of freedom; 1.96 beyond
const T95 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042];

const finite = (xs) => xs.filter((x) => typeof x === 'number' && Number.isFinite(x));

function median(xs) {
  const v = finite(xs).sort((a, b) => a - b);
  if (!v.length) return null;
  const m = v.length >> 1;
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
}

/** mean, sample standard deviation, range and a 95% interval of the mean. Unmeasured (null) values are excluded and counted. */
function summarize(values) {
  const all = Array.isArray(values) ? values : [];
  const v = finite(all);
  const unmeasured = all.length - v.length;
  if (!v.length) return { n: 0, unmeasured, mean: null, stdev: null, min: null, max: null, ci95: null, representative: false, note: 'no measured value' };
  const n = v.length;
  const mean = v.reduce((a, b) => a + b, 0) / n;
  const stdev = n > 1 ? Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1)) : null;
  const t = n > 1 ? (T95[n - 2] ?? 1.96) : null;
  const half = stdev == null ? null : t * stdev / Math.sqrt(n);
  const representative = n >= MIN_REPRESENTATIVE_RUNS;
  return {
    n, unmeasured, mean, stdev, min: Math.min(...v), max: Math.max(...v),
    ci95: half == null ? null : { low: mean - half, high: mean + half },
    representative,
    ...(representative ? {} : { note: `${n} run${n === 1 ? '' : 's'}: fewer than ${MIN_REPRESENTATIVE_RUNS}, not representative` }),
  };
}

const ratio = (num, den) => (den > 0 ? num / den : null);
const f1 = (p, r) => (p == null || r == null ? null : p + r === 0 ? 0 : (2 * p * r) / (p + r));
const pct = (x, digits = 1) => (x == null ? 'n/a' : `${(x * 100).toFixed(digits)}%`);

;// CONCATENATED MODULE: ./src/posture/evaluation/lab/score.js
// Scoring for the Eval Lab (PRD 6): detection, falsification, exploit proof, remediation, economics. Pure functions over
// recorded attempts and the dataset's labels; no fs, no clock, no process.
//
// Principles carried over from the rest of the evaluation code:
//   * a figure never appears without the counts behind it;
//   * an attempt that timed out, errored or was blocked is a recorded NO-RESULT. For a known positive it is a miss; for a
//     negative it is neither a true negative nor a false positive (it is `unscored`), so a model cannot look precise by crashing;
//   * a quantity that could not be measured is `null` with a reason, never 0;
//   * detection is scored on LOCATION. A finding of the right class in the right file but outside the labelled span is a
//     file-level hit and a localization miss, and only a localized hit is a true positive.



const DEFAULT_LINE_TOLERANCE = 3;

const resultOf = (a) => a && a.status === 'completed';

/** @param {object[]} entries dataset entries @param {Map<string, object>} attempts entryId -> attempt @param {Map<string,string>} fileMaps `${entryId}\0${path}` -> staged path */
function scoreDetect({ entries, attempts, mapFile = (entryId, f) => f, tolerance = DEFAULT_LINE_TOLERANCE, targetCwes = null }) {
  const cweSet = targetCwes ? new Set(targetCwes.map(normalizeCwe)) : null;
  const perCwe = new Map();
  const slot = (c) => { if (!perCwe.has(c)) perCwe.set(c, { tp: 0, fn: 0, fp: 0, fileHits: 0 }); return perCwe.get(c); };
  const byCategory = {};
  const c = { tp: 0, fn: 0, fp: 0, tn: 0, unscoredNegatives: 0, noResultPositives: 0, fileHits: 0, positives: 0, negatives: 0, attempted: 0, completed: 0 };
  const misses = [];
  for (const e of entries) {
    const a = attempts.get(e.id);
    if (!a) continue;
    c.attempted++;
    if (resultOf(a)) c.completed++;
    const found = resultOf(a) ? (a.output?.findings ?? []) : [];
    if (e.kind === 'vulnerable') {
      c.positives++;
      const cwe = normalizeCwe(e.cwe); const s = slot(cwe);
      if (!resultOf(a)) { c.fn++; s.fn++; c.noResultPositives++; misses.push({ entryId: e.id, reason: `no-result:${a.status}` }); continue; }
      const file = mapFile(e.id, e.expectedSpan.file);
      const sameFile = found.filter((f) => f.file === file && normalizeCwe(f.cwe) === cwe);
      const loc = sameFile.some((f) => Number.isInteger(f.line) && f.line >= e.expectedSpan.startLine - tolerance && f.line <= e.expectedSpan.endLine + tolerance);
      if (sameFile.length) { c.fileHits++; s.fileHits++; }
      if (loc) { c.tp++; s.tp++; } else { c.fn++; s.fn++; misses.push({ entryId: e.id, reason: sameFile.length ? 'wrong-location' : found.some((f) => f.file === file) ? 'wrong-class' : 'not-found' }); }
    } else {
      c.negatives++;
      const cat = e.kind === 'hard-negative' ? e.category : 'fixed';
      byCategory[cat] ??= { entries: 0, falsePositives: 0, unscored: 0 };
      byCategory[cat].entries++;
      if (!resultOf(a)) { c.unscoredNegatives++; byCategory[cat].unscored++; continue; }
      const relevant = found.filter((f) => !cweSet || f.cwe == null || cweSet.has(normalizeCwe(f.cwe)));
      if (relevant.length) {
        c.fp++; byCategory[cat].falsePositives++;
        for (const k of new Set(relevant.map((f) => normalizeCwe(f.cwe) ?? 'unclassified'))) slot(k).fp++;
      } else c.tn++;
    }
  }
  const precision = ratio(c.tp, c.tp + c.fp); const recall = ratio(c.tp, c.tp + c.fn);
  const per = {};
  for (const [k, v] of [...perCwe.entries()].sort()) { const p = ratio(v.tp, v.tp + v.fp); const r = ratio(v.tp, v.tp + v.fn); per[k] = { ...v, precision: p, recall: r, f1: v.tp + v.fn > 0 ? f1(p ?? (v.tp + v.fn > 0 ? 0 : null), r) : null }; }
  const f1s = Object.values(per).filter((p) => p.tp + p.fn > 0 && p.f1 != null).map((p) => p.f1);
  return {
    counts: c, precision, recall, f1: c.positives > 0 && c.tp === 0 ? 0 : f1(precision, recall),
    macroF1: f1s.length ? f1s.reduce((a, b) => a + b, 0) / f1s.length : null, perCwe: per,
    fileLevelRecall: ratio(c.fileHits, c.positives), localizationAccuracy: ratio(c.tp, c.fileHits),
    hardNegativeFalsePositiveRate: Object.fromEntries(Object.entries(byCategory).map(([k, v]) => [k, { ...v, rate: ratio(v.falsePositives, v.entries - v.unscored) }])),
    completion: ratio(c.completed, c.attempted), misses, tolerance,
  };
}

/** truth: Map candidateId -> 'vulnerable' | 'not-vulnerable'. verdicts: Map candidateId -> attempt-level verdict or null (no result). */
function scoreFalsify({ truth, verdicts }) {
  const c = { vulnerable: 0, negative: 0, confirmedVuln: 0, refutedVuln: 0, abstainedVuln: 0, refutedNeg: 0, confirmedNeg: 0, abstainedNeg: 0, noResult: 0 };
  for (const [id, t] of truth) {
    const v = verdicts.get(id) ?? null;
    if (t === 'vulnerable') c.vulnerable++; else c.negative++;
    if (v == null) { c.noResult++; continue; }
    if (t === 'vulnerable') { if (v === 'confirmed') c.confirmedVuln++; else if (v === 'refuted') c.refutedVuln++; else c.abstainedVuln++; }
    else if (v === 'refuted') c.refutedNeg++; else if (v === 'confirmed') c.confirmedNeg++; else c.abstainedNeg++;
  }
  const tpr = ratio(c.confirmedVuln, c.vulnerable); const tnr = ratio(c.refutedNeg, c.negative);
  return { counts: c, truePositiveRate: tpr, trueNegativeRate: tnr, balancedAccuracy: tpr == null || tnr == null ? null : (tpr + tnr) / 2, falseRefutationRate: ratio(c.refutedVuln, c.vulnerable), falseConfirmationRate: ratio(c.confirmedNeg, c.negative) };
}

/** proofs: array of {entryKind, reproducerValid, state, successes, runs, status}. */
function scoreExploit({ proofs }) {
  const vuln = proofs.filter((p) => p.entryKind === 'vulnerable');
  const neg = proofs.filter((p) => p.entryKind !== 'vulnerable');
  const valid = proofs.filter((p) => p.reproducerValid);
  const executed = valid.filter((p) => p.executed);
  // reproduction is a property of the VULNERABLE code: a reproducer that (rightly) does nothing to fixed code is not a failure to reproduce
  const executedVuln = executed.filter((p) => p.entryKind === 'vulnerable');
  const reproduced = executedVuln.filter((p) => (p.successes ?? 0) > 0);
  const confirmedVuln = vuln.filter((p) => p.state === 'EXPLOIT_CONFIRMED').length;
  const confirmedNeg = neg.filter((p) => p.state === 'EXPLOIT_CONFIRMED').length;
  return {
    counts: { attempted: proofs.length, vulnerable: vuln.length, negative: neg.length, reproducerValid: valid.length, executed: executed.length, notExecuted: valid.length - executed.length, reproduced: reproduced.length, confirmedVuln, confirmedNeg },
    pocGenerationSuccess: ratio(valid.length, proofs.length),
    reproductionRate: ratio(reproduced.length, executedVuln.length),
    confirmationRate: ratio(confirmedVuln, vuln.length),
    falseConfirmationRate: ratio(confirmedNeg, neg.length),
    unmeasured: valid.length > executed.length ? `${valid.length - executed.length} reproducer(s) could not be executed here (no execution environment); they are not counted as failures` : null,
  };
}

/** patches: array of {applicable, patchProvided, exploitBlocked: true|false|null, testsPass: true|false|null, completeness, state}. */
function scorePatch({ patches }) {
  const app = patches.filter((p) => p.applicable);
  const provided = app.filter((p) => p.patchProvided);
  const verified = provided.filter((p) => p.exploitBlocked !== null);
  const blocked = verified.filter((p) => p.exploitBlocked === true);
  const testable = provided.filter((p) => p.testsPass !== null);
  const strict = provided.filter((p) => p.exploitBlocked === true && p.testsPass === true);
  const tiers = { FULL: 0, DEGRADED: 0, INCOMPLETE: 0 };
  for (const p of provided) if (tiers[p.completeness] !== undefined) tiers[p.completeness]++;
  return {
    counts: { applicable: app.length, patchProvided: provided.length, verifiable: verified.length, exploitBlocked: blocked.length, testsMeasured: testable.length, testsPassed: testable.filter((p) => p.testsPass).length, validStrict: strict.length },
    patchRate: ratio(provided.length, app.length),
    validPatchRate: ratio(strict.length, app.length),
    exploitBlockedRate: ratio(blocked.length, app.length),
    testPreservationRate: ratio(testable.filter((p) => p.testsPass).length, testable.length),
    regressionRate: ratio(testable.filter((p) => !p.testsPass).length, testable.length),
    completenessTier: tiers,
    unmeasured: testable.length < provided.length ? `${provided.length - testable.length} patch(es) had no runnable test command, so test preservation is unmeasured for them` : null,
  };
}

/** Sum what the attempts cost. Unknown usage is counted, never read as zero. */
function scoreEconomics(attempts) {
  const known = attempts.filter((a) => a.usage?.usd != null);
  const lat = attempts.map((a) => a.usage?.latencyMs).filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  const sum = (k) => attempts.reduce((s, a) => s + (a.usage?.[k] ?? 0), 0);
  return {
    attempts: attempts.length, usdMeasured: known.reduce((s, a) => s + a.usage.usd, 0), attemptsWithUnknownCost: attempts.length - known.length,
    inputTokens: sum('inputTokens'), outputTokens: sum('outputTokens'), tokensUnknownAttempts: attempts.filter((a) => a.usage?.inputTokens == null || a.usage?.outputTokens == null).length,
    latencyMs: { median: lat.length ? (lat.length % 2 ? lat[lat.length >> 1] : (lat[(lat.length >> 1) - 1] + lat[lat.length >> 1]) / 2) : null, p95: lat.length ? lat[Math.min(lat.length - 1, Math.ceil(lat.length * 0.95) - 1)] : null, total: lat.reduce((a, b) => a + b, 0) },
    timeouts: attempts.filter((a) => a.status === 'timeout').length, failures: attempts.filter((a) => ['error', 'blocked', 'unavailable'].includes(a.status)).length,
  };
}

;// CONCATENATED MODULE: ./src/posture/evaluation/lab/run.js
// The Eval Lab run (PRD 6): arms x repeats x tasks x dataset entries, with the leakage controls in front and the scores behind.
//
//   prepare   materialize each entry's workspace, neutralize it, audit it (custody) -> staged dir, or quarantined and excluded
//   execute   one attempt per (arm, repeat, task, entry), bounded concurrency, per-attempt timeout, cancellable
//   score     detection, falsification, exploit proof and remediation, each recomputed from what the lab itself observed
//
// Mechanical evidence decides (the shared engineering contract): an arm's claim that its PoC works or its patch holds is never
// taken. The lab executes the arm's reproducer in the proof fabric and replays the original exploit against the arm's patch.
// An attempt that does not complete is recorded as such and never dropped, so a model cannot improve its score by failing.


















const run_RUN_SCHEMA = 'agentic-security/eval-lab-run';
const RUN_VERSION = 1;
const DEFAULT_REPEATS = 3;
const run_require = (0,external_node_module_.createRequire)(import.meta.url);

const hasTarget = (e) => !!(e.kind === 'vulnerable' ? e.expectedSpan : e.lookalikeSpan);
const targetOf = (e) => (e.kind === 'vulnerable' ? { span: e.expectedSpan, cwe: normalizeCwe(e.cwe) } : { span: e.lookalikeSpan, cwe: normalizeCwe(e.resemblesCwe ?? e.cwe) });

function machineProfile() {
  const cpus = external_node_os_.cpus();
  return { platform: external_node_os_.platform(), arch: external_node_os_.arch(), cpus: cpus.length, cpuModel: cpus[0]?.model ?? null, memoryGb: Math.round(external_node_os_.totalmem() / 2 ** 30), node: process.version };
}
function scannerIdentity() {
  let version = null; let commit = null;
  try { version = run_require('../../../../package.json').version; } catch { /* bundled: unknown */ }
  try {
    const r = (0,external_node_child_process_.spawnSync)('git', ['rev-parse', 'HEAD'], { cwd: external_node_path_.dirname(new URL(import.meta.url).pathname), encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    if (r.status === 0) commit = r.stdout.trim() || null;
  } catch { /* not a checkout */ }
  return { version, commit };
}

async function pool(jobs, limit, run, signal) {
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, jobs.length || 1)) }, async () => {
    while (next < jobs.length && !signal?.aborted) { const j = jobs[next++]; await run(j); }
  });
  await Promise.all(workers);
}

/** Stage every entry's workspace. Returns the prepared map and the leakage-audit record for the run. */
function prepareWorkspaces({ manifest, baseDir, workRoot }) {
  const policy = manifest.dataset.leakagePolicy;
  const terms = protectedTermsFrom({ advisoryText: policy.protectedTerms ?? [] });
  const prepared = new Map(); const quarantined = []; const failed = [];
  let filesAudited = 0;
  for (const e of manifest.entries) {
    const raw = external_node_path_.join(workRoot, `raw-${prepared.size + quarantined.length + failed.length}`);
    const m = materializeEntry(e, { baseDir, destDir: raw });
    if (!m.ok) { failed.push({ entryId: e.id, reason: m.reason }); external_node_fs_.rmSync(raw, { recursive: true, force: true }); continue; }
    const dest = external_node_path_.join(workRoot, `w${prepared.size + quarantined.length + failed.length}`);
    const s = stageNeutralized({ srcDir: raw, destDir: dest, policy, terms });
    external_node_fs_.rmSync(raw, { recursive: true, force: true });
    filesAudited += s.audit.scannedFiles;
    if (!s.ok) { quarantined.push({ entryId: e.id, leaks: s.leaks.slice(0, 5).map((l) => ({ kind: l.kind, file: l.file ?? null })) }); continue; }
    prepared.set(e.id, { dir: dest, fileMap: s.fileMap });
  }
  const status = failed.length || quarantined.length ? (prepared.size ? 'entries-excluded' : 'no-entries-usable') : 'clean';
  return { prepared, terms, audit: { status, mode: 'enforce', stripComments: !!policy.stripComments, renameFiles: !!policy.renameFiles, entries: manifest.entries.length, usable: prepared.size, quarantined, unavailable: failed, filesAudited, termCount: terms.length, scope: 'workspace contents and every request the lab sends an arm; an arm\'s own internal prompts are not visible to the lab' } };
}

async function testsPass({ argv, dir, files, timeoutMs, signal }) {
  if (!argv) return null;
  const copy = external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'eval-test-'));
  try {
    external_node_fs_.cpSync(dir, copy, { recursive: true, dereference: false });
    for (const [rel, content] of Object.entries(files)) {
      const t = external_node_path_.resolve(copy, rel);
      if (!t.startsWith(copy + external_node_path_.sep)) return null;
      external_node_fs_.mkdirSync(external_node_path_.dirname(t), { recursive: true }); external_node_fs_.writeFileSync(t, content);
    }
    const r = await (0,supervise/* superviseSpawn */.u)(argv[0], argv.slice(1), { cwd: copy, env: (0,trust_domains/* scrubEnv */.LK)(process.env), timeoutMs, signal });
    if (r.spawnError || r.timedOut || r.cancelled) return null;
    return r.exitCode === 0;
  } finally { external_node_fs_.rmSync(copy, { recursive: true, force: true }); }
}

/**
 * @param {object} o
 * @param {{manifest: object, baseDir: string, hash: string}} o.dataset
 * @param {object[]} o.arms
 * @param {string[]} [o.tasks]
 * @param {number} [o.repeats]
 */
async function runEval({ dataset, arms, tasks = ['detect'], repeats = DEFAULT_REPEATS, concurrency = 2, timeoutMs = 120_000, budgetUsd = null, scanRoot = process.cwd(), signal, onProgress = () => {}, deps = {} } = {}) {
  const now = deps.now ?? Date.now;
  const startedAt = new Date(now()).toISOString();
  const errors = [];
  if (!Array.isArray(arms) || !arms.length) errors.push('at least one arm is required');
  const ids = new Set();
  for (const a of arms ?? []) { const v = validateArm(a); if (!v.ok) errors.push(`arm ${a?.id ?? '?'}: ${v.errors.join('; ')}`); if (ids.has(a?.id)) errors.push(`arm id ${a.id} is duplicated`); ids.add(a?.id); }
  if (!tasks.length || !tasks.every((t) => TASKS.includes(t))) errors.push(`tasks must be some of ${TASKS.join(', ')}`);
  if (!(Number.isInteger(repeats) && repeats >= 1 && repeats <= 50)) errors.push('repeats must be an integer from 1 to 50');
  if (errors.length) return { ok: false, errors };

  const { manifest, baseDir } = dataset;
  const workRoot = external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'eval-lab-'));
  try {
    const prep = prepareWorkspaces({ manifest, baseDir, workRoot });
    const entriesById = new Map(manifest.entries.map((e) => [e.id, e]));
    const usable = manifest.entries.filter((e) => prep.prepared.has(e.id));
    const attempts = [];
    const spend = { usd: 0 };
    const armPlans = arms.map((a) => ({ arm: a, repeats: a.kind === 'deterministic' ? 1 : repeats, tasks: tasks.filter((t) => a.tasks.includes(t)) }));
    const jobs = [];
    for (const plan of armPlans) for (let r = 0; r < plan.repeats; r++) for (const t of plan.tasks) {
      for (const e of usable) {
        if (t !== 'detect' && !hasTarget(e)) continue;
        if (t === 'patch' && !(e.kind === 'vulnerable' && e.reproducer)) continue;
        jobs.push({ arm: plan.arm, repeat: r, task: t, entry: e });
      }
    }
    let completedJobs = 0;
    const armLimit = new Map();
    const take = async (arm) => { const cap = arm.maxConcurrency ?? (arm.kind === 'model' ? 1 : concurrency); const st = armLimit.get(arm.id) ?? { n: 0, q: [] }; armLimit.set(arm.id, st); if (st.n >= cap) await new Promise((res) => st.q.push(res)); st.n++; };
    const give = (arm) => { const st = armLimit.get(arm.id); st.n--; st.q.shift()?.(); };

    await pool(jobs, concurrency, async (job) => {
      const { arm, task, entry } = job;
      const rec = { armId: arm.id, repeat: job.repeat, task, entryId: entry.id, entryKind: entry.kind };
      if (budgetUsd != null && spend.usd >= budgetUsd) { attempts.push({ ...rec, status: 'skipped-budget', reason: `the ${budgetUsd} USD budget was reached`, usage: { usd: null, latencyMs: 0 } }); return; }
      await take(arm);
      try {
        const ws = prep.prepared.get(entry.id);
        const t = targetOf(entry);
        const mappedFile = t.span ? (ws.fileMap[t.span.file] ?? t.span.file) : null;
        const base = { language: manifest.dataset.language, workspace: ws.dir };
        let request = { schema: 'agentic-security/eval-request', task, ...base };
        if (task === 'falsify') request = { ...request, candidates: [{ id: 'c1', file: mappedFile, line: t.span.startLine, cwe: t.cwe }] };
        if (task === 'exploit' || task === 'patch') request = { ...request, target: { file: mappedFile, line: t.span.startLine, endLine: t.span.endLine, cwe: t.cwe } };
        const res = await (deps.runArmTask ?? runArmTask)({ arm, task, request, workspaceDir: ws.dir, terms: prep.terms, scanRoot, signal, timeoutMs, egress: deps.egress, scanFn: deps.scanFn });
        if (res.usage?.usd != null) spend.usd += res.usage.usd;
        const out = { ...rec, status: res.status, reason: res.reason ?? null, usage: res.usage };
        if (res.status === 'completed') {
          if (task === 'detect') out.output = { findings: res.output.findings.slice(0, 200) };
          if (task === 'falsify') out.output = { verdict: res.output.verdicts?.c1 ?? 'uncertain' };
          if (task === 'exploit') {
            const rp = res.output.reproducer;
            const valid = rp && (0,reproducer/* validateReproducer */.mC)(rp).length === 0;
            out.proof = { reproducerProvided: !!rp, reproducerValid: !!valid, executed: false, state: null, successes: null, runs: null };
            if (valid) {
              const proved = await (deps.proveFn ?? orchestrator/* proveFinding */.kO)({ finding: { id: `eval-${entry.id}`, stableId: `eval-${entry.id}`, parser: 'IR-TAINT' }, reproducer: { ...rp, findingId: `eval-${entry.id}` }, sourceRoot: ws.dir, policy: { timeoutMs: Math.min(timeoutMs, 60_000) }, signal });
              const ran = proved.attempts && proved.attempts.run > 0 && proved.environment?.mode !== 'unavailable';
              out.proof = { ...out.proof, executed: !!ran, state: proved.state, successes: proved.attempts?.successes ?? null, runs: proved.attempts?.run ?? null, degraded: (proved.degradation ?? []).slice(0, 5) };
            }
          }
          if (task === 'patch') {
            const files = res.output.files;
            const rpFile = resolveInside(baseDir, entry.reproducer);
            out.patch = { applicable: true, patchProvided: !!files && Object.keys(files).length > 0, exploitBlocked: null, testsPass: null, completeness: null, state: null, bytes: files ? Object.values(files).reduce((s, v) => s + v.length, 0) : 0, digest: files ? (0,identity/* digestOf */.ol)(files) : null };
            if (out.patch.patchProvided && rpFile) {
              let rp = JSON.parse(external_node_fs_.readFileSync(rpFile, 'utf8'));
              if (rp.sources) rp = { ...rp, sources: Object.fromEntries(Object.entries(rp.sources).map(([d, s]) => [d, ws.fileMap[s] ?? s])) };
              const fp = await (deps.verifyPatchFn ?? fix_proof.verifyFixWithProof)({ finding: { id: `eval-${entry.id}`, stableId: `eval-${entry.id}` }, reproducer: { ...rp, findingId: `eval-${entry.id}` }, files, scanRoot: ws.dir, policy: { timeoutMs: Math.min(timeoutMs, 60_000) }, staticVerification: null, signal });
              const pre = fp.legs?.prePatch?.state === 'EXPLOIT_CONFIRMED';
              const post = fp.legs?.postPatch;
              out.patch.state = fp.state; out.patch.completeness = fp.completeness ?? null;
              out.patch.exploitBlocked = pre && post && post.attempts > 0 && post.completed === post.attempts ? post.exploitSucceeded === 0 : null;
              out.patch.testsPass = await testsPass({ argv: entry.test ?? manifest.dataset.test ?? null, dir: ws.dir, files, timeoutMs: Math.min(timeoutMs, 120_000), signal });
            }
          }
        }
        attempts.push(out);
      } finally { give(arm); completedJobs++; onProgress({ done: completedJobs, total: jobs.length }); }
    }, signal);

    // ---- scoring: per arm, per repeat, per task
    const mapFileFor = (entryId, f) => prep.prepared.get(entryId)?.fileMap[f] ?? f;
    const results = [];
    for (const plan of armPlans) {
      for (let r = 0; r < plan.repeats; r++) {
        const mine = attempts.filter((a) => a.armId === plan.arm.id && a.repeat === r);
        const scores = {};
        for (const t of plan.tasks) {
          const ta = mine.filter((a) => a.task === t);
          if (t === 'detect') scores.detect = scoreDetect({ entries: usable, attempts: new Map(ta.map((a) => [a.entryId, a])), mapFile: mapFileFor, targetCwes: manifest.dataset.cwe });
          if (t === 'falsify') {
            const truth = new Map(); const verdicts = new Map();
            for (const a of ta) { const e = entriesById.get(a.entryId); truth.set(a.entryId, e.kind === 'vulnerable' ? 'vulnerable' : 'not-vulnerable'); verdicts.set(a.entryId, a.status === 'completed' ? a.output?.verdict ?? 'uncertain' : null); }
            scores.falsify = scoreFalsify({ truth, verdicts });
          }
          if (t === 'exploit') scores.exploit = scoreExploit({ proofs: ta.map((a) => ({ entryKind: a.entryKind, reproducerValid: !!a.proof?.reproducerValid, executed: !!a.proof?.executed, state: a.proof?.state ?? null, successes: a.proof?.successes ?? null, runs: a.proof?.runs ?? null })) });
          if (t === 'patch') scores.patch = scorePatch({ patches: ta.map((a) => a.patch ?? { applicable: true, patchProvided: false, exploitBlocked: null, testsPass: null, completeness: null }) });
        }
        results.push({ armId: plan.arm.id, repeat: r, scores, economics: scoreEconomics(mine) });
      }
    }
    const finishedAt = new Date(now()).toISOString();
    const config = { tasks, repeats, concurrency, timeoutMs, budgetUsd, lineTolerance: 3 };
    const armsRecord = arms.map((a) => ({ id: a.id, kind: a.kind, tasks: a.tasks, model: a.model ? { id: a.model.id, provider: a.model.provider, local: a.model.local, version: a.model.version ?? null } : null, adapter: a.adapter.type, repeats: armPlans.find((p) => p.arm.id === a.id).repeats, configDigest: (0,identity/* digestOf */.ol)({ ...a, adapter: { ...a.adapter } }) }));
    const run = {
      schema: run_RUN_SCHEMA, version: RUN_VERSION,
      runId: `elab-${(0,identity/* digestOf */.ol)({ d: dataset.hash, a: armsRecord, config, startedAt }).slice(-14)}`,
      startedAt, finishedAt, scanner: scannerIdentity(), machine: machineProfile(),
      dataset: { id: manifest.dataset.id, version: manifest.dataset.version, hash: dataset.hash, split: manifest.dataset.split, language: manifest.dataset.language, license: manifest.dataset.license, entries: manifest.entries.length },
      config, arms: armsRecord, leakageAudit: prep.audit, attempts, results,
      complete: jobs.length === attempts.length && !attempts.some((a) => a.status === 'skipped-budget') && prep.audit.status === 'clean',
      incompleteReasons: [
        ...(prep.audit.status !== 'clean' ? [`leakage audit: ${prep.audit.status} (${prep.audit.quarantined.length} quarantined, ${prep.audit.unavailable.length} unavailable)`] : []),
        ...(attempts.some((a) => a.status === 'skipped-budget') ? ['budget reached; later attempts were skipped'] : []),
        ...(signal?.aborted ? ['cancelled'] : []),
      ],
      spendUsdMeasured: spend.usd,
    };
    run.digest = (0,identity/* digestOf */.ol)({ ...run, digest: undefined });
    return { ok: true, run };
  } finally { external_node_fs_.rmSync(workRoot, { recursive: true, force: true }); }
}

;// CONCATENATED MODULE: ./src/posture/evaluation/lab/report.js
// Eval Lab reports (PRD 6): quality + proof + remediation + cost + latency + repeatability for each arm, and the metric the
// product is for, intelligence per dollar. Pure: no fs, no clock.
//
// Rules that keep the numbers honest:
//   * a mean over fewer than three runs is printed with "not representative"; one lucky run is never a headline;
//   * every spread (stdev, range, 95% interval) sits beside the mean it qualifies;
//   * a dollar figure divides by MEASURED spend only, and when any attempt's cost is unknown the figure says so instead of
//     treating unknown as free; a deterministic arm has no model cost, so a per-dollar figure for it is `n/a`, not infinite;
//   * a quantity that was not measured is `n/a` (null), never 0;
//   * the leakage audit and any incompleteness appear in the header of every format.


const REPORT_SCHEMA = 'agentic-security/eval-lab-report';
const REPORT_FORMATS = Object.freeze(['json', 'csv', 'md', 'html', 'chart']);

const pick = (rs, task, path) => rs.map((r) => path.reduce((o, k) => (o == null ? null : o[k]), r.scores[task] ?? null));

const METRICS = {
  detect: [['precision', ['precision']], ['recall', ['recall']], ['f1', ['f1']], ['macroF1', ['macroF1']], ['localizationAccuracy', ['localizationAccuracy']], ['completion', ['completion']]],
  falsify: [['balancedAccuracy', ['balancedAccuracy']], ['falseRefutationRate', ['falseRefutationRate']], ['falseConfirmationRate', ['falseConfirmationRate']]],
  exploit: [['pocGenerationSuccess', ['pocGenerationSuccess']], ['reproductionRate', ['reproductionRate']], ['confirmationRate', ['confirmationRate']], ['falseConfirmationRate', ['falseConfirmationRate']]],
  patch: [['validPatchRate', ['validPatchRate']], ['exploitBlockedRate', ['exploitBlockedRate']], ['testPreservationRate', ['testPreservationRate']], ['regressionRate', ['regressionRate']]],
};

/** The one number a task is judged by when ranking or routing. Defined once, here. */
const PRIMARY = Object.freeze({ detect: 'f1', falsify: 'balancedAccuracy', exploit: 'confirmationRate', patch: 'validPatchRate' });

function recallAtBudget(run, armId, repeat, budgetUsd) {
  const mine = run.attempts.filter((a) => a.armId === armId && a.repeat === repeat && a.task === 'detect');
  if (!mine.length) return null;
  if (mine.some((a) => a.usage?.usd == null)) return { value: null, reason: 'some attempts have unknown cost' };
  const positives = mine.filter((a) => a.entryKind === 'vulnerable');
  if (!positives.length) return null;
  const res = run.results.find((r) => r.armId === armId && r.repeat === repeat);
  const hit = new Set((res.scores.detect.misses ?? []).map((m) => m.entryId));
  let spent = 0; let found = 0;
  for (const a of mine) { // attempts are in dataset order within a repeat
    spent += a.usage.usd;
    if (spent > budgetUsd) break;
    if (a.entryKind === 'vulnerable' && a.status === 'completed' && !hit.has(a.entryId)) found++;
  }
  return { value: found / positives.length, spentUsd: spent, budgetUsd };
}

function summarizeRun(run, { budgetUsd = 10 } = {}) {
  const arms = run.arms.map((arm) => {
    const rs = run.results.filter((r) => r.armId === arm.id);
    const tasks = {};
    for (const [task, metrics] of Object.entries(METRICS)) {
      if (!rs.some((r) => r.scores[task])) continue;
      tasks[task] = Object.fromEntries(metrics.map(([name, path]) => [name, summarize(pick(rs, task, path))]));
    }
    const usdPerRepeat = rs.map((r) => (r.economics.attemptsWithUnknownCost > 0 ? null : r.economics.usdMeasured));
    const econ = {
      usd: summarize(usdPerRepeat), latencyMedianMs: summarize(rs.map((r) => r.economics.latencyMs.median)), latencyP95Ms: summarize(rs.map((r) => r.economics.latencyMs.p95)),
      inputTokens: summarize(rs.map((r) => (r.economics.tokensUnknownAttempts > 0 ? null : r.economics.inputTokens))), outputTokens: summarize(rs.map((r) => (r.economics.tokensUnknownAttempts > 0 ? null : r.economics.outputTokens))),
      timeouts: rs.reduce((s, r) => s + r.economics.timeouts, 0), failures: rs.reduce((s, r) => s + r.economics.failures, 0), unknownCostAttempts: rs.reduce((s, r) => s + r.economics.attemptsWithUnknownCost, 0),
    };
    const usdTotal = usdPerRepeat.every((x) => x != null) && usdPerRepeat.length ? usdPerRepeat.reduce((a, b) => a + b, 0) : null;
    const modelCost = arm.kind === 'model';
    const per = (count) => (!modelCost ? { value: null, reason: 'no model cost' } : usdTotal == null ? { value: null, reason: 'cost unknown for some attempts' } : usdTotal === 0 ? { value: null, reason: 'zero measured spend' } : { value: count / usdTotal * 100, perRun: count / rs.length });
    const sum = (task, key) => rs.reduce((s, r) => s + (r.scores[task]?.counts?.[key] ?? 0), 0);
    const ipd = {
      confirmedVulnerabilitiesPer100Usd: tasks.exploit ? per(sum('exploit', 'confirmedVuln')) : { value: null, reason: 'exploit task not run' },
      verifiedFixesPer100Usd: tasks.patch ? per(sum('patch', 'validStrict')) : { value: null, reason: 'patch task not run' },
      truePositivesPer100Usd: tasks.detect ? per(sum('detect', 'tp')) : { value: null, reason: 'detect task not run' },
      recallAtBudget: tasks.detect ? { budgetUsd, perRepeat: rs.map((r) => recallAtBudget(run, arm.id, r.repeat, budgetUsd)), summary: summarize(rs.map((r) => recallAtBudget(run, arm.id, r.repeat, budgetUsd)?.value ?? null)) } : null,
    };
    const dollarsPer = {
      truePositive: tasks.detect && modelCost && usdTotal != null && sum('detect', 'tp') > 0 ? usdTotal / sum('detect', 'tp') : null,
      confirmedExploit: tasks.exploit && modelCost && usdTotal != null && sum('exploit', 'confirmedVuln') > 0 ? usdTotal / sum('exploit', 'confirmedVuln') : null,
      verifiedFix: tasks.patch && modelCost && usdTotal != null && sum('patch', 'validStrict') > 0 ? usdTotal / sum('patch', 'validStrict') : null,
    };
    const primary = Object.fromEntries(Object.entries(tasks).map(([t, m]) => [t, m[PRIMARY[t]]]));
    return { id: arm.id, kind: arm.kind, model: arm.model, runs: rs.length, tasks, economics: econ, intelligencePerDollar: ipd, dollarsPer, primary };
  });
  return {
    schema: REPORT_SCHEMA, version: 1, runId: run.runId, runDigest: run.digest,
    header: { scannerCommit: run.scanner?.commit ?? null, scannerVersion: run.scanner?.version ?? null, datasetId: run.dataset.id, datasetVersion: run.dataset.version, datasetHash: run.dataset.hash, split: run.dataset.split, models: run.arms.filter((a) => a.model).map((a) => `${a.model.provider}/${a.model.id}${a.model.local ? ' (local)' : ''}`), config: run.config, machine: run.machine, startedAt: run.startedAt, finishedAt: run.finishedAt },
    leakageAudit: run.leakageAudit, complete: run.complete, incompleteReasons: run.incompleteReasons, arms,
    notes: arms.some((a) => Object.values(a.primary).some((s) => s && !s.representative)) ? ['At least one figure rests on fewer than three runs and is marked not representative.'] : [],
  };
}

const fmt = (s, kind = 'pct') => {
  if (!s || s.mean == null) return 'n/a';
  const base = kind === 'pct' ? pct(s.mean) : kind === 'usd' ? `$${s.mean.toFixed(4)}` : kind === 'ms' ? `${Math.round(s.mean)}ms` : String(s.mean);
  const spread = s.stdev == null ? '' : ` ±${kind === 'pct' ? pct(s.stdev) : kind === 'usd' ? `$${s.stdev.toFixed(4)}` : kind === 'ms' ? `${Math.round(s.stdev)}ms` : s.stdev.toFixed(2)}`;
  return `${base}${spread}${s.representative ? '' : ' (not representative)'}`;
};
const money = (x) => (x == null ? 'n/a' : x === 0 ? '$0.00' : x < 0.01 ? `$${x.toFixed(4)}` : `$${x.toFixed(2)}`);

function toMarkdown(rep) {
  const h = rep.header;
  const L = [`# Eval Lab report ${rep.runId}`, '',
    `* Scanner: ${h.scannerVersion ?? 'unknown'} @ ${h.scannerCommit ? h.scannerCommit.slice(0, 12) : 'unknown commit'}`,
    `* Dataset: ${h.datasetId} ${h.datasetVersion} (${h.split}), hash ${String(h.datasetHash).slice(-16)}`,
    `* Models: ${h.models.length ? h.models.join(', ') : 'none (deterministic only)'}`,
    `* Config: tasks ${h.config.tasks.join(', ')}; repeats ${h.config.repeats}; timeout ${h.config.timeoutMs}ms; budget ${h.config.budgetUsd ?? 'none'}`,
    `* Machine: ${h.machine.platform}/${h.machine.arch}, ${h.machine.cpus} cpus, ${h.machine.memoryGb} GB, node ${h.machine.node}`,
    `* Run: ${h.startedAt} to ${h.finishedAt}`,
    `* Leakage audit: ${rep.leakageAudit.status} (${rep.leakageAudit.usable}/${rep.leakageAudit.entries} entries usable; comments ${rep.leakageAudit.stripComments ? 'stripped' : 'kept'})`,
    ...(rep.complete ? [] : [`* **INCOMPLETE**: ${rep.incompleteReasons.join('; ')}`]), ''];
  for (const task of Object.keys(METRICS)) {
    const present = rep.arms.filter((a) => a.tasks[task]);
    if (!present.length) continue;
    const cols = METRICS[task].map(([n]) => n);
    L.push(`## ${task}`, '', `| arm | runs | ${cols.join(' | ')} |`, `|---|---|${cols.map(() => '---').join('|')}|`);
    for (const a of present) L.push(`| ${a.id} | ${a.runs} | ${cols.map((c) => fmt(a.tasks[task][c])).join(' | ')} |`);
    L.push('');
  }
  L.push('## Cost, speed and reliability', '', '| arm | spend per run | median latency | p95 latency | timeouts | failures | unknown-cost attempts |', '|---|---|---|---|---|---|---|');
  for (const a of rep.arms) L.push(`| ${a.id} | ${a.kind === 'deterministic' ? 'no model cost' : fmt(a.economics.usd, 'usd')} | ${fmt(a.economics.latencyMedianMs, 'ms')} | ${fmt(a.economics.latencyP95Ms, 'ms')} | ${a.economics.timeouts} | ${a.economics.failures} | ${a.economics.unknownCostAttempts} |`);
  L.push('', '## Intelligence per dollar', '', '| arm | confirmed vulnerabilities / $100 | verified fixes / $100 | true positives / $100 | recall at fixed budget |', '|---|---|---|---|---|');
  for (const a of rep.arms) {
    const i = a.intelligencePerDollar; const cell = (x) => (x?.value == null ? `n/a (${x?.reason ?? 'not measured'})` : x.value.toFixed(1));
    const rb = i.recallAtBudget; L.push(`| ${a.id} | ${cell(i.confirmedVulnerabilitiesPer100Usd)} | ${cell(i.verifiedFixesPer100Usd)} | ${cell(i.truePositivesPer100Usd)} | ${rb ? `${fmt(rb.summary)} at $${rb.budgetUsd}` : 'n/a'} |`);
  }
  L.push('', '## Dollars per outcome', '', '| arm | per true positive | per confirmed exploit | per verified fix |', '|---|---|---|---|');
  for (const a of rep.arms) L.push(`| ${a.id} | ${money(a.dollarsPer.truePositive)} | ${money(a.dollarsPer.confirmedExploit)} | ${money(a.dollarsPer.verifiedFix)} |`);
  if (rep.notes.length) L.push('', ...rep.notes.map((n) => `> ${n}`));
  return `${L.join('\n')}\n`;
}

function toCsv(rep) {
  const q = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const rows = [['arm', 'kind', 'task', 'metric', 'n', 'mean', 'stdev', 'min', 'max', 'ci95_low', 'ci95_high', 'representative']];
  for (const a of rep.arms) {
    for (const [task, ms] of Object.entries(a.tasks)) for (const [name, s] of Object.entries(ms)) rows.push([a.id, a.kind, task, name, s.n, s.mean, s.stdev, s.min, s.max, s.ci95?.low, s.ci95?.high, s.representative]);
    for (const [name, s] of [['usd', a.economics.usd], ['latencyMedianMs', a.economics.latencyMedianMs], ['latencyP95Ms', a.economics.latencyP95Ms]]) rows.push([a.id, a.kind, 'economics', name, s.n, s.mean, s.stdev, s.min, s.max, s.ci95?.low, s.ci95?.high, s.representative]);
  }
  return `${rows.map((r) => r.map(q).join(',')).join('\n')}\n`;
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function toHtml(rep) {
  const md = toMarkdown(rep).split('\n');
  const out = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Eval Lab report</title><style>body{font:14px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;margin:.5rem 0 1.5rem}td,th{border:1px solid #8884;padding:.25rem .6rem;text-align:left}h1,h2{margin-top:1.5rem}blockquote{border-left:3px solid #c80;margin:1rem 0;padding:.1rem 1rem}</style></head><body>'];
  let table = null; let list = false;
  const closeList = () => { if (list) { out.push('</ul>'); list = false; } };
  for (const line of md) {
    if (line.startsWith('|')) {
      closeList();
      const cells = line.split('|').slice(1, -1).map((c) => c.trim());
      if (cells.every((c) => /^-+$/.test(c))) continue;
      if (!table) { table = true; out.push(`<table><thead><tr>${cells.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>`); } else out.push(`<tr>${cells.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`);
      continue;
    }
    if (table) { out.push('</tbody></table>'); table = null; }
    if (line.startsWith('# ')) { closeList(); out.push(`<h1>${esc(line.slice(2))}</h1>`); } else if (line.startsWith('## ')) { closeList(); out.push(`<h2>${esc(line.slice(3))}</h2>`); } else if (line.startsWith('* ')) { if (!list) { out.push('<ul>'); list = true; } out.push(`<li>${esc(line.slice(2).replace(/\*\*/g, ''))}</li>`); } else if (line.startsWith('> ')) { closeList(); out.push(`<blockquote>${esc(line.slice(2))}</blockquote>`); } else if (line.trim()) { closeList(); out.push(`<p>${esc(line)}</p>`); }
  }
  closeList(); if (table) out.push('</tbody></table>');
  out.push('</body></html>');
  return `${out.join('\n')}\n`;
}

/** Chart-ready series: one point per arm and metric, with the error bar the repeats support. */
function toChartData(rep) {
  const series = [];
  for (const a of rep.arms) for (const [task, ms] of Object.entries(a.tasks)) for (const [metric, s] of Object.entries(ms)) {
    if (s.mean == null) continue;
    series.push({ arm: a.id, task, metric, value: s.mean, low: s.ci95?.low ?? null, high: s.ci95?.high ?? null, n: s.n, representative: s.representative });
  }
  const scatter = rep.arms.filter((a) => a.economics.usd.mean != null).flatMap((a) => Object.entries(a.primary).filter(([, s]) => s?.mean != null).map(([task, s]) => ({ arm: a.id, task, costUsd: a.economics.usd.mean, quality: s.mean, representative: s.representative })));
  return { schema: 'agentic-security/eval-lab-chart-data', version: 1, runId: rep.runId, series, qualityVsCost: scatter };
}

function renderReport(rep, format) {
  if (format === 'json') return `${JSON.stringify(rep, null, 2)}\n`;
  if (format === 'csv') return toCsv(rep);
  if (format === 'md') return toMarkdown(rep);
  if (format === 'html') return toHtml(rep);
  if (format === 'chart') return `${JSON.stringify(toChartData(rep), null, 2)}\n`;
  throw new Error(`unknown report format: ${format}`);
}


// EXTERNAL MODULE: ./src/posture/encryption-provider.js
var encryption_provider = __webpack_require__(39984);
// EXTERNAL MODULE: ./src/posture/proof-fabric/store.js
var store = __webpack_require__(62199);
;// CONCATENATED MODULE: ./src/posture/evaluation/lab/store.js
// Persistence for the Eval Lab: `.agentic-security/eval-lab/runs/<runId>.json` and `.agentic-security/eval-lab/scoreboard.json`.
// Same machinery as the proof and detection stores (safe state writes, the encryption policy, retention as evidence, a secret
// scrub before anything touches disk). A run or scoreboard whose content no longer matches its own digest is returned flagged
// and never used for routing: a hand-edited scoreboard must not be able to steer which model gets the work.







const DIR = 'eval-lab';
const MAX_BYTES = 64 * 1024 * 1024;
const safeId = (id) => /^[A-Za-z0-9._-]{1,80}$/.test(id);

function write(root, parts, doc) {
  const safe = (0,store.scrubDeep)(doc);
  safe.digest = (0,identity/* digestOf */.ol)({ ...safe, digest: undefined });
  const text = JSON.stringify(safe);
  if (Buffer.byteLength(text) > MAX_BYTES) return { ok: false, reason: 'record exceeds the size limit' };
  if (!(0,state_dir.ensureStateDir)(root)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = (0,encryption_provider/* maybeEncryptForWrite */.v2)(root, DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = (0,state_dir.statePath)(root, DIR, ...parts);
  if (!(0,state_dir.safeWriteState)(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.digest, encrypted: enc.encrypted };
}
function read(file) {
  try {
    const doc = JSON.parse((0,encryption_provider.maybeDecryptForRead)(external_node_fs_.readFileSync(file, 'utf8')));
    return { doc, tampered: doc.digest !== (0,identity/* digestOf */.ol)({ ...doc, digest: undefined }) };
  } catch { return { doc: null, tampered: true }; }
}

const saveRun = (root, run) => (safeId(run.runId) ? write(root, ['runs', `${run.runId}.json`], run) : { ok: false, reason: 'unsafe run id' });
function loadRun(root, runId) {
  if (!safeId(String(runId))) return { doc: null, tampered: false, missing: true };
  const file = (0,state_dir.statePath)(root, DIR, 'runs', `${runId}.json`);
  if (!external_node_fs_.existsSync(file)) return { doc: null, tampered: false, missing: true };
  return read(file);
}
function listRuns(root) {
  const dir = (0,state_dir.statePath)(root, DIR, 'runs');
  let names = [];
  try { names = external_node_fs_.readdirSync(dir).filter((n) => n.endsWith('.json')); } catch { return []; }
  return names.map((n) => { const { doc, tampered } = read(external_node_path_.join(dir, n)); return { runId: n.replace(/\.json$/, ''), tampered, startedAt: doc?.startedAt ?? null, dataset: doc?.dataset?.id ?? null, arms: doc?.arms?.map((a) => a.id) ?? [] }; }).sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
}
const saveScoreboard = (root, sb) => write(root, ['scoreboard.json'], sb);
function loadScoreboard(root) {
  const file = (0,state_dir.statePath)(root, DIR, 'scoreboard.json');
  if (!external_node_fs_.existsSync(file)) return { doc: null, tampered: false, missing: true };
  return read(file);
}

;// CONCATENATED MODULE: ./src/posture/evaluation/lab/scoreboard.js
// From measured runs to the table the router reads (PRD 6, requirement 7). One entry per (model, task, dataset): the task's
// primary quality with its spread and run count, the MEDIAN cost and latency of a single task call, where the evidence came from,
// and whether the model is local. Only model arms appear; the deterministic baseline is a comparison point, not a routing choice.
// Pure.



const SCOREBOARD_SCHEMA = 'agentic-security/model-scoreboard';
const ROUTER_TASK_OF = Object.freeze({ hunt: 'detect', falsification: 'falsify', 'exploit-generation': 'exploit', 'patch-generation': 'patch' });
const EVAL_TASK_OF_ROUTER = Object.fromEntries(Object.entries(ROUTER_TASK_OF).map(([k, v]) => [v, k]));

const primaryValue = (score, evalTask) => {
  const s = score?.[PRIMARY[evalTask]];
  return typeof s === 'number' && Number.isFinite(s) ? s : null;
};

function scoreboardFromRun(run, armDefs = []) {
  const entries = [];
  for (const arm of run.arms.filter((a) => a.model)) {
    const def = armDefs.find((d) => d.id === arm.id);
    const rs = run.results.filter((r) => r.armId === arm.id);
    for (const evalTask of ['detect', 'falsify', 'exploit', 'patch']) {
      if (!rs.some((r) => r.scores[evalTask])) continue;
      const q = summarize(rs.map((r) => primaryValue(r.scores[evalTask], evalTask)));
      const calls = run.attempts.filter((a) => a.armId === arm.id && a.task === evalTask && a.status !== 'skipped-budget');
      const costs = calls.map((a) => a.usage?.usd);
      const costKnown = costs.length > 0 && costs.every((x) => x != null);
      entries.push({
        model: `${arm.model.provider}/${arm.model.id}`, armId: arm.id, local: arm.model.local, endpoint: def?.model?.endpoint ?? null,
        routerTask: EVAL_TASK_OF_ROUTER[evalTask], evalTask, datasetHash: run.dataset.hash, datasetId: run.dataset.id,
        quality: { mean: q.mean, stdev: q.stdev, ci95: q.ci95, n: q.n, representative: q.representative, metric: PRIMARY[evalTask] },
        medianCostUsd: costKnown ? median(costs) : null, costKnown,
        medianLatencyMs: median(calls.map((a) => a.usage?.latencyMs)),
        failures: calls.filter((a) => a.status !== 'completed').length, calls: calls.length,
        evidence: { runId: run.runId, runDigest: run.digest, measuredAt: run.finishedAt },
      });
    }
  }
  return entries;
}

/** Merge a run's entries into a scoreboard document; a newer entry for the same (model, task, dataset) replaces the older. */
function mergeScoreboard(existing, entries) {
  const key = (e) => `${e.model}|${e.routerTask}|${e.datasetHash}`;
  const map = new Map((existing?.entries ?? []).map((e) => [key(e), e]));
  for (const e of entries) map.set(key(e), e);
  return { schema: SCOREBOARD_SCHEMA, version: 1, updatedAt: new Date().toISOString(), entries: [...map.values()].sort((a, b) => key(a).localeCompare(key(b))) };
}

;// CONCATENATED MODULE: ./src/posture/routing/policy-router.js
// Per-task model routing from MEASURED results (PRD 6, requirements 7 and 8).
//
// The router reads the scoreboard the Eval Lab writes and picks a model for each task independently, under one of four policies:
//
//   best-quality                          the highest measured quality
//   balanced                              the cheapest model whose quality is within `tolerance` of the best
//   lowest-cost-above-quality-threshold   the cheapest model whose quality meets `qualityThreshold`
//   local-only                            the best-quality LOCAL model; a non-local model is never a candidate
//
// What it will not do:
//   * guess. A model with fewer than `minRuns` measured runs, or with unknown cost under a cost-based policy, is excluded with
//     the reason stated, and when nothing is eligible the answer is `blocked`, not a default;
//   * invent a benchmark. `threat-model` has no evaluation task, so routing it is blocked as `no-benchmark-for-task`;
//   * route around the egress policy. A non-local candidate is checked against it, and a denial excludes the model;
//   * fall back from a local model to a cloud one. `local-only` has no non-local path at all.
// This is the policy layer over measurements. The calibrated, per-stratum router in `decide.js` keeps its own job (quality LOWER
// bounds on held-out outcomes); the two do not call each other.


const ROUTER_TASKS = Object.freeze({ 'threat-model': null, hunt: 'detect', falsification: 'falsify', 'exploit-generation': 'exploit', 'patch-generation': 'patch' });
const ROUTER_POLICIES = Object.freeze(['best-quality', 'balanced', 'lowest-cost-above-quality-threshold', 'local-only']);
const DEFAULT_TOLERANCE = 0.02;
const DEFAULT_MIN_RUNS = 3;
const QUALITY_LABEL = { hunt: 'Detection quality', falsification: 'Falsification quality', 'exploit-generation': 'Exploit quality', 'patch-generation': 'Patch quality' };

const cmpCost = (a, b) => (a.medianCostUsd == null ? 1 : b.medianCostUsd == null ? -1 : a.medianCostUsd - b.medianCostUsd);

function routeTask({ task, policy = 'balanced', scoreboard, tolerance = DEFAULT_TOLERANCE, qualityThreshold = null, minRuns = DEFAULT_MIN_RUNS, datasetHash = null, scanRoot, egress = egress_policy/* evaluateEgress */.nn } = {}) {
  const base = { schema: 'agentic-security/model-route', version: 1, task, policy };
  if (!(task in ROUTER_TASKS)) return { ...base, ok: false, blocked: 'unknown-task', reason: `unknown task "${task}"; choose one of ${Object.keys(ROUTER_TASKS).join(', ')}` };
  if (!ROUTER_POLICIES.includes(policy)) return { ...base, ok: false, blocked: 'invalid-policy', reason: `unknown policy "${policy}"; choose one of ${ROUTER_POLICIES.join(', ')}` };
  if (ROUTER_TASKS[task] === null) return { ...base, ok: false, blocked: 'no-benchmark-for-task', reason: `there is no evaluation task for ${task}, so no model has measured quality for it and none is recommended` };
  if (policy === 'lowest-cost-above-quality-threshold' && !(typeof qualityThreshold === 'number' && qualityThreshold > 0 && qualityThreshold <= 1)) return { ...base, ok: false, blocked: 'invalid-policy', reason: 'lowest-cost-above-quality-threshold needs a quality threshold between 0 and 1' };
  if (!(typeof tolerance === 'number' && tolerance >= 0 && tolerance < 1)) return { ...base, ok: false, blocked: 'invalid-policy', reason: 'tolerance must be between 0 and 1' };

  const all = (scoreboard?.entries ?? []).filter((e) => e.routerTask === task);
  if (!all.length) return { ...base, ok: false, blocked: 'no-evidence', reason: `no model has been benchmarked for ${task}; run: agentic-security models benchmark` };

  // entries measured on different datasets are not comparable: use one dataset, the one with the most candidates unless named
  const byDs = new Map();
  for (const e of all) { const g = byDs.get(e.datasetHash) ?? []; g.push(e); byDs.set(e.datasetHash, g); }
  let ds = datasetHash;
  if (ds && !byDs.has(ds)) return { ...base, ok: false, blocked: 'no-evidence', reason: `no benchmark for ${task} on dataset ${ds}` };
  if (!ds) ds = [...byDs.entries()].sort((a, b) => b[1].length - a[1].length || String(b[1][0].evidence?.measuredAt).localeCompare(String(a[1][0].evidence?.measuredAt)))[0][0];
  const pool = byDs.get(ds);

  const excluded = []; const eligible = [];
  for (const e of pool) {
    const why = [];
    if (e.quality.mean == null) why.push('no measured quality');
    if ((e.quality.n ?? 0) < minRuns) why.push(`only ${e.quality.n ?? 0} measured run(s); ${minRuns} are required`);
    if (policy === 'local-only' && e.local !== true) why.push('not a local model');
    if (e.local !== true && policy !== 'local-only') {
      if (!e.endpoint) why.push('no declared endpoint, so the egress policy cannot judge it');
      else { const d = egress({ scanRoot, purpose: 'model-routing', endpoint: e.endpoint, model: e.model.split('/').slice(1).join('/'), provider: e.model.split('/')[0], role: `route-${task}`, dataClass: 'source-code' }); if (!d.allowed) why.push(`egress policy: ${d.reason}`); }
    }
    if (['balanced', 'lowest-cost-above-quality-threshold'].includes(policy) && e.medianCostUsd == null && !e.local) why.push('cost is unknown, and this policy ranks by cost');
    if (policy === 'lowest-cost-above-quality-threshold' && e.quality.mean != null && e.quality.mean < qualityThreshold) why.push(`quality ${(e.quality.mean * 100).toFixed(0)}% is below the ${(qualityThreshold * 100).toFixed(0)}% threshold`);
    (why.length ? excluded.push({ model: e.model, reasons: why }) : eligible.push(e));
  }
  const evidence = { datasetHash: ds, datasetId: pool[0].datasetId, candidates: pool.length, runs: [...new Set(pool.map((e) => e.evidence?.runId))].filter(Boolean) };
  if (!eligible.length) return { ...base, ok: false, blocked: 'no-eligible-model', reason: 'no benchmarked model satisfies the policy and the evidence requirements', excluded, evidence };

  const byQuality = [...eligible].sort((a, b) => b.quality.mean - a.quality.mean || cmpCost(a, b) || a.model.localeCompare(b.model));
  const best = byQuality[0];
  let chosen = best; let rule;
  if (policy === 'best-quality' || policy === 'local-only') rule = policy === 'local-only' ? 'it has the highest measured quality among local models' : 'it has the highest measured quality';
  else if (policy === 'balanced') {
    const within = eligible.filter((e) => e.quality.mean >= best.quality.mean - tolerance);
    chosen = [...within].sort((a, b) => cmpCost(a, b) || b.quality.mean - a.quality.mean || a.model.localeCompare(b.model))[0];
    rule = chosen === best ? `no cheaper model is within ${(tolerance * 100).toFixed(0)} points of its quality` : `quality is within ${(tolerance * 100).toFixed(0)} points of the best and it is the cheapest such model`;
  } else {
    chosen = [...eligible].sort((a, b) => cmpCost(a, b) || b.quality.mean - a.quality.mean || a.model.localeCompare(b.model))[0];
    rule = `it is the cheapest model with quality at or above ${(qualityThreshold * 100).toFixed(0)}%`;
  }
  const view = (e) => ({ model: e.model, local: e.local, quality: e.quality.mean, qualityCi95: e.quality.ci95, runs: e.quality.n, medianCostUsd: e.medianCostUsd, medianLatencyMs: e.medianLatencyMs });
  const costReduction = chosen !== best && best.medianCostUsd != null && chosen.medianCostUsd != null && best.medianCostUsd > 0 ? 1 - chosen.medianCostUsd / best.medianCostUsd : null;
  return {
    ...base, ok: true, recommended: view(chosen), alternatives: byQuality.filter((e) => e !== chosen).map(view), excluded, evidence,
    comparison: chosen === best ? null : { against: best.model, qualityDifference: best.quality.mean - chosen.quality.mean, costReduction },
    rationale: rule, label: QUALITY_LABEL[task], parameters: { tolerance, qualityThreshold, minRuns },
  };
}

/** The text `models route explain <task>` prints. */
function explainRoute(r) {
  if (!r.ok) return [`Task: ${r.task}`, `Policy: ${r.policy}`, `No recommendation (${r.blocked}): ${r.reason}`, ...(r.excluded?.length ? ['', 'Excluded:', ...r.excluded.map((e) => `  ${e.model}: ${e.reasons.join('; ')}`)] : [])].join('\n');
  const pc = (x) => (x == null ? 'n/a' : `${(x * 100).toFixed(0)}%`);
  const usd = (x) => (x == null ? 'unknown' : x === 0 ? '$0.00' : x < 0.01 ? `$${x.toFixed(4)}` : `$${x.toFixed(2)}`);
  const sec = (x) => (x == null ? 'unknown' : `${(x / 1000).toFixed(1)}s`);
  const rec = r.recommended;
  const L = [`Recommended: ${rec.model}${rec.local ? ' (local)' : ''}`, `${r.label}: ${pc(rec.quality)}`, `Median cost: ${usd(rec.medianCostUsd)}`, `Median latency: ${sec(rec.medianLatencyMs)}`, `Measured runs: ${rec.runs}`];
  for (const a of r.alternatives) L.push('', `${a.model}${a.local ? ' (local)' : ''}:`, `Quality: ${pc(a.quality)}`, `Cost: ${usd(a.medianCostUsd)}`);
  L.push('');
  if (!r.comparison) L.push(`${rec.model} selected because ${r.rationale}.`);
  else {
    const qd = (r.comparison.qualityDifference * 100).toFixed(0);
    L.push(`${rec.model} selected because ${r.rationale}${r.comparison.costReduction != null ? `: quality difference is ${qd} point${qd === '1' ? '' : 's'} and cost is ${(r.comparison.costReduction * 100).toFixed(0)}% lower than ${r.comparison.against}` : ''}.`);
  }
  if (r.excluded.length) L.push('', 'Not considered:', ...r.excluded.map((e) => `  ${e.model}: ${e.reasons.join('; ')}`));
  L.push('', `Evidence: dataset ${r.evidence.datasetId} (${String(r.evidence.datasetHash).slice(-12)}), ${r.evidence.runs.length} run record(s).`);
  return L.join('\n');
}

;// CONCATENATED MODULE: ./src/posture/evaluation/lab/cli.js
// CLI for the Eval Lab and the model router: `eval run|compare|report|list`, `models benchmark`, `models route explain`.
// Non-interactive (nothing reads stdin), bounded (every attempt has a timeout, the run is cancellable with SIGINT), and local:
// the lab itself makes no network call. A model arm that is not local needs `--allow-external`, and even then the egress policy
// is consulted for it before it runs.
//
// Exit codes: 0 done, 1 done but incomplete or no recommendation, 4 usage or precondition.











const MAX_ARMS_BYTES = 1024 * 1024;

function readArms(file) {
  let doc;
  try {
    const st = external_node_fs_.statSync(file);
    if (!st.isFile() || st.size > MAX_ARMS_BYTES) return { ok: false, errors: [`${file} is not a regular file under ${MAX_ARMS_BYTES} bytes`] };
    const text = external_node_fs_.readFileSync(file, 'utf8');
    doc = /\.json$/i.test(file) ? JSON.parse(text) : (0,yaml/* load */.Hh)(text);
  } catch (e) { return { ok: false, errors: [`cannot read ${file}: ${String(e.message).split('\n')[0]}`] }; }
  const arms = Array.isArray(doc) ? doc : doc?.arms;
  if (!Array.isArray(arms) || !arms.length) return { ok: false, errors: ['the arms file needs a list of arms (or { "arms": [...] })'] };
  const errors = arms.flatMap((a, i) => { const v = validateArm(a); return v.ok ? [] : v.errors.map((e) => `arms[${i}]: ${e}`); });
  return errors.length ? { ok: false, errors } : { ok: true, arms };
}

const usageRun = () => { console.error('usage: eval run --dataset <file> --arms <file> [--tasks detect,falsify,exploit,patch] [--repeats N] [--concurrency N] [--timeout S] [--budget USD] [--allow-external]\n       eval report <run-id> [--format md|json|csv|html|chart] [--out <file>]\n       eval compare <run-id> [<other-run-id>]\n       eval list'); return 4; };

async function doRun(args, root, { updateScoreboard }) {
  const f = args.flags;
  if (!f.dataset || !f.arms) return usageRun();
  const ds = loadDatasetFile(external_node_path_.resolve(String(f.dataset)));
  if (!ds.ok) { console.error(`Invalid dataset:\n  ${ds.errors.join('\n  ')}`); return 4; }
  const ar = readArms(external_node_path_.resolve(String(f.arms)));
  if (!ar.ok) { console.error(`Invalid arms:\n  ${ar.errors.join('\n  ')}`); return 4; }
  const external = ar.arms.filter((a) => a.kind === 'model' && a.model.local === false);
  if (external.length && !f['allow-external']) { console.error(`These arms send source code to a non-local model: ${external.map((a) => a.id).join(', ')}. Pass --allow-external to run them; the egress policy is still consulted for each.`); return 4; }
  const tasks = f.tasks ? String(f.tasks).split(',').map((s) => s.trim()).filter(Boolean) : ['detect'];
  if (!tasks.every((t) => TASKS.includes(t))) { console.error(`--tasks must be some of ${TASKS.join(', ')}`); return 4; }
  const num = (v, name, lo, hi) => { if (v === undefined) return undefined; const n = Number(v); if (!Number.isFinite(n) || n < lo || n > hi) { console.error(`--${name} must be a number from ${lo} to ${hi}`); return null; } return n; };
  const repeats = num(f.repeats, 'repeats', 1, 50); const concurrency = num(f.concurrency, 'concurrency', 1, 32); const timeoutS = num(f.timeout, 'timeout', 1, 3600); const budget = num(f.budget, 'budget', 0, 1e6);
  if (repeats === null || concurrency === null || timeoutS === null || budget === null) return 4;
  const ac = new AbortController(); const onSig = () => ac.abort(); process.once('SIGINT', onSig);
  let res;
  try {
    res = await runEval({ dataset: ds, arms: ar.arms, tasks, repeats: repeats ?? DEFAULT_REPEATS, concurrency: concurrency ?? 2, timeoutMs: (timeoutS ?? 120) * 1000, budgetUsd: budget ?? null, scanRoot: root, signal: ac.signal });
  } finally { process.off('SIGINT', onSig); }
  if (!res.ok) { console.error(`Cannot run:\n  ${res.errors.join('\n  ')}`); return 4; }
  const run = res.run;
  const saved = saveRun(root, run);
  let sbNote = '';
  if (updateScoreboard) {
    const cur = loadScoreboard(root);
    if (cur.tampered) sbNote = 'The existing scoreboard failed its integrity check and was not updated; remove it to start again.';
    else { const w = saveScoreboard(root, mergeScoreboard(cur.doc, scoreboardFromRun(run, ar.arms))); sbNote = w.ok ? 'Scoreboard updated.' : `Scoreboard not stored: ${w.reason}`; }
  }
  const rep = summarizeRun(run);
  if (f.json) console.log(JSON.stringify({ runId: run.runId, stored: saved.ok ? saved.file : null, complete: run.complete, report: rep }, null, 2));
  else { console.log(renderReport(rep, 'md')); console.log(saved.ok ? `Run stored: ${run.runId}` : `(run not stored: ${saved.reason})`); if (sbNote) console.log(sbNote); }
  return run.complete ? 0 : 1;
}

async function cmdEval(args, root) {
  const sub = args._[1];
  if (sub === 'run') return doRun(args, root, { updateScoreboard: false });
  if (sub === 'list') {
    const runs = listRuns(root);
    if (args.flags.json) { console.log(JSON.stringify(runs, null, 2)); return 0; }
    if (!runs.length) console.log('No eval runs yet. Start one with: eval run --dataset <file> --arms <file>');
    for (const r of runs) console.log(`${r.runId}  ${r.startedAt}  ${r.dataset}  arms: ${r.arms.join(', ')}${r.tampered ? '  (FAILED INTEGRITY CHECK)' : ''}`);
    return 0;
  }
  if (sub === 'report' || sub === 'compare') {
    const id = String(args._[2] ?? '');
    if (!id) return usageRun();
    const a = loadRun(root, id);
    if (a.missing) { console.error(`No run ${id}. List runs with: eval list`); return 4; }
    if (a.tampered) { console.error(`Run ${id} failed its integrity check and is not used.`); return 1; }
    if (sub === 'report') {
      const format = String(args.flags.format ?? 'md');
      if (!REPORT_FORMATS.includes(format)) { console.error(`--format must be one of ${REPORT_FORMATS.join(', ')}`); return 4; }
      const text = renderReport(summarizeRun(a.doc), format);
      if (args.flags.out) { external_node_fs_.writeFileSync(external_node_path_.resolve(String(args.flags.out)), text); console.log(`Wrote ${format} report to ${external_node_path_.resolve(String(args.flags.out))}`); } else process.stdout.write(text);
      return 0;
    }
    const other = args._[3] ? loadRun(root, String(args._[3])) : null;
    if (other && (other.missing || other.tampered)) { console.error(`Run ${args._[3]} is ${other.missing ? 'missing' : 'not intact'}.`); return other.missing ? 4 : 1; }
    return compare(a.doc, other?.doc ?? null, !!args.flags['allow-different-datasets'], !!args.flags.json);
  }
  return usageRun();
}

function compare(a, b, allowDiff, json) {
  const ra = summarizeRun(a);
  if (!b) {
    const rows = ra.arms.map((arm) => ({ arm: arm.id, kind: arm.kind, runs: arm.runs, ...Object.fromEntries(Object.entries(arm.primary).map(([t, s]) => [`${t}:${PRIMARY[t]}`, s?.mean ?? null])), usdPerRun: arm.economics.usd.mean, medianLatencyMs: arm.economics.latencyMedianMs.mean, representative: Object.values(arm.primary).every((s) => s?.representative) }));
    if (json) console.log(JSON.stringify({ runId: a.runId, rows }, null, 2)); else console.log(renderReport(ra, 'md'));
    return 0;
  }
  if (a.dataset.hash !== b.dataset.hash && !allowDiff) { console.error(`These runs used different datasets (${a.dataset.id} ${String(a.dataset.hash).slice(-8)} vs ${b.dataset.id} ${String(b.dataset.hash).slice(-8)}); a comparison would not mean anything. Pass --allow-different-datasets to see the numbers anyway.`); return 1; }
  const rb = summarizeRun(b);
  const out = [];
  for (const arm of ra.arms) {
    const other = rb.arms.find((x) => x.id === arm.id);
    if (!other) continue;
    for (const [t, s] of Object.entries(arm.primary)) { const o = other.primary[t]; if (s?.mean == null || o?.mean == null) continue; out.push({ arm: arm.id, task: t, metric: PRIMARY[t], a: s.mean, b: o.mean, delta: o.mean - s.mean, representative: !!(s.representative && o.representative) }); }
  }
  if (json) console.log(JSON.stringify({ a: a.runId, b: b.runId, sameDataset: a.dataset.hash === b.dataset.hash, rows: out }, null, 2));
  else { console.log(`${a.runId} -> ${b.runId}${a.dataset.hash === b.dataset.hash ? '' : '  (DIFFERENT DATASETS)'}`); for (const r of out) console.log(`  ${r.arm} ${r.task}/${r.metric}: ${(r.a * 100).toFixed(1)}% -> ${(r.b * 100).toFixed(1)}% (${r.delta >= 0 ? '+' : ''}${(r.delta * 100).toFixed(1)} points)${r.representative ? '' : '  not representative'}`); if (!out.length) console.log('  no arm appears in both runs'); }
  return 0;
}

async function cmdModelsLab(args, root) {
  const sub = args._[1];
  if (sub === 'benchmark') return doRun(args, root, { updateScoreboard: true });
  if (sub === 'route') {
    if (args._[2] !== 'explain') { console.error(`usage: models route explain <${Object.keys(ROUTER_TASKS).join('|')}> [--policy ${ROUTER_POLICIES.join('|')}] [--threshold 0.8] [--tolerance 0.02] [--dataset-hash <hash>]`); return 4; }
    const task = String(args._[3] ?? '');
    if (!task) { console.error(`models route explain needs a task: ${Object.keys(ROUTER_TASKS).join(', ')}`); return 4; }
    const sb = loadScoreboard(root);
    if (sb.tampered) { console.error('The scoreboard failed its integrity check and is not used for routing. Remove .agentic-security/eval-lab/scoreboard.json and re-run: models benchmark'); return 1; }
    const n = (v) => (v === undefined ? undefined : Number(v));
    const r = routeTask({ task, policy: args.flags.policy ? String(args.flags.policy) : 'balanced', scoreboard: sb.doc, qualityThreshold: n(args.flags.threshold) ?? null, ...(args.flags.tolerance !== undefined ? { tolerance: n(args.flags.tolerance) } : {}), ...(args.flags['min-runs'] !== undefined ? { minRuns: n(args.flags['min-runs']) } : {}), datasetHash: args.flags['dataset-hash'] ? String(args.flags['dataset-hash']) : null, scanRoot: root });
    if (args.flags.json) console.log(JSON.stringify(r, null, 2)); else console.log(explainRoute(r));
    return r.ok ? 0 : (r.blocked === 'unknown-task' || r.blocked === 'invalid-policy' ? 4 : 1);
  }
  return null;
}


/***/ }),

/***/ 818:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   formatFixProof: () => (/* binding */ formatFixProof),
/* harmony export */   verifyFixWithProof: () => (/* binding */ verifyFixWithProof)
/* harmony export */ });
/* harmony import */ var _states_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(12090);
/* harmony import */ var _orchestrator_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3740);
/* harmony import */ var _runner_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(23081);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(37055);
// Verified remediation, extended with exploit replay. This EXTENDS the fix-verify vocabulary (`verifiedFull`,
// `degradedLegs`); it does not define a competing meaning of "verified".
//
//   1. pre-patch: the original exploit must be EXPLOIT_CONFIRMED (3/3 + independent replay) on the unpatched code;
//   2. the candidate patch is overlaid on the imported sources and the SAME exploit is replayed;
//   3. the patched replay must COMPLETE in every attempt and the oracle must not fire in any: BLOCKED.
//      An attempt that did not complete (timeout, build failure, no environment) is inconclusive, never "blocked";
//   4. static legs (re-scan, lint, tests, honesty) come from `verifyFix`, passed in so they are not re-implemented;
//   5. FIX_VERIFIED only when 1-4 hold and the static verification had no degraded leg.





async function verifyFixWithProof({ finding, reproducer, files, scanRoot, revision = null, policy = {}, staticVerification = null, siblings = null, siblingSearchTruncated = [], signal, deps = {} } = {}) {
  const t0 = Date.now();
  const attemptFn = deps.attemptFn ?? _runner_js__WEBPACK_IMPORTED_MODULE_2__/* .runAttempt */ .Tm;
  const patchHash = (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .sha256 */ .sc)((0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .canonicalize */ .dw)(files || {}));
  const legs = { prePatch: null, postPatch: null, regression: staticVerification ? { ok: !!staticVerification.ok, verifiedFull: !!staticVerification.verifiedFull } : { status: 'not-run' }, rescan: staticVerification?.rescan ?? { status: 'not-run' } };
  const out = (extra) => ({ schema: 'agentic-security/fix-proof', version: 1, findingId: finding?.stableId ?? finding?.id ?? null, patchHash, reproducerDigest: (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .reproducerDigest */ .we)(reproducer), legs, durationMs: Date.now() - t0, ...extra });

  const pre = await (0,_orchestrator_js__WEBPACK_IMPORTED_MODULE_1__/* .proveFinding */ .kO)({ finding, revision, reproducer, policy, signal, deps, sourceRoot: scanRoot });
  legs.prePatch = { state: pre.state, outcome: pre.outcome, completeness: pre.completeness };
  if (pre.state !== 'EXPLOIT_CONFIRMED') {
    return out({ state: pre.state, verified: false, completeness: 'INCOMPLETE', incompleteStep: 'pre-patch-exploit', reason: `the original exploit was not confirmed before the patch (${pre.outcome}); a fix cannot be proven against an exploit that does not reproduce` });
  }

  const attempts = Math.max(1, Math.min(10, policy.attempts ?? 3));
  const results = [];
  for (let i = 0; i < attempts; i++) {
    if (signal?.aborted) break;
    results.push(await attemptFn(structuredClone(reproducer), { limits: { timeoutMs: policy.timeoutMs }, signal, sourceRoot: scanRoot, overlay: files, requireContainer: policy.requireContainer, force: policy.force }));
  }
  const completed = results.filter((r) => r.status === 'completed' && !r.oracle?.inconclusive);
  const fired = completed.filter((r) => r.oracle?.fired).length;
  legs.postPatch = { attempts: results.length, completed: completed.length, exploitSucceeded: fired, statuses: results.map((r) => r.status) };

  if (fired > 0) return out({ state: 'EXPLOIT_CONFIRMED', verified: false, completeness: 'FULL', incompleteStep: 'post-patch-exploit', reason: 'the exploit still succeeds against the patched code' });
  if (completed.length < results.length || results.length === 0) {
    return out({ state: 'EXPLOIT_CONFIRMED', verified: false, completeness: 'INCOMPLETE', incompleteStep: 'post-patch-replay', reason: 'the patched replay did not complete in every attempt, so the patch is not shown to block the exploit' });
  }
  let state = (0,_states_js__WEBPACK_IMPORTED_MODULE_0__/* .advance */ .np)('EXPLOIT_CONFIRMED', 'FIX_REPLAY_BLOCKED').state;

  const degraded = [];
  if (!staticVerification) degraded.push('static-verification-not-run');
  else {
    if (!staticVerification.ok) return out({ state, verified: false, completeness: 'FULL', incompleteStep: 'static-verification', reason: `exploit blocked, but static verification failed: ${staticVerification.rescan?.reason || 'a leg failed'}` });
    for (const d of staticVerification.degradedLegs || []) degraded.push(d);
  }
  const lowAssurance = pre.environment?.assurance === 'lower';
  if (lowAssurance) degraded.push('lower-assurance-local-confinement');
  const siblingCount = Array.isArray(siblings) ? siblings.length : null;
  if (siblingCount === null) degraded.push('sibling-search-not-run');
  else if (siblingCount > 0) degraded.push(`sibling-exposures:${siblingCount}`);
  if (siblingCount !== null && siblingSearchTruncated?.length) degraded.push('sibling-search-incomplete');

  const full = degraded.length === 0;
  // Same split as fix-verify: `ok` (nothing that ran failed) earns FIX_VERIFIED; `completeness` says whether anything was skipped.
  if (staticVerification && staticVerification.ok) state = (0,_states_js__WEBPACK_IMPORTED_MODULE_0__/* .advance */ .np)(state, 'FIX_VERIFIED').state;
  return out({ state, verified: state === 'FIX_VERIFIED', completeness: full ? 'FULL' : 'DEGRADED', degradedLegs: degraded, siblings: siblings ?? null });
}

function formatFixProof(r) {
  const L = r.legs || {};
  return [
    `Pre-patch exploit: ${L.prePatch?.state === 'EXPLOIT_CONFIRMED' ? 'PASS' : 'NOT CONFIRMED'}`,
    `Post-patch exploit: ${!L.postPatch ? 'NOT RUN' : L.postPatch.exploitSucceeded > 0 ? 'STILL SUCCEEDS' : L.postPatch.completed === L.postPatch.attempts ? 'BLOCKED' : 'INCONCLUSIVE'}`,
    `Regression tests: ${L.regression?.status === 'not-run' ? 'not run' : L.regression?.verifiedFull ? 'PASS' : L.regression?.ok ? 'PASS (degraded)' : 'FAIL'}`,
    `Security rescan: ${L.rescan?.ok === true ? 'PASS' : L.rescan?.status === 'not-run' ? 'not run' : 'FAIL'}`,
    `Completeness: ${r.completeness}${r.degradedLegs?.length ? ` (${r.degradedLegs.join('; ')})` : ''}`,
    '',
    `Evidence: ${r.state}${r.verified ? '' : ` (not verified: ${r.reason || r.incompleteStep || 'degraded'})`}`,
  ].join('\n');
}


/***/ }),

/***/ 3740:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   kO: () => (/* binding */ proveFinding)
/* harmony export */ });
/* unused harmony exports independentVerify, applySeverityPolicy, _newRunId */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var _states_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(12090);
/* harmony import */ var _runner_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(23081);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(37055);
/* harmony import */ var _proof_tier_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(40216);
// Proof orchestration: finding + revision + reproducer + policy -> structured evidence.
//
// Rules that make this safe to trust:
//  * The model may propose a reproducer and select an oracle. The oracle (oracles.js) judges. Never a model.
//  * An attempt that did not complete (timeout, build failure, blocked, unsupported, error) is NOT a negative and NOT a
//    positive: it is degraded evidence, it never advances the state, and it makes the result INCOMPLETE.
//  * EXPLOIT_CONFIRMED needs `required` successes in `attempts` completed attempts AND a pass from an independent
//    verifier that receives only {revision, reproducer, findingId, oracle} in a fresh environment.
//  * "Not reproduced" is reported as such; it is never reported as safe.






const PROOF_POLICY_DEFAULTS = Object.freeze({ attempts: 3, required: 3, independentReplay: true, timeoutMs: 20_000, cpus: 1, memoryMb: 512, network: 'none', requireContainer: false });
const RESULT_SCHEMA = 'agentic-security/proof-result';

function normalizePolicy(p = {}) {
  const x = { ...PROOF_POLICY_DEFAULTS, ...p };
  x.attempts = Math.max(1, Math.min(10, Math.trunc(Number(x.attempts)) || PROOF_POLICY_DEFAULTS.attempts));
  x.required = Math.max(1, Math.min(x.attempts, Math.trunc(Number(x.required)) || x.attempts));
  x.timeoutMs = Math.max(1000, Math.min(120_000, Number(x.timeoutMs) || PROOF_POLICY_DEFAULTS.timeoutMs));
  return x;
}

const summarize = (a) => ({ status: a.status, fired: a.oracle?.fired === true, inconclusive: a.oracle?.inconclusive === true, reason: a.oracle?.reason ?? a.reasons?.[0] ?? null, durationMs: a.durationMs, degraded: a.degraded });

/**
 * Independent verifier. Takes a verifierView ONLY; any extra property (a model's reasoning, prior results) is rejected so
 * the isolation of its inputs is checkable rather than a convention.
 */
async function independentVerify(view, opts = {}) {
  const allowed = new Set(['revision', 'reproducer', 'findingId', 'oracle']);
  const extra = Object.keys(view || {}).filter((k) => !allowed.has(k));
  if (extra.length) return { status: 'rejected', reason: `verifier input must be exactly revision, reproducer, findingId, oracle; got extra: ${extra.join(', ')}` };
  const attempt = await (opts.attemptFn ?? _runner_js__WEBPACK_IMPORTED_MODULE_2__/* .runAttempt */ .Tm)(structuredClone(view.reproducer), { ...opts, preferContainer: opts.preferContainer });
  return { status: attempt.status === 'completed' ? (attempt.oracle?.fired ? 'confirmed' : 'not-reproduced') : 'incomplete', attempt: summarize(attempt), environment: attempt.environment ?? null };
}

/**
 * @param {object} a
 * @param {object} a.finding       the finding (id/stableId, severity, proofTier ...)
 * @param {string} [a.revision]    commit the proof applies to
 * @param {object} a.reproducer    serialized reproducer
 * @param {object} [a.policy]
 * @param {object} [a.deps]        test seams: { attemptFn }
 */
async function proveFinding({ finding, revision = null, reproducer, policy = {}, signal, deps = {}, sourceState = null, sourceRoot = null, overlay = null } = {}) {
  const started = Date.now();
  const pol = normalizePolicy(policy);
  const attemptFn = deps.attemptFn ?? _runner_js__WEBPACK_IMPORTED_MODULE_2__/* .runAttempt */ .Tm;
  const findingId = finding?.stableId ?? finding?.id ?? reproducer?.findingId ?? 'unknown';
  const degradation = [];
  let state = sourceState ?? (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .fromProofTier */ .jn)((0,_proof_tier_js__WEBPACK_IMPORTED_MODULE_4__/* .proofTierOf */ .gx)(finding || {}));
  if (state === 'REPRODUCED') state = 'STATICALLY_CORROBORATED'; // an old single-run marker proof must be re-earned here
  const startState = state;

  const result = (extra) => ({
    schema: RESULT_SCHEMA, version: 1, findingId, revision, startState, state, staticCorroboration: (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .stateRank */ .g3)(startState) >= 1, tier: (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .toProofTier */ .KF)(state),
    oracle: reproducer?.oracle?.type ?? null, policy: pol,
    reproducerDigest: reproducer ? safeDigest(reproducer) : null,
    degradation, timing: { proofMs: Date.now() - started }, ...extra,
  });

  const errs = reproducer ? (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .validateReproducer */ .mC)(reproducer) : ['no reproducer supplied'];
  if (errs.length) { degradation.push('invalid-reproducer'); return result({ completeness: 'INCOMPLETE', outcome: 'invalid-reproducer', reasons: errs, attempts: { required: pol.required, run: 0, successes: 0, incomplete: 0 }, independentReplay: { status: 'not-run' } }); }

  // A valid reproducer is itself the REPRODUCER_GENERATED rung. Static corroboration is recorded, not required: an exploit
  // that reproduces under an independent oracle is deterministic corroboration in its own right, and a pattern-only finding
  // must not be unable to earn proof merely because the taint engine never saw it. The record says which it was.
  const staticCorroboration = (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .stateRank */ .g3)(startState) >= (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .stateRank */ .g3)('STATICALLY_CORROBORATED');
  if (!staticCorroboration) degradation.push('no-static-corroboration');
  state = 'REPRODUCER_GENERATED';

  const attempts = [];
  for (let i = 0; i < pol.attempts; i++) {
    if (signal?.aborted) { degradation.push('cancelled'); break; }
    const a = await attemptFn(structuredClone(reproducer), { limits: { timeoutMs: pol.timeoutMs }, signal, requireContainer: pol.requireContainer, preferContainer: pol.preferContainer, force: pol.force, sourceRoot, overlay });
    attempts.push(a);
    // Stop early once the threshold can no longer be met only if every attempt is a decisive negative; incomplete runs continue.
  }
  const completed = attempts.filter((a) => a.status === 'completed' && !a.oracle?.inconclusive);
  const successes = completed.filter((a) => a.oracle?.fired).length;
  const incomplete = attempts.length - completed.length;
  for (const a of attempts) for (const d of a.degraded || []) if (!degradation.includes(d)) degradation.push(d);
  if (incomplete) degradation.push(`incomplete-attempts:${incomplete}`);
  const env = attempts.find((a) => a.environment)?.environment ?? null;
  const base = {
    environment: env && { mode: env.mode, assurance: env.assurance, backend: env.backend ?? null, note: env.note ?? null },
    build: attempts.some((a) => a.status === 'build-failed') ? 'failed' : attempts.length ? 'ok' : 'not-run',
    attempts: { required: pol.required, run: attempts.length, successes, incomplete, detail: attempts.map(summarize) },
    artifactHashes: { reproducer: safeDigest(reproducer), observations: (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .sha256 */ .sc)((0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .canonicalize */ .dw)(attempts.map((a) => a.observation ?? null))) },
  };

  if (successes > 0) {
    const r = (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .advance */ .np)(state, 'REPRODUCED'); if (r.ok) state = r.state;
  }
  if (!attempts.length) return result({ ...base, completeness: 'INCOMPLETE', outcome: 'not-run', independentReplay: { status: 'not-run' } });
  if (successes === 0) {
    const decisive = completed.length === attempts.length;
    return result({ ...base, completeness: decisive ? 'FULL' : 'INCOMPLETE', outcome: decisive ? 'not-reproduced' : 'inconclusive', note: 'not reproduced is not proof of safety', independentReplay: { status: 'not-run' } });
  }
  if (successes < pol.required || incomplete) {
    return result({ ...base, completeness: incomplete ? 'INCOMPLETE' : 'DEGRADED', outcome: 'reproduced-below-threshold', independentReplay: { status: 'not-run' } });
  }

  let independent = { status: 'skipped' };
  if (pol.independentReplay) {
    independent = await independentVerify((0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .verifierView */ .IW)({ revision, reproducer, findingId, oracle: reproducer.oracle }), { attemptFn, limits: { timeoutMs: pol.timeoutMs }, signal, requireContainer: pol.requireContainer, force: pol.force, sourceRoot, overlay });
    if (independent.status !== 'confirmed') degradation.push(`independent-replay:${independent.status}`);
  } else degradation.push('independent-replay-disabled');
  if (independent.status === 'confirmed') {
    const r = (0,_states_js__WEBPACK_IMPORTED_MODULE_1__/* .advance */ .np)(state, 'EXPLOIT_CONFIRMED'); if (r.ok) state = r.state;
  }
  const full = state === 'EXPLOIT_CONFIRMED' && base.environment?.assurance !== 'none';
  return result({ ...base, independentReplay: independent, completeness: full ? (base.environment.assurance === 'lower' ? 'DEGRADED' : 'FULL') : 'INCOMPLETE', outcome: full ? 'exploit-confirmed' : 'reproduced-unverified' });
}

const safeDigest = (r) => { try { return (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_3__/* .reproducerDigest */ .we)(r); } catch { return null; } };

/** Severity policy: optional, never on by default. Returns the finding unchanged unless the policy asks to demote. */
function applySeverityPolicy(finding, evidenceState, policy) {
  const req = policy?.criticalRequires;
  if (!Array.isArray(req) || !req.length || finding?.severity !== 'critical') return finding;
  const ok = req.some((s) => stateRankOf(evidenceState ?? 'CANDIDATE') >= stateRankOf(s));
  return ok ? finding : { ...finding, severity: 'high', severityPolicy: { demotedFrom: 'critical', reason: `critical requires ${req.join(' or ')}; evidence state is ${evidenceState ?? 'CANDIDATE'}` } };
}
const _newRunId = () => randomBytes(6).toString('hex');


/***/ }),

/***/ 12090:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   KF: () => (/* binding */ toProofTier),
/* harmony export */   g3: () => (/* binding */ stateRank),
/* harmony export */   jn: () => (/* binding */ fromProofTier),
/* harmony export */   np: () => (/* binding */ advance)
/* harmony export */ });
/* unused harmony exports EVIDENCE_STATES, COMPLETENESS */
// Evidence state ladder for the Universal Exploit Proof Fabric.
//
// Evidence state is SEPARATE from severity and confidence. It extends, never replaces, the vocabulary that already
// exists: `proof-tier.js` (execution-proven / proof-failed / taint-proven / unproven) and the fix-verify legs
// (`verifiedFull`, `degradedLegs`). `toProofTier` / `fromProofTier` are the explicit bridges.
//
// Transitions are guarded: a state can only be reached from the state directly before it (or by dropping back), so no
// caller can jump a finding to EXPLOIT_CONFIRMED without passing REPRODUCED, or to FIX_VERIFIED without
// FIX_REPLAY_BLOCKED. A degraded or incomplete run NEVER advances a state.
const EVIDENCE_STATES = Object.freeze([
  'CANDIDATE',
  'STATICALLY_CORROBORATED',
  'REPRODUCER_GENERATED',
  'REPRODUCED',
  'EXPLOIT_CONFIRMED',
  'FIX_REPLAY_BLOCKED',
  'FIX_VERIFIED',
]);

const stateRank = (s) => EVIDENCE_STATES.indexOf(s);

const REQUIRES_PREDECESSOR = Object.freeze(Object.fromEntries(EVIDENCE_STATES.map((s, i) => [s, i === 0 ? null : EVIDENCE_STATES[i - 1]])));

/**
 * Advance `from` to `to`. Returns { ok, state, reason }. Moving up requires `to` to be exactly the next rung; moving
 * down or staying is always allowed (evidence can be lost, never invented). Unknown states are rejected.
 */
function advance(from, to) {
  if (!EVIDENCE_STATES.includes(from)) return { ok: false, state: 'CANDIDATE', reason: `unknown current state: ${String(from)}` };
  if (!EVIDENCE_STATES.includes(to)) return { ok: false, state: from, reason: `unknown target state: ${String(to)}` };
  if (stateRank(to) <= stateRank(from)) return { ok: true, state: to, reason: null };
  if (REQUIRES_PREDECESSOR[to] !== from) return { ok: false, state: from, reason: `cannot reach ${to} from ${from}: ${REQUIRES_PREDECESSOR[to]} is required first` };
  return { ok: true, state: to, reason: null };
}

// Bridges to the older vocabulary so existing consumers keep working.
function toProofTier(state) {
  const r = stateRank(state);
  if (r >= stateRank('EXPLOIT_CONFIRMED')) return 'execution-proven';
  if (r >= stateRank('STATICALLY_CORROBORATED')) return 'taint-proven';
  return 'unproven';
}

function fromProofTier(tier) {
  if (tier === 'taint-proven') return 'STATICALLY_CORROBORATED';
  // execution-proven under the older single-run marker path is one run, not the 3/3 + independent replay the fabric
  // requires, so it maps to REPRODUCED and never to EXPLOIT_CONFIRMED.
  if (tier === 'execution-proven') return 'REPRODUCED';
  return 'CANDIDATE';
}

// Completeness vocabulary shared with fix-verify: FULL only when nothing was skipped.
const COMPLETENESS = Object.freeze(['FULL', 'DEGRADED', 'INCOMPLETE']);


/***/ }),

/***/ 62199:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   findingKey: () => (/* binding */ findingKey),
/* harmony export */   latestProof: () => (/* binding */ latestProof),
/* harmony export */   listProofs: () => (/* binding */ listProofs),
/* harmony export */   saveProof: () => (/* binding */ saveProof),
/* harmony export */   scrubDeep: () => (/* binding */ scrubDeep)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(31174);
/* harmony import */ var _encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(39984);
/* harmony import */ var _llm_validator_redact_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(65388);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(37055);
// Proof artifact store: `.agentic-security/proofs/<findingKey>/<recordDigest>.json`.
//
// Reuses the existing state machinery rather than adding another: `safeWriteState` (refuses unsafe dirs and symlinks),
// `maybeEncryptForWrite` / `maybeDecryptForRead` (the `proofs` artifact is registered `confidential`), retention
// (evidence class) and legal holds (a hold on `proofs` blocks purge). Nothing persisted contains a plaintext credential:
// records are passed through a recursive secret filter first, and the runner never returns its per-run nonce or secrets.







const PROOF_RECORD_SCHEMA = 'agentic-security/proof-record';
const PROOFS_DIR = 'proofs';
const MAX_RECORD_BYTES = 512 * 1024;

const findingKey = (id) => `${String(id).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80)}-${(0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .sha256 */ .sc)(String(id)).slice(0, 8)}`;

// The shared redactor catches key=value shapes; bare tokens need their own pass, so persisted evidence cannot carry one.
const BARE_SECRET_RES = [
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, /\bSECRET-[0-9a-f]{24}-[a-z0-9_-]+\b/g,
];
function scrubString(text) {
  let t = String(text);
  try { t = (0,_llm_validator_redact_js__WEBPACK_IMPORTED_MODULE_4__/* .redactSecrets */ .f)(t).text; } catch { return '[unredactable]'; }
  for (const re of BARE_SECRET_RES) t = t.replace(re, '[REDACTED-SECRET]');
  return t;
}

/** Deep-copy `v` with every string passed through the secret redactor. */
function scrubDeep(v) {
  if (typeof v === 'string') return scrubString(v);
  if (Array.isArray(v)) return v.map(scrubDeep);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrubDeep(x)]));
  return v;
}

function recordDigest(record) {
  const { recordDigest: _omit, ...rest } = record;
  return (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .sha256 */ .sc)((0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .canonicalize */ .dw)(rest));
}

function saveProof(scanRoot, record) {
  const safe = scrubDeep(record);
  safe.schema = PROOF_RECORD_SCHEMA;
  safe.recordDigest = recordDigest(safe);
  const text = JSON.stringify(safe, null, 2);
  if (Buffer.byteLength(text) > MAX_RECORD_BYTES) return { ok: false, reason: 'proof record exceeds the size limit' };
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__/* .maybeEncryptForWrite */ .v2)(scanRoot, PROOFS_DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, PROOFS_DIR, findingKey(record.findingId), `${safe.recordDigest}.json`);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.safeWriteState)(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.recordDigest, encrypted: enc.encrypted };
}

function readRecord(file) {
  const text = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__.maybeDecryptForRead)(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8'));
  const rec = JSON.parse(text);
  // A record whose content no longer matches its own digest was modified after it was written.
  if (rec.recordDigest !== recordDigest(rec)) return { tampered: true, record: rec };
  return { tampered: false, record: rec };
}

/** Newest-first records for a finding. Tampered records are returned flagged, never silently dropped or trusted. */
function listProofs(scanRoot, findingId) {
  const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, PROOFS_DIR, findingKey(findingId));
  let names = [];
  try { names = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir).filter((n) => n.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const n of names) {
    const f = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, n);
    try { const { tampered, record } = readRecord(f); out.push({ file: f, tampered, record, mtime: node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(f).mtimeMs }); } catch { out.push({ file: f, tampered: true, record: null, mtime: 0 }); }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

function latestProof(scanRoot, findingId) {
  return listProofs(scanRoot, findingId).find((p) => p.record) ?? null;
}


/***/ })

};
