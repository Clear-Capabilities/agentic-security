export const id = 8551;
export const ids = [8551];
export const modules = {

/***/ 58551:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hasTamperedRecords: () => (/* binding */ hasTamperedRecords),
/* harmony export */   latestRecord: () => (/* binding */ latestRecord),
/* harmony export */   listRecords: () => (/* binding */ listRecords),
/* harmony export */   saveRecord: () => (/* binding */ saveRecord)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(31174);
/* harmony import */ var _encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(39984);
/* harmony import */ var _proof_fabric_reproducer_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(37055);
/* harmony import */ var _proof_fabric_store_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(62199);
// Persistence for the detection-and-response loop: `.agentic-security/dnr/<findingKey>/<kind>-<digest>.json`.
// Same machinery and the same guarantees as the proof store, reused rather than copied where it is exported:
// safe state-directory writes (no symlinks, no unsafe dirs), the encryption policy, retention as evidence, legal holds, and
// a recursive secret scrub before anything touches disk. A record that no longer matches its own digest is returned FLAGGED,
// never trusted and never silently dropped.







const DIR = 'dnr';
const MAX_RECORD_BYTES = 1024 * 1024;
const RECORD_KINDS = Object.freeze(['detection', 'hunt', 'window', 'fix']);

const digestOf = (record) => { const { recordDigest: _omit, ...rest } = record; return (0,_proof_fabric_reproducer_js__WEBPACK_IMPORTED_MODULE_4__/* .sha256 */ .sc)((0,_proof_fabric_reproducer_js__WEBPACK_IMPORTED_MODULE_4__/* .canonicalize */ .dw)(rest)); };

function saveRecord(root, findingId, kind, record) {
  if (!RECORD_KINDS.includes(kind)) return { ok: false, reason: `unknown record kind: ${kind}` };
  const safe = (0,_proof_fabric_store_js__WEBPACK_IMPORTED_MODULE_5__.scrubDeep)(record);
  safe.schema = `agentic-security/dnr-${kind}-record`;
  safe.kind = kind;
  safe.findingId = String(findingId);
  safe.savedAt = record.savedAt ?? new Date().toISOString();
  safe.recordDigest = digestOf(safe);
  const text = JSON.stringify(safe, null, 2);
  if (Buffer.byteLength(text) > MAX_RECORD_BYTES) return { ok: false, reason: 'record exceeds the size limit' };
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.ensureStateDir)(root)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__/* .maybeEncryptForWrite */ .v2)(root, DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(root, DIR, (0,_proof_fabric_store_js__WEBPACK_IMPORTED_MODULE_5__.findingKey)(findingId), `${kind}-${safe.recordDigest.slice(0, 16)}.json`);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.safeWriteState)(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.recordDigest, encrypted: enc.encrypted };
}

/** Newest-first records of one kind for a finding. Tampered records are flagged. */
function listRecords(root, findingId, kind) {
  const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(root, DIR, (0,_proof_fabric_store_js__WEBPACK_IMPORTED_MODULE_5__.findingKey)(findingId));
  let names = [];
  try { names = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir).filter((n) => n.startsWith(`${kind}-`) && n.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const n of names) {
    const file = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, n);
    try {
      const rec = JSON.parse((0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__.maybeDecryptForRead)(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8')));
      out.push({ file, record: rec, tampered: rec.recordDigest !== digestOf(rec), mtime: node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(file).mtimeMs });
    } catch { out.push({ file, record: null, tampered: true, mtime: 0 }); }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

/** Newest intact record of a kind, or null. A tampered newest record does NOT fall through silently: the caller can see it via listRecords. */
function latestRecord(root, findingId, kind) {
  return listRecords(root, findingId, kind).find((r) => r.record && !r.tampered) ?? null;
}
const hasTamperedRecords = (root, findingId, kind) => listRecords(root, findingId, kind).some((r) => r.tampered);


/***/ })

};
