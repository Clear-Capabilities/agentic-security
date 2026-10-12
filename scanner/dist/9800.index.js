export const id = 9800;
export const ids = [9800];
export const modules = {

/***/ 59800:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cmdProof: () => (/* binding */ cmdProof),
/* harmony export */   cmdProve: () => (/* binding */ cmdProve),
/* harmony export */   loadReproducerFor: () => (/* binding */ loadReproducerFor)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(31174);
/* harmony import */ var _orchestrator_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(3740);
/* harmony import */ var _store_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(62199);
/* harmony import */ var _runner_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(2998);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(37055);
// CLI surface for the proof fabric: `proof show|replay|doctor`, `triage exploit|validate`. Non-interactive by design: no
// command reads stdin, every run is bounded by the policy timeouts, and a missing reproducer is a typed exit code, not a
// prompt. Exit codes: 0 confirmed/ok, 1 not confirmed (any reason), 4 usage/precondition.










function loadFinding(root, id) {
  const p = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_3__.statePath)(root, 'last-scan.json');
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(p)) return null;
  const last = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(p, 'utf8'));
  return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
}

function loadReproducerFor(root, id, flagPath) { return loadReproducer(root, id, flagPath); }

function loadReproducer(root, id, flagPath) {
  const candidates = [flagPath && node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(String(flagPath)), (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_3__.statePath)(root, 'reproducers', `${(0,_store_js__WEBPACK_IMPORTED_MODULE_5__.findingKey)(id)}.json`)].filter(Boolean);
  for (const c of candidates) {
    try { return { reproducer: JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(c, 'utf8')), file: c }; } catch { /* next */ }
  }
  return null;
}

function formatResult(r) {
  const env = r.environment ? `${r.environment.mode} (${r.environment.assurance} assurance)` : 'none';
  return [
    `Finding: ${r.findingId}`,
    `Evidence: ${r.state}`,
    `Oracle: ${r.oracle}`,
    `Reproductions: ${r.attempts?.successes ?? 0}/${r.attempts?.run ?? 0} (required ${r.attempts?.required})`,
    `Independent replay: ${r.independentReplay?.status ?? 'not-run'}`,
    `Environment: ${env}`,
    `Completeness: ${r.completeness}`,
    `Duration: ${(r.timing.proofMs / 1000).toFixed(1)}s`,
    ...(r.degradation?.length ? [`Degraded: ${r.degradation.join(', ')}`] : []),
    ...(r.note ? [`Note: ${r.note}`] : []),
  ].join('\n');
}

async function cmdProve(args, root, { json = false } = {}) {
  const id = String(args._[2] ?? '');
  if (!id) { console.error('usage: triage exploit <finding-id> --prove [--reproducer file] [--attempts N] [--required N]'); return 4; }
  const finding = loadFinding(root, id);
  if (!finding) { console.error(`Finding ${id} not found in last scan.`); return 4; }
  const loaded = loadReproducer(root, id, args.flags.reproducer);
  if (!loaded) { console.error(`No reproducer for ${id}. Supply one with --reproducer <file> or place it at .agentic-security/reproducers/. Nothing was executed.`); return 4; }
  const errs = (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_7__/* .validateReproducer */ .mC)(loaded.reproducer);
  if (errs.length) { console.error(`Invalid reproducer: ${errs.join('; ')}`); return 4; }
  const policy = {};
  if (args.flags.attempts) policy.attempts = Number(args.flags.attempts);
  if (args.flags.required) policy.required = Number(args.flags.required);
  if (args.flags.timeout) policy.timeoutMs = Number(args.flags.timeout) * 1000;
  if (args.flags['require-container']) policy.requireContainer = true;
  const ac = new AbortController();
  const onSig = () => ac.abort();
  process.once('SIGINT', onSig);
  let result;
  try { result = await (0,_orchestrator_js__WEBPACK_IMPORTED_MODULE_4__/* .proveFinding */ .kO)({ finding, reproducer: loaded.reproducer, revision: args.flags.revision ?? null, policy, signal: ac.signal }); } finally { process.off('SIGINT', onSig); }
  const saved = (0,_store_js__WEBPACK_IMPORTED_MODULE_5__.saveProof)(root, { ...result, reproducer: loaded.reproducer });
  // Printed output gets the same secret-scrubbing pass as what is persisted (defense in depth: a free-text reason/note
  // field that captured something from stdout/stderr should never reach a terminal unredacted either).
  if (json || args.flags.json) console.log(JSON.stringify((0,_store_js__WEBPACK_IMPORTED_MODULE_5__.scrubDeep)({ ...result, stored: saved.ok ? saved.file : null }), null, 2));
  else { console.log(formatResult(result)); if (!saved.ok) console.log(`(proof not stored: ${saved.reason})`); }
  return result.state === 'EXPLOIT_CONFIRMED' ? 0 : 1;
}

async function cmdProof(args, root) {
  const sub = args._[1];
  if (sub === 'doctor') return doctor(args);
  const id = String(args._[2] ?? '');
  if (!id) { console.error('usage: proof show <finding-id> | proof replay <finding-id> | proof doctor'); return 4; }
  if (sub === 'show') {
    const all = (0,_store_js__WEBPACK_IMPORTED_MODULE_5__.listProofs)(root, id);
    if (!all.length) { console.error(`No stored proof for ${id}.`); return 4; }
    const latest = all.find((p) => p.record);
    if (all.some((p) => p.tampered)) console.error(`WARNING: ${all.filter((p) => p.tampered).length} stored record(s) failed their integrity check and are not trusted.`);
    const good = all.find((p) => p.record && !p.tampered);
    if (!good) { console.error('No intact proof record.'); return 1; }
    if (args.flags.json) console.log(JSON.stringify(good.record, null, 2)); else console.log(formatResult(good.record));
    void latest;
    return 0;
  }
  if (sub === 'replay') {
    const stored = (0,_store_js__WEBPACK_IMPORTED_MODULE_5__.latestProof)(root, id);
    if (!stored?.record?.reproducer) { console.error(`No stored reproducer for ${id}.`); return 4; }
    const tmpDir = node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdtempSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.tmpdir(), 'proof-replay-'));
    const tmp = node_path__WEBPACK_IMPORTED_MODULE_2__.join(tmpDir, 'reproducer.json');
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(tmp, JSON.stringify(stored.record.reproducer));
    args.flags.reproducer = tmp;
    args._ = ['triage', 'exploit', id];
    try { return await cmdProve(args, root); } finally { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(tmpDir, { recursive: true, force: true }); }
  }
  console.error('usage: proof show|replay <finding-id> | proof doctor');
  return 4;
}

function doctor(args) {
  const tools = (0,_runner_js__WEBPACK_IMPORTED_MODULE_6__/* .hostTools */ .qV)();
  const rows = _reproducer_js__WEBPACK_IMPORTED_MODULE_7__/* .LANGUAGES */ .Yj.map((l) => ({ lang: l, ...(0,_runner_js__WEBPACK_IMPORTED_MODULE_6__/* .languageSupport */ .ql)(l, tools) }));
  const envs = ['javascript', 'python'].map((l) => ({ lang: l, ...(0,_runner_js__WEBPACK_IMPORTED_MODULE_6__/* .selectEnvironment */ .aP)({ lang: l }) }));
  if (args.flags.json) { console.log(JSON.stringify({ tools, languages: rows, environments: envs }, null, 2)); return 0; }
  console.log('Proof fabric doctor');
  for (const r of rows) console.log(`  ${r.lang.padEnd(11)} ${r.supported ? 'supported' : `unsupported (${r.reason})`}`);
  for (const e of envs) console.log(`  environment for ${e.lang}: ${e.mode}, ${e.assurance} assurance${e.reason ? ` (${e.reason})` : ''}${e.containerSkipped ? `; container skipped: ${e.containerSkipped}` : ''}`);
  const usable = envs.some((e) => e.mode !== 'unavailable');
  if (!usable) console.log('  RESULT: no execution environment available; proofs will report blocked, never clean.');
  return usable ? 0 : 1;
}


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
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .ensureStateDir */ .xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__/* .maybeEncryptForWrite */ .v2)(scanRoot, PROOFS_DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, PROOFS_DIR, findingKey(record.findingId), `${safe.recordDigest}.json`);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .safeWriteState */ .Ep)(file, enc.content)) return { ok: false, reason: 'state write refused' };
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
