export const id = 5738;
export const ids = [5738];
export const modules = {

/***/ 35738:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdProof: () => (/* binding */ cmdProof),
  cmdProve: () => (/* binding */ cmdProve),
  formatResult: () => (/* binding */ formatResult),
  loadReproducerFor: () => (/* binding */ loadReproducerFor)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(48161);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/posture/proof-fabric/orchestrator.js
var orchestrator = __webpack_require__(3740);
// EXTERNAL MODULE: ./src/posture/encryption-provider.js
var encryption_provider = __webpack_require__(39984);
// EXTERNAL MODULE: ./src/llm-validator/redact.js
var redact = __webpack_require__(65388);
// EXTERNAL MODULE: ./src/posture/proof-fabric/reproducer.js
var reproducer = __webpack_require__(37055);
;// CONCATENATED MODULE: ./src/posture/proof-fabric/store.js
// Proof artifact store: `.agentic-security/proofs/<findingKey>/<recordDigest>.json`.
//
// Reuses the existing state machinery rather than adding another: `safeWriteState` (refuses unsafe dirs and symlinks),
// `maybeEncryptForWrite` / `maybeDecryptForRead` (the `proofs` artifact is registered `confidential`), retention
// (evidence class) and legal holds (a hold on `proofs` blocks purge). Nothing persisted contains a plaintext credential:
// records are passed through a recursive secret filter first, and the runner never returns its per-run nonce or secrets.







const PROOF_RECORD_SCHEMA = 'agentic-security/proof-record';
const PROOFS_DIR = 'proofs';
const MAX_RECORD_BYTES = 512 * 1024;

const findingKey = (id) => `${String(id).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80)}-${(0,reproducer/* sha256 */.sc)(String(id)).slice(0, 8)}`;

// The shared redactor catches key=value shapes; bare tokens need their own pass, so persisted evidence cannot carry one.
const BARE_SECRET_RES = [
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, /\bSECRET-[0-9a-f]{24}-[a-z0-9_-]+\b/g,
];
function scrubString(text) {
  let t = String(text);
  try { t = (0,redact/* redactSecrets */.f)(t).text; } catch { return '[unredactable]'; }
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
  return (0,reproducer/* sha256 */.sc)((0,reproducer/* canonicalize */.dw)(rest));
}

function saveProof(scanRoot, record) {
  const safe = scrubDeep(record);
  safe.schema = PROOF_RECORD_SCHEMA;
  safe.recordDigest = recordDigest(safe);
  const text = JSON.stringify(safe, null, 2);
  if (Buffer.byteLength(text) > MAX_RECORD_BYTES) return { ok: false, reason: 'proof record exceeds the size limit' };
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = (0,encryption_provider/* maybeEncryptForWrite */.v2)(scanRoot, PROOFS_DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = (0,state_dir.statePath)(scanRoot, PROOFS_DIR, findingKey(record.findingId), `${safe.recordDigest}.json`);
  if (!(0,state_dir/* safeWriteState */.Ep)(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.recordDigest, encrypted: enc.encrypted };
}

function readRecord(file) {
  const text = (0,encryption_provider.maybeDecryptForRead)(external_node_fs_.readFileSync(file, 'utf8'));
  const rec = JSON.parse(text);
  // A record whose content no longer matches its own digest was modified after it was written.
  if (rec.recordDigest !== recordDigest(rec)) return { tampered: true, record: rec };
  return { tampered: false, record: rec };
}

/** Newest-first records for a finding. Tampered records are returned flagged, never silently dropped or trusted. */
function listProofs(scanRoot, findingId) {
  const dir = (0,state_dir.statePath)(scanRoot, PROOFS_DIR, findingKey(findingId));
  let names = [];
  try { names = external_node_fs_.readdirSync(dir).filter((n) => n.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const n of names) {
    const f = external_node_path_.join(dir, n);
    try { const { tampered, record } = readRecord(f); out.push({ file: f, tampered, record, mtime: external_node_fs_.statSync(f).mtimeMs }); } catch { out.push({ file: f, tampered: true, record: null, mtime: 0 }); }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

function latestProof(scanRoot, findingId) {
  return listProofs(scanRoot, findingId).find((p) => p.record) ?? null;
}

// EXTERNAL MODULE: ./src/posture/proof-fabric/runner.js
var runner = __webpack_require__(2998);
;// CONCATENATED MODULE: ./src/posture/proof-fabric/cli.js
// CLI surface for the proof fabric: `proof show|replay|doctor`, `triage exploit|validate`. Non-interactive by design: no
// command reads stdin, every run is bounded by the policy timeouts, and a missing reproducer is a typed exit code, not a
// prompt. Exit codes: 0 confirmed/ok, 1 not confirmed (any reason), 4 usage/precondition.










function loadFinding(root, id) {
  const p = (0,state_dir.statePath)(root, 'last-scan.json');
  if (!external_node_fs_.existsSync(p)) return null;
  const last = JSON.parse(external_node_fs_.readFileSync(p, 'utf8'));
  return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
}

function loadReproducerFor(root, id, flagPath) { return loadReproducer(root, id, flagPath); }

function loadReproducer(root, id, flagPath) {
  const candidates = [flagPath && external_node_path_.resolve(String(flagPath)), (0,state_dir.statePath)(root, 'reproducers', `${findingKey(id)}.json`)].filter(Boolean);
  for (const c of candidates) {
    try { return { reproducer: JSON.parse(external_node_fs_.readFileSync(c, 'utf8')), file: c }; } catch { /* next */ }
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
  const errs = (0,reproducer/* validateReproducer */.mC)(loaded.reproducer);
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
  try { result = await (0,orchestrator/* proveFinding */.kO)({ finding, reproducer: loaded.reproducer, revision: args.flags.revision ?? null, policy, signal: ac.signal }); } finally { process.off('SIGINT', onSig); }
  const saved = saveProof(root, { ...result, reproducer: loaded.reproducer });
  if (json || args.flags.json) console.log(JSON.stringify({ ...result, stored: saved.ok ? saved.file : null }, null, 2));
  else { console.log(formatResult(result)); if (!saved.ok) console.log(`(proof not stored: ${saved.reason})`); }
  return result.state === 'EXPLOIT_CONFIRMED' ? 0 : 1;
}

async function cmdProof(args, root) {
  const sub = args._[1];
  if (sub === 'doctor') return doctor(args);
  const id = String(args._[2] ?? '');
  if (!id) { console.error('usage: proof show <finding-id> | proof replay <finding-id> | proof doctor'); return 4; }
  if (sub === 'show') {
    const all = listProofs(root, id);
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
    const stored = latestProof(root, id);
    if (!stored?.record?.reproducer) { console.error(`No stored reproducer for ${id}.`); return 4; }
    const tmpDir = external_node_fs_.mkdtempSync(external_node_path_.join(external_node_os_.tmpdir(), 'proof-replay-'));
    const tmp = external_node_path_.join(tmpDir, 'reproducer.json');
    external_node_fs_.writeFileSync(tmp, JSON.stringify(stored.record.reproducer));
    args.flags.reproducer = tmp;
    args._ = ['triage', 'exploit', id];
    try { return await cmdProve(args, root); } finally { external_node_fs_.rmSync(tmpDir, { recursive: true, force: true }); }
  }
  console.error('usage: proof show|replay <finding-id> | proof doctor');
  return 4;
}

function doctor(args) {
  const tools = (0,runner/* hostTools */.qV)();
  const rows = reproducer/* LANGUAGES */.Yj.map((l) => ({ lang: l, ...(0,runner/* languageSupport */.ql)(l, tools) }));
  const envs = ['javascript', 'python'].map((l) => ({ lang: l, ...(0,runner/* selectEnvironment */.aP)({ lang: l }) }));
  if (args.flags.json) { console.log(JSON.stringify({ tools, languages: rows, environments: envs }, null, 2)); return 0; }
  console.log('Proof fabric doctor');
  for (const r of rows) console.log(`  ${r.lang.padEnd(11)} ${r.supported ? 'supported' : `unsupported (${r.reason})`}`);
  for (const e of envs) console.log(`  environment for ${e.lang}: ${e.mode}, ${e.assurance} assurance${e.reason ? ` (${e.reason})` : ''}${e.containerSkipped ? `; container skipped: ${e.containerSkipped}` : ''}`);
  const usable = envs.some((e) => e.mode !== 'unavailable');
  if (!usable) console.log('  RESULT: no execution environment available; proofs will report blocked, never clean.');
  return usable ? 0 : 1;
}


/***/ })

};
