export const id = 2199;
export const ids = [2199];
export const modules = {

/***/ 25517:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   $: () => (/* binding */ ORACLE_TYPES),
/* harmony export */   U: () => (/* binding */ evaluateOracle)
/* harmony export */ });
// Deterministic security oracles. A model may SELECT an oracle and propose its parameters; it may never decide that the
// oracle succeeded. Each oracle is a pure function of an Observation gathered by the TRUSTED runner (never by the model):
//
//   Observation = {
//     exitCode, signal, timedOut, stdout, stderr,
//     canaries: { <name>: { exists, digestBefore, digestAfter } }      // checked by the runner on disk, after the run
//     callbacks: [{ nonce }]                                            // hits recorded by the runner's loopback listener
//     nonce                                                             // per-run random token the target cannot predict
//   }
//
// An oracle returns { fired, reason }. `fired:false` with `inconclusive:true` means the observation could not decide
// (for example a timeout); it is never treated as "not exploitable".
const ORACLE_TYPES = Object.freeze([
  'crash_sanitizer', 'command_execution', 'unauthorized_http_access', 'unauthorized_db_read', 'database_mutation',
  'filesystem_mutation', 'outbound_callback', 'authentication_bypass', 'arbitrary_assertion',
]);

const SANITIZER_RE = /(AddressSanitizer|UndefinedBehaviorSanitizer|stack-buffer-overflow|heap-buffer-overflow|SEGV on unknown address|stack smashing detected|buffer overflow detected)/i;
const CRASH_SIGNALS = new Set(['SIGSEGV', 'SIGABRT', 'SIGBUS', 'SIGILL', 'SIGFPE']);

const out = (fired, reason, extra = {}) => ({ fired, reason, ...extra });
const inconclusive = (reason) => ({ fired: false, inconclusive: true, reason });
const has = (obs, text) => typeof text === 'string' && text.length > 0 && `${obs.stdout || ''}${obs.stderr || ''}`.includes(text);

const IMPL = {
  crash_sanitizer(obs) {
    if (SANITIZER_RE.test(obs.stderr || '')) return out(true, 'sanitizer or runtime memory-safety report on stderr');
    if (obs.signal && CRASH_SIGNALS.has(obs.signal)) return out(true, `process terminated by ${obs.signal}`);
    if (obs.timedOut) return inconclusive('run timed out before a crash could be judged');
    return out(false, 'no crash signal and no sanitizer report');
  },
  // The injected payload asks the shell/interpreter to create a file named after the per-run nonce inside the
  // watched canary directory. The target cannot create it unless attacker data reached a command.
  command_execution(obs, p) {
    const c = obs.canaries?.[p.canary || 'command'];
    if (!c) return inconclusive('command canary was not armed by the runner');
    if (c.exists && !c.existedBefore) return out(true, 'nonce-named canary file created by an injected command');
    if (obs.timedOut) return inconclusive('run timed out before the canary could be judged');
    return out(false, 'canary file not created');
  },
  // A secret planted behind authorization (never shown to the exploit client). Seeing the nonce-bearing secret in the
  // client's output while the actor held no credential is the violation.
  unauthorized_http_access(obs, p) {
    const secret = obs.secrets?.[p.secret || 'http'];
    if (!secret) return inconclusive('protected secret was not armed by the runner');
    if (has(obs, secret)) return out(true, 'protected resource content returned to an unauthenticated actor');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'protected content not observed');
  },
  unauthorized_db_read(obs, p) {
    const secret = obs.secrets?.[p.secret || 'db'];
    if (!secret) return inconclusive('database canary row was not armed by the runner');
    if (has(obs, secret)) return out(true, 'row the actor may not read was returned');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'canary row value not observed');
  },
  database_mutation(obs, p) {
    const c = obs.canaries?.[p.canary || 'db'];
    if (!c) return inconclusive('database canary was not armed by the runner');
    if (c.digestBefore && c.digestAfter && c.digestBefore !== c.digestAfter) return out(true, 'protected database state changed');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'protected database state unchanged');
  },
  filesystem_mutation(obs, p) {
    const c = obs.canaries?.[p.canary || 'fs'];
    if (!c) return inconclusive('filesystem canary was not armed by the runner');
    if ((c.exists && !c.existedBefore) || (c.digestBefore && c.digestAfter && c.digestBefore !== c.digestAfter)) return out(true, 'file outside the permitted area was created or modified');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'protected path unchanged');
  },
  outbound_callback(obs) {
    if (obs.callbackUnavailable) return { fired: false, unsupported: true, reason: 'loopback callback listener is not available on this backend' };
    const hit = (obs.callbacks || []).some((c) => c && c.nonce && c.nonce === obs.nonce);
    if (hit) return out(true, 'nonce-bearing request reached the runner-controlled listener');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'no nonce-bearing callback received');
  },
  authentication_bypass(obs, p) {
    const secret = obs.secrets?.[p.secret || 'auth'];
    if (!secret) return inconclusive('protected secret was not armed by the runner');
    if (has(obs, secret)) return out(true, 'privileged content returned without valid credentials');
    if (obs.timedOut) return inconclusive('run timed out');
    return out(false, 'privileged content not observed without credentials');
  },
  // Declarative only: no code, no regex supplied by a model. Operators are a closed set.
  arbitrary_assertion(obs, p) {
    const a = p.assert;
    if (!a || typeof a !== 'object') return inconclusive('assertion missing');
    if (obs.timedOut) return inconclusive('run timed out');
    if ('exitCode' in a) return a.exitCode === obs.exitCode ? out(true, `exit code was ${obs.exitCode}`) : out(false, `exit code was ${obs.exitCode}`);
    if ('stdoutIncludes' in a) return has({ stdout: obs.stdout }, String(a.stdoutIncludes)) ? out(true, 'stdout contained the asserted text') : out(false, 'stdout did not contain the asserted text');
    if ('stderrIncludes' in a) return has({ stderr: obs.stderr }, String(a.stderrIncludes)) ? out(true, 'stderr contained the asserted text') : out(false, 'stderr did not contain the asserted text');
    return inconclusive('unsupported assertion operator');
  },
};

function evaluateOracle(spec, observation) {
  if (!spec || !ORACLE_TYPES.includes(spec.type)) return { fired: false, unsupported: true, reason: `unknown oracle type: ${String(spec?.type)}` };
  if (!observation || typeof observation !== 'object') return inconclusive('no observation');
  try { return IMPL[spec.type](observation, spec.params || {}); } catch (e) { return inconclusive(`oracle error: ${e.message}`); }
}


/***/ }),

/***/ 37055:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   IW: () => (/* binding */ verifierView),
/* harmony export */   V2: () => (/* binding */ substitute),
/* harmony export */   Yj: () => (/* binding */ LANGUAGES),
/* harmony export */   dw: () => (/* binding */ canonicalize),
/* harmony export */   mC: () => (/* binding */ validateReproducer),
/* harmony export */   sc: () => (/* binding */ sha256),
/* harmony export */   we: () => (/* binding */ reproducerDigest)
/* harmony export */ });
/* unused harmony exports MAX_FILES, MAX_FILE_BYTES, isSafeRelPath */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var _oracles_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(25517);
// Serialized reproducer: the ONLY thing an independent verifier receives (besides revision, finding id and oracle).
// It carries no reasoning, no model output and no prior results. Everything per-run (nonce, secrets, canary paths,
// callback URL) is a placeholder substituted fresh by the trusted runner, so a replay can never reuse a stale value
// and a target cannot learn the values in advance.



const REPRODUCER_SCHEMA = 'agentic-security/reproducer';
const REPRODUCER_VERSION = 1;
const LANGUAGES = Object.freeze(['javascript', 'typescript', 'python', 'java', 'c', 'cpp', 'csharp']);
const MAX_FILES = 64;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024;
const PLACEHOLDER_RE = /\{\{([A-Z_]+)(?::([a-z0-9_-]{1,32}))?\}\}/g;
const ALLOWED_PLACEHOLDERS = new Set(['NONCE', 'SECRET', 'CANARY', 'CALLBACK_URL', 'CALLBACK_PORT', 'ROOT', 'NODE', 'PYTHON', 'JAVA', 'JAVAC', 'CC']);

function isSafeRelPath(rel) {
  if (typeof rel !== 'string' || !rel || rel.length > 200) return false;
  if (rel.startsWith('/') || rel.includes('\0') || rel.includes('\\')) return false;
  if (['canary', 'tmp'].includes(rel.split('/')[0])) return false;
  return rel.split('/').every((seg) => seg && seg !== '.' && seg !== '..' && !seg.startsWith('__oracle_'));
}

/** Canonical JSON (sorted keys) so identical reproducers hash identically regardless of key order. */
function canonicalize(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
const sha256 = (s) => (0,node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash)('sha256').update(s).digest('hex');
const reproducerDigest = (r) => sha256(canonicalize(r));

function validateReproducer(r) {
  const errs = [];
  if (!r || typeof r !== 'object' || Array.isArray(r)) return ['reproducer must be an object'];
  if (r.schema !== REPRODUCER_SCHEMA) errs.push('unknown schema');
  if (r.version !== REPRODUCER_VERSION) errs.push('unsupported reproducer version');
  if (typeof r.findingId !== 'string' || !r.findingId || r.findingId.length > 200) errs.push('findingId required');
  if (!LANGUAGES.includes(r.lang)) errs.push(`unsupported language: ${String(r.lang)}`);
  if (!r.oracle || !_oracles_js__WEBPACK_IMPORTED_MODULE_1__/* .ORACLE_TYPES */ .$.includes(r.oracle.type)) errs.push(`unknown oracle: ${String(r.oracle?.type)}`);
  const files = r.files ?? {};
  if (typeof files !== 'object' || Array.isArray(files)) errs.push('files must be an object');
  else {
    const names = Object.keys(files);
    if (names.length > MAX_FILES) errs.push(`file count must be at most ${MAX_FILES}`);
    let total = 0;
    for (const n of names) {
      if (!isSafeRelPath(n)) { errs.push(`unsafe file path: ${n}`); continue; }
      if (typeof files[n] !== 'string') { errs.push(`file ${n} must be a string`); continue; }
      const b = Buffer.byteLength(files[n]);
      total += b;
      if (b > MAX_FILE_BYTES) errs.push(`file ${n} exceeds ${MAX_FILE_BYTES} bytes`);
    }
    if (total > MAX_TOTAL_BYTES) errs.push('reproducer exceeds total size limit');
  }
  const sourceNames = r.sources && typeof r.sources === 'object' && !Array.isArray(r.sources) ? Object.keys(r.sources) : [];
  if (Object.keys(files).length + sourceNames.length === 0) errs.push('reproducer must declare at least one file or source');
  for (const key of ['build', 'run']) {
    const a = r[key];
    if (a == null && key === 'build') continue;
    if (!Array.isArray(a) || !a.length || !a.every((x) => typeof x === 'string' && x.length < 2000 && !x.includes('\0'))) errs.push(`${key} must be a non-empty argv array of strings (no shell string)`);
  }
  for (const text of [...Object.values(files || {}), ...(r.build || []), ...(r.run || [])]) {
    if (typeof text !== 'string') continue;
    for (const m of text.matchAll(PLACEHOLDER_RE)) if (!ALLOWED_PLACEHOLDERS.has(m[1])) errs.push(`unknown placeholder {{${m[1]}}}`);
  }
  if (r.watch != null) {
    if (typeof r.watch !== 'object' || Array.isArray(r.watch)) errs.push('watch must be an object');
    else for (const [k, v] of Object.entries(r.watch)) if (!/^[a-z0-9_-]{1,32}$/.test(k) || !isSafeRelPath(v)) errs.push(`bad watch entry: ${k}`);
  }
  if (r.env != null) {
    if (typeof r.env !== 'object' || Array.isArray(r.env)) errs.push('env must be an object');
    else for (const [k, v] of Object.entries(r.env)) {
      if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(k)) errs.push(`bad env var name: ${k}`);
      if (typeof v !== 'string' || v.length > 4096) errs.push(`env value for ${k} must be a short string`);
    }
  }
  if (r.sources != null) {
    if (typeof r.sources !== 'object' || Array.isArray(r.sources)) errs.push('sources must be an object');
    else for (const [dest, src] of Object.entries(r.sources)) if (!isSafeRelPath(dest) || !isSafeRelPath(src)) errs.push(`bad sources entry: ${dest}`);
  }
  if (r.network != null && !['none', 'callback'].includes(r.network)) errs.push('network must be none or callback');
  return errs;
}

/** The view handed to an independent verifier: exactly the reproducer, plus identifiers. Nothing else. */
function verifierView({ revision, reproducer, findingId, oracle }) {
  return Object.freeze({ revision: revision ?? null, findingId, oracle, reproducer: structuredClone(reproducer) });
}

function substitute(text, ctx) {
  return text.replace(PLACEHOLDER_RE, (whole, name, arg) => {
    switch (name) {
      case 'NONCE': return ctx.nonce;
      case 'SECRET': return ctx.secret(arg || 'default');
      case 'CANARY': return ctx.canary(arg || 'default');
      case 'CALLBACK_URL': return ctx.callbackUrl ?? whole;
      case 'CALLBACK_PORT': return String(ctx.callbackPort ?? '');
      case 'ROOT': return ctx.root;
      case 'NODE': return ctx.tools.node;
      case 'PYTHON': return ctx.tools.python ?? whole;
      case 'JAVA': return ctx.tools.java ?? whole;
      case 'JAVAC': return ctx.tools.javac ?? whole;
      case 'CC': return ctx.tools.cc ?? whole;
      default: return whole;
    }
  });
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
