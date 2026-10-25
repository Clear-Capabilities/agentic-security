export const id = 3740;
export const ids = [3740];
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

/***/ 3740:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   kO: () => (/* binding */ proveFinding)
/* harmony export */ });
/* unused harmony exports independentVerify, applySeverityPolicy, _newRunId */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var _states_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(12090);
/* harmony import */ var _runner_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(2998);
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

/***/ 2998:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Tm: () => (/* binding */ runAttempt),
/* harmony export */   aP: () => (/* binding */ selectEnvironment),
/* harmony export */   qV: () => (/* binding */ hostTools),
/* harmony export */   ql: () => (/* binding */ languageSupport)
/* harmony export */ });
/* unused harmony export DEFAULT_LIMITS */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(31421);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(77598);
/* harmony import */ var _sandbox_trust_boundary_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(43547);
/* harmony import */ var _sandbox_index_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(75778);
/* harmony import */ var _oracles_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(25517);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(37055);
// Hermetic execution of one reproducer attempt.
//
// Isolation preference: container (when a working runtime and a pre-pulled image exist) > local confined sandbox >
// unavailable. The local mode is LOWER assurance and says so in every result; it is never silently substituted for a
// container where a policy requires one (`requireContainer`). Nothing here ever executes target code unconfined.
//
// Defaults: outbound network denied; only a runner-controlled loopback callback listener may be reachable, and only when
// the reproducer asks for it; no privileged containers; bounded CPU, memory, disk, process count and wall time.










const DEFAULT_LIMITS = Object.freeze({
  timeoutMs: 20_000, buildTimeoutMs: 60_000, graceMs: 1000, maxOutputBytes: 256 * 1024,
  cpus: 1, memoryMb: 512, pids: 128, diskMb: 64,
});

const CONTAINER_IMAGES = Object.freeze({
  javascript: 'node:24-slim', typescript: 'node:24-slim', python: 'python:3-slim', java: 'eclipse-temurin:21',
  c: 'gcc:latest', cpp: 'gcc:latest', csharp: 'mcr.microsoft.com/dotnet/sdk:8.0',
});

const SIGNALS = { 134: 'SIGABRT', 135: 'SIGBUS', 136: 'SIGFPE', 132: 'SIGILL', 139: 'SIGSEGV' };

function findTool(name, pathEnv = process.env.PATH || '') {
  for (const dir of pathEnv.split(node_path__WEBPACK_IMPORTED_MODULE_2__.delimiter)) {
    if (!dir) continue;
    const p = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, name);
    try { node_fs__WEBPACK_IMPORTED_MODULE_0__.accessSync(p, node_fs__WEBPACK_IMPORTED_MODULE_0__.constants.X_OK); if (node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(p).isFile()) return node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(p); } catch { /* next */ }
  }
  return null;
}

function hostTools() {
  return { node: process.execPath, python: findTool('python3'), java: findTool('java'), javac: findTool('javac'), cc: findTool('cc') || findTool('gcc'), dotnet: findTool('dotnet') };
}

/** Language -> tools it needs. Missing tools make the language `unsupported` with a typed reason, never a pass. */
function languageSupport(lang, tools = hostTools()) {
  const need = { javascript: ['node'], typescript: ['node'], python: ['python'], java: ['java', 'javac'], c: ['cc'], cpp: ['cc'], csharp: ['dotnet'] }[lang];
  if (!need) return { supported: false, reason: `unsupported language: ${lang}` };
  const missing = need.filter((t) => !tools[t]);
  return missing.length ? { supported: false, reason: `missing toolchain: ${missing.join(', ')}` } : { supported: true, reason: null };
}

/**
 * Pick the execution environment. `docker` is injectable for tests. A container needs a responsive daemon AND the image
 * already present: nothing is ever pulled (no network during proof).
 */
function selectEnvironment({ lang, preferContainer = true, requireContainer = false, docker = null, tools = hostTools(), force } = {}) {
  const dockerBin = docker?.bin ?? findTool('docker');
  if (preferContainer && dockerBin) {
    const image = docker?.images?.[lang] ?? CONTAINER_IMAGES[lang];
    const probe = (docker?.probe ?? defaultDockerProbe)(dockerBin, image);
    if (probe.ok) return { mode: 'container', assurance: 'high', runtime: dockerBin, image, reason: null };
    if (requireContainer) return { mode: 'unavailable', assurance: 'none', reason: `container required but unavailable: ${probe.reason}` };
    const local = localEnv(force);
    return { ...local, containerSkipped: probe.reason };
  }
  if (requireContainer) return { mode: 'unavailable', assurance: 'none', reason: 'container required but no container runtime found' };
  return localEnv(force);
}

function localEnv(force) {
  const backend = (0,_sandbox_index_js__WEBPACK_IMPORTED_MODULE_6__/* .detectBackend */ .kS)({ force });
  if (backend === 'disabled') return { mode: 'unavailable', assurance: 'none', reason: 'no confinement backend works on this host; refusing to execute' };
  return { mode: 'local-confined', assurance: 'lower', backend, reason: null, note: 'lower-assurance local confinement: not a container boundary' };
}

function defaultDockerProbe(bin, image) {
  const info = (0,node_child_process__WEBPACK_IMPORTED_MODULE_3__.spawnSync)(bin, ['info', '--format', '{{.ServerVersion}}'], { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
  if (info.status !== 0) return { ok: false, reason: 'container daemon not responding' };
  const img = (0,node_child_process__WEBPACK_IMPORTED_MODULE_3__.spawnSync)(bin, ['image', 'inspect', image], { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
  return img.status === 0 ? { ok: true } : { ok: false, reason: `image ${image} is not present locally (proofs never pull)` };
}

// ---------------------------------------------------------------------------------------------------------------

const digestFile = (p) => { try { return (0,node_crypto__WEBPACK_IMPORTED_MODULE_4__.createHash)('sha256').update(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(p)).digest('hex'); } catch { return null; } };

const LISTENER_SRC = `
const http = require('node:http'); const fs = require('node:fs');
const out = process.argv[1];
const s = http.createServer((req, res) => {
  const m = /^\\/([A-Za-z0-9_-]{8,64})/.exec(req.url || '');
  if (m) fs.appendFileSync(out, JSON.stringify({ nonce: m[1] }) + '\\n');
  req.resume(); res.end('ok');
});
s.on('error', () => process.exit(2));
s.listen(0, '127.0.0.1', () => { process.stdout.write(String(s.address().port) + '\\n'); });
setTimeout(() => process.exit(0), 120000).unref();
`;

async function startListener(dir) {
  const hits = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, 'hits.jsonl');
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(hits, '');
  const child = (0,node_child_process__WEBPACK_IMPORTED_MODULE_3__.spawn)(process.execPath, ['-e', LISTENER_SRC, hits], { stdio: ['ignore', 'pipe', 'ignore'], detached: false });
  const port = await new Promise((resolve) => {
    let buf = '';
    const t = setTimeout(() => resolve(null), 3000);
    child.stdout.on('data', (d) => { buf += d; const n = Number(buf.trim()); if (n > 0) { clearTimeout(t); resolve(n); } });
    child.on('exit', () => { clearTimeout(t); resolve(null); });
  });
  return {
    port, child,
    hits: () => { try { return node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(hits, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); } catch { return []; } },
    stop: () => { try { child.kill('SIGKILL'); } catch { /* gone */ } },
  };
}

function trimOut(s, max) { s = String(s ?? ''); return s.length > max ? `${s.slice(0, max)}\n[truncated]` : s; }

/**
 * Run one attempt. Never throws. Result:
 *   { status, executed, environment, observation, oracle, durationMs, reasons[], degraded[], nonceDigest }
 * status: 'completed' | 'build-failed' | 'blocked' | 'unsupported' | 'invalid' | 'error'
 * Only `completed` carries an oracle verdict; everything else is incomplete evidence.
 */
async function runAttempt(reproducer, opts = {}) {
  const started = Date.now();
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits || {}) };
  const done = (o) => ({ executed: false, observation: null, oracle: null, degraded: [], reasons: [], ...o, durationMs: Date.now() - started });

  const errs = (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_8__/* .validateReproducer */ .mC)(reproducer);
  if (errs.length) return done({ status: 'invalid', reasons: errs });
  const tools = opts.tools ?? hostTools();
  const sup = languageSupport(reproducer.lang, tools);
  if (!sup.supported) return done({ status: 'unsupported', reasons: [sup.reason] });
  const env = opts.environment ?? selectEnvironment({ lang: reproducer.lang, requireContainer: opts.requireContainer, preferContainer: opts.preferContainer ?? true, force: opts.force });
  if (env.mode === 'unavailable') return done({ status: 'blocked', environment: env, reasons: [env.reason] });
  if (env.mode === 'container') {
    return done({ status: 'blocked', environment: env, reasons: ['container execution is selected but the container runner is not enabled in this build; use requireContainer:false for local-confined proof'] });
  }
  if (reproducer.network === 'callback' && env.backend !== 'userspace') {
    return done({ status: 'unsupported', environment: env, reasons: [`loopback callback needs the userspace backend; this host uses ${env.backend}`] });
  }

  const nonce = (0,node_crypto__WEBPACK_IMPORTED_MODULE_4__.randomBytes)(12).toString('hex');
  const base = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdtempSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.tmpdir(), 'proof-fabric-')));
  const root = node_path__WEBPACK_IMPORTED_MODULE_2__.join(base, 'root');
  const aux = node_path__WEBPACK_IMPORTED_MODULE_2__.join(base, 'aux');
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(root, { recursive: true });
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, 'canary'));
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, 'tmp'));
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(aux);
  let listener = null;
  try {
    const secrets = {};
    const canaries = {};
    const ctx = {
      nonce, root, tools,
      secret: (n) => (secrets[n] ??= `SECRET-${nonce}-${n}`),
      canary: (n) => { canaries[n] ??= { path: node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, 'canary', `${nonce}-${n}`) }; return canaries[n].path; },
    };
    if (reproducer.network === 'callback') {
      listener = await startListener(aux);
      if (!listener.port) return done({ status: 'error', environment: env, reasons: ['could not start the loopback callback listener'] });
      ctx.callbackPort = listener.port;
      ctx.callbackUrl = `http://127.0.0.1:${listener.port}/${nonce}`;
    }
    // Repository sources imported at proof time (so a patch can be overlaid). Read-only, size-bounded, confined to sourceRoot.
    const imported = {};
    if (reproducer.sources) {
      if (!opts.sourceRoot) return done({ status: 'invalid', environment: env, reasons: ['reproducer imports repository sources but no sourceRoot was given'] });
      const realRoot = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(opts.sourceRoot);
      for (const [dest, src] of Object.entries(reproducer.sources)) {
        let text;
        if (opts.overlay && Object.hasOwn(opts.overlay, src)) text = String(opts.overlay[src]);
        else {
          const abs = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(realRoot, src);
          let real; try { real = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(abs); } catch { return done({ status: 'invalid', environment: env, reasons: [`source not found: ${src}`] }); }
          if (real !== realRoot && !real.startsWith(realRoot + node_path__WEBPACK_IMPORTED_MODULE_2__.sep)) return done({ status: 'invalid', environment: env, reasons: [`source escapes the repository: ${src}`] });
          const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(real);
          if (!st.isFile() || st.size > 256 * 1024) return done({ status: 'invalid', environment: env, reasons: [`source is not a regular file within the size limit: ${src}`] });
          text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(real, 'utf8');
        }
        imported[dest] = text;
      }
    }
    for (const [rel, text] of Object.entries({ ...imported, ...reproducer.files })) {
      const dest = node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, rel);
      node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(dest), { recursive: true });
      node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(dest, (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_8__/* .substitute */ .V2)(text, ctx));
    }
    const argv = (a) => a.map((x) => (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_8__/* .substitute */ .V2)(x, ctx));
    const watch = {};
    for (const [name, rel] of Object.entries(reproducer.watch || {})) {
      const p = node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, rel);
      watch[name] = { path: p, existedBefore: node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(p), digestBefore: digestFile(p) };
    }
    const runEnv = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin', HOME: root, TMPDIR: node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, 'tmp'), LANG: 'C.UTF-8', CI: '1' };
    for (const [k, v] of Object.entries(reproducer.env || {})) runEnv[k] = (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_8__/* .substitute */ .V2)(v, ctx);
    const boundary = { root, timeoutMs: limits.timeoutMs, graceMs: limits.graceMs, maxOutputBytes: limits.maxOutputBytes, env: runEnv, force: opts.force, signal: opts.signal, controlProbes: opts.controlProbes };

    const degraded = [];
    if (env.assurance === 'lower') degraded.push('lower-assurance-local-confinement');

    if (reproducer.build) {
      const b = await (0,_sandbox_trust_boundary_js__WEBPACK_IMPORTED_MODULE_5__/* .runInBoundary */ .N)(argv(reproducer.build), { ...boundary, timeoutMs: limits.buildTimeoutMs, cwd: undefined });
      if (b.blocked) return done({ status: 'blocked', environment: env, reasons: b.reasons, degraded });
      if (b.timedOut || b.exitCode !== 0) return done({ status: 'build-failed', executed: true, environment: env, reasons: [b.timedOut ? 'build timed out' : `build exited ${b.exitCode}`], degraded, observation: { buildStderr: trimOut(b.targetOutput?.stderr, 2000) } });
    }

    const r = await (0,_sandbox_trust_boundary_js__WEBPACK_IMPORTED_MODULE_5__/* .runInBoundary */ .N)(argv(reproducer.run), { ...boundary, ...(listener ? { networkProxyPort: listener.port } : {}) });
    if (r.blocked) return done({ status: 'blocked', environment: env, reasons: r.reasons, degraded });
    if (!r.executed) return done({ status: 'error', environment: env, reasons: [`target did not execute (${r.status})`], degraded });

    const exitCode = r.exitCode ?? null;
    const observation = {
      exitCode, signal: SIGNALS[exitCode] ?? null, timedOut: !!r.timedOut,
      stdout: trimOut(r.targetOutput?.stdout, limits.maxOutputBytes), stderr: trimOut(r.targetOutput?.stderr, limits.maxOutputBytes),
      nonce, secrets, canaries: {}, callbacks: listener ? listener.hits() : [],
    };
    for (const [n, c] of Object.entries(canaries)) observation.canaries[n] = { exists: node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(c.path), existedBefore: false };
    for (const [n, w] of Object.entries(watch)) observation.canaries[n] = { exists: node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(w.path), existedBefore: w.existedBefore, digestBefore: w.digestBefore, digestAfter: digestFile(w.path) };
    if (r.outputCapped) degraded.push('output-capped');
    if (r.timedOut) degraded.push('timed-out');
    if (r.termination?.survivors?.length) degraded.push('surviving-processes');

    const oracle = (0,_oracles_js__WEBPACK_IMPORTED_MODULE_7__/* .evaluateOracle */ .U)(reproducer.oracle, observation);
    // Raw secrets/nonce must not leave this function: persisted evidence carries digests only.
    const safeObs = { ...observation, secrets: Object.fromEntries(Object.keys(secrets).map((k) => [k, '[redacted]'])), nonce: '[redacted]', callbacks: observation.callbacks.length };
    safeObs.stdout = scrub(safeObs.stdout, nonce); safeObs.stderr = scrub(safeObs.stderr, nonce);
    return done({
      status: oracle.unsupported ? 'unsupported' : 'completed', executed: true, environment: { ...env, backend: r.backend ?? env.backend },
      observation: safeObs, oracle, degraded, reasons: oracle.unsupported ? [oracle.reason] : [], controls: r.controls,
      nonceDigest: (0,node_crypto__WEBPACK_IMPORTED_MODULE_4__.createHash)('sha256').update(nonce).digest('hex').slice(0, 16),
    });
  } catch (e) {
    return done({ status: 'error', environment: env, reasons: [`runner error: ${e.message}`] });
  } finally {
    if (listener) listener.stop();
    node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(base, { recursive: true, force: true });
  }
}

const scrub = (s, nonce) => String(s).split(nonce).join('[nonce]');


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


/***/ })

};
