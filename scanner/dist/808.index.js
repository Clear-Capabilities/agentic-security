export const id = 808;
export const ids = [808];
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

/***/ 30808:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  cmdRules: () => (/* binding */ cmdRules)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/posture/proof-fabric/reproducer.js
var reproducer = __webpack_require__(37055);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/ir.js
// Rule intermediate representation: compiles DOWN into the existing pattern-rule engine
// (`../custom-rules.js`), never a parallel matcher. "Compile" here means "emit a
// custom-rules.js-compatible document" — detection at runtime is 100% the already-proven
// regex/allOf/notMatch/window engine; this module only adds PROVENANCE metadata around it.
//
// A rule's match semantics are deliberately the same closed vocabulary custom-rules.js
// already supports (pattern | allOf+window | notMatch) — no new matching primitive is
// introduced, so a promoted rule is exactly as auditable as a hand-written one.


const RULE_IR_SCHEMA = 'agentic-security/rule-ir';
const RULE_IR_VERSION = 1;
const RULE_STATES = Object.freeze(['DRAFT', 'CANDIDATE', 'VALIDATED', 'PROMOTED', 'DEPRECATED', 'ROLLED_BACK']);
const VALID_LANGS = new Set(['javascript', 'typescript', 'python', 'go', 'ruby', 'java', 'rust', 'csharp', 'php', 'any']);

const isStr = (v) => typeof v === 'string' && v.length > 0;

/** Problems with a draft rule IR; an empty list means it is well-formed (not yet validated/promoted). */
function validateRuleIR(ir) {
  const errs = [];
  if (!ir || typeof ir !== 'object') return ['rule IR must be an object'];
  if (ir.schema !== RULE_IR_SCHEMA) errs.push('unknown schema');
  if (ir.version !== RULE_IR_VERSION) errs.push('unsupported rule IR version');
  if (!isStr(ir.id) || !/^[a-z][a-z0-9-]{2,79}$/.test(ir.id)) errs.push('id must be a lowercase kebab-case string');
  if (!isStr(ir.title)) errs.push('title required');
  if (!['critical', 'high', 'medium', 'low'].includes(ir.severity)) errs.push('severity must be critical|high|medium|low');
  if (!isStr(ir.cwe) || !/^CWE-\d+$/.test(ir.cwe)) errs.push('cwe must look like CWE-###');
  if (!isStr(ir.family)) errs.push('family required');
  if (!Array.isArray(ir.languages) || !ir.languages.length || !ir.languages.every((l) => VALID_LANGS.has(l))) errs.push('languages must be a non-empty array from the supported set');
  const m = ir.match;
  if (!m || typeof m !== 'object') errs.push('match required');
  else {
    const hasPattern = isStr(m.pattern);
    const hasAllOf = Array.isArray(m.allOf) && m.allOf.length > 0 && m.allOf.every(isStr);
    if (!hasPattern && !hasAllOf) errs.push('match needs a pattern or a non-empty allOf');
    if (m.notMatch != null && !isStr(m.notMatch)) errs.push('notMatch must be a string');
    if (m.window != null && !(Number.isInteger(m.window) && m.window > 0 && m.window <= 200)) errs.push('window must be an integer in 1..200');
    for (const re of [m.pattern, ...(m.allOf || []), m.notMatch].filter(isStr)) {
      try { new RegExp(re); } catch { errs.push(`invalid regex: ${re}`); }
    }
  }
  // Declarative-only hint fields (sink/source/propagator/sanitizer/dominatingGuard/frameworkConstraint): free text,
  // never executable, carried for provenance/review only and NOT consulted by the matcher.
  for (const k of ['sink', 'source', 'propagator', 'sanitizer', 'dominatingGuard', 'frameworkConstraint']) {
    if (ir[k] != null && !isStr(ir[k])) errs.push(`${k} must be a string when present`);
  }
  if (ir.exclusions != null && !(Array.isArray(ir.exclusions) && ir.exclusions.every(isStr))) errs.push('exclusions must be an array of strings');
  if (!ir.provenance || typeof ir.provenance !== 'object') errs.push('provenance required');
  else {
    if (!isStr(ir.provenance.originatingFindingId)) errs.push('provenance.originatingFindingId required');
    if (ir.provenance.originatingCommit != null && !isStr(ir.provenance.originatingCommit)) errs.push('provenance.originatingCommit must be a string');
    if (!['execution-proven', 'taint-proven', 'deterministic-corroboration'].includes(ir.provenance.evidenceState)) errs.push('provenance.evidenceState must be execution-proven|taint-proven|deterministic-corroboration');
  }
  return errs;
}

function ruleIRDigest(ir) {
  const { state: _s, ...rest } = ir;
  return (0,reproducer/* sha256 */.sc)(JSON.stringify(rest, Object.keys(rest).sort()));
}

/** Build a DRAFT rule IR. Caller supplies the candidate pattern — this module never invents one. */
function draftRuleIR({ id, title, severity, cwe, family, languages, match, remediation, originatingFindingId, originatingCommit, evidenceState, model = null, promptConfigVersion = null, ...hints }) {
  const ir = {
    schema: RULE_IR_SCHEMA, version: RULE_IR_VERSION, id, title, severity, cwe, family, languages, match,
    remediation: remediation ?? null, state: 'DRAFT',
    ...hints,
    provenance: { originatingFindingId, originatingCommit: originatingCommit ?? null, evidenceState, model, promptConfigVersion },
  };
  return ir;
}

/** Compile a rule IR into a custom-rules.js-compatible document. Caller writes the YAML. */
function compileToCustomRule(ir) {
  const errs = validateRuleIR(ir);
  if (errs.length) return { ok: false, errs };
  const doc = {
    id: `rule-compiler/${ir.id}`,
    title: ir.title,
    severity: ir.severity,
    cwe: ir.cwe,
    languages: ir.languages,
    match: { ...(ir.match.pattern ? { pattern: ir.match.pattern } : {}), ...(ir.match.allOf ? { allOf: ir.match.allOf, window: ir.match.window ?? 5 } : {}), ...(ir.match.notMatch ? { notMatch: ir.match.notMatch } : {}) },
    message: ir.remediation || `${ir.title} (${ir.cwe}, compiled from ${ir.provenance.originatingFindingId})`,
  };
  return { ok: true, doc };
}

// EXTERNAL MODULE: ./src/posture/proof-fabric/states.js
var states = __webpack_require__(12090);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/eligibility.js
// X-eligibility (PRD 3 "Eligibility"): a finding may enter synthesis only with a stable id, a vulnerable span, a
// CWE/family, code-flow evidence, and deterministic corroboration OR exploit proof. Reuses the existing
// vocabularies rather than inventing a third: proof-fabric's evidence-state ladder when present, else the older
// proof-tier (`taint-proven`/`execution-proven`), else the finding's own `parser` (an IR-TAINT/MULTI-SINK parser
// origin is code-flow evidence even with no execution).


const ANALYSED_PARSERS = new Set(['IR-TAINT', 'MULTI-SINK']);

function checkEligibility(finding, { proofState = null } = {}) {
  const reasons = [];
  if (!finding?.stableId && !finding?.id) reasons.push('no stable id');
  if (finding?.file == null || finding?.line == null) reasons.push('no vulnerable span (file:line)');
  if (!finding?.cwe && !finding?.family) reasons.push('no CWE or family');
  const hasFlowEvidence = ANALYSED_PARSERS.has(finding?.parser) || !!finding?.snippet;
  if (!hasFlowEvidence) reasons.push('no code-flow evidence (parser not IR-TAINT/MULTI-SINK, no snippet)');

  let evidenceState = 'none';
  if (proofState && (0,states/* stateRank */.g3)(proofState) >= (0,states/* stateRank */.g3)('EXPLOIT_CONFIRMED')) evidenceState = 'execution-proven';
  else if (finding?.proofTier === 'execution-proven') evidenceState = 'execution-proven';
  else if (finding?.proofTier === 'taint-proven' || ANALYSED_PARSERS.has(finding?.parser)) evidenceState = 'taint-proven';
  if (evidenceState === 'none') reasons.push('no deterministic corroboration or exploit proof');

  return { eligible: reasons.length === 0, reasons, evidenceState };
}

;// CONCATENATED MODULE: ./src/posture/rule-compiler/mutation.js
// Bounded structural mutation for ONE candidate rule's own corpus — not bench/mutation's engine-wide verdict-flip
// harness (a different scope: the whole deterministic+taint engine against curated adversarial cases). This module
// exists only to answer PRD 3's "unseen sibling" question for a single rule: does the candidate still fire on a
// structurally different variant of the same vulnerable shape, and does it still decline on a structurally
// different variant of a mitigated shape.
//
// Mutations are SYNTACTIC, deterministic, seed-free and language-agnostic: variable rename, wrap-in-function,
// reorder-adjacent-statements, insert-indirection (a pass-through local variable). No semantics are changed on
// purpose — a mutation that silently changed behavior would make a "same vulnerability, different shape" claim
// false.
const RESERVED = new Set(['if', 'else', 'for', 'while', 'return', 'function', 'const', 'let', 'var', 'import', 'from', 'def', 'class', 'req', 'res']);

function identifiers(code) {
  const seen = new Set();
  for (const m of code.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g)) if (!RESERVED.has(m[1]) && !/^[A-Z_]+$/.test(m[1])) seen.add(m[1]);
  return [...seen];
}

function renameOne(code, from, to) {
  if (!from || code.includes(to)) return null;
  return code.replace(new RegExp(`\\b${from}\\b`, 'g'), to);
}

function variableRename(code, { suffix = '_v2' } = {}) {
  const ids = identifiers(code);
  const target = ids.find((id) => id.length > 1);
  if (!target) return null;
  return renameOne(code, target, `${target}${suffix}`);
}

function wrapInFunction(code, { name = 'wrapped_v2' } = {}) {
  const indented = code.split('\n').map((l) => (l ? `  ${l}` : l)).join('\n');
  return `function ${name}() {\n${indented}\n}\n${name}();\n`;
}

/** Insert a pass-through local for the first simple right-hand-side identifier assigned with `=` (indirection,
 * no behavior change): `x = y;` becomes `const indirectN = y; x = indirectN;`. */
function insertIndirection(code) {
  const m = /^(\s*)([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*;/m.exec(code);
  if (!m) return null;
  const [whole, indent, lhs, rhs] = m;
  const varName = `indirect_${Math.abs(_hash(rhs)) % 1000}`;
  if (code.includes(varName)) return null;
  return code.replace(whole, `${indent}const ${varName} = ${rhs};\n${indent}${lhs} = ${varName};`);
}

function _hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }

const MUTATORS = Object.freeze({ 'variable-rename': variableRename, 'wrap-in-function': wrapInFunction, 'insert-indirection': insertIndirection });

/** Every mutator applied to `code`; mutators that don't apply (return null) are omitted, never silently skipped without saying so. */
function generateVariants(code) {
  const out = [];
  for (const [name, fn] of Object.entries(MUTATORS)) {
    let variant = null;
    try { variant = fn(code); } catch { variant = null; }
    if (variant && variant !== code) out.push({ mutator: name, code: variant });
  }
  return out;
}

// EXTERNAL MODULE: ./src/posture/custom-rules.js + 1 modules
var custom_rules = __webpack_require__(9049);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/corpus.js
// Automatic corpus creation and scoring for ONE candidate rule.
//
// Positive corpus: the original vulnerable snippet plus its generated sibling variants (mutation.js).
// Negative corpus: an explicit patched/clean variant the caller supplies, nearby clean patterns, protected
// (sanitizer/guard) variants, and the NEGATIVE mutations of those (same mutators, applied to the safe side) — a
// candidate rule must decline on ALL of them, not just the one hand-picked negative.
//
// Scoring reuses the exact runtime matcher (`runRule` in `../custom-rules.js`), never a second implementation —
// the score a rule gets here is the score it will actually produce once promoted.




function toRuntimeRule(ir) {
  const { ok, doc, errs } = compileToCustomRule(ir);
  if (!ok) throw new Error(`cannot build corpus for an invalid rule IR: ${errs.join('; ')}`);
  const regexes = doc.match.allOf ? doc.match.allOf.map((p) => new RegExp(p, 'g')) : [new RegExp(doc.match.pattern, 'g')];
  return {
    id: doc.id, title: doc.title, severity: doc.severity, cwe: doc.cwe, languages: doc.languages, message: doc.message,
    regexes, requireAll: !!doc.match.allOf, windowLines: doc.match.window ?? 5,
    notMatch: doc.match.notMatch ? new RegExp(doc.match.notMatch) : null,
  };
}

const EXT = { javascript: 'x.js', typescript: 'x.ts', python: 'x.py', go: 'x.go', ruby: 'x.rb', java: 'x.java', rust: 'x.rs', csharp: 'x.cs', php: 'x.php', any: 'x.txt' };

function buildCorpus(ir, { originalCode, patchedCode = null, nearbyCleanCode = [], protectedVariantsCode = [] } = {}) {
  const positives = [{ label: 'original', code: originalCode }];
  for (const v of generateVariants(originalCode)) positives.push({ label: `sibling:${v.mutator}`, code: v.code });

  const negatives = [];
  if (patchedCode) {
    negatives.push({ label: 'patched', code: patchedCode });
    for (const v of generateVariants(patchedCode)) negatives.push({ label: `patched-sibling:${v.mutator}`, code: v.code });
  }
  nearbyCleanCode.forEach((code, i) => negatives.push({ label: `nearby-clean-${i}`, code }));
  protectedVariantsCode.forEach((code, i) => negatives.push({ label: `protected-${i}`, code }));

  return { positives, negatives };
}

function scoreRule(ir, corpus) {
  const rule = toRuntimeRule(ir);
  const lang = ir.languages[0] || 'javascript';
  const file = EXT[lang] || 'x.txt';
  const run = (code) => (0,custom_rules/* runRule */.OA)(rule, file, code).length > 0;

  const posResults = corpus.positives.map((p) => ({ ...p, fired: run(p.code) }));
  const negResults = corpus.negatives.map((n) => ({ ...n, fired: run(n.code) }));

  const tp = posResults.filter((p) => p.fired).length;
  const fn = posResults.length - tp;
  const fp = negResults.filter((n) => n.fired).length;
  const tn = negResults.length - fp;
  const precision = tp + fp === 0 ? null : tp / (tp + fp);
  const recall = corpus.positives.length === 0 ? null : tp / corpus.positives.length;
  // "Protected negative failures" per PRD 3: a rule firing on a sanitizer/guard-carrying variant specifically.
  const protectedFailures = negResults.filter((n) => n.label.startsWith('protected-') && n.fired).length;

  return { precision, recall, tp, fp, tn, fn, protectedFailures, positives: posResults, negatives: negResults };
}

// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/sandbox/trust-domains.js
var trust_domains = __webpack_require__(38832);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
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
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (truncated) return;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { leaks.push({ kind: 'symlink', file: r, detail: 'symlinks are refused in an engine workspace' }); continue; }
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(path.join(d, e.name), r); continue; }
      if (!e.isFile()) continue;
      if (++scanned > maxFiles) { truncated = true; leaks.push({ kind: 'audit-truncated', file: r, detail: `more than ${maxFiles} files; the audit cannot vouch for the rest` }); return; }
      if (LEAK_FILENAME_PATTERNS.some((re) => re.test(r))) { leaks.push({ kind: 'answer-key-file', file: r, detail: 'file name looks like a label, answer key or advisory record' }); continue; }
      let st; try { st = fs.statSync(path.join(d, e.name)); } catch { continue; }
      if (st.size > maxFileBytes) { skippedLarge++; continue; }
      let body; try { body = fs.readFileSync(path.join(d, e.name), 'utf8'); } catch { continue; }
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
function stageWorkspace({ srcDir, destDir, terms, strictAdvisoryIds = true }) {
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
function engineEnvironment(base, { labelDir } = {}) {
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

;// CONCATENATED MODULE: ./src/posture/rule-compiler/promotion.js
// Promotion gate (PRD 3 "Promotion Gate"): precision/recall thresholds, zero protected-negative failures, zero
// benchmark leakage. A candidate rule does NOT automatically become a production rule — `evaluateRule` only
// scores; `gatePromotion` only judges; the lifecycle ledger (`lifecycle.js`) is the one place a PROMOTED state is
// actually recorded, and nothing in this module writes to it.



const PROMOTION_DEFAULTS = Object.freeze({ minPrecision: 0.95, minRecall: 0.80, maxProtectedFailures: 0 });

/** Anti-cheating: the synthesis agent must never see benchmark answer keys, hidden labels, CWE-bearing hidden
 * filenames, vulnerability comments or protected test metadata. Reuses the evaluation custodian's own term list
 * and guard (QA-002.AC03) rather than inventing a second leakage checker. */
function checkLeakage(promptText, { benchmarkNames = [] } = {}) {
  const terms = protectedTermsFrom({ advisoryText: [], benchmarkNames });
  const g = guardPrompt(promptText, terms);
  return { ok: g.ok, offendingTerms: g.ok ? [] : g.leaks.map((l) => l.detail) };
}

function evaluateRule(ir, corpus, thresholds = PROMOTION_DEFAULTS) {
  const score = scoreRule(ir, corpus);
  const t = { ...PROMOTION_DEFAULTS, ...thresholds };
  const reasons = [];
  if (score.precision === null) reasons.push('precision unmeasured (no positive or negative corpus fired)');
  else if (score.precision < t.minPrecision) reasons.push(`precision ${(score.precision * 100).toFixed(1)}% below ${(t.minPrecision * 100).toFixed(0)}%`);
  if (score.recall === null) reasons.push('recall unmeasured (empty positive corpus)');
  else if (score.recall < t.minRecall) reasons.push(`recall ${(score.recall * 100).toFixed(1)}% below ${(t.minRecall * 100).toFixed(0)}%`);
  if (score.protectedFailures > t.maxProtectedFailures) reasons.push(`${score.protectedFailures} protected-negative failure(s) (max ${t.maxProtectedFailures})`);
  return { pass: reasons.length === 0, reasons, score, thresholds: t };
}

/** The one promotion decision. Never auto-applied: a caller still has to act on `pass:true` by recording a
 * lifecycle transition. Localization ("acceptable") is a human/caller judgment this function cannot make from
 * line/column alone; it is surfaced for review, never silently assumed. */
function gatePromotion({ ir, corpus, leakageCheck, thresholds } = {}) {
  const evalResult = evaluateRule(ir, corpus, thresholds);
  const reasons = [...evalResult.reasons];
  if (!leakageCheck || leakageCheck.ok !== true) reasons.push(leakageCheck ? `leakage check failed: ${leakageCheck.offendingTerms.join(', ')}` : 'leakage check was not run');
  return { pass: reasons.length === 0, reasons, evaluation: evalResult };
}

// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
;// CONCATENATED MODULE: ./src/posture/rule-compiler/lifecycle.js
// Rule lifecycle ledger: DRAFT -> CANDIDATE -> VALIDATED -> PROMOTED -> DEPRECATED/ROLLED_BACK.
//
// Append-only, hash-chained (same idiom as remediation-ledger.js / invariants/lifecycle.js): each entry links the
// previous entry's hash, so a dropped or edited middle record breaks the chain and `verifyLedger` catches it. A
// rule cannot promote itself: `transition` only records a transition a caller already decided; `advance`-style
// guarding on VALID edges lives here so no caller can jump DRAFT straight to PROMOTED.



const LEDGER_SCHEMA = 'agentic-security/rule-lifecycle-ledger';
const EDGES = Object.freeze({
  DRAFT: ['CANDIDATE'], CANDIDATE: ['VALIDATED', 'DRAFT'], VALIDATED: ['PROMOTED', 'DRAFT'],
  PROMOTED: ['DEPRECATED', 'ROLLED_BACK'], DEPRECATED: [], ROLLED_BACK: ['CANDIDATE'],
});

const hashOf = (entry) => (0,external_node_crypto_.createHash)('sha256').update(JSON.stringify(entry)).digest('hex');

function newLedger() { return { schema: LEDGER_SCHEMA, entries: [] }; }

function currentState(ledger, ruleId) {
  for (let i = ledger.entries.length - 1; i >= 0; i--) if (ledger.entries[i].ruleId === ruleId) return ledger.entries[i].to;
  return null;
}

/**
 * Record a transition. Refuses an edge not in EDGES, and refuses DRAFT->DRAFT re-entry for a rule that has never
 * existed (the first entry for a rule id must be `from: null, to: 'DRAFT'`).
 */
function recordTransition(ledger, { ruleId, from, to, reason, evidence = null, actor }) {
  if (!RULE_STATES.includes(to)) return { ok: false, reason: `unknown target state: ${to}` };
  const cur = currentState(ledger, ruleId);
  if (cur === null) {
    if (from !== null || to !== 'DRAFT') return { ok: false, reason: 'first transition for a rule must be null -> DRAFT' };
  } else {
    if (from !== cur) return { ok: false, reason: `stale transition: current state is ${cur}, not ${from}` };
    if (!EDGES[cur].includes(to)) return { ok: false, reason: `cannot go from ${cur} to ${to}` };
  }
  const prevHash = ledger.entries.length ? ledger.entries[ledger.entries.length - 1].entryHash : null;
  const entry = { ruleId, from: cur, to, reason: reason ?? null, evidence, actor: actor ?? 'unknown', at: new Date().toISOString(), prevHash };
  entry.entryHash = hashOf({ ...entry, entryHash: undefined });
  ledger.entries.push(entry);
  return { ok: true, entry };
}

function verifyLedger(ledger) {
  let prevHash = null;
  for (const e of ledger.entries) {
    if (e.prevHash !== prevHash) return { ok: false, reason: 'chain broken: prevHash mismatch' };
    const recomputed = hashOf({ ...e, entryHash: undefined });
    if (recomputed !== e.entryHash) return { ok: false, reason: `entry hash mismatch for ${e.ruleId} at ${e.at}` };
    prevHash = e.entryHash;
  }
  return { ok: true };
}

function historyFor(ledger, ruleId) { return ledger.entries.filter((e) => e.ruleId === ruleId); }
function stateOf(ledger, ruleId) { return currentState(ledger, ruleId); }

;// CONCATENATED MODULE: ./src/posture/rule-compiler/store.js
// Persistence for the rule compiler: one directory per rule under `.agentic-security/rule-compiler/<id>/`
// (`ir.json`, `ledger.json`, `evaluation.json`), the promoted custom-rule document at
// `.agentic-security/rules/<id>.yml` (so the EXISTING `loadCustomRules`/`rule test` machinery picks it up with no
// change), and a regression fixture pair at `.agentic-security/rule-compiler/fixtures/<id>/{vulnerable,clean}/`
// using the SAME filename convention `runRuleTests` already reads (`vulnerable`/`clean` in the path).






const DIR = 'rule-compiler';
const store_EXT = { javascript: 'js', typescript: 'ts', python: 'py', go: 'go', ruby: 'rb', java: 'java', rust: 'rs', csharp: 'cs', php: 'php', any: 'txt' };

function ruleDir(scanRoot, id) { return (0,state_dir.statePath)(scanRoot, DIR, id); }

function loadLedger(scanRoot) {
  const f = (0,state_dir.statePath)(scanRoot, DIR, 'ledger.json');
  if (!external_node_fs_.existsSync(f)) return newLedger();
  try {
    const ledger = JSON.parse(external_node_fs_.readFileSync(f, 'utf8'));
    const v = verifyLedger(ledger);
    return v.ok ? ledger : { ...newLedger(), tampered: true, tamperReason: v.reason };
  } catch { return newLedger(); }
}

function saveLedger(scanRoot, ledger) {
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = (0,state_dir.statePath)(scanRoot, DIR, 'ledger.json');
  return { ok: (0,state_dir/* safeWriteState */.Ep)(f, JSON.stringify(ledger, null, 2)) };
}

function saveIR(scanRoot, ir) {
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = external_node_path_.join(ruleDir(scanRoot, ir.id), 'ir.json');
  return { ok: (0,state_dir/* safeWriteState */.Ep)(f, JSON.stringify(ir, null, 2)), file: f };
}

function loadIR(scanRoot, id) {
  const f = external_node_path_.join(ruleDir(scanRoot, id), 'ir.json');
  try { return JSON.parse(external_node_fs_.readFileSync(f, 'utf8')); } catch { return null; }
}

function saveEvaluation(scanRoot, id, evaluation) {
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = external_node_path_.join(ruleDir(scanRoot, id), 'evaluation.json');
  return { ok: (0,state_dir/* safeWriteState */.Ep)(f, JSON.stringify(evaluation, null, 2)) };
}

/** Write the regression fixtures a promoted rule needs: the SAME vulnerable/clean convention `runRuleTests`
 * already reads, scored against the exact corpus the rule was promoted on. */
function writeFixtures(scanRoot, ir, corpus) {
  const ext = store_EXT[ir.languages[0]] || 'txt';
  const base = external_node_path_.join(ruleDir(scanRoot, ir.id), 'fixtures');
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const written = [];
  for (const p of corpus.positives) {
    const f = external_node_path_.join(base, 'vulnerable', `${p.label.replace(/[^a-z0-9_-]/gi, '_')}.${ext}`);
    if ((0,state_dir/* safeWriteState */.Ep)(f, p.code)) written.push(f);
  }
  for (const n of corpus.negatives) {
    const f = external_node_path_.join(base, 'clean', `${n.label.replace(/[^a-z0-9_-]/gi, '_')}.${ext}`);
    if ((0,state_dir/* safeWriteState */.Ep)(f, n.code)) written.push(f);
  }
  return { ok: true, written, glob: external_node_path_.join(base, '**', '*') };
}

/** Promote: write the compiled custom-rule document to the live rules directory. Does not touch the ledger —
 * the caller records the PROMOTED transition itself, so a failed write here can never produce an inconsistent
 * "promoted but not live" or "live but not recorded" state silently. */
function publishCustomRule(scanRoot, ir) {
  const { ok, doc, errs } = compileToCustomRule(ir);
  if (!ok) return { ok: false, reason: `invalid rule IR: ${errs.join('; ')}` };
  if (!(0,state_dir/* ensureStateDir */.xH)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const f = (0,state_dir.statePath)(scanRoot, 'rules', `${ir.id}.yml`);
  const yamlText = [
    `# Compiled by the rule compiler from finding ${ir.provenance.originatingFindingId} (${ir.provenance.evidenceState}).`,
    `- id: ${doc.id}`,
    `  title: ${JSON.stringify(doc.title)}`,
    `  severity: ${doc.severity}`,
    `  cwe: ${doc.cwe}`,
    `  languages: [${doc.languages.join(', ')}]`,
    `  match:`,
    ...(doc.match.pattern ? [`    pattern: ${JSON.stringify(doc.match.pattern)}`] : []),
    ...(doc.match.allOf ? [`    allOf:`, ...doc.match.allOf.map((p) => `      - ${JSON.stringify(p)}`), `    window: ${doc.match.window}`] : []),
    ...(doc.match.notMatch ? [`    notMatch: ${JSON.stringify(doc.match.notMatch)}`] : []),
    `  message: ${JSON.stringify(doc.message)}`,
    '',
  ].join('\n');
  return { ok: (0,state_dir/* safeWriteState */.Ep)(f, yamlText), file: f };
}

function unpublishCustomRule(scanRoot, id) {
  const f = (0,state_dir.statePath)(scanRoot, 'rules', `${id}.yml`);
  try { if (external_node_fs_.existsSync(f)) external_node_fs_.unlinkSync(f); return { ok: true }; } catch (e) { return { ok: false, reason: e.message }; }
}

;// CONCATENATED MODULE: ./src/posture/rule-compiler/cli.js
// CLI surface: `agentic-security rules synthesize|evaluate|promote|status|rollback`.
//
// Distinct from the pre-existing `labs synthesize-rule` (posture/rule-synthesis.js), which proposes SUPPRESSION
// rules from repeated false-positive triage verdicts — a different input, a different output and a different
// command group on purpose, so the two are never confused at the CLI.
//
// Non-interactive by construction: no command reads stdin, every corpus evaluation is bounded (no network, no
// model call — this is the deterministic half; a model may PROPOSE the candidate pattern this CLI is handed, but
// it never decides promotion).









function loadFinding(root, id) {
  const p = (0,state_dir.statePath)(root, 'last-scan.json');
  if (!external_node_fs_.existsSync(p)) return null;
  const last = JSON.parse(external_node_fs_.readFileSync(p, 'utf8'));
  return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
}

function readJsonArg(pathOrInline) {
  if (!pathOrInline) return null;
  try { return JSON.parse(external_node_fs_.existsSync(pathOrInline) ? external_node_fs_.readFileSync(pathOrInline, 'utf8') : pathOrInline); } catch { return null; }
}

async function cmdRules(args, root) {
  const sub = args._[1];
  if (sub === 'synthesize') return cmdSynthesize(args, root);
  if (sub === 'evaluate') return cmdEvaluate(args, root);
  if (sub === 'promote') return cmdPromote(args, root);
  if (sub === 'status') return cmdStatus(args, root);
  if (sub === 'rollback') return cmdRollback(args, root);
  console.error('usage: rules synthesize <finding-id> --spec <file.json> | evaluate <rule-id> | promote <rule-id> | status [rule-id] | rollback <rule-id>');
  return 4;
}

// `--spec` carries exactly what a model or a human proposed: id/title/severity/cwe/family/languages/match/
// remediation plus the corpus inputs (originalCode/patchedCode/nearbyCleanCode/protectedVariantsCode). This
// command never invents a pattern; it only drafts the IR, checks eligibility and records DRAFT->CANDIDATE.
async function cmdSynthesize(args, root) {
  const findingId = args._[2];
  const spec = readJsonArg(args.flags.spec);
  if (!findingId || !spec) { console.error('usage: rules synthesize <finding-id> --spec <file.json>'); return 4; }
  const finding = loadFinding(root, findingId);
  if (!finding) { console.error(`Finding ${findingId} not found in last scan.`); return 4; }
  const elig = checkEligibility(finding, { proofState: args.flags['proof-state'] || null });
  if (!elig.eligible) { console.error(`Not eligible for rule synthesis: ${elig.reasons.join('; ')}`); return 4; }

  const ir = draftRuleIR({ ...spec, originatingFindingId: finding.stableId ?? finding.id, originatingCommit: spec.originatingCommit ?? null, evidenceState: elig.evidenceState });
  const errs = validateRuleIR(ir);
  if (errs.length) { console.error(`Invalid rule: ${errs.join('; ')}`); return 4; }

  const ledger = loadLedger(root);
  const draft = recordTransition(ledger, { ruleId: ir.id, from: null, to: 'DRAFT', reason: `drafted from ${findingId}`, actor: args.flags.actor || 'agent' });
  if (!draft.ok) { console.error(draft.reason); return 4; }
  const cand = recordTransition(ledger, { ruleId: ir.id, from: 'DRAFT', to: 'CANDIDATE', reason: 'eligibility passed', evidence: { eligibility: elig }, actor: args.flags.actor || 'agent' });
  saveLedger(root, ledger);
  saveIR(root, { ...ir, state: 'CANDIDATE' });
  console.log(`Rule ${ir.id}: DRAFT -> CANDIDATE (digest ${ruleIRDigest(ir).slice(0, 12)})`);
  if (!cand.ok) console.error(cand.reason);
  return 0;
}

async function cmdEvaluate(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules evaluate <rule-id> --corpus <file.json>'); return 4; }
  const ir = loadIR(root, id);
  if (!ir) { console.error(`No rule IR found for ${id}. Run rules synthesize first.`); return 4; }
  const corpusSpec = readJsonArg(args.flags.corpus);
  if (!corpusSpec) { console.error('No corpus supplied. Pass --corpus <file.json> with originalCode (and optionally patchedCode/nearbyCleanCode/protectedVariantsCode).'); return 4; }
  const corpus = buildCorpus(ir, corpusSpec);
  const leakage = checkLeakage(JSON.stringify(corpusSpec), { benchmarkNames: args.flags['benchmark-names'] ? String(args.flags['benchmark-names']).split(',') : [] });
  const gate = gatePromotion({ ir, corpus, leakageCheck: leakage, thresholds: args.flags.thresholds ? readJsonArg(args.flags.thresholds) : PROMOTION_DEFAULTS });

  const ledger = loadLedger(root);
  const cur = stateOf(ledger, id);
  if (gate.pass && cur === 'CANDIDATE') recordTransition(ledger, { ruleId: id, from: 'CANDIDATE', to: 'VALIDATED', reason: 'promotion gate passed', evidence: { score: gate.evaluation.score }, actor: args.flags.actor || 'agent' });
  saveLedger(root, ledger);
  saveEvaluation(root, id, gate);
  if (args.flags.json) console.log(JSON.stringify(gate, null, 2));
  else {
    console.log(`Rule ${id}: ${gate.pass ? 'VALIDATED' : 'gate FAILED'}`);
    console.log(`  precision ${fmtPct(gate.evaluation.score.precision)}  recall ${fmtPct(gate.evaluation.score.recall)}  protected-failures ${gate.evaluation.score.protectedFailures}`);
    for (const r of gate.reasons) console.log(`  - ${r}`);
  }
  if (gate.pass) { const f = writeFixtures(root, ir, corpus); if (f.ok) console.log(`  regression fixtures written: ${f.written.length} file(s) under .agentic-security/rule-compiler/${id}/fixtures/`); }
  return gate.pass ? 0 : 1;
}
const fmtPct = (n) => (n == null ? 'unmeasured' : `${(n * 100).toFixed(1)}%`);

async function cmdPromote(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules promote <rule-id>'); return 4; }
  const ledger = loadLedger(root);
  if (ledger.tampered) { console.error(`Refusing: rule lifecycle ledger failed its integrity check (${ledger.tamperReason}).`); return 4; }
  if (stateOf(ledger, id) !== 'VALIDATED') { console.error(`Rule ${id} is not VALIDATED (run rules evaluate first); refusing to promote.`); return 4; }
  const ir = loadIR(root, id);
  if (!ir) { console.error(`No rule IR found for ${id}.`); return 4; }
  const pub = publishCustomRule(root, ir);
  if (!pub.ok) { console.error(`Promotion refused: ${pub.reason}`); return 4; }
  const t = recordTransition(ledger, { ruleId: id, from: 'VALIDATED', to: 'PROMOTED', reason: args.flags.reason || 'promoted', actor: args.flags.actor || 'operator' });
  saveLedger(root, ledger);
  console.log(`Rule ${id}: VALIDATED -> PROMOTED. Published to ${pub.file}.`);
  if (!t.ok) console.error(t.reason);
  return 0;
}

async function cmdRollback(args, root) {
  const id = args._[2];
  if (!id) { console.error('usage: rules rollback <rule-id> [--reason text]'); return 4; }
  const ledger = loadLedger(root);
  const cur = stateOf(ledger, id);
  if (cur !== 'PROMOTED') { console.error(`Rule ${id} is not PROMOTED (current: ${cur ?? 'unknown'}); nothing to roll back.`); return 4; }
  const un = unpublishCustomRule(root, id);
  const t = recordTransition(ledger, { ruleId: id, from: 'PROMOTED', to: 'ROLLED_BACK', reason: args.flags.reason || 'operator rollback', actor: args.flags.actor || 'operator' });
  saveLedger(root, ledger);
  console.log(`Rule ${id}: PROMOTED -> ROLLED_BACK.${un.ok ? '' : ` (warning: could not remove published rule file: ${un.reason})`}`);
  return t.ok ? 0 : 1;
}

async function cmdStatus(args, root) {
  const ledger = loadLedger(root);
  const id = args._[2];
  if (id) {
    const h = historyFor(ledger, id);
    if (!h.length) { console.error(`No history for rule ${id}.`); return 4; }
    if (args.flags.json) console.log(JSON.stringify(h, null, 2));
    else { console.log(`Rule ${id}: ${stateOf(ledger, id)}`); for (const e of h) console.log(`  ${e.at}  ${e.from ?? '(new)'} -> ${e.to}  (${e.reason || ''})`); }
    return 0;
  }
  const ids = [...new Set(ledger.entries.map((e) => e.ruleId))];
  if (args.flags.json) { console.log(JSON.stringify(ids.map((rid) => ({ id: rid, state: stateOf(ledger, rid) })), null, 2)); return 0; }
  if (!ids.length) { console.log('No rules in the lifecycle ledger yet.'); return 0; }
  for (const rid of ids) console.log(`  ${rid.padEnd(40)} ${stateOf(ledger, rid)}`);
  return 0;
}


/***/ })

};
