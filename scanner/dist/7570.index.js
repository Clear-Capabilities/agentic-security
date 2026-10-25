export const id = 7570;
export const ids = [7570];
export const modules = {

/***/ 87570:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   formatFixProof: () => (/* binding */ formatFixProof),
/* harmony export */   verifyFixWithProof: () => (/* binding */ verifyFixWithProof)
/* harmony export */ });
/* harmony import */ var _states_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(48122);
/* harmony import */ var _orchestrator_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(61148);
/* harmony import */ var _runner_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(48104);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(54079);
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

/***/ 61148:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   kO: () => (/* binding */ proveFinding)
/* harmony export */ });
/* unused harmony exports independentVerify, applySeverityPolicy, _newRunId */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var _states_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48122);
/* harmony import */ var _runner_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(48104);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(54079);
/* harmony import */ var _proof_tier_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(58008);
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

/***/ 48122:
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
