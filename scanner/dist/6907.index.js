export const id = 6907;
export const ids = [6907];
export const modules = {

/***/ 26907:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   verifyPatchNegative: () => (/* binding */ verifyPatchNegative)
/* harmony export */ });
/* harmony import */ var _assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(41877);
/* harmony import */ var _assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(53353);
/* harmony import */ var _assurance_config_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(90385);
/* harmony import */ var _replay_replay_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(37098);
/* harmony import */ var _oracles_registry_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(18357);
/* harmony import */ var _patch_promotion_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(51487);
/* harmony import */ var _repair_records_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(38899);
// Patch-negative verification (X-204).
//
// A re-scan that no longer fires proves the DETECTOR went quiet; a cosmetic edit can do that. A repair is `verified-fix` here
// only when three things are shown, each by an executed oracle run in an equivalent disposable environment:
//
//   1. original-positive   the original revision reproduces the exploit        (oracle outcome: confirmed)
//   2. patched-negative    the patched revision no longer does, same oracle    (oracle outcome: refuted)
//   3. functional-regression  declared legitimate behaviour is intact on the patched revision, with the same expectations
//      holding on the original first (a baseline), so a wrong expectation is reported rather than blamed on the patch.
//
// All four runs (the baseline is one) go through `replayManifest`, so each is pinned by commit, fixture hash, patch hash,
// toolchain, oracle version and inputs, executes inside the trust boundary, and issues a verifier receipt. The result is then
// handed to `promotePatch`, which re-derives the diff and revision from the proposal and refuses any receipt that does not
// match them. `verified-fix` needs the promotion; nothing else grants it.
//
// A failure never degrades to a vague "not verified": it names the SPECIFIC step that is incomplete and a typed failure code:
//   original-not-reproduced      the original did not reproduce under the oracle (nothing to fix, or the scenario is wrong)
//   patched-still-exploitable    the exploit still works on the patched revision
//   patched-build-broken         the patched revision did not load or its benign control failed
//   patched-negative-inconclusive the patched run decided nothing
//   functional-omitted           no functional check was supplied
//   functional-baseline-invalid  the declared expectations do not hold on the ORIGINAL revision
//   functional-regression-detected the patched revision behaves differently from the declared expectations
//   oracle-changed               the oracle, its version or its inputs differ between the original and patched runs
//   revision-unbound             no exact commit: a verdict cannot be tied to a revision
//   prerequisite-unmet           a toolchain, feature or isolation prerequisite is missing; resumable where stated
//   environment-mismatch         the runs were not in equivalent environments
//   promotion-refused            the receipts do not match the exact proposed diff and revision
//
// The behaviour check is the functional-regression oracle by default. A requester may name `business-state` as `functional.oracleId`
// (X-406, `invariants/repair.js`): the same two runs and the same expectation, with an authorized-workflow scenario as the declared
// case, and `promotePatch` then requires the functional receipts to come from that oracle class instead.
//
// Scope, stated so no caller overclaims: the exploit scenario and the functional cases are the REQUESTER's; this verifies the
// declared scenario and cases, not that the patch is correct elsewhere. Linux is not claimed (the oracle platform statements
// stay `unverified`). Receipts are valid inside this process only (see patch-promotion.js).








const PATCH_NEGATIVE_FEATURE = 'patch-negative-verification';
const FUNCTIONAL_ORACLE = 'functional-regression';
// The check that behaviour is preserved is normally the functional-regression oracle. A requester may name `business-state`
// instead (X-406): the same two runs, the same expectation (refuted), with an authorized-workflow scenario as the declared case.
const FUNCTIONAL_ORACLES = Object.freeze([FUNCTIONAL_ORACLE, 'business-state']);

const STEPS = Object.freeze(['original-positive', 'patched-negative', 'functional-baseline', 'functional-regression']);

const ROLE_OF_STEP = Object.freeze({ 'original-positive': 'original', 'patched-negative': 'patched', 'functional-baseline': 'functionalBaseline', 'functional-regression': 'functional' });
const EXPECTED = Object.freeze({ 'original-positive': 'confirmed', 'patched-negative': 'refuted', 'functional-baseline': 'refuted', 'functional-regression': 'refuted' });

const stepResult = (step, status, extra = {}) => ({ step, status, expected: EXPECTED[step], outcome: null, code: null, reason: null, recordId: null, receiptDigest: null, ...extra });

function replayCode(run) {
  const first = (run.errors || [])[0];
  if (!first) return 'manifest-rejected';
  if (first.code === 'ORACLE_MISMATCH') return 'oracle-changed';
  if (first.code === 'HASH_MISMATCH') return 'content-hash-mismatch';
  return 'manifest-rejected';
}

function classify(step, run) {
  if (run.status === 'rejected') return { status: 'incomplete', code: replayCode(run), reason: (run.errors || []).map((e) => e.message).join('; ').slice(0, 300) || 'the replay manifest was rejected' };
  if (run.status === 'awaiting-prerequisites') {
    const resumable = (run.prerequisites || []).every((p) => p.resumable);
    return { status: 'incomplete', code: 'prerequisite-unmet', outcome: run.outcome ?? null, resumable, reason: `${(run.prerequisites || []).map((p) => `${p.kind} ${p.id} (${p.state})`).join('; ') || 'a prerequisite is unmet'}; nothing was executed${resumable ? ' (resumable)' : ''}` };
  }
  const outcome = run.outcome;
  const observed = run.receipt?.observed || {};
  // a business-state run reports its control flow under `preconditions`: a control flow that no longer works is a broken revision
  const loadBroken = observed.targetLoaded === false || observed.benignCompleted === false || observed.preconditions?.controlRan === false || observed.preconditions?.controlDurableEffect === false;
  if (outcome === 'error') return { status: 'incomplete', code: 'harness-error', reason: String(run.record?.reason || 'the oracle run failed').slice(0, 300), outcome };
  if (outcome === EXPECTED[step]) return { status: 'passed', code: null, reason: run.record?.reason ?? null, outcome };
  const reason = String(run.record?.reason || '').slice(0, 300);
  switch (step) {
    case 'original-positive':
      return { status: 'failed', code: 'original-not-reproduced', reason: `the original revision did not reproduce the exploit (outcome '${outcome}'): ${reason}`, outcome };
    case 'patched-negative':
      if (outcome === 'confirmed') return { status: 'failed', code: 'patched-still-exploitable', reason: `the exploit still works on the patched revision: ${reason}`, outcome };
      return loadBroken
        ? { status: 'failed', code: 'patched-build-broken', reason: `the patched revision did not load or its benign control failed: ${reason}`, outcome }
        : { status: 'failed', code: 'patched-negative-inconclusive', reason: `the patched run decided nothing (outcome '${outcome}'): ${reason}`, outcome };
    case 'functional-baseline':
      return { status: 'failed', code: 'functional-baseline-invalid', reason: `the declared functional expectations do not hold on the original revision (outcome '${outcome}'): ${reason}`, outcome };
    default:
      if (outcome === 'confirmed') return { status: 'failed', code: 'functional-regression-detected', reason: `the patched revision behaves differently from the declared expectations: ${reason}`, outcome };
      return loadBroken
        ? { status: 'failed', code: 'patched-build-broken', reason: `the patched revision did not load for the functional check: ${reason}`, outcome }
        : { status: 'failed', code: 'functional-inconclusive', reason: `the functional check decided nothing (outcome '${outcome}'): ${reason}`, outcome };
  }
}

function summaryOf(steps, verified, incomplete, code) {
  const label = (s) => ({ passed: 'PASS', failed: 'FAIL', incomplete: 'INCOMPLETE', 'not-run': 'not run' })[s.status];
  const lines = steps.map((s) => `${s.step}: ${label(s)}${s.code ? ` (${s.code})` : ''}${s.reason && s.status !== 'passed' ? ` - ${s.reason}` : ''}`);
  lines.push(verified
    ? 'verified-fix: the exploit reproduced on the original revision, did not reproduce on the patched revision, and the declared functional cases still hold. Only the declared scenario and cases were exercised.'
    : `NOT verified-fix: incomplete step '${incomplete}'${code ? ` (${code})` : ''}.`);
  return lines.join('\n');
}

/**
 * Run the three-part patch-negative verification for one proposed patch. Never throws.
 *
 * @param {object} req
 * @param {string} req.hypothesisId   the finding's stable id
 * @param {string} req.commit         exact revision the patch is proposed against (40 or 64 hex)
 * @param {object} req.original       { files, entry, oracleId, inputs, budgets? } the exploit scenario on the original files
 * @param {object} req.patch          { files } the proposed diff: the new content of each changed file
 * @param {object} [req.patched]      { oracleId?, inputs?, entry? }: must equal the original's; anything else is `oracle-changed`
 * @param {object} [req.functional]   { inputs, budgets? } for the functional-regression oracle; omitting it prevents verified-fix
 * @param {object} [req.pinnedOracle] { id, version, logicDigest } the oracle identity the requester recorded earlier
 * @param {object[]} [req.ledger]     earlier repair records to extend
 * @param {object} [o] { config, runOptions } config is the assurance config; runOptions go to the oracle runner (test seams)
 */
async function verifyPatchNegative(req, o = {}) {
  const config = o.config || (0,_assurance_config_js__WEBPACK_IMPORTED_MODULE_2__.resolveAssuranceConfig)({ env: process.env });
  const gate = (0,_assurance_config_js__WEBPACK_IMPORTED_MODULE_2__/* .featureStatus */ .FX)(config, PATCH_NEGATIVE_FEATURE);
  const steps = STEPS.map((s) => stepResult(s, 'not-run', { reason: 'not reached' }));
  const base = {
    status: 'not-verified-fix', verifiedFix: false, incompleteStep: null, failureCode: null, reason: null, steps,
    patchDigest: null, promotion: null, receipts: null, records: {}, verificationRecord: null, repairRecords: Array.isArray(req?.ledger) ? req.ledger : [], summary: '',
  };
  if (gate.status !== 'ok') {
    return { ...base, status: 'disabled', incompleteStep: 'feature-gate', failureCode: gate.code || 'disabled', reason: `${PATCH_NEGATIVE_FEATURE} is not available: ${gate.reason}`, summary: `patch-negative verification did not run: ${gate.reason}` };
  }
  const refuse = (step, code, reason, extra = {}) => {
    const rejected = req && (0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(req.patch) && (0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(req.patch.files) && Object.keys(req.patch.files).length && typeof req.hypothesisId === 'string'
      ? ledgerFor(base.repairRecords, req, base.patchDigest ?? (0,_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .digestOf */ .ol)(req.patch.files), { rejected: { step, code, reason } }) : { records: base.repairRecords };
    return { ...base, ...extra, patchDigest: req?.patch?.files ? (0,_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .digestOf */ .ol)(req.patch.files) : null, incompleteStep: step, failureCode: code, reason, repairRecords: rejected.records, summary: summaryOf(steps, false, step, code) };
  };

  // ---- shape and preconditions that need no execution
  const patchFiles = req?.patch?.files;
  if (!(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(req) || typeof req.hypothesisId !== 'string' || !req.hypothesisId || !(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(req.original) || !(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(req.original.files)
    || typeof req.original.entry !== 'string' || typeof req.original.oracleId !== 'string' || !(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(req.original.inputs)
    || !(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(patchFiles) || Object.keys(patchFiles).length === 0) {
    return refuse('input-validation', 'bad-request', 'a request needs a hypothesis id, the original files, entry, oracle and inputs, and a non-empty patch');
  }
  if (!(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isCommit */ .WM)(req.commit)) return refuse('input-validation', 'revision-unbound', 'no exact commit was given: a verdict cannot be tied to a revision');
  const original = req.original;
  const oracle = _oracles_registry_js__WEBPACK_IMPORTED_MODULE_4__.getOracle(original.oracleId);
  if (!oracle) return refuse('input-validation', 'unknown-oracle', `the exploit oracle '${String(original.oracleId).slice(0, 60)}' is not registered`);
  if (oracle.id === FUNCTIONAL_ORACLE) return refuse('input-validation', 'bad-request', 'the exploit oracle cannot be the functional-regression oracle');
  const patched = (0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(req.patched) ? req.patched : {};
  if ((patched.oracleId !== undefined && patched.oracleId !== original.oracleId) || (patched.inputs !== undefined && (0,_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .digestOf */ .ol)(patched.inputs) !== (0,_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .digestOf */ .ol)(original.inputs)) || (patched.entry !== undefined && patched.entry !== original.entry)) {
    return refuse('oracle-consistency', 'oracle-changed', 'the patched run names a different oracle, entry or inputs than the original run: a changed oracle cannot show the exploit is closed');
  }
  const pin = req.pinnedOracle;
  if (pin !== undefined && (!(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(pin) || pin.id !== oracle.id || pin.version !== oracle.version || pin.logicDigest !== oracle.logicDigest)) {
    return refuse('oracle-consistency', 'oracle-changed', 'the oracle differs from the identity the requester pinned (id, version or logic digest)');
  }
  const fn = req.functional;
  if (!(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(fn) || !(0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isPlainObject */ .Qd)(fn.inputs)) {
    return refuse('functional-regression', 'functional-omitted', 'no functional regression check was supplied: a patch that was never checked for behaviour cannot be a verified fix');
  }
  const functionalOracle = fn.oracleId === undefined ? FUNCTIONAL_ORACLE : fn.oracleId;
  if (!FUNCTIONAL_ORACLES.includes(functionalOracle)) {
    return refuse('input-validation', 'bad-request', `the functional check oracle must be one of ${FUNCTIONAL_ORACLES.join(', ')}`);
  }

  const patchDigest = (0,_assurance_identity_js__WEBPACK_IMPORTED_MODULE_0__/* .digestOf */ .ol)(patchFiles);
  base.patchDigest = patchDigest;
  let ledger = ledgerFor(base.repairRecords, req, patchDigest, {}).records; // proposed
  const common = { hypothesisId: req.hypothesisId, commit: req.commit };
  const plan = [
    ['original-positive', { oracleId: original.oracleId, entry: original.entry, inputs: original.inputs, patchFiles: null, budgets: original.budgets }],
    ['patched-negative', { oracleId: original.oracleId, entry: original.entry, inputs: original.inputs, patchFiles, budgets: original.budgets }],
    ['functional-baseline', { oracleId: functionalOracle, entry: original.entry, inputs: fn.inputs, patchFiles: null, budgets: fn.budgets }],
    ['functional-regression', { oracleId: functionalOracle, entry: original.entry, inputs: fn.inputs, patchFiles, budgets: fn.budgets }],
  ];
  const runs = {};
  let failed = null;
  for (const [i, [step, spec]] of plan.entries()) {
    if (failed) continue;
    let run;
    try {
      const manifest = (0,_replay_replay_js__WEBPACK_IMPORTED_MODULE_3__/* .createReplayManifest */ .$A)({ ...common, fixtureFiles: original.files, patchFiles: spec.patchFiles, oracleId: spec.oracleId, entry: spec.entry, inputs: spec.inputs, budgets: spec.budgets || {}, expected: { outcome: EXPECTED[step] } });
      run = await (0,_replay_replay_js__WEBPACK_IMPORTED_MODULE_3__/* .replayManifest */ .TY)({ manifest, fixtureFiles: original.files, patchFiles: spec.patchFiles }, { config: o.config || config, runOptions: o.runOptions });
    } catch (e) {
      run = { status: 'rejected', errors: [{ code: 'RUN_FAILED', message: String(e?.message || e).slice(0, 200) }] };
    }
    const c = classify(step, run);
    steps[i] = stepResult(step, c.status, { ...c, recordId: run.record?.id ?? null, receiptDigest: run.receipt?.receiptDigest ?? null });
    if (run.executed && run.receipt) runs[ROLE_OF_STEP[step]] = run;
    if (c.status !== 'passed') failed = { step, ...c };
  }
  base.records = Object.fromEntries(Object.entries(runs).map(([k, r]) => [k, r.record]));
  if (failed) {
    ledger = ledgerFor(ledger, req, patchDigest, { rejected: { step: failed.step, code: failed.code, reason: failed.reason } }).records;
    const original0 = base.records.original ? (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .withRepairStatus */ .m$)(base.records.original, (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .verificationRepairFor */ .Kf)(ledger, req.hypothesisId, patchDigest)) : null;
    return { ...base, incompleteStep: failed.step, failureCode: failed.code, reason: failed.reason, resumable: failed.resumable ?? false, repairRecords: ledger, verificationRecord: original0, summary: summaryOf(steps, false, failed.step, failed.code) };
  }

  // ---- the receipts must match the exact proposed diff and revision before anything is promoted
  const receipts = Object.fromEntries(Object.entries(runs).map(([k, r]) => [k, r.receipt]));
  const promotion = (0,_patch_promotion_js__WEBPACK_IMPORTED_MODULE_5__/* .promotePatch */ .l)({ proposal: { hypothesisId: req.hypothesisId, revision: req.commit, originalFiles: original.files, patchFiles, functionalOracle }, receipts });
  if (!promotion.ok) {
    const envBroken = promotion.reasons.some((r) => r.code === 'environment-mismatch');
    const code = envBroken ? 'environment-mismatch' : promotion.reasons.some((r) => r.code === 'oracle-changed') ? 'oracle-changed' : 'promotion-refused';
    const step = envBroken ? 'environment-equivalence' : code === 'oracle-changed' ? 'oracle-consistency' : 'promotion';
    const reason = promotion.reasons.map((r) => r.message).join('; ').slice(0, 400);
    ledger = ledgerFor(ledger, req, patchDigest, { rejected: { step, code, reason } }).records;
    return { ...base, promotion, incompleteStep: step, failureCode: code, reason, repairRecords: ledger, verificationRecord: base.records.original ? (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .withRepairStatus */ .m$)(base.records.original, (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .verificationRepairFor */ .Kf)(ledger, req.hypothesisId, patchDigest)) : null, summary: summaryOf(steps, false, step, code) };
  }
  const promoted = (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .recordPromotion */ .Zw)(ledger, promotion, { verificationRecordId: base.records.patched?.id ?? null });
  ledger = promoted.records;
  const verificationRecord = (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .withRepairStatus */ .m$)(base.records.original, (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .verificationRepairFor */ .Kf)(ledger, req.hypothesisId, patchDigest, base.records.patched?.id));
  return {
    ...base, status: 'verified-fix', verifiedFix: true, promotion, receipts, repairRecords: ledger, verificationRecord,
    reason: 'verified', summary: summaryOf(steps, true, null, null),
  };
}

// The ledger for one verification: always starts with a `proposed` record, and records a rejection when verification stopped.
function ledgerFor(records, req, patchDigest, { rejected } = {}) {
  let list = Array.isArray(records) ? records : [];
  const fields = { hypothesisId: req.hypothesisId, revision: (0,_assurance_schema_kit_js__WEBPACK_IMPORTED_MODULE_1__/* .isCommit */ .WM)(req.commit) ? req.commit : null, diffDigest: patchDigest };
  if (!list.some((r) => r.hypothesisId === fields.hypothesisId && r.diffDigest === patchDigest)) list = (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .appendRepairRecord */ .f7)(list, { ...fields, kind: 'proposed', reason: 'a patch was proposed for verification' }).records;
  if (rejected) list = (0,_repair_records_js__WEBPACK_IMPORTED_MODULE_6__/* .appendRepairRecord */ .f7)(list, { ...fields, kind: 'rejected', step: rejected.step, reason: `${rejected.code}: ${String(rejected.reason || '').slice(0, 300)}` }).records;
  return { records: list };
}


/***/ })

};
