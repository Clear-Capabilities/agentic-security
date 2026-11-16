export const id = 3477;
export const ids = [3477,6907];
export const modules = {

/***/ 73477:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  runInvariantsCommand: () => (/* binding */ runInvariantsCommand)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/assurance/config.js
var assurance_config = __webpack_require__(90385);
// EXTERNAL MODULE: ./src/posture/invariants/export.js
var invariants_export = __webpack_require__(90145);
// EXTERNAL MODULE: ./src/posture/invariants/coverage.js
var coverage = __webpack_require__(95821);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: ./src/posture/assurance/schema-kit.js
var schema_kit = __webpack_require__(53353);
// EXTERNAL MODULE: ./src/posture/replay/replay.js
var replay = __webpack_require__(37098);
// EXTERNAL MODULE: ./src/posture/verification/patch-negative.js
var patch_negative = __webpack_require__(26907);
// EXTERNAL MODULE: ./src/posture/verification/repair-records.js
var repair_records = __webpack_require__(38899);
// EXTERNAL MODULE: ./src/posture/invariants/schema.js
var schema = __webpack_require__(27784);
// EXTERNAL MODULE: ./src/posture/invariants/lifecycle.js
var lifecycle = __webpack_require__(80891);
// EXTERNAL MODULE: ./src/posture/invariants/scenarios.js
var scenarios = __webpack_require__(9960);
;// CONCATENATED MODULE: ./src/posture/invariants/repair.js
// Verify a repair against invariants (X-406).
//
// A patch for a business-logic violation is `verified-fix` here only when ALL of this is shown by executed, receipted runs on a
// disposable fixture, each one pinned by a replay manifest (so by commit, fixture hash, patch hash, toolchain and oracle logic):
//
//   1. the violated contract is APPROVED (verified ledger, `lifecycle.js`). A model-proposed or code-inferred contract cannot be
//      the ground truth a repair is judged against, so a repair of a candidate violation is never `verified-fix`;
//   2. the original revision reproduces the violation, and the patched revision no longer does (`verifyPatchNegative`, the same
//      four-run discipline, promotion and repair ledger every other repair uses; this is that module with the business-state
//      oracle as the declared behaviour check, not a second implementation of it);
//   3. the authorized workflows still work: the scenario's own control flow plus any workflows the requester declares are run as
//      the behaviour check on the original (a baseline, so a wrong expectation is not blamed on the patch) and on the patched
//      revision. A patch that blocks everyone "fixes" the violation and fails here, because the business-state oracle will not
//      call a flow clean unless the application visibly changed durable state;
//   4. every OTHER approved contract on the same fixture is still not violated: its bounded scenarios run on both revisions. A
//      violation that appears only on the patched revision is a regression and blocks; one already present on the original is
//      reported as pre-existing and is not blamed on the patch. Proposed contracts are not required (they are advisory).
//
// Anything else blocks, with an explicit reason code from `REASON_CODES`: failed setup (a prerequisite, the harness, a rejected
// manifest), an unsupported or inconclusive check, a violation that is still reproduced, a broken authorized workflow, an
// unrelated invariant that now fails, an unapproved contract. A blocked result never reads as a pass.
//
// The regression artifact. A verified repair yields a self-contained document: the exact patch, the invariant revision and its
// approval evidence, the exploit scenario, and one replay manifest per leg with its expected outcome. `runRegressionArtifact`
// re-executes every leg from the artifact alone (no agent conversation, no in-process receipt: each leg runs again through the
// trust boundary) and passes only if every leg settles as recorded. It carries the fixture and patch source, so it refuses to be
// built if either holds a credential.
//
// Limits, stated: only the declared exploit scenario, the declared authorized workflows and the other contracts' bounded
// scenarios are exercised; the patch is not shown correct anywhere else. The approval evidence in the artifact is a digest and a
// transition id; verifying the HMAC needs the operator's key (symmetric: tamper-evidence, not third-party non-repudiation).
// Receipts are valid inside the verifier's process; the artifact is how a result crosses a process, by re-execution. Linux is
// not claimed.











const ARTIFACT_SCHEMA = 'agentic-security/invariant-regression-artifact';
const REASON_CODES = Object.freeze([
  'feature-disabled', 'bad-request', 'invariant-not-approved', 'setup-failed', 'unsupported-check', 'original-not-reproduced',
  'violation-not-eliminated', 'authorized-workflow-broken', 'workflow-regression', 'workflow-check-inconclusive', 'workflow-baseline-invalid',
  'invariant-regression', 'preservation-inconclusive', 'preservation-unsupported', 'patched-check-inconclusive',
  'oracle-changed', 'environment-mismatch', 'promotion-refused', 'revision-unbound', 'artifact-refused',
]);
const REQUIRED_FEATURES = Object.freeze([scenarios/* FEATURE */.RI, 'verification-oracles', 'patch-negative-verification']);
const SCENARIO_SCHEMA = 'agentic-security/invariant-scenario';
const MAX_WORKFLOW_ITEMS = 12;
const EXPECT = Object.freeze({ original: 'confirmed', patched: 'refuted', workflowBaseline: 'refuted', workflow: 'refuted' });

const copy = (v) => JSON.parse(JSON.stringify(v));
const blocker = (code, step, reason, extra = {}) => ({ code, step, reason: String(reason).slice(0, 400), ...extra });

// patch-negative's typed failure -> the reason code a reader of an invariant repair sees
const CODE_OF = Object.freeze({
  'original-not-reproduced': 'original-not-reproduced',
  'patched-still-exploitable': 'violation-not-eliminated',
  'patched-build-broken': 'authorized-workflow-broken',
  'patched-negative-inconclusive': 'patched-check-inconclusive',
  'functional-inconclusive': 'workflow-check-inconclusive',
  'functional-regression-detected': 'workflow-regression',
  'functional-baseline-invalid': 'workflow-baseline-invalid',
  'functional-omitted': 'unsupported-check',
  'prerequisite-unmet': 'setup-failed', 'harness-error': 'setup-failed', 'manifest-rejected': 'setup-failed', 'content-hash-mismatch': 'setup-failed',
  'oracle-changed': 'oracle-changed', 'environment-mismatch': 'environment-mismatch', 'promotion-refused': 'promotion-refused', 'revision-unbound': 'revision-unbound',
});

/** The reason code (from `REASON_CODES`) for a patch-negative failure code; unknown ones become `setup-failed`, never a pass. */
function reasonCodeFor(failureCode) { return CODE_OF[failureCode] || 'setup-failed'; }

const validStep = (s, actors) => isPlainObject(s) && actors.has(s.actor) && typeof s.action === 'string' && /^[A-Za-z_$][\w$]{0,63}$/.test(s.action)
  && (s.args === undefined || (Array.isArray(s.args) && s.args.length <= 4));

/** The business-state inputs of the authorized-workflow check: the scenario's control flow plus declared workflows, as both phases. */
function workflowInputs(scenario, extra) {
  const actors = new Set(scenario.inputs.actors.map((a) => a.id));
  const steps = copy(scenario.inputs.control);
  for (const wf of Array.isArray(extra) ? extra : []) {
    if (!Array.isArray(wf) || !wf.every((s) => validStep(s, actors))) return { error: 'a declared workflow is a list of steps by declared actors, each with an action identifier' };
    for (const s of wf) steps.push(copy(s));
  }
  if (steps.length > MAX_WORKFLOW_ITEMS) return { error: `the authorized workflows exceed ${MAX_WORKFLOW_ITEMS} steps` };
  return { inputs: { ...copy(scenario.inputs), control: copy(steps), attack: steps } };
}

function approvalEvidence(ledger, verified, invariant) {
  const rec = [...(ledger?.records || [])].reverse().find((r) => r.invariantId === invariant.id && r.action === 'approve');
  const head = ledger?.records?.length ? ledger.records[ledger.records.length - 1].id : null;
  return { state: verified.ok ? (verified.states[invariant.id] ?? 'unrecorded') : 'unverified', transitionId: rec?.id ?? null, reviewer: rec?.actor?.id ?? null, authority: rec?.policyId ?? null, ledgerHead: head, ledgerDigest: ledger ? digestOf(ledger.records) : null };
}

async function runLeg(manifest, fixtureFiles, patchFiles, o) {
  try {
    return await (0,replay/* replayManifest */.TY)({ manifest, fixtureFiles, patchFiles }, { config: o.config, runOptions: o.runOptions, hostEnvironment: o.hostEnvironment });
  } catch (e) {
    return { status: 'rejected', executed: false, outcome: null, errors: [{ code: 'RUN_FAILED', message: String(e?.message || e).slice(0, 200) }] };
  }
}

/** Run the bounded scenarios of one other approved contract on both revisions and judge preservation. */
async function preserveOther(other, ctx) {
  const entry = { invariantId: other.id, key: other.key, revision: other.revision, status: 'preserved', legs: [], preexisting: [], blockers: [] };
  const gen = generateScenarios(other, { fixture: ctx.fixture, config: ctx.config, bounds: ctx.bounds });
  if (gen.status !== 'ok' || !gen.scenarios.length) {
    entry.status = 'unsupported';
    entry.blockers.push(blocker('preservation-unsupported', `preserve:${other.key}`, gen.reason || (gen.unsupported[0]?.reason ?? 'no scenario could be built for this contract on this fixture'), { invariant: other.id }));
    return entry;
  }
  for (const s of gen.scenarios) {
    const mk = (patchFiles) => createReplayManifest({
      hypothesisId: s.id, commit: ctx.commit, fixtureFiles: ctx.fixture.files, patchFiles, oracleId: 'business-state', entry: s.entry, inputs: s.inputs, budgets: { timeoutMs: s.limits.timeBudgetMs },
    });
    const baseManifest = mk(null);
    const patchManifest = mk(ctx.patchFiles);
    const base = await runLeg(baseManifest, ctx.fixture.files, null, ctx);
    const pat = await runLeg(patchManifest, ctx.fixture.files, ctx.patchFiles, ctx);
    const where = `preserve:${other.key}:${s.kind}`;
    const leg = { scenarioId: s.id, kind: s.kind, baseline: base.outcome ?? base.status, patched: pat.outcome ?? pat.status, baselineReceipt: base.receipt?.receiptDigest ?? null, patchedReceipt: pat.receipt?.receiptDigest ?? null };
    entry.legs.push(leg);
    if (base.status !== 'completed' || pat.status !== 'completed') {
      const why = base.status !== 'completed' ? base : pat;
      entry.blockers.push(blocker('setup-failed', where, (why.prerequisites || []).map((p) => `${p.kind} ${p.id} (${p.state})`).join('; ') || why.errors?.[0]?.message || 'the preservation run did not execute', { invariant: other.id }));
      continue;
    }
    if (!['refuted', 'confirmed'].includes(base.outcome)) {
      entry.blockers.push(blocker('preservation-inconclusive', where, `the original revision settled '${base.outcome}' for this contract, so preservation cannot be shown`, { invariant: other.id }));
      continue;
    }
    if (base.outcome === 'confirmed') {
      leg.note = 'pre-existing violation on the original revision; not blamed on the patch';
      entry.preexisting.push({ scenarioId: s.id, kind: s.kind, patched: pat.outcome });
      if (!['refuted', 'confirmed'].includes(pat.outcome)) entry.blockers.push(blocker('preservation-inconclusive', where, `the patched revision settled '${pat.outcome}'`, { invariant: other.id }));
      ctx.legs.push({ role: `${where}:baseline`, patched: false, manifest: baseManifest, expected: base.outcome }, { role: `${where}:patched`, patched: true, manifest: patchManifest, expected: pat.outcome });
      continue;
    }
    if (pat.outcome === 'confirmed') entry.blockers.push(blocker('invariant-regression', where, `the patch makes an approved contract fail that held on the original: ${String(pat.record?.reason || '').slice(0, 200)}`, { invariant: other.id }));
    else if (pat.outcome !== 'refuted') entry.blockers.push(blocker('preservation-inconclusive', where, `the patched revision settled '${pat.outcome}': ${String(pat.record?.reason || '').slice(0, 200)}`, { invariant: other.id }));
    ctx.legs.push({ role: `${where}:baseline`, patched: false, manifest: baseManifest, expected: 'refuted' }, { role: `${where}:patched`, patched: true, manifest: patchManifest, expected: 'refuted' });
  }
  if (entry.blockers.length) entry.status = 'blocked';
  return entry;
}

/**
 * Verify one repair against an approved invariant, the authorized workflows and every other approved invariant. Never throws.
 *
 * @param {object} req
 * @param {object} req.invariant   the violated contract (a valid invariant document)
 * @param {object} req.ledger      the approval ledger; the contract must be approved in it
 * @param {object} req.scenario    a scenario that reproduces the violation (generated, or the minimized one from `shrinkScenario`)
 * @param {{ files: object }} req.fixture   the disposable fixture the scenario was generated from
 * @param {{ files: object }} req.patch     the exact diff: the new content of each changed file
 * @param {string} req.commit      exact revision the patch is proposed against
 * @param {object[][]} [req.workflows]      extra authorized workflows (lists of steps by declared actors)
 * @param {object[]} [req.others]  other invariant documents on the same fixture; the approved ones must still hold
 * @param {object[]} [req.repairRecords]    an earlier repair ledger to extend
 * @param {object} [req.shrinkRecordId]     id of the shrink record when the scenario is a minimized one (carried into the artifact)
 * @param {object} [o]  { config, runOptions, signer, bounds }
 */
async function verifyInvariantRepair(req, o = {}) {
  const config = o.config || resolveAssuranceConfig({ env: process.env });
  const base = { status: 'not-verified-fix', verifiedFix: false, blockers: [], patchNegative: null, preservation: [], notRequired: [], artifact: null, repairRecords: Array.isArray(req?.repairRecords) ? req.repairRecords : [], verificationRecord: null, summary: '' };
  const done = (extra) => {
    const r = { ...base, ...extra };
    r.reasonCodes = [...new Set(r.blockers.map((b) => b.code))];
    r.summary = r.verifiedFix
      ? 'verified-fix: the violation is gone on the patched revision, the authorized workflows and every other approved contract still hold. Only the declared scenario, workflows and the other contracts\' bounded scenarios were exercised.'
      : `NOT verified-fix: ${r.blockers.map((b) => `${b.code} (${b.step})`).join('; ') || 'not reached'}`;
    return r;
  };
  const stop = (status, ...blockers) => done({ status, blockers });

  for (const f of REQUIRED_FEATURES) {
    const gate = featureStatus(config, f);
    if (gate.status !== 'ok') return stop('disabled', blocker('feature-disabled', 'feature-gate', `${f} is not available: ${gate.reason}`));
  }
  // ---- shape: nothing executes on a malformed request
  const inv = req?.invariant;
  const valid = validateInvariant(inv);
  const scenario = req?.scenario;
  const fixtureFiles = req?.fixture?.files;
  const patchFiles = req?.patch?.files;
  if (!valid.ok) return stop('rejected', blocker('bad-request', 'input-validation', 'the invariant is not valid'));
  if (!isPlainObject(scenario) || scenario.schema !== SCENARIO_SCHEMA || scenario.invariant?.id !== inv.id) return stop('rejected', blocker('bad-request', 'input-validation', 'the scenario is missing or belongs to a different invariant'));
  if (!isPlainObject(fixtureFiles) || digestOf(fixtureFiles) !== scenario.fixtureDigest) return stop('rejected', blocker('bad-request', 'input-validation', 'the fixture is missing or does not match the scenario\'s pinned digest'));
  if (!isPlainObject(patchFiles) || !Object.keys(patchFiles).length) return stop('rejected', blocker('bad-request', 'input-validation', 'a repair needs a non-empty patch'));
  if (!isCommit(req.commit)) return stop('rejected', blocker('revision-unbound', 'input-validation', 'no exact commit was given: a verdict cannot be tied to a revision'));
  const wf = workflowInputs(scenario, req.workflows);
  if (wf.error) return stop('rejected', blocker('bad-request', 'input-validation', wf.error));

  // ---- the contract must be approved: a repair is judged against a requirement a reviewer owns, not against a guess
  const verified = verifyLedger(req.ledger, { signer: o.signer });
  const approval = approvalEvidence(req.ledger, verified, inv);
  if (approval.state !== 'approved') {
    return done({ status: 'not-verified-fix', approval, blockers: [blocker('invariant-not-approved', 'approval', approval.state === 'unverified'
      ? 'the approval ledger does not verify, so no contract counts as approved'
      : `the contract is ${approval.state}: only a reviewer-approved contract can define a verified fix; a model- or code-derived contract does not establish its own ground truth`)] });
  }
  const others = (Array.isArray(req.others) ? req.others : []).filter((x) => isPlainObject(x) && x.id !== inv.id);
  const requiredOthers = []; const notRequired = [];
  for (const x of others) {
    const state = verified.states[x.id];
    if (state === 'approved' && validateInvariant(x).ok) requiredOthers.push(x);
    else notRequired.push({ invariantId: x.id ?? null, key: x.key ?? null, state: state ?? 'unrecorded', reason: 'only approved contracts must be preserved; this one is advisory' });
  }

  // ---- the four-run repair verification, with the authorized workflows as the declared behaviour check
  const budgets = { timeoutMs: scenario.limits.timeBudgetMs };
  const pn = await verifyPatchNegative({
    hypothesisId: scenario.id, commit: req.commit, ledger: req.repairRecords,
    original: { files: fixtureFiles, entry: scenario.entry, oracleId: 'business-state', inputs: scenario.inputs, budgets },
    patch: { files: patchFiles },
    functional: { oracleId: 'business-state', inputs: wf.inputs, budgets },
  }, { config, runOptions: o.runOptions });
  const common = { approval, patchNegative: pn, notRequired, repairRecords: pn.repairRecords, verificationRecord: pn.verificationRecord };
  if (!pn.verifiedFix) {
    return done({ ...common, status: pn.status === 'disabled' ? 'disabled' : 'not-verified-fix', blockers: [blocker(reasonCodeFor(pn.failureCode), pn.incompleteStep || 'verification', pn.reason || 'the repair verification did not complete', { underlying: pn.failureCode, resumable: pn.resumable === true })] });
  }

  // ---- every other approved contract must still hold
  const ctx = { fixture: { files: fixtureFiles }, patchFiles, commit: req.commit, config, runOptions: o.runOptions, bounds: o.bounds, legs: [] };
  const preservation = [];
  for (const x of requiredOthers) preservation.push(await preserveOther(x, ctx));
  const blockers = preservation.flatMap((p) => p.blockers);
  if (blockers.length) {
    const rejected = appendRepairRecord(pn.repairRecords, { kind: 'rejected', hypothesisId: scenario.id, revision: req.commit, diffDigest: pn.patchDigest, step: 'invariant-preservation', reason: `${blockers[0].code}: ${blockers[0].reason}`.slice(0, 300) });
    const repairRecords = rejected.ok ? rejected.records : pn.repairRecords;
    const downgraded = pn.records?.original ? withRepairStatus(pn.records.original, verificationRepairFor(repairRecords, scenario.id, pn.patchDigest)) : pn.verificationRecord;
    return done({ ...common, status: 'not-verified-fix', preservation, blockers, repairRecords, verificationRecord: downgraded });
  }

  const artifact = buildRegressionArtifact({
    invariant: inv, approval, scenario, fixtureFiles, patchFiles, commit: req.commit, budgets, workflowInputs: wf.inputs, extraLegs: ctx.legs, pn, shrinkRecordId: req.shrinkRecordId ?? null, repairRecords: pn.repairRecords,
  });
  if (!artifact.ok) {
    return done({ ...common, status: 'not-verified-fix', preservation, blockers: [blocker('artifact-refused', 'regression-artifact', artifact.reason)], artifactErrors: artifact.errors });
  }
  return done({ ...common, status: 'verified-fix', verifiedFix: true, preservation, artifact: artifact.artifact });
}

// ---------------------------------------------------------------- the regression artifact

function leg(role, manifest, patched, expected) { return { role, patched, expected, manifest }; }

function buildRegressionArtifact({ invariant, approval, scenario, fixtureFiles, patchFiles, commit, budgets, workflowInputs: wfi, extraLegs, pn, shrinkRecordId, repairRecords }) {
  const secrets = [...findSecrets(fixtureFiles).map((s) => ({ ...s, where: `fixture:${s.where}` })), ...findSecrets(patchFiles).map((s) => ({ ...s, where: `patch:${s.where}` }))];
  if (secrets.length) return { ok: false, reason: 'the fixture or the patch holds secret-looking content; a self-contained artifact would embed it', errors: secrets };
  const mk = (spec) => createReplayManifest({ hypothesisId: scenario.id, commit, fixtureFiles, patchFiles: spec.patched ? patchFiles : null, oracleId: 'business-state', entry: scenario.entry, inputs: spec.inputs, budgets, expected: { outcome: spec.expected } });
  const legs = [
    leg('original-positive', mk({ patched: false, inputs: scenario.inputs, expected: EXPECT.original }), false, EXPECT.original),
    leg('patched-negative', mk({ patched: true, inputs: scenario.inputs, expected: EXPECT.patched }), true, EXPECT.patched),
    leg('workflow-baseline', mk({ patched: false, inputs: wfi, expected: EXPECT.workflowBaseline }), false, EXPECT.workflowBaseline),
    leg('workflow-preserved', mk({ patched: true, inputs: wfi, expected: EXPECT.workflow }), true, EXPECT.workflow),
    ...extraLegs,
  ];
  // the manifests rebuilt here must be the ones the verification actually ran: compare what each receipt pinned
  const pins = [['original', legs[0]], ['patched', legs[1]], ['functionalBaseline', legs[2]], ['functional', legs[3]]];
  for (const [role, l] of pins) {
    const r = pn.receipts?.[role];
    if (!r || r.request.inputsDigest !== l.manifest.inputsDigest || r.request.entry !== l.manifest.entry) return { ok: false, reason: `the ${role} manifest does not match the run the verification executed`, errors: [] };
  }
  const body = {
    schema: ARTIFACT_SCHEMA, schemaVersion: SCHEMA_VERSION, hypothesisId: scenario.id, commit,
    patch: { digest: digestOf(patchFiles), files: copy(patchFiles) },
    fixture: { digest: digestOf(fixtureFiles), files: copy(fixtureFiles) },
    invariant: { id: invariant.id, key: invariant.key, revision: invariant.revision, class: invariant.class, document: copy(invariant), approval },
    scenario: { id: scenario.id, digest: digestOf(scenario), document: copy(scenario), shrinkRecordId },
    legs,
    repair: { diffDigest: pn.patchDigest, ledger: copy(repairRecords) },
    scope: 'the declared exploit scenario, the declared authorized workflows and the bounded scenarios of the other approved contracts, on one disposable fixture; the patch is not shown correct anywhere else',
  };
  body.id = semanticId('rart', { ...body, legDigests: legs.map((l) => l.manifest.id) }, ['hypothesisId', 'commit', 'patch', 'invariant', 'legDigests']);
  body.artifactDigest = digestOf({ ...body });
  return { ok: true, artifact: body };
}

/** Structural and integrity check of an artifact, without executing anything. Never throws. */
function validateRegressionArtifact(a) {
  const errors = [];
  const fail = (code, message) => errors.push({ code, message });
  try {
    if (!(0,schema_kit/* isPlainObject */.Qd)(a) || a.schema !== ARTIFACT_SCHEMA) return { ok: false, errors: [{ code: 'malformed', message: 'not a regression artifact' }] };
    const { artifactDigest, ...rest } = a;
    if ((0,identity/* digestOf */.ol)(rest) !== artifactDigest) fail('artifact-tampered', 'the artifact does not match its digest');
    if ((0,identity/* digestOf */.ol)(a.patch?.files) !== a.patch?.digest) fail('patch-tampered', 'the patch files do not match the recorded patch digest');
    if ((0,identity/* digestOf */.ol)(a.fixture?.files) !== a.fixture?.digest) fail('fixture-tampered', 'the fixture files do not match the recorded fixture digest');
    if ((0,identity/* digestOf */.ol)(a.scenario?.document) !== a.scenario?.digest) fail('scenario-tampered', 'the scenario does not match its digest');
    if (a.scenario?.document?.fixtureDigest !== a.fixture?.digest) fail('fixture-pin-mismatch', 'the scenario pins a different fixture than the artifact carries');
    if (a.invariant?.document?.id !== a.invariant?.id) fail('invariant-mismatch', 'the invariant document does not match the recorded id');
    if (a.invariant?.approval?.state !== 'approved') fail('not-approved', 'the artifact records an invariant that was not approved');
    if (!Array.isArray(a.legs) || a.legs.length < 4) fail('legs-missing', 'the four required legs are not all present');
    for (const l of a.legs || []) {
      if (l.manifest?.repository?.commit !== a.commit) fail('leg-commit', `leg ${l.role} is pinned to a different commit`);
      if (l.manifest?.fixture?.digest !== a.fixture?.digest) fail('leg-fixture', `leg ${l.role} pins a different fixture`);
      const wantPatch = l.patched ? a.patch?.digest : null;
      if ((l.manifest?.patch?.digest ?? null) !== wantPatch) fail('leg-patch', `leg ${l.role} does not carry the artifact's exact patch`);
    }
    const roles = (a.legs || []).map((l) => l.role);
    for (const r of ['original-positive', 'patched-negative', 'workflow-baseline', 'workflow-preserved']) if (!roles.includes(r)) fail('leg-missing', `required leg '${r}' is absent`);
  } catch (e) {
    fail('malformed', `the check could not complete: ${String(e?.message || e).slice(0, 120)}`);
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Re-execute a regression artifact from the artifact alone. Passes only if every leg settles as recorded. Never throws.
 * @param {object} artifact
 * @param {object} [o]  { config, runOptions, hostEnvironment }
 * @returns {Promise<{ status: 'passed'|'failed'|'invalid'|'prerequisite-unmet'|'disabled', legs: object[], reasonCodes: string[], summary: string }>}
 */
async function runRegressionArtifact(artifact, o = {}) {
  const check = validateRegressionArtifact(artifact);
  if (!check.ok) return { status: 'invalid', legs: [], reasonCodes: [...new Set(check.errors.map((e) => e.code))], errors: check.errors, summary: `the artifact was not run: ${check.errors[0].message}` };
  const config = o.config || (0,assurance_config.resolveAssuranceConfig)({ env: process.env });
  for (const f of ['verification-oracles', scenarios/* FEATURE */.RI]) {
    const gate = (0,assurance_config/* featureStatus */.FX)(config, f);
    if (gate.status !== 'ok') return { status: 'disabled', legs: [], reasonCodes: ['feature-disabled'], summary: `${f} is not available: ${gate.reason}` };
  }
  const legs = [];
  let blocked = false;
  for (const l of artifact.legs) {
    const run = await runLeg(l.manifest, artifact.fixture.files, l.patched ? artifact.patch.files : null, { config, runOptions: o.runOptions, hostEnvironment: o.hostEnvironment });
    const awaiting = run.status === 'awaiting-prerequisites';
    if (awaiting) blocked = true;
    legs.push({ role: l.role, expected: l.expected, outcome: run.outcome ?? null, status: run.status, matched: run.status === 'completed' && run.outcome === l.expected, recordId: run.record?.id ?? null, receiptDigest: run.receipt?.receiptDigest ?? null, prerequisites: awaiting ? (run.prerequisites || []).map((p) => `${p.kind}:${p.id}:${p.state}`) : [] });
  }
  const failed = legs.filter((l) => !l.matched);
  const status = !failed.length ? 'passed' : blocked ? 'prerequisite-unmet' : 'failed';
  return {
    status, legs, reasonCodes: failed.map((l) => (l.status === 'completed' ? (l.role === 'original-positive' ? 'original-not-reproduced' : l.role === 'patched-negative' ? 'violation-not-eliminated' : l.role.startsWith('preserve:') ? 'invariant-regression' : 'workflow-regression') : 'setup-failed')),
    summary: status === 'passed' ? `all ${legs.length} legs settled as recorded` : `${failed.length} of ${legs.length} legs did not settle as recorded: ${failed.map((l) => `${l.role} (expected ${l.expected}, got ${l.outcome ?? l.status})`).join('; ')}`,
  };
}

// EXTERNAL MODULE: ./src/posture/invariants/project-input.js
var project_input = __webpack_require__(93211);
;// CONCATENATED MODULE: ./src/posture/invariants/cli.js
// `agentic-security invariants <export|coverage|regress>` (X-405 to X-407 CLI surface).
//
//   invariants export   --invariant <file> --fixture <dir> [--ledger <file>] [--commit <sha>] [--seed <n>] [--output <file>] [--json]
//       The reproducible scenario package for one contract (see export.js). Builds nothing and runs nothing when the
//       `invariant-scenarios` feature is off. Exit 0 ok, 1 refused (disabled, rejected, unsupported, blocked), 2 usage.
//   invariants coverage --invariant <file> | --invariants-dir <dir> [--ledger <file>] [--results <file>] [--json]
//       The bounded business-coverage report (see coverage.js). `--results` is a JSON array of `{ invariantId, result }` where
//       `result` is what `verifyInvariant` returned; without it the report is the static inventory with every contract's
//       transitions listed as untested, which is the honest answer when nothing was run. Exit 0, 1 refused, 2 usage.
//   invariants regress  <artifact.json>
//       Re-execute a regression artifact from the file alone (see repair.js). Exit 0 every leg settled as recorded, 1 a leg did
//       not (or the artifact is invalid), 3 not run (a prerequisite is unmet or the feature is off): not-run is not a pass.
//
// The logic lives here, not in bin/, so the same functions are exercised by tests without spawning the CLI; bin/ only
// dispatches. Paths are the operator's own and are resolved against the working directory (the MCP tool, which takes paths from
// an agent, confines them to its session root instead).








const USAGE = [
  'Usage: agentic-security invariants export   --invariant <file> --fixture <dir> [--ledger <file>] [--commit <sha>] [--seed <n>] [--output <file>] [--json]',
  '       agentic-security invariants coverage --invariant <file> | --invariants-dir <dir> [--ledger <file>] [--results <file>] [--json]',
  '       agentic-security invariants regress  <artifact.json>',
].join('\n');

const abs = (cwd, p) => external_node_path_.resolve(cwd, String(p));

/**
 * @param {{ _: string[], flags: object }} args  parsed arguments; `_[0]` is `invariants`, `_[1]` the sub-command
 * @param {{ cwd?: string, out?: (s: string) => void, err?: (s: string) => void, env?: object }} [io]
 * @returns {Promise<number>} the exit code
 */
async function runInvariantsCommand(args, io = {}) {
  const cwd = io.cwd || process.cwd();
  const out = io.out || ((s) => process.stdout.write(s));
  const err = io.err || ((s) => process.stderr.write(s));
  const sub = args._[1];
  const flags = args.flags || {};
  const config = (0,assurance_config.resolveAssuranceConfig)({ scanRoot: cwd, env: io.env || process.env });
  const emit = (value, lines) => out(flags.json ? `${JSON.stringify(value, null, 2)}\n` : `${lines.join('\n')}\n`);

  if (sub === 'export') {
    if (typeof flags.invariant !== 'string' || typeof flags.fixture !== 'string') { err(`${USAGE}\n`); return 2; }
    const r = (0,invariants_export/* exportFromFiles */.iF)({
      invariantPath: abs(cwd, flags.invariant), fixturePath: abs(cwd, flags.fixture), ledgerPath: typeof flags.ledger === 'string' ? abs(cwd, flags.ledger) : undefined,
      commit: typeof flags.commit === 'string' ? flags.commit : undefined, seed: flags.seed !== undefined ? Number(flags.seed) : undefined, config,
    });
    if (r.status !== 'ok') { err(`agentic-security invariants export: ${r.status}: ${r.reason ?? ''}\n`); return 1; }
    const text = `${JSON.stringify(r.export, null, 2)}\n`;
    if (typeof flags.output === 'string') {
      external_node_fs_.writeFileSync(abs(cwd, flags.output), text);
      out(`wrote ${r.export.scenarios.length} scenario(s) to ${flags.output}${r.withheld.length ? `; ${r.withheld.length} withheld (secret-looking content)` : ''}\n`);
    } else out(text);
    return 0;
  }

  if (sub === 'coverage') {
    let files = [];
    if (typeof flags.invariant === 'string') files = [abs(cwd, flags.invariant)];
    else if (typeof flags['invariants-dir'] === 'string') {
      try { files = external_node_fs_.readdirSync(abs(cwd, flags['invariants-dir'])).filter((f) => f.endsWith('.json')).sort().map((f) => external_node_path_.join(abs(cwd, flags['invariants-dir']), f)); } catch { err('agentic-security invariants coverage: the invariants directory is unreadable\n'); return 1; }
    } else { err(`${USAGE}\n`); return 2; }
    const docs = [];
    for (const f of files) {
      const j = (0,project_input/* readJsonFile */.J)(f);
      if (!j.ok) { err(`agentic-security invariants coverage: ${external_node_path_.basename(f)}: ${j.reason}\n`); return 1; }
      docs.push(j.value);
    }
    let ledger; let results = [];
    if (typeof flags.ledger === 'string') { const l = (0,project_input/* readJsonFile */.J)(abs(cwd, flags.ledger)); if (!l.ok) { err(`agentic-security invariants coverage: the ledger: ${l.reason}\n`); return 1; } ledger = l.value; }
    if (typeof flags.results === 'string') { const rr = (0,project_input/* readJsonFile */.J)(abs(cwd, flags.results)); if (!rr.ok || !Array.isArray(rr.value)) { err('agentic-security invariants coverage: --results must be a JSON array of { invariantId, result }\n'); return 1; } results = rr.value; }
    const byId = new Map(results.filter((x) => x && typeof x.invariantId === 'string').map((x) => [x.invariantId, x.result]));
    const cov = (0,coverage/* businessCoverage */.Hr)({ entries: docs.map((invariant) => ({ invariant, result: byId.get(invariant.id) ?? null })), ledger });
    emit(cov, cov.lines);
    return 0;
  }

  if (sub === 'regress') {
    const file = args._[2];
    if (!file) { err(`${USAGE}\n`); return 2; }
    const a = (0,project_input/* readJsonFile */.J)(abs(cwd, file));
    if (!a.ok) { err(`agentic-security invariants regress: ${a.reason}\n`); return 1; }
    const r = await runRegressionArtifact(a.value, { config });
    emit(r, [`regression artifact: ${r.status}`, r.summary, ...r.legs.map((l) => `  ${l.matched ? 'ok ' : 'FAIL'} ${l.role}: expected ${l.expected}, got ${l.outcome ?? l.status}`)]);
    return r.status === 'passed' ? 0 : (r.status === 'prerequisite-unmet' || r.status === 'disabled') ? 3 : 1;
  }

  err(`agentic-security invariants: unrecognized sub-command "${sub}"\n${USAGE}\n`);
  return 2;
}


/***/ }),

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
