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
import { digestOf, semanticId } from '../assurance/identity.js';
import { SCHEMA_VERSION, isPlainObject, isCommit } from '../assurance/schema-kit.js';
import { featureStatus, resolveAssuranceConfig } from '../assurance/config.js';
import { createReplayManifest, replayManifest } from '../replay/replay.js';
import { verifyPatchNegative } from '../verification/patch-negative.js';
import { appendRepairRecord, verificationRepairFor, withRepairStatus } from '../verification/repair-records.js';
import { validateInvariant } from './schema.js';
import { verifyLedger } from './lifecycle.js';
import { generateScenarios, FEATURE } from './scenarios.js';
import { findSecrets } from './export.js';

const ARTIFACT_SCHEMA = 'agentic-security/invariant-regression-artifact';
export const REASON_CODES = Object.freeze([
  'feature-disabled', 'bad-request', 'invariant-not-approved', 'setup-failed', 'unsupported-check', 'original-not-reproduced',
  'violation-not-eliminated', 'authorized-workflow-broken', 'workflow-regression', 'workflow-check-inconclusive', 'workflow-baseline-invalid',
  'invariant-regression', 'preservation-inconclusive', 'preservation-unsupported', 'patched-check-inconclusive',
  'oracle-changed', 'environment-mismatch', 'promotion-refused', 'revision-unbound', 'artifact-refused',
]);
const REQUIRED_FEATURES = Object.freeze([FEATURE, 'verification-oracles', 'patch-negative-verification']);
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
export function reasonCodeFor(failureCode) { return CODE_OF[failureCode] || 'setup-failed'; }

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
    return await replayManifest({ manifest, fixtureFiles, patchFiles }, { config: o.config, runOptions: o.runOptions, hostEnvironment: o.hostEnvironment });
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
export async function verifyInvariantRepair(req, o = {}) {
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
export function validateRegressionArtifact(a) {
  const errors = [];
  const fail = (code, message) => errors.push({ code, message });
  try {
    if (!isPlainObject(a) || a.schema !== ARTIFACT_SCHEMA) return { ok: false, errors: [{ code: 'malformed', message: 'not a regression artifact' }] };
    const { artifactDigest, ...rest } = a;
    if (digestOf(rest) !== artifactDigest) fail('artifact-tampered', 'the artifact does not match its digest');
    if (digestOf(a.patch?.files) !== a.patch?.digest) fail('patch-tampered', 'the patch files do not match the recorded patch digest');
    if (digestOf(a.fixture?.files) !== a.fixture?.digest) fail('fixture-tampered', 'the fixture files do not match the recorded fixture digest');
    if (digestOf(a.scenario?.document) !== a.scenario?.digest) fail('scenario-tampered', 'the scenario does not match its digest');
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
export async function runRegressionArtifact(artifact, o = {}) {
  const check = validateRegressionArtifact(artifact);
  if (!check.ok) return { status: 'invalid', legs: [], reasonCodes: [...new Set(check.errors.map((e) => e.code))], errors: check.errors, summary: `the artifact was not run: ${check.errors[0].message}` };
  const config = o.config || resolveAssuranceConfig({ env: process.env });
  for (const f of ['verification-oracles', FEATURE]) {
    const gate = featureStatus(config, f);
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
