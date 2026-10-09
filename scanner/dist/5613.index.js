export const id = 5613;
export const ids = [5613];
export const modules = {

/***/ 95613:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  verifyPatchNegative: () => (/* binding */ verifyPatchNegative)
});

// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: ./src/posture/assurance/schema-kit.js
var schema_kit = __webpack_require__(53353);
// EXTERNAL MODULE: ./src/posture/assurance/config.js
var assurance_config = __webpack_require__(90385);
// EXTERNAL MODULE: ./src/sandbox/capabilities.js
var capabilities = __webpack_require__(60450);
// EXTERNAL MODULE: ./src/posture/oracles/oracle.js + 4 modules
var oracles_oracle = __webpack_require__(80219);
// EXTERNAL MODULE: ./src/posture/oracles/registry.js + 1 modules
var registry = __webpack_require__(56239);
;// CONCATENATED MODULE: ./src/posture/replay/replay.js
// Replay manifests and environment identity (X-203).
//
// Extends the existing proof-of-concept sandbox path (a payload run under the
// confinement backend, judged by an observed effect) with an identity for the run
// and a way to repeat it. It is NOT a second sandbox or a second runner: a replay
// is an oracle run (`oracles/oracle.js`), which goes through `runInBoundary` and
// therefore through the supervised process tree, output cap and cleanup of
// CORE-003. What this module adds is the pinned, validated description of the run.
//
// A manifest pins: the repository commit, the patch hash, the fixture hash, the
// toolchain (and container digest when there is one), the oracle id, version and
// logic digest, the inputs and the budgets. Replaying it on the same supported
// environment reproduces the verdict, and the identical verification record id.
//
// Honesty rules, each with a test:
//   - A manifest is REJECTED, and nothing executes, when a content hash does not
//     match the content, when the oracle changed since the manifest was made, when
//     its scope asks for more than the oracle's declared scope (network, another
//     oracle, a write outside the workspace) or when a budget exceeds the oracle's
//     ceiling. The manifest is closed-world, so a field such as a model verdict
//     cannot ride along.
//   - A missing toolchain, container image or container runtime, or a disabled
//     feature, is a typed PREREQUISITE and the attempt is resumable. Nothing is
//     substituted for the execution that did not happen: the outcome is `not-run`
//     (or `unsupported` when this build can never meet it), with no evidence.
//   - This build never fetches anything. A prerequisite whose acquisition would
//     need the network is reported as such, with the network denied.
//   - Container execution is not implemented. A manifest pinning a container
//     digest is therefore `unsupported` here, never run outside the container it
//     names.
//   - Toolchain identity is exact (runtime version, platform, architecture). A
//     different patch release is a different environment, reported as an unmet
//     prerequisite rather than silently tolerated.






const REPLAY_SCHEMA = 'agentic-security/replay-manifest';
const ATTEMPT_SCHEMA = 'agentic-security/replay-attempt';
const MAX_ATTEMPTS = 10;

const ALLOWED = ['schema', 'schemaVersion', 'id', 'hypothesisId', 'repository', 'patch', 'fixture', 'toolchain', 'oracle', 'entry', 'inputs', 'inputsDigest', 'budgets', 'scope', 'expected'];
const REQUIRED = ['schema', 'schemaVersion', 'id', 'hypothesisId', 'repository', 'patch', 'fixture', 'toolchain', 'oracle', 'entry', 'inputs', 'inputsDigest', 'budgets', 'scope'];
const ID_FIELDS = ALLOWED.filter((k) => k !== 'id');
const REPLAY_BUDGET_KEYS = ['timeoutMs', 'graceMs', 'maxOutputBytes'];
const EXPECTED_OUTCOMES = ['confirmed', 'refuted', 'inconclusive'];

/** The pinned scope a replay may have: exactly the oracle it names, no network, workspace-only writes. */
function allowedScope(oracleId) {
  return { executes: [oracleId], network: false, writes: 'workspace-only' };
}

/** Sanitized identity of the execution environment: facts about the toolchain, nothing about the host. */
function environmentIdentity(overrides = {}) {
  const base = {
    runtime: 'node', version: process.versions.node, platform: process.platform, arch: process.arch,
    containerDigest: null, backend: (0,capabilities/* detectBackend */.kS)(),
  };
  const env = { ...base, ...overrides };
  return { ...env, toolchainDigest: (0,identity/* digestOf */.ol)({ runtime: env.runtime, version: env.version, platform: env.platform, arch: env.arch, containerDigest: env.containerDigest }) };
}

/**
 * Build a manifest from the pieces of a verification. The oracle identity and the
 * environment come from this build, not from the caller.
 */
function createReplayManifest({ hypothesisId, commit, fixtureFiles, patchFiles = null, oracleId, entry, inputs, budgets = {}, expected, environment }) {
  const oracle = registry.getOracle(oracleId);
  if (!oracle) throw new Error(`unknown oracle '${oracleId}'`);
  const env = environment || environmentIdentity();
  const m = {
    schema: REPLAY_SCHEMA, schemaVersion: schema_kit/* SCHEMA_VERSION */.f$, hypothesisId,
    repository: { commit },
    patch: patchFiles && Object.keys(patchFiles).length ? { digest: (0,identity/* digestOf */.ol)(patchFiles) } : null,
    fixture: { digest: (0,identity/* digestOf */.ol)(fixtureFiles) },
    toolchain: { runtime: env.runtime, version: env.version, platform: env.platform, arch: env.arch, containerDigest: env.containerDigest ?? null },
    oracle: { id: oracle.id, version: oracle.version, logicDigest: oracle.logicDigest },
    entry, inputs, inputsDigest: (0,identity/* digestOf */.ol)(inputs),
    budgets: { timeoutMs: oracle.budgets.timeoutMs, graceMs: oracle.budgets.graceMs, maxOutputBytes: oracle.budgets.maxOutputBytes, ...budgets },
    scope: allowedScope(oracle.id),
  };
  if (expected) m.expected = expected;
  m.id = manifestId(m);
  return m;
}

function manifestId(m) { return (0,identity/* semanticId */.YN)('rpl', m, ID_FIELDS); }

function err(errors, code, path, message) { errors.push({ code, path, message }); }

/**
 * Validate a manifest against the content it describes. Rejects, and the caller
 * must not execute, on any error. Pure: reads no file and runs nothing.
 */
function validateReplayManifest(m, { fixtureFiles, patchFiles = null } = {}) {
  const errors = [];
  if (!(0,schema_kit/* isPlainObject */.Qd)(m)) { err(errors, 'NOT_AN_OBJECT', '', 'manifest must be an object'); return { ok: false, errors }; }
  if (m.schema !== REPLAY_SCHEMA) { err(errors, 'SCHEMA_MISMATCH', 'schema', `expected '${REPLAY_SCHEMA}'`); return { ok: false, errors }; }
  if (typeof m.schemaVersion !== 'string' || m.schemaVersion.split('.')[0] !== '1') { err(errors, 'UNSUPPORTED_MAJOR', 'schemaVersion', 'only major version 1 is supported'); return { ok: false, errors }; }
  for (const k of Object.keys(m)) if (!ALLOWED.includes(k)) err(errors, 'UNKNOWN_FIELD', k, `field '${k}' is not part of a replay manifest`);
  for (const k of REQUIRED) if (m[k] === undefined) err(errors, 'MISSING_FIELD', k, `required field '${k}' is missing`);
  if (errors.length) return { ok: false, errors };

  if (typeof m.hypothesisId !== 'string' || !m.hypothesisId) err(errors, 'BAD_TYPE', 'hypothesisId', 'must be a non-empty string');
  if (!(0,schema_kit/* isPlainObject */.Qd)(m.repository) || !(0,schema_kit/* isCommit */.WM)(m.repository.commit)) err(errors, 'BAD_COMMIT', 'repository.commit', 'a replay pins an exact 40 or 64 character commit');
  if (!(0,schema_kit/* isPlainObject */.Qd)(m.fixture) || !(0,schema_kit/* isDigest */.Bc)(m.fixture.digest)) err(errors, 'BAD_DIGEST', 'fixture.digest', 'must be sha256:<64 hex>');
  else if (!(0,schema_kit/* isPlainObject */.Qd)(fixtureFiles) || (0,identity/* digestOf */.ol)(fixtureFiles) !== m.fixture.digest) err(errors, 'HASH_MISMATCH', 'fixture.digest', 'the fixture content does not match its pinned hash');
  const havePatch = (0,schema_kit/* isPlainObject */.Qd)(patchFiles) && Object.keys(patchFiles).length > 0;
  if (m.patch === null) {
    if (havePatch) err(errors, 'HASH_MISMATCH', 'patch', 'patch content was supplied but the manifest pins no patch');
  } else if (!(0,schema_kit/* isPlainObject */.Qd)(m.patch) || !(0,schema_kit/* isDigest */.Bc)(m.patch.digest)) err(errors, 'BAD_DIGEST', 'patch.digest', 'must be null or { digest: sha256:<64 hex> }');
  else if (!havePatch || (0,identity/* digestOf */.ol)(patchFiles) !== m.patch.digest) err(errors, 'HASH_MISMATCH', 'patch.digest', 'the patch content does not match its pinned hash');
  if (!(0,schema_kit/* isDigest */.Bc)(m.inputsDigest) || !(0,schema_kit/* isPlainObject */.Qd)(m.inputs) || (0,identity/* digestOf */.ol)(m.inputs) !== m.inputsDigest) err(errors, 'HASH_MISMATCH', 'inputsDigest', 'the inputs do not match their pinned hash');

  // Paths are part of the allowed execution scope: a fixture or patch that names a file outside the workspace is refused here,
  // before anything can run, even when its hash matches.
  for (const [label, files] of [['fixture', fixtureFiles], ['patch', patchFiles]]) {
    for (const rel of Object.keys((0,schema_kit/* isPlainObject */.Qd)(files) ? files : {})) {
      if (!(0,oracles_oracle/* isSafeRelativePath */.VH)(rel)) err(errors, 'SCOPE_VIOLATION', `${label}.files`, `path ${JSON.stringify(String(rel).slice(0, 60))} is not a safe relative path inside the workspace`);
    }
  }
  if (typeof m.entry === 'string' && (0,schema_kit/* isPlainObject */.Qd)(fixtureFiles) && !(m.entry in { ...fixtureFiles, ...((0,schema_kit/* isPlainObject */.Qd)(patchFiles) ? patchFiles : {}) })) err(errors, 'SCOPE_VIOLATION', 'entry', 'the entry must be one of the pinned files');

  const tc = m.toolchain;
  if (!(0,schema_kit/* isPlainObject */.Qd)(tc) || tc.runtime !== 'node' || typeof tc.version !== 'string' || typeof tc.platform !== 'string' || typeof tc.arch !== 'string') err(errors, 'BAD_TYPE', 'toolchain', 'needs runtime node, version, platform and arch');
  else if (tc.containerDigest !== null && !(0,schema_kit/* isDigest */.Bc)(tc.containerDigest)) err(errors, 'BAD_DIGEST', 'toolchain.containerDigest', 'must be null or sha256:<64 hex>');

  const oracle = (0,schema_kit/* isPlainObject */.Qd)(m.oracle) ? registry.getOracle(m.oracle.id) : null;
  if (!oracle) err(errors, 'UNKNOWN_ORACLE', 'oracle.id', 'the manifest names an oracle this build does not have');
  else {
    if (m.oracle.version !== oracle.version || m.oracle.logicDigest !== oracle.logicDigest) err(errors, 'ORACLE_MISMATCH', 'oracle', 'the oracle version or logic digest differs from the pinned one: this is not the oracle the manifest was made with');
    const sc = m.scope;
    const want = allowedScope(oracle.id);
    if (!(0,schema_kit/* isPlainObject */.Qd)(sc) || Object.keys(sc).some((k) => !(k in want))) err(errors, 'SCOPE_VIOLATION', 'scope', 'unknown scope keys');
    else {
      if (JSON.stringify(sc.executes) !== JSON.stringify(want.executes)) err(errors, 'SCOPE_VIOLATION', 'scope.executes', 'a replay may execute only the oracle it names');
      if (sc.network !== false) err(errors, 'SCOPE_VIOLATION', 'scope.network', 'replay grants no network access');
      if (sc.writes !== 'workspace-only') err(errors, 'SCOPE_VIOLATION', 'scope.writes', 'replay writes only inside its workspace');
    }
    const b = m.budgets;
    if (!(0,schema_kit/* isPlainObject */.Qd)(b)) err(errors, 'BAD_TYPE', 'budgets', 'must be an object');
    else {
      for (const k of Object.keys(b)) if (!REPLAY_BUDGET_KEYS.includes(k)) err(errors, 'UNKNOWN_FIELD', `budgets.${k}`, 'not a replay budget');
      for (const k of REPLAY_BUDGET_KEYS) {
        if (!Number.isInteger(b[k]) || b[k] < 1) err(errors, 'BAD_TYPE', `budgets.${k}`, 'must be a positive integer');
        else if (b[k] > oracle.budgets[k]) err(errors, 'BUDGET_EXCEEDED', `budgets.${k}`, `exceeds the oracle ceiling of ${oracle.budgets[k]}`);
      }
    }
  }
  if (typeof m.entry !== 'string' || !m.entry) err(errors, 'BAD_TYPE', 'entry', 'must be a non-empty string');
  if (m.expected !== undefined && (!(0,schema_kit/* isPlainObject */.Qd)(m.expected) || Object.keys(m.expected).some((k) => k !== 'outcome') || !EXPECTED_OUTCOMES.includes(m.expected.outcome))) err(errors, 'BAD_TYPE', 'expected', `must be { outcome: one of ${EXPECTED_OUTCOMES.join(', ')} }`);
  if (m.id !== manifestId(m)) err(errors, 'ID_MISMATCH', 'id', 'the manifest id does not match its content');
  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------- prerequisites

/**
 * Typed prerequisites that are not met on this host. `resumable` is true when
 * meeting it is something an operator can do (install a toolchain, enable the
 * feature) and false when this build cannot meet it at all.
 */
function unmetPrerequisites(m, host = environmentIdentity()) {
  const out = [];
  const tc = m.toolchain;
  if (tc.containerDigest !== null) {
    out.push({ kind: 'container-runtime', id: tc.containerDigest, state: 'unsupported', resumable: false, reason: 'container execution is not implemented in this build; the run is never executed outside the container the manifest names' });
    out.push({ kind: 'container-image', id: tc.containerDigest, state: 'missing', resumable: false, reason: 'this build neither holds nor pulls container images' });
    out.push({ kind: 'network', id: 'image-acquisition', state: 'denied', resumable: false, reason: 'acquiring a container image needs network access, which replay does not grant' });
  }
  if (tc.version !== host.version || tc.platform !== host.platform || tc.arch !== host.arch) {
    out.push({
      kind: 'toolchain', id: `${tc.runtime}@${tc.version} ${tc.platform}/${tc.arch}`, state: 'missing', resumable: true,
      reason: `this host runs ${host.runtime}@${host.version} ${host.platform}/${host.arch}; the manifest pins an exact toolchain`,
    });
    out.push({ kind: 'network', id: 'toolchain-acquisition', state: 'denied', resumable: true, reason: 'installing the pinned toolchain needs network access, which replay does not grant; install it out of band and resume' });
  }
  return out;
}

function nextAttempt(resume, manifestId_) {
  if (resume === undefined || resume === null) return { n: 1, history: [] };
  if (!(0,schema_kit/* isPlainObject */.Qd)(resume) || resume.schema !== ATTEMPT_SCHEMA || resume.manifestId !== manifestId_) return { error: 'the attempt does not belong to this manifest' };
  if (resume.status !== 'awaiting-prerequisites') return { error: `an attempt in status '${resume.status}' is not resumable` };
  if (!Number.isInteger(resume.attempt) || resume.attempt < 1 || !Array.isArray(resume.history)) return { error: 'the attempt record is malformed' };
  if (resume.attempt >= MAX_ATTEMPTS) return { error: `the attempt limit of ${MAX_ATTEMPTS} was reached` };
  return { n: resume.attempt + 1, history: resume.history.slice(-MAX_ATTEMPTS) };
}

function attemptRecord(manifestId_, n, history, status, entry) {
  return { schema: ATTEMPT_SCHEMA, manifestId: manifestId_, attempt: n, status, history: [...history, { attempt: n, ...entry }] };
}

/**
 * Replay a manifest. Never throws.
 *
 * @param {object} bundle { manifest, fixtureFiles, patchFiles? }
 * @param {object} [o]
 * @param {object} [o.resume]  an attempt returned earlier with status 'awaiting-prerequisites'
 * @param {object} [o.hostEnvironment] environment identity override (test seam)
 * @param {object} [o.config]  assurance config (the verification-oracles feature is off by default)
 * @param {object} [o.runOptions] passed to runOracle (test seams: deps, probeEnv, signal)
 * @returns {Promise<object>} { status: 'completed'|'awaiting-prerequisites'|'rejected', executed, outcome, record, receipt, reproduced, prerequisites, attempt, errors }
 */
async function replayManifest(bundle, o = {}) {
  const { manifest, fixtureFiles, patchFiles = null } = bundle || {};
  const valid = validateReplayManifest(manifest, { fixtureFiles, patchFiles });
  if (!valid.ok) return { status: 'rejected', executed: false, outcome: null, record: null, receipt: null, reproduced: null, prerequisites: [], attempt: null, errors: valid.errors };

  const step = nextAttempt(o.resume, manifest.id);
  if (step.error) return { status: 'rejected', executed: false, outcome: null, record: null, receipt: null, reproduced: null, prerequisites: [], attempt: null, errors: [{ code: 'ATTEMPT_REJECTED', path: 'resume', message: step.error }] };

  const request = {
    oracleId: manifest.oracle.id, hypothesisId: manifest.hypothesisId, commit: manifest.repository.commit,
    files: { ...fixtureFiles, ...(patchFiles || {}) }, entry: manifest.entry, inputs: manifest.inputs, attempt: step.n,
    budgets: manifest.budgets,
  };
  const waiting = (prerequisites, outcome, reason) => {
    const record = (0,oracles_oracle/* recordWithoutExecution */.Wp)(manifest.oracle.id, request, outcome, reason, registry);
    return {
      status: 'awaiting-prerequisites', executed: false, outcome, record, receipt: null, reproduced: null, prerequisites, errors: [],
      attempt: attemptRecord(manifest.id, step.n, step.history, 'awaiting-prerequisites', { outcome, prerequisites: prerequisites.map((p) => `${p.kind}:${p.state}`) }),
    };
  };

  const unmet = unmetPrerequisites(manifest, o.hostEnvironment || environmentIdentity());
  if (unmet.length) {
    const never = unmet.some((p) => !p.resumable);
    return waiting(unmet, never ? 'unsupported' : 'not-run', `replay prerequisite(s) not met: ${unmet.map((p) => `${p.kind} ${p.id} (${p.state})`).join('; ')}; nothing was executed`);
  }

  const run = await (0,oracles_oracle/* runOracle */.qm)(request, { config: o.config, ...(o.runOptions || {}) });
  if (run.status === 'rejected') return { status: 'rejected', executed: false, outcome: null, record: null, receipt: null, reproduced: null, prerequisites: [], attempt: null, errors: (run.errors || []).map((m) => ({ code: 'REQUEST_REJECTED', path: '', message: m })) };
  if (!run.executed) {
    const feature = run.status === 'disabled';
    const prereq = feature
      ? [{ kind: 'feature', id: oracles_oracle/* FEATURE_ID */.DU, state: 'disabled', resumable: true, reason: run.reason }]
      : (run.prerequisites || [{ id: 'trust-boundary', reason: run.reason }]).map((p) => ({ kind: p.id === 'trust-boundary' ? 'trust-boundary' : 'oracle-prerequisite', id: p.id, state: 'unmet', resumable: false, reason: p.reason }));
    return waiting(prereq, run.outcome === 'unsupported' ? 'unsupported' : 'not-run', run.reason);
  }
  const reproduced = manifest.expected ? run.outcome === manifest.expected.outcome : null;
  return {
    status: 'completed', executed: true, outcome: run.outcome, record: run.record, receipt: run.receipt, reproduced, disclosure: run.disclosure,
    prerequisites: [], errors: [], run: run.run, environment: run.environment,
    attempt: attemptRecord(manifest.id, step.n, step.history, 'completed', { outcome: run.outcome }),
  };
}

// EXTERNAL MODULE: ./src/posture/verification/patch-promotion.js
var patch_promotion = __webpack_require__(51487);
// EXTERNAL MODULE: ./src/posture/verification/repair-records.js
var repair_records = __webpack_require__(38899);
;// CONCATENATED MODULE: ./src/posture/verification/patch-negative.js
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
// Scope, stated so no caller overclaims: the exploit scenario and the functional cases are the REQUESTER's; this verifies the
// declared scenario and cases, not that the patch is correct elsewhere. Linux is not claimed (the oracle platform statements
// stay `unverified`). Receipts are valid inside this process only (see patch-promotion.js).








const PATCH_NEGATIVE_FEATURE = 'patch-negative-verification';
const FUNCTIONAL_ORACLE = 'functional-regression';

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
  const loadBroken = observed.targetLoaded === false || observed.benignCompleted === false;
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
  const config = o.config || (0,assurance_config/* resolveAssuranceConfig */.cc)({ env: process.env });
  const gate = (0,assurance_config/* featureStatus */.FX)(config, PATCH_NEGATIVE_FEATURE);
  const steps = STEPS.map((s) => stepResult(s, 'not-run', { reason: 'not reached' }));
  const base = {
    status: 'not-verified-fix', verifiedFix: false, incompleteStep: null, failureCode: null, reason: null, steps,
    patchDigest: null, promotion: null, receipts: null, records: {}, verificationRecord: null, repairRecords: Array.isArray(req?.ledger) ? req.ledger : [], summary: '',
  };
  if (gate.status !== 'ok') {
    return { ...base, status: 'disabled', incompleteStep: 'feature-gate', failureCode: gate.code || 'disabled', reason: `${PATCH_NEGATIVE_FEATURE} is not available: ${gate.reason}`, summary: `patch-negative verification did not run: ${gate.reason}` };
  }
  const refuse = (step, code, reason, extra = {}) => {
    const rejected = req && (0,schema_kit/* isPlainObject */.Qd)(req.patch) && (0,schema_kit/* isPlainObject */.Qd)(req.patch.files) && Object.keys(req.patch.files).length && typeof req.hypothesisId === 'string'
      ? ledgerFor(base.repairRecords, req, base.patchDigest ?? (0,identity/* digestOf */.ol)(req.patch.files), { rejected: { step, code, reason } }) : { records: base.repairRecords };
    return { ...base, ...extra, patchDigest: req?.patch?.files ? (0,identity/* digestOf */.ol)(req.patch.files) : null, incompleteStep: step, failureCode: code, reason, repairRecords: rejected.records, summary: summaryOf(steps, false, step, code) };
  };

  // ---- shape and preconditions that need no execution
  const patchFiles = req?.patch?.files;
  if (!(0,schema_kit/* isPlainObject */.Qd)(req) || typeof req.hypothesisId !== 'string' || !req.hypothesisId || !(0,schema_kit/* isPlainObject */.Qd)(req.original) || !(0,schema_kit/* isPlainObject */.Qd)(req.original.files)
    || typeof req.original.entry !== 'string' || typeof req.original.oracleId !== 'string' || !(0,schema_kit/* isPlainObject */.Qd)(req.original.inputs)
    || !(0,schema_kit/* isPlainObject */.Qd)(patchFiles) || Object.keys(patchFiles).length === 0) {
    return refuse('input-validation', 'bad-request', 'a request needs a hypothesis id, the original files, entry, oracle and inputs, and a non-empty patch');
  }
  if (!(0,schema_kit/* isCommit */.WM)(req.commit)) return refuse('input-validation', 'revision-unbound', 'no exact commit was given: a verdict cannot be tied to a revision');
  const original = req.original;
  const oracle = registry.getOracle(original.oracleId);
  if (!oracle) return refuse('input-validation', 'unknown-oracle', `the exploit oracle '${String(original.oracleId).slice(0, 60)}' is not registered`);
  if (oracle.id === FUNCTIONAL_ORACLE) return refuse('input-validation', 'bad-request', 'the exploit oracle cannot be the functional-regression oracle');
  const patched = (0,schema_kit/* isPlainObject */.Qd)(req.patched) ? req.patched : {};
  if ((patched.oracleId !== undefined && patched.oracleId !== original.oracleId) || (patched.inputs !== undefined && (0,identity/* digestOf */.ol)(patched.inputs) !== (0,identity/* digestOf */.ol)(original.inputs)) || (patched.entry !== undefined && patched.entry !== original.entry)) {
    return refuse('oracle-consistency', 'oracle-changed', 'the patched run names a different oracle, entry or inputs than the original run: a changed oracle cannot show the exploit is closed');
  }
  const pin = req.pinnedOracle;
  if (pin !== undefined && (!(0,schema_kit/* isPlainObject */.Qd)(pin) || pin.id !== oracle.id || pin.version !== oracle.version || pin.logicDigest !== oracle.logicDigest)) {
    return refuse('oracle-consistency', 'oracle-changed', 'the oracle differs from the identity the requester pinned (id, version or logic digest)');
  }
  const fn = req.functional;
  if (!(0,schema_kit/* isPlainObject */.Qd)(fn) || !(0,schema_kit/* isPlainObject */.Qd)(fn.inputs)) {
    return refuse('functional-regression', 'functional-omitted', 'no functional regression check was supplied: a patch that was never checked for behaviour cannot be a verified fix');
  }

  const patchDigest = (0,identity/* digestOf */.ol)(patchFiles);
  base.patchDigest = patchDigest;
  let ledger = ledgerFor(base.repairRecords, req, patchDigest, {}).records; // proposed
  const common = { hypothesisId: req.hypothesisId, commit: req.commit };
  const plan = [
    ['original-positive', { oracleId: original.oracleId, entry: original.entry, inputs: original.inputs, patchFiles: null, budgets: original.budgets }],
    ['patched-negative', { oracleId: original.oracleId, entry: original.entry, inputs: original.inputs, patchFiles, budgets: original.budgets }],
    ['functional-baseline', { oracleId: FUNCTIONAL_ORACLE, entry: original.entry, inputs: fn.inputs, patchFiles: null, budgets: fn.budgets }],
    ['functional-regression', { oracleId: FUNCTIONAL_ORACLE, entry: original.entry, inputs: fn.inputs, patchFiles, budgets: fn.budgets }],
  ];
  const runs = {};
  let failed = null;
  for (const [i, [step, spec]] of plan.entries()) {
    if (failed) continue;
    let run;
    try {
      const manifest = createReplayManifest({ ...common, fixtureFiles: original.files, patchFiles: spec.patchFiles, oracleId: spec.oracleId, entry: spec.entry, inputs: spec.inputs, budgets: spec.budgets || {}, expected: { outcome: EXPECTED[step] } });
      run = await replayManifest({ manifest, fixtureFiles: original.files, patchFiles: spec.patchFiles }, { config: o.config || config, runOptions: o.runOptions });
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
    const original0 = base.records.original ? (0,repair_records/* withRepairStatus */.m$)(base.records.original, (0,repair_records/* verificationRepairFor */.Kf)(ledger, req.hypothesisId, patchDigest)) : null;
    return { ...base, incompleteStep: failed.step, failureCode: failed.code, reason: failed.reason, resumable: failed.resumable ?? false, repairRecords: ledger, verificationRecord: original0, summary: summaryOf(steps, false, failed.step, failed.code) };
  }

  // ---- the receipts must match the exact proposed diff and revision before anything is promoted
  const receipts = Object.fromEntries(Object.entries(runs).map(([k, r]) => [k, r.receipt]));
  const promotion = (0,patch_promotion/* promotePatch */.l)({ proposal: { hypothesisId: req.hypothesisId, revision: req.commit, originalFiles: original.files, patchFiles }, receipts });
  if (!promotion.ok) {
    const envBroken = promotion.reasons.some((r) => r.code === 'environment-mismatch');
    const code = envBroken ? 'environment-mismatch' : promotion.reasons.some((r) => r.code === 'oracle-changed') ? 'oracle-changed' : 'promotion-refused';
    const step = envBroken ? 'environment-equivalence' : code === 'oracle-changed' ? 'oracle-consistency' : 'promotion';
    const reason = promotion.reasons.map((r) => r.message).join('; ').slice(0, 400);
    ledger = ledgerFor(ledger, req, patchDigest, { rejected: { step, code, reason } }).records;
    return { ...base, promotion, incompleteStep: step, failureCode: code, reason, repairRecords: ledger, verificationRecord: base.records.original ? (0,repair_records/* withRepairStatus */.m$)(base.records.original, (0,repair_records/* verificationRepairFor */.Kf)(ledger, req.hypothesisId, patchDigest)) : null, summary: summaryOf(steps, false, step, code) };
  }
  const promoted = (0,repair_records/* recordPromotion */.Zw)(ledger, promotion, { verificationRecordId: base.records.patched?.id ?? null });
  ledger = promoted.records;
  const verificationRecord = (0,repair_records/* withRepairStatus */.m$)(base.records.original, (0,repair_records/* verificationRepairFor */.Kf)(ledger, req.hypothesisId, patchDigest, base.records.patched?.id));
  return {
    ...base, status: 'verified-fix', verifiedFix: true, promotion, receipts, repairRecords: ledger, verificationRecord,
    reason: 'verified', summary: summaryOf(steps, true, null, null),
  };
}

// The ledger for one verification: always starts with a `proposed` record, and records a rejection when verification stopped.
function ledgerFor(records, req, patchDigest, { rejected } = {}) {
  let list = Array.isArray(records) ? records : [];
  const fields = { hypothesisId: req.hypothesisId, revision: (0,schema_kit/* isCommit */.WM)(req.commit) ? req.commit : null, diffDigest: patchDigest };
  if (!list.some((r) => r.hypothesisId === fields.hypothesisId && r.diffDigest === patchDigest)) list = (0,repair_records/* appendRepairRecord */.f7)(list, { ...fields, kind: 'proposed', reason: 'a patch was proposed for verification' }).records;
  if (rejected) list = (0,repair_records/* appendRepairRecord */.f7)(list, { ...fields, kind: 'rejected', step: rejected.step, reason: `${rejected.code}: ${String(rejected.reason || '').slice(0, 300)}` }).records;
  return { records: list };
}


/***/ })

};
