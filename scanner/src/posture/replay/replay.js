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
import { digestOf, semanticId } from '../assurance/identity.js';
import { SCHEMA_VERSION, isCommit, isDigest, isPlainObject } from '../assurance/schema-kit.js';
import { detectBackend } from '../../sandbox/capabilities.js';
import { runOracle, recordWithoutExecution, isSafeRelativePath, FEATURE_ID } from '../oracles/oracle.js';
import * as registry from '../oracles/registry.js';

export const REPLAY_SCHEMA = 'agentic-security/replay-manifest';
export const ATTEMPT_SCHEMA = 'agentic-security/replay-attempt';
export const MAX_ATTEMPTS = 10;

const ALLOWED = ['schema', 'schemaVersion', 'id', 'hypothesisId', 'repository', 'patch', 'fixture', 'toolchain', 'oracle', 'entry', 'inputs', 'inputsDigest', 'budgets', 'scope', 'expected'];
const REQUIRED = ['schema', 'schemaVersion', 'id', 'hypothesisId', 'repository', 'patch', 'fixture', 'toolchain', 'oracle', 'entry', 'inputs', 'inputsDigest', 'budgets', 'scope'];
const ID_FIELDS = ALLOWED.filter((k) => k !== 'id');
const REPLAY_BUDGET_KEYS = ['timeoutMs', 'graceMs', 'maxOutputBytes'];
const EXPECTED_OUTCOMES = ['confirmed', 'refuted', 'inconclusive'];

/** The pinned scope a replay may have: exactly the oracle it names, no network, workspace-only writes. */
export function allowedScope(oracleId) {
  return { executes: [oracleId], network: false, writes: 'workspace-only' };
}

/** Sanitized identity of the execution environment: facts about the toolchain, nothing about the host. */
export function environmentIdentity(overrides = {}) {
  const base = {
    runtime: 'node', version: process.versions.node, platform: process.platform, arch: process.arch,
    containerDigest: null, backend: detectBackend(),
  };
  const env = { ...base, ...overrides };
  return { ...env, toolchainDigest: digestOf({ runtime: env.runtime, version: env.version, platform: env.platform, arch: env.arch, containerDigest: env.containerDigest }) };
}

/**
 * Build a manifest from the pieces of a verification. The oracle identity and the
 * environment come from this build, not from the caller.
 */
export function createReplayManifest({ hypothesisId, commit, fixtureFiles, patchFiles = null, oracleId, entry, inputs, budgets = {}, expected, environment }) {
  const oracle = registry.getOracle(oracleId);
  if (!oracle) throw new Error(`unknown oracle '${oracleId}'`);
  const env = environment || environmentIdentity();
  const m = {
    schema: REPLAY_SCHEMA, schemaVersion: SCHEMA_VERSION, hypothesisId,
    repository: { commit },
    patch: patchFiles && Object.keys(patchFiles).length ? { digest: digestOf(patchFiles) } : null,
    fixture: { digest: digestOf(fixtureFiles) },
    toolchain: { runtime: env.runtime, version: env.version, platform: env.platform, arch: env.arch, containerDigest: env.containerDigest ?? null },
    oracle: { id: oracle.id, version: oracle.version, logicDigest: oracle.logicDigest },
    entry, inputs, inputsDigest: digestOf(inputs),
    budgets: { timeoutMs: oracle.budgets.timeoutMs, graceMs: oracle.budgets.graceMs, maxOutputBytes: oracle.budgets.maxOutputBytes, ...budgets },
    scope: allowedScope(oracle.id),
  };
  if (expected) m.expected = expected;
  m.id = manifestId(m);
  return m;
}

export function manifestId(m) { return semanticId('rpl', m, ID_FIELDS); }

function err(errors, code, path, message) { errors.push({ code, path, message }); }

/**
 * Validate a manifest against the content it describes. Rejects, and the caller
 * must not execute, on any error. Pure: reads no file and runs nothing.
 */
export function validateReplayManifest(m, { fixtureFiles, patchFiles = null } = {}) {
  const errors = [];
  if (!isPlainObject(m)) { err(errors, 'NOT_AN_OBJECT', '', 'manifest must be an object'); return { ok: false, errors }; }
  if (m.schema !== REPLAY_SCHEMA) { err(errors, 'SCHEMA_MISMATCH', 'schema', `expected '${REPLAY_SCHEMA}'`); return { ok: false, errors }; }
  if (typeof m.schemaVersion !== 'string' || m.schemaVersion.split('.')[0] !== '1') { err(errors, 'UNSUPPORTED_MAJOR', 'schemaVersion', 'only major version 1 is supported'); return { ok: false, errors }; }
  for (const k of Object.keys(m)) if (!ALLOWED.includes(k)) err(errors, 'UNKNOWN_FIELD', k, `field '${k}' is not part of a replay manifest`);
  for (const k of REQUIRED) if (m[k] === undefined) err(errors, 'MISSING_FIELD', k, `required field '${k}' is missing`);
  if (errors.length) return { ok: false, errors };

  if (typeof m.hypothesisId !== 'string' || !m.hypothesisId) err(errors, 'BAD_TYPE', 'hypothesisId', 'must be a non-empty string');
  if (!isPlainObject(m.repository) || !isCommit(m.repository.commit)) err(errors, 'BAD_COMMIT', 'repository.commit', 'a replay pins an exact 40 or 64 character commit');
  if (!isPlainObject(m.fixture) || !isDigest(m.fixture.digest)) err(errors, 'BAD_DIGEST', 'fixture.digest', 'must be sha256:<64 hex>');
  else if (!isPlainObject(fixtureFiles) || digestOf(fixtureFiles) !== m.fixture.digest) err(errors, 'HASH_MISMATCH', 'fixture.digest', 'the fixture content does not match its pinned hash');
  const havePatch = isPlainObject(patchFiles) && Object.keys(patchFiles).length > 0;
  if (m.patch === null) {
    if (havePatch) err(errors, 'HASH_MISMATCH', 'patch', 'patch content was supplied but the manifest pins no patch');
  } else if (!isPlainObject(m.patch) || !isDigest(m.patch.digest)) err(errors, 'BAD_DIGEST', 'patch.digest', 'must be null or { digest: sha256:<64 hex> }');
  else if (!havePatch || digestOf(patchFiles) !== m.patch.digest) err(errors, 'HASH_MISMATCH', 'patch.digest', 'the patch content does not match its pinned hash');
  if (!isDigest(m.inputsDigest) || !isPlainObject(m.inputs) || digestOf(m.inputs) !== m.inputsDigest) err(errors, 'HASH_MISMATCH', 'inputsDigest', 'the inputs do not match their pinned hash');

  // Paths are part of the allowed execution scope: a fixture or patch that names a file outside the workspace is refused here,
  // before anything can run, even when its hash matches.
  for (const [label, files] of [['fixture', fixtureFiles], ['patch', patchFiles]]) {
    for (const rel of Object.keys(isPlainObject(files) ? files : {})) {
      if (!isSafeRelativePath(rel)) err(errors, 'SCOPE_VIOLATION', `${label}.files`, `path ${JSON.stringify(String(rel).slice(0, 60))} is not a safe relative path inside the workspace`);
    }
  }
  if (typeof m.entry === 'string' && isPlainObject(fixtureFiles) && !(m.entry in { ...fixtureFiles, ...(isPlainObject(patchFiles) ? patchFiles : {}) })) err(errors, 'SCOPE_VIOLATION', 'entry', 'the entry must be one of the pinned files');

  const tc = m.toolchain;
  if (!isPlainObject(tc) || tc.runtime !== 'node' || typeof tc.version !== 'string' || typeof tc.platform !== 'string' || typeof tc.arch !== 'string') err(errors, 'BAD_TYPE', 'toolchain', 'needs runtime node, version, platform and arch');
  else if (tc.containerDigest !== null && !isDigest(tc.containerDigest)) err(errors, 'BAD_DIGEST', 'toolchain.containerDigest', 'must be null or sha256:<64 hex>');

  const oracle = isPlainObject(m.oracle) ? registry.getOracle(m.oracle.id) : null;
  if (!oracle) err(errors, 'UNKNOWN_ORACLE', 'oracle.id', 'the manifest names an oracle this build does not have');
  else {
    if (m.oracle.version !== oracle.version || m.oracle.logicDigest !== oracle.logicDigest) err(errors, 'ORACLE_MISMATCH', 'oracle', 'the oracle version or logic digest differs from the pinned one: this is not the oracle the manifest was made with');
    const sc = m.scope;
    const want = allowedScope(oracle.id);
    if (!isPlainObject(sc) || Object.keys(sc).some((k) => !(k in want))) err(errors, 'SCOPE_VIOLATION', 'scope', 'unknown scope keys');
    else {
      if (JSON.stringify(sc.executes) !== JSON.stringify(want.executes)) err(errors, 'SCOPE_VIOLATION', 'scope.executes', 'a replay may execute only the oracle it names');
      if (sc.network !== false) err(errors, 'SCOPE_VIOLATION', 'scope.network', 'replay grants no network access');
      if (sc.writes !== 'workspace-only') err(errors, 'SCOPE_VIOLATION', 'scope.writes', 'replay writes only inside its workspace');
    }
    const b = m.budgets;
    if (!isPlainObject(b)) err(errors, 'BAD_TYPE', 'budgets', 'must be an object');
    else {
      for (const k of Object.keys(b)) if (!REPLAY_BUDGET_KEYS.includes(k)) err(errors, 'UNKNOWN_FIELD', `budgets.${k}`, 'not a replay budget');
      for (const k of REPLAY_BUDGET_KEYS) {
        if (!Number.isInteger(b[k]) || b[k] < 1) err(errors, 'BAD_TYPE', `budgets.${k}`, 'must be a positive integer');
        else if (b[k] > oracle.budgets[k]) err(errors, 'BUDGET_EXCEEDED', `budgets.${k}`, `exceeds the oracle ceiling of ${oracle.budgets[k]}`);
      }
    }
  }
  if (typeof m.entry !== 'string' || !m.entry) err(errors, 'BAD_TYPE', 'entry', 'must be a non-empty string');
  if (m.expected !== undefined && (!isPlainObject(m.expected) || Object.keys(m.expected).some((k) => k !== 'outcome') || !EXPECTED_OUTCOMES.includes(m.expected.outcome))) err(errors, 'BAD_TYPE', 'expected', `must be { outcome: one of ${EXPECTED_OUTCOMES.join(', ')} }`);
  if (m.id !== manifestId(m)) err(errors, 'ID_MISMATCH', 'id', 'the manifest id does not match its content');
  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------- prerequisites

/**
 * Typed prerequisites that are not met on this host. `resumable` is true when
 * meeting it is something an operator can do (install a toolchain, enable the
 * feature) and false when this build cannot meet it at all.
 */
export function unmetPrerequisites(m, host = environmentIdentity()) {
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
  if (!isPlainObject(resume) || resume.schema !== ATTEMPT_SCHEMA || resume.manifestId !== manifestId_) return { error: 'the attempt does not belong to this manifest' };
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
export async function replayManifest(bundle, o = {}) {
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
    const record = recordWithoutExecution(manifest.oracle.id, request, outcome, reason, registry);
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

  const run = await runOracle(request, { config: o.config, ...(o.runOptions || {}) });
  if (run.status === 'rejected') return { status: 'rejected', executed: false, outcome: null, record: null, receipt: null, reproduced: null, prerequisites: [], attempt: null, errors: (run.errors || []).map((m) => ({ code: 'REQUEST_REJECTED', path: '', message: m })) };
  if (!run.executed) {
    const feature = run.status === 'disabled';
    const prereq = feature
      ? [{ kind: 'feature', id: FEATURE_ID, state: 'disabled', resumable: true, reason: run.reason }]
      : (run.prerequisites || [{ id: 'trust-boundary', reason: run.reason }]).map((p) => ({ kind: p.id === 'trust-boundary' ? 'trust-boundary' : 'oracle-prerequisite', id: p.id, state: 'unmet', resumable: false, reason: p.reason }));
    return waiting(prereq, run.outcome === 'unsupported' ? 'unsupported' : 'not-run', run.reason);
  }
  const reproduced = manifest.expected ? run.outcome === manifest.expected.outcome : null;
  return {
    status: 'completed', executed: true, outcome: run.outcome, record: run.record, receipt: run.receipt, reproduced,
    prerequisites: [], errors: [], run: run.run, environment: run.environment,
    attempt: attemptRecord(manifest.id, step.n, step.history, 'completed', { outcome: run.outcome }),
  };
}
