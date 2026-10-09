// The oracle interface and its runner (X-202).
//
// An ORACLE is a bounded, class-specific assertion about whether a hypothesis
// holds, executed against a target INSIDE the trust boundary (CORE-003) and judged
// by verifier-domain code. This module owns three things and nothing else:
//
//   1. The adapter contract (`validateOracleSpec`, `defineOracle`): every adapter
//      declares its class, prerequisites, supported platforms, budgets and negative
//      controls, or it is not an adapter. X-208 gates a release on this.
//   2. The runner (`runOracle`): feature gate, request validation, prerequisite
//      check, a fresh workspace, the target run through `runInBoundary` ONLY, an
//      integrity check of the adapter's own logic, verifier-side interpretation,
//      and a verifier-produced receipt.
//   3. The receipt registry: receipts exist only if `runOracle` issued them.
//
// What makes the verdict trustworthy, and what does not:
//   - The target runs in a workspace the target can write. The VERDICT is formed
//     by `settleVerification` from evidence stamped `observedBy: 'verifier'`, and
//     the effect it examines is read by the verifier AFTER the whole process tree
//     is dead (marker files, the supervisor's own deadline observation). Target
//     stdout and stderr are data: they are captured, capped and labelled, never
//     parsed for a status.
//   - A run alone can only be `inconclusive`. `confirmed` and `refuted` need the
//     adapter's verifier-side assertion, and `refuted` additionally needs the
//     adapter to show its own preconditions held (a benign control passed), so a
//     target that failed to load or a harness that never reported is
//     `inconclusive`, never a refutation.
//   - An unavailable prerequisite is `unsupported` with a reason and the target is
//     never executed. It never counts as a pass and never as a failure of the
//     hypothesis.
//   - Candidate workers cannot alter adapter logic, labels or receipts: the
//     registry is frozen, labels (what counts as the effect) live in the adapter
//     and in verifier-built tokens the request cannot set, the request rejects any
//     field that looks like a verdict, the adapter's harness file is digest-checked
//     after the run (a target that rewrote it makes the run `error`), the
//     authoritative evidence directory is outside the workspace and read-denied by
//     the boundary, and a receipt is only valid if this module issued it.
//   - KNOWN LIMIT, not hidden: a target that recognises the oracle's payload and
//     forges the effect artifact inside its own process is not distinguishable
//     from one that was really exploited. The oracle bounds the effect it tests;
//     it is not a defence against a target written to fool this oracle.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runInBoundary } from '../../sandbox/trust-boundary.js';
import { detectBackend } from '../../sandbox/capabilities.js';
import { DOMAINS, settleVerification } from '../../sandbox/trust-domains.js';
import { resolveAssuranceConfig, featureStatus } from '../assurance/config.js';
import { digestOf, digestOfBytes } from '../assurance/identity.js';
import { isCommit, isPlainObject } from '../assurance/schema-kit.js';
import { emitVerification } from '../verification/emit.js';
import { scenarioClassesForAdapter, scenarioClassReportLines } from './scenario-classes.js';

export const ORACLE_CLASSES = Object.freeze([
  'injection-execution', 'authorization-decision', 'state-transition', 'side-effect-reachability', 'parser-resource',
  // X-205 and X-204: a replayed request that repeats its effect, and a differential behaviour check for a patch.
  'replay-idempotency', 'functional-regression',
]);
const PLATFORM_STATUSES = Object.freeze(['supported', 'unverified', 'unsupported']);
export const FEATURE_ID = 'verification-oracles';
export const HARNESS_FILE = '__oracle_harness.mjs';
export const RESULT_FILE = '__oracle_result.json';
const RECEIPT_SCHEMA = 'agentic-security/oracle-receipt';

const RESERVED_PREFIX = '__oracle_';
const MAX_INPUT_BYTES = 64 * 1024;
const MAX_OBSERVED_BYTES = 4 * 1024;
const REQUEST_KEYS = ['oracleId', 'hypothesisId', 'finding', 'commit', 'files', 'entry', 'inputs', 'attempt', 'budgets', 'detectorOrigin'];
const BUDGET_KEYS = ['timeoutMs', 'graceMs', 'maxOutputBytes', 'maxFileBytes', 'maxFiles'];

// ---------------------------------------------------------------- prerequisites

// Shared prerequisite checks. An adapter names the ones it needs by id; `check`
// reads only the injected environment snapshot, so any host can simulate a missing
// prerequisite and every host can read why a check failed.
export const PREREQUISITES = Object.freeze({
  'node-runtime': {
    description: 'Node.js 24 or later (the version this scanner supports)',
    check: (env) => (env.nodeMajor >= 24 ? { ok: true } : { ok: false, reason: `Node ${env.nodeMajor} is older than the supported 24` }),
  },
  'confinement-backend': {
    description: 'a confinement backend that passes its functional probe on this host',
    check: (env) => (env.backend && env.backend !== 'disabled' ? { ok: true } : { ok: false, reason: 'no confinement backend works on this host' }),
  },
  'posix-shell': {
    description: 'a POSIX shell at /bin/sh (the injected command needs a shell to run)',
    check: (env) => (env.hasPosixShell ? { ok: true } : { ok: false, reason: '/bin/sh is not present' }),
  },
});

function probeEnvironment() {
  return {
    platform: process.platform,
    nodeMajor: Number(String(process.versions.node).split('.')[0]),
    backend: detectBackend(),
    hasPosixShell: fs.existsSync('/bin/sh'),
  };
}

// ---------------------------------------------------------------- adapter contract

const isPosInt = (n) => Number.isInteger(n) && n > 0;

/** Problems with an adapter spec; an empty list means it satisfies the contract. */
export function validateOracleSpec(spec) {
  const errs = [];
  if (!isPlainObject(spec)) return ['adapter spec must be an object'];
  if (typeof spec.id !== 'string' || !/^[a-z][a-z0-9-]{2,63}$/.test(spec.id)) errs.push('id must be a lowercase slug');
  if (!ORACLE_CLASSES.includes(spec.class)) errs.push(`class must be one of ${ORACLE_CLASSES.join(', ')}`);
  if (typeof spec.version !== 'string' || !/^\d+$/.test(spec.version)) errs.push('version must be an integer string');
  if (typeof spec.description !== 'string' || !spec.description.trim()) errs.push('description is required');
  if (!Array.isArray(spec.prerequisites) || spec.prerequisites.length === 0) errs.push('declared prerequisites are required');
  else for (const id of spec.prerequisites) if (!PREREQUISITES[id]) errs.push(`unknown prerequisite '${id}'`);
  if (!isPlainObject(spec.platforms)) errs.push('platforms are required');
  else {
    for (const p of ['darwin', 'linux', 'win32']) {
      const e = spec.platforms[p];
      if (!isPlainObject(e) || !PLATFORM_STATUSES.includes(e.status) || typeof e.note !== 'string' || !e.note) errs.push(`platforms.${p} needs a status and a note`);
    }
    if (spec.platforms.linux?.status === 'supported') errs.push('platforms.linux cannot be "supported": Linux enforcement is not verified by this build');
  }
  const b = spec.budgets;
  if (!isPlainObject(b)) errs.push('budgets are required');
  else for (const k of BUDGET_KEYS) if (!isPosInt(b[k])) errs.push(`budgets.${k} must be a positive integer`);
  if (!Array.isArray(spec.negativeControls) || spec.negativeControls.length === 0) errs.push('at least one negative control is required');
  else for (const [i, n] of spec.negativeControls.entries()) {
    if (!isPlainObject(n) || typeof n.id !== 'string' || typeof n.description !== 'string' || n.expectedOutcome !== 'refuted') errs.push(`negativeControls[${i}] needs id, description and expectedOutcome 'refuted'`);
  }
  if (!isPlainObject(spec.fixtures) || !['dir', 'positive', 'negative', 'inconclusive'].every((k) => typeof spec.fixtures[k] === 'string' && spec.fixtures[k])) errs.push('fixtures need dir, positive, negative and inconclusive');
  if (!Array.isArray(spec.limitations) || spec.limitations.length === 0) errs.push('limitations must be stated');
  if (typeof spec.harnessSource !== 'string' || !spec.harnessSource.includes('__INPUT__')) errs.push('harnessSource (verifier-authored) is required');
  for (const fn of ['prepare', 'validateInputs', 'interpret']) if (typeof spec[fn] !== 'function') errs.push(`${fn} must be a function`);
  return errs;
}

/** Digest of everything that decides what this adapter asserts. A replay manifest pins it. */
export function oracleLogicDigest(spec) {
  return digestOf({ id: spec.id, class: spec.class, version: spec.version, budgets: spec.budgets, harness: spec.harnessSource });
}

/** Validate, freeze and fingerprint an adapter. Throws on an invalid spec: registration is verifier-side code, at load. */
export function defineOracle(spec) {
  const errs = validateOracleSpec(spec);
  if (errs.length) throw new Error(`invalid oracle adapter '${spec?.id}': ${errs.join('; ')}`);
  const deep = (o) => { Object.values(o).forEach((v) => { if (v && typeof v === 'object') deep(v); }); return Object.freeze(o); };
  return Object.freeze({ ...spec, platforms: deep({ ...spec.platforms }), budgets: deep({ ...spec.budgets }), logicDigest: oracleLogicDigest(spec) });
}

// ---------------------------------------------------------------- receipts

const ISSUED = new WeakSet();

/** True only for a receipt object `runOracle` itself created. A forged lookalike is not. */
export function isIssuedReceipt(r) { return isPlainObject(r) && ISSUED.has(r); }

function deepFreeze(o) {
  for (const v of Object.values(o)) if (v && typeof v === 'object' && !Object.isFrozen(v)) deepFreeze(v);
  return Object.freeze(o);
}

function issueReceipt(body) {
  const copy = JSON.parse(JSON.stringify(body));
  const receipt = deepFreeze({ ...copy, receiptDigest: digestOf(copy) });
  ISSUED.add(receipt);
  return receipt;
}

// ---------------------------------------------------------------- environment metadata

/**
 * Sanitized environment metadata: an allowlist of facts about the platform and the
 * proved controls. No hostnames, user names, paths or environment variables.
 */
export function sanitizedEnvironment({ backend, controls } = {}) {
  const controlStates = {};
  for (const [name, c] of Object.entries(isPlainObject(controls) ? controls : {})) {
    if (c && typeof c.state === 'string') controlStates[name] = c.state;
  }
  return {
    platform: process.platform, arch: os.arch(), runtime: 'node', nodeVersion: process.versions.node,
    backend: backend || null, controlStates, containerDigest: null,
  };
}

// ---------------------------------------------------------------- request validation

/** A relative path that stays inside a workspace and cannot name the adapter's own reserved files. */
export function isSafeRelativePath(rel) {
  if (typeof rel !== 'string' || !rel || rel.length > 200 || rel.includes('\0') || rel.includes('\\')) return false;
  if (path.isAbsolute(rel) || rel.split('/').some((seg) => seg === '..' || seg === '' || seg === '.')) return false;
  if (path.basename(rel).startsWith(RESERVED_PREFIX)) return false;
  return true;
}

function validateRequest(req, oracle) {
  const errs = [];
  if (!isPlainObject(req)) return ['request must be an object'];
  for (const k of Object.keys(req)) if (!REQUEST_KEYS.includes(k)) errs.push(`field '${k}' is not part of an oracle request (verdicts, labels and receipts are never supplied by a caller)`);
  if (typeof req.hypothesisId !== 'string' || !req.hypothesisId) errs.push('hypothesisId is required');
  if (req.commit !== undefined && req.commit !== null && !isCommit(req.commit)) errs.push('commit must be a 40 or 64 character lowercase hex commit id or null');
  if (!isPlainObject(req.files)) errs.push('files must be an object of relative path to text');
  else {
    const names = Object.keys(req.files);
    if (names.length === 0 || names.length > oracle.budgets.maxFiles) errs.push(`files must hold 1 to ${oracle.budgets.maxFiles} entries`);
    for (const n of names) {
      if (!isSafeRelativePath(n)) errs.push(`file path ${JSON.stringify(String(n).slice(0, 60))} is not a safe relative path`);
      else if (typeof req.files[n] !== 'string' || Buffer.byteLength(req.files[n]) > oracle.budgets.maxFileBytes) errs.push(`file '${n}' must be text of at most ${oracle.budgets.maxFileBytes} bytes`);
    }
  }
  if (typeof req.entry !== 'string' || !isPlainObject(req.files) || !(req.entry in req.files)) errs.push('entry must name one of the supplied files');
  if (!isPlainObject(req.inputs)) errs.push('inputs must be an object');
  else {
    let size = 0;
    try { size = Buffer.byteLength(JSON.stringify(req.inputs)); } catch { errs.push('inputs must be JSON-serializable'); }
    if (size > MAX_INPUT_BYTES) errs.push(`inputs exceed ${MAX_INPUT_BYTES} bytes`);
    const why = errs.length ? null : oracle.validateInputs(req.inputs);
    if (why) errs.push(`inputs: ${why}`);
  }
  if (req.attempt !== undefined && !isPosInt(req.attempt)) errs.push('attempt must be a positive integer');
  if (req.budgets !== undefined) {
    if (!isPlainObject(req.budgets)) errs.push('budgets must be an object');
    else for (const [k, v] of Object.entries(req.budgets)) {
      if (!BUDGET_KEYS.includes(k)) errs.push(`unknown budget '${k}'`);
      else if (!isPosInt(v) || v > oracle.budgets[k]) errs.push(`budget ${k} must be a positive integer within the adapter ceiling of ${oracle.budgets[k]}`);
    }
  }
  return errs;
}

// ---------------------------------------------------------------- workspace reads (verifier side)

function makeReader(root) {
  return (rel, maxBytes = 4096) => {
    try {
      const abs = path.resolve(root, rel);
      if (!abs.startsWith(root + path.sep)) return null;
      const st = fs.lstatSync(abs);
      if (!st.isFile() || st.isSymbolicLink()) return null;
      const fd = fs.openSync(abs, 'r');
      try {
        const buf = Buffer.alloc(Math.min(st.size, maxBytes));
        fs.readSync(fd, buf, 0, buf.length, 0);
        return buf.toString('utf8');
      } finally { fs.closeSync(fd); }
    } catch { return null; }
  };
}

function writeFiles(root, files) {
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.resolve(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
  }
}

function capObserved(obj) {
  let s = JSON.stringify(obj ?? null);
  if (Buffer.byteLength(s) <= MAX_OBSERVED_BYTES) return JSON.parse(s);
  return { truncated: true, digest: digestOf(obj ?? null) };
}

// ---------------------------------------------------------------- the runner

function outcomeFields(oracle, req, { outcome, reason, attempt, evidence, preconditionsValid, backend }) {
  const platformNote = oracle.platforms[process.platform]?.status === 'unverified' ? ' (platform unverified for this oracle)' : '';
  return {
    outcome, reason, attempt, evidence: evidence || [],
    oracle: { id: oracle.id, kind: 'runtime-replay', version: oracle.version },
    preconditions: { valid: !!preconditionsValid },
    scope: { description: `${oracle.class} oracle '${oracle.id}' v${oracle.version}, bounded assertion in the trust boundary${platformNote}`, platform: process.platform, ...(backend ? { backend } : {}) },
  };
}

/**
 * What a reader of any result from this oracle must be shown next to it: the prerequisites it needed, the platform statement
 * and its limitations, and, for a non-taint class it serves, that class's own report lines (X-205.AC02). Data only.
 */
function disclosureOf(oracle) {
  return {
    oracle: oracle.id,
    prerequisites: oracle.prerequisites.map((id) => ({ id, description: PREREQUISITES[id].description })),
    platform: { name: process.platform, status: oracle.platforms[process.platform]?.status ?? 'unsupported' },
    limitations: [...oracle.limitations],
    scenarioClasses: scenarioClassesForAdapter(oracle.id).map((c) => ({ id: c.id, report: scenarioClassReportLines(c, oracle) })),
  };
}

function finishWithRecord(oracle, req, status, fields, extra = {}) {
  const emitted = emitVerification('oracle', null, {
    hypothesisId: req.hypothesisId, commit: req.commit ?? null, finding: req.finding || null,
    ...(req.detectorOrigin ? { detectorOrigin: req.detectorOrigin } : {}), fields,
  });
  return { status, outcome: fields.outcome, reason: fields.reason, record: emitted.ok ? emitted.record : null, recordErrors: emitted.errors, disclosure: disclosureOf(oracle), ...extra };
}

/**
 * The record for an attempt that did not execute anything (replay prerequisites, a refused request). `not-run` and
 * `unsupported` are the only outcomes available: with no execution there is nothing to settle.
 */
export function recordWithoutExecution(oracleId, req, outcome, reason, registry) {
  const oracle = (registry || { getOracle: () => null }).getOracle(oracleId);
  if (!oracle || !['not-run', 'unsupported'].includes(outcome)) return null;
  return finishWithRecord(oracle, req, outcome === 'unsupported' ? 'unsupported' : 'awaiting-prerequisites',
    outcomeFields(oracle, req, { outcome, reason, attempt: 0, preconditionsValid: false })).record;
}

/**
 * Run one oracle against one target. Never throws. The target is executed through
 * `runInBoundary` and nowhere else.
 *
 * @param {object} request  see REQUEST_KEYS; labels, verdicts and receipts are rejected
 * @param {object} [o]
 * @param {object} [o.config]   resolved assurance config; default resolves the process environment (feature off by default)
 * @param {object} [o.probeEnv] environment snapshot for prerequisite checks (test seam)
 * @param {object} [o.deps]     `{ runInBoundary }` test seam
 * @param {AbortSignal} [o.signal]
 * @param {object} [o.registry] `{ getOracle }` (defaults to the frozen registry)
 */
export async function runOracle(request, o = {}) {
  const registry = o.registry || (await import('./registry.js'));
  const oracle = registry.getOracle(request?.oracleId);
  if (!oracle) return { status: 'rejected', outcome: null, reason: `unknown oracle '${String(request?.oracleId).slice(0, 80)}'`, record: null, errors: ['unknown oracle'] };
  const errs = validateRequest(request, oracle);
  if (errs.length) return { status: 'rejected', outcome: null, reason: 'the request failed validation', record: null, errors: errs };
  const req = request;
  const attemptNo = req.attempt ?? 1;
  const none = (outcome, reason, status, extra) => finishWithRecord(oracle, req, status, outcomeFields(oracle, req, { outcome, reason, attempt: 0, preconditionsValid: false }), { executed: false, receipt: null, ...extra });

  // 1. feature gate: high-risk execution is off unless the operator enabled it
  const config = o.config || resolveAssuranceConfig({ env: process.env });
  const gate = featureStatus(config, FEATURE_ID);
  if (gate.status !== 'ok') {
    return none(gate.status === 'unsupported' ? 'unsupported' : 'not-run', `${FEATURE_ID} is not available: ${gate.reason}`, gate.status === 'unsupported' ? 'unsupported' : 'disabled', { gate });
  }

  // 2. prerequisites: an unmet one is `unsupported`, never a pass, and nothing executes
  const env = o.probeEnv || probeEnvironment();
  const unmet = [];
  const plat = oracle.platforms[env.platform];
  if (!plat || plat.status === 'unsupported') unmet.push({ id: 'supported-platform', reason: `${env.platform} is not a supported platform for this oracle${plat ? `: ${plat.note}` : ''}` });
  for (const id of oracle.prerequisites) {
    let r;
    try { r = PREREQUISITES[id].check(env); } catch (e) { r = { ok: false, reason: `check failed: ${String(e?.message || e).slice(0, 100)}` }; }
    if (!r.ok) unmet.push({ id, reason: r.reason || 'unavailable' });
  }
  if (unmet.length) {
    return none('unsupported', `unmet prerequisite(s): ${unmet.map((u) => `${u.id} (${u.reason})`).join('; ')}`, 'unsupported', { prerequisites: unmet });
  }

  // 3. workspace + verifier-owned evidence directory (outside the workspace)
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'oracle-ws-')));
  const evidenceDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'oracle-ev-')));
  const token = crypto.randomBytes(12).toString('hex');
  try {
    const harnessInput = oracle.prepare(req.inputs, token);
    // One pass, so a placeholder-looking string inside the input can never be substituted a second time.
    const subst = { __INPUT__: JSON.stringify(harnessInput), __ENTRY__: JSON.stringify(req.entry) };
    const harness = oracle.harnessSource.replace(/__INPUT__|__ENTRY__/g, (m) => subst[m]);
    writeFiles(root, req.files);
    fs.writeFileSync(path.join(root, HARNESS_FILE), harness, 'utf8');
    const harnessDigest = digestOfBytes(Buffer.from(harness, 'utf8'));
    const budgets = { ...oracle.budgets, ...(req.budgets || {}) };

    // 4. the target runs through the trust boundary and nowhere else
    const run = o.deps?.runInBoundary || runInBoundary;
    const boundary = await run([process.execPath, HARNESS_FILE], {
      root, evidenceDirs: [evidenceDir], env: {}, allowNetwork: false, signal: o.signal, force: o.force,
      timeoutMs: budgets.timeoutMs, graceMs: budgets.graceMs, maxOutputBytes: budgets.maxOutputBytes,
      limits: { maxFileSizeKb: 1024 },
    });
    if (boundary.blocked) {
      // An unproved control or an unavailable backend: the isolation prerequisite is not met.
      return none('unsupported', `the trust boundary refused to run the target: ${boundary.reasons.join('; ')}`, 'blocked', { boundary: { backend: boundary.backend ?? null, reasons: boundary.reasons }, prerequisites: [{ id: 'trust-boundary', reason: boundary.reasons.join('; ') }] });
    }
    const environment = sanitizedEnvironment({ backend: boundary.backend, controls: boundary.controls });
    const runInfo = {
      status: boundary.status, executed: boundary.executed, timedOut: !!boundary.timedOut, outputCapped: !!boundary.outputCapped,
      cancelled: !!boundary.cancelled, exitCode: boundary.exitCode ?? null, survivors: boundary.termination?.survivors?.length ?? 0,
    };

    // 5. adapter-logic integrity: a target that rewrote the harness invalidates the run
    const read = makeReader(root);
    const harnessAfter = read(HARNESS_FILE, harness.length + 1024);
    const tampered = harnessAfter === null || digestOfBytes(Buffer.from(harnessAfter, 'utf8')) !== harnessDigest;
    const failed = (outcome, reason, status) => finishWithRecord(oracle, req, status, outcomeFields(oracle, req, {
      outcome, reason, attempt: attemptNo, preconditionsValid: false, backend: boundary.backend,
      evidence: [{ id: 'run-observation', kind: 'observation', producer: 'trusted-runner', digest: digestOf({ run: runInfo, environment }), source: `oracle:${oracle.id}@${oracle.version}` }],
    }), { executed: boundary.executed, receipt: null, run: runInfo, environment });
    if (tampered) return failed('error', 'the adapter harness was modified during the run; the run is invalid and no verdict is formed', 'error');
    if (runInfo.cancelled) return failed('inconclusive', 'the run was cancelled before it finished', 'cancelled');
    if (runInfo.survivors > 0) return failed('error', 'processes survived termination; the run cannot be trusted', 'error');

    // 6. verifier-side interpretation of what the run left behind (all of it read after the tree is dead)
    let resultDoc = null;
    const rawResult = read(RESULT_FILE, 16 * 1024);
    if (rawResult !== null) { try { const j = JSON.parse(rawResult); if (isPlainObject(j)) resultDoc = j; } catch { /* untrusted data that does not parse is absent */ } }
    let judged;
    try { judged = oracle.interpret({ inputs: req.inputs, token, result: resultDoc, run: runInfo, read }); } catch (e) { judged = { satisfied: null, preconditionsHeld: false, observed: {}, reason: `adapter interpretation failed: ${String(e?.message || e).slice(0, 100)}` }; }
    const evidenceIn = { observedBy: DOMAINS.VERIFIER, satisfied: judged.satisfied, preconditionsHeld: judged.preconditionsHeld === true };
    let outcome = settleVerification({ executed: boundary.executed, status: boundary.status }, evidenceIn);
    let reason = judged.reason;
    if ((outcome === 'confirmed' || outcome === 'refuted') && !req.commit) {
      outcome = 'inconclusive';
      reason = `${judged.reason}; not carried to '${evidenceIn.satisfied ? 'confirmed' : 'refuted'}' because the request is not bound to an exact commit`;
    }
    const observed = capObserved(judged.observed);
    const decided = outcome === 'confirmed' || outcome === 'refuted';
    const evidence = [{
      id: 'oracle-observation', kind: decided ? 'trusted-runtime-proof' : 'observation', producer: 'trusted-runner',
      // The harness text carries a per-run token, so it stays out of the record's digest (an identical replay must give an
      // identical record id); it is bound into the receipt instead.
      digest: digestOf({ oracle: oracle.logicDigest, observed }), source: `oracle:${oracle.id}@${oracle.version}`,
    }];
    const out = finishWithRecord(oracle, req, 'completed', outcomeFields(oracle, req, {
      outcome, reason, attempt: attemptNo, evidence, preconditionsValid: evidenceIn.preconditionsHeld, backend: boundary.backend,
    }), { executed: true, run: runInfo, environment, targetOutput: boundary.targetOutput });
    out.receipt = issueReceipt({
      schema: RECEIPT_SCHEMA, issuedBy: 'verifier',
      oracle: { id: oracle.id, class: oracle.class, version: oracle.version, logicDigest: oracle.logicDigest },
      request: { hypothesisId: req.hypothesisId, commit: req.commit ?? null, entry: req.entry, inputsDigest: digestOf(req.inputs), filesDigest: digestOf(req.files), attempt: attemptNo },
      environment, run: runInfo, observed, harnessDigest,
      settled: { outcome, satisfied: judged.satisfied, preconditionsHeld: evidenceIn.preconditionsHeld }, recordId: out.record?.id ?? null,
    });
    return out;
  } catch (e) {
    return none('error', `the oracle runner failed: ${String(e?.message || e).slice(0, 160)}`, 'error');
  } finally {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
    try { fs.rmSync(evidenceDir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}
