// The single emit function for the one verification record (X-201).
//
// Every surface that verifies something (fix verification, the closed fix loop,
// execution proof, the verifier verdicts, autopilot, hunt, the trusted oracle
// adapters) calls `emitVerification(surface, source, ctx)` and gets back a
// version-1 record from `assurance/verification-record.js`. The surface keeps
// producing its own native fields; the record is ADDITIVE (callers attach it
// under `verificationRecord`) so no existing consumer changes.
//
// The rule that governs every mapping here is the one CORE-002 states: evidence
// can be lost in translation but never invented. Each surface's native result
// lands on the strongest outcome its OWN evidence supports, and none of the
// legacy surfaces ran under the trusted boundary, so none of them can reach
// `confirmed` or `refuted` through this function:
//   - a PoC that ran under the older sandbox path is `inconclusive` (the older
//     path is not a trusted runner; re-verify under an oracle adapter to confirm);
//   - a PoC that ran and did not fire is `inconclusive`, never `refuted`;
//   - a model verdict is recorded as `inference` evidence and nothing more;
//   - a surface that executed nothing (static legs only) is `not-run`;
//   - a family or class with no oracle is `unsupported`, a harness failure `error`.
// `confirmed`/`refuted` records come only from `oracle` emissions, whose caller
// (`oracles/oracle.js`) supplies trusted-runner evidence produced by the
// verifier domain. This function validates before it returns and never throws.
import { spawnSync } from 'node:child_process';
import { buildVerificationRecord, validateVerificationRecord } from '../assurance/verification-record.js';
import { legacyVerificationOutcome, toLegacyVerificationView } from '../assurance/migrations.js';
import { digestOf, hypothesisIdFromFinding } from '../assurance/identity.js';
import { isCommit, isPlainObject } from '../assurance/schema-kit.js';
import { judgeNonTaintHypothesis } from '../oracles/scenario-classes.js';

export const SURFACES = Object.freeze([
  'fix-verify', 'fix-verify-loop', 'execution-proof', 'verifier', 'autopilot', 'hunt', 'oracle',
]);

const POC_ORACLE = Object.freeze({ id: 'poc-marker-replay', kind: 'runtime-replay', version: '1' });
const TAINT_ORACLE = Object.freeze({ id: 'taint-engine-confirmation', kind: 'static-proof', version: '1' });
const SANITIZER_ORACLE = Object.freeze({ id: 'sanitizer-absence-window', kind: 'static-proof', version: '1' });

/** HEAD of `root`, or null when it is not a git work tree. Bounded; never throws. */
export function headCommit(root) {
  if (!root || typeof root !== 'string') return null;
  try {
    const r = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', timeout: 2000 });
    const out = String(r.stdout || '').trim();
    return r.status === 0 && isCommit(out) ? out : null;
  } catch { return null; }
}

function detectorOriginOf(finding, ctx) {
  if (isPlainObject(ctx.detectorOrigin)) return ctx.detectorOrigin;
  const f = finding || {};
  const origin = { detector: String(f.ruleId || f.vuln || f.id || f.parser || 'unknown') };
  if (typeof f.family === 'string' && f.family) origin.family = f.family;
  if (typeof f.parser === 'string' && f.parser) origin.parser = f.parser;
  return origin;
}

const observation = (id, source, value) => ({ id, kind: 'observation', producer: 'tool', digest: digestOf(value ?? null), source });
const inference = (id, source, value) => ({ id, kind: 'inference', producer: 'model', digest: digestOf(value ?? null), source });

function scopeOf(description, backend) {
  const scope = { description, platform: process.platform };
  if (backend && typeof backend === 'string') scope.backend = backend;
  return scope;
}

// ------------------------------------------------------------ per-surface mappers

function mapFixVerify(r, ctx) {
  const files = ctx.files && typeof ctx.files === 'object' ? ctx.files : null;
  const repair = files ? { status: 'proposed', patchDigest: digestOf(files) } : { status: 'none' };
  const legs = {
    rescan: { ok: r?.rescan?.ok ?? null, reason: r?.rescan?.reason ?? null },
    lint: { ok: r?.lint?.ok ?? null, runner: r?.lint?.runner ?? null, skipped: !!r?.lint?.skipped },
    tests: { passed: r?.tests?.passed ?? null, skipped: !!r?.tests?.skipped },
    poc: { status: r?.poc?.status ?? 'not-requested', tier: r?.poc?.tier ?? null },
  };
  const evidence = [observation('legs', 'fix-verify legs', legs)];
  const legText = `re-scan ${legs.rescan.ok ? 'passed' : 'failed'}, lint ${legs.lint.skipped ? 'skipped' : legs.lint.ok ? 'passed' : 'failed'}, tests ${legs.tests.skipped ? 'skipped' : legs.tests.passed ? 'passed' : 'failed'}`;
  const base = { repair, evidence, scope: scopeOf('candidate patch re-verification (hypothesis: the vulnerability is still present on the patched tree)', r?.poc?.backend) };
  if (!files || legs.rescan.reason === 'no-files-provided') {
    return { ...base, outcome: 'not-run', reason: 'no candidate patch files were supplied, so nothing was verified', attempt: 0, oracle: null, preconditions: { valid: false } };
  }
  if (legs.rescan.reason === 'rescan-failed') {
    return { ...base, outcome: 'error', reason: 'the verification re-scan failed to run', attempt: 1, oracle: null, preconditions: { valid: false } };
  }
  const p = legs.poc.status;
  if (p === 'not-requested') {
    return {
      ...base, outcome: 'not-run', attempt: 0, oracle: null, preconditions: { valid: false },
      reason: `no exploit oracle was executed against the patch; only detector-level and project-test legs ran (${legText})`,
    };
  }
  // The leg's own free text (it can echo scanned source) is deliberately not copied into the record's reason.
  if (p === 'inconclusive') {
    return { ...base, outcome: 'inconclusive', attempt: 1, oracle: POC_ORACLE, preconditions: { valid: false },
      reason: `the proof-of-concept leg did not complete, so nothing was established about the patch (${legText})` };
  }
  const mapped = legacyVerificationOutcome({ proofEvidence: { tier: p === 'still-exploitable' ? 'execution-proven' : 'proof-failed', ran: true } });
  return {
    ...base, outcome: mapped.outcome, attempt: 1, oracle: POC_ORACLE, preconditions: { valid: true },
    reason: `proof-of-concept leg '${p}': ${mapped.reason} (${legText})`,
  };
}

function mapFixLoop(r, ctx) {
  const files = ctx.files && typeof ctx.files === 'object' ? ctx.files : null;
  const repair = files ? { status: 'proposed', patchDigest: digestOf(files) } : { status: 'none' };
  const legs = r?.legs || {};
  const evidence = [observation('legs', 'fix-verify-loop legs', {
    scan: legs.scan?.ok ?? null, lint: legs.lint?.ok ?? null, tests: { ok: legs.tests?.ok ?? null, skipped: !!legs.tests?.skipped }, verdict: r?.verdict ?? null,
  })];
  const base = { repair, evidence, scope: scopeOf('closed-loop fix verification (scan, lint, project tests)', null), oracle: null, preconditions: { valid: false } };
  if (!files) return { ...base, outcome: 'not-run', attempt: 0, reason: 'no candidate patch files were supplied, so nothing was verified' };
  if (legs.scan?.detail?.reason === 'rescan-failed') return { ...base, outcome: 'error', attempt: 1, reason: 'the verification re-scan failed to run' };
  return {
    ...base, outcome: 'not-run', attempt: 0,
    reason: `loop verdict '${r?.verdict ?? 'unknown'}': the loop runs the detector, linter and project tests; no exploit oracle ran against the patch`,
  };
}

function mapExecutionProof(finding) {
  const pe = isPlainObject(finding?.proofEvidence) ? finding.proofEvidence : null;
  if (!pe) return { outcome: 'not-run', attempt: 0, reason: 'no execution-proof evidence is attached to this finding', oracle: null, evidence: [], preconditions: { valid: false }, scope: scopeOf('execution proof (no evidence attached)', null) };
  const m = legacyVerificationOutcome({ proofEvidence: pe });
  const ran = pe.ran === true;
  return {
    outcome: m.outcome, reason: m.reason, attempt: ['not-run', 'unsupported'].includes(m.outcome) ? 0 : 1,
    oracle: ran ? POC_ORACLE : null,
    evidence: ran ? [observation('proof-evidence', 'execution-proof sandbox run', { tier: pe.tier, backend: pe.backend ?? null, observed: pe.observed ?? null, exitCode: pe.exitCode ?? null })] : [],
    preconditions: { valid: ran },
    scope: scopeOf(`proof-of-concept execution (${pe.proofKind || 'in-process marker proof'})`, pe.backend),
  };
}

// verifier.js verdicts. `cannot-verify` carries its cause in the reason string; the cause decides the state.
function mapVerifierVerdict(finding) {
  const verdict = finding?.verifier_verdict;
  const reason = String(finding?.verifier_reason || '');
  const scope = scopeOf(`verifier verdict '${verdict}'`, finding?.verifier_runner);
  const none = { oracle: null, evidence: [], preconditions: { valid: false }, scope };
  switch (verdict) {
    case 'verified-exploit':
      return { ...none, outcome: 'inconclusive', attempt: 1, oracle: POC_ORACLE, preconditions: { valid: true },
        evidence: [observation('poc-exit', 'verifier live PoC run', { reason })],
        reason: 'the PoC exited 0 against the caller-provided target under the older confined runner; an exit code is not trusted runtime proof, so this is not carried forward as confirmed' };
    case 'verified-by-llm':
      return { ...none, outcome: 'inconclusive', attempt: 1, evidence: [inference('llm-accept', 'layer-3 validator', { reason })],
        reason: 'a model accepted the finding; a model verdict alone is an inference and never confirms' };
    case 'verified-sanitizer-absence':
      return { ...none, outcome: 'inconclusive', attempt: 1, oracle: SANITIZER_ORACLE, evidence: [observation('sanitizer-window', 'sanitizer-absence window scan', { reason })],
        reason: `no sanitizer was found in the source window (${reason}); a static absence check does not execute anything` };
    case 'unverified-by-design':
      return { ...none, outcome: 'unsupported', attempt: 0, reason: `this vulnerability family has no verification oracle (${reason})` };
    case 'cannot-verify': {
      if (/^verifier-exception/.test(reason) || /^sandbox-error/.test(reason)) return { ...none, outcome: 'error', attempt: 1, reason };
      if (/confinement primitive|disabled/.test(reason)) return { ...none, outcome: 'unsupported', attempt: 0, reason };
      if (/^poc-timeout|^poc-exit/.test(reason)) return { ...none, outcome: 'inconclusive', attempt: 1, oracle: POC_ORACLE, preconditions: { valid: true }, reason: `${reason}: the PoC ran but did not demonstrate the effect; absence of proof is not refutation` };
      if (/^no-poc-no-sanitizer-rule/.test(reason)) return { ...none, outcome: 'unsupported', attempt: 0, reason: 'neither a PoC nor a sanitizer rule exists for this finding, so no oracle applies' };
      return { ...none, outcome: 'not-run', attempt: 0, reason: reason || 'the verifier did not run' };
    }
    default:
      return { ...none, outcome: 'not-run', attempt: 0, reason: 'the finding carries no verifier verdict' };
  }
}

function mapAutopilot(rec, ctx) {
  const patch = ctx.patch && typeof ctx.patch === 'object' ? ctx.patch : null;
  const repairStatus = rec?.applied === true ? 'applied' : patch ? 'proposed' : 'none';
  const repair = patch ? { status: repairStatus, patchDigest: digestOf(patch) } : { status: 'none' };
  const evidence = [observation('autopilot-stage', 'autopilot stage outcome', {
    outcome: rec?.outcome ?? null, proofTier: rec?.proofTier ?? null, pocStillFires: rec?.pocStillFires ?? null, testsPass: rec?.testsPass ?? null, validation: rec?.validation ?? null,
  })];
  const scope = scopeOf('autopilot scan, prove, validate, fix, re-verify chain', null);
  const base = { repair, evidence, scope, oracle: null, preconditions: { valid: false } };
  if (rec?.validation === 'refuted') {
    return { ...base, outcome: 'inconclusive', attempt: 1, evidence: [...evidence, inference('validator-refutation', 'autopilot validate stage', { validation: rec.validation })],
      reason: 'a validator voted to refute the finding; a validator verdict is not an applicable oracle, so this is not a refutation' };
  }
  if (rec?.outcome === 'UNPROVEN') {
    return rec.proofTier === 'proof-failed'
      ? { ...base, outcome: 'inconclusive', attempt: 1, oracle: POC_ORACLE, preconditions: { valid: true }, reason: 'the proof-of-concept ran and did not demonstrate the effect; absence of proof is not refutation' }
      : { ...base, outcome: 'not-run', attempt: 0, reason: String(rec.reason || 'no proof-of-concept ran for this finding') };
  }
  if (rec?.outcome === 'NO_FIX') return { ...base, outcome: 'inconclusive', attempt: 1, oracle: POC_ORACLE, preconditions: { valid: true }, reason: 'the finding was proved by the older runner but no patch was synthesised, so no re-verification ran' };
  if (rec?.pocStillFires === true) return { ...base, outcome: 'inconclusive', attempt: 1, oracle: POC_ORACLE, preconditions: { valid: true }, reason: 'the proof-of-concept still fires against the patch under the older runner' };
  if (rec?.outcome === 'VERIFIED_FIXED') return { ...base, outcome: 'inconclusive', attempt: 1, oracle: POC_ORACLE, preconditions: { valid: true }, reason: 'the proof-of-concept no longer fires against the patch under the older runner; that is not a trusted exploit-negative result' };
  return { ...base, outcome: 'inconclusive', attempt: 1, reason: String(rec?.reason || 'the patch did not re-verify') };
}

function mapHunt(finding) {
  const d = isPlainObject(finding?.discovery) ? finding.discovery : {};
  const tier = d.confirmation?.tier || 'unconfirmed';
  const scope = scopeOf(`hunt candidate from the ${d.lens || 'unknown'} lens (advisory)`, null);
  const evidence = [];
  if (d.refutation) evidence.push(inference('refutation-panel', 'refutation panel votes', d.refutation));
  // X-205: a non-taint hypothesis (a tenant check, a privileged action, workflow order, replay, resource use) is not judged by
  // a taint probe in EITHER direction. Without an executed oracle of its own class it is `not-run` (or `unsupported`).
  const nonTaint = judgeNonTaintHypothesis({ finding, taint: { clean: !(tier === 'taint-confirmed' || tier === 'sink-adjacent') } });
  if (nonTaint.nonTaint) {
    return { outcome: nonTaint.outcome, attempt: 0, oracle: null, evidence, preconditions: { valid: false }, scope, reason: nonTaint.reason };
  }
  if (tier === 'taint-confirmed' || tier === 'sink-adjacent') {
    evidence.unshift(observation('taint-probe', 'deterministic taint probe', d.confirmation));
    return { outcome: 'inconclusive', attempt: 1, oracle: TAINT_ORACLE, evidence, preconditions: { valid: true }, scope,
      reason: `the deterministic taint probe corroborated this candidate at tier '${tier}'; a static probe is corroboration, not execution` };
  }
  return { outcome: 'not-run', attempt: 0, oracle: null, evidence, preconditions: { valid: false }, scope,
    reason: String(d.confirmation?.reason || 'the candidate was not corroborated by any deterministic probe; no oracle ran') };
}

const MAPPERS = Object.freeze({
  'fix-verify': (s, ctx) => mapFixVerify(s, ctx),
  'fix-verify-loop': (s, ctx) => mapFixLoop(s, ctx),
  'execution-proof': (s) => mapExecutionProof(s),
  verifier: (s) => mapVerifierVerdict(s),
  autopilot: (s, ctx) => mapAutopilot(s, ctx),
  hunt: (s) => mapHunt(s),
});

/**
 * Emit the version-1 verification record for one surface result.
 *
 * @param {string} surface one of SURFACES
 * @param {object} source  the surface's native result (see each mapper)
 * @param {object} [ctx]   { finding, hypothesisId, commit, scanRoot, files, patch, detectorOrigin }
 *   `oracle` emissions pass `ctx.fields`: the record fields the oracle runner
 *   built (including trusted-runner evidence). Nothing else can supply them.
 * @returns {{ ok: boolean, record: object|null, legacy: object|null, errors: object[] }} never throws
 */
export function emitVerification(surface, source, ctx = {}) {
  try {
    if (!SURFACES.includes(surface)) return fail('UNKNOWN_ENUM', `unknown verification surface '${surface}'`);
    const finding = ctx.finding || (surface === 'execution-proof' || surface === 'verifier' || surface === 'hunt' ? source : null);
    const hypothesisId = ctx.hypothesisId || ctx.originalFindingStableId || hypothesisIdFromFinding(finding);
    if (!hypothesisId) return fail('MISSING_FIELD', 'a verification record needs a hypothesis id (a finding stableId); it is not guessed');
    const commit = ctx.commit !== undefined ? (isCommit(ctx.commit) ? ctx.commit : null) : headCommit(ctx.scanRoot);
    let fields;
    if (surface === 'oracle') {
      if (!isPlainObject(ctx.fields)) return fail('MISSING_FIELD', 'an oracle emission needs the fields built by the oracle runner');
      fields = ctx.fields;
    } else {
      fields = MAPPERS[surface](source, ctx);
    }
    const record = buildVerificationRecord({
      ...fields, hypothesisId, commit, detectorOrigin: detectorOriginOf(finding, ctx),
    });
    const v = validateVerificationRecord(record);
    if (!v.ok) return { ok: false, record: null, legacy: null, errors: v.errors };
    return { ok: true, record, legacy: toLegacyVerificationView(record), errors: [] };
  } catch (e) {
    return fail('RULE_VIOLATION', `verification record emission failed: ${String(e?.message || e).slice(0, 200)}`);
  }
}

function fail(code, message) { return { ok: false, record: null, legacy: null, errors: [{ code, path: '', message }] }; }
