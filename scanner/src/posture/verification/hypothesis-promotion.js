// Promoting an advisory hypothesis into a finding (X-207.AC02, AC03).
//
// A hunt hypothesis is advisory. It becomes a FINDING only through `promoteHypothesis`, which needs all three of:
//
//   1. a trusted verifier receipt, VERIFIED here (not merely present): issued by `runOracle` in this process
//      (`isIssuedReceipt`: a copy, a JSON round trip or a hand-built object is not), bound to this hypothesis and one exact
//      commit, carrying a valid version-1 record whose id is the receipt's `recordId`, settled `confirmed` at the
//      `runtime-confirmed` level with trusted-runtime-proof evidence from the trusted runner;
//   2. an explicit policy evaluation. The caller passes a policy; the result carries every rule that was evaluated with its
//      outcome and a digest of the policy. The mandatory rules cannot be removed by a policy, and a policy key this module does
//      not know is refused (fail closed);
//   3. an audit record, returned for EVERY decision (promoted or not), that links the source hypothesis to the promoted finding
//      (or to none) and names the receipt, the record and the policy evaluation. It carries no clock, so identical inputs give
//      an identical record.
//
// What can never satisfy the policy: a confidence score, a repeated or unanimous model agreement, a refutation panel's votes,
// a taint-probe tier, or a severity. None of them is an input to any rule except the optional `minConfidence` / `minAgreement`
// rules, which can only ADD a requirement: the receipt rules are always evaluated, so a hypothesis with perfect confidence and
// no receipt is rejected, and a policy made only of those rules still rejects it.
//
// The producer of a hunt hypothesis and the verifier that confirms it must be different parties (`verification-separation.js`
// is reused for that check). The audit record is returned, not persisted: persisting an audit trail needs an artifact-registry
// classification and a signing domain, which are not decided here.
import { isIssuedReceipt, ORACLE_CLASSES } from '../oracles/oracle.js';
import { validateVerificationRecord } from '../assurance/verification-record.js';
import { digestOf, hypothesisIdFromFinding, semanticId } from '../assurance/identity.js';
import { isPlainObject } from '../assurance/schema-kit.js';
import { recordProducer, assertSeparation } from '../verification-separation.js';
import { isAdvisoryHypothesis } from './advisory-state.js';

export const AUDIT_SCHEMA = 'agentic-security/promotion-audit';
const AUDIT_VERSION = '1.0.0';
export const POLICY_SCHEMA = 'agentic-security/promotion-policy';

export const DECISIONS = Object.freeze(['promoted', 'rejected', 'unsupported', 'inconclusive']);
const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

/** The default policy: runtime-confirmed by a class oracle other than the functional-regression one, severity capped at high. */
export const DEFAULT_PROMOTION_POLICY = Object.freeze({
  schema: POLICY_SCHEMA, id: 'default', version: '1',
  allowedOracleClasses: Object.freeze(ORACLE_CLASSES.filter((c) => c !== 'functional-regression')),
  maxSeverity: 'high',
});

const POLICY_KEYS = ['schema', 'id', 'version', 'allowedOracleClasses', 'maxSeverity', 'expectedCommit', 'minConfidence', 'minAgreement'];

const PROMOTED = new WeakSet();
/** True only for a finding `promoteHypothesis` itself returned. */
export function isPromotedFinding(f) { return isPlainObject(f) && PROMOTED.has(f); }

function validatePolicy(policy) {
  if (!isPlainObject(policy)) return ['no policy was supplied: promotion needs an explicit policy evaluation'];
  const errs = [];
  for (const k of Object.keys(policy)) if (!POLICY_KEYS.includes(k)) errs.push(`unknown policy key '${k}'`);
  if (policy.schema !== POLICY_SCHEMA) errs.push(`policy.schema must be '${POLICY_SCHEMA}'`);
  if (typeof policy.id !== 'string' || !policy.id) errs.push('policy.id is required');
  if (typeof policy.version !== 'string' || !policy.version) errs.push('policy.version is required');
  if (!Array.isArray(policy.allowedOracleClasses) || policy.allowedOracleClasses.length === 0 || !policy.allowedOracleClasses.every((c) => ORACLE_CLASSES.includes(c))) errs.push('policy.allowedOracleClasses must list known oracle classes');
  if (!SEVERITY_ORDER.includes(policy.maxSeverity)) errs.push('policy.maxSeverity must be a severity');
  if (policy.expectedCommit !== undefined && !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(String(policy.expectedCommit))) errs.push('policy.expectedCommit must be an exact commit');
  for (const k of ['minConfidence', 'minAgreement']) if (policy[k] !== undefined && !(typeof policy[k] === 'number' && policy[k] >= 0 && policy[k] <= 1)) errs.push(`policy.${k} must be a number between 0 and 1`);
  return errs;
}

function agreementOf(h) {
  const votes = h?.discovery?.refutation?.votes;
  if (!Array.isArray(votes) || votes.length === 0) return null;
  const upheld = votes.filter((v) => v && (v.verdict === 'upheld' || v.upheld === true)).length;
  return upheld / votes.length;
}

/**
 * Evaluate the policy for one hypothesis and one oracle result. Every rule is evaluated and listed.
 * @returns {{ ok: boolean, rules: {id: string, pass: boolean, detail: string}[], status: string, policyDigest: string|null, record: object|null }}
 */
export function evaluatePromotionPolicy({ hypothesis, result, policy } = {}) {
  const rules = [];
  const rule = (id, pass, detail) => rules.push({ id, pass: !!pass, detail });
  const bad = validatePolicy(policy);
  if (bad.length) {
    rule('policy-valid', false, bad.join('; '));
    return { ok: false, rules, status: 'rejected', policyDigest: null, record: null };
  }
  rule('policy-valid', true, `policy '${policy.id}' v${policy.version}`);
  const policyDigest = digestOf(policy);

  const receipt = result?.receipt ?? null;
  const record = result?.record ?? null;
  const hypothesisId = isPlainObject(hypothesis) ? hypothesisIdFromFinding(hypothesis) : null;

  rule('hypothesis-advisory', isAdvisoryHypothesis(hypothesis) && !!hypothesisId, 'the source must be an unpromoted hunt hypothesis with a stable id');
  const issued = isIssuedReceipt(receipt) && receipt.issuedBy === 'verifier' && receipt.schema === 'agentic-security/oracle-receipt';
  rule('receipt-issued', issued, issued ? 'the receipt was issued by the verifier domain in this process' : 'no receipt issued by the verifier domain was supplied (a copy, a parsed file or a constructed object is not valid)');

  const recordOk = isPlainObject(record) && validateVerificationRecord(record).ok;
  rule('record-valid', recordOk, recordOk ? 'the verification record validates' : 'the verification record is missing or invalid');
  const bound = issued && recordOk && receipt.recordId === record.id && receipt.request.hypothesisId === hypothesisId && record.hypothesisId === hypothesisId;
  rule('receipt-binds-hypothesis', bound, bound ? 'the receipt, the record and the hypothesis name one another' : 'the receipt or record is for a different hypothesis, or they do not reference each other');
  const commit = issued ? receipt.request.commit : null;
  rule('commit-bound', !!commit && (!policy.expectedCommit || policy.expectedCommit === commit) && recordOk && record.commit === commit,
    commit ? (policy.expectedCommit && policy.expectedCommit !== commit ? `the receipt is for a different commit than the policy expects` : 'the receipt is bound to one exact commit') : 'the receipt is not bound to an exact commit');

  const outcome = bound ? receipt.settled.outcome : null;
  rule('outcome-confirmed', outcome === 'confirmed', `the verifier settled '${outcome ?? 'nothing'}'`);
  const runtime = bound && record.confirmationLevel === 'runtime-confirmed'
    && record.evidence.some((e) => e.kind === 'trusted-runtime-proof' && e.producer === 'trusted-runner' && record.evidenceRefs.includes(e.id));
  rule('runtime-confirmed', runtime, runtime ? 'trusted runtime proof from the trusted runner is referenced' : 'no referenced trusted runtime proof at the runtime-confirmed level');
  const classOk = bound && policy.allowedOracleClasses.includes(receipt.oracle.class);
  rule('class-allowed', classOk, classOk ? `oracle class '${receipt.oracle.class}' is allowed` : 'the oracle class is not allowed by the policy');

  // producer and verifier must be different parties
  const probe = { ...hypothesis };
  let sep = { ok: false, reason: 'no receipt' };
  if (bound) {
    const stamped = recordProducer(probe, `hunter:${hypothesis?.discovery?.lens ?? 'unknown'}`);
    sep = stamped.ok ? assertSeparation(probe, `verifier:oracle:${receipt.oracle.id}`) : stamped;
  }
  rule('producer-verifier-separation', sep.ok, sep.ok ? 'the hunter and the verifying oracle are different parties' : String(sep.reason));

  // additive-only rules: they can add a requirement, never satisfy one
  if (policy.minConfidence !== undefined) {
    const c = typeof hypothesis?.confidence === 'number' ? hypothesis.confidence : null;
    rule('min-confidence', c !== null && c >= policy.minConfidence, `an additional requirement only: confidence ${c ?? 'absent'} against ${policy.minConfidence}`);
  }
  if (policy.minAgreement !== undefined) {
    const a = agreementOf(hypothesis);
    rule('min-agreement', a !== null && a >= policy.minAgreement, `an additional requirement only: panel agreement ${a ?? 'absent'} against ${policy.minAgreement}`);
  }

  const ok = rules.every((r) => r.pass);
  let status = 'promoted';
  if (!ok) {
    const settled = bound ? outcome : (isPlainObject(record) && typeof record.outcome === 'string' ? record.outcome : null);
    if (settled === 'unsupported') status = 'unsupported';
    else if (['inconclusive', 'not-run', 'error'].includes(settled)) status = 'inconclusive';
    else status = 'rejected';
  }
  return { ok, rules, status, policyDigest, record: recordOk ? record : null };
}

const capSeverity = (sev, max) => (SEVERITY_ORDER.indexOf(sev) > SEVERITY_ORDER.indexOf(max) ? max : (SEVERITY_ORDER.includes(sev) ? sev : max));

/**
 * Promote one hypothesis, or decline to. Never throws.
 *
 * @param {object} args
 * @param {object} args.hypothesis  a hunt finding (`discovery/judge.js` shape)
 * @param {object} args.result      the `runOracle` result for it (`{ record, receipt, outcome }`)
 * @param {object} args.policy      an explicit policy (see DEFAULT_PROMOTION_POLICY)
 * @returns {{ ok: boolean, decision: string, finding: object|null, audit: object, evaluation: object }}
 */
export function promoteHypothesis({ hypothesis, result, policy } = {}) {
  let evaluation;
  try { evaluation = evaluatePromotionPolicy({ hypothesis, result, policy }); }
  catch (e) { evaluation = { ok: false, status: 'rejected', policyDigest: null, record: null, rules: [{ id: 'evaluation', pass: false, detail: `the policy evaluation failed: ${String(e?.message || e).slice(0, 120)}` }] }; }
  const hypothesisId = isPlainObject(hypothesis) ? hypothesisIdFromFinding(hypothesis) : null;
  const decision = evaluation.ok ? 'promoted' : evaluation.status;

  let finding = null;
  if (evaluation.ok) {
    const h = hypothesis;
    const base = {
      id: `promoted-${hypothesisId}`, stableId: hypothesisId,
      severity: capSeverity(h.severity, policy.maxSeverity),
      file: h.file, line: h.line, vuln: h.vuln, cwe: h.cwe, description: h.description, remediation: h.remediation,
      // A promoted finding is no longer a hunt hypothesis: it carries neither the hunt parser nor the `discovery` stamp, so the
      // advisory exclusion does not apply to it, and its origin lives in `promotedFrom`.
      parser: 'PROMOTED-HYPOTHESIS', family: h.family ?? 'other', ruleId: h.ruleId ?? 'promoted-hypothesis', snippet: h.snippet ?? '',
    };
    finding = { ...base, verificationRecord: JSON.parse(JSON.stringify(evaluation.record)) };
  }

  const audit = {
    schema: AUDIT_SCHEMA, schemaVersion: AUDIT_VERSION, decision,
    sourceHypothesis: {
      id: hypothesisId, digest: digestOf(isPlainObject(hypothesis) ? hypothesis : null),
      origin: { lens: hypothesis?.discovery?.lens ?? null, parser: hypothesis?.parser ?? null, family: hypothesis?.family ?? null },
    },
    promotedFinding: finding ? { stableId: finding.stableId, id: finding.id } : null,
    verification: {
      recordId: evaluation.record?.id ?? null, receiptDigest: isIssuedReceipt(result?.receipt) ? result.receipt.receiptDigest : null,
      oracle: evaluation.record?.oracle ?? null, outcome: evaluation.record?.outcome ?? null,
      confirmationLevel: evaluation.record?.confirmationLevel ?? null, commit: evaluation.record?.commit ?? null,
    },
    policy: { id: isPlainObject(policy) ? policy.id ?? null : null, version: isPlainObject(policy) ? policy.version ?? null : null, digest: evaluation.policyDigest, rules: evaluation.rules },
  };
  audit.id = semanticId('padt', audit, ['decision', 'sourceHypothesis', 'promotedFinding', 'verification', 'policy']);
  deepFreeze(audit);
  if (finding) {
    finding.promotedFrom = { hypothesisId, auditId: audit.id, lens: hypothesis?.discovery?.lens ?? null };
    deepFreeze(finding);
    PROMOTED.add(finding);
  }
  return { ok: !!finding, decision, finding, audit, evaluation };
}

/** Do an audit record, the hypothesis it names and the promoted finding it names agree? (The link, checked from both ends.) */
export function auditLinksHold({ audit, hypothesis, finding }) {
  if (!isPlainObject(audit) || audit.schema !== AUDIT_SCHEMA) return false;
  const hid = isPlainObject(hypothesis) ? hypothesisIdFromFinding(hypothesis) : null;
  if (!hid || audit.sourceHypothesis?.id !== hid || audit.sourceHypothesis?.digest !== digestOf(hypothesis)) return false;
  if (audit.id !== semanticId('padt', audit, ['decision', 'sourceHypothesis', 'promotedFinding', 'verification', 'policy'])) return false;
  if (audit.decision !== 'promoted') return finding == null && audit.promotedFinding === null;
  return isPromotedFinding(finding) && finding.promotedFrom?.auditId === audit.id && finding.promotedFrom?.hypothesisId === hid
    && audit.promotedFinding?.stableId === finding.stableId && finding.verificationRecord?.id === audit.verification.recordId;
}

function deepFreeze(o) {
  for (const v of Object.values(o)) if (v && typeof v === 'object' && !Object.isFrozen(v)) deepFreeze(v);
  return Object.freeze(o);
}
