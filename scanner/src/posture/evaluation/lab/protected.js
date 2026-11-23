// Protected baseline defects (contract-driven verification, C-AC06).
//
// The aggregate no-regression gate (`evaluation/gates.js`) compares scores; a configuration can lose a defect the baseline found
// reliably and still pass it, because a new detection elsewhere lifts the total. This gate compares DEFECTS. A defect is protected when
// the baseline run detected it stably (at the baseline's own preregistered stability threshold; a deterministic arm's single run
// counts as stable when it detected the defect). The current run loses it when the same arm no longer detects it stably on the same
// population. Every loss fails the gate unless an adjudicated exception covers exactly that arm and defect; the aggregate is reported
// beside the verdict and never changes it.
//
// What makes the policy "registered": it is a versioned record whose `registeredAt` precedes the current run's start, so its
// threshold and scope cannot be chosen after the result is known. An exception is adjudicated when it names a reviewer from the
// operator's reviewer policy (`reviewer-policy.json`), carries a reason, is bound to the current run's dataset hash, and has not
// expired. Anything else is listed as rejected with the reason and does not excuse the loss.
//
// Different populations (dataset hashes differ) or a run without per-defect stability cannot be compared: `unmeasured`, never pass.
import { digestOf } from '../../assurance/identity.js';

export const PROTECTED_POLICY_SCHEMA = 'agentic-security/protected-defect-policy';
const GATE_SCHEMA = 'agentic-security/protected-defect-gate';
const MIN_REASON = 20;

const isoOk = (s) => typeof s === 'string' && !Number.isNaN(Date.parse(s));

/** Validate a policy record. Returns `{ ok, errors }`. */
function validateProtectedPolicy(p) {
  const errors = [];
  if (!p || typeof p !== 'object' || p.schema !== PROTECTED_POLICY_SCHEMA) return { ok: false, errors: ['not a protected-defect policy'] };
  if (typeof p.id !== 'string' || !p.id) errors.push('policy.id is required');
  if (!Number.isInteger(p.version) || p.version < 1) errors.push('policy.version must be a positive integer');
  if (!isoOk(p.registeredAt)) errors.push('policy.registeredAt must be an ISO time');
  if (p.arms !== undefined && (!Array.isArray(p.arms) || !p.arms.every((a) => typeof a === 'string'))) errors.push('policy.arms must list arm ids');
  for (const [i, e] of (p.exceptions || []).entries()) {
    for (const k of ['armId', 'entryId', 'reason', 'adjudicatedBy', 'datasetHash', 'expires']) if (typeof e?.[k] !== 'string' || !e[k]) errors.push(`exceptions[${i}].${k} is required`);
  }
  return { ok: errors.length === 0, errors };
}

const armsOf = (run) => new Map((run?.stability?.arms || []).map((a) => [a.armId, a]));

/**
 * @param {object} o
 * @param {object} o.baseline   a stored lab run (the reference)
 * @param {object} o.current    a stored lab run (the configuration under test)
 * @param {object} o.policy     a registered protected-defect policy
 * @param {string[]} [o.reviewers]  the operator's reviewer ids
 * @param {string} [o.now]      ISO time the gate is evaluated at
 */
export function protectedDefectGate({ baseline, current, policy, reviewers = [], now = new Date().toISOString() }) {
  const base = { schema: GATE_SCHEMA, policy: policy ? { id: policy.id, version: policy.version, digest: digestOf(policy) } : null, baselineRunId: baseline?.runId ?? null, currentRunId: current?.runId ?? null };
  const v = validateProtectedPolicy(policy);
  if (!v.ok) return { ...base, status: 'fail', reason: `the policy is not valid: ${v.errors[0]}`, lost: [], exceptions: { accepted: [], rejected: [] } };
  if (!isoOk(current?.startedAt) || Date.parse(policy.registeredAt) > Date.parse(current.startedAt)) {
    return { ...base, status: 'fail', reason: 'the policy was registered after the run it judges started; a policy chosen after the result is not a registered policy', lost: [], exceptions: { accepted: [], rejected: [] } };
  }
  if (baseline?.dataset?.hash !== current?.dataset?.hash) return { ...base, status: 'unmeasured', reason: 'the two runs measured different populations (dataset hashes differ)', lost: [], exceptions: { accepted: [], rejected: [] } };
  if (!baseline?.stability || !current?.stability) return { ...base, status: 'unmeasured', reason: 'a run has no per-defect stability record (detect task not run)', lost: [], exceptions: { accepted: [], rejected: [] } };

  const bArms = armsOf(baseline); const cArms = armsOf(current);
  const armIds = [...bArms.keys()].filter((id) => !policy.arms || policy.arms.includes(id)).sort();
  const lost = []; const protectedCount = {}; const aggregate = [];
  for (const armId of armIds) {
    const b = bArms.get(armId);
    const prot = b.perDefect.filter((d) => d.stable);
    protectedCount[armId] = prot.length;
    const c = cArms.get(armId);
    const byEntry = new Map((c?.perDefect || []).map((d) => [d.entryId, d]));
    for (const d of prot) {
      const now2 = byEntry.get(d.entryId);
      if (!c) lost.push({ armId, entryId: d.entryId, cwe: d.cwe, baseline: `${d.detected}/${d.scheduled}`, current: null, why: 'arm-missing' });
      else if (!now2 || !now2.stable) lost.push({ armId, entryId: d.entryId, cwe: d.cwe, baseline: `${d.detected}/${d.scheduled}`, current: now2 ? `${now2.detected}/${now2.scheduled}` : null, why: now2 ? 'no-longer-stable' : 'defect-missing' });
    }
    aggregate.push({ armId, baselineStableRecall: b.stableRecall, currentStableRecall: c?.stableRecall ?? null, improved: c ? (c.stableRecall ?? 0) > (b.stableRecall ?? 0) : false });
  }

  const reviewerSet = new Set(reviewers);
  const accepted = []; const rejected = [];
  for (const e of policy.exceptions || []) {
    const why = !reviewerSet.has(e.adjudicatedBy) ? `${e.adjudicatedBy} is not a reviewer in the operator's reviewer policy`
      : e.reason.trim().length < MIN_REASON ? `the reason is shorter than ${MIN_REASON} characters`
      : e.datasetHash !== current.dataset.hash ? 'the exception is bound to a different population'
      : !isoOk(e.expires) || Date.parse(e.expires) <= Date.parse(now) ? 'the exception has expired'
      : !lost.some((l) => l.armId === e.armId && l.entryId === e.entryId) ? 'no protected defect of that arm was lost (unused)'
      : null;
    if (why) rejected.push({ armId: e.armId, entryId: e.entryId, why }); else accepted.push({ armId: e.armId, entryId: e.entryId, adjudicatedBy: e.adjudicatedBy, reason: e.reason, expires: e.expires });
  }
  const excused = (l) => accepted.some((a) => a.armId === l.armId && a.entryId === l.entryId);
  const unexcused = lost.filter((l) => !excused(l));
  return {
    ...base,
    status: unexcused.length ? 'fail' : 'pass',
    reason: unexcused.length ? `${unexcused.length} protected defect(s) lost without an adjudicated exception` : null,
    protected: protectedCount, lost: lost.map((l) => ({ ...l, excused: excused(l) })),
    exceptions: { accepted, rejected },
    aggregate, aggregateNote: 'reported beside the verdict; an improved aggregate never excuses a lost protected defect',
  };
}
