// Canary window, circuit breaker and rollback (X-606.AC02), and the drift-aware route entry point (X-606.AC01).
//
// Lifecycle (PRD section 8, routing policy): offline -> shadow -> canary -> active, with degradation sending the policy back to the
// previous known-good one. This module owns the last three steps.
//
//   shadow           the candidate only records proposals (shadow.js); production is the known-good policy
//   canary           a deterministic share of tasks (by task id hash, no randomness) is served by the candidate, under FINITE limits:
//                    a task count, a spend budget, an error-rate threshold, a consecutive-error (outage) threshold and an incorrect-rate
//                    threshold. An outcome with an unknown cost is charged at `perCallUsdCeiling`, never at zero.
//   canary-complete  the canary ran its finite window without tripping; the candidate receives no further traffic until `activate`
//   active           only reachable through `activate`, which needs a promotion verdict of `pass` (promotion.js): a canary that merely
//                    did not fail is not evidence of an advantage
//   rolled-back      a limit tripped (or drift invalidated the evidence); the known-good policy is restored and stays active
//
// Receipts are never lost. Every start, trip, completion, activation and rollback is appended to the hash-chained receipt log
// (receipts.js), and a rollback only appends. `observe` after a rollback is refused, so a degraded policy cannot keep accruing.

import { digestOf } from '../assurance/identity.js';
import { FAILURE_STATUSES } from './outcomes.js';
import { createReceiptLog } from './receipts.js';
import { routeConstrained } from './decide.js';

export const CANARY_STATES = Object.freeze(['shadow', 'canary', 'canary-complete', 'active', 'rolled-back']);
export const CANARY_CEILINGS = Object.freeze({ maxTasks: 10_000, budgetUsd: 1000 });
export const TRIP_CODES = Object.freeze(['budget-exhausted', 'provider-outage', 'error-rate', 'degraded-quality', 'drift-invalidation']);

function validateLimits(l) {
  const errors = [];
  const bad = (k, m) => errors.push({ path: k, message: m });
  if (!l || typeof l !== 'object') return [{ path: '', message: 'limits are required: a canary has no unbounded mode' }];
  if (!(Number.isInteger(l.maxTasks) && l.maxTasks >= 1 && l.maxTasks <= CANARY_CEILINGS.maxTasks)) bad('maxTasks', `a finite task count of 1 to ${CANARY_CEILINGS.maxTasks}`);
  if (!(typeof l.budgetUsd === 'number' && l.budgetUsd > 0 && l.budgetUsd <= CANARY_CEILINGS.budgetUsd)) bad('budgetUsd', `a finite budget above 0 and at most ${CANARY_CEILINGS.budgetUsd}`);
  if (!(typeof l.perCallUsdCeiling === 'number' && l.perCallUsdCeiling > 0)) bad('perCallUsdCeiling', 'a positive ceiling charged for any outcome of unknown cost');
  if (!(typeof l.maxErrorRate === 'number' && l.maxErrorRate >= 0 && l.maxErrorRate <= 1)) bad('maxErrorRate', 'a rate in [0, 1]');
  if (!(Number.isInteger(l.minSamples) && l.minSamples >= 1)) bad('minSamples', 'the sample count before rates are judged');
  if (!(Number.isInteger(l.maxConsecutiveErrors) && l.maxConsecutiveErrors >= 1)) bad('maxConsecutiveErrors', 'the run of errors that counts as an outage');
  if (!(typeof l.maxIncorrectRate === 'number' && l.maxIncorrectRate >= 0 && l.maxIncorrectRate <= 1)) bad('maxIncorrectRate', 'a rate in [0, 1]');
  if (!(Number.isInteger(l.minDecided) && l.minDecided >= 1)) bad('minDecided', 'the decided-outcome count before quality is judged');
  return errors;
}

const shareBucket = (taskId) => parseInt(digestOf({ canary: taskId }).slice('sha256:'.length, 'sha256:'.length + 8), 16) / 0x1_0000_0000;

/**
 * @param {object} o
 * @param {{policyVersion:string}} o.knownGood   the policy to restore (and to serve outside the canary)
 * @param {{policyVersion:string}} o.candidate
 * @param {object} o.limits
 * @param {number} [o.canaryShare]  fraction of tasks served by the candidate while the canary runs, in (0, 1]
 * @param {object} [o.log]          receipt log; one is created when absent
 */
export function createCanary({ knownGood, candidate, limits, canaryShare = 0.1, log = null }) {
  const errs = validateLimits(limits);
  if (!knownGood?.policyVersion || !candidate?.policyVersion) errs.push({ path: 'policy', message: 'both a known-good and a candidate policy version are required' });
  if (!(typeof canaryShare === 'number' && canaryShare > 0 && canaryShare <= 1)) errs.push({ path: 'canaryShare', message: 'a share in (0, 1]' });
  if (errs.length) return { ok: false, errors: errs };
  const receipts = log || createReceiptLog();
  let state = 'shadow';
  let rollback = null;
  const c = { candidateTasks: 0, spentUsd: 0, errors: 0, consecutiveErrors: 0, decided: 0, incorrect: 0, knownGoodTasks: 0 };
  const note = (kind, body) => receipts.append(kind, { policyCandidate: candidate.policyVersion, policyKnownGood: knownGood.policyVersion, state, ...body });
  const trip = (code, detail) => {
    state = 'rolled-back';
    rollback = { code, detail, restored: knownGood.policyVersion, counters: { ...c } };
    note('rollback', { code, detail, restored: knownGood.policyVersion, counters: { ...c } });
  };

  const api = {
    state: () => state,
    counters: () => ({ ...c }),
    rollbackInfo: () => (rollback ? { ...rollback } : null),
    limits: () => ({ ...limits, canaryShare }),
    /** The policy that serves production right now. */
    activePolicy: () => (state === 'active' ? candidate : knownGood),
    receipts: receipts,
    /** shadow -> canary. Needs at least one recorded shadow decision: a policy never seen proposing is not canaried. */
    start({ shadowRecords = 0 } = {}) {
      if (state !== 'shadow') return { ok: false, code: 'BAD_STATE', reason: `cannot start a canary from '${state}'` };
      if (!(shadowRecords >= 1)) return { ok: false, code: 'NO_SHADOW_EVIDENCE', reason: 'a canary follows shadow mode: no shadow decision has been recorded' };
      state = 'canary';
      note('canary', { event: 'start', shadowRecords, limits: { ...limits, canaryShare } });
      return { ok: true };
    },
    /** Which policy serves this task. Deterministic; the candidate is never selected outside the canary window or past its budget. */
    select(taskId) {
      if (state === 'active') return { arm: 'candidate', policyVersion: candidate.policyVersion };
      if (state === 'canary' && c.candidateTasks < limits.maxTasks && c.spentUsd + limits.perCallUsdCeiling <= limits.budgetUsd && shareBucket(String(taskId)) < canaryShare) {
        return { arm: 'candidate', policyVersion: candidate.policyVersion };
      }
      return { arm: 'known-good', policyVersion: knownGood.policyVersion };
    },
    /** Record the outcome of a task served by the candidate during the canary. */
    observe({ taskId = null, outcome }) {
      if (state !== 'canary') return { ok: false, code: 'NOT_IN_CANARY', reason: `the policy is '${state}'; no further observations are accepted` };
      if (!outcome || typeof outcome !== 'object') return { ok: false, code: 'BAD_OUTCOME', reason: 'an outcome record is required' };
      c.candidateTasks += 1;
      c.spentUsd += typeof outcome.costUsd === 'number' ? outcome.costUsd : limits.perCallUsdCeiling;
      const failed = FAILURE_STATUSES.includes(outcome.status);
      c.errors += failed ? 1 : 0;
      c.consecutiveErrors = failed ? c.consecutiveErrors + 1 : 0;
      if (outcome.outcome === 'correct' || outcome.outcome === 'incorrect') { c.decided += 1; if (outcome.outcome === 'incorrect') c.incorrect += 1; }
      note('canary', { event: 'observation', taskId, status: outcome.status, outcome: outcome.outcome, costUsd: outcome.costUsd ?? null, counters: { ...c } });
      if (c.spentUsd > limits.budgetUsd) trip('budget-exhausted', `spent ${c.spentUsd} of a ${limits.budgetUsd} canary budget`);
      else if (c.consecutiveErrors >= limits.maxConsecutiveErrors) trip('provider-outage', `${c.consecutiveErrors} consecutive failures (limit ${limits.maxConsecutiveErrors})`);
      else if (c.candidateTasks >= limits.minSamples && c.errors / c.candidateTasks > limits.maxErrorRate) trip('error-rate', `${c.errors}/${c.candidateTasks} failed (limit ${limits.maxErrorRate})`);
      else if (c.decided >= limits.minDecided && c.incorrect / c.decided > limits.maxIncorrectRate) trip('degraded-quality', `${c.incorrect}/${c.decided} decided outcomes incorrect (limit ${limits.maxIncorrectRate})`);
      else if (c.candidateTasks >= limits.maxTasks) { state = 'canary-complete'; note('canary', { event: 'window-complete', counters: { ...c } }); }
      return { ok: true, state, tripped: state === 'rolled-back' ? rollback.code : null };
    },
    /** An outside signal (drift.js) that the evidence behind the candidate is invalid. Restores the known-good policy. */
    reportDrift(assessment) {
      if (!assessment || assessment.state === 'active' || assessment.unchanged) return { ok: true, rolledBack: false };
      if (state === 'rolled-back') return { ok: true, rolledBack: true, already: true };
      trip('drift-invalidation', `${(assessment.kinds || []).join(', ') || 'unspecified'}: ${(assessment.invalidations || []).length} estimate(s) invalidated`);
      return { ok: true, rolledBack: true };
    },
    /** canary-complete -> active, only on a passing promotion verdict. */
    activate(verdict) {
      if (state !== 'canary-complete') return { ok: false, code: 'BAD_STATE', reason: `cannot activate from '${state}'` };
      if (!verdict || verdict.status !== 'pass') return { ok: false, code: 'NOT_PROMOTED', reason: `the promotion gate reads '${verdict ? verdict.status : 'absent'}': a canary that did not fail is not evidence of an advantage` };
      state = 'active';
      note('canary', { event: 'activate', verdictHash: verdict.verdictHash ?? null });
      return { ok: true };
    },
  };
  return { ok: true, canary: api };
}

/**
 * Route under the drift state. `fallback`: the production route stands and nothing is decided. `shadow`: the proposal is recorded
 * (through the recorder) and production stands. `active`: the constrained router decides.
 */
export function routeUnderDrift({ assessment, recorder, productionRoute, ...decideArgs }) {
  const state = assessment?.state ?? 'fallback';
  if (state === 'active') {
    const decision = routeConstrained({ ...decideArgs, baselineRoute: productionRoute });
    return { route: decision.selected ? { model: decision.selected.model } : null, decision, state };
  }
  if (state === 'shadow' && recorder) { const r = recorder.shadow({ productionRoute, ...decideArgs }); return { route: productionRoute, shadow: r.shadow, state, reason: assessment.documentedFallback }; }
  return { route: productionRoute, state: 'fallback', reason: assessment?.documentedFallback ?? 'no drift assessment: the existing route stands' };
}
