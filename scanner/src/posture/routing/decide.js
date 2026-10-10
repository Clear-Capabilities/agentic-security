// Constrained routing decisions (X-604).
//
// A decision is made in two stages that never swap places:
//
//   1. CONSTRAINTS. A candidate model is acceptable only if it is available, has every capability the task requires, is allowed to
//      receive the task's data (the egress policy, egress/policy.js, decides; the capability manifest's egress check is used when a
//      manifest is supplied), has a context window that fits the task, and has RELIABLE calibrated quality evidence that is fresh,
//      narrow enough and whose LOWER bound meets the policy's minimum quality, and fits the remaining budget.
//   2. OPTIMIZATION. Only among acceptable candidates is cost (or latency) minimised, using MEASURED cost and latency from the
//      calibration. A candidate with no measured cost is ranked behind every candidate that has one, on its catalog upper bound, and
//      the explanation says so.
//
// Every candidate is evaluated against every constraint and ALL failures are recorded, so the explanation shows why each was
// rejected, not only the first reason. When nothing is acceptable the outcome is one of:
//
//   fallback  the existing capability route (the baseline), but only if it passes the HARD constraints (capability, privacy, context,
//             budget). Its quality is then `unverified`, and the decision says so. `fallbackMode: 'block'` refuses this entirely.
//   blocked   with a code: `no-compliant-model`, `budget-exhausted`, `insufficient-quality-evidence`, `excessive-uncertainty`,
//             `stale-evidence`, `invalid-policy`. A blocked decision selects nothing. A constraint is never relaxed to find a route.
//
// Pure given its inputs: the clock is a parameter (`now`), the egress evaluator is injectable, no network.

import { digestOf } from '../assurance/identity.js';
import { evaluateEgress } from '../../egress/policy.js';
import { costOf } from './economics.js';

export const DECISION_SCHEMA = 'agentic-security/routing-decision';
const DECISION_VERSION = '1.0.0';
export const CONSTRAINTS = Object.freeze(['availability', 'capability', 'privacy', 'context', 'quality', 'uncertainty', 'freshness', 'budget']);
export const BLOCK_CODES = Object.freeze(['no-compliant-model', 'budget-exhausted', 'insufficient-quality-evidence', 'excessive-uncertainty', 'stale-evidence', 'invalid-policy', 'invalid-task']);
const HARD = Object.freeze(['availability', 'capability', 'privacy', 'context']);
const DAY = 86_400_000;

function deepFreeze(v) {
  if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.freeze(v); for (const k of Object.keys(v)) deepFreeze(v[k]); }
  return v;
}

export function validateRoutingPolicy(p) {
  const errors = [];
  const bad = (path, message) => errors.push({ code: 'BAD_POLICY', path, message });
  if (!p || typeof p !== 'object') return { ok: false, errors: [{ code: 'BAD_POLICY', path: '', message: 'not an object' }] };
  if (typeof p.version !== 'string' || !p.version) bad('version', 'a policy is versioned');
  const frac = (k, lo, hiOpen) => { if (!(typeof p[k] === 'number' && Number.isFinite(p[k]) && p[k] >= lo && p[k] <= 1)) bad(k, `must be a number in [${lo}, 1]`); else if (hiOpen && p[k] === lo) bad(k, 'must be above 0'); };
  frac('minQualityLower', 0, false); frac('maxIntervalWidth', 0, true);
  if (!(typeof p.maxEvidenceAgeDays === 'number' && p.maxEvidenceAgeDays > 0)) bad('maxEvidenceAgeDays', 'must be a positive number');
  if (!['cost', 'latency'].includes(p.objective)) bad('objective', "must be 'cost' or 'latency'");
  if (p.fallbackMode !== undefined && !['baseline-unverified', 'block'].includes(p.fallbackMode)) bad('fallbackMode', "must be 'baseline-unverified' or 'block'");
  if (!p.budget || !(typeof p.budget.remainingUsd === 'number' && Number.isFinite(p.budget.remainingUsd))) bad('budget.remainingUsd', 'a finite remaining budget is required');
  if (!(Number.isInteger(p.expectedOutputTokens) && p.expectedOutputTokens >= 0)) bad('expectedOutputTokens', 'a non-negative integer bound on output size is required');
  return { ok: errors.length === 0, errors };
}

/**
 * A candidate from the provider catalog's price entry plus operator-supplied facts. The catalog carries prices and cache models but
 * NOT capabilities or context windows, and this function does not invent them: a missing `maxContextTokens` stays null and the
 * candidate is rejected on the context constraint as unknown.
 */
export function candidateFromCatalog({ id, provider, modelVersion = null, priceBook, capabilities = [], maxContextTokens = null, endpoint = null, local = false, available = true }) {
  return { id, provider, modelVersion, capabilities: [...capabilities].sort(), maxContextTokens, endpoint, local, available, price: priceBook?.entries?.[id] ?? null };
}

const fresh = (artifact, est, now, maxDays) => {
  const latest = est?.latestObservationAt || artifact?.latestObservationAt || null;
  if (!latest || Number.isNaN(Date.parse(latest))) return { fresh: false, ageDays: null, latest };
  const ageDays = (Date.parse(now) - Date.parse(latest)) / DAY;
  return { fresh: ageDays >= 0 && ageDays <= maxDays, ageDays: Math.round(ageDays * 1000) / 1000, latest };
};

function expectedCost(c, task, policy, est) {
  const priced = c.price && costOf({
    usage: { inputTokens: task.contextTokens, outputTokens: policy.expectedOutputTokens, cachedInputTokens: 0, source: 'measured' },
    model: c.id, priceBook: { version: 'candidate-price', currency: 'USD', billingBasis: 'list-price', entries: { [c.id]: c.price } },
    toolExecutionUsd: 0, // the bound covers model tokens only; tool execution is priced by the caller's runner
  });
  // The upper bound is the catalog price on the full request with NO cache credit: a ceiling for the budget check, not a measurement.
  const upperUsd = priced && priced.totalStatus !== 'unknown' ? priced.totalUpperUsd : null;
  const measuredP50 = est && est.costUsd && est.costUsd.n > 0 ? est.costUsd.p50 : null;
  return { measuredP50Usd: measuredP50, boundUpperUsd: upperUsd, basis: measuredP50 !== null ? 'measured-median' : upperUsd !== null ? 'catalog-upper-bound' : 'unknown' };
}

/**
 * Decide a route for one task.
 *
 * @param {object} o
 * @param {object} o.task          from buildRoutingTask
 * @param {object[]} o.candidates  candidate descriptors (see candidateFromCatalog)
 * @param {object|null} o.calibration  buildCalibration() artifact
 * @param {object} o.policy        versioned routing policy (validateRoutingPolicy)
 * @param {string} o.now           ISO timestamp; the only clock this function sees
 * @param {{model:string, effort?:string, reason?:string}|null} o.baselineRoute  the existing capability route, used as the fallback
 * @param {(ctx)=>object} [o.egress]  egress evaluator, default evaluateEgress
 * @param {string} [o.scanRoot]
 * @param {((egressCtx)=>object)|null} [o.manifestEgress]  optional capability-manifest egress check, used INSTEAD of `egress`; for example
 *        `(ctx) => evaluateManifestEgress(bound, binding, ctx)` from capabilities/egress.js, which applies the task grant AND the operator policy
 */
export function routeConstrained({ task, candidates, calibration = null, policy, now, baselineRoute = null, egress = evaluateEgress, scanRoot = null, manifestEgress = null, allowSynthetic = false }) {
  const header = { schema: DECISION_SCHEMA, schemaVersion: DECISION_VERSION, policyVersion: policy?.version ?? null, taskId: task?.taskId ?? null, stratum: task?.stratum ?? null };
  const finish = (d) => { const out = { ...header, ...d }; out.decisionHash = digestOf({ ...out, decisionHash: undefined }); return deepFreeze(JSON.parse(JSON.stringify(out))); };
  const pv = validateRoutingPolicy(policy);
  if (!pv.ok) return finish({ status: 'blocked', code: 'invalid-policy', reason: pv.errors.map((e) => `${e.path}: ${e.message}`).join('; '), selected: null, candidates: [], alternatives: [], fallback: null });
  if (!task || !task.stratum || !Array.isArray(task.requiredCapabilities) || Number.isNaN(Date.parse(now))) {
    return finish({ status: 'blocked', code: 'invalid-task', reason: 'a valid task record and an ISO `now` are required', selected: null, candidates: [], alternatives: [], fallback: null });
  }
  const permitSynthetic = allowSynthetic === true || policy.allowSynthetic === true;
  const remaining = policy.budget.remainingUsd;
  const evalOne = (c) => {
    const rejections = [];
    const rej = (constraint, code, detail) => rejections.push({ constraint, code, detail });
    if (c.available === false) rej('availability', 'unavailable', 'the model is not currently available');
    const missing = task.requiredCapabilities.filter((cap) => !(c.capabilities || []).includes(cap));
    if (missing.length) rej('capability', 'missing-capability', `lacks: ${missing.join(', ')}`);
    // privacy: the egress policy decides whether this task's data class may go to this endpoint/model, and local endpoints are judged the same way
    if (!c.endpoint) rej('privacy', 'no-endpoint', 'no endpoint is configured, so the egress policy cannot clear it');
    else {
      const ectx = { scanRoot, purpose: 'routing-decision', endpoint: c.endpoint, model: c.id, dataClass: task.dataClass, contextTokens: task.contextTokens };
      let e;
      try { e = manifestEgress ? manifestEgress(ectx) : egress(ectx); } catch { e = { allowed: false, code: 'egress-error' }; }
      if (!e || e.allowed !== true) rej('privacy', 'egress-denied', (e && (e.reason || e.code || e.policy?.reason)) || 'egress policy denied');
    }
    if (c.maxContextTokens === null || c.maxContextTokens === undefined) rej('context', 'context-unknown', 'the model\'s context window is not known');
    else if (c.maxContextTokens < task.contextTokens + policy.expectedOutputTokens) rej('context', 'context-too-small', `needs ${task.contextTokens + policy.expectedOutputTokens} tokens, window is ${c.maxContextTokens}`);

    // quality evidence for exactly this model and version
    const est = calibration ? calibration.estimates.find((x) => x.model === c.id && (x.modelVersion ?? null) === (c.modelVersion ?? null) && x.stratum === task.stratum) : null;
    const anyVersion = calibration ? calibration.estimates.some((x) => x.model === c.id && x.stratum === task.stratum) : false;
    let quality = null;
    if (!est) rej('quality', anyVersion ? 'model-version-mismatch' : 'no-quality-evidence', anyVersion ? 'evidence exists only for another version of this model' : 'no calibration for this model and stratum');
    else {
      quality = { estimate: est.accuracy, low: est.interval.low, high: est.interval.high, n: est.n, label: est.label, shift: est.shift };
      const reliable = est.label === 'reliable' || (est.label === 'reliable-synthetic' && permitSynthetic);
      if (!reliable) rej('quality', est.label === 'reliable-synthetic' ? 'synthetic-evidence' : `not-reliable:${est.label}`, est.reasons.length ? est.reasons[0] : `calibration label is ${est.label}`);
      else if (est.interval.low === null || est.interval.low < policy.minQualityLower) rej('quality', 'below-minimum-quality', `lower bound ${est.interval.low} is under the required ${policy.minQualityLower}`);
      if (est.interval.low !== null && est.interval.high !== null && est.interval.high - est.interval.low > policy.maxIntervalWidth) rej('uncertainty', 'excessive-uncertainty', `interval width ${(est.interval.high - est.interval.low).toFixed(3)} exceeds ${policy.maxIntervalWidth}`);
      else if (est.interval.low === null) rej('uncertainty', 'unmeasured-uncertainty', 'no uncertainty interval could be measured');
    }
    const fr = est ? fresh(calibration, est, now, policy.maxEvidenceAgeDays) : { fresh: null, ageDays: null, latest: null };
    if (est && !fr.fresh) rej('freshness', 'stale-evidence', fr.latest ? `evidence is ${fr.ageDays} days old, over ${policy.maxEvidenceAgeDays}` : 'evidence has no observation time');

    const cost = expectedCost(c, task, policy, est);
    if (cost.boundUpperUsd === null && cost.measuredP50Usd === null) rej('budget', 'cost-unknown', 'no price and no measured cost: an unknown cost is never treated as free');
    else {
      // budget uses the LARGER of the catalog ceiling and the measured median, so neither can understate what a task may cost
      const need = Math.max(cost.boundUpperUsd ?? 0, cost.measuredP50Usd ?? 0);
      if (!(remaining > 0)) rej('budget', 'budget-exhausted', 'no budget remains');
      else if (need > remaining) rej('budget', 'over-budget', `expected at most ${need} against ${remaining} remaining`);
      if (typeof policy.budget.maxUsdPerTask === 'number' && need > policy.budget.maxUsdPerTask) rej('budget', 'over-task-cap', `expected at most ${need} against a per-task cap of ${policy.budget.maxUsdPerTask}`);
    }
    return {
      model: c.id, provider: c.provider ?? null, modelVersion: c.modelVersion ?? null, accepted: rejections.length === 0, rejections,
      quality, evidence: est ? { label: est.label, latestObservationAt: fr.latest, ageDays: fr.ageDays, fresh: fr.fresh, maxAgeDays: policy.maxEvidenceAgeDays, calibrationHash: calibration.calibrationHash } : null,
      expectedCost: cost, latencyMs: est ? est.latencyMs : null, hardCompliant: rejections.every((r) => !HARD.includes(r.constraint)),
      fitsBudget: rejections.every((r) => r.constraint !== 'budget'),
    };
  };
  const evaluated = [...candidates].sort((a, b) => (a.id < b.id ? -1 : 1)).map(evalOne);
  const accepted = evaluated.filter((e) => e.accepted);

  const rank = (e) => {
    if (policy.objective === 'latency') return [e.latencyMs && e.latencyMs.p50 !== null ? 0 : 1, e.latencyMs?.p50 ?? Infinity, e.expectedCost.measuredP50Usd ?? e.expectedCost.boundUpperUsd ?? Infinity, e.model];
    return [e.expectedCost.measuredP50Usd !== null ? 0 : 1, e.expectedCost.measuredP50Usd ?? e.expectedCost.boundUpperUsd ?? Infinity, e.latencyMs?.p50 ?? Infinity, e.model];
  };
  const cmp = (a, b) => { const ra = rank(a); const rb = rank(b); for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return ra[i] < rb[i] ? -1 : 1; return 0; };
  const summary = (e) => ({ model: e.model, modelVersion: e.modelVersion, accepted: e.accepted, rejections: e.rejections, quality: e.quality, evidence: e.evidence, expectedCost: e.expectedCost, latencyMs: e.latencyMs });

  if (accepted.length) {
    const ordered = [...accepted].sort(cmp);
    const sel = ordered[0];
    return finish({
      status: 'routed', code: null, reason: `selected ${sel.model}: every constraint met, lowest ${policy.objective === 'latency' ? 'p50 latency' : 'cost'} among ${accepted.length} acceptable candidate(s) (${sel.expectedCost.basis})`,
      selected: { model: sel.model, provider: sel.provider, modelVersion: sel.modelVersion, via: 'optimized' },
      candidates: evaluated.map(summary),
      alternatives: ordered.slice(1).map((e) => ({ model: e.model, why: `acceptable, but ${policy.objective === 'latency' ? 'slower' : 'costlier'} than the selection` })),
      expectedBounds: { quality: { low: sel.quality.low, high: sel.quality.high }, costUsd: { measuredMedian: sel.expectedCost.measuredP50Usd, upperBound: sel.expectedCost.boundUpperUsd, basis: sel.expectedCost.basis }, latencyMs: sel.latencyMs },
      evidence: sel.evidence, fallback: { considered: false, used: false }, synthetic: calibration?.synthetic === true || sel.quality.label === 'reliable-synthetic',
    });
  }

  // Nothing is acceptable. Classify why, then offer the bounded fallback or block.
  const hard = evaluated.filter((e) => e.hardCompliant);
  const anyRej = (code) => evaluated.some((e) => e.rejections.some((r) => r.code === code));
  const budgetExhausted = !(remaining > 0) || (hard.length > 0 && hard.every((e) => !e.fitsBudget));
  let code;
  if (!hard.length) code = 'no-compliant-model';
  else if (budgetExhausted) code = 'budget-exhausted';
  else if (hard.every((e) => e.rejections.some((r) => r.code === 'stale-evidence'))) code = 'stale-evidence';
  else if (hard.some((e) => e.rejections.some((r) => r.code === 'excessive-uncertainty')) && !anyRej('no-quality-evidence')) code = 'excessive-uncertainty';
  else code = 'insufficient-quality-evidence';

  const fb = baselineRoute && baselineRoute.model ? evaluated.find((e) => e.model === baselineRoute.model) : null;
  const fallbackInfo = { considered: !!baselineRoute, model: baselineRoute?.model ?? null, mode: policy.fallbackMode ?? 'baseline-unverified', used: false, qualityVerified: false };
  const base = { candidates: evaluated.map(summary), alternatives: [], expectedBounds: null, evidence: null, synthetic: calibration?.synthetic === true };
  const canFallback = code !== 'no-compliant-model' && code !== 'budget-exhausted' && (policy.fallbackMode ?? 'baseline-unverified') === 'baseline-unverified'
    && fb && fb.hardCompliant && fb.fitsBudget;
  // A fallback that could not be taken because it breaks a hard constraint or the budget is blocked, never relaxed.
  if (canFallback) {
    return finish({
      ...base, status: 'fallback', code, reason: `no model has reliable quality evidence that meets the policy (${code}); using the existing capability route ${fb.model}, which passes the capability, privacy, context and budget constraints. Its quality is UNVERIFIED.`,
      selected: { model: fb.model, provider: fb.provider, modelVersion: fb.modelVersion, via: 'fallback' },
      expectedBounds: { quality: null, costUsd: { measuredMedian: fb.expectedCost.measuredP50Usd, upperBound: fb.expectedCost.boundUpperUsd, basis: fb.expectedCost.basis }, latencyMs: fb.latencyMs },
      fallback: { ...fallbackInfo, used: true },
    });
  }
  return finish({
    ...base, status: 'blocked', code,
    reason: code === 'no-compliant-model' ? 'no candidate satisfies the capability, privacy and context constraints; no constraint was relaxed'
      : code === 'budget-exhausted' ? 'the remaining budget cannot cover any compliant candidate; no constraint was relaxed'
        : `${code}: no reliable evidence clears the policy and the baseline fallback ${fallbackInfo.mode === 'block' ? 'is disabled by policy' : 'does not satisfy the hard constraints or the budget'}`,
    selected: null, fallback: fallbackInfo,
  });
}
