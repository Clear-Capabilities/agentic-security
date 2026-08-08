// R13 — multi-model routing gated on MEASURED trust.
//
// `model-routing.js` already routes by capability: crypto and auth go to the
// strongest model, hardening to the cheapest. That policy is a set of
// hand-written beliefs about which classes are hard. It has never been checked
// against what the cheap model actually gets wrong.
//
// This module supplies the check. A decision class may be downgraded to a
// cheaper model only once that model's measured MISS RATE clears a statistical
// bound — specifically the Wilson 95% UPPER bound, not the point estimate.
//
// WHY THE UPPER BOUND, AND WHY THAT IS THE WHOLE IDEA. "0 misses in 5 samples"
// has a point estimate of 0% and looks perfect. Its Wilson upper bound is
// about 52%: the data is equally consistent with a model that misses half the
// time. Routing on the point estimate would let five lucky samples hand a
// security decision to a model that fails constantly. The upper bound is what
// converts "we have not seen it fail" into "we have enough evidence that it
// rarely fails", and it is precisely what makes small-n evidence unusable
// rather than flattering. Small n cannot clear a tight threshold at all — that
// is the feature, not a limitation to engineer around.
//
// FAIL CLOSED. No evidence for a class means no downgrade. The expensive model
// is the safe default, so absence of data must never read as permission. This
// is the same rule as everywhere else here: an unverified check is not a pass.
//
// A MISS IS ASYMMETRIC. `record()` takes agreement with the trusted model, and
// what is counted is DISAGREEMENT WHERE THE CHEAP MODEL WAS WRONG — a missed
// true positive. A cheap model that is merely noisier (extra false positives)
// costs triage time; one that misses real vulnerabilities costs a breach. Only
// the second gates routing.

import { wilsonInterval } from './calibration.js';

// The default bar a cheap model must clear: its true miss rate must be below
// 5% with 95% confidence. Deliberately strict — this gates security decisions,
// and the cost of being wrong is a missed vulnerability, not a wasted token.
export const DEFAULT_MAX_MISS_RATE = 0.05;

// Below this, no bound is tight enough to matter and we refuse on principle
// rather than letting an unusually clean run through on a technicality.
export const MIN_SAMPLES = 30;

/**
 * An observation ledger, keyed by decision class.
 *
 * A "decision class" is whatever granularity routing decides at — this module
 * does not impose one. `model-routing.js` decides by CWE family and severity,
 * so `${model}::${cwe}` is the natural key there.
 */
export function createTrustLedger({ maxMissRate = DEFAULT_MAX_MISS_RATE, minSamples = MIN_SAMPLES } = {}) {
  /** @type {Map<string, {n:number, misses:number}>} */
  const classes = new Map();

  function _get(key) {
    let c = classes.get(key);
    if (!c) { c = { n: 0, misses: 0 }; classes.set(key, c); }
    return c;
  }

  return {
    maxMissRate,
    minSamples,

    /**
     * Record one adjudicated decision.
     * @param {string}  key    decision class
     * @param {boolean} missed did the cheap model MISS something the trusted
     *                         model caught? Extra false positives are not misses.
     */
    record(key, missed) {
      if (typeof key !== 'string' || !key) return false;
      const c = _get(key);
      c.n++;
      if (missed) c.misses++;
      return true;
    },

    observations(key) {
      const c = classes.get(key);
      return c ? { ...c } : { n: 0, misses: 0 };
    },

    /**
     * May this class be routed to the cheaper model?
     * @returns {{allowed:boolean, reason:string, n:number, misses:number,
     *            missRate:number|null, upperBound:number|null}}
     */
    verdict(key) {
      const { n, misses } = this.observations(key);
      if (n < minSamples) {
        return {
          allowed: false, n, misses, missRate: n ? misses / n : null, upperBound: null,
          reason: `only ${n} adjudicated sample(s) for '${key}'; ${minSamples} are required before a `
            + 'downgrade can be justified. No evidence is not permission — the stronger model stands.',
        };
      }
      // wilsonInterval is written for a SUCCESS count; the miss rate's interval
      // is the same computation with misses as the successes.
      const [, upper] = wilsonInterval(misses, n);
      const missRate = misses / n;
      if (upper > maxMissRate) {
        return {
          allowed: false, n, misses, missRate, upperBound: upper,
          reason: `measured miss rate ${(missRate * 100).toFixed(1)}% over ${n} samples, but the 95% upper `
            + `bound is ${(upper * 100).toFixed(1)}% — above the ${(maxMissRate * 100).toFixed(1)}% bar. `
            + 'The point estimate is not the claim; the data is still consistent with a worse model.',
        };
      }
      return {
        allowed: true, n, misses, missRate, upperBound: upper,
        reason: `${misses} miss(es) in ${n} samples; 95% upper bound ${(upper * 100).toFixed(1)}% is within the `
          + `${(maxMissRate * 100).toFixed(1)}% bar, so the cheaper model is justified for '${key}'.`,
      };
    },

    /** Every class with its verdict, for reporting. */
    report() {
      const out = {};
      for (const key of [...classes.keys()].sort()) out[key] = this.verdict(key);
      return out;
    },
  };
}

/**
 * Apply measured trust on top of a capability route.
 *
 * The capability route is the FLOOR, never overridden upward by this module:
 * measured trust can only permit a downgrade that policy already proposed, it
 * cannot promote a class the policy thinks is hard. Evidence about a cheap
 * model's miss rate says nothing about whether a hard class deserves a strong
 * one.
 *
 * @param {object} route     from routeModelForFinding: {model, effort, reason}
 * @param {object} proposal  the cheaper alternative: {model, effort}
 * @param {object} ledger    createTrustLedger()
 * @param {string} key       decision class
 */
export function applyMeasuredTrust(route, proposal, ledger, key) {
  if (!route || !proposal || !ledger) return { ...route, trust: null };
  const v = ledger.verdict(key);
  if (!v.allowed) {
    return {
      ...route,
      trust: { ...v, applied: false },
      reason: `${route.reason} Downgrade withheld: ${v.reason}`,
    };
  }
  return {
    model: proposal.model,
    effort: proposal.effort ?? route.effort,
    trust: { ...v, applied: true },
    reason: `Downgraded to ${proposal.model} on measured evidence: ${v.reason}`,
  };
}

/** One-line summary of a trust report. */
export function renderTrustSummary(report) {
  const keys = Object.keys(report || {});
  if (!keys.length) return null;
  const allowed = keys.filter(k => report[k].allowed);
  const short = keys.filter(k => report[k].n < MIN_SAMPLES);
  return `measured-trust routing: ${allowed.length}/${keys.length} class(es) cleared the `
    + `95% upper-bound bar; ${short.length} still below the ${MIN_SAMPLES}-sample minimum `
    + '(those keep the stronger model).';
}
