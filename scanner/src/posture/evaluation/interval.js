// Documented 95% interval methods (QA-004.AC01).
//
// Two methods, each registered by name in the protocol (`thresholds.intervalMethod`) before any result is observed:
//
//   grouped-bootstrap-95   For F1, precision and recall, and for the micro and macro aggregates. Resamples GROUPS, not cases:
//                          targets that share a pair, upstream, advisory, commit or template (grouping.js) are one resampling
//                          unit, because treating near-duplicates as independent draws makes the interval narrower than the
//                          evidence supports. The percentile method over `replicates` resamples (default 2000), driven by a
//                          seeded generator, so the same score and protocol produce the same interval to the last digit.
//                          The seed is derived from the protocol hash: nobody picks a seed after seeing a result.
//   wilson-95              For a single proportion (the completion rate), where there is no group structure to resample.
//
// When there are too few groups for resampling to mean anything (`minGroups`, default 10), the interval is `unmeasured` with the
// reason, never a degenerate zero-width or a made-up range. An undefined statistic in a resample (no positives drawn) is skipped
// and counted, and a method that skips too many resamples is itself reported `unmeasured`.
//
// Pure: no fs, no clock, no Math.random.

import * as crypto from 'node:crypto';

export const INTERVAL_METHODS = Object.freeze({
  'grouped-bootstrap-95': Object.freeze({
    level: 0.95,
    unit: 'target group (grouping.js union-find over pair, upstream, advisory, commit, template)',
    estimator: 'percentile',
    replicates: 2000,
    minGroups: 10,
    maxUndefinedFraction: 0.1,
    seed: 'first 32 bits of sha256(protocolHash + "|" + statisticName)',
  }),
  'wilson-95': Object.freeze({ level: 0.95, unit: 'case', estimator: 'wilson-score', z: 1.959964 }),
});

/** mulberry32: a small, well-distributed 32-bit generator. Deterministic for a given seed. */
export function seededRng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A 32-bit seed that depends only on the frozen protocol and the statistic's name. */
export function seedFor(protocolHash, statisticName) {
  return crypto.createHash('sha256').update(`${protocolHash}|${statisticName}`).digest().readUInt32BE(0);
}

const quantile = (sorted, q) => {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos); const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
};

const ZERO = () => ({ tp: 0, fn: 0, fp: 0, tn: 0 });
const add = (a, b) => { a.tp += b.tp; a.fn += b.fn; a.fp += b.fp; a.tn += b.tn; };

export const f1Of = (c) => (c.tp + c.fp + c.fn === 0 ? null : (2 * c.tp) / (2 * c.tp + c.fp + c.fn));
export const precisionOf = (c) => (c.tp + c.fp > 0 ? c.tp / (c.tp + c.fp) : null);
export const recallOf = (c) => (c.tp + c.fn > 0 ? c.tp / (c.tp + c.fn) : null);

/**
 * Grouped percentile bootstrap.
 * @param {object} o
 * @param {{id: string, language: string, tp: number, fn: number, fp: number, tn: number}[]} o.units  per-target tallies
 * @param {Object<string,string>} o.groupOf  target id -> group id (a target with no entry is its own group)
 * @param {(agg: {total: object, byLanguage: Object<string,object>}) => (number|null)} o.statistic
 * @param {string} o.name        the statistic's name (feeds the seed)
 * @param {string} o.protocolHash
 */
export function groupedBootstrap({ units, groupOf = {}, statistic, name, protocolHash, replicates = INTERVAL_METHODS['grouped-bootstrap-95'].replicates, minGroups = INTERVAL_METHODS['grouped-bootstrap-95'].minGroups, level = 0.95 }) {
  const method = 'grouped-bootstrap-95';
  const groups = new Map();
  for (const u of units || []) {
    const g = groupOf[u.id] || `solo:${u.id}`;
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(u);
  }
  const G = [...groups.keys()].sort();
  const aggOf = (members) => {
    const total = ZERO(); const byLanguage = {};
    for (const u of members) {
      add(total, u);
      byLanguage[u.language] = byLanguage[u.language] || ZERO();
      add(byLanguage[u.language], u);
    }
    return { total, byLanguage };
  };
  const all = aggOf(units || []);
  const point = statistic(all);
  const base = { method, level, replicates, groups: G.length, units: (units || []).length, point };
  if (G.length < minGroups) {
    return { ...base, status: 'unmeasured', low: null, high: null, reason: `${G.length} independent group${G.length === 1 ? '' : 's'}, fewer than the ${minGroups} needed for a resampling interval to mean anything` };
  }
  const rng = seededRng(seedFor(protocolHash, name));
  const perGroup = G.map((g) => aggOf(groups.get(g)));
  const draws = [];
  let undefinedDraws = 0;
  for (let r = 0; r < replicates; r++) {
    const total = ZERO(); const byLanguage = {};
    for (let i = 0; i < G.length; i++) {
      const pick = perGroup[Math.floor(rng() * G.length)];
      add(total, pick.total);
      for (const [lang, c] of Object.entries(pick.byLanguage)) { byLanguage[lang] = byLanguage[lang] || ZERO(); add(byLanguage[lang], c); }
    }
    const v = statistic({ total, byLanguage });
    if (v === null || v === undefined || Number.isNaN(v)) undefinedDraws++; else draws.push(v);
  }
  const maxUndef = INTERVAL_METHODS[method].maxUndefinedFraction;
  if (undefinedDraws / replicates > maxUndef) {
    return { ...base, status: 'unmeasured', low: null, high: null, undefinedDraws, reason: `the statistic was undefined in ${undefinedDraws} of ${replicates} resamples (more than ${maxUndef * 100}%), so the interval would describe a different population` };
  }
  draws.sort((a, b) => a - b);
  const alpha = (1 - level) / 2;
  return { ...base, status: 'measured', low: quantile(draws, alpha), high: quantile(draws, 1 - alpha), undefinedDraws, seed: seedFor(protocolHash, name) };
}

/** Wilson score interval for a proportion. n = 0 is unmeasured. */
export function wilsonInterval(successes, n, z = INTERVAL_METHODS['wilson-95'].z) {
  const method = 'wilson-95';
  if (!Number.isInteger(successes) || !Number.isInteger(n) || n <= 0 || successes < 0 || successes > n) {
    return { method, level: 0.95, status: 'unmeasured', point: null, low: null, high: null, successes, n, reason: 'no cases' };
  }
  const p = successes / n; const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { method, level: 0.95, status: 'measured', point: p, low: Math.max(0, centre - half), high: Math.min(1, centre + half), successes, n };
}
