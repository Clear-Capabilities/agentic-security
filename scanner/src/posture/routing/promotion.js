// Paired replay and the routing-promotion gate (X-605.AC02, X-605.AC03).
//
// The PRD section 5 routing row, in full:
//   >= 200 paired adjudicated tasks overall and >= 30 per promoted stratum;
//   lower 95% bound on the quality difference (proposed minus baseline) above -0.02;
//   measured median cost >= 20% lower, OR quality >= +0.05 at no higher median cost;
//   p95 latency <= 1.2x baseline; full failure reporting; retries, cache and tools accounted for.
//
// The comparison is over a FROZEN task set (`freezeTaskSet`): a hash of the task ids and strata fixed before any outcome is looked at.
// `replayPaired` pairs, for every frozen task, the baseline arm (the model production used) with the proposed arm (the model the
// shadow decision picked) from recorded outcomes. It issues no provider call unless the caller supplies BOTH an `invoke` function and a
// bounded authorization (a finite call count, a finite spend, a per-call ceiling for unknown costs); without both it is offline, and
// an `invoke` without a valid authorization is refused (`UNBOUNDED_REPLAY`). A replay that stops at its bound leaves tasks unpaired.
//
// What invalidates the gate (status `invalid`, whatever the figures say):
//   cherry-picked    the paired task set differs from the frozen set (an extra task, or a task not in the frozen set)
//   dropped          a frozen task has no pair: no shadow record, a missing or ambiguous outcome, or a replay that ran out of bound
//   unbounded        a replay that ran unauthorized, over its bounds, or was truncated
//   edited           the replay or frozen set no longer matches its own hash
// A FAILED arm is never dropped: a failure status, a timeout, a blocked proposal or a task the proposed policy left unserved counts as
// not-correct in the quality comparison and is reported. A pair where correctness is still unknown for either arm is counted
// (`unadjudicated`) and kept out of the quality statistic, never imputed.
//
// Synthetic data can never pass: the verdict is `unmeasured`. Nothing here claims an improvement.

import { groupedBootstrap } from '../evaluation/interval.js';
import { digestOf } from '../assurance/identity.js';
import { ROUTING_MINIMUMS, ROUTING_PROMOTION_TARGETS } from './calibration.js';
import { FAILURE_STATUSES, validateRoutingOutcome } from './outcomes.js';

export const FROZEN_SET_SCHEMA = 'agentic-security/routing-frozen-task-set';
export const REPLAY_SCHEMA = 'agentic-security/routing-paired-replay';
export const PROMOTION_SCHEMA = 'agentic-security/routing-promotion-verdict';
export const REPLAY_LIMITS = Object.freeze({ maxCalls: 1000, maxUsd: 1000 });
export const INVALIDATION_CODES = Object.freeze(['frozen-set-edited', 'replay-edited', 'cherry-picked', 'dropped-tasks', 'unbounded-replay', 'truncated-replay']);

const keyOf = (taskId, model) => `${taskId}\u0000${model}`;

/** Fix the evaluation tasks before any outcome is examined. `tasks` are routing task records (outcomes.js). */
export function freezeTaskSet(tasks) {
  const list = Array.isArray(tasks) ? tasks : [];
  const seen = new Set();
  const rows = [];
  for (const t of list) {
    if (!t || typeof t.taskId !== 'string' || typeof t.stratum !== 'string') return { ok: false, code: 'BAD_TASK', reason: 'every frozen task needs a taskId and a stratum' };
    if (seen.has(t.taskId)) return { ok: false, code: 'DUPLICATE_TASK', reason: `task ${t.taskId} appears twice` };
    seen.add(t.taskId);
    rows.push({ taskId: t.taskId, stratum: t.stratum, synthetic: t.synthetic === true });
  }
  rows.sort((a, b) => (a.taskId < b.taskId ? -1 : 1));
  const strata = {};
  for (const r of rows) strata[r.stratum] = (strata[r.stratum] || 0) + 1;
  const frozen = { schema: FROZEN_SET_SCHEMA, count: rows.length, tasks: rows, strata, synthetic: rows.some((r) => r.synthetic) };
  frozen.hash = digestOf({ tasks: rows });
  return { ok: true, frozen: Object.freeze(frozen) };
}

const frozenIntact = (f) => !!f && Array.isArray(f.tasks) && digestOf({ tasks: f.tasks }) === f.hash;

function validAuthorization(a) {
  const finite = (v, hi) => typeof v === 'number' && Number.isFinite(v) && v > 0 && v <= hi;
  return !!a && typeof a.authorizedBy === 'string' && a.authorizedBy.length > 0
    && Number.isInteger(a.maxCalls) && a.maxCalls >= 1 && a.maxCalls <= REPLAY_LIMITS.maxCalls
    && finite(a.maxUsd, REPLAY_LIMITS.maxUsd) && finite(a.perCallUsdCeiling, REPLAY_LIMITS.maxUsd);
}

function qualityOf(outcome, served) {
  if (!served) return { quality: 0, kind: 'unserved' };
  if (outcome.outcome === 'correct') return { quality: 1, kind: 'correct' };
  if (outcome.outcome === 'incorrect') return { quality: 0, kind: 'incorrect' };
  if (FAILURE_STATUSES.includes(outcome.status)) return { quality: 0, kind: 'failed' };
  return { quality: null, kind: 'undecided' };
}

function armOf(model, outcome, served) {
  if (!served) return { model: null, modelVersion: null, served: false, outcomeId: null, status: 'unserved', quality: 0, kind: 'unserved', costUsd: 0, costStatus: 'measured', latencyMs: null, retries: 0, cacheState: 'unknown', synthetic: false, group: null };
  const q = qualityOf(outcome, true);
  return {
    model, modelVersion: outcome.modelVersion ?? null, served: true, outcomeId: outcome.id, status: outcome.status, quality: q.quality, kind: q.kind,
    costUsd: outcome.costUsd, costStatus: outcome.costStatus, latencyMs: outcome.latencyMs, retries: outcome.usage?.retries ?? 0, cacheState: outcome.cacheState,
    synthetic: outcome.synthetic === true, group: outcome.group ?? null,
  };
}

/**
 * Pair every frozen task's baseline arm with its proposed arm.
 *
 * @param {object} o
 * @param {object} o.frozen          freezeTaskSet().frozen
 * @param {object[]} o.shadowRecords shadow.js records (the latest per task is used)
 * @param {object[]} o.outcomes      recorded routing outcomes (outcomes.js)
 * @param {object} [o.authorization] { authorizedBy, maxCalls, maxUsd, perCallUsdCeiling }; only used with `invoke`
 * @param {(req:{task:object, model:string})=>Promise<object>} [o.invoke] injected paid replay; absent means offline
 * @param {object} [o.log]           receipt log
 */
export async function replayPaired({ frozen, shadowRecords, outcomes, authorization = null, invoke = null, log = null }) {
  if (!frozenIntact(frozen)) return { ok: false, code: 'FROZEN_SET_EDITED', reason: 'the frozen task set does not match its own hash' };
  if (invoke && !validAuthorization(authorization)) {
    return { ok: false, code: 'UNBOUNDED_REPLAY', reason: `a paid replay needs an authorization naming who approved it and finite maxCalls (<= ${REPLAY_LIMITS.maxCalls}), maxUsd (<= ${REPLAY_LIMITS.maxUsd}) and perCallUsdCeiling` };
  }
  const latest = new Map();
  for (const r of Array.isArray(shadowRecords) ? shadowRecords : []) latest.set(r.taskId, r);
  const pool = new Map();
  for (const o of Array.isArray(outcomes) ? outcomes : []) {
    if (!validateRoutingOutcome(o).ok) continue;
    const k = keyOf(o.taskId, o.model);
    if (!pool.has(k)) pool.set(k, []);
    pool.get(k).push(o);
  }
  const replay = { authorized: !!invoke, authorizedBy: invoke ? authorization.authorizedBy : null, bounds: invoke ? { maxCalls: authorization.maxCalls, maxUsd: authorization.maxUsd, perCallUsdCeiling: authorization.perCallUsdCeiling } : null, calls: 0, spentUsd: 0, truncated: false, offline: !invoke };
  const fetched = new Map(); // calls already made this replay, by (task, model)

  async function obtain(task, model) {
    const k = keyOf(task.taskId, model);
    const have = pool.get(k) || [];
    if (have.length > 1) return { problem: 'ambiguous-outcomes' };
    if (have.length === 1) return { outcome: have[0] };
    if (fetched.has(k)) return fetched.get(k);
    if (!invoke) return { problem: 'missing-outcome' };
    if (replay.calls >= authorization.maxCalls || replay.spentUsd + authorization.perCallUsdCeiling > authorization.maxUsd) {
      replay.truncated = true;
      return { problem: 'replay-bound-reached' };
    }
    replay.calls += 1;
    let out;
    try { out = await invoke({ task, model }); } catch { out = null; }
    let res;
    if (!out || !validateRoutingOutcome(out).ok || out.taskId !== task.taskId || out.model !== model) {
      replay.spentUsd += authorization.perCallUsdCeiling; // a failed or malformed replay is charged at the ceiling, never at zero
      res = { problem: 'invalid-replay-outcome' };
    } else {
      replay.spentUsd += typeof out.costUsd === 'number' ? out.costUsd : authorization.perCallUsdCeiling;
      res = { outcome: out };
    }
    fetched.set(k, res);
    return res;
  }

  const pairs = [];
  for (const t of frozen.tasks) {
    const rec = latest.get(t.taskId);
    if (!rec) { pairs.push({ taskId: t.taskId, stratum: t.stratum, status: 'dropped', dropReason: 'no-shadow-record' }); continue; }
    const taskLike = { taskId: t.taskId, stratum: t.stratum };
    const base = await obtain(taskLike, rec.production.model);
    const servedProposed = rec.proposed.model !== null && rec.proposed.model !== undefined;
    const prop = servedProposed ? await obtain(taskLike, rec.proposed.model) : { unserved: true };
    if (base.problem || prop.problem) {
      pairs.push({ taskId: t.taskId, stratum: t.stratum, status: 'dropped', dropReason: base.problem || prop.problem, side: base.problem ? 'baseline' : 'proposed' });
      continue;
    }
    const a = armOf(rec.production.model, base.outcome, true);
    const b = servedProposed ? armOf(rec.proposed.model, prop.outcome, true) : armOf(null, null, false);
    pairs.push({
      taskId: t.taskId, stratum: t.stratum, status: 'paired', group: a.group || b.group || t.taskId,
      proposedStatus: rec.proposed.status, proposedCode: rec.proposed.code, baseline: a, proposed: b,
    });
  }
  const out = { schema: REPLAY_SCHEMA, ok: true, frozenHash: frozen.hash, pairs, replay, paidCalls: replay.calls };
  out.replayHash = digestOf({ ...out, replayHash: undefined });
  if (log) log.append('replay', { frozenHash: frozen.hash, replayHash: out.replayHash, paired: pairs.filter((p) => p.status === 'paired').length, dropped: pairs.filter((p) => p.status === 'dropped').length, replay });
  return out;
}

// ---------------------------------------------------------------- statistics

const sortedNums = (xs) => xs.filter((x) => typeof x === 'number' && Number.isFinite(x)).sort((x, y) => x - y);
function median(xs) {
  const s = sortedNums(xs);
  if (!s.length) return null;
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
function nearestRank(xs, q) {
  const s = sortedNums(xs);
  return s.length ? s[Math.min(s.length - 1, Math.max(0, Math.ceil(q * s.length) - 1))] : null;
}
const round = (x) => (x === null || x === undefined ? null : Math.round(x * 1e9) / 1e9);
const tally = (arms, key, vocab) => { const o = Object.fromEntries(vocab.map((v) => [v, 0])); for (const a of arms) o[a[key]] = (o[a[key]] || 0) + 1; return o; };

/** One slice of pairs (overall or one stratum) against the section 5 criteria. */
function analyse(pairs, { replicates, protocolHash, name }) {
  const paired = pairs.filter((p) => p.status === 'paired');
  const adjudicated = paired.filter((p) => p.baseline.quality !== null && p.proposed.quality !== null);
  const n = adjudicated.length;
  const mean = (arm) => (n ? adjudicated.reduce((s, p) => s + p[arm].quality, 0) / n : null);
  const units = adjudicated.map((p) => {
    const pq = p.proposed.quality; const bq = p.baseline.quality;
    return { id: p.taskId, language: 'all', tp: pq === 1 && bq === 0 ? 1 : 0, fn: pq === 0 && bq === 1 ? 1 : 0, fp: 0, tn: pq === bq ? 1 : 0 };
  });
  const groupOf = Object.fromEntries(adjudicated.map((p) => [p.taskId, p.group]));
  const diffStat = (a) => { const t = a.total; const d = t.tp + t.fn + t.fp + t.tn; return d ? (t.tp - t.fn) / d : null; };
  const interval = n === 0 ? { status: 'unmeasured', low: null, high: null, point: null, reason: 'no paired adjudicated task' }
    : groupedBootstrap({ units, groupOf, statistic: diffStat, name, protocolHash, replicates });
  const diffPoint = n ? units.reduce((s, u) => s + u.tp - u.fn, 0) / n : null;

  const arms = (k) => adjudicated.map((p) => p[k]);
  const costKnown = adjudicated.every((p) => p.baseline.costStatus === 'measured' && typeof p.baseline.costUsd === 'number' && p.proposed.costStatus === 'measured' && typeof p.proposed.costUsd === 'number');
  const medBase = costKnown ? median(arms('baseline').map((a) => a.costUsd)) : null;
  const medProp = costKnown ? median(arms('proposed').map((a) => a.costUsd)) : null;
  const reduction = costKnown && medBase !== null && medBase > 0 ? 1 - medProp / medBase : null;
  const served = (k) => arms(k).filter((a) => a.served);
  const latencyKnown = n > 0 && ['baseline', 'proposed'].every((k) => served(k).every((a) => typeof a.latencyMs === 'number'));
  const p95Base = latencyKnown ? nearestRank(served('baseline').map((a) => a.latencyMs), 0.95) : null;
  const p95Prop = latencyKnown ? nearestRank(served('proposed').map((a) => a.latencyMs), 0.95) : null;
  const p95Ratio = latencyKnown && p95Base > 0 ? p95Prop / p95Base : null;

  const T = ROUTING_PROMOTION_TARGETS;
  const qualityLowerMet = interval.status === 'measured' ? interval.low > T.qualityDifferenceLowerBound : null;
  const costPath = reduction === null ? null : reduction >= T.medianCostReduction;
  // The quality path is stricter than the PRD wording: the lower bound must also clear zero, so a gain cannot rest on a point estimate.
  const qualityPath = interval.status === 'measured' && costKnown && medBase !== null ? (diffPoint >= T.qualityGain && interval.low > 0 && medProp <= medBase) : null;
  const advantageMet = costPath === true || qualityPath === true ? true : (costPath === null && qualityPath === null ? null : false);
  const latencyMet = p95Ratio === null ? null : p95Ratio <= T.p95LatencyRatio;
  const all = qualityLowerMet === true && advantageMet === true && latencyMet === true;
  const failuresOf = (k) => tally(paired.map((p) => p[k]), 'kind', ['correct', 'incorrect', 'failed', 'unserved', 'undecided']);

  return {
    pairedTasks: paired.length, adjudicated: n, unadjudicated: paired.length - n,
    quality: { baseline: round(mean('baseline')), proposed: round(mean('proposed')), difference: round(diffPoint), interval: { method: interval.method ?? 'grouped-bootstrap-95', status: interval.status, low: round(interval.low), high: round(interval.high), groups: interval.groups ?? 0, ...(interval.reason ? { reason: interval.reason } : {}) } },
    cost: { complete: costKnown, medianBaselineUsd: round(medBase), medianProposedUsd: round(medProp), medianReduction: round(reduction), totalBaselineUsd: costKnown ? round(arms('baseline').reduce((s, a) => s + a.costUsd, 0)) : null, totalProposedUsd: costKnown ? round(arms('proposed').reduce((s, a) => s + a.costUsd, 0)) : null, retriesBaseline: arms('baseline').reduce((s, a) => s + a.retries, 0), retriesProposed: arms('proposed').reduce((s, a) => s + a.retries, 0), basis: 'outcome cost covers input, output, cached input, retries and tool execution as measured by the adapter; an unknown cost makes the cost criterion unmet, never zero' },
    cache: { baseline: tally(arms('baseline'), 'cacheState', ['hit', 'partial', 'miss', 'ineligible', 'unknown']), proposed: tally(arms('proposed').filter((a) => a.served), 'cacheState', ['hit', 'partial', 'miss', 'ineligible', 'unknown']) },
    latencyMs: { complete: latencyKnown, baselineP50: latencyKnown ? nearestRank(served('baseline').map((a) => a.latencyMs), 0.5) : null, baselineP95: p95Base, proposedP50: latencyKnown ? nearestRank(served('proposed').map((a) => a.latencyMs), 0.5) : null, proposedP95: p95Prop, p95Ratio: round(p95Ratio) },
    failures: { baseline: failuresOf('baseline'), proposed: failuresOf('proposed') },
    criteria: { qualityLowerBound: { met: qualityLowerMet, need: `> ${T.qualityDifferenceLowerBound}`, value: round(interval.low) }, advantage: { met: advantageMet, costPath, qualityPath, needMedianCostReduction: T.medianCostReduction, needQualityGain: T.qualityGain }, p95Latency: { met: latencyMet, need: `<= ${T.p95LatencyRatio}x baseline`, value: round(p95Ratio) }, all },
  };
}

/**
 * Judge a paired replay against the section 5 routing-promotion row.
 * `status`: `invalid` | `unmeasured` | `insufficient-population` | `fail` | `pass`, in that precedence. Never throws.
 */
export function evaluatePromotion({ frozen, replay, replicates = 1000, log = null } = {}) {
  const invalidations = [];
  const inval = (code, detail) => invalidations.push({ code, detail });
  if (!frozenIntact(frozen)) inval('frozen-set-edited', 'the frozen task set does not match its own hash');
  if (!replay || replay.schema !== REPLAY_SCHEMA || digestOf({ ...replay, replayHash: undefined }) !== replay.replayHash) inval('replay-edited', 'the replay does not match its own hash');
  const pairs = Array.isArray(replay?.pairs) ? replay.pairs : [];
  if (frozenIntact(frozen) && replay) {
    if (replay.frozenHash !== frozen.hash) inval('cherry-picked', 'the replay was built against a different task set than the frozen one');
    const frozenIds = new Set(frozen.tasks.map((t) => t.taskId));
    const seen = new Map();
    for (const p of pairs) seen.set(p.taskId, (seen.get(p.taskId) || 0) + 1);
    const extras = [...seen.keys()].filter((id) => !frozenIds.has(id));
    const repeated = [...seen.entries()].filter(([, c]) => c > 1).map(([id]) => id);
    const absent = [...frozenIds].filter((id) => !seen.has(id));
    if (extras.length || repeated.length) inval('cherry-picked', `${extras.length} task(s) outside the frozen set, ${repeated.length} repeated`);
    if (absent.length) inval('dropped-tasks', `${absent.length} frozen task(s) are missing from the replay`);
  }
  const dropped = pairs.filter((p) => p.status === 'dropped');
  if (dropped.length) {
    const byReason = {};
    for (const d of dropped) byReason[d.dropReason] = (byReason[d.dropReason] || 0) + 1;
    inval('dropped-tasks', `${dropped.length} frozen task(s) could not be paired: ${Object.entries(byReason).map(([k, v]) => `${k} x${v}`).join(', ')}`);
  }
  const rp = replay?.replay;
  if (rp) {
    if (rp.truncated) inval('truncated-replay', 'the replay stopped at its bound, so tasks were left unpaired');
    if (rp.calls > 0 && (!rp.authorized || !rp.bounds || rp.calls > rp.bounds.maxCalls || rp.spentUsd > rp.bounds.maxUsd)) inval('unbounded-replay', 'paid calls were made without a valid authorization or beyond its bounds');
  }

  const protocolHash = frozen?.hash ?? 'no-frozen-set';
  const overall = analyse(pairs, { replicates, protocolHash, name: 'routing-promotion|overall' });
  const strata = {};
  for (const s of Object.keys(frozen?.strata ?? {}).sort()) {
    const sub = analyse(pairs.filter((p) => p.stratum === s), { replicates, protocolHash, name: `routing-promotion|${s}` });
    const enough = sub.adjudicated >= ROUTING_MINIMUMS.pairedTasksPerStratum;
    strata[s] = { ...sub, frozenTasks: frozen.strata[s], promoted: enough && sub.criteria.all, reason: !enough ? `${sub.adjudicated} paired adjudicated task(s); ${ROUTING_MINIMUMS.pairedTasksPerStratum} are required` : sub.criteria.all ? 'criteria met' : 'criteria not met' };
  }
  const promotedStrata = Object.entries(strata).filter(([, v]) => v.promoted).map(([k]) => k);
  const synthetic = (frozen?.synthetic === true) || pairs.some((p) => p.status === 'paired' && (p.baseline.synthetic || p.proposed.synthetic));

  let status; let reason;
  if (invalidations.length) { status = 'invalid'; reason = `the gate is invalidated: ${invalidations.map((i) => i.code).join(', ')}`; }
  else if (synthetic) { status = 'unmeasured'; reason = 'the population is synthetic: it exercises the machinery and measures nothing about real routing'; }
  else if (overall.adjudicated < ROUTING_MINIMUMS.pairedTasksOverall) { status = 'insufficient-population'; reason = `${overall.adjudicated} paired adjudicated task(s); ${ROUTING_MINIMUMS.pairedTasksOverall} are required`; }
  else if (!Object.values(strata).some((v) => v.adjudicated >= ROUTING_MINIMUMS.pairedTasksPerStratum)) { status = 'insufficient-population'; reason = `no stratum has ${ROUTING_MINIMUMS.pairedTasksPerStratum} paired adjudicated tasks`; }
  else if (!overall.criteria.all) { status = 'fail'; reason = 'the overall quality, cost or latency criteria are not met'; }
  else if (!promotedStrata.length) { status = 'fail'; reason = 'no stratum meets the criteria on its own sample'; }
  else { status = 'pass'; reason = `criteria met overall and in ${promotedStrata.length} stratum/strata`; }

  const versions = [...new Set(pairs.filter((p) => p.status === 'paired').flatMap((p) => [p.baseline, p.proposed]).filter((a) => a.served).map((a) => `${a.model}@${a.modelVersion ?? 'unversioned'}`))].sort();
  const verdict = {
    schema: PROMOTION_SCHEMA, status, reason, invalidations, synthetic, frozenHash: frozen?.hash ?? null, replayHash: replay?.replayHash ?? null,
    thresholds: { ...ROUTING_MINIMUMS, ...ROUTING_PROMOTION_TARGETS }, replicates,
    overall, strata, promotedStrata, testedModelVersions: versions,
    claim: status === 'pass' ? { allowed: true, scope: promotedStrata, modelVersions: versions, note: 'applies to the listed strata and model versions only' } : { allowed: false, note: 'no routing advantage is claimed' },
  };
  verdict.verdictHash = digestOf({ ...verdict, verdictHash: undefined });
  if (log) log.append('promotion', { status, reason, invalidations, verdictHash: verdict.verdictHash, frozenHash: verdict.frozenHash, replayHash: verdict.replayHash });
  return verdict;
}
