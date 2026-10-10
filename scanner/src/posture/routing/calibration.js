// Quality calibration by supported strata (X-603).
//
// From outcome records (outcomes.js) to a quality estimate per (model, model version, task stratum), each with an uncertainty
// interval and an explicit statement of whether it may be relied on. The central design choice: a stratum earns the label `reliable`
// only by clearing every one of these, and otherwise it carries a named fallback and NEVER the label.
//
//   population   at least 200 PAIRED adjudicated tasks overall (a task labelled for the baseline model AND a candidate) and at least
//                30 for the stratum (PRD section 5; frozen in ROUTING_MINIMUMS and a test pins them to the PRD numbers)
//   uncertainty  the grouped bootstrap (evaluation/interval.js, the same method the accuracy reports register) over HELD-OUT outcomes
//                is `measured`; below 10 independent groups it is `unmeasured` and the stratum cannot be reliable
//   stability    the held-out rate agrees with the development rate: a development rate outside the held-out 95% interval makes the
//                stratum `shifted`, and a stratum with no development baseline cannot be called stable
//   provenance   only outcomes decided by adjudication or trusted execution are used (outcomes.js); unknown and delayed are counted
//                and disclosed, never imputed
//   reality      a synthetic population can never produce `reliable`, only `reliable-synthetic`, which a production policy refuses
//
// Splits. Held-out data is what the estimate is computed on; development data only tests whether the held-out rate has shifted.
//   time          outcomes observed at or after `timeSplit.heldOutFrom` are held out
//   model version a (model, version) listed in `heldOutModelVersions` is held out entirely, so a new version is judged on its own
//                 data and never inherits a predecessor's. Estimates are per version and versions are never pooled.
//   group         a group (target, upstream, advisory) that appears on BOTH sides is removed from the held-out side and counted, so a
//                 near-duplicate cannot appear to generalise
//
// The artifact records dataset hashes, adjudication versions, sample counts and every exclusion with its reason, and rebuilds
// byte-for-byte from the same outcomes (`verifyCalibration`). No clock, no randomness beyond the seeded bootstrap.

import { digestOf } from '../assurance/identity.js';
import { groupedBootstrap, recallOf, wilsonInterval } from '../evaluation/interval.js';
import { stratumParents, FAILURE_STATUSES, validateRoutingOutcome } from './outcomes.js';
import { medianKnown } from './economics.js';

export const CALIBRATION_SCHEMA = 'agentic-security/routing-calibration';
const CALIBRATION_VERSION = '1.0.0';

/** PRD section 5, "Routing promotion". Frozen here so a config cannot quietly loosen them. */
export const ROUTING_MINIMUMS = Object.freeze({
  pairedTasksOverall: 200,
  pairedTasksPerStratum: 30,
  /** Development outcomes needed before a stratum's stability can be tested at all (an engineering choice, recorded in the artifact). */
  developmentPerStratum: 10,
});
/** The rest of the section 5 routing row, carried for the promotion gate (X-605). The comparison itself is not implemented here. */
export const ROUTING_PROMOTION_TARGETS = Object.freeze({
  qualityDifferenceLowerBound: -0.02, medianCostReduction: 0.20, qualityGain: 0.05, p95LatencyRatio: 1.2,
});

export const CALIBRATION_LABELS = Object.freeze(['reliable', 'reliable-synthetic', 'fallback-parent', 'shifted', 'insufficient-evidence']);
export const EXCLUSION_REASONS = Object.freeze([
  'invalid-record', 'duplicate', 'unlabelled-unknown', 'unlabelled-delayed', 'not-adjudicated-or-executed', 'missing-time', 'missing-group', 'group-straddles-split',
]);

const DAY = 86_400_000;
const T = (s) => Date.parse(s);
const round = (x) => (x === null || x === undefined ? null : Math.round(x * 1e9) / 1e9);

export function validateCalibrationConfig(c) {
  const errors = [];
  const bad = (path, message) => errors.push({ code: 'BAD_CALIBRATION_CONFIG', path, message });
  if (!c || typeof c !== 'object') return { ok: false, errors: [{ code: 'BAD_CALIBRATION_CONFIG', path: '', message: 'not an object' }] };
  if (typeof c.id !== 'string' || !c.id) bad('id', 'a configuration has an id');
  if (typeof c.baselineModel !== 'string' || !c.baselineModel) bad('baselineModel', 'the paired baseline model is named');
  if (!c.timeSplit || Number.isNaN(T(c.timeSplit.heldOutFrom))) bad('timeSplit.heldOutFrom', 'an ISO timestamp is required');
  if (c.heldOutModelVersions !== undefined && !Array.isArray(c.heldOutModelVersions)) bad('heldOutModelVersions', 'must be an array of { model, modelVersion }');
  const m = c.minimums || {};
  for (const [k, floor] of Object.entries(ROUTING_MINIMUMS)) {
    if (m[k] !== undefined && !(Number.isInteger(m[k]) && m[k] >= floor)) bad(`minimums.${k}`, `cannot be set below the preregistered minimum of ${floor}`);
  }
  if (c.replicates !== undefined && !(Number.isInteger(c.replicates) && c.replicates >= 100)) bad('replicates', 'at least 100 bootstrap resamples');
  return { ok: errors.length === 0, errors };
}

const keyOf = (o) => `${o.model}\u0000${o.modelVersion ?? ''}`;
const isDecided = (o) => (o.outcome === 'correct' || o.outcome === 'incorrect') && (o.labelSource === 'adjudication' || o.labelSource === 'trusted-execution');

function nearestRank(sorted, q) {
  if (!sorted.length) return null;
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1))];
}

/**
 * Build the calibration artifact.
 *
 * @param {object} o
 * @param {object[]} o.outcomes   routing-outcome records (outcomes.js). Order does not matter.
 * @param {object} o.config       { id, version, baselineModel, timeSplit:{heldOutFrom}, heldOutModelVersions?, minimums?, replicates? }
 * @returns {{ok:boolean, errors:object[], artifact?:object}}
 */
export function buildCalibration({ outcomes, config }) {
  const cv = validateCalibrationConfig(config);
  if (!cv.ok) return { ok: false, errors: cv.errors };
  const minimums = { ...ROUTING_MINIMUMS, ...(config.minimums || {}) };
  const replicates = config.replicates ?? 1000;
  const heldVersions = new Set((config.heldOutModelVersions || []).map((v) => `${v.model}\u0000${v.modelVersion ?? ''}`));
  const cutoff = T(config.timeSplit.heldOutFrom);
  const configCore = { id: config.id, version: config.version ?? null, baselineModel: config.baselineModel, timeSplit: { heldOutFrom: config.timeSplit.heldOutFrom }, heldOutModelVersions: [...heldVersions].sort(), minimums, replicates };
  const configHash = digestOf(configCore);

  const exclusions = Object.fromEntries(EXCLUSION_REASONS.map((r) => [r, 0]));
  const excludedIds = Object.fromEntries(EXCLUSION_REASONS.map((r) => [r, []]));
  const exclude = (reason, id) => { exclusions[reason] += 1; if (id) excludedIds[reason].push(id); };

  // 1. validity and duplicates
  const seen = new Set();
  const valid = [];
  const input = Array.isArray(outcomes) ? outcomes : [];
  for (const o of input) {
    if (!validateRoutingOutcome(o).ok) { exclude('invalid-record', o?.id ?? null); continue; }
    if (seen.has(o.id)) { exclude('duplicate', o.id); continue; }
    seen.add(o.id); valid.push(o);
  }
  valid.sort((a, b) => (a.id < b.id ? -1 : 1));

  const datasetHash = digestOf(valid.map((o) => ({
    id: o.id, taskId: o.taskId, model: o.model, modelVersion: o.modelVersion, stratum: o.stratum, outcome: o.outcome, labelSource: o.labelSource,
    adjudicationVersion: o.adjudicationVersion ?? null, group: o.group ?? null, observedAt: o.observedAt ?? null, status: o.status, synthetic: o.synthetic,
  })));
  const synthetic = valid.length > 0 && valid.some((o) => o.synthetic);

  // 2. usable (decided) outcomes; operational facts about the rest are counted, never imputed
  const usable = [];
  for (const o of valid) {
    if (!isDecided(o)) {
      if (o.outcome === 'unknown') exclude('unlabelled-unknown', o.id);
      else if (o.outcome === 'delayed') exclude('unlabelled-delayed', o.id);
      else exclude('not-adjudicated-or-executed', o.id);
      continue;
    }
    if (!o.observedAt || Number.isNaN(T(o.observedAt))) { exclude('missing-time', o.id); continue; }
    if (!o.group) { exclude('missing-group', o.id); continue; }
    usable.push(o);
  }

  // 3. splits
  const isHeld = (o) => heldVersions.has(keyOf(o)) || T(o.observedAt) >= cutoff;
  const dev = usable.filter((o) => !isHeld(o));
  let held = usable.filter(isHeld);
  const devGroups = new Set(dev.map((o) => o.group));
  const straddlers = held.filter((o) => devGroups.has(o.group));
  for (const o of straddlers) exclude('group-straddles-split', o.id);
  const straddleIds = new Set(straddlers.map((o) => o.id));
  held = held.filter((o) => !straddleIds.has(o.id));

  // 4. pairing against the baseline, on held-out data
  const baseline = config.baselineModel;
  const labelledBy = new Map(); // taskId -> Set(model)
  for (const o of held) { if (!labelledBy.has(o.taskId)) labelledBy.set(o.taskId, new Set()); labelledBy.get(o.taskId).add(o.model); }
  const pairedTasks = [...labelledBy.entries()].filter(([, ms]) => ms.has(baseline) && [...ms].some((m) => m !== baseline)).map(([t]) => t).sort();
  const overallPaired = pairedTasks.length;
  const overallMet = overallPaired >= minimums.pairedTasksOverall;
  const pairedSet = new Set(pairedTasks);

  // 5. estimates per (model, version, stratum) and per parent level
  const heldBy = new Map(); const devByModel = new Map();
  const add = (map, k, o) => { if (!map.has(k)) map.set(k, []); map.get(k).push(o); };
  for (const o of held) { add(heldBy, keyOf(o), o); }
  for (const o of dev) { add(devByModel, o.model, o); }
  const stratumOf = (o, depth) => o.stratum.split('|').slice(0, depth).join('|');
  const modelVersions = [...new Set(valid.map(keyOf))].sort();
  const estimates = [];
  for (const mk of modelVersions) {
    const [model, modelVersion] = mk.split('\u0000');
    const heldRows = heldBy.get(mk) || [];
    const strata = new Set(valid.filter((o) => keyOf(o) === mk).map((o) => o.stratum));
    const levels = new Map(); // stratum key -> depth
    for (const s of strata) { levels.set(s, 4); for (const p of stratumParents(s)) levels.set(p, p.split('|').length); }
    for (const [stratum, depth] of [...levels.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      const rows = heldRows.filter((o) => stratumOf(o, depth) === stratum);
      const devRows = (devByModel.get(model) || []).filter((o) => stratumOf(o, depth) === stratum);
      const correct = rows.filter((o) => o.outcome === 'correct').length;
      const n = rows.length;
      const units = rows.map((o) => ({ id: o.id, language: 'all', tp: o.outcome === 'correct' ? 1 : 0, fn: o.outcome === 'correct' ? 0 : 1, fp: 0, tn: 0 }));
      const groupOf = Object.fromEntries(rows.map((o) => [o.id, o.group]));
      const interval = n === 0 ? { method: 'grouped-bootstrap-95', status: 'unmeasured', low: null, high: null, groups: 0, reason: 'no held-out outcomes' }
        : groupedBootstrap({ units, groupOf, statistic: (a) => recallOf(a.total), name: `routing-quality|${mk}|${stratum}`, protocolHash: `${configHash}|${datasetHash}`, replicates });
      const accuracy = n ? correct / n : null;
      const w = wilsonInterval(correct, n);
      const devN = devRows.length;
      const devAcc = devN ? devRows.filter((o) => o.outcome === 'correct').length / devN : null;
      let shift = 'untested';
      if (devN >= minimums.developmentPerStratum && w.status === 'measured') shift = devAcc < w.low || devAcc > w.high ? 'shifted' : 'stable';
      const paired = model === baseline ? n : rows.filter((o) => pairedSet.has(o.taskId)).length;
      const scope = valid.filter((o) => keyOf(o) === mk && stratumOf(o, depth) === stratum);
      const op = { total: scope.length, failed: 0, timeout: 0, cancelled: 0, providerError: 0, blocked: 0, partial: 0, unlabelled: 0 };
      for (const o of scope) {
        if (o.status === 'timeout') op.timeout += 1; else if (o.status === 'cancelled') op.cancelled += 1; else if (o.status === 'provider-error') op.providerError += 1;
        else if (o.status === 'blocked') op.blocked += 1; else if (o.status === 'failed') op.failed += 1; else if (o.status === 'partial') op.partial += 1;
        if (!isDecided(o)) op.unlabelled += 1;
      }
      const failuresNotInRows = scope.filter((o) => FAILURE_STATUSES.includes(o.status) && !isDecided(o)).length;
      const reasons = [];
      if (!overallMet) reasons.push(`only ${overallPaired} paired adjudicated task(s) overall; ${minimums.pairedTasksOverall} are required`);
      if (paired < minimums.pairedTasksPerStratum) reasons.push(`only ${paired} paired adjudicated task(s) in this stratum; ${minimums.pairedTasksPerStratum} are required`);
      if (n < minimums.pairedTasksPerStratum) reasons.push(`only ${n} held-out adjudicated outcome(s) for this model version; ${minimums.pairedTasksPerStratum} are required`);
      if (interval.status !== 'measured') reasons.push(`uncertainty interval is ${interval.status}${interval.reason ? `: ${interval.reason}` : ''}`);
      if (shift === 'untested') reasons.push(`no usable development baseline (needs ${minimums.developmentPerStratum}) to test for shift`);
      if (shift === 'shifted') reasons.push('the development rate lies outside the held-out 95% interval');
      const lat = scope.map((o) => o.latencyMs).filter((x) => typeof x === 'number').sort((x, y) => x - y);
      const costs = scope;
      const estimate = {
        model, modelVersion: modelVersion || null, stratum, level: depth === 4 ? 'stratum' : 'parent',
        n, correct, accuracy: round(accuracy), interval: { method: interval.method, status: interval.status, low: round(interval.low), high: round(interval.high), groups: interval.groups, ...(interval.reason ? { reason: interval.reason } : {}) },
        development: { n: devN, accuracy: round(devAcc) }, shift, pairedWithBaseline: paired,
        // operational failures are never silently ignored: the labelled rate above is over decided outcomes only
        operational: op,
        conservativeAccuracy: round(n + failuresNotInRows > 0 ? correct / (n + failuresNotInRows) : null),
        latencyMs: { n: lat.length, p50: round(nearestRank(lat, 0.5)), p95: round(nearestRank(lat, 0.95)) },
        costUsd: { n: costs.filter((o) => o.costUsd !== null).length, unknown: costs.filter((o) => o.costUsd === null).length, p50: round(medianKnown(costs.map((o) => o.costUsd))) },
        latestObservationAt: rows.concat(dev.filter((o) => keyOf(o) === mk && stratumOf(o, depth) === stratum)).map((o) => o.observedAt).sort().pop() ?? null,
        reasons,
        label: null, fallback: null,
      };
      const clears = overallMet && paired >= minimums.pairedTasksPerStratum && n >= minimums.pairedTasksPerStratum && interval.status === 'measured' && shift === 'stable';
      estimate.label = clears ? (synthetic ? 'reliable-synthetic' : 'reliable') : (shift === 'shifted' ? 'shifted' : 'insufficient-evidence');
      estimates.push(estimate);
    }
  }
  // 6. explicit fallback for every stratum-level estimate that is not reliable
  const isReliable = (e) => e.label === 'reliable' || e.label === 'reliable-synthetic';
  const find = (model, version, stratum) => estimates.find((e) => e.model === model && e.modelVersion === version && e.stratum === stratum);
  for (const e of estimates) {
    if (isReliable(e)) { e.fallback = null; continue; }
    if (e.label !== 'shifted') {
      for (const p of stratumParents(e.stratum)) {
        const pe = find(e.model, e.modelVersion, p);
        if (pe && isReliable(pe)) { e.fallback = { policy: 'parent-stratum', from: p, parentLabel: pe.label, parentAccuracy: pe.accuracy, parentInterval: pe.interval }; if (e.level === 'stratum') e.label = 'fallback-parent'; break; }
      }
    }
    if (!e.fallback) e.fallback = { policy: 'baseline-model', model: baseline, note: 'no reliable evidence for this model version in this stratum; the baseline route stands' };
  }
  estimates.sort((a, b) => (`${a.model}|${a.modelVersion}|${a.stratum}` < `${b.model}|${b.modelVersion}|${b.stratum}` ? -1 : 1));

  const adjudicationVersions = [...new Set(usable.map((o) => o.adjudicationVersion).filter(Boolean))].sort();
  const byStatus = {};
  for (const o of valid) byStatus[o.status] = (byStatus[o.status] || 0) + 1;
  const artifact = {
    schema: CALIBRATION_SCHEMA, schemaVersion: CALIBRATION_VERSION, synthetic,
    config: configCore, configHash,
    dataset: { hash: datasetHash, hashOf: 'sorted outcome identity, label, version, group and time fields', outcomeCount: input.length },
    adjudicationVersions,
    counts: { input: input.length, valid: valid.length, usable: usable.length, development: dev.length, heldOut: held.length, byStatus },
    exclusions: { counts: exclusions, ids: Object.fromEntries(Object.entries(excludedIds).map(([k, v]) => [k, v.sort()])) },
    pairing: { baselineModel: baseline, overallPairedHeldOut: overallPaired, requiredOverall: minimums.pairedTasksOverall, requiredPerStratum: minimums.pairedTasksPerStratum, overallMet },
    latestObservationAt: valid.map((o) => o.observedAt).filter(Boolean).sort().pop() ?? null,
    estimates,
    disclosure: 'quality is the rate of independently decided correct outcomes on held-out grouped data; operational failures are counted beside it and never dropped',
  };
  artifact.calibrationHash = digestOf({ ...artifact, calibrationHash: undefined });
  return { ok: true, errors: [], artifact: Object.freeze(artifact) };
}

/** Rebuild from the same outcomes and config and compare. A different hash means the artifact was edited or the inputs changed. */
export function verifyCalibration(artifact, { outcomes, config }) {
  if (!artifact || typeof artifact !== 'object') return { ok: false, reason: 'not an artifact' };
  const claimed = artifact.calibrationHash;
  const selfCheck = digestOf({ ...artifact, calibrationHash: undefined });
  if (selfCheck !== claimed) return { ok: false, reason: 'the artifact does not match its own hash (edited after it was built)' };
  const rebuilt = buildCalibration({ outcomes, config });
  if (!rebuilt.ok) return { ok: false, reason: 'configuration rejected', errors: rebuilt.errors };
  if (rebuilt.artifact.calibrationHash !== claimed) return { ok: false, reason: 'rebuilding from these outcomes and this configuration gives a different artifact' };
  return { ok: true, reason: 'rebuilt identically' };
}

/**
 * The population half of the PRD section 5 routing-promotion row. It can say the evidence is `insufficient-population`, `unmeasured`
 * (a synthetic population measures nothing real) or `population-sufficient`. It NEVER says pass: the paired quality, cost and latency
 * comparison is what promotion needs (X-605) and does not exist here.
 */
export function routingPopulationGate(artifact) {
  const base = { id: 'routing-promotion-population', thresholds: { ...ROUTING_MINIMUMS, ...ROUTING_PROMOTION_TARGETS }, promotion: 'not-evaluated' };
  if (!artifact) return { ...base, status: 'unmeasured', reason: 'no calibration artifact' };
  const paired = artifact.pairing?.overallPairedHeldOut ?? 0;
  const strata = artifact.estimates.filter((e) => e.level === 'stratum' && e.model !== artifact.pairing.baselineModel && e.pairedWithBaseline >= artifact.pairing.requiredPerStratum);
  const measured = { pairedTasks: paired, strataMeetingMinimum: strata.length };
  if (artifact.synthetic) return { ...base, status: 'unmeasured', measured, reason: 'the population is synthetic: it exercises the machinery and measures nothing about real routing' };
  if (paired < artifact.pairing.requiredOverall) return { ...base, status: 'insufficient-population', measured, reason: `${paired} paired adjudicated task(s); ${artifact.pairing.requiredOverall} are required` };
  if (!strata.length) return { ...base, status: 'insufficient-population', measured, reason: `no candidate stratum has ${artifact.pairing.requiredPerStratum} paired adjudicated tasks` };
  return { ...base, status: 'population-sufficient', measured, reason: 'the population minimums are met; promotion still needs the paired quality, cost and latency comparison, which is not evaluated here' };
}
