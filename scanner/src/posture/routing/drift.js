// Drift detection and explicit invalidation (X-606.AC01).
//
// A calibration is evidence about one model version, one price book, one set of record schemas and one measured quality level. When
// any of those moves, the estimates built on them no longer describe what the router would be choosing, and silently carrying them
// forward is the failure this module exists to prevent.
//
//   snapshotRoutingBasis   what the policy was promoted on: calibration hash, per-model version, per-model price digest, schema versions
//   assessDrift            compare a snapshot with the present, plus a window of recent decided outcomes
//   applyInvalidations     a DERIVED calibration in which the affected estimates are labelled `invalidated` (quality, version, schema)
//                          or have their measured cost removed (pricing), with the reason on the estimate and the artifact
//
// Kinds of drift and what each invalidates:
//   model-version    the candidate's current version differs from the calibrated one (or is no longer reported): that model's estimates
//   schema           a record or calibration schema version differs: every estimate
//   pricing          the model's price entry changed: its measured COST (decisions fall back to the catalog upper bound); quality stands
//   quality-shift    recent decided outcomes sit significantly below the calibrated lower bound: that model/stratum estimate
//
// State on any invalidation is the policy's documented choice: `fallback` (the existing capability route stands, because invalidated
// estimates are refused by the constrained router) or `shadow` (proposals are recorded, production is untouched). It is never
// `active`, and the assessment says which estimates were invalidated and why. No clock and no network: `now` is not even needed.

import { digestOf } from '../assurance/identity.js';
import { wilsonInterval } from '../evaluation/interval.js';
import { CALIBRATION_SCHEMA } from './calibration.js';
import { ROUTING_OUTCOME_SCHEMA } from './outcomes.js';
import { DECISION_SCHEMA } from './decide.js';

export const BASIS_SCHEMA = 'agentic-security/routing-basis-snapshot';
export const DRIFT_KINDS = Object.freeze(['model-version', 'schema', 'pricing', 'quality-shift']);
export const DRIFT_STATES = Object.freeze(['active', 'fallback', 'shadow']);
export const DRIFT_DEFAULTS = Object.freeze({ onInvalidation: 'fallback', minRecentDecided: 30 });
export const SCHEMA_VERSIONS = Object.freeze({ calibration: `${CALIBRATION_SCHEMA}@1.0.0`, outcome: ROUTING_OUTCOME_SCHEMA, decision: DECISION_SCHEMA });

/**
 * @param {object} o
 * @param {object} o.calibration  buildCalibration() artifact
 * @param {object} o.priceBook    priceBookFromCatalog() result
 * @param {{id:string, modelVersion:string|null}[]} o.models  the candidates the policy was promoted on
 */
export function snapshotRoutingBasis({ calibration, priceBook, models, schemas = SCHEMA_VERSIONS }) {
  const priceDigests = {};
  for (const m of models) priceDigests[m.id] = priceBook?.entries?.[m.id] ? digestOf(priceBook.entries[m.id]) : null;
  const quality = {};
  for (const e of calibration?.estimates ?? []) {
    if (e.level === 'stratum' && (e.label === 'reliable' || e.label === 'reliable-synthetic')) quality[`${e.model}|${e.modelVersion ?? ''}|${e.stratum}`] = { low: e.interval.low, accuracy: e.accuracy, n: e.n };
  }
  const snap = {
    schema: BASIS_SCHEMA, calibrationHash: calibration?.calibrationHash ?? null, priceVersion: priceBook?.version ?? null,
    models: Object.fromEntries(models.map((m) => [m.id, m.modelVersion ?? null])), priceDigests, schemas: { ...schemas }, quality,
    synthetic: calibration?.synthetic === true,
  };
  snap.snapshotHash = digestOf({ ...snap, snapshotHash: undefined });
  return Object.freeze(snap);
}

/**
 * @param {object} o
 * @param {object} o.basis    snapshotRoutingBasis() result
 * @param {object} o.current  { models: [{id, modelVersion}], priceBook, schemas }
 * @param {object[]} [o.recentOutcomes]  decided outcomes observed since the snapshot
 * @param {{onInvalidation?:'fallback'|'shadow', minRecentDecided?:number}} [o.policy]
 */
export function assessDrift({ basis, current, recentOutcomes = [], policy = {} }) {
  const onInvalidation = policy.onInvalidation ?? DRIFT_DEFAULTS.onInvalidation;
  const minRecent = policy.minRecentDecided ?? DRIFT_DEFAULTS.minRecentDecided;
  const invalidations = [];
  const add = (kind, model, modelVersion, stratum, reason) => invalidations.push({ kind, model, modelVersion, stratum, reason });
  if (!basis || basis.schema !== BASIS_SCHEMA || digestOf({ ...basis, snapshotHash: undefined }) !== basis.snapshotHash) {
    return { state: DRIFT_STATES.includes(onInvalidation) ? onInvalidation : 'fallback', invalidations: [{ kind: 'schema', model: null, modelVersion: null, stratum: null, reason: 'the basis snapshot is missing or does not match its own hash' }], documentedFallback: onInvalidation, unchanged: false };
  }
  const have = new Map((current?.models ?? []).map((m) => [m.id, m.modelVersion ?? null]));
  for (const [id, version] of Object.entries(basis.models)) {
    if (!have.has(id)) { add('model-version', id, version, null, `${id} is no longer offered (calibrated at version ${version ?? 'unversioned'})`); continue; }
    if (have.get(id) !== version) add('model-version', id, version, null, `${id} moved from version ${version ?? 'unversioned'} to ${have.get(id) ?? 'unreported'}; estimates for the old version do not carry over`);
    const priceNow = current?.priceBook?.entries?.[id] ? digestOf(current.priceBook.entries[id]) : null;
    if (priceNow !== basis.priceDigests[id]) add('pricing', id, version, null, `the price entry for ${id} changed (price book ${basis.priceVersion} to ${current?.priceBook?.version ?? 'unknown'}); measured cost estimates are no longer valid`);
  }
  for (const [k, v] of Object.entries(basis.schemas)) {
    const now = current?.schemas?.[k];
    if (now !== v) add('schema', null, null, null, `the ${k} schema changed from ${v} to ${now ?? 'unreported'}`);
  }
  // measured quality: recent decided outcomes per (model, version, stratum) against the calibrated lower bound
  const groups = new Map();
  for (const o of recentOutcomes) {
    if (o.outcome !== 'correct' && o.outcome !== 'incorrect') continue;
    const k = `${o.model}|${o.modelVersion ?? ''}|${o.stratum}`;
    if (!groups.has(k)) groups.set(k, { correct: 0, n: 0, model: o.model, modelVersion: o.modelVersion ?? null, stratum: o.stratum });
    const g = groups.get(k); g.n += 1; if (o.outcome === 'correct') g.correct += 1;
  }
  for (const [k, g] of [...groups.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const base = basis.quality[k];
    if (!base || g.n < minRecent || base.low === null) continue;
    const w = wilsonInterval(g.correct, g.n);
    if (w.status === 'measured' && w.high < base.low) add('quality-shift', g.model, g.modelVersion, g.stratum, `recent quality ${g.correct}/${g.n} (95% upper ${w.high.toFixed(3)}) is below the calibrated lower bound ${base.low}`);
  }
  const state = invalidations.length ? (DRIFT_STATES.includes(onInvalidation) && onInvalidation !== 'active' ? onInvalidation : 'fallback') : 'active';
  return {
    state, invalidations, unchanged: invalidations.length === 0,
    documentedFallback: invalidations.length ? (state === 'shadow' ? 'shadow: proposals are recorded and production selection is unchanged' : 'fallback: the existing capability route stands; invalidated estimates are refused by the constrained router') : null,
    kinds: [...new Set(invalidations.map((i) => i.kind))].sort(),
  };
}

/** A derived calibration with the assessed invalidations applied. The original artifact is not modified. */
export function applyInvalidations(calibration, assessment) {
  const list = assessment?.invalidations ?? [];
  const schemaWide = list.find((i) => i.kind === 'schema');
  const estimates = calibration.estimates.map((e) => {
    const hits = list.filter((i) => {
      if (i.kind === 'schema') return true;
      if (i.model !== e.model) return false;
      if (i.kind === 'model-version') return (i.modelVersion ?? null) === (e.modelVersion ?? null);
      if (i.kind === 'pricing') return (i.modelVersion ?? null) === (e.modelVersion ?? null);
      if (i.kind === 'quality-shift') return i.stratum === e.stratum && (i.modelVersion ?? null) === (e.modelVersion ?? null);
      return false;
    });
    if (!hits.length) return e;
    const qualityHits = hits.filter((h) => h.kind !== 'pricing');
    const next = JSON.parse(JSON.stringify(e));
    if (qualityHits.length) {
      next.label = 'invalidated';
      next.reasons = qualityHits.map((h) => `${h.kind}: ${h.reason}`);
      next.fallback = { policy: 'baseline-model', model: calibration.pairing?.baselineModel ?? null, note: 'this estimate was invalidated; the baseline route stands' };
    }
    if (hits.some((h) => h.kind === 'pricing' || h.kind === 'schema')) {
      next.costUsd = { n: 0, unknown: e.costUsd?.n ?? 0, p50: null, invalidated: true, reason: hits.filter((h) => h.kind === 'pricing' || h.kind === 'schema').map((h) => h.reason)[0] };
    }
    next.invalidatedBy = hits.map((h) => h.kind).sort();
    return next;
  });
  const out = JSON.parse(JSON.stringify({ ...calibration, estimates }));
  out.derivedFrom = calibration.calibrationHash;
  out.invalidations = list;
  out.invalidatedAll = !!schemaWide;
  out.calibrationHash = digestOf({ ...out, calibrationHash: undefined });
  return Object.freeze(out);
}
