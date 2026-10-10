// Dependency-aware resume and invalidation for portfolio work units (X-705).
//
// A verified unit is reusable only while everything it was computed from is unchanged. Each verified result records one digest per
// dependency dimension (code, policy, graph, invariant, oracle, toolchain; work-units.js refuses a result that lacks any). On resume
// the CURRENT digests are compared dimension by dimension (X-705.AC01):
//
//   match                 the unit stays verified and counts.
//   any dimension differs the unit is INVALIDATED: its result moves to `stale` (still inspectable, with the changed dimensions and the
//                         digests on both sides) and the unit returns to pending in a new generation. A stale result never counts
//                         toward completion (X-705.AC02), and every assurance claim that depends on the unit goes stale with it.
//
// One dimension is narrowed with the deployment drift module rather than treated as all-or-nothing: when only the GRAPH digest changed
// and a drift plan (lineage/deployment/drift.js `planRescan`) is supplied, a unit bound to hypotheses is reused only if the plan is
// complete and every one of its hypotheses is in the plan's `skipped` set, meaning the diff provably does not touch it. An incomplete
// plan, an unbound hypothesis or a unit with no hypotheses invalidates: the narrowing fails closed. A unit reused this way is
// re-stamped with the current graph digest and the stamp is recorded as a `revalidated` event naming the drift plan.
//
// Convergence (X-705.AC03) is checked by comparing `scopedResults` of an interrupted or incremental run with a fresh full run's; the
// executors are deterministic functions of the unit and its current dependencies, so equal inputs give equal results.

import { digestOf } from '../assurance/identity.js';
import { computeRunKey, computeGlobalKey } from '../scan-checkpoint.js';
import { DEPENDENCY_DIMENSIONS, checkDependencies, typedError, appendEvent as pushEvent } from './work-units.js';

/** Code dependency digest from file contents, reusing the scan checkpoint's content-hash run key. */
export function codeDigestFromFiles(fileContents) {
  return `sha256:${computeRunKey({ engineVersion: '', rulesetVersion: '', bundleSha: '', fileContents, depFileContents: {}, env: {} })}`;
}

/** Toolchain dependency digest from the engine identity, reusing the checkpoint's global key. */
export function toolchainDigest({ engineVersion, rulesetVersion, bundleSha }) {
  return `sha256:${computeGlobalKey({ engineVersion, rulesetVersion, bundleSha, depFileContents: {}, env: {} })}`;
}

/** Compare recorded and current dependency digests. Returns the dimensions that differ, sorted. */
export function changedDimensions(recorded, current) {
  // a dimension that is absent on either side is a difference: two unknowns are not a match
  return DEPENDENCY_DIMENSIONS.filter((d) => recorded?.[d] === undefined || recorded[d] !== current?.[d]);
}

function graphUntouched(unit, drift) {
  if (!drift?.plan || drift.plan.status !== 'complete') return { ok: false, reason: 'no complete drift plan' };
  const hyps = Array.isArray(unit.hypothesisIds) ? unit.hypothesisIds : [];
  if (hyps.length === 0) return { ok: false, reason: 'the unit is not bound to hypotheses, so the diff cannot be shown not to touch it' };
  const skipped = new Set(drift.plan.skipped.map((s) => s.hypothesisId));
  const redo = new Set(drift.plan.rescan.map((s) => s.hypothesisId));
  for (const h of hyps) {
    if (redo.has(h)) return { ok: false, reason: `hypothesis ${h} is affected by the graph change` };
    if (!skipped.has(h)) return { ok: false, reason: `hypothesis ${h} is not covered by the drift plan` };
  }
  return { ok: true, reason: 'the drift plan shows the graph change does not touch this unit' };
}

/**
 * Decide, without changing anything, what a resume would reuse and invalidate.
 *
 * @param {object} store
 * @param {(unit:object)=>Object<string,string>} currentDependencies  the CURRENT six digests for a unit
 * @param {{plan:object}} [drift]   a `planRescan` result, to narrow graph-only changes
 * @param {Object<string,string[]>} [hypothesesByUnit]  unit id -> hypothesis ids the unit covers
 */
export function planResume(store, currentDependencies, { drift = null, hypothesesByUnit = {} } = {}) {
  const reuse = [], invalidate = [], revalidate = [];
  for (const id of Object.keys(store.units).sort()) {
    const u = store.units[id];
    if (u.state !== 'verified') continue;
    const cur = currentDependencies(u);
    const missing = checkDependencies(cur);
    if (missing.length) { invalidate.push({ unitId: id, changed: missing, reason: `current dependency digests are unavailable for: ${missing.join(', ')}` }); continue; }
    const changed = changedDimensions(u.result.dependencies, cur);
    if (changed.length === 0) { reuse.push(id); continue; }
    if (changed.length === 1 && changed[0] === 'graph') {
      const verdict = graphUntouched({ ...u, hypothesisIds: hypothesesByUnit[id] ?? u.hypothesisIds }, drift);
      if (verdict.ok) { revalidate.push({ unitId: id, graph: cur.graph, driftPlan: digestOf(drift.plan.changeIds ?? []), reason: verdict.reason }); continue; }
      invalidate.push({ unitId: id, changed, reason: `graph changed and ${verdict.reason}`, current: cur });
      continue;
    }
    invalidate.push({ unitId: id, changed, reason: `${changed.join(', ')} changed since the result was recorded`, current: cur });
  }
  return { reuse, revalidate, invalidate, reusableCount: reuse.length + revalidate.length };
}

/**
 * Apply a resume plan to the store (mutates). Invalidated units keep their old result in `stale`, return to pending in a new generation
 * and record an `invalidated` event; revalidated units are re-stamped. Returns the invalidated unit ids.
 */
export function applyResume(store, plan, now) {
  const invalidated = [];
  for (const r of plan.revalidate) {
    const u = store.units[r.unitId];
    if (!u || u.state !== 'verified') throw typedError('PLAN_STALE', `unit ${r.unitId} is no longer verified`);
    u.result = { ...u.result, dependencies: { ...u.result.dependencies, graph: r.graph } };
    u.result.dependencyDigest = digestOf(u.result.dependencies);
    pushEvent(u, { type: 'revalidated', at: now, graph: r.graph, driftPlan: r.driftPlan, reason: r.reason, dependencyDigest: u.result.dependencyDigest });
  }
  for (const inv of plan.invalidate) {
    const u = store.units[inv.unitId];
    if (!u || u.state !== 'verified') throw typedError('PLAN_STALE', `unit ${inv.unitId} is no longer verified`);
    u.stale.push({ ...u.result, invalidatedAt: now, changedDimensions: inv.changed, reason: inv.reason });
    if (u.stale.length > 20) u.stale.shift();
    pushEvent(u, { type: 'invalidated', at: now, changed: inv.changed, reason: inv.reason, previousDependencyDigest: u.result.dependencyDigest });
    u.result = null;
    u.state = 'pending';
    u.generation += 1;
    u.retryCount = 0;
    invalidated.push(inv.unitId);
  }
  return invalidated;
}

/**
 * Mark every assurance claim that rests on an invalidated (or not-currently-verified) unit as stale. A claim is `current` only while all
 * of its units are verified in the store.
 *
 * @param {Array<{id:string, unitIds:string[]}>} claims
 */
export function assessClaims(store, claims) {
  return claims.map((c) => {
    const notCurrent = c.unitIds.filter((id) => store.units[id]?.state !== 'verified');
    const stale = c.unitIds.filter((id) => store.units[id]?.stale?.length && store.units[id].state !== 'verified');
    return { id: c.id, status: notCurrent.length === 0 ? 'current' : 'stale', notCurrent, staleUnits: stale };
  });
}

/** The stale results, for inspection. They never count toward completion. */
export function inspectStale(store) {
  const out = [];
  for (const u of Object.values(store.units)) for (const s of u.stale) out.push({ unitId: u.id, repository: u.repository, taskType: u.taskType, ...s });
  return out.sort((a, b) => (a.unitId < b.unitId ? -1 : 1));
}
