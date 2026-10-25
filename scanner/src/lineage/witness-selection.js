// witness-selection.js: which paths to DISPLAY, and what may be claimed from
// them (DAG-07 R07.8).
//
// Two jobs that must never be confused:
//   1. rankWitnesses: choose a small, diverse sample of the enumerated paths
//      to show. Diversity is over source, sink, data class, trust boundary,
//      control state and ambiguity. This is presentation only.
//   2. assessAllPathsProtected: decide whether "every path is protected" may
//      be said. It looks at EVERY enumerated path, displayed or not, and it
//      refuses outright when the enumeration itself was truncated, so a
//      sample that happens to contain only protected paths can never produce
//      the claim. A hidden unprotected path refutes the claim.
//
// Pure: no store access, no engine imports.

export const DIVERSITY_DIMENSIONS = Object.freeze(['source', 'sink', 'dataClass', 'trustBoundary', 'controlState', 'ambiguity']);

/**
 * Attribute values for one path. `attrsOf(path)` may supply `dataClass` and
 * `controlState` ('protected' | 'unprotected' | 'unknown'); source, sink,
 * boundary and ambiguity come from the path itself.
 */
export function witnessAttributes(path, attrsOf) {
  const extra = typeof attrsOf === 'function' ? (attrsOf(path) ?? {}) : {};
  return {
    source: path.sourceNodeId ?? null,
    sink: path.sinkNodeId ?? null,
    dataClass: extra.dataClass ?? path.dataElementId ?? 'unknown',
    trustBoundary: (path.crossScopeCount ?? 0) > 0 ? 'crosses' : 'local',
    controlState: extra.controlState ?? 'unknown',
    ambiguity: (path.ambiguousHopCount ?? 0) > 0 ? 'ambiguous' : 'correlated',
  };
}

/**
 * Greedy diversity ranking. Each step picks the path adding the most
 * not-yet-shown values across the six dimensions; ties go to the path id so
 * the order is deterministic. Never drops or alters a path: `ranked` is a
 * permutation of the input and `displayed` is its prefix.
 */
export function rankWitnesses(paths, { limit = 10, attrsOf } = {}) {
  const list = Array.isArray(paths) ? paths : [];
  const cap = Number.isInteger(limit) && limit >= 0 ? limit : 10;
  const seen = Object.fromEntries(DIVERSITY_DIMENSIONS.map((d) => [d, new Set()]));
  const pool = list.map((p) => ({ p, a: witnessAttributes(p, attrsOf) }));
  const ranked = [];
  while (pool.length) {
    let best = -1;
    let bestGain = -1;
    for (let i = 0; i < pool.length; i++) {
      let gain = 0;
      for (const d of DIVERSITY_DIMENSIONS) if (!seen[d].has(pool[i].a[d])) gain += 1;
      if (gain > bestGain || (gain === bestGain && String(pool[i].p.id) < String(pool[best].p.id))) { best = i; bestGain = gain; }
    }
    const [chosen] = pool.splice(best, 1);
    for (const d of DIVERSITY_DIMENSIONS) seen[d].add(chosen.a[d]);
    ranked.push(chosen.p);
  }
  const displayed = ranked.slice(0, cap);
  const coverage = Object.fromEntries(DIVERSITY_DIMENSIONS.map((d) => [d, new Set(displayed.map((p) => witnessAttributes(p, attrsOf)[d])).size]));
  return { ranked, displayed, hiddenCount: ranked.length - displayed.length, coverage };
}

/**
 * May "all paths are protected" be asserted?
 *
 * `enumerated` is every path the query produced (before any display cap);
 * `result` is the reconstructPaths result they came from. The claim is
 * allowed only when the query was exhaustive (status complete, nothing
 * dropped or truncated, at least one path) and every path is protected.
 * `holds` is false when ANY enumerated path, hidden or not, is unprotected
 * (a refutation needs no exhaustiveness), and null when it is merely not
 * established.
 */
export function assessAllPathsProtected({ result, enumerated, attrsOf }) {
  const paths = Array.isArray(enumerated) ? enumerated : [];
  const stateOf = (p) => (typeof attrsOf === 'function' ? (attrsOf(p)?.controlState ?? 'unknown') : 'unknown');
  const unprotected = paths.filter((p) => stateOf(p) === 'unprotected');
  const unknown = paths.filter((p) => stateOf(p) !== 'protected' && stateOf(p) !== 'unprotected');
  const reasons = [];
  if (!result || result.status !== 'complete') reasons.push('query-not-complete');
  if (result && (result.truncated || result.droppedPathCount > 0 || result.analysisTruncated)) reasons.push('truncated-sample');
  if (result && result.resumed) reasons.push('resumed-page');
  if (paths.length === 0) reasons.push('no-paths');
  if (unknown.length) reasons.push('control-state-unknown');
  if (unprotected.length) {
    return {
      claim: 'all-paths-protected', allowed: false, holds: false,
      reasons: ['refuted-by-unprotected-path'],
      refutingPathId: unprotected[0].id ?? null, unprotectedCount: unprotected.length,
    };
  }
  const allowed = reasons.length === 0;
  return { claim: 'all-paths-protected', allowed, holds: allowed ? true : null, reasons, unprotectedCount: 0 };
}
