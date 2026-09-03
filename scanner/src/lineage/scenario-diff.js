// scenario-diff.js — M5 deliverable #3a (FR-502): a dedicated
// comparison for a Scenario's own simulated graph delta. Deliberately
// NOT graph-diff.js's computeGraphDiff — see this sub-project's own
// scoping doc for the full reasoning: computeGraphDiff's flow-
// reidentification pairing and causeClassification vocabulary
// (`'application_change'`, `'possible_coverage_regression'`,
// `'reidentified'`) are shaped for a REAL rescan across two commits,
// where the cause of a change is genuinely ambiguous. A Scenario's own
// delta has no such ambiguity — every difference between the base graph
// and a scenario clone IS the declared hypothetical operation that
// produced it — so this module reports only "what differs", with no
// cause classification and no reidentification.

export const WATCHED_SCENARIO_FIELDS = Object.freeze({
  node: Object.freeze(['destination', 'storeDetail']),
  edge: Object.freeze(['protection.transit', 'protection.atRest', 'protection.handling']),
  flow: Object.freeze(['policyVerdict', 'protectionSummary', 'governanceRefs']),
});

function _get(obj, dottedPath) {
  return dottedPath.split('.').reduce((v, k) => (v == null ? v : v[k]), obj);
}

function _deepEqual(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

function _byId(arr) { return new Map((arr ?? []).map((x) => [x.id, x])); }

function _diffKind(beforeArr, afterArr, kind) {
  const beforeMap = _byId(beforeArr);
  const afterMap = _byId(afterArr);
  const changed = [];
  const removed = [];
  for (const [id, beforeEntity] of beforeMap) {
    const afterEntity = afterMap.get(id);
    if (!afterEntity) { removed.push(id); continue; }
    const changedFields = [];
    for (const field of WATCHED_SCENARIO_FIELDS[kind]) {
      const before = _get(beforeEntity, field);
      const after = _get(afterEntity, field);
      if (!_deepEqual(before, after)) changedFields.push({ field, before, after });
    }
    if (changedFields.length) changed.push({ id, kind, changedFields });
  }
  return { changed, removed };
}

/**
 * Compare `baseGraph` against `scenarioGraph` (either a real
 * applyScenario({graph}) result, or another Scenario's own graph, for a
 * scenario-vs-scenario comparison). Never throws — an empty/missing
 * entity array on either side is treated as zero entities.
 */
export function diffScenarioGraph(baseGraph, scenarioGraph) {
  const nodeDiff = _diffKind(baseGraph.nodes ?? [], scenarioGraph.nodes ?? [], 'node');
  const edgeDiff = _diffKind(baseGraph.edges ?? [], scenarioGraph.edges ?? [], 'edge');
  const flowDiff = _diffKind(baseGraph.flows ?? [], scenarioGraph.flows ?? [], 'flow');
  return {
    changedEntities: [...nodeDiff.changed, ...edgeDiff.changed, ...flowDiff.changed],
    removedEntityIds: [...nodeDiff.removed, ...edgeDiff.removed, ...flowDiff.removed],
  };
}
