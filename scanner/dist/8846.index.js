export const id = 8846;
export const ids = [8846];
export const modules = {

/***/ 8846:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   diffScenarioGraph: () => (/* binding */ diffScenarioGraph)
/* harmony export */ });
/* unused harmony export WATCHED_SCENARIO_FIELDS */
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

const WATCHED_SCENARIO_FIELDS = Object.freeze({
  // 'destination' + 'storeDetail' are exhaustive by construction, not by
  // convention: change_storage_fact/change_governance_fact write into an
  // already-watched CONTAINER object, so any field they set is caught
  // regardless of key; replace_recipient_fact is the one operation that
  // writes directly onto the node's own top level, and scenario-engine.js
  // restricts it, at the applier level, to exactly node.destination (any
  // other `field` value is skipped, never applied) — so this list never
  // needs to name a field replace_recipient_fact could reach beyond
  // 'destination'. See scenario-engine.js's _applyReplaceRecipientFact.
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

// AC-26 ("What-if changes cannot masquerade as implementation"): a
// simulated edge must be LABELED `HYPOTHETICAL`, not merely carry an
// `evidenceGrade: 'assumed'` value a reader has to notice buried inside
// a before/after diff. Mirrors AC-29's own precedent
// (`observation-correlation.js`'s literal `'runtime_observed'` layer
// value) — a named acceptance criterion that specifies an exact string
// gets an exact string in the shipped output, not an inference left to
// the reader.
function _hasAssumedEvidence(changedEntity) {
  return changedEntity.changedFields.some((f) => f.after && typeof f.after === 'object' && f.after.evidenceGrade === 'assumed');
}

/**
 * Compare `baseGraph` against `scenarioGraph` (either a real
 * applyScenario({graph}) result, or another Scenario's own graph, for a
 * scenario-vs-scenario comparison). Never throws — an empty/missing
 * entity array on either side is treated as zero entities.
 */
function diffScenarioGraph(baseGraph, scenarioGraph) {
  const nodeDiff = _diffKind(baseGraph.nodes ?? [], scenarioGraph.nodes ?? [], 'node');
  const edgeDiff = _diffKind(baseGraph.edges ?? [], scenarioGraph.edges ?? [], 'edge');
  const flowDiff = _diffKind(baseGraph.flows ?? [], scenarioGraph.flows ?? [], 'flow');
  const changedEntities = [...nodeDiff.changed, ...edgeDiff.changed, ...flowDiff.changed]
    .map((e) => (e.kind === 'edge' && _hasAssumedEvidence(e) ? { ...e, label: 'HYPOTHETICAL' } : e));
  return {
    changedEntities,
    removedEntityIds: [...nodeDiff.removed, ...edgeDiff.removed, ...flowDiff.removed],
  };
}


/***/ })

};
