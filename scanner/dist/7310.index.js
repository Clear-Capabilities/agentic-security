export const id = 7310;
export const ids = [7310];
export const modules = {

/***/ 7310:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  computeImpactAssessment: () => (/* binding */ computeImpactAssessment)
});

;// CONCATENATED MODULE: ../frontend/src/lib/focus-controls.js
// Milestone 3, sub-project M3-UX-Query, Task 3. Nine focus-control graph
// traversals over the SAME DataFlowGraph v1 structure the query language
// (lib/query-language.js) reads. Each function returns the SAME
// `{nodeIds: Set<string>, edgeIds: Set<string>}` shape
// `views/architecture-view.js`'s own `resolveSelection` already produces
// for `selection` — so the render layer needs zero new consumption code to
// accept output from any of these. `resetToOverview` is deliberately NOT
// implemented here: Task 4 wires the existing `resolveSelection(graph,
// null)` directly for that control (see this file's own header note in the
// task brief) — duplicating it here would just be a second, divergent copy
// of the same empty-selection shape.

function buildAdjacency(graph) {
  const forward = new Map(); // nodeId -> [{edgeId, toId}]
  const backward = new Map(); // nodeId -> [{edgeId, fromId}]
  for (const n of graph.nodes) { forward.set(n.id, []); backward.set(n.id, []); }
  for (const e of graph.edges) {
    forward.get(e.from)?.push({ edgeId: e.id, toId: e.to });
    backward.get(e.to)?.push({ edgeId: e.id, fromId: e.from });
  }
  return { forward, backward };
}

function bfsDirection(graph, startId, adjacencyKey, adjacency) {
  const nodeIds = new Set([startId]);
  const edgeIds = new Set();
  const queue = [startId];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const { edgeId, toId, fromId } of adjacency.get(current) ?? []) {
      const nextId = adjacencyKey === 'forward' ? toId : fromId;
      edgeIds.add(edgeId);
      if (!nodeIds.has(nextId)) { nodeIds.add(nextId); queue.push(nextId); }
    }
  }
  return { nodeIds, edgeIds };
}

function showDownstream(graph, nodeId) {
  const { forward } = buildAdjacency(graph);
  return bfsDirection(graph, nodeId, 'forward', forward);
}

function showUpstream(graph, nodeId) {
  const { backward } = buildAdjacency(graph);
  return bfsDirection(graph, nodeId, 'backward', backward);
}

function showAllPaths(graph, nodeId) {
  const down = showDownstream(graph, nodeId);
  const up = showUpstream(graph, nodeId);
  return {
    nodeIds: new Set([...down.nodeIds, ...up.nodeIds]),
    edgeIds: new Set([...down.edgeIds, ...up.edgeIds]),
  };
}

function showShortestPath(graph, fromId, toId) {
  const { forward } = buildAdjacency(graph);
  const cameFrom = new Map(); // nodeId -> {viaEdgeId, fromId}
  const visited = new Set([fromId]);
  const queue = [fromId];
  let found = false;
  while (queue.length > 0 && !found) {
    const current = queue.shift();
    for (const { edgeId, toId: nextId } of forward.get(current) ?? []) {
      if (visited.has(nextId)) continue;
      visited.add(nextId);
      cameFrom.set(nextId, { viaEdgeId: edgeId, fromId: current });
      if (nextId === toId) { found = true; break; }
      queue.push(nextId);
    }
  }
  if (!found) return { nodeIds: new Set(), edgeIds: new Set() };
  const nodeIds = new Set([toId]);
  const edgeIds = new Set();
  let cursor = toId;
  while (cursor !== fromId) {
    const step = cameFrom.get(cursor);
    edgeIds.add(step.viaEdgeId);
    nodeIds.add(step.fromId);
    cursor = step.fromId;
  }
  return { nodeIds, edgeIds };
}

function showExternalPathsOnly(graph) {
  const externalNodeIds = new Set(graph.nodes.filter((n) => n.externality?.value === 'external').map((n) => n.id));
  const nodeIds = new Set();
  const edgeIds = new Set();
  for (const flow of graph.flows) {
    const pathNodeIds = new Set([flow.source, flow.sink]);
    for (const edgeId of flow.edgeIds) {
      const edge = graph.edges.find((e) => e.id === edgeId);
      if (edge) { pathNodeIds.add(edge.from); pathNodeIds.add(edge.to); }
    }
    if ([...pathNodeIds].some((id) => externalNodeIds.has(id))) {
      for (const id of pathNodeIds) nodeIds.add(id);
      for (const edgeId of flow.edgeIds) edgeIds.add(edgeId);
    }
  }
  return { nodeIds, edgeIds };
}

const UNPROTECTED_VERDICTS = new Set(['unprotected', 'mixed', 'unknown']);
function showUnprotectedPathsOnly(graph) {
  const nodeIds = new Set();
  const edgeIds = new Set();
  for (const edge of graph.edges) {
    const verdicts = [edge.protection.transit.verdict, edge.protection.atRest.verdict, edge.protection.handling.verdict];
    if (verdicts.some((v) => UNPROTECTED_VERDICTS.has(v))) {
      edgeIds.add(edge.id);
      nodeIds.add(edge.from);
      nodeIds.add(edge.to);
    }
  }
  return { nodeIds, edgeIds };
}

function showAliases(graph, nodeId) {
  const node = graph.nodes.find((n) => n.id === nodeId);
  const nodeIds = new Set([nodeId]);
  // Real, honest implementation. This plan's own Global Constraints section
  // disclosed node.aliases as "confirmed always empty in real scan output" —
  // that claim does NOT hold against the real committed flagship fixture
  // (Web App/Payment API/Analytics API all carry non-empty aliases arrays
  // there; see test/focus-controls.test.js for the correction). What IS
  // true, confirmed against that same fixture: every alias entry is an
  // alternate DISPLAY NAME for the node itself (e.g. "Checkout Form" is
  // another name for the Web App node), never a pointer to a distinct
  // sibling node record — no alias string in the fixture matches any other
  // real node's label or id. This loop is still real, correct logic (not a
  // no-op stub): it looks up each alias against the graph's own nodes and
  // only adds a match it actually finds, so it will do the right thing the
  // moment (if ever) alias data that DOES reference a distinct node record
  // shows up in a real scan — nothing here is invented alias data.
  for (const alias of node?.aliases ?? []) {
    const aliasNode = graph.nodes.find((n) => n.label === alias || n.id === alias);
    if (aliasNode) nodeIds.add(aliasNode.id);
  }
  return { nodeIds, edgeIds: new Set() };
}

function showDisconnected(graph) {
  const connectedIds = new Set();
  for (const e of graph.edges) { connectedIds.add(e.from); connectedIds.add(e.to); }
  const nodeIds = new Set(graph.nodes.filter((n) => !connectedIds.has(n.id)).map((n) => n.id));
  return { nodeIds, edgeIds: new Set() };
}

// EXTERNAL MODULE: ./src/lineage/export-json.js
var export_json = __webpack_require__(859);
// EXTERNAL MODULE: ./src/lineage/ids.js
var ids = __webpack_require__(5034);
;// CONCATENATED MODULE: ./src/lineage/impact-assessment.js
// impact-assessment.js — M5 deliverable #4 (FR-507 §10.10): the
// ImpactAssessment extension contract — the result of asking "what is
// reachable from this compromised node/edge/flow/data element, per the
// graph's own already-scanned evidence." NOT a DataFlowGraph v1 entity,
// mirrors recipient-profile.js's/scenario.js's own contract shape
// exactly (structural-only {valid, errors} validator, zero graph
// access at construction time).
//
// See docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-blast-radius-impact-scoping.md
// for the full design reasoning, including why there is no
// affectedObligationIds field (ObligationMapping records are built on
// demand per compliance framework, not stored on the graph) and why
// `scope` is always 'possible' today (no runtime-corroboration layer
// exists yet).

const IMPACT_VERSION = '1.0.0';

const IMPACT_TARGET_KINDS = Object.freeze(['node', 'edge', 'flow', 'dataElement']);

// 'possible' is the only value any producer emits today — 'observed'
// is reserved for a future Digital Twin (M5 #7) increment with a real
// runtime-corroboration signal. Both are valid schema values now so
// that increment needs no breaking change to this contract later.
const IMPACT_SCOPE_VALUES = Object.freeze(['possible', 'observed']);

// Discloses WHICH of the two genuinely different traversal semantics
// produced this record (final-review I2 fix) — `scope` alone cannot
// distinguish them, since both families emit `scope: 'possible'`.
// 'topology_reachable': a `node` target's topology-wide showAllPaths
// BFS — "everything this compromised node could push to." 'flow_
// restricted': an `edge`/`flow`/`dataElement` target's direct trace
// over the flows that actually carry it — never the topology-wide BFS.
// Without this field a JSON consumer cannot tell "exact carrier trace"
// from "topological presumption" apart, the exact silent-conflation
// this codebase's own disclosure discipline exists to prevent.
const IMPACT_TRACE_KINDS = Object.freeze(['topology_reachable', 'flow_restricted']);

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isStringArray(v) { return Array.isArray(v) && v.every((x) => typeof x === 'string'); }

/**
 * Structural validation only — mirrors validateRecipientProfile's/
 * validateScenario's own {valid, errors} shape and "never throws"
 * contract.
 */
function validateImpactAssessment(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'ImpactAssessment record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('impact:')) {
    err('$.id', 'id is required and must start with "impact:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.graphId)) err('$.graphId', 'graphId is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');
  if (!_isNonEmptyString(record.targetId)) err('$.targetId', 'targetId is required');
  if (!IMPACT_TARGET_KINDS.includes(record.targetKind)) {
    err('$.targetKind', `targetKind must be one of ${IMPACT_TARGET_KINDS.join('|')}`);
  }
  if (!IMPACT_SCOPE_VALUES.includes(record.scope)) {
    err('$.scope', `scope must be one of ${IMPACT_SCOPE_VALUES.join('|')}`);
  }
  if (!IMPACT_TRACE_KINDS.includes(record.traceKind)) {
    err('$.traceKind', `traceKind must be one of ${IMPACT_TRACE_KINDS.join('|')}`);
  }
  if (!_isStringArray(record.affectedNodeIds ?? [])) err('$.affectedNodeIds', 'affectedNodeIds must be an array of strings');
  if (!_isStringArray(record.affectedEdgeIds ?? [])) err('$.affectedEdgeIds', 'affectedEdgeIds must be an array of strings');
  if (!_isStringArray(record.affectedDataClasses ?? [])) err('$.affectedDataClasses', 'affectedDataClasses must be an array of strings');
  if (!_isStringArray(record.affectedRecipientProfileIds ?? [])) err('$.affectedRecipientProfileIds', 'affectedRecipientProfileIds must be an array of strings');
  if (!_isStringArray(record.coverageLimitations ?? [])) err('$.coverageLimitations', 'coverageLimitations must be an array of strings');
  if (!_isNonEmptyString(record.generatedAt)) err('$.generatedAt', 'generatedAt is required');
  return { valid: errors.length === 0, errors };
}

;// CONCATENATED MODULE: ./src/lineage/impact-engine.js
// impact-engine.js — M5 deliverable #4 (FR-507): the pure read/
// aggregate computation behind "assess impact" from a compromised
// node/edge/flow/data element. Reuses the already-shipped, already-
// tested BFS traversal in frontend/src/lib/focus-controls.js — the
// established scanner/src/ -> frontend/src/ cross-import precedent
// (export-privacy.js's own computePrivacyViewModel import). No
// mutation, no hypothesis, no re-run of the taint/path pipeline — a
// pure filter/aggregate over the graph's own already-computed fields.






// dataElement's real stable-id prefix is 'data:' (see ids.js's own
// dataElementId(), which returns `data:${hash}` — every real
// DataFlowGraph v1 document's dataElements[] carries this prefix, not
// 'de:'). node/edge/flow below match ids.js's nodeId/edgeId/flowId
// prefixes exactly for the identical reason.
const _KIND_PREFIXES = Object.freeze({ node: 'node:', edge: 'edge:', flow: 'flow:', dataElement: 'data:' });

function _resolveTargetKind(targetId) {
  if (typeof targetId !== 'string') return null;
  for (const [kind, prefix] of Object.entries(_KIND_PREFIXES)) {
    if (targetId.startsWith(prefix)) return kind;
  }
  return null;
}

// The seed set for showAllPaths, node targets only — a node target
// seeds itself; edge/flow/dataElement targets never reach this
// function any more (final-review I1 fix). See
// _flowRestrictedAffectedSet's header comment for why: compromising a
// NODE genuinely puts everything reachable from it in the blast
// radius, but compromising one EDGE/FLOW/data-element does not — the
// affected record still NAMES that edge/flow's own two endpoint nodes
// (you need them to know what the compromised channel actually
// touches), it just never treats either endpoint as ITSELF fully
// compromised for the purpose of finding everything ELSE reachable
// from it via unrelated edges — that further step is exactly the
// over-inclusion class the original dataElement fix removed.
function _seedNodeIds(graph, targetId, targetKind) {
  if (targetKind === 'node') return [targetId];
  return [];
}

// Generalizes the direct flow-based trace to all three "named
// relationship" target kinds (dataElement/edge/flow) — each is
// restricted to the REAL flows that carry it, never the topology-wide
// showAllPaths BFS below (that stays node-only). A compromised
// flow/edge/data-element never sweeps in an unrelated sibling flow
// that merely shares a node — the exact carrier path is already on
// each flow's own record (source/sink/edgeIds/dataElementIds), so
// approximating with topology reachability here would discard real
// data, not fill a gap (reproduced live by this task's own review on
// a branching-topology graph: one source, three sinks, one flow each
// carrying a distinct data element — a `flow:`/`edge:` target for the
// sink-A flow incorrectly swept in sinks B and C, and their unrelated
// data classes/recipients with them). `matchesFlow(flow) -> boolean`
// selects which flows carry the target. Also computes dataClasses
// directly from the SAME matched-flow set (closes a related leak: the
// edge-membership-based _affectedDataClasses below could pull in an
// unrelated flow that merely shares one edge with the target flow but
// carries a different data element — unreachable on any real
// graph-builder output today since ids.edgeId's own discriminator
// includes the data element id, but this closes the gap for a future
// builder or an externally-supplied graph). Never adds a dangling
// edge id that doesn't resolve to a real edge in graph.edges. Node
// targets keep the showAllPaths BFS above — for those, "everything
// topologically reachable from the compromised node's own endpoints"
// IS the intended pessimistic scope:'possible' semantics.
function _flowRestrictedAffectedSet(graph, matchesFlow) {
  const nodeIds = new Set();
  const edgeIds = new Set();
  const dataClasses = new Set();
  for (const f of graph.flows ?? []) {
    if (!matchesFlow(f)) continue;
    nodeIds.add(f.source);
    nodeIds.add(f.sink);
    for (const deId of f.dataElementIds ?? []) {
      const de = (graph.dataElements ?? []).find((d) => d.id === deId);
      for (const c of de?.dataClasses ?? []) dataClasses.add(c);
    }
    for (const eId of f.edgeIds ?? []) {
      const edge = (graph.edges ?? []).find((e) => e.id === eId);
      if (!edge) continue; // never surface a dangling/unresolved edge id
      edgeIds.add(eId);
      nodeIds.add(edge.from);
      nodeIds.add(edge.to);
    }
  }
  return { nodeIds, edgeIds, dataClasses };
}

// Edge-membership-based aggregation — kept ONLY as the `node` target's
// fallback (a topology-reachability target has no single "the matched
// flows" set to read dataClasses off directly, unlike the three named-
// relationship kinds above, which use _flowRestrictedAffectedSet's own
// dataClasses instead).
function _affectedDataClasses(graph, affectedEdgeIds) {
  const classes = new Set();
  for (const f of graph.flows ?? []) {
    if (!(f.edgeIds ?? []).some((id) => affectedEdgeIds.has(id))) continue;
    for (const deId of f.dataElementIds ?? []) {
      const de = (graph.dataElements ?? []).find((d) => d.id === deId);
      for (const c of de?.dataClasses ?? []) classes.add(c);
    }
  }
  return [...classes].sort();
}

function _affectedRecipientProfileIds(graph, affectedNodeIds) {
  return (graph.recipientProfiles ?? [])
    .filter((rp) => (rp.contributingGraphIds ?? []).some((id) => affectedNodeIds.has(id)))
    .map((rp) => rp.id)
    .sort();
}

// Whole-graph, not scoped to the affected subgraph — no node carries a
// language field to filter by, so a per-language coverage gap is
// reported as a real, honest limitation on any assessment computed
// over this graph, not narrowed to the exact affected nodes. See this
// sub-project's own implementation plan for the full disclosed
// reasoning. Complemented, not replaced, by _affectedCoverageLimitations
// below — that function reports the real per-entity coverageStatus gaps
// among the entities THIS assessment actually affects, which this
// whole-graph language disclosure cannot express.
function _coverageLimitations(graph) {
  return (graph.coverage?.languages ?? [])
    .filter((l) => l.tier && l.tier !== 'full')
    .map((l) => `${l.language}: coverage tier '${l.tier}'${typeof l.irTaintRecallPct === 'number' ? ` (${l.irTaintRecallPct}% measured recall)` : ''}`);
}

// Per-entity coverage gap among the entities THIS assessment actually
// affects, using the real, required `coverageStatus` field every
// node/edge/flow already carries (`modeled|partial|candidate|
// unsupported|manual` — populated by graph-builder.js, already
// consumed by export-csv.js/graph-diff.js). Complements (never
// replaces) _coverageLimitations' whole-graph language disclosure
// above — both are real, complementary limitations of the same
// assessment.
function _affectedCoverageLimitations(graph, affectedNodeIds, affectedEdgeIds) {
  const limitations = [];
  const nonModeledNodes = (graph.nodes ?? []).filter((n) => affectedNodeIds.has(n.id) && n.coverageStatus && n.coverageStatus !== 'modeled');
  const nonModeledEdges = (graph.edges ?? []).filter((e) => affectedEdgeIds.has(e.id) && e.coverageStatus && e.coverageStatus !== 'modeled');
  if (nonModeledNodes.length) {
    limitations.push(`${nonModeledNodes.length} of ${affectedNodeIds.size} affected node(s) have less-than-modeled coverage (e.g. ${nonModeledNodes[0].id}: coverage tier '${nonModeledNodes[0].coverageStatus}')`);
  }
  if (nonModeledEdges.length) {
    limitations.push(`${nonModeledEdges.length} of ${affectedEdgeIds.size} affected edge(s) have less-than-modeled coverage (e.g. ${nonModeledEdges[0].id}: coverage tier '${nonModeledEdges[0].coverageStatus}')`);
  }
  return limitations;
}

/**
 * Compute an ImpactAssessment for `targetId` over `graph`. Throws when
 * `graph` is structurally malformed (missing `nodes`/`edges` arrays —
 * see `loadSignedGraph`'s own "signature-only, no schema validation"
 * contract for why a signed-but-malformed graph can reach here) with a
 * message prefixed `computeImpactAssessment: malformed graph — `, so a
 * caller can distinguish that from the other thrown case: `targetId`
 * has no recognized canonical-id prefix (a genuine caller error, not a
 * missing-entity case). A well-formed targetId that does not exist in
 * the graph degrades honestly to empty affected-* arrays, never an
 * error — mirrors applyScenario's own skip-not-throw contract for a
 * stale/missing target.
 *
 * `node` targets report a deliberately pessimistic "everything
 * topologically reachable" blast radius (`traceKind:
 * 'topology_reachable'`) — compromising a node genuinely puts
 * everything it can reach in the blast radius. `edge`/`flow`/
 * `dataElement` targets report only the flows/nodes/edges that
 * actually carry that specific edge/flow/data element (`traceKind:
 * 'flow_restricted'`) — the record still names that edge/flow's own
 * two endpoint nodes (you need them to know what the channel actually
 * touches), it just never treats either endpoint as itself fully
 * compromised for finding everything ELSE reachable from it via
 * unrelated edges. The two target-kind families answer genuinely
 * different questions, both honestly disclosed via `traceKind` rather
 * than silently conflated under one `scope` value.
 */
function computeImpactAssessment(graph, targetId, opts = {}) {
  if (!Array.isArray(graph?.nodes) || !Array.isArray(graph?.edges)) {
    throw new Error('computeImpactAssessment: malformed graph — graph.nodes and graph.edges must both be arrays');
  }

  const targetKind = _resolveTargetKind(targetId);
  if (!targetKind) {
    throw new Error(`computeImpactAssessment: targetId "${targetId}" has no recognized prefix (expected one of node:/edge:/flow:/data:)`);
  }

  // showAllPaths (frontend/src/lib/focus-controls.js) unconditionally
  // seeds its own result with the start id itself, even when that id
  // does not exist in the graph at all (bfsDirection's `nodeIds = new
  // Set([startId])`) — so a seed must be filtered against the graph's
  // real node ids first, or a well-formed-but-nonexistent targetId
  // would surface as a phantom single-node "affected" set instead of
  // degrading honestly to empty arrays. The same filter is applied to
  // _flowRestrictedAffectedSet's own node ids below, for the identical
  // reason.
  const realNodeIds = new Set((graph.nodes ?? []).map((n) => n.id));
  const affectedNodeIds = new Set();
  const affectedEdgeIds = new Set();
  let affectedDataClasses;

  if (targetKind === 'node') {
    const seedNodeIds = _seedNodeIds(graph, targetId, targetKind).filter((id) => realNodeIds.has(id));
    for (const seedId of seedNodeIds) {
      const { nodeIds, edgeIds } = showAllPaths(graph, seedId);
      for (const id of nodeIds) affectedNodeIds.add(id);
      for (const id of edgeIds) affectedEdgeIds.add(id);
    }
    affectedDataClasses = _affectedDataClasses(graph, affectedEdgeIds);
  } else {
    // dataElement/edge/flow — direct flow-based trace via
    // _flowRestrictedAffectedSet, never showAllPaths. See that
    // function's own header comment for why.
    const matchesFlow = targetKind === 'dataElement'
      ? (f) => f.dataElementIds?.includes(targetId)
      : targetKind === 'edge'
        ? (f) => f.edgeIds?.includes(targetId)
        : (f) => f.id === targetId; // flow
    const { nodeIds, edgeIds, dataClasses } = _flowRestrictedAffectedSet(graph, matchesFlow);
    for (const id of nodeIds) if (realNodeIds.has(id)) affectedNodeIds.add(id);
    for (const id of edgeIds) affectedEdgeIds.add(id);
    // N3 (final-review re-review): an edge: target that exists in
    // graph.edges but appears in NO flow's own edgeIds (real for the
    // real graph — an edge with zero flows using it is a legitimate
    // graph shape, e.g. a dead-end connection no data currently
    // traverses) must never come back fully empty — "this edge is
    // compromised" means, at minimum, that edge and its own two
    // endpoints are affected, flow or no flow. A nonexistent edge id
    // still correctly degrades to fully empty (realNodeIds/the edge
    // lookup below both filter it out).
    if (targetKind === 'edge') {
      const edge = (graph.edges ?? []).find((e) => e.id === targetId);
      if (edge) {
        affectedEdgeIds.add(edge.id);
        if (realNodeIds.has(edge.from)) affectedNodeIds.add(edge.from);
        if (realNodeIds.has(edge.to)) affectedNodeIds.add(edge.to);
      }
    }
    affectedDataClasses = [...dataClasses].sort();
  }

  const graphDigest = (0,export_json.computeGraphDigest)(graph);
  const generatedAt = opts.generatedAt ?? new Date().toISOString();

  return {
    id: (0,ids/* impactAssessmentId */.Oy)({ graphId: graph.graphId, graphDigest, targetId }, [generatedAt]),
    version: IMPACT_VERSION,
    graphId: graph.graphId,
    graphDigest,
    targetId,
    targetKind,
    scope: 'possible',
    traceKind: targetKind === 'node' ? 'topology_reachable' : 'flow_restricted',
    affectedNodeIds: [...affectedNodeIds].sort(),
    affectedEdgeIds: [...affectedEdgeIds].sort(),
    affectedDataClasses,
    affectedRecipientProfileIds: _affectedRecipientProfileIds(graph, affectedNodeIds),
    coverageLimitations: [
      ..._coverageLimitations(graph),
      ..._affectedCoverageLimitations(graph, affectedNodeIds, affectedEdgeIds),
    ],
    generatedAt,
  };
}


/***/ })

};
