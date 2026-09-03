// impact-engine.js — M5 deliverable #4 (FR-507): the pure read/
// aggregate computation behind "assess impact" from a compromised
// node/edge/flow/data element. Reuses the already-shipped, already-
// tested BFS traversal in frontend/src/lib/focus-controls.js — the
// established scanner/src/ -> frontend/src/ cross-import precedent
// (export-privacy.js's own computePrivacyViewModel import). No
// mutation, no hypothesis, no re-run of the taint/path pipeline — a
// pure filter/aggregate over the graph's own already-computed fields.

import { showAllPaths } from '../../../frontend/src/lib/focus-controls.js';
import { computeGraphDigest } from './export-json.js';
import { impactAssessmentId } from './ids.js';
import { IMPACT_VERSION } from './impact-assessment.js';

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
// radius, but compromising one EDGE/FLOW/data-element does not — it
// silently upgrades "this channel is compromised" to "the process
// node at each end is compromised", the same over-inclusion class the
// original dataElement fix removed.
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
 * 'flow_restricted'`) — compromising one channel does not compromise
 * the process node at each end. The two target-kind families answer
 * genuinely different questions, both honestly disclosed via
 * `traceKind` rather than silently conflated under one `scope` value.
 */
export function computeImpactAssessment(graph, targetId, opts = {}) {
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
    affectedDataClasses = [...dataClasses].sort();
  }

  const graphDigest = computeGraphDigest(graph);
  const generatedAt = opts.generatedAt ?? new Date().toISOString();

  return {
    id: impactAssessmentId({ graphId: graph.graphId, graphDigest, targetId }, [generatedAt]),
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
