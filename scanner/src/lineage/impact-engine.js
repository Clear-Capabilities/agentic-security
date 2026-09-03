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

// Every node id a target resolves to, as the seed set for showAllPaths.
// A node target is itself; an edge target is its own from/to; a flow
// target is its own source/sink. dataElement targets never reach this
// function — they get their own direct trace via _dataElementAffectedSet
// below, never seeded into the topology-wide showAllPaths BFS. See that
// function's header comment for why.
function _seedNodeIds(graph, targetId, targetKind) {
  if (targetKind === 'node') return [targetId];
  if (targetKind === 'edge') {
    const edge = (graph.edges ?? []).find((e) => e.id === targetId);
    return edge ? [edge.from, edge.to] : [];
  }
  if (targetKind === 'flow') {
    const flow = (graph.flows ?? []).find((f) => f.id === targetId);
    return flow ? [flow.source, flow.sink] : [];
  }
  return [];
}

// dataElement targets get their own direct trace, deliberately NOT
// showAllPaths — a data element's blast radius is "which flows
// actually carry this specific piece of data", not "everything
// topologically reachable from a node this data happened to touch".
// showAllPaths is a topology-wide BFS (unrestricted to any particular
// flow), so seeding it from a data element's own source/sink nodes
// would sweep in unrelated sinks reached by OTHER flows through the
// same node — reproduced live by this task's own review on a
// branching-topology graph (one source, three sinks, the target data
// element flowing to only two of them; showAllPaths incorrectly
// included the third). Node/edge/flow targets keep the showAllPaths
// BFS below — for those, "everything topologically reachable from the
// compromised node/edge/flow's own endpoints" IS the intended
// pessimistic scope:'possible' semantics.
function _dataElementAffectedSet(graph, targetId) {
  const nodeIds = new Set();
  const edgeIds = new Set();
  for (const f of graph.flows ?? []) {
    if (!f.dataElementIds?.includes(targetId)) continue;
    nodeIds.add(f.source);
    nodeIds.add(f.sink);
    for (const eId of f.edgeIds ?? []) {
      edgeIds.add(eId);
      const edge = (graph.edges ?? []).find((e) => e.id === eId);
      if (edge) { nodeIds.add(edge.from); nodeIds.add(edge.to); }
    }
  }
  return { nodeIds, edgeIds };
}

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
// reasoning.
function _coverageLimitations(graph) {
  return (graph.coverage?.languages ?? [])
    .filter((l) => l.tier && l.tier !== 'full')
    .map((l) => `${l.language}: coverage tier '${l.tier}'${typeof l.irTaintRecallPct === 'number' ? ` (${l.irTaintRecallPct}% measured recall)` : ''}`);
}

/**
 * Compute an ImpactAssessment for `targetId` over `graph`. Throws only
 * when `targetId` has no recognized canonical-id prefix (a genuine
 * caller error, not a missing-entity case). A well-formed targetId
 * that does not exist in the graph degrades honestly to empty
 * affected-* arrays, never an error — mirrors applyScenario's own
 * skip-not-throw contract for a stale/missing target.
 *
 * `node`/`edge`/`flow` targets report a deliberately pessimistic
 * "everything topologically reachable" blast radius (matching
 * `scope: 'possible'`), while `dataElement` targets report only the
 * flows/nodes/edges that actually carry that specific data element —
 * the two target-kind families answer genuinely different questions,
 * both honestly disclosed rather than silently conflated.
 */
export function computeImpactAssessment(graph, targetId, opts = {}) {
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
  // degrading honestly to empty arrays.
  const realNodeIds = new Set((graph.nodes ?? []).map((n) => n.id));
  const affectedNodeIds = new Set();
  const affectedEdgeIds = new Set();

  if (targetKind === 'dataElement') {
    // Direct flow-based trace — never showAllPaths. See
    // _dataElementAffectedSet's own header comment for why.
    const { nodeIds, edgeIds } = _dataElementAffectedSet(graph, targetId);
    for (const id of nodeIds) if (realNodeIds.has(id)) affectedNodeIds.add(id);
    for (const id of edgeIds) affectedEdgeIds.add(id);
  } else {
    const seedNodeIds = _seedNodeIds(graph, targetId, targetKind).filter((id) => realNodeIds.has(id));
    for (const seedId of seedNodeIds) {
      const { nodeIds, edgeIds } = showAllPaths(graph, seedId);
      for (const id of nodeIds) affectedNodeIds.add(id);
      for (const id of edgeIds) affectedEdgeIds.add(id);
    }
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
    affectedNodeIds: [...affectedNodeIds].sort(),
    affectedEdgeIds: [...affectedEdgeIds].sort(),
    affectedDataClasses: _affectedDataClasses(graph, affectedEdgeIds),
    affectedRecipientProfileIds: _affectedRecipientProfileIds(graph, affectedNodeIds),
    coverageLimitations: _coverageLimitations(graph),
    generatedAt,
  };
}
