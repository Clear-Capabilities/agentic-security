// Shared per-flow path/topology helpers, used by every view that needs to
// know "which nodes does this flow actually touch" — extracted here after
// Architecture View independently reimplemented the same node-collection
// logic inline in computeFlowSummary, to avoid a third divergent copy when
// Privacy View needed it too.

export function flowPathNodeIds(graph, flow) {
  const ids = new Set([flow.source, flow.sink]);
  for (const edgeId of flow.edgeIds) {
    const edge = graph.edges.find((e) => e.id === edgeId);
    if (edge) {
      ids.add(edge.from);
      ids.add(edge.to);
    }
  }
  return ids;
}

const AI_SUBTYPES = new Set(['ai-assistant', 'ai-model-provider', 'vector-store']);

// AI relevance is computed from flow/node TOPOLOGY (does the path touch an
// AI-kind node), never from dataElement.aiContexts — that field is never
// populated by name-only classification (see scanner/src/lineage's
// classification.js), so an aiContexts-based filter would show zero AI
// relevance despite real AI-processing flows existing in the graph.
export function isAiRelevantFlow(graph, flow) {
  const pathNodeIds = flowPathNodeIds(graph, flow);
  return graph.nodes.some((n) => pathNodeIds.has(n.id) && AI_SUBTYPES.has(n.subtype));
}
