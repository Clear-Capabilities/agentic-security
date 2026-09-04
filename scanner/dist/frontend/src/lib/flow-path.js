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

// Backend AI node-subtype vocabulary (scanner/src/lineage/schema.js's
// SOURCE_CATEGORIES/SINK_CATEGORIES, AI-flavored entries only). This list
// must be hand-kept in sync with that schema file — the frontend never
// imports scanner/src/lineage/ at runtime (see frontend/CLAUDE.md).
// Corrected this increment: the previous set ('ai-assistant',
// 'vector-store') matched neither real enum and silently never matched
// any real node.
export const AI_SUBTYPES = new Set([
  'ai-model-provider', 'ai-local-model', 'ai-agent', 'ai-tool',
  'ai-vector-store', 'ai-memory', 'ai-training', 'ai-evaluation', 'ai-telemetry',
  'ai-model-output', 'ai-tool-result', 'ai-retrieved-document',
]);

// AI relevance is computed from flow/node TOPOLOGY (does the path touch an
// AI-kind node), never from dataElement.aiContexts — that field is never
// populated by name-only classification (see scanner/src/lineage's
// classification.js), so an aiContexts-based filter would show zero AI
// relevance despite real AI-processing flows existing in the graph.
export function isAiRelevantFlow(graph, flow) {
  const pathNodeIds = flowPathNodeIds(graph, flow);
  return graph.nodes.some((n) => pathNodeIds.has(n.id) && AI_SUBTYPES.has(n.subtype));
}
