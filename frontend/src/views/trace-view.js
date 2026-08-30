export function computeTraceSteps(graph, flow) {
  const steps = [];
  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));

  steps.push({
    kind: 'source',
    fieldName: dataElement?.name ?? 'unknown field',
    node: sourceNode?.label ?? 'unknown source',
  });

  const edges = flow.edgeIds.map((id) => graph.edges.find((e) => e.id === id)).filter(Boolean);
  for (const edge of edges) {
    const toNode = graph.nodes.find((n) => n.id === edge.to);
    const mappings = edge.fieldMappings ?? [];

    if (mappings.length === 0) {
      steps.push({
        kind: 'hop',
        node: toNode?.label ?? 'unknown',
        protection: edge.protection,
        evidenceRefs: edge.evidenceRefs ?? [],
      });
      continue;
    }

    for (const mapping of mappings) {
      const transformations = (mapping.transformationIds ?? [])
        .map((tid) => graph.transformations.find((t) => t.id === tid))
        .filter(Boolean);
      steps.push({
        kind: transformations.length > 0 ? 'transformation' : 'propagation',
        fromPath: mapping.fromPath,
        toPath: mapping.toPath,
        mappingType: mapping.mappingType,
        transformations,
        node: toNode?.label ?? 'unknown',
        boundaryCrossing: (edge.boundaryCrossings ?? []).length > 0,
        protection: edge.protection,
        evidenceRefs: edge.evidenceRefs ?? [],
      });
    }
  }

  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  steps.push({
    kind: 'sink',
    node: sinkNode?.label ?? 'unknown destination',
    externality: sinkNode?.externality?.value ?? 'unknown',
    protectionSummary: flow.protectionSummary,
  });

  return steps;
}

export function computeAlternatePaths(graph, flow) {
  return graph.flows
    .filter((f) => f.id !== flow.id && f.dataElementIds.some((id) => flow.dataElementIds.includes(id)))
    .map((f) => ({
      flowId: f.id,
      destinationLabel: graph.nodes.find((n) => n.id === f.sink)?.label ?? 'unknown',
      protectionSummary: f.protectionSummary,
    }));
}

export function computeTraceViewModel(graph, state) {
  if (!state.selectedId) return null;
  const flow = graph.flows.find((f) => f.id === state.selectedId);
  if (!flow) return null;
  return {
    flow,
    steps: computeTraceSteps(graph, flow),
    alternatePaths: computeAlternatePaths(graph, flow),
  };
}
