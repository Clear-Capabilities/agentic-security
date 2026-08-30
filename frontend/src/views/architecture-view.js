import { worstVerdict } from '../lib/protection-visual.js';

export const ZONE_ORDER = Object.freeze(['Public Internet', 'Application Layer', 'Service Layer', 'Data Layer', 'External Zone']);

export function zoneForNode(node) {
  switch (node.kind) {
    case 'source':
      return 'Public Internet';
    case 'api':
      return 'Application Layer';
    case 'process':
    case 'transform':
      return 'Service Layer';
    case 'store':
    case 'log':
    case 'queue':
    case 'sink':
      return 'Data Layer';
    case 'external':
    case 'unresolved':
      return 'External Zone';
    default:
      // boundary, or any future kind not yet mapped: a safe internal default
      // rather than silently dropping the node from every zone.
      return 'Service Layer';
  }
}

export function resolveSelection(graph, selectedId) {
  const empty = { active: false, nodeIds: new Set(), edgeIds: new Set(), flow: null };
  if (!selectedId) return empty;

  const flow = graph.flows.find((f) => f.id === selectedId);
  if (flow) {
    const edgeIds = new Set(flow.edgeIds);
    const nodeIds = new Set();
    for (const edgeId of flow.edgeIds) {
      const edge = graph.edges.find((e) => e.id === edgeId);
      if (edge) {
        nodeIds.add(edge.from);
        nodeIds.add(edge.to);
      }
    }
    nodeIds.add(flow.source);
    nodeIds.add(flow.sink);
    return { active: true, nodeIds, edgeIds, flow };
  }

  const node = graph.nodes.find((n) => n.id === selectedId);
  if (node) {
    const edgeIds = new Set(graph.edges.filter((e) => e.from === selectedId || e.to === selectedId).map((e) => e.id));
    return { active: true, nodeIds: new Set([selectedId]), edgeIds, flow: null };
  }

  const edge = graph.edges.find((e) => e.id === selectedId);
  if (edge) {
    return { active: true, nodeIds: new Set([edge.from, edge.to]), edgeIds: new Set([selectedId]), flow: null };
  }

  return empty;
}

function edgeVerdict(edge) {
  return worstVerdict([edge.protection.transit.verdict, edge.protection.atRest.verdict, edge.protection.handling.verdict]);
}

export function computeFlowSummary(graph, flow) {
  const edges = flow.edgeIds.map((id) => graph.edges.find((e) => e.id === id)).filter(Boolean);
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);

  const pathNodeIds = new Set([flow.source, flow.sink]);
  for (const e of edges) {
    pathNodeIds.add(e.from);
    pathNodeIds.add(e.to);
  }
  const externalRecipients = graph.nodes
    .filter((n) => pathNodeIds.has(n.id) && n.externality?.value === 'external')
    .map((n) => n.label);

  let protectedCount = 0;
  let unprotectedCount = 0;
  let unknownCount = 0;
  for (const e of edges) {
    const v = edgeVerdict(e);
    if (v === 'protected') protectedCount += 1;
    else if (v === 'unprotected' || v === 'mixed') unprotectedCount += 1;
    else unknownCount += 1;
  }

  return {
    flowId: flow.id,
    dataElementName: dataElement?.name ?? 'unknown field',
    dataClasses: dataElement?.dataClasses ?? [],
    sourceLabel: sourceNode?.label ?? 'unknown source',
    destinationLabel: sinkNode?.label ?? 'unknown destination',
    totalDestinations: 1,
    protectedCount,
    unprotectedCount,
    unknownCount,
    externalRecipients,
    transitVerdict: worstVerdict(edges.map((e) => e.protection.transit.verdict)),
    atRestVerdict: worstVerdict(edges.map((e) => e.protection.atRest.verdict)),
    handlingVerdict: worstVerdict(edges.map((e) => e.protection.handling.verdict)),
    protectionSummary: flow.protectionSummary,
    policyVerdict: flow.policyVerdict,
  };
}

export function computeArchitectureViewModel(graph, state) {
  const selection = resolveSelection(graph, state.selectedId);

  const zones = ZONE_ORDER.map((name) => ({
    name,
    nodeIds: graph.nodes.filter((n) => zoneForNode(n) === name).map((n) => n.id),
  }));

  const nodes = graph.nodes.map((n) => ({
    id: n.id,
    label: n.label,
    kind: n.kind,
    subtype: n.subtype,
    zone: zoneForNode(n),
    selected: selection.nodeIds.has(n.id),
    dimmed: selection.active && !selection.nodeIds.has(n.id),
  }));

  const edges = graph.edges.map((e) => ({
    id: e.id,
    from: e.from,
    to: e.to,
    verdict: edgeVerdict(e),
    selected: selection.edgeIds.has(e.id),
    dimmed: selection.active && !selection.edgeIds.has(e.id),
  }));

  const flowSummary = selection.flow ? computeFlowSummary(graph, selection.flow) : null;

  return { zones, nodes, edges, flowSummary };
}
