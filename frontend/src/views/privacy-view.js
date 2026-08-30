import { flowPathNodeIds, isAiRelevantFlow } from '../lib/flow-path.js';

export const LIFECYCLE_STAGES = Object.freeze(['collection', 'processing', 'storage', 'sharing', 'retention', 'deletion']);

export function stageForNode(node) {
  return LIFECYCLE_STAGES.includes(node.lifecycleStages?.[0]) ? node.lifecycleStages[0] : 'processing';
}

export function computePrivacyRow(graph, flow) {
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const pathNodeIds = flowPathNodeIds(graph, flow);
  const pathNodes = graph.nodes.filter((n) => pathNodeIds.has(n.id));

  const stageCells = LIFECYCLE_STAGES.map((stage) => ({
    stage,
    nodeLabels: pathNodes.filter((n) => stageForNode(n) === stage).map((n) => n.label),
  }));

  return {
    flowId: flow.id,
    dataElementName: dataElement?.name ?? 'unknown field',
    dataClasses: dataElement?.dataClasses ?? [],
    stageCells,
    governanceRefs: flow.governanceRefs ?? {},
    protectionSummary: flow.protectionSummary,
    policyVerdict: flow.policyVerdict,
    isAiRelevant: isAiRelevantFlow(graph, flow),
  };
}

function rowMatchesFilters(row, filters) {
  if (filters.dataClass?.length && !filters.dataClass.some((c) => row.dataClasses.includes(c))) return false;
  if (filters.protection?.length && !filters.protection.includes(row.protectionSummary)) return false;
  if (filters.ai && !row.isAiRelevant) return false;
  return true;
}

export function computePrivacyViewModel(graph, state) {
  const rows = graph.flows.map((flow) => {
    const row = computePrivacyRow(graph, flow);
    return {
      ...row,
      selected: row.flowId === state.selectedId,
      visible: rowMatchesFilters(row, state.filters ?? {}),
    };
  });
  return { stages: LIFECYCLE_STAGES, rows };
}
