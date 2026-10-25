//
// adapters/dataflow.js: read-only view over a DataFlowGraph v1 document (the
// graph-builder output / signed export body).
//
// The graph keeps its own schema, validator and digest. This view:
//   - uses the existing `computeGraphDigest` as the graph digest, so the
//     digest in every reference equals the digest the export already signs;
//   - exposes node, edge, flow, dataElement, evidence and transformation
//     entities under their original ids;
//   - maps `edge.provenance` to the origin axis (code -> code, schema ->
//     schema, manual -> declared, runtime -> observed), so a runtime-observed
//     or manually declared edge is never traversed as a code-derived one by a
//     default query;
//   - reports completion from `scanHealth`, `coverage` and `limitations`.
//
// Projected nodes are category-granular: one node can stand for many source
// sites. That coarsening is not hidden here; it is recorded by crosswalks
// (one-to-many) built in crosswalk-builders.js.

import { computeGraphDigest } from '../../lineage/export-json.js';
import { IndexedGraphView, local } from '../view.js';

export const DATAFLOW_ADAPTER_VERSION = '1.0.0';

const ORIGIN_OF_PROVENANCE = { code: 'code', schema: 'schema', manual: 'declared', runtime: 'observed' };

const ENTITY_SECTIONS = [
  ['node', 'nodes'], ['edge', 'edges'], ['flow', 'flows'],
  ['dataElement', 'dataElements'], ['evidence', 'evidence'], ['transformation', 'transformations'],
];

/**
 * @param {object} graph  DataFlowGraph v1 (e.g. buildDataFlowGraph(...).graph)
 * @param {{repository?:string}} [opts]
 */
export function dataflowView(graph, opts = {}) {
  if (!graph || typeof graph !== 'object' || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new TypeError('dataflowView requires a DataFlowGraph v1 object with nodes[] and edges[]');
  }
  const repository = opts.repository ?? graph.scope?.repository;
  const graphDigest = computeGraphDigest(graph);

  const nodes = [];
  for (const [kind, section] of ENTITY_SECTIONS) {
    for (const e of graph[section] || []) {
      nodes.push({ entityKind: kind, localId: e.id, native: e, summary: kind === 'node' ? { kind: e.kind, subtype: e.subtype ?? null, label: e.label ?? null, coverageStatus: e.coverageStatus ?? null } : null });
    }
  }
  const edges = graph.edges.map((e) => {
    const unknowns = [];
    if (e.protocol?.destinationResolution && e.protocol.destinationResolution !== 'literal') unknowns.push({ kind: 'destination-resolution', reason: e.protocol.destinationResolution });
    if (e.coverageStatus && e.coverageStatus !== 'modeled') unknowns.push({ kind: 'coverage', reason: e.coverageStatus });
    return {
      id: e.id, relation: 'data_flow', origin: ORIGIN_OF_PROVENANCE[e.provenance] ?? 'schema',
      from: local('node', e.from), to: local('node', e.to),
      evidence: { grade: e.evidenceGrade ?? e.coverageStatus ?? 'none', source: 'dataflow-graph', evidenceRefs: e.evidenceRefs ?? [] },
      unknowns, attrs: { provenance: e.provenance, relationship: e.relationship }, native: e,
    };
  });

  const health = graph.scanHealth || {};
  const reasons = [];
  const status = health.status === 'complete' ? 'complete' : health.status ? 'partial' : 'unknown';
  if (health.status && health.status !== 'complete') reasons.push(`scan-health:${health.status}${health.reason ? `:${health.reason}` : ''}`);
  if (graph.coverage?.pathBudgetTruncation) reasons.push('path-budget-truncation');
  if (health.analysisCompletion && health.analysisCompletion.status && health.analysisCompletion.status !== 'complete') reasons.push(`analysis-${health.analysisCompletion.status}`);
  if ((graph.limitations || []).length) reasons.push(`limitations:${graph.limitations.length}`);

  return new IndexedGraphView({
    graphKind: 'dataflow', adapterVersion: DATAFLOW_ADAPTER_VERSION, repository, graphDigest,
    metadata: { schemaVersion: graph.schemaVersion ?? null, graphId: graph.graphId ?? null, scope: graph.scope ?? null, counts: Object.fromEntries(ENTITY_SECTIONS.map(([k, s]) => [k, (graph[s] || []).length])) },
    completion: { status: reasons.length && status === 'complete' ? 'partial' : status, reasons, coverage: graph.coverage ?? null },
    nodes, edges,
    reconstruct: () => graph,
  });
}
