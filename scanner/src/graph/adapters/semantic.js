//
// adapters/semantic.js: read-only view over a SemanticGraph v1
// (ir/semantic-graph.js). Imports only the schema constants and validator; it
// never builds or mutates a graph.
//
// A graph that fails `validateGraph`, or whose major version is not the
// supported one, is REJECTED (INCOMPATIBLE_VERSION / INVALID_GRAPH) rather than
// partially adapted.
//
// Entities: symbol, callSite, allocation, fieldAccess, valueOrigin,
// serviceBoundary, storageEdge, sanitizer, guard (singular names of the
// graph's own lists). The semantic graph stores references as id fields, not
// an edge list, so the relation edges here are DERIVED (origin 'derived') and
// get deterministic ids; the underlying confidence tier becomes the evidence
// grade, and an unresolved call is carried as an `unknowns` entry, never as a
// fabricated callee edge.
//
//   symbol --declaration--> callSite      (the caller declares/contains it)
//   symbol --declaration--> valueOrigin / fieldAccess / allocation
//   callSite --calls--> symbol            (resolved calls only)
//   valueOrigin --data_flow--> callSite   (an argument origin feeds the call)

import {
  SEMANTIC_GRAPH_SCHEMA, SUPPORTED_MAJOR, validateGraph, ENTITY_LISTS,
} from '../../ir/semantic-graph.js';
import { GraphViewError, digestOf } from '../refs.js';
import { IndexedGraphView, local } from '../view.js';

export const SEMANTIC_ADAPTER_VERSION = '1.0.0';

const SINGULAR = {
  symbols: 'symbol', callSites: 'callSite', allocations: 'allocation', fieldAccesses: 'fieldAccess',
  valueOrigins: 'valueOrigin', serviceBoundaries: 'serviceBoundary', storageEdges: 'storageEdge',
  sanitizers: 'sanitizer', guards: 'guard',
};

/**
 * @param {object} graph  SemanticGraph v1 (buildSemanticGraph output)
 * @param {{repository:string}} opts
 */
export function semanticView(graph, opts) {
  const m = typeof graph?.schemaVersion === 'string' ? /^(\d+)\./.exec(graph.schemaVersion) : null;
  if (graph?.schema === SEMANTIC_GRAPH_SCHEMA && m && Number(m[1]) !== SUPPORTED_MAJOR) {
    throw new GraphViewError('INCOMPATIBLE_VERSION', `semantic graph major ${m[1]} is not supported (supported: ${SUPPORTED_MAJOR})`, { schemaVersion: graph.schemaVersion });
  }
  const v = validateGraph(graph);
  if (!v.ok) throw new GraphViewError('INVALID_GRAPH', `semantic graph failed validation: ${v.errors[0].code} at ${v.errors[0].path}`, { errors: v.errors.slice(0, 5) });

  const graphDigest = digestOf(graph);
  const nodes = [];
  for (const list of ENTITY_LISTS) {
    for (const e of graph[list]) {
      nodes.push({ entityKind: SINGULAR[list], localId: e.id, native: e, summary: { file: e.file, line: e.line, tier: e.confidence?.tier ?? null } });
    }
  }
  const edges = [];
  const edge = (relation, from, to, grade, extra = {}) => {
    edges.push({
      id: `sgedge:${relation}:${from.localId}:${to.localId}`, relation, origin: 'derived',
      from, to, evidence: { grade, source: 'semantic-graph' }, unknowns: extra.unknowns ?? [], attrs: extra.attrs ?? {}, native: null,
    });
  };
  for (const c of graph.callSites) {
    edge('declaration', local('symbol', c.caller), local('callSite', c.id), c.confidence.tier);
    if (c.callee) edge('calls', local('callSite', c.id), local('symbol', c.callee), c.confidence.tier, { attrs: { resolution: c.resolution } });
    for (const a of c.args || []) {
      if (a.origin) edge('data_flow', local('valueOrigin', a.origin), local('callSite', c.id), c.confidence.tier, { attrs: { argIndex: a.index } });
    }
  }
  for (const o of graph.valueOrigins) if (o.symbol) edge('declaration', local('symbol', o.symbol), local('valueOrigin', o.id), o.confidence.tier);
  for (const f of graph.fieldAccesses) if (f.symbol) edge('declaration', local('symbol', f.symbol), local('fieldAccess', f.id), f.confidence.tier);
  for (const a of graph.allocations) if (a.symbol) edge('declaration', local('symbol', a.symbol), local('allocation', a.id), a.confidence.tier);

  // Unresolved calls are unknowns on the view, not edges.
  const unresolvedCalls = graph.callSites.filter((c) => !c.callee).length;
  const reasons = [];
  const schemaOnly = ENTITY_LISTS.filter((k) => graph.coverage[k].state === 'schema-only');
  if (schemaOnly.length) reasons.push(`schema-only:${schemaOnly.join(',')}`);
  if (unresolvedCalls) reasons.push(`unresolved-calls:${unresolvedCalls}`);
  if ((graph.dynamicFeatures || []).length) reasons.push(`dynamic-features:${graph.dynamicFeatures.length}`);

  return new IndexedGraphView({
    graphKind: 'semantic', adapterVersion: SEMANTIC_ADAPTER_VERSION, repository: opts?.repository, graphDigest,
    metadata: { schema: graph.schema, schemaVersion: graph.schemaVersion, producer: graph.producer ?? null, limits: graph.limits ?? [], unresolvedCalls },
    completion: { status: reasons.length ? 'partial' : 'complete', reasons, coverage: graph.coverage },
    nodes, edges,
    reconstruct: () => graph,
  });
}
