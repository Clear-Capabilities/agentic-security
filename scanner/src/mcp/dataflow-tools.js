// dataflow-tools.js — Milestone 4, sub-project MCP tools.
//
// Thin, read-only MCP adapter over the DataFlowGraph v1 artifact. Every
// piece of actual graph-loading and graph-query logic here is REUSED,
// unmodified, from scanner/src/server/ (built for the `explore` HTTP
// server, Milestone 3): loadSignedGraph does the signed-artifact
// load+verify, the four handleX functions do the lookups. This module
// adds nothing but MCP tool shape (name/description/inputSchema/handler)
// and MCP-appropriate error handling — no new graph-query logic is
// written here, on purpose (see this sub-project's own scoping doc).

import { loadSignedGraph } from '../server/graph-loader.js';
import { handleGraph, handleNode, handleEdge, handleFlow } from '../server/routes.js';
import { _redactNode, _redactEvidence, _redactGraph } from '../lineage/redact-graph.js';
import { _filterGraph, validateFilterShape } from '../lineage/export-json.js';

const META = { source: 'agentic-security-mcp', untrusted_excerpts: true };

function _loadOrFailure(sessionRoot) {
  const loaded = loadSignedGraph(sessionRoot);
  if (loaded.ok) return { graph: loaded.graph };
  return {
    failure: {
      _meta: META,
      hasResult: false,
      reason: loaded.reason,
      message: loaded.message,
    },
  };
}

// Milestone 5, large-graph pagination: an optional `filter` input narrows the
// returned graph via the exact same `validateFilterShape`/`_filterGraph`
// pair the CLI's own `--filter` and the `explore` server's new
// `POST /api/v1/query` endpoint both already use — one real, shared
// primitive, not a third drifting copy. KNOWN, DISCLOSED GAP (still open):
// an OMITTED filter still returns the whole graph inline, with the same
// stdio.js MAX_LINE_BYTES (4MB) risk on a very large, unfiltered scan as
// before this change — this increment adds an opt-in capability for a
// caller that supplies a filter, it does not add a forced fallback/offload
// for a caller that doesn't. That remains a follow-up increment.
export const dataflow_get_graph = {
  name: 'dataflow_get_graph',
  description: 'Return the DataFlowGraph v1 artifact from the last signed, verified deep-mode scan: nodes, edges, flows, scope, coverage, and limitations. Requires a prior `AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan`. Optional `filter: {nodeIds, edgeIds}` narrows the returned nodes/edges/flows/dataElements (same primitive as the CLI\'s `--filter` and the `explore` server\'s `POST /api/v1/query`). KNOWN GAP: an OMITTED filter still returns the whole graph inline with no pagination/offload — may exceed the stdio transport line cap on a very large, unfiltered graph; supply a filter to narrow the response.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      filter: {
        type: 'object',
        additionalProperties: false,
        properties: {
          nodeIds: { type: 'array', items: { type: 'string' } },
          edgeIds: { type: 'array', items: { type: 'string' } },
        },
      },
    },
  },
  async handler(args, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    // Milestone 5, large-graph pagination: reuses the exact same
    // validateFilterShape/_filterGraph pair the new POST /api/v1/query
    // server endpoint and the CLI's own --filter both use — one real,
    // shared primitive, not a third drifting copy.
    const filterCheck = validateFilterShape(args?.filter);
    if (!filterCheck.valid) {
      return { _meta: META, hasResult: false, reason: 'invalid-filter', message: filterCheck.error };
    }
    const { status, body } = handleGraph(graph);
    return {
      _meta: META,
      hasResult: true,
      status,
      data: _redactGraph(args?.filter ? _filterGraph(body.data, args.filter) : body.data),
      digest: body.digest,
      schemaVersion: body.schemaVersion,
      extensions: body.extensions,
      scope: body.scope,
      coverage: body.coverage,
      limitations: body.limitations,
    };
  },
};

export const dataflow_get_node = {
  name: 'dataflow_get_node',
  description: 'Look up one node by canonical id in the DataFlowGraph v1 artifact.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = handleNode(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: _redactNode(body.data),
      canonicalIds: body.canonicalIds,
    };
  },
};

export const dataflow_get_edge = {
  name: 'dataflow_get_edge',
  description: 'Look up one edge by canonical id in the DataFlowGraph v1 artifact.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = handleEdge(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};

export const dataflow_get_flow = {
  name: 'dataflow_get_flow',
  description: 'Look up one flow by canonical id in the DataFlowGraph v1 artifact, including its contributing node/edge canonical ids.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = handleFlow(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};
