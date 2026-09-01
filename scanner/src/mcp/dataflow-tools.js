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
import { redactString } from './redact.js';

const META = { source: 'agentic-security-mcp', untrusted_excerpts: false };

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

// Redacts evidence[].location.note in place on a COPY of the graph slice
// being returned — never mutates the loaded graph object, which may be
// reused across calls within the same process lifetime by other tools.
function _redactEvidenceNotes(data) {
  if (!data || !Array.isArray(data.evidence)) return data;
  return {
    ...data,
    evidence: data.evidence.map((e) => {
      if (!e?.location?.note) return e;
      return { ...e, location: { ...e.location, note: redactString(e.location.note) } };
    }),
  };
}

export const dataflow_get_graph = {
  name: 'dataflow_get_graph',
  description: 'Return the full DataFlowGraph v1 artifact from the last signed, verified deep-mode scan: nodes, edges, flows, scope, coverage, and limitations. Requires a prior `AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan`.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {},
  },
  async handler(_args, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = handleGraph(graph);
    return {
      _meta: META,
      hasResult: true,
      status,
      data: _redactEvidenceNotes(body.data),
      digest: body.digest,
      schemaVersion: body.schemaVersion,
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
      data: body.data,
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
