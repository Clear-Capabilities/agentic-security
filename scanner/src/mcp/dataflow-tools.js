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

// Redacts every scanned-source-derived string field on a COPY of the data
// being returned — never mutates the loaded graph object, which may be
// reused across calls within the same process lifetime by other tools.
//
// Three real source-derived surfaces, confirmed by reading the graph
// pipeline directly (findings from Task 1's own follow-up security
// review, not assumed from the schema alone):
//   - `node.destination.raw`/`.literalValue` — resolve-destination.js's
//     `resolveDestination()` lifts these straight out of scanned call-site
//     arguments (`renderExpr(arg0)` / `String(arg0.value)`); a hardcoded
//     connection string, webhook URL, or API-key literal used as a
//     destination argument lands here verbatim.
//   - `evidence[].claim` — composed from resolved values in
//     graph-builder.js; can echo the same literal content.
//   - `evidence[].location.note` / `.snippet` — schema-declared free-text
//     fields; `.note` is fixture-only today (the real emitter uses
//     `{file,line}`, never `{note}`) and `.snippet` is always null today,
//     but both are declared string fields a future evidence producer could
//     populate with raw source text, so both stay defensively redacted
//     rather than trusting today's producers to never change.
function _redactNode(node) {
  if (!node?.destination) return node;
  const d = node.destination;
  if (typeof d.raw !== 'string' && typeof d.literalValue !== 'string') return node;
  return {
    ...node,
    destination: {
      ...d,
      raw: typeof d.raw === 'string' ? redactString(d.raw) : d.raw,
      literalValue: typeof d.literalValue === 'string' ? redactString(d.literalValue) : d.literalValue,
    },
  };
}

function _redactEvidence(evidence) {
  if (!Array.isArray(evidence)) return evidence;
  return evidence.map((e) => {
    if (!e || typeof e !== 'object') return e;
    return {
      ...e,
      claim: typeof e.claim === 'string' ? redactString(e.claim) : e.claim,
      snippet: typeof e.snippet === 'string' ? redactString(e.snippet) : e.snippet,
      location: e.location?.note
        ? { ...e.location, note: redactString(e.location.note) }
        : e.location,
    };
  });
}

// Full-graph redaction: every node's destination, plus the top-level
// evidence array. Edges/flows carry only evidenceRefs (id strings into
// graph.evidence), never embedded evidence objects or destination-shaped
// fields — confirmed against dataflow-graph.schema.json — so they need no
// redaction pass of their own here.
function _redactGraph(data) {
  if (!data) return data;
  return {
    ...data,
    nodes: Array.isArray(data.nodes) ? data.nodes.map(_redactNode) : data.nodes,
    evidence: _redactEvidence(data.evidence),
  };
}

// KNOWN, DISCLOSED GAP (not fixed in this increment): this plan's own scope
// item 1 required dataflow_get_graph to paginate/offload per query_taint's
// precedent (`_maybeOffload` in tools.js) once a graph is large. That
// precedent offloads a single flat array; a graph has three (nodes/edges/
// flows) plus a top-level evidence array, so a correct offload design needs
// its own real scoping pass, not a same-shape reuse. Returning the whole
// graph inline risks exceeding stdio.js's MAX_LINE_BYTES (4MB) on a large
// scan. Left for a follow-up increment rather than shipping a rushed,
// under-designed pagination scheme in a security-fix round.
export const dataflow_get_graph = {
  name: 'dataflow_get_graph',
  description: 'Return the full DataFlowGraph v1 artifact from the last signed, verified deep-mode scan: nodes, edges, flows, scope, coverage, and limitations. Requires a prior `AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan`. KNOWN GAP: does not yet paginate/offload for very large graphs (may exceed the stdio transport line cap) — a future increment will add this, matching query_taint\'s own precedent.',
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
      data: _redactGraph(body.data),
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
