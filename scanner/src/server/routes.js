// routes.js — Milestone 3, sub-project Server, increment 1.
//
// Five pure GET-endpoint handlers, each `(graph, ...) -> {status, body}`.
// No req/res access anywhere in this file — that is what makes these
// handlers unit-testable without an HTTP layer at all. http-server.js is
// the only module that touches node:http and calls into these.
//
// Every response body is wrapped in `wrapResponse`, which adds the exact
// envelope fields PRD line 1326 names (quoted in the implementation plan):
// "base graph/snapshot digest, schema/extension versions, scope, coverage,
// limitations, and contributing canonical IDs."

import { _filterGraph, validateFilterShape } from '../lineage/export-json.js';

/**
 * Shared response envelope. Maps PRD line 1326's required fields onto the
 * graph's own real fields:
 *   - digest              -> graph.graphId (the base graph/snapshot digest)
 *   - schemaVersion        -> graph.schemaVersion
 *   - extensions           -> graph.extensions (schema/extension versions —
 *                             today always `{}`; see schema.js)
 *   - scope                -> graph.scope
 *   - coverage              -> graph.coverage
 *   - limitations           -> graph.limitations
 *   - canonicalIds          -> see the design note below
 *
 * "contributing canonical IDs" design decision (disclosed per the plan):
 * for `handleScan`/`handleGraph`, which describe the WHOLE graph rather
 * than one entity, `canonicalIds` is `null` — the response body for
 * `handleGraph` already IS the full nodes/edges/flows arrays, so echoing
 * every id again here would be pure duplication with no informational
 * gain, and for a large graph would materially bloat the response for
 * zero benefit. For `handleNode`/`handleEdge`, `canonicalIds` is the
 * single id the response is about. For `handleFlow`, `canonicalIds` is
 * the flow's own id PLUS the node/edge ids that flow's evidence draws
 * from (source, sink, edgeIds) — a flow is a derived record referencing
 * several underlying entities, and naming all of them here is genuinely
 * useful metadata a client would otherwise have to re-derive from the
 * flow body itself.
 */
export function wrapResponse(data, graph, { canonicalIds = null } = {}) {
  return {
    digest: graph?.graphId ?? null,
    schemaVersion: graph?.schemaVersion ?? null,
    extensions: graph?.extensions ?? {},
    scope: graph?.scope ?? null,
    coverage: graph?.coverage ?? null,
    limitations: graph?.limitations ?? [],
    canonicalIds,
    data,
  };
}

function _findById(list, id) {
  if (!Array.isArray(list)) return null;
  return list.find((item) => item && item.id === id) ?? null;
}

/** Scan/graph metadata — NOT the full node/edge arrays. */
export function handleScan(graph) {
  const data = {
    schemaVersion: graph?.schemaVersion ?? null,
    graphId: graph?.graphId ?? null,
    generatedAt: graph?.generatedAt ?? null,
    scope: graph?.scope ?? null,
    scanHealth: graph?.scanHealth ?? null,
    coverage: graph?.coverage ?? null,
  };
  return { status: 200, body: wrapResponse(data, graph, { canonicalIds: null }) };
}

/** The full graph document. No pagination/filtering in S1 (that's `query`'s job, S2). */
export function handleGraph(graph) {
  return { status: 200, body: wrapResponse(graph, graph, { canonicalIds: null }) };
}

/**
 * A deterministic typed projection query — Milestone 5's own
 * `POST /api/v1/query`, the S2 endpoint `handleGraph`'s own header
 * comment named and deferred. `filter` is the exact `{nodeIds, edgeIds}`
 * shape `dataflow export --filter`/`exportGraphJSON` already use — reused
 * via `_filterGraph`, never reimplemented. `undefined`/`{}` returns the
 * whole graph, identical to `handleGraph`. A malformed filter is a 400,
 * never a thrown exception reaching the caller.
 */
export function handleQuery(graph, filter) {
  const check = validateFilterShape(filter);
  if (!check.valid) {
    return { status: 400, body: { error: check.error } };
  }
  return { status: 200, body: wrapResponse(_filterGraph(graph, filter), graph, { canonicalIds: null }) };
}

/** Look up one node by id. 404 with a clear body if not found. */
export function handleNode(graph, id) {
  const node = _findById(graph?.nodes, id);
  if (!node) {
    return { status: 404, body: wrapResponse({ error: `node not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  return { status: 200, body: wrapResponse(node, graph, { canonicalIds: [id] }) };
}

/** Look up one edge by id. 404 with a clear body if not found. */
export function handleEdge(graph, id) {
  const edge = _findById(graph?.edges, id);
  if (!edge) {
    return { status: 404, body: wrapResponse({ error: `edge not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  return { status: 200, body: wrapResponse(edge, graph, { canonicalIds: [id] }) };
}

/** Look up one flow by id. 404 with a clear body if not found. */
export function handleFlow(graph, id) {
  const flow = _findById(graph?.flows, id);
  if (!flow) {
    return { status: 404, body: wrapResponse({ error: `flow not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  const contributing = new Set([id]);
  if (flow.source) contributing.add(flow.source);
  if (flow.sink) contributing.add(flow.sink);
  for (const eid of (flow.edgeIds || [])) contributing.add(eid);
  return { status: 200, body: wrapResponse(flow, graph, { canonicalIds: [...contributing] }) };
}
