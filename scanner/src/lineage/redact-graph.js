// redact-graph.js — Milestone 4. Shared redaction logic for the
// DataFlowGraph v1 artifact, extracted from the MCP-tools sub-project's
// own dataflow-tools.js (where a whole-branch security review found and
// fixed the real gap this logic closes — see that sub-project's own
// CLAUDE.md section, "Dataflow-tools redaction scope"). Any export path
// that returns graph content to a consumer outside the scan process must
// reuse this module rather than re-deriving redaction logic — that is
// exactly the "two near-identical copies" bug class this extraction
// exists to prevent (the same bug class M3-UX-Filters' own
// `rowMatchesFilters` duplication hit once already this session).

import { redactString } from '../mcp/redact.js';

// Redacts every scanned-source-derived string field on a COPY of the data
// being returned — never mutates the loaded graph object, which may be
// reused across calls within the same process lifetime by other callers.
//
// Real source-derived surfaces, confirmed by reading the graph pipeline
// directly (the destination/evidence findings are from the MCP-tools
// sub-project's own follow-up security review; the blockingExpression and
// queueDetail/storeDetail findings are from the JSON/CSV export
// sub-project's own final whole-branch review, which found the two
// omissions below by tracing resolve-destination.js/graph-builder.js
// directly rather than trusting this comment's own prior "confirmed
// exhaustive" claim — do not repeat that mistake; re-verify against the
// real pipeline before trusting this list again in the future):
//   - `node.destination.raw`/`.literalValue`/`.blockingExpression` —
//     resolve-destination.js's `resolveDestination()` lifts these straight
//     out of scanned call-site arguments (`renderExpr(arg0)` /
//     `String(arg0.value)`); a hardcoded connection string, webhook URL,
//     or API-key literal used as a destination argument lands here
//     verbatim. `blockingExpression` is NOT a derived/summary field — for
//     a `'dynamic'` resolution, `resolve-destination.js` sets it to the
//     IDENTICAL string as `raw` (confirmed by direct read), so omitting it
//     was a real, exploitable redaction bypass (the whole-branch review's
//     own repro: `raw` redacted, `blockingExpression` carrying the same
//     un-redacted secret verbatim on the very same object).
//   - `node.queueDetail.topic` — `graph-builder.js`'s `extractQueueDetail`
//     lifts this verbatim from a scanned call-site's own object-literal
//     argument (`QueueUrl`/`TopicArn`/`topic`/`queueName`), the identical
//     "literal argument value" shape `destination.literalValue` already
//     covers, just on a different node field.
//   - `node.storeDetail.table`/`.columns` — `graph-builder.js`'s ORM-write
//     extraction lifts these from a scanned receiver identifier and
//     object-literal property keys. Lower risk than the fields above (an
//     identifier/property name, not typically a secret-shaped literal),
//     but still genuinely scanned-source text — redacted defensively for
//     the same reason `evidence[].snippet` is, even though no known
//     producer currently emits a secret-shaped table/column name.
//   - `evidence[].claim` — composed from resolved values in
//     graph-builder.js; can echo the same literal content.
//   - `evidence[].location.note` / `.snippet` — schema-declared free-text
//     fields; `.note` is fixture-only today (the real emitter uses
//     `{file,line}`, never `{note}`) and `.snippet` is always null today,
//     but both are declared string fields a future evidence producer could
//     populate with raw source text, so both stay defensively redacted
//     rather than trusting today's producers to never change.
function _redactDestination(d) {
  if (!d) return d;
  const hasRedactable = typeof d.raw === 'string' || typeof d.literalValue === 'string' || typeof d.blockingExpression === 'string';
  if (!hasRedactable) return d;
  return {
    ...d,
    raw: typeof d.raw === 'string' ? redactString(d.raw) : d.raw,
    literalValue: typeof d.literalValue === 'string' ? redactString(d.literalValue) : d.literalValue,
    blockingExpression: typeof d.blockingExpression === 'string' ? redactString(d.blockingExpression) : d.blockingExpression,
  };
}

function _redactQueueDetail(q) {
  if (!q || typeof q.topic !== 'string') return q;
  return { ...q, topic: redactString(q.topic) };
}

function _redactStoreDetail(s) {
  if (!s) return s;
  return {
    ...s,
    table: typeof s.table === 'string' ? redactString(s.table) : s.table,
    columns: Array.isArray(s.columns) ? s.columns.map((c) => (typeof c === 'string' ? redactString(c) : c)) : s.columns,
  };
}

export function _redactNode(node) {
  if (!node?.destination && !node?.queueDetail && !node?.storeDetail) return node;
  return {
    ...node,
    destination: _redactDestination(node.destination),
    queueDetail: _redactQueueDetail(node.queueDetail),
    storeDetail: _redactStoreDetail(node.storeDetail),
  };
}

export function _redactEvidence(evidence) {
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
export function _redactGraph(data) {
  if (!data) return data;
  return {
    ...data,
    nodes: Array.isArray(data.nodes) ? data.nodes.map(_redactNode) : data.nodes,
    evidence: _redactEvidence(data.evidence),
  };
}
