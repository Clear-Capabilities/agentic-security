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
// Three real source-derived surfaces, confirmed by reading the graph
// pipeline directly (findings from the MCP-tools sub-project's own
// follow-up security review, not assumed from the schema alone):
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
export function _redactNode(node) {
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
