// export-json.js — Milestone 4, sub-project JSON/CSV export.
//
// Deterministic JSON export of a DataFlowGraph v1 document, satisfying
// PRD §17.5 (embed filtered-or-full graph; default-redacted; scan health/
// scope/versions/limitations/generated timestamp; tamper-evident digest;
// confidential-content disclosure) and AC-14 (export reproducibility).
//
// graph.graphId is scan-metadata-derived (dfg:<repo>:<commit>:<config>,
// see ids.js's own `graphId()` — `dfg:${repo}:${commit}:${cfg}`), NOT a
// content digest — confirmed by direct read before this module was
// written. computeRunAttestation (posture/attestation.js) runs over
// `findings: normalizeFindings(scan)` only, never `scan.lineageGraph` —
// confirmed by direct read of both call sites in bin/agentic-security.js
// (the `agentic-security scan` and `agentic-security ci` commands). This
// module computes its own content digest instead of reusing either.

import * as crypto from 'node:crypto';
import { _redactGraph } from './redact-graph.js';

// Canonicalization for the content digest.
//
// REVISED after the final whole-branch review of this sub-project found
// the original hand-enumerated per-field allowlist (id/kind/subtype/
// coverageStatus on a node, etc.) silently EXCLUDED most risk-bearing
// content: mutating node.destination, node.externality, node.label,
// flow.handling, edge.provenance, dataElement.aiContexts/.name, and
// wiping graph.evidence/graph.transformations ENTIRELY all left the
// digest unchanged — the worse of the two possible failure modes for a
// "tamper-evident" claim (under-inclusion silently hides real tampering;
// AC-14's own concern, over-inclusion breaking reproducibility on a
// genuinely volatile field, is far easier to notice and fix, since it
// fails the reproducibility test immediately rather than failing
// silently in production).
//
// Rather than hand-list every field of every entity kind (exactly the
// approach that produced the gap above — dataflow-graph.schema.json
// alone declares 60+ distinct fields across 6 entity kinds, and a manual
// list drifts the moment the schema gains a field), this canonicalizes
// EVERYTHING in the graph via a small, explicit EXCLUDE list of the only
// genuinely volatile/non-content fields in the schema (confirmed against
// dataflow-graph.schema.json directly): `generatedAt` (graph-level,
// explicitly excluded per AC-14's own wording), `scanHealth` (describes
// the scan PROCESS — timing/duration-shaped, not the data content), and
// `timestamp` (evidence-level, scan-time-of-observation, not content).
// Everything else — every node/edge/flow/dataElement/evidence/
// transformation field, including ones added to the schema after this
// comment was written — is included by default, which is the safer
// default for a tamper-evidence digest: a new field must be deliberately
// ADDED to EXCLUDE_KEYS to be left out, rather than deliberately added to
// an allowlist to be included.
const EXCLUDE_KEYS = new Set(['generatedAt', 'scanHealth', 'timestamp']);
const ENTITY_ARRAY_KEYS = new Set(['nodes', 'edges', 'flows', 'dataElements', 'evidence', 'transformations']);

function _canon(value, keyHint) {
  if (Array.isArray(value)) {
    const mapped = value.map((v) => _canon(v));
    // Only the six top-level entity arrays get sorted by id — they are
    // graph-builder.js's own emission-sorted arrays (defensively re-sorted
    // here rather than trusted), and sorting them makes the digest
    // independent of array order. Nested arrays (edgeIds on a flow,
    // fieldMappings on an edge, etc.) are NOT re-sorted: several are
    // semantically ordered (a flow's edgeIds is a real path sequence,
    // per ids.js's own pathId discriminator precedent) and re-sorting
    // them would hide a genuine reordering of graph content.
    if (keyHint && ENTITY_ARRAY_KEYS.has(keyHint)) {
      mapped.sort((a, b) => {
        const ai = a && typeof a === 'object' ? String(a.id ?? '') : String(a);
        const bi = b && typeof b === 'object' ? String(b.id ?? '') : String(b);
        // Plain codepoint comparison, not localeCompare — ICU-dependent
        // collation can return 0 for genuinely distinct strings, which a
        // digest sort must never do.
        return ai < bi ? -1 : ai > bi ? 1 : 0;
      });
    }
    return mapped;
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) {
      if (EXCLUDE_KEYS.has(k)) continue;
      out[k] = _canon(value[k], k);
    }
    return out;
  }
  return value;
}

export function computeGraphDigest(graph) {
  const canon = _canon(graph ?? {});
  return crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
}

// --- Filter narrowing rule (the real design decision this module makes) ---
//
// `opts.filter` is `{nodeIds, edgeIds}` — the exact shape
// `frontend/src/lib/focus-controls.js`'s nine graph-traversal functions
// (showUpstream/showDownstream/showAllPaths/showShortestPath/
// showExternalPathsOnly/showUnprotectedPathsOnly/showAliases/
// showDisconnected) and `views/architecture-view.js`'s own
// `resolveSelection` already produce and consume, confirmed by direct
// read of `focus-controls.js` — reused verbatim rather than inventing a
// third selection shape for export.
//
// nodes/edges narrow by direct id membership (the brief's own starter
// code). flows/dataElements need their own rule, decided and grounded
// here against the real flagship fixture (see export-json.test.js's
// `filter narrows` tests):
//
//   FLOW survives iff BOTH (a) its `source` and `sink` node ids are
//   still present in the filtered node set, AND (b) every id in its own
//   `edgeIds[]` is still present in the filtered edge set (a full
//   subset — not "at least one edge survives", not "some overlap").
//
//   Why not node-membership alone: the real fixture has two flows
//   (flow:f7273b6e7b61, flow:154396169be8) sharing the identical
//   source/sink pair (Web App -> Application Logs, the masked- and
//   raw-log branches) but diverging on their SECOND edge. A filter
//   admitting both endpoint nodes plus only ONE of the two flows' full
//   edge sets must keep the flow whose edges are fully present and drop
//   the other — node-membership alone cannot tell them apart, and would
//   leave the dropped flow's own `edgeIds[]` naming an edge no longer in
//   `graph.edges`, a dangling reference in the exported document.
//   Why not edgeIds-subset alone: a flow's `source`/`sink` fields are
//   themselves references into `graph.nodes`, independent of its edges
//   (an edgeIds-only rule could keep a flow whose own declared source or
//   sink node was filtered out). Requiring both is the only rule that
//   guarantees every remaining flow is fully, referentially resolvable
//   using only what's left in the filtered graph.
//
//   DATAELEMENTS narrow to the UNION of every id referenced by a
//   surviving node's `dataElementIds[]` and every id referenced by a
//   surviving flow's `dataElementIds[]` — not either alone. Node-only
//   would leave a surviving flow's own `dataElementIds[]` dangling
//   whenever a flow carries a data element none of its endpoint nodes'
//   own list happens to name; flow-only would leave a surviving node's
//   `dataElementIds[]` dangling whenever a filter keeps a node but drops
//   every flow touching it (exactly the single-node filter test below,
//   where zero flows survive but the one kept node still legitimately
//   references three data elements). The union is the only rule that
//   keeps every remaining reference resolvable.
//
//   `graph.transformations` is deliberately left UNFILTERED — out of
//   scope for this decision (the brief names only flows/dataElements,
//   and `frontend/src/lib/focus-controls.js` has no transformation-aware
//   selection to mirror). An unfiltered transformation can end up
//   referenced by nothing remaining (orphaned, not dangling — the
//   opposite direction of the two problems narrowed above), a disclosed,
//   deliberate non-goal of this filter, not an oversight.
function _filterGraph(graph, filter) {
  if (!filter) return graph;
  const nodeIds = new Set(filter.nodeIds ?? []);
  const edgeIds = new Set(filter.edgeIds ?? []);
  const nodes = (graph.nodes ?? []).filter((n) => nodeIds.has(n.id));
  const edges = (graph.edges ?? []).filter((e) => edgeIds.has(e.id));

  const flows = (graph.flows ?? []).filter((f) => {
    if (!nodeIds.has(f.source) || !nodeIds.has(f.sink)) return false;
    return (f.edgeIds ?? []).every((id) => edgeIds.has(id));
  });

  const keptDataElementIds = new Set();
  for (const n of nodes) for (const id of n.dataElementIds ?? []) keptDataElementIds.add(id);
  for (const f of flows) for (const id of f.dataElementIds ?? []) keptDataElementIds.add(id);
  const dataElements = (graph.dataElements ?? []).filter((d) => keptDataElementIds.has(d.id));

  return { ...graph, nodes, edges, flows, dataElements };
}

export function exportGraphJSON(graph, opts = {}) {
  const redact = opts.redact !== false;
  const filtered = _filterGraph(graph, opts.filter);
  const body = redact ? _redactGraph(filtered) : filtered;
  return {
    exportedAt: new Date().toISOString(),
    schemaVersion: graph?.schemaVersion ?? null,
    // Deliberate: the digest always identifies the SOURCE graph this
    // export was taken from, never the filtered/redacted `graph:` body
    // below — two different filters (or redact:true vs redact:false) of
    // the same scan must report the same digest, since both are views
    // of one underlying scan result, not independently-verifiable
    // artifacts of their own. A caller wanting to verify `graph:`'s own
    // content should re-filter/re-redact the source and compare, not
    // treat this digest as a hash of the returned body.
    digest: computeGraphDigest(graph),
    scope: graph?.scope ?? null,
    coverage: graph?.coverage ?? null,
    limitations: graph?.limitations ?? [],
    confidential: true,
    graph: body,
  };
}
