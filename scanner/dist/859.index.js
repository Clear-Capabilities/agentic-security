export const id = 859;
export const ids = [859];
export const modules = {

/***/ 859:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   exportGraphJSON: () => (/* binding */ exportGraphJSON)
/* harmony export */ });
/* unused harmony export computeGraphDigest */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(7598);
/* harmony import */ var _redact_graph_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(334);
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

function computeGraphDigest(graph) {
  const canon = _canon(graph ?? {});
  return node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
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

function exportGraphJSON(graph, opts = {}) {
  const redact = opts.redact !== false;
  const filtered = _filterGraph(graph, opts.filter);
  const body = redact ? (0,_redact_graph_js__WEBPACK_IMPORTED_MODULE_1__/* ._redactGraph */ .zl)(filtered) : filtered;
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


/***/ }),

/***/ 334:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   T2: () => (/* binding */ _redactNode),
/* harmony export */   zl: () => (/* binding */ _redactGraph)
/* harmony export */ });
/* unused harmony export _redactEvidence */
/* harmony import */ var _mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3468);
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



// Redacts every scanned-source-derived string field on a COPY of the data
// being returned — never mutates the loaded graph object, which may be
// reused across calls within the same process lifetime by other callers.
//
// Real source-derived surfaces, confirmed by reading the graph pipeline
// directly (the destination/evidence findings are from the MCP-tools
// sub-project's own follow-up security review; the blockingExpression,
// queueDetail/storeDetail, and coverageReason findings are from the
// JSON/CSV export sub-project's own final whole-branch review AND its own
// scoped re-review — the re-review found `coverageReason` carrying the
// SAME unredacted string as an already-redacted `blockingExpression` on
// the same object, the identical bug class surviving one review round
// after the first fix, on a different field — do not repeat that
// mistake a third time; re-verify against the real pipeline before
// trusting this list again in the future):
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
//   - `node.coverageReason` — `sink-registry.js`'s FR-203 branch builds
//     this as `` `destination could not be statically resolved: ${blockingExpression}` ``
//     (confirmed at sink-registry.js's own FR-203 reason-string site,
//     threaded through coverage.js/graph-builder.js to `node.coverageReason`
//     at mint time) — the SAME secret content `destination.blockingExpression`
//     already carries, copied verbatim into a second, unrelated-looking
//     field on the same node. A caller who trusts `destination` alone is
//     redacted correctly still gets the identical secret back via this
//     field. Proven live by the scoped re-review that found this gap.
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
    raw: typeof d.raw === 'string' ? (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(d.raw) : d.raw,
    literalValue: typeof d.literalValue === 'string' ? (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(d.literalValue) : d.literalValue,
    blockingExpression: typeof d.blockingExpression === 'string' ? (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(d.blockingExpression) : d.blockingExpression,
  };
}

function _redactQueueDetail(q) {
  if (!q || typeof q.topic !== 'string') return q;
  return { ...q, topic: (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(q.topic) };
}

function _redactStoreDetail(s) {
  if (!s) return s;
  return {
    ...s,
    table: typeof s.table === 'string' ? (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(s.table) : s.table,
    columns: Array.isArray(s.columns) ? s.columns.map((c) => (typeof c === 'string' ? (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(c) : c)) : s.columns,
  };
}

function _redactNode(node) {
  const hasRedactable = node?.destination || node?.queueDetail || node?.storeDetail || typeof node?.coverageReason === 'string';
  if (!hasRedactable) return node;
  const out = { ...node };
  // Only overwrite a key that was actually present on the input — never
  // inject a `key: undefined` own-property onto a node that never had it
  // (found by the scoped re-review: unconditionally writing `destination`/
  // `queueDetail`/`storeDetail` added an own `undefined` value even when
  // absent from the source node, which JSON.stringify silently drops but
  // which could still trip a `hasOwnProperty` structural check elsewhere,
  // e.g. validate.js's own storeDetail.columns guard).
  if ('destination' in node) out.destination = _redactDestination(node.destination);
  if ('queueDetail' in node) out.queueDetail = _redactQueueDetail(node.queueDetail);
  if ('storeDetail' in node) out.storeDetail = _redactStoreDetail(node.storeDetail);
  if (typeof node.coverageReason === 'string') out.coverageReason = (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(node.coverageReason);
  return out;
}

function _redactEvidence(evidence) {
  if (!Array.isArray(evidence)) return evidence;
  return evidence.map((e) => {
    if (!e || typeof e !== 'object') return e;
    return {
      ...e,
      claim: typeof e.claim === 'string' ? (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(e.claim) : e.claim,
      snippet: typeof e.snippet === 'string' ? (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(e.snippet) : e.snippet,
      location: e.location?.note
        ? { ...e.location, note: (0,_mcp_redact_js__WEBPACK_IMPORTED_MODULE_0__/* .redactString */ .rd)(e.location.note) }
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


/***/ }),

/***/ 3468:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   MC: () => (/* binding */ redactArgsBlob),
/* harmony export */   lE: () => (/* binding */ redactFinding),
/* harmony export */   rd: () => (/* binding */ redactString)
/* harmony export */ });
// Secret redactor for MCP tool outputs and audit log argument summaries.
//
// OWASP MCP01 + MCP10: the scanner reads source code, and findings carry
// `snippet` / `description` / `trace` strings that may contain hardcoded
// credentials, API keys, JWTs, private keys, etc. When those flow back to
// the agent through tools/call responses they land in the agent's context
// — exposing the secret to model logs, transcripts, and any downstream tool
// the agent passes them to.
//
// We replace high-confidence secret shapes with [REDACTED:<kind>] before
// emitting them. The original full content is still on disk (scanner
// findings); the MCP surface is the bottleneck we control.
//
// Patterns deliberately stay narrow: high-precision so we don't garble
// non-secret long strings (UUIDs, SHAs, base64-encoded scan IDs).

const PATTERNS = [
  // Provider-specific high-entropy keys (anchored prefixes give very low FP)
  [/AKIA[0-9A-Z]{16}/g, 'aws-access-key'],
  [/ASIA[0-9A-Z]{16}/g, 'aws-temp-key'],
  [/gh[pousr]_[A-Za-z0-9]{36,255}/g, 'github-token'],
  [/xox[abprs]-[A-Za-z0-9-]{10,}/g, 'slack-token'],
  [/sk-ant-[A-Za-z0-9_-]{20,}/g, 'anthropic-key'],
  [/sk-proj-[A-Za-z0-9_-]{20,}/g, 'openai-project-key'],
  [/sk-[A-Za-z0-9]{32,}/g, 'openai-or-stripe-key'],
  [/sk_(?:live|test)_[A-Za-z0-9]{20,}/g, 'stripe-key'],
  [/rk_(?:live|test)_[A-Za-z0-9]{20,}/g, 'stripe-restricted-key'],
  [/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, 'sendgrid-key'],
  [/AIza[0-9A-Za-z_-]{35}/g, 'google-api-key'],
  // Stage 4 correctness audit (coverage breadth, AI security): this list
  // only covered a small subset of what the scanner's OWN credential
  // detector (engine.js's CREDENTIAL_PATTERNS, 40+ provider shapes) finds
  // — a Shopify/Telegram/Twilio/Discord-webhook/Square/Google-OAuth/JDBC
  // secret detected and reported by a scan reached explain_finding's
  // output completely unredacted, because none of those shapes were in
  // THIS separate, narrower list. Reusing the same regex bodies as
  // engine.js's CREDENTIAL_PATTERNS for the shapes verified to leak
  // (rather than importing engine.js itself, which would pull its entire
  // multi-thousand-line module graph into the MCP server's dependency
  // surface for a handful of consts).
  [/ya29\.[0-9A-Za-z_-]{20,}/g, 'google-oauth-token'],
  [/shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}/g, 'shopify-token'],
  [/(?<![0-9])[0-9]{8,10}:AA[0-9A-Za-z_-]{33}(?![A-Za-z0-9_])/g, 'telegram-bot-token'],
  [/twilio.{0,20}SK[0-9a-fA-F]{32}/gi, 'twilio-api-key'],
  [/sq0atp-[0-9A-Za-z_-]{22}/g, 'square-access-token'],
  [/sq0csp-[0-9A-Za-z_-]{43}/g, 'square-oauth-secret'],
  [/access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, 'paypal-braintree-token'],
  [/https:\/\/(?:discordapp|discord)\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g, 'discord-webhook'],
  [/https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/g, 'slack-webhook'],
  [/https:\/\/outlook\.office\.com\/webhook\/[A-Za-z0-9\-@]+\/IncomingWebhook\/[A-Za-z0-9-]+\/[A-Za-z0-9-]+/g, 'teams-webhook'],
  [/https:\/\/(?:www\.)?hooks\.zapier\.com\/hooks\/catch\/[A-Za-z0-9]+\/[A-Za-z0-9]+\//g, 'zapier-webhook'],
  // JDBC connection string carrying a password: only redact when password
  // evidence is actually on the line (matches engine.js's own ctx gate),
  // so a credential-free JDBC URL in docs isn't needlessly mangled.
  [/jdbc:[a-z:]+:\/\/[A-Za-z0-9.\-_:;=/@?,&]*(?:@|password=|passwd=|pwd=)[A-Za-z0-9.\-_:;=/@?,&]*/gi, 'jdbc-connection-string'],
  // JWT — three dot-separated b64url segments starting with eyJ
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'jwt'],
  // PEM-encoded private keys
  [/-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, 'private-key-block'],
  // Authorization headers — common copy-paste shape
  [/(?:Authorization|authorization)\s*:\s*Bearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/g, 'bearer-token'],
  // Hardcoded password literals — assignment shape with quoted value
  [/(password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"'\n]{6,}["']/gi, 'hardcoded-credential'],
];

const SNIPPET_MAX = 2000;
// OWASP A03 — cap input before running 14 regex patterns over it. A forged
// last-scan.json could plant a 50MB description string; without this cap a
// single explain_finding/query_taint call would peg CPU. After truncation
// the snippet still gets the final SNIPPET_MAX trim downstream.
const INPUT_MAX = 100_000;

function redactString(s) {
  if (typeof s !== 'string') return s;
  let out = s;
  if (out.length > INPUT_MAX) out = out.slice(0, INPUT_MAX) + `…(+${out.length - INPUT_MAX})`;
  for (const [re, kind] of PATTERNS) {
    out = out.replace(re, `[REDACTED:${kind}]`);
  }
  if (out.length > SNIPPET_MAX) out = out.slice(0, SNIPPET_MAX) + `…(+${out.length - SNIPPET_MAX})`;
  return out;
}

// Deep-redact every string in a finding-like object (mutates returned copy).
function redactFinding(f) {
  if (!f || typeof f !== 'object') return f;
  const out = { ...f };
  for (const k of ['snippet', 'description', 'remediation', 'title', 'vuln', 'message']) {
    if (typeof out[k] === 'string') out[k] = redactString(out[k]);
  }
  if (out.trace) {
    try { out.trace = JSON.parse(redactString(JSON.stringify(out.trace))); }
    catch { /* keep as-is if not round-trippable */ }
  }
  return out;
}

// Redact a freeform JSON-stringified argument blob (used by audit log).
function redactArgsBlob(s) {
  return redactString(s);
}


/***/ })

};
