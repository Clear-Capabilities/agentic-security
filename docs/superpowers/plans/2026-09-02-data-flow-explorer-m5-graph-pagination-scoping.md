# M5, large-graph server/worker-side pagination: scoping

Per the M5 top-level scoping doc's own deliverable #2 row: the hardest,
highest-uncertainty piece of "large-graph projections and performance
work" (client-side clustering/rendering) is already built and measured —
148ms first paint, ~53 FPS pan/zoom at the PRD's own 5,000-node/10,000-edge
reference scale (M3-Render, 2026-09-01). The real remaining gap, named in
two separate places in the code but never connected to a deliverable
before that scoping pass, is that the whole graph is always transferred
before any client-side clustering can help: `server/routes.js`'s own
comment ("No pagination/filtering in S1 — that's `query`'s job, S2") and
`mcp/dataflow-tools.js`'s own header comment ("does not yet paginate/
offload for very large graphs"). This sub-project closes that gap.

## What already exists (confirmed by direct read this session)

- **The server was already built anticipating this exact feature.**
  `scanner/src/server/CLAUDE.md`'s own "What this does NOT do" section
  names `POST /api/v1/query` explicitly: "a deterministic typed projection
  query — real design work of its own, deferred to a future S2." The
  request-size-cap middleware in `http-server.js` (`MAX_REQUEST_BODY_BYTES
  = 64KB`) was built with this in mind, per its own comment: "S1's GET
  endpoints have no meaningful body, but the middleware exists now so a
  future S2's POST endpoints inherit it without retrofitting."
- **`http-server.js`'s route dispatch is already method-aware** — `ROUTES`
  is `[{method, pattern, handler}]`, matched via `route.method !== method`
  before the pattern test (confirmed by direct read, `http-server.js:60-65`
  and the dispatch loop at `~254`). Adding a POST route is a genuine new
  array entry, not a redesign. **What's genuinely missing**: the request
  handler currently only accumulates `bodySize` (a running byte count for
  the 413 cap) — it never stores the actual body bytes anywhere, since no
  existing route needs them. A POST route needs the body content
  accumulated and JSON-parsed before dispatch, a real, new piece of
  plumbing this sub-project has to add.
- **The exact filter primitive this endpoint needs already exists, tested,
  and is already reused three times**: `export-json.js`'s `_filterGraph(graph,
  filter)` — `filter: {nodeIds?: string[], edgeIds?: string[]}` — narrows
  nodes/edges by direct membership, flows by both endpoints AND every
  `edgeIds[]` member surviving, dataElements by the union of surviving
  nodes' and flows' own `dataElementIds[]` references (confirmed via
  direct read, `export-json.js:149-167`). Already consumed by
  `exportGraphJSON` (CLI `--filter`) and `export-privacy.js`'s DPIA/RoPA
  export. **The filter SHAPE-VALIDATION logic, however, is NOT
  extracted anywhere** — it lives only as inline code inside
  `bin/agentic-security.js`'s `cmdDataflowExport` (rejecting a
  non-object/array/malformed-`nodeIds`/malformed-`edgeIds` filter file
  before it ever reaches `_filterGraph`, since `new Set("not-an-array")`
  silently iterates a string as characters instead of throwing — a real
  bug the CLI's own final review found and fixed once already). This
  sub-project extracts it into `export-json.js` as a real, shared,
  exported function, so the server (and MCP, below) get the same
  malformed-input protection the CLI already has, rather than a second,
  potentially-drifting copy.
- **`mcp/tools.js`'s `_maybeOffload` is a real, working, already-shipped
  precedent for "large result → write to scratchpad, return a
  paging hint"** — but its shape (a flat array, sliced into `head`/`tail`
  samples) does not map cleanly onto a whole `DataFlowGraph v1` document
  (four differently-sized entity arrays plus metadata, not one flat
  list). Rather than force-fitting `_maybeOffload`'s own shape onto a
  graph, or building a second, divergent offload mechanism, this
  sub-project gives `dataflow_get_graph` the SAME `filter` capability the
  new server endpoint gets — reusing the one real, already-tested
  primitive (`_filterGraph` + the new shared validator) a third time,
  rather than inventing a graph-shaped offload scheme from scratch. An
  agent that wants "just the flows touching this node" can now ask for
  exactly that in one call, which is more directly useful than an opaque
  scratchpad dump it would still have to page through separately.
- **A real import-cycle constraint, checked directly**: `dataflow-tools.js`
  does not currently import anything from `tools.js`, and `tools.js`
  imports the 4 `dataflow_*` tool definitions FROM `dataflow-tools.js`
  (confirmed via `mcp/CLAUDE.md`'s own "21 tools, not 12" note). Making
  `dataflow-tools.js` import `_maybeOffload` from `tools.js` would create
  a genuine cycle — moot here anyway, since Task 2 doesn't reuse
  `_maybeOffload` at all (see above), but worth naming for whoever scopes
  a future graph-shaped offload mechanism, since the same constraint
  would apply then too.

## Design

**Task 1 — `POST /api/v1/query` server endpoint.**
- `export-json.js` gains a new exported `validateFilterShape(filter) ->
  {valid, error}` — the CLI's own existing inline validation logic
  (object/non-array/`nodeIds`-is-array-if-present/`edgeIds`-is-array-if-
  present), extracted verbatim, not rewritten. `bin/agentic-security.js`'s
  `cmdDataflowExport` is updated to call it instead of its own inline
  copy (a real, disclosed refactor — deduplication, not new behavior).
- `routes.js` gains `handleQuery(graph, filter)` — validates via
  `validateFilterShape` (a 400 with a clear message on failure, mirroring
  the CLI's own error wording), then returns `{status: 200, body:
  wrapResponse(_filterGraph(graph, filter), graph, {canonicalIds: null})}`
  — the identical envelope shape `handleGraph` already uses, just over a
  narrowed `data`.
- `http-server.js` gains real body-content accumulation for the request
  lifecycle (buffer chunks alongside the existing `bodySize` counter,
  `Buffer.concat` + `JSON.parse` once `end` fires — 400 on malformed
  JSON, not a 500), and one new `ROUTES` entry: `{method: 'POST', pattern:
  /^\/api\/v1\/query\/?$/, handler: (graph, m, body) => handleQuery(graph,
  body?.filter)}`. The dispatch loop's `matched.handler(graph, match)`
  call needs a third argument threaded through for this to work — a real,
  disclosed, minimal signature change to the dispatch call site, with
  every EXISTING handler unaffected (they simply never read a 3rd
  argument).
- Every existing security property applies unchanged and is re-verified,
  not re-designed: Host-header check, session-token check, and the
  request-size cap all already run BEFORE the route-dispatch loop that
  this task extends — a query request is authenticated and size-capped
  exactly like every other request, inheriting the existing middleware
  chain rather than adding a parallel one.
- `scanner/src/server/CLAUDE.md`'s "What this does NOT do" section is
  updated to remove `POST /api/v1/query` from the deferred list and add a
  real row for it in the "What's here" table.

**Task 2 — `dataflow_get_graph` MCP tool gains an optional `filter`
input.**
- `dataflow-tools.js`'s `dataflow_get_graph.inputSchema` gains an
  optional `filter: {type: 'object', properties: {nodeIds: {type:
  'array', items: {type: 'string'}}, edgeIds: {type: 'array', items:
  {type: 'string'}}}, additionalProperties: false}` property (matching
  this codebase's own `additionalProperties: false` MCP-input convention,
  `mcp/CLAUDE.md`'s own "Adding a new tool" step 1).
- The handler validates the supplied filter via Task 1's new
  `validateFilterShape` (a clear tool-error result on malformed input,
  never a thrown exception reaching the MCP transport), applies
  `_filterGraph` to `body.data` BEFORE `_redactGraph` (redaction narrows
  what's returned, never widens it — filtering first means the redaction
  pass only ever touches what's actually being returned, cheaper and
  correct either way since redaction is per-field, not order-sensitive
  with filtering, but filtering first is the more natural read order and
  matches `export-json.js`'s own `exportGraphJSON`'s existing
  filter-then-redact order).
- The tool's own description and `dataflow-tools.js`'s header comment are
  updated to disclose the REAL, honest scope of this fix: an agent that
  supplies a `filter` gets a scoped, smaller response; an agent that
  omits it still gets the WHOLE graph inline, with the same
  `stdio.js` 4MB-line-cap risk as before — this task does not add a hard
  size cap or a forced fallback offload, which remains real, disclosed,
  deferred scope for a future increment if it's ever needed.

## Global constraints for the implementation plan

- Every existing `server/http-server.js` security property (Host check,
  token check, size cap, CSP/no-store headers, generic 500 body) applies
  unchanged to the new route — re-verified by the task's own tests, never
  bypassed or reordered.
- `validateFilterShape` must reject exactly what the CLI's own inline
  logic already rejects today (non-object, array, non-array `nodeIds`/
  `edgeIds`) — a behavior change here would silently change the CLI's own
  `--filter` validation too, since Task 1 makes the CLI call the extracted
  function instead of its own inline copy.
- No change to `_filterGraph` itself — reused exactly as it already is.
- No frontend/UI work — wiring `frontend/src/lib/api-client.js` to use
  the new query endpoint for a genuinely large graph is real, disclosed,
  deferred follow-up, matching every prior M4 decision-intelligence
  capability's own backend-first precedent.
- No new npm dependency (`scanner/src/server/CLAUDE.md`'s own standing
  convention).
- Every security-relevant string/token comparison in this file already
  goes through `constantTimeEqual` — this task does not add any new
  comparison of that kind (a query filter is not a secret), so no new
  timing-sensitive code is introduced.

## Out of scope

- A hard size cap / forced fallback offload for an unfiltered
  `dataflow_get_graph`/`GET /api/v1/graph` call on a genuinely huge
  graph — real, disclosed, deferred future work if it's ever needed.
- Wiring `frontend/` to use the new query endpoint.
- A stress-test pass for Privacy/Trace/Inventory's HTML-table views at
  large scale (the M5 top-level doc's own item (b) for this deliverable)
  — a separate, smaller investigation, not bundled into this 2-task plan;
  tracked as a follow-up, not attempted here.
- True semantic zoom (already confirmed blocked on a backend
  node-identity redesign by the M3-Render/SemanticZoom sub-project).
- A richer query language (traversal-shaped queries via
  `frontend/src/lib/focus-controls.js`'s own `showUpstream`/
  `showDownstream`/etc.) — the `{nodeIds, edgeIds}` direct-membership
  filter is the one real, already-proven primitive this sub-project
  reuses; a traversal-shaped query endpoint is a separate, larger design
  decision for a future increment.
