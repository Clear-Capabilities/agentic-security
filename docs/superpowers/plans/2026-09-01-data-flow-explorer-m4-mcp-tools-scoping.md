# Milestone 4, sub-project MCP tools: expose `DataFlowGraph v1` read-only via MCP

Per the M4 top-level scoping doc's own sub-project table: *"MCP
read-only tools... Small–Medium. Follows the exact existing pattern
(`query_taint`/`explain_finding`): read-only, ID-scoped, already-hardened
MCP server. No new backend capability — just new tools reading the
already-built graph."* No dependency on any other M4 sub-project.

## What already exists (confirmed by direct read this session)

- **`scanner/src/server/graph-loader.js`**'s `loadSignedGraph(scanRoot)`
  — reads `.agentic-security/lineage-graph.json`, verifies its `.sig`
  sidecar via `posture/integrity.js`'s `verifyLastScan` (the SAME
  HMAC-integrity mechanism `last-scan.json` uses, reused directly, no new
  crypto). Returns `{ok:true, graph}` or `{ok:false, reason, message}`
  with exactly 4 distinct failure reasons (`missing`/`unsigned`/
  `tampered`/`malformed`). This is directly reusable by MCP tools with
  zero changes — it already does not care who its caller is (HTTP route
  handler today; an MCP tool handler is just another caller).
- **`scanner/src/server/routes.js`** already has the exact query shapes
  this sub-project needs, as plain, HTTP-framework-independent functions:
  `handleGraph(graph)` (whole graph, presumably paginated/summarized —
  confirm exact shape when implementing), `handleNode(graph, id)`,
  `handleEdge(graph, id)`, `handleFlow(graph, id)`, plus a shared
  `wrapResponse(data, graph, {canonicalIds})` envelope helper. **These
  are the real query logic already** — MCP tools do not need to
  reimplement graph lookups, only wrap these same functions in MCP tool
  request/response shape. This makes this sub-project smaller than the
  M4 top-level doc's own "Small–Medium" estimate suggested before this
  detail was confirmed.
- **`scanner/src/mcp/tools.js`**'s existing read-only tool shape
  (`query_taint`, `explain_finding`, `find_rule_module`, `lookup_cve`) —
  each: reads a local artifact (never the network, except `lookup_cve`'s
  disk-cached OSV/KEV/EPSS data), supports pagination/offset for large
  results, offloads oversized payloads to the scratchpad mechanism rather
  than returning them inline. New dataflow tools follow this exact shape.
- **`scanner/src/mcp/redact.js`** — secret redaction currently applied to
  finding fields (snippet/description/title/vuln/remediation/trace). The
  lineage graph's own node/edge/flow data does not carry raw source
  snippets (per this session's own earlier-confirmed finding that
  `node.location` is always `null` and detail is category-level, not
  code-level) — so redaction is likely a no-op for graph data, but this
  needs an explicit, disclosed confirmation during implementation, not an
  assumption. `graph.evidence[].location.note` (real per-claim file/line
  data, confirmed earlier this session) is the one field that plausibly
  needs the same redaction pass findings get, since it can carry
  human-written notes referencing real code.
- **`scanner/src/mcp/CLAUDE.md`**'s own hardening table (confinement,
  path-escape refusal, reserved-write paths, HMAC integrity, redaction) —
  every new tool this sub-project adds is READ-ONLY (no writes, no
  `RESERVED_WRITE_*` concerns), narrowing the hardening surface to just
  "verify the signed graph before serving any of it" (already solved by
  `loadSignedGraph`) and "redact evidence notes if warranted" (above).

## Decisions this scoping makes explicitly

1. **Reuse `graph-loader.js` and `routes.js`'s handler functions
   directly — do not fork or reimplement graph-query logic in
   `scanner/src/mcp/`.** A thin adapter module
   (`scanner/src/mcp/dataflow-tools.js`, new) imports both and exposes
   MCP-tool-shaped wrappers. This keeps exactly one graph-query
   implementation in the codebase (avoiding the "two near-identical
   copies" bug class this session already found and fixed once, in
   M3-UX-Filters' `rowMatchesFilters`).
2. **Four new MCP tools**, mirroring the four existing HTTP routes
   one-to-one (no invented shapes beyond what `routes.js` already
   defines):
   | Tool | Wraps | Notes |
   |---|---|---|
   | `dataflow_get_graph` | `handleGraph` | Whole-graph summary; must paginate/offload per the existing `query_taint` precedent — a real flagship-scale graph can be large. |
   | `dataflow_get_node` | `handleNode` | ID-scoped, single node. |
   | `dataflow_get_edge` | `handleEdge` | ID-scoped, single edge. |
   | `dataflow_get_flow` | `handleFlow` | ID-scoped, single flow. |
   A 5th tool, `dataflow_query`, is **explicitly deferred** (below) — it
   would wrap `lib/query-language.js`'s `compileQuery`, which lives in
   `frontend/`, a different package with no current dependency edge from
   `scanner/`. Wiring that in is real, disclosed, future work, not silently
   dropped.
3. **No `agentic-security explore` server dependency.** These tools call
   `loadSignedGraph` directly against `scanRoot` (same as `explore`
   does), independent of whether a server is running — an agent using
   `query_taint` today doesn't need `agentic-security scan` running in
   another process, and these tools shouldn't need `explore` running
   either. Confirmed real by reading `bin/agentic-security.js`'s
   `cmdExplore` — it is a thin CLI wrapper around `graph-loader.js` +
   `http-server.js`, not a required prerequisite process.
4. **Missing-graph failure is a real, first-class MCP tool response, not
   an error/exception** — `loadSignedGraph`'s own 4 reasons
   (`missing`/`unsigned`/`tampered`/`malformed`) map directly onto a
   structured MCP tool result (matching `query_taint`'s own precedent of
   returning a clear "no last-scan.json, run a scan first" result rather
   than throwing), each with its own actionable message (e.g. "run
   `AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan` first" for
   `missing`).
5. **Evidence-note redaction**: apply `redact.js`'s existing redaction
   function to `evidence[].location.note` fields specifically (the one
   field on the graph that can carry human-authored text referencing real
   code/paths) before returning `dataflow_get_graph`/`dataflow_get_flow`
   results that include evidence. Node/edge/flow structural fields
   (kind, subtype, verdicts, IDs) are never redacted — they are already
   category-level, not raw code.

## Scope for this increment

1. `scanner/src/mcp/dataflow-tools.js` (new) — the 4 tool handlers,
   each: calls `loadSignedGraph(scanRoot)`, handles all 4 failure
   reasons with a clear structured result, wraps the corresponding
   `routes.js` handler's return value in the MCP tool response shape,
   applies evidence-note redaction, and paginates/offloads per the
   `query_taint` precedent for `dataflow_get_graph`.
2. `scanner/src/mcp/tools.js` — register the 4 new tools (mirroring how
   the existing 17 are registered — read the exact registration
   mechanism when implementing, do not guess its shape).
3. `scanner/src/mcp/CLAUDE.md` — add the 4 new tools to the existing
   table (`## Tools exposed today`), update "17 tools, not 12" to "21
   tools, not 17" (re-derive the exact count via
   `grep -c "name: '" scanner/src/mcp/tools.js` when implementing —
   this doc's own note already warns against a hardcoded number going
   stale).
4. Tests: one per tool for the success path against a real signed test
   graph fixture, one per tool for each of the 4 `loadSignedGraph`
   failure reasons (12 failure-path tests total, or fewer if a shared
   parametrized test covers all 4 tools identically — real implementer
   judgment, since the failure-handling logic should be identical across
   all 4 tools if built as a shared wrapper).
5. **No audit-logging wiring needed** — confirmed by direct read of
   `scanner/src/mcp/server.js`: `auditCall` is invoked generically at the
   dispatch layer for EVERY tool call (`rejected`/`ok`/`error` outcomes),
   not per-tool inside `tools.js`. Registering the 4 new tools in the
   existing registration mechanism (scope item 2) gets audit logging for
   free — no separate wiring step, and no new file to touch here.

## Explicitly deferred

- `dataflow_query` (wrapping the query language) — needs a real decision
  about whether `scanner/` gains a dependency on `frontend/`'s
  `lib/query-language.js`, or whether the query grammar gets
  reimplemented/shared via a common package — a real architectural
  question, not a quick addition. Named here, not silently dropped.
- Any write capability (e.g. an MCP tool that could edit governance
  facts, once M4's Regulatory Overlay sub-project exists) — read-only
  only, per this sub-project's own name and the M4 top-level doc's own
  "MCP read-only tools" deliverable wording.
- Watch-mode / live graph updates (a different M4 sub-project,
  deliverable #9) — these tools read one static, already-scanned,
  already-signed graph snapshot per call, same as `explore` does today.

## Test plan

1. Real signed-graph fixture in `scanner/test/fixtures/` (reuse an
   existing lineage fixture if one is already signed for a test purpose;
   confirm before creating a new one).
2. Success-path test per tool against that fixture, asserting the
   returned shape matches `scanner/test/server/routes.test.js` (confirmed
   to exist this session) — keep the two surfaces' contracts visibly
   aligned rather than drifting.
3. Failure-path tests: `missing` (no graph file), `unsigned` (graph file,
   no `.sig`), `tampered` (mismatched signature), `malformed` (valid
   signature, invalid JSON body) — one assertion set per tool or one
   shared parametrized set, per the implementer's own judgment (decision
   4 above).
4. `npm run test:mcp` (`scanner/package.json`) is confirmed this session
   to be an explicit space-separated file list, not a glob — exactly the
   same gotcha `frontend/package.json`'s own `test` script has (found
   earlier this session). The new test file(s) MUST be added to that
   list explicitly or they silently get zero regression coverage in CI,
   same as the real `query-language.test.js` gap this session found and
   fixed in M3-UX-Query.
5. Full `scanner/npm test` green.
