# Milestone 3, sub-project Server, increment 1: read-only GET endpoints + full security posture

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-server-scoping.md`.
Implements the `explore` CLI command, a `node:http`-based loopback server,
the five P0 read-only GET endpoints, and the FULL §17.4 security
checklist as first-class requirements of this one increment.

## What already exists (confirmed by direct read, this session, HEAD `c0a0245a`)

- `scanner/src/posture/integrity.js` exports `signLastScan(body)` →
  hex HMAC-SHA256 string, and `verifyLastScan(body, sigFile)` → `true`/
  `false`/`null` (absent), using `crypto.timingSafeEqual` internally
  already — call this DIRECTLY to verify `lineage-graph.json`, never
  hand-roll a second comparison mechanism. `null` (sig file absent) and
  `false` (mismatch) both mean "refuse to serve," but should produce
  DIFFERENT error messages (missing vs. tampered) — `explore` should
  tell the operator which happened.
- `scanner/src/posture/state-dir.js`'s `stateDir(scanRoot)`/
  `statePath(scanRoot, ...parts)` — use these to locate
  `.agentic-security/lineage-graph.json`/`.sig`, never hand-construct
  the path with `path.join('.agentic-security', ...)` directly.
- `bin/agentic-security.js`'s command dispatch (`~line 3002-3070` —
  re-verify current line numbers) — every `cmdX(args)` function returns
  a numeric exit code; `case 'mcp':` is the nearest structural precedent
  for a subcommand that starts a long-running process rather than a
  one-shot scan-and-exit.
- **No `node:http` usage anywhere in `scanner/src/` yet** — this is a
  genuinely first use of Node's built-in HTTP server in this codebase;
  read Node's own `node:http` docs' `createServer`/`IncomingMessage`/
  `ServerResponse` shapes directly if unfamiliar with the exact API
  surface, don't guess method signatures.

## Scope for this increment

1. **`scanner/src/server/graph-loader.js`**:
   ```js
   export function loadSignedGraph(scanRoot) {
     const graphPath = statePath(scanRoot, 'lineage-graph.json');
     const sigPath = graphPath + '.sig';
     if (!fs.existsSync(graphPath)) {
       return { ok: false, reason: 'missing', message: 'No lineage graph found. Run a scan first with AGENTIC_SECURITY_LINEAGE_DEEP=1.' };
     }
     const body = fs.readFileSync(graphPath, 'utf8');
     const verified = verifyLastScan(body, sigPath);
     if (verified === null) return { ok: false, reason: 'unsigned', message: '...' };
     if (verified === false) return { ok: false, reason: 'tampered', message: '...' };
     let graph;
     try { graph = JSON.parse(body); } catch { return { ok: false, reason: 'malformed', message: '...' }; }
     return { ok: true, graph };
   }
   ```
   (Sketch — the implementer fills in real message text and confirms
   `statePath`'s exact signature/behavior before relying on the call
   shape above.) Loaded ONCE at server startup, held in memory — never
   re-read per-request (this is a read-only, single-scan-snapshot
   server; a change to the underlying graph on disk mid-session is out
   of scope, matching §17.3's own "P0 is read-only" framing).
2. **`scanner/src/server/security.js`**:
   - `generateSessionToken()` — `crypto.randomBytes(32).toString('hex')`.
   - `constantTimeEqual(a, b)` — wraps `crypto.timingSafeEqual`, handling
     the length-mismatch case safely (², `timingSafeEqual` throws on
     unequal-length buffers — guard this, don't let it throw past a
     length check that itself leaks timing, mirror `verifyLastScan`'s
     own `stored.length !== expected.length` guard shape).
   - `isValidHost(hostHeader, expectedPort)` — accepts only
     `127.0.0.1:<port>`/`localhost:<port>`/`[::1]:<port>` (and bare
     `127.0.0.1`/`localhost`/`::1` when the port is implied), rejects
     everything else — this is the T2 DNS-rebinding defense.
   - `CSP_HEADER_VALUE` — a restrictive policy constant (e.g.
     `default-src 'none'; connect-src 'self'` — the implementer should
     confirm the exact directives needed once real response bodies are
     known to be JSON-only with no inline script/style requirement for
     THIS increment, since S1 serves no HTML at all — `explore` in S1
     is an API-only server, `frontend/`'s own static assets are Wire's
     job to serve, not S1's; confirm this scoping boundary before
     writing the CSP value, since an API-only server's correct CSP is
     simpler than one also serving the app shell).
3. **`scanner/src/server/routes.js`** — five pure handler functions,
   each `(graph, params) -> {status, body}` (never touching `req`/`res`
   directly, so they're testable without an HTTP layer):
   - `handleScan(graph)` → scan/graph metadata (schemaVersion, graphId,
     generatedAt, scope, scanHealth, coverage — NOT the full node/edge
     arrays).
   - `handleGraph(graph)` → the full graph document (S1 has no
     pagination/filtering — that's `query`'s own job, S2).
   - `handleNode(graph, id)` / `handleEdge(graph, id)` /
     `handleFlow(graph, id)` → look up by id in the respective array,
     404 with a clear body if not found.
   - Every response body wrapped in a shared envelope function
     (`wrapResponse(data, graph)`) adding the exact fields PRD line 1326
     names, verbatim: *"base graph/snapshot digest, schema/extension
     versions, scope, coverage, limitations, and contributing canonical
     IDs."* Map onto the graph's own real fields: digest = `graph.
     graphId`; schema/extension versions = `graph.schemaVersion` (+
     `graph.extensions`'s own versioning if any exists — check); scope =
     `graph.scope`; coverage = `graph.coverage`; limitations = `graph.
     limitations`; contributing canonical IDs = the specific id(s) the
     response is actually about (e.g. `handleNode`'s own node id) —
     `handleGraph`'s own "contributing canonical IDs" is a real, small
     design question (the whole graph IS the canonical ID set — decide
     whether this field is omitted, or lists something meaningful, at
     implementation time, and disclose the choice).
4. **`scanner/src/server/http-server.js`** — `createExploreServer({
   graph, port, sessionToken, idleTimeoutMs, keepOpen })`:
   - Binds to `127.0.0.1` explicitly (never `0.0.0.0`, never omit the
     host argument to `listen()` — omitting it is NOT the same as
     `127.0.0.1` on every platform).
   - Every request: validate `Host` header (`security.js`'s
     `isValidHost`) → 400 if invalid; validate the session token (a
     custom header, e.g. `X-Agentic-Security-Token`, or a query param —
     pick one and disclose the choice; compare with `constantTimeEqual`)
     → 401 if invalid/missing; enforce a request-size cap (reject
     bodies over a small threshold before parsing — S1's own GET-only
     endpoints have no request body to speak of, so this mostly matters
     for future S2 `POST` endpoints, but the cap-checking MIDDLEWARE
     should exist now, applied uniformly, so S2 doesn't have to
     retrofit it).
   - Every response: `Content-Security-Policy` header set;
     `Access-Control-Allow-Origin` NEVER set (CORS disabled by default
     — the absence of the header IS the disabling, don't accidentally
     add a permissive default); `Cache-Control: no-store`.
   - Idle-timeout: a `setTimeout` reset on every request, calling
     `server.close()` when it fires, UNLESS `keepOpen` is true. Pick a
     real default duration (no PRD-specified number — confirmed by
     direct search this scoping — 30 minutes is a reasonable, disclosed
     default; the implementer may pick a different reasoned value but
     must disclose it in a code comment, not silently invent one).
   - Logging: method/path/status/duration only, via `console.error`
     or a small internal logger — NEVER log response bodies, NEVER log
     the session token itself even on a failed-auth attempt.
5. **`bin/agentic-security.js`**: `case 'explore': process.exit(await
   cmdExplore(args));` plus a new `cmdExplore(args)` function — parses
   `args._[1]` (the scan root, defaulting to cwd, matching `cmdScan`'s
   own arg-parsing convention), `--port`, `--keep-open`; calls
   `loadSignedGraph`, exits with a clear error message and non-zero code
   if it fails; otherwise starts the server, prints the URL + session
   token to stdout (the ONLY place the token is ever displayed — never
   written to a file, never logged by the server itself after this one
   print).

## Do NOT touch

`frontend/` (not wired in this increment — S1 is a standalone,
independently-testable server; Wire is where the two connect).
`POST /api/v1/query`/`POST /api/v1/export` (explicitly deferred, per the
scoping doc's own Decision 3). `scanner/src/mcp/`, `scanner/src/lsp/`
(read-only structural precedent only).

## Test plan

1. `graph-loader.js`: missing file → `reason: 'missing'`; a real signed
   graph → `ok: true`; a tampered body (mutate one byte after signing,
   re-verify) → `reason: 'tampered'`; a missing `.sig` → `reason:
   'unsigned'`; malformed JSON in an otherwise-signed body → `reason:
   'malformed'`.
2. `security.js`: `constantTimeEqual` correctness (equal, unequal same-
   length, unequal different-length — must not throw); `isValidHost`
   accepts the loopback forms, rejects a spoofed/arbitrary `Host` header
   (the T2 regression guard — a real HTTP request through the running
   server with a forged `Host` header, not just a unit test of the
   pure function, since the THREAT is an actual cross-origin request).
3. `routes.js`: each of the five handlers against a small, real,
   committed test graph (NOT the 5,000-node perf fixture — this is
   correctness testing, not scale testing) — found/not-found cases,
   envelope fields present.
4. `http-server.js`, real end-to-end HTTP requests against a real
   started server (Node's own `http.request`, no test-only shortcut):
   valid token + valid Host → 200 with real data; missing/wrong token →
   401; forged Host → 400 (the T2 live regression guard); response
   headers include CSP, exclude `Access-Control-Allow-Origin`, include
   `Cache-Control: no-store`; a short-timeout variant proving idle-stop
   actually closes the server; `keepOpen: true` proving it doesn't.
5. `cmdExplore`: missing graph → clear error, non-zero exit, server
   never starts (proven by attempting a connection and confirming
   refusal, not just checking the exit code).
6. Full `npm test` (this increment touches `bin/agentic-security.js` and
   adds a new `src/server/` package — confirm no existing suite breaks,
   and add the new test files to the appropriate scoped `package.json`
   script, likely a new `test:server` entry mirroring `test:mcp`'s own
   pattern).

## Explicitly deferred

`POST /api/v1/query`/`POST /api/v1/export` (S2/M4). Wiring `frontend/`
to this server (M3-Wire). File/line evidence path resolution + its own
T4 confinement test (no such lookup exists in S1's five endpoints — the
graph JSON is served verbatim). `explore` triggering a scan itself.
Any language beyond what the graph already covers.
