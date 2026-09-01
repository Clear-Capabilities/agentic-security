# Milestone 3, sub-project Server scoping: local server + secured read-only API

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`
Decision 2. The entire "local server and secure API" deliverable is
greenfield — no HTTP/loopback server code exists anywhere in this repo
(confirmed by direct search: the MCP server is JSON-RPC-over-stdio, the
LSP server is a different stdio protocol, neither has an HTTP surface).
This document scopes the FIRST increment: read-only GET endpoints +
the full §17.4 security list, deferring the write-adjacent/complex
endpoints (`query`, `export`) to a later increment.

## What already exists (confirmed by direct read, this session, HEAD `f12ce43e`)

- **No CLI command launches anything server-shaped.** `bin/
  agentic-security.js`'s command dispatch (`~line 3002` — re-verify
  before trusting) has no `serve`/`explore`/`ui` case. The closest
  precedent is `case 'mcp':` (`~line 3065`), which launches the MCP
  stdio server — a useful STRUCTURAL precedent for "a new subcommand
  that starts a long-running process instead of a one-shot scan," not a
  code-reuse target (stdio JSON-RPC vs. HTTP are unrelated protocols).
- **The graph artifact already exists, signed.** `bin/
  agentic-security.js` (confirmed, `~line 1070-1072`) writes
  `.agentic-security/lineage-graph.json` + `.sig` using
  `signLastScan`/`verifyLastScan` from `scanner/src/posture/
  integrity.js` — the SAME generic HMAC signing mechanism
  `last-scan.json` uses (confirmed generic: an arbitrary string body,
  no filename baked in). This is written only when
  `AGENTIC_SECURITY_LINEAGE_DEEP=1` was set for that scan AND a graph
  was actually built. **The server's own first responsibility is
  reading and VERIFYING this artifact before ever serving it** — a
  server that serves an unsigned or tampered graph file defeats the
  entire point of `last-scan.json`'s own integrity model, applied here
  for the first time to a server context rather than a CLI read.
- **`posture/state-dir.js`'s `stateDir`/`statePath`** (already used by
  Sub-project G1's own `loadPrivacySinkPolicy` this session) is the
  established mechanism for locating `.agentic-security/` given a scan
  root — reuse it, never hand-construct the path.
- **No web-framework dependency exists in `scanner/package.json`**
  (confirmed: no `express`/`fastify`/`koa`/`hapi`). Per this repo's own
  minimalism convention (`validate.js`'s own header: "no new npm
  dependency" is a real, followed principle here, not just stated once)
  and the dependency-currency gate's own scrutiny of every new
  dependency, this sub-project uses **Node's built-in `node:http`
  module**, never a new framework dependency — everything §17.4 requires
  (Host-header validation, CSP headers, CORS-disabled-by-default,
  session tokens, request-size caps) is directly implementable over
  `node:http` with no framework needed, and the MCP/LSP servers already
  establish the precedent of hand-rolled protocol handling in this
  codebase rather than reaching for a dependency.
- **`docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`** (read in full this
  session) is the binding security spec for this sub-project — T2
  (DNS rebinding), T3 (CSRF), T4 (path traversal), and the server-side
  half of T5 (request-size/query-complexity caps) are ALL explicitly
  named "Milestone 3 (server does not exist yet)." This document's own
  test-shape requirements (nothing prescriptive beyond T1's own XSS
  fixture, which is a DIFFERENT sub-project, M3-XSS) are the ones this
  increment must close for T2/T3/T4.

## Decisions this scoping makes explicitly

**Decision 1 — the CLI command is named `explore`.** Not specified
anywhere in the PRD (confirmed by search: `--keep-open` is named as a
flag, no command name is given). `agentic-security explore [path]
[--port <n>] [--keep-open]` — chosen over `serve` (too generic/confusable
with a future non-graph server) and over reusing `scan`'s own flag space
(this is a genuinely different, long-running-process command, matching
`mcp`'s own precedent of a distinct subcommand for a distinct process
mode). A judgment call, disclosed as one — revisit if the user has a
naming preference.

**Decision 2 — this increment requires a pre-existing, already-scanned
graph artifact; it does NOT trigger a scan itself.** `explore` reads
`.agentic-security/lineage-graph.json` + `.sig` from the given (or
current) directory, verifies the signature, and refuses to start if
missing/invalid/tampered, with a clear error directing the user to run
`agentic-security scan` with `AGENTIC_SECURITY_LINEAGE_DEEP=1` first (or,
if ergonomics matter enough, `explore` could shell out to that scan
itself as a later increment's own convenience feature — NOT decided
here, deliberately kept out of S1's scope to keep the first increment's
own surface small and testable). This also keeps `explore` genuinely
read-only end to end, matching §17.3's own "P0 is read-only with respect
to source and project policy" — no scan-triggering write path in this
increment at all.

**Decision 3 — S1 ships the five GET endpoints only
(`scan`/`graph`/`nodes/:id`/`edges/:id`/`flows/:id`); `POST /api/v1/
query` and `POST /api/v1/export` are a later increment (S2).** `query`'s
own contract ("a deterministic typed projection... no arbitrary code")
is real design work of its own — what filter/projection language, how it
maps onto the already-shipped `flow-path.js`-style helpers in
`frontend/`, whether it reuses any `path-query.js`-style budget/
truncation semantics from the engine — and `export`'s own contract
(§17.5) is explicitly Milestone 4 territory per the parent M3 scoping
doc's own Decision 4/§4. Mirrors this session's own established
"plumbing first, complexity later" pattern (e.g. Sub-project B1 before
B2 in Milestone 2) — S1 proves the server, its security posture, and its
five simplest endpoints; S2 (or a future M4 sub-project for `export`)
builds the harder ones on top of a working, hardened base.

**Decision 4 — every §17.4 security bullet is a first-class S1
requirement, never a follow-up hardening pass**, per the parent scoping
doc's own Decision 2: T2/T3/T4 are explicitly gated on "the server does
not exist yet" in the threat model doc, meaning THIS increment is what
creates those threat surfaces. The full checklist (bind
`127.0.0.1`/`::1` only; random port unless `--port` given; random
session token required on every request; `Host` header validated;
restrictive CSP; CORS disabled by default; same-site cookie or request
token — moot for S1 since it ships no state-changing endpoint, but the
session-token requirement on EVERY request, read or write, satisfies
this for now; never serve arbitrary repository paths; confine evidence
lookups to the scanned root — no such lookup exists in S1's own five
endpoints, since they serve the graph JSON directly, not raw file
content, so this is a real, disclosed non-issue for S1 specifically,
revisit when a future increment adds file/line evidence resolution;
request-size caps; never cache sensitive evidence — set
`Cache-Control: no-store` on every response; idle-timeout auto-stop
unless `--keep-open`; metadata-only logging — log method/path/status/
duration, never response bodies; outbound calls — none, this server
makes none) is this increment's own acceptance checklist, one test per
bullet where a bullet is genuinely testable in isolation.

## Scope for this increment (S1)

1. **New `scanner/src/server/` package** (mirroring `scanner/src/mcp/`'s
   own directory-per-subsystem convention): `http-server.js` (the
   `node:http` server itself — routing, security headers, session-token
   check), `routes.js` (the five GET endpoint handlers, each a pure
   function of `(graph, params) -> {status, body}` so they're unit-
   testable without spinning up a real server), `security.js` (Host-
   header validation, CSP header value, session-token generation/
   comparison — a real constant-time comparison, never `===` on a
   secret, matching this codebase's own established HMAC-comparison
   discipline elsewhere in `posture/integrity.js`), `graph-loader.js`
   (reads + verifies `lineage-graph.json`/`.sig` via `verifyLastScan`,
   refuses to proceed on failure).
2. **CLI wiring**: `bin/agentic-security.js` gains `case 'explore':` and
   a new `cmdExplore(args)` function, following the existing command
   functions' own shape (parse args, call into the real logic, return an
   exit code) — never inline the server logic in `bin/`, the same
   separation `cmdScan`/`runFullScan` already establish.
3. **Idle-timeout auto-stop**: a timer reset on every real request,
   calling `server.close()` past the timeout — default value needs a
   real decision at plan-writing time (the PRD names the REQUIREMENT,
   not a specific duration; check §17 once more for any number before
   inventing one, and if genuinely none is given, pick a reasoned
   default and disclose it as a judgment call, e.g. 30 minutes).
4. **Response envelope**: every response includes the base graph/
   snapshot digest, schema/extension versions, and scope (§17.3's own
   "every response must include..." requirement) — a small shared
   wrapper function, not repeated per-endpoint.

## Do NOT touch

`frontend/` (Wire's own job — this increment builds and tests the server
in isolation, never wires the existing views to it). `POST /api/v1/
query`, `POST /api/v1/export` (Decision 3 — S2/future). Any Milestone
4/5 decision-intelligence endpoint (`stories/`, `scenarios/`, etc. —
named out of scope by the parent M3 scoping doc already). The T1 XSS
adversarial-fixture suite (M3-XSS's own territory — a frontend-rendering
concern, not this server's). `scanner/src/mcp/`, `scanner/src/lsp/` (read
only, as structural precedent — never modified).

## Test plan (sketch — a real plan document should make this concrete before implementation)

Per-bullet security tests (§17.4 checklist, one test each where
isolatable): binds only to loopback (attempt a non-loopback bind,
confirm refusal or that the OS-level bind itself only succeeds
loopback-side); a request with a forged `Host` header is rejected;
a request missing/with a wrong session token is rejected on every one of
the five endpoints; response headers include the CSP value and no
`Access-Control-Allow-Origin`; response headers include `Cache-Control:
no-store`; a request exceeding the size cap is rejected before being
parsed. Per-endpoint tests: each of the five GET endpoints against a
real (small, committed) graph fixture, correct shape, correct 404 for an
unknown id, the required envelope fields present. The idle-timeout: a
real, short-timeout test (not the real default) proving the server
actually stops. `--keep-open`: proving it suppresses the stop.

## Explicitly deferred

`POST /api/v1/query`/`POST /api/v1/export` (S2/M4). Any state-changing
endpoint (`rescan`, remediation writes — none exist in P0's own read-only
scope per §17.3's own text, reconfirmed here). File/line evidence
resolution and its own path-traversal confinement (T4's own concrete
test needs a real resolver to exist first — S1 serves the graph JSON
verbatim, which already has no file-path-resolution surface, so T4 stays
correctly "no surface today" for S1 specifically, same honest status the
threat model doc itself currently records, not yet closed by code).
`explore` triggering a scan itself (Decision 2). Any language beyond
what the graph itself already covers (JS/TS, unchanged — this server
serves whatever graph exists, language-agnostic itself).
