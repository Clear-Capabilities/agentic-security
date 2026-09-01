# Milestone 3, sub-project Wire scoping: live-API wiring for the existing three views

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-scoping.md`'s
own Wire row. Replaces `frontend/`'s static-generated-module import with
real, live consumption of the `explore` server built in Sub-project
Server, increment 1.

## The load-bearing correction (found before writing an implementation plan)

**§17.4's own "CORS disabled by default" requirement means the frontend
CANNOT be served separately from the API and still work.** Confirmed:
`http-server.js` never sets `Access-Control-Allow-Origin` anywhere (by
design — the header's absence IS the CORS-disabling mechanism). A
browser enforces same-origin policy on `fetch()` calls with no explicit
exception: a page served from `http://localhost:8420` (`frontend/`'s own
existing `python3 -m http.server` dev harness) attempting `fetch()`
against `http://127.0.0.1:<explore-port>/api/v1/graph` would have its
response BLOCKED by the browser's own CORS enforcement, regardless of
what the server itself returns — the request might even reach the
server and get a real 200, but the browser's JS never sees the body.

**This means `explore` must serve `frontend/`'s own static assets from
the SAME origin (same server, same port) as the `/api/v1/*` routes.**
This is not a Wire-invented requirement — it is what makes §17.4's own
CORS-disabled-by-default posture actually coherent: "disabled by
default" doesn't mean "nobody can ever read this data," it means "only
same-origin requests — i.e., the app THIS SAME SERVER serves — can read
it," which is exactly the right security posture for a local tool. The
PRD's own §17.1 diagram ("Loopback read-only API → Interactive web
application") is consistent with this reading; it just doesn't spell out
same-origin explicitly, and this document is where that gap is closed
before implementation, not discovered mid-build.

**Consequence for S1's own "JSON-only, `default-src 'none'`" scoping
decision**: that CSP was correct for S1's own scope (an API-only server
serving no HTML) but must be EXTENDED, not replaced, once static-asset
serving is added — a route serving `frontend/`'s own HTML/JS/CSS needs a
CSP permitting its own same-origin script/style/connect sources, while
the `/api/v1/*` JSON routes keep their existing maximally-restrictive
policy. Two different response shapes, two different CSP values, decided
per-route, not one global policy loosened for everything.

## What already exists (confirmed by direct read, this session)

- `frontend/index.html`'s current data path: a hardcoded static ES
  module import (`import { FLAGSHIP_GRAPH } from
  './src/data/flagship-graph.js'`) — the ONLY place this needs to change
  is this one file's own bootstrap call, replacing the static import
  with a `fetch('/api/v1/graph', {headers: {...}})` call. `bootstrap()`
  itself (`frontend/src/app.js`) already takes a plain graph object as
  its second argument — it has NO knowledge of where that object came
  from, confirmed by reading its own signature — so the three existing
  views' own rendering code needs ZERO changes for this sub-project.
- `scanner/src/server/routes.js`'s `handleGraph`'s response envelope
  wraps the real graph under a `.data` key (confirmed:
  `wrapResponse(graph, graph, {...})` → `{digest, schemaVersion,
  extensions, scope, coverage, limitations, canonicalIds, data: graph}`)
  — the frontend's own fetch call must unwrap `.data`, not assume the
  response body IS the graph directly.
- `scanner/src/server/http-server.js`'s `TOKEN_HEADER` constant
  (`x-agentic-security-token`) is the exact header name the frontend's
  own `fetch()` calls must set.
- `scanner/src/server/security.js`'s `isValidHost` accepts requests only
  with a `Host` header matching the loopback address + the EXACT bound
  port — a static asset served from this same server will naturally
  carry the correct `Host` header on its own subsequent `fetch()` calls
  (same origin the page itself was loaded from), so this needs no new
  logic, just confirmation it isn't accidentally broken by adding static
  routes.

## Decisions this scoping makes explicitly

**Decision 1 — the session token reaches the browser via the URL
fragment (`#token=...`), never a query string, never a cookie in this
increment.** A URL fragment is never sent to the server in any HTTP
request (confirmed browser behavior, not a new claim) — so the initial
page-load request itself carries no token in the URL an access log could
capture, yet the fragment IS readable by the page's own JS via
`location.hash`, letting the frontend extract the token once on load and
attach it as the `X-Agentic-Security-Token` header on every subsequent
`fetch()` call. `cmdExplore`'s own printed URL (currently `http://
127.0.0.1:<port>/api/v1/scan`) changes to point at the new static-asset
route instead, with the token appended as a fragment (e.g. `http://
127.0.0.1:<port>/#token=<64-hex-chars>`) — the ONE URL an operator needs
to open in a browser to get a working, authenticated session with no
manual header-pasting.

**Decision 2 — `explore` serves `frontend/`'s static assets directly
from disk, at server-startup time, via a new small static-file route in
the SAME `http-server.js`** (not a separate server process, not a
build/bundling step — `frontend/`'s own zero-build-step nature is
exactly what makes "serve these files as-is" trivial: no compilation,
no bundling, just reading files off disk and setting the right
Content-Type per extension). A minimal, hand-rolled static file server
(matching this package's own "no new dependency" convention, and
`node:http`'s own precedent from S1) — NOT a general-purpose static
file server library. Confine served paths to `frontend/`'s own directory
tree ONLY (a real, disclosed path-traversal surface THIS increment
creates that S1 never had — S1's own routes never touched the
filesystem beyond the one already-loaded, already-verified graph; static
serving reads arbitrary requested paths off disk for the first time in
this server, so path-traversal defense is now genuinely load-bearing,
not the honestly-empty "no surface yet" status the threat model doc
recorded for S1).

**Decision 3 — the frontend's own token-extraction/attachment code lives
in a small new module (`frontend/src/lib/api-client.js`), not scattered
across `app.js`/each view.** A single `fetchGraph()` function (or
similarly named) that reads the token from `location.hash` once,
performs the `fetch('/api/v1/graph', {headers: {...}})` call, unwraps
`.data`, and hands the plain graph object to the EXISTING, UNCHANGED
`bootstrap()` — this is the entire integration surface; every view's own
rendering code stays untouched, confirming Decision 4/§4's own claim
below.

**Decision 4 — AC-16's "same fixture graph renders identically across
lanes" property gets a real, direct proof: fetch the SAME flagship graph
via the new live path and assert byte-for-byte equal rendering output
against the existing static-import baseline**, before trusting that
AC-16/17/18/19's already-passing test status still holds against the new
data path. This is the plan's own primary test, not an afterthought —
Wire's whole point is proving the swap is safe, and "the existing tests
still pass" alone would not prove that if a subtly different code path
(e.g. an async fetch timing issue) happened to produce the same DOM by
coincidence on the small flagship fixture specifically.

**Decision 5 — this increment does NOT change `explore`'s printed
message shape beyond the URL**, and does NOT add a `--frontend-dir`
override flag or similar configurability — the static path is
hardcoded to the real, shipped `frontend/` directory, located via
`path.dirname(fileURLToPath(import.meta.url))` — confirmed as a real,
existing precedent in `scanner/src/mcp/server.js` (two call sites) for
locating a file relative to its own module, not a new convention. A
future increment can add real configurability if a genuine need arises;
not decided or attempted here.

## What this does NOT do

Change the graph FETCH mechanism into something more complex than one
`fetch()` call (no polling, no websocket, no incremental loading — S1's
own single-snapshot, read-only design is unchanged, Wire only changes
WHERE the frontend gets that one snapshot from). Add the Inventory view
(a separate sub-project, sequenced after Wire per the parent scoping
doc). Add `query`/`export` support to the frontend (those endpoints
don't exist yet — S2/M4). Change `frontend/`'s own view-rendering code in
any way (Decision 3's own claim — if implementation reveals this isn't
fully true, that is itself a real finding to disclose, not silently
absorbed). Solve M3-Render's own large-graph rendering problem (Wire
operates at the current flagship-fixture scale, 14 nodes — unaffected by
that finding, per the Perf result doc's own explicit disclaimer).

## Recommended next step

Write Wire's implementation plan, covering: the new static-file route in
`http-server.js` (with its own path-traversal test, since this is
genuinely new attack surface); the CSP-per-route-shape decision (JSON
routes keep `default-src 'none'`, the static/HTML route gets a
same-origin-permitting policy); `cmdExplore`'s updated printed URL
(fragment-token form); the new `frontend/src/lib/api-client.js`; and the
AC-16 byte-for-byte-equivalence proof named in Decision 4.
