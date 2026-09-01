# Milestone 3, sub-project Wire: live-API wiring for the existing three views

Per `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-wire-scoping.md`.
Adds same-origin static-asset serving to the `explore` server (a genuinely
new, security-relevant surface — path confinement is load-bearing here,
not decorative) and a small frontend-side fetch client, with zero changes
to any existing view's own rendering code.

## What already exists (confirmed by direct read, this session, HEAD `cf8f6b72`)

- `frontend/index.html`'s current data path (the ONE line this plan
  changes in that file): `import { FLAGSHIP_GRAPH } from
  './src/data/flagship-graph.js'; bootstrap(root, FLAGSHIP_GRAPH);`.
  `bootstrap(rootEl, graph)` (`frontend/src/app.js`) takes a plain graph
  object, confirmed no assumption about its origin.
- `frontend/`'s real, servable file inventory (confirmed via direct
  listing — re-verify before trusting if the tree has grown):
  `index.html`; `src/**/*.js` (app.js, shell.js, data/flagship-graph.js,
  lib/*.js, views/*.js, components/*.js); `styles/*.css`. **`test/`,
  `scripts/`, `package.json`, `README.md`, `CLAUDE.md`, `.gitignore` must
  NEVER be servable** — this is a real, deliberate ALLOWLIST decision,
  not merely a `../`-traversal guard; a naive "confine to inside
  frontend/" check would still happily serve `frontend/README.md` or
  `frontend/test/dom-shim.js` over the network, which is real,
  unnecessary information disclosure even though neither file is secret.
- `scanner/src/server/http-server.js`'s `ROUTES` array (confirmed,
  current file) is a flat list of `{method, pattern, handler}` — adding
  static-asset serving means either a new route pattern per servable
  path prefix, or (cleaner) one catch-all `GET /` + `GET /(index.html|
  src/.../..|styles/...)` route whose handler resolves against the
  allowlist below. Re-verify the exact current `ROUTES` shape before
  writing code — S1 shipped it, but confirm no drift.
- `scanner/src/server/security.js`'s `CSP_HEADER_VALUE` (currently
  `"default-src 'none'; frame-ancestors 'none'"`) is correct ONLY for
  the JSON API routes — the static-asset routes need their OWN, separate
  CSP value permitting same-origin script/style/connect (the frontend's
  own JS needs to load its own modules and fetch its own API), still
  denying everything cross-origin (no remote scripts/fonts/analytics,
  matching `frontend/README.md`'s own "no CDN scripts, remote fonts,
  analytics" rule and §17.2's own explicit prohibition).
- `scanner/src/mcp/server.js` (two call sites) is the real, existing
  precedent for `path.dirname(fileURLToPath(import.meta.url))` — use
  this pattern to locate `frontend/` relative to `http-server.js`'s own
  file location (`../../../frontend` from `scanner/src/server/`, but
  RE-VERIFY the exact relative path by computing it, don't guess the dot
  count).
- `bin/agentic-security.js`'s `cmdExplore` currently prints `URL:
  http://127.0.0.1:${actualPort}/api/v1/scan` — this plan changes that
  line to point at `/` with the token fragment appended.

## Scope for this increment

1. **`scanner/src/server/static-assets.js`** (new file, mirroring
   `graph-loader.js`/`security.js`'s own one-concern-per-file
   convention):
   - `FRONTEND_ROOT` — resolved once via `path.dirname(fileURLToPath(
     import.meta.url))` + a relative path to the real `frontend/`
     directory.
   - `ALLOWLIST` — an explicit, small, enumerated set of servable
     relative paths (NOT a glob, NOT "anything under src/" without
     enumeration if that risks including a future non-JS file
     accidentally — implementer's judgment on glob-vs-enumerate, but
     the DEFAULT must be deny: an unrecognized extension or an
     unlisted top-level directory (`test/`, `scripts/`, anything else)
     is refused, never served, even if it resolves to a real file
     inside `frontend/`).
   - `resolveStaticAsset(requestPath)` — a PURE function (no
     `fs`/`http` access, unit-testable in isolation): takes a URL
     pathname, returns `{ok: true, relativePath, contentType} |
     {ok: false, reason}`. MUST reject: any path containing `..`
     (even after normalization — normalize FIRST via `path.normalize`,
     then re-check for a leading `..` or an escape past `FRONTEND_ROOT`,
     never trust normalization alone to be sufficient — a classic
     traversal-bypass class); any path resolving outside the allowlist;
     null-byte injection (`path` containing `\0` — reject outright,
     Node's own `fs` calls would throw on this but reject earlier and
     explicitly); an absolute path in the request (`req.url` starting
     with `//` or containing a scheme). `/` itself maps to
     `index.html`.
   - `CONTENT_TYPE_MAP` — `.html` → `text/html; charset=utf-8`, `.js` →
     `text/javascript; charset=utf-8`, `.css` → `text/css; charset=utf-8`
     (no other extensions needed per the real file inventory above — if
     a future frontend file needs a new type, that's a real, disclosed
     addition, not silently guessed at).
   - `STATIC_CSP_HEADER_VALUE` — same-origin permitting: e.g.
     `default-src 'self'; script-src 'self'; style-src 'self';
     connect-src 'self'; frame-ancestors 'none'; base-uri 'none'`.
     **Correction found this session, before implementation**:
     `frontend/index.html` currently has an INLINE `<script
     type="module">` block (the very bootstrap logic item 5 below
     already needs to change) — a strict `script-src 'self'` CSP would
     block it, needing `'unsafe-inline'` or a nonce/hash. **Do not add
     `'unsafe-inline'`** — instead, move the bootstrap logic out of
     `index.html`'s inline block into a new external module (e.g.
     `frontend/src/main.js`, loaded via `<script type="module"
     src="./src/main.js"></script>`), which `script-src 'self'` permits
     with no exception needed. This is a one-time, small refactor
     (moving a handful of lines this plan's own item 5 already touches
     into their own file) — grep the rest of `frontend/`'s files for any
     OTHER inline `<script>`/`style="..."` attribute before finalizing
     the CSP value; none were found in this session's own check, but
     re-verify at implementation time, don't trust this citation without
     re-running the grep yourself.
2. **`scanner/src/server/http-server.js`** (extended, additively):
   - New route(s) for `GET /` and `GET /<allowlisted-path>`, calling
     `resolveStaticAsset`, reading the file via `fs.readFileSync`
     (synchronous is fine here — small, local, already-open-sourced-on-
     disk files, matching this server's own existing synchronous
     `graph-loader.js` precedent), and responding with the STATIC CSP
     (not the JSON one) + the resolved Content-Type + `Cache-Control:
     no-store` (unchanged — still never cache, even static assets, per
     §17.4's own blanket rule) + **no session-token requirement on
     these specific routes** (a real, disclosed design decision — the
     token lives in the URL FRAGMENT the browser never sends to the
     server at all, so the initial page-load request CANNOT carry it;
     the page's own subsequent `/api/v1/*` fetches still require it,
     unchanged from S1). This is the ONE place in this server where an
     unauthenticated request is intentionally allowed to succeed —
     name this explicitly in a code comment, since it is a deliberate
     exception to S1's own "every request" language, not an oversight.
     Static routes still go through the EXISTING `Host`-header
     validation (T2) — that check is not token-specific, it defends
     against DNS rebinding regardless of auth, and must still apply
     here.
   - A 404 (never a 403, to avoid confirming a path's existence to a
     prober) for any `resolveStaticAsset` rejection.
3. **`bin/agentic-security.js`**: `cmdExplore`'s printed URL changes
   from `http://127.0.0.1:${actualPort}/api/v1/scan` to
   `http://127.0.0.1:${actualPort}/#token=${sessionToken}` — still the
   ONE place the token is ever displayed. Update the surrounding print
   lines' own wording to describe "open this URL in a browser" rather
   than "pass the token as a header" (that instruction still applies,
   but now automatically, via the frontend's own code, not manually).
4. **`frontend/src/lib/api-client.js`** (new): a small module,
   `extractTokenFromFragment()` (parses `location.hash`, e.g.
   `#token=<hex>` → the token string, or `null` if absent/malformed —
   pure, testable via the same dependency-free shim pattern
   `test/dom-shim.js` already establishes, or a plain string-parsing
   unit test if no DOM is actually needed for this specific function)
   and `fetchGraph({token})` (calls `fetch('/api/v1/graph', {headers:
   {'x-agentic-security-token': token}}))`, unwraps `.data`, throws or
   returns an error-shaped result on a non-200 — implementer's choice,
   consistent with this file's own established error-handling style;
   check `frontend/CLAUDE.md`'s own conventions before picking a new
   one).
5. **`frontend/src/main.js`** (new — see item 2's own CSP correction
   above) + **`frontend/index.html`**: move the current inline
   `<script type="module">` block's logic into the new external
   `main.js`, replacing the static import + `bootstrap` call with:
   extract the token via `api-client.js`, call `fetchGraph`, and call
   `bootstrap(root, graph)` with the FETCHED graph — handle the fetch
   failure case visibly (a plain error message in `#app-root`, never a
   silent blank page) rather than leaving this unhandled. `index.html`
   itself shrinks to a single `<script type="module"
   src="./src/main.js"></script>` tag.

## Do NOT touch

Any existing view's own rendering code (`architecture-view.js`,
`privacy-view.js`, `trace-view.js`, `shell.js`, `app.js`'s own
`bootstrap` internals) — Decision 3 of the scoping doc's own claim; if
implementation reveals a real need to touch one of these, STOP and
disclose why before proceeding, don't silently expand scope.
`frontend/src/data/flagship-graph.js`/`scripts/generate-fixture-
module.mjs` (still used by `test/fixture-module-parity.test.js` — kept
as-is, this increment doesn't remove the static fixture, only stops
`index.html` importing it directly). `scanner/src/server/graph-loader.js`/
`routes.js` (unchanged — the `/api/v1/*` routes and their token
requirement are exactly as S1 shipped them). Inventory, XSS, A11y,
Golden (separate, later sub-projects).

## Test plan

1. `static-assets.js`: `resolveStaticAsset` unit tests — every real
   allowlisted path resolves correctly with the right content type;
   `/` maps to `index.html`; a `../`-containing path is rejected
   (several encodings: `../`, `..%2f`, a path that normalizes to
   escape even after `path.normalize`); a null-byte path is rejected;
   an unlisted extension/directory (`/test/dom-shim.js`,
   `/package.json`, `/scripts/generate-fixture-module.mjs`,
   `/CLAUDE.md`) is rejected even though the file genuinely exists on
   disk — THIS is the real proof the allowlist is doing real work, not
   merely a traversal guard.
2. `http-server.js`, real live requests (mirroring S1's own precedent —
   never a mocked layer for this file): `GET /` with NO token header at
   all succeeds (the deliberate unauthenticated-static-route exception);
   the served `index.html`'s own body is asserted to contain the real
   expected markup; a forged `Host` header is STILL rejected on a
   static route (T2 applies uniformly); a path-traversal attempt via a
   real HTTP request (`GET /../package.json` or its URL-encoded form)
   is rejected with 404, proven live, not just via the pure-function
   unit test above; response headers on a static route carry the
   SEPARATE static CSP value, not the JSON API's `default-src 'none'`.
3. `frontend/src/lib/api-client.js`: `extractTokenFromFragment` against
   a real `#token=...` hash, a missing hash, a malformed hash;
   `fetchGraph` against a mocked/real fetch (implementer's choice,
   matching this test suite's own established conventions) for the
   success and failure paths.
4. **The AC-16 byte-for-byte equivalence proof** (the scoping doc's own
   Decision 4, the single most important test in this increment): start
   a real `explore` server over the real flagship graph, load
   `index.html` through it (or drive the SAME rendering call directly
   with the live-fetched graph), and assert the resulting DOM is
   byte-for-byte identical to `bootstrap(root, FLAGSHIP_GRAPH)`'s own
   existing, already-tested output on the static import — proving the
   swap changed WHERE the data came from and nothing about WHAT gets
   rendered.
5. Full `npm run test:server` (frontend/scanner's own test), full
   `frontend/`'s own `npm test`, and the scanner's full `npm test` gate,
   green, real captured exit codes.

## Explicitly deferred

Inventory, XSS, A11y, Golden (separate sub-projects, per the parent M3
scoping doc's own dependency order). `query`/`export` frontend
integration (those endpoints don't exist yet). Any configurability of
the served frontend path (Decision 5). M3-Render's own large-graph
rendering fix (out of scope — Wire operates at the current 14-node
flagship scale).
