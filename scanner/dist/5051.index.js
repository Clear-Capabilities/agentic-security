export const id = 5051;
export const ids = [5051,6944];
export const modules = {

/***/ 5051:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  createExploreServer: () => (/* binding */ createExploreServer)
});

// UNUSED EXPORTS: DEFAULT_IDLE_TIMEOUT_MS, MAX_REQUEST_BODY_BYTES, TOKEN_HEADER

// EXTERNAL MODULE: external "node:http"
var external_node_http_ = __webpack_require__(7067);
// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(3024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(6760);
// EXTERNAL MODULE: ./src/server/security.js
var security = __webpack_require__(6944);
// EXTERNAL MODULE: ./src/server/routes.js
var routes = __webpack_require__(4268);
// EXTERNAL MODULE: external "node:url"
var external_node_url_ = __webpack_require__(3136);
;// CONCATENATED MODULE: ./src/server/static-assets.js
// static-assets.js — Milestone 3, sub-project Wire.
//
// Confines the `explore` server's new same-origin static-asset surface to an
// explicit ALLOWLIST of `frontend/`'s own real, servable files. This is the
// first place scanner/src/server/ ever reads arbitrary requested paths off
// disk — S1's five JSON endpoints never touched the filesystem beyond the
// one already-loaded, already-verified graph — so path confinement here is
// genuinely load-bearing, not decorative (see the M3-Wire scoping doc's
// Decision 2, and the threat-model doc's T4 entry).
//
// `resolveStaticAsset()` is a PURE function: no fs/http access anywhere in
// this file, fully unit-testable in isolation. http-server.js is the only
// caller that actually reads a resolved file off disk.




// Located the SAME way scanner/src/mcp/server.js locates files relative to
// its own module (path.dirname(fileURLToPath(import.meta.url))) — the real,
// existing precedent for this pattern in this codebase, not a new one.
// scanner/src/server/ -> ../../../frontend, computed (not guessed) and
// confirmed to resolve to the real frontend/ directory.
const _here = external_node_path_.dirname((0,external_node_url_.fileURLToPath)(import.meta.url));
const FRONTEND_ROOT = external_node_path_.resolve(_here, '..', '..', '..', 'frontend');

const CONTENT_TYPE_MAP = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
});

// Same-origin-permitting CSP for the static/HTML surface — deliberately
// DIFFERENT from security.js's CSP_HEADER_VALUE ("default-src 'none'"),
// which stays correct for the JSON-only /api/v1/* routes (unchanged). This
// one needs to let the page load its OWN same-origin script/style and make
// its OWN same-origin fetch() calls, while still denying everything
// cross-origin — no remote scripts/fonts/analytics, matching
// frontend/README.md's own "no CDN scripts, remote fonts, analytics" rule.
//
// Grepped across the whole frontend/ tree for any inline <script>/
// style="..." attribute/<style> tag beyond the one index.html inline
// <script type="module"> block this increment moves into main.js (see
// item 5 of the plan): none found (confirmed this session, 2026-09-01).
// So a strict script-src 'self'/style-src 'self' needs no 'unsafe-inline'
// exception — do not add one without re-running that grep.
const STATIC_CSP_HEADER_VALUE =
  "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

// Deliberately restrictive character class (no backslash, no space, no
// percent sign, no null) — every real filename in frontend/'s inventory is
// plain ASCII with letters/digits/hyphen/underscore/dot/slash, and keeping
// the allowlist regex this narrow means an unexpected character in a
// request path fails allowlisting by default rather than being silently
// accepted and handed to a platform-specific path.join() later.
const SRC_JS_RE = /^src\/[A-Za-z0-9/_.-]+\.js$/;
const STYLES_CSS_RE = /^styles\/[A-Za-z0-9_.-]+\.css$/; // top-level only under styles/, no nested subdirectories — matches the real, current inventory

/**
 * Resolves a request pathname (e.g. `/`, `/src/app.js`, `/styles/tokens.css`)
 * against `frontend/`'s explicit servable-file allowlist. Returns
 * `{ok:true, relativePath, contentType}` or `{ok:false, reason}`.
 *
 * Deliberately an ALLOWLIST, not merely a `../`-traversal guard: `test/`,
 * `scripts/`, `package.json`, `README.md`, `CLAUDE.md`, and `.gitignore` are
 * all real files that exist under FRONTEND_ROOT on disk and must NEVER be
 * served — a naive "stays inside frontend/" confinement check would still
 * happily serve every one of them.
 */
function resolveStaticAsset(requestPath) {
  if (typeof requestPath !== 'string' || requestPath.length === 0) {
    return { ok: false, reason: 'invalid-path' };
  }
  if (requestPath.includes('\0')) {
    return { ok: false, reason: 'null-byte' };
  }
  // Absolute-URL-looking input: a scheme (`http://...`) or a
  // protocol-relative `//host/...` — neither is a valid same-origin
  // pathname this server should ever try to resolve.
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(requestPath) || requestPath.startsWith('//')) {
    return { ok: false, reason: 'absolute-url' };
  }
  if (!requestPath.startsWith('/')) {
    return { ok: false, reason: 'invalid-path' };
  }

  let decoded;
  try {
    decoded = decodeURIComponent(requestPath);
  } catch {
    return { ok: false, reason: 'malformed-encoding' };
  }
  if (decoded.includes('\0')) {
    // Catches a %00-encoded null byte the raw-string check above can't see.
    return { ok: false, reason: 'null-byte' };
  }

  if (decoded === '/' || decoded === '') {
    return { ok: true, relativePath: 'index.html', contentType: CONTENT_TYPE_MAP['.html'] };
  }
  if (decoded.startsWith('//')) {
    return { ok: false, reason: 'absolute-url' };
  }

  const candidate = decoded.slice(1); // strip the single leading '/'

  // Normalize using POSIX rules regardless of host OS — this is a URL path,
  // never a platform filesystem path, and must be treated as forward-slash
  // segments even on a host where path.normalize would use backslashes.
  const normalized = external_node_path_.posix.normalize(candidate);

  // Re-check for a traversal escape AFTER normalization — never trust
  // normalize() alone to have removed a traversal attempt (a classic
  // traversal-bypass class): explicitly reject anything that still IS, or
  // still CONTAINS, a `..` segment, or that normalized to an absolute path.
  if (
    normalized === '..' ||
    normalized === '.' ||
    normalized.startsWith('../') ||
    normalized.includes('/../') ||
    normalized.endsWith('/..') ||
    normalized.startsWith('/')
  ) {
    return { ok: false, reason: 'path-traversal' };
  }

  // --- The actual ALLOWLIST (default: deny) ---

  if (normalized === 'index.html') {
    return { ok: true, relativePath: normalized, contentType: CONTENT_TYPE_MAP['.html'] };
  }
  if (SRC_JS_RE.test(normalized)) {
    return { ok: true, relativePath: normalized, contentType: CONTENT_TYPE_MAP['.js'] };
  }
  if (STYLES_CSS_RE.test(normalized)) {
    return { ok: true, relativePath: normalized, contentType: CONTENT_TYPE_MAP['.css'] };
  }

  return { ok: false, reason: 'not-allowlisted' };
}

;// CONCATENATED MODULE: ./src/server/http-server.js
// http-server.js — Milestone 3, sub-project Server, increment 1.
//
// The real node:http server for `agentic-security explore`. Binds ONLY to
// 127.0.0.1 (never 0.0.0.0, never an omitted host arg). Every request is
// validated (Host header, then session token) before any route handler
// ever runs. Every response carries CSP + Cache-Control: no-store and
// NEVER carries Access-Control-Allow-Origin (CORS stays disabled by the
// absence of that header — see security.js).
//
// This is the first node:http usage anywhere in scanner/src/.








// Idle-timeout default. No PRD-specified duration exists (confirmed by the
// scoping doc's own search) — 30 minutes is a reasoned, disclosed default:
// long enough that a human actually exploring a graph in a browser tab
// won't get cut off mid-session, short enough that a forgotten terminal
// doesn't leave a loopback server (and its session token, printed once to
// stdout/scrollback) listening indefinitely.
const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000;

// Request-size cap, applied uniformly to every request. Milestone 5's own
// POST /api/v1/query is the first real consumer of a request body — every
// pre-M5 GET endpoint has no meaningful body of its own, so this mostly
// protects that one route today, but the cap applies to any future
// body-bearing route without retrofitting. 64KB is generous for any
// header/body this server should ever legitimately receive.
const MAX_REQUEST_BODY_BYTES = 64 * 1024;

// Session token header. A custom header (never a query param) so the
// token never ends up in server access logs, browser history, or a
// Referer header the way a query-string token could.
const TOKEN_HEADER = 'x-agentic-security-token';

function _log(method, urlPath, status, durationMs) {
  // Metadata only — NEVER log request/response bodies, NEVER log the
  // session token itself, even on a failed-auth attempt (T3/§17.4).
  console.error(`[explore] ${method} ${urlPath} ${status} ${durationMs}ms`);
}

function _sendJson(res, status, bodyObj) {
  const body = JSON.stringify(bodyObj);
  if (!res.headersSent) {
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Security-Policy': security/* CSP_HEADER_VALUE */.Xv,
      'Cache-Control': 'no-store',
      'Content-Length': Buffer.byteLength(body),
      // Access-Control-Allow-Origin is intentionally NEVER set anywhere in
      // this file. CORS stays disabled by the absence of this header.
    });
  }
  res.end(body);
}

const ROUTES = [
  { method: 'GET', pattern: /^\/api\/v1\/scan\/?$/, handler: (graph) => (0,routes/* handleScan */.Yo)(graph) },
  { method: 'GET', pattern: /^\/api\/v1\/graph\/?$/, handler: (graph) => (0,routes/* handleGraph */.fn)(graph) },
  { method: 'GET', pattern: /^\/api\/v1\/nodes\/([^/]+)\/?$/, handler: (graph, m) => (0,routes/* handleNode */.d5)(graph, decodeURIComponent(m[1])) },
  { method: 'GET', pattern: /^\/api\/v1\/edges\/([^/]+)\/?$/, handler: (graph, m) => (0,routes/* handleEdge */.Yu)(graph, decodeURIComponent(m[1])) },
  { method: 'GET', pattern: /^\/api\/v1\/flows\/([^/]+)\/?$/, handler: (graph, m) => (0,routes/* handleFlow */.jg)(graph, decodeURIComponent(m[1])) },
  { method: 'POST', pattern: /^\/api\/v1\/query\/?$/, handler: (graph, m, body) => (0,routes/* handleQuery */.rR)(graph, body?.filter) },
];

/**
 * Serves one resolved static asset from disk. `resolved` is a real
 * `{ok:true, relativePath, contentType}` from resolveStaticAsset() —
 * already vetted against the allowlist, so the only failure mode left here
 * is the file genuinely missing/unreadable on disk (allowlist/inventory
 * drift), which degrades to a 404 rather than a 500.
 *
 * `relativePath` is built entirely from static-assets.js's own restricted
 * character class (no backslash, already traversal-checked) before it ever
 * reaches this function, so joining it onto FRONTEND_ROOT with the platform
 * path.join is safe.
 */
function _serveStaticAsset(res, resolved) {
  let body;
  try {
    body = external_node_fs_.readFileSync(external_node_path_.join(FRONTEND_ROOT, resolved.relativePath));
  } catch {
    _sendJson(res, 404, { error: 'not found' });
    return 404;
  }
  if (!res.headersSent) {
    res.writeHead(200, {
      'Content-Type': resolved.contentType,
      // The STATIC CSP (same-origin-permitting), NOT the JSON API's
      // `default-src 'none'` — this response is HTML/JS/CSS, not JSON.
      'Content-Security-Policy': STATIC_CSP_HEADER_VALUE,
      'Cache-Control': 'no-store',
      'Content-Length': body.length,
      // Access-Control-Allow-Origin is intentionally NEVER set anywhere in
      // this file, on any response, static or JSON alike.
    });
  }
  res.end(body);
  return 200;
}

/**
 * Creates and starts the `explore` HTTP server. Returns a Promise that
 * resolves once the server is actually listening, with `{server, port}`
 * (the REAL bound port, resolved from the OS when `port: 0`/omitted was
 * requested).
 *
 * @param {object} opts
 * @param {object} opts.graph - the verified, in-memory lineage graph
 * @param {number} [opts.port=0] - 0 lets the OS choose a random free port
 * @param {string} opts.sessionToken - required on every request
 * @param {number} [opts.idleTimeoutMs=DEFAULT_IDLE_TIMEOUT_MS]
 * @param {boolean} [opts.keepOpen=false] - suppresses idle-timeout auto-stop
 */
function createExploreServer({
  graph,
  port = 0,
  sessionToken,
  idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
  keepOpen = false,
} = {}) {
  if (!graph || typeof graph !== 'object') {
    throw new Error('createExploreServer requires a graph object');
  }
  if (typeof sessionToken !== 'string' || sessionToken.length < 32) {
    throw new Error('createExploreServer requires a real sessionToken (>= 32 chars)');
  }

  let idleTimer = null;

  function _clearIdleTimer() {
    if (idleTimer) {
      clearTimeout(idleTimer);
      idleTimer = null;
    }
  }

  // Reset the idle-auto-stop timer. Only called for requests that pass
  // BOTH the Host and session-token checks — an unauthenticated request
  // (a DNS-rebinding probe, a stray scan) must never be able to keep the
  // server alive indefinitely by hammering it; only genuine, authenticated
  // activity extends the session.
  function _resetIdleTimer() {
    if (keepOpen) return;
    _clearIdleTimer();
    idleTimer = setTimeout(() => {
      try { server.closeAllConnections?.(); } catch { /* best-effort */ }
      server.close();
    }, idleTimeoutMs);
    // Don't let this timer alone keep the Node process alive past a clean
    // shutdown path.
    if (typeof idleTimer.unref === 'function') idleTimer.unref();
  }

  const server = external_node_http_.createServer((req, res) => {
    const start = Date.now();
    const method = req.method || 'GET';
    let urlPath = '/';
    try {
      urlPath = new URL(req.url, 'http://internal').pathname;
    } catch {
      urlPath = req.url || '/';
    }

    const finish = (status) => _log(method, urlPath, status, Date.now() - start);

    // The actual bound port. Cheap (no syscall — Node caches the bound
    // address on the server object), so it's safe to read per-request
    // rather than caching it in a closure variable that could theoretically
    // race the 'listening' event.
    const boundPort = server.address()?.port;

    // 1. Host header validation (T2 defense) — before anything else.
    const hostHeader = req.headers.host;
    if (!(0,security/* isValidHost */.HO)(hostHeader, boundPort)) {
      _sendJson(res, 400, { error: 'invalid Host header' });
      finish(400);
      req.resume(); // drain and discard any body without processing it
      return;
    }

    // 1.5. Static-asset serving (Wire's own new surface) — the ONE
    // deliberate, disclosed exception to "every request requires a session
    // token" below. The token travels to the browser via a URL FRAGMENT
    // (`#token=...`), which is NEVER sent to the server by the browser in
    // any HTTP request — so the very first page-load request (GET /) is
    // structurally incapable of carrying it. Every subsequent same-origin
    // fetch() the page itself makes against /api/v1/* still requires the
    // token, completely unchanged from S1.
    //
    // Namespaced away from /api/v1/* so there is no ambiguity: any GET
    // request NOT under /api/ is resolved against the static-asset
    // allowlist and NEVER reaches the token check at all, matching or
    // rejecting with a 404 (never a 403 — a 403 would confirm to a prober
    // that a rejected path exists). This still runs strictly AFTER the
    // Host-header check above (T2 applies uniformly, auth or not — DNS
    // rebinding does not care whether the resource behind it needs a
    // token).
    if (method === 'GET' && !urlPath.startsWith('/api/')) {
      const staticResult = resolveStaticAsset(urlPath);
      if (staticResult.ok) {
        const status = _serveStaticAsset(res, staticResult);
        finish(status);
      } else {
        _sendJson(res, 404, { error: 'not found' });
        finish(404);
      }
      req.resume();
      return;
    }

    // 2. Session-token validation (T3 defense) — required on EVERY
    // request, read or write, per the threat-model doc's own §17.4
    // checklist. Compared in constant time.
    const provided = req.headers[TOKEN_HEADER];
    if (typeof provided !== 'string' || !(0,security/* constantTimeEqual */.SK)(provided, sessionToken)) {
      _sendJson(res, 401, { error: 'missing or invalid session token' });
      finish(401);
      req.resume();
      return;
    }

    // Genuine, authenticated request — extend the idle-auto-stop window.
    _resetIdleTimer();

    // 3. Request-size cap, applied uniformly (S1's GET endpoints have no
    // meaningful body; Milestone 5's own POST /api/v1/query is the first
    // real consumer). Milestone 5 also starts accumulating the actual body
    // BYTES (not just the size) — no earlier route needed them.
    let bodySize = 0;
    let bodyChunks = [];
    let aborted = false;
    req.on('data', (chunk) => {
      if (aborted) return;
      bodySize += chunk.length;
      if (bodySize > MAX_REQUEST_BODY_BYTES) {
        aborted = true;
        _sendJson(res, 413, { error: 'request body too large' });
        finish(413);
        // Stop reading further body bytes only once the 413 response has
        // actually been flushed to the client — destroying the request
        // stream immediately can race the response write and cut it off
        // before the client sees it.
        res.once('finish', () => { try { req.destroy(); } catch { /* best-effort */ } });
        return;
      }
      bodyChunks.push(chunk);
    });

    req.on('end', () => {
      if (aborted) return;

      // 4. Route.
      let matched = null;
      let match = null;
      for (const route of ROUTES) {
        if (route.method !== method) continue;
        const m = route.pattern.exec(urlPath);
        if (m) { matched = route; match = m; break; }
      }
      if (!matched) {
        _sendJson(res, 404, { error: 'not found' });
        finish(404);
        return;
      }

      // Milestone 5: parse the body ONLY for a matched route, and only as
      // JSON when non-empty — every pre-M5 GET route still ignores this
      // 3rd argument entirely, so an empty/missing body for them is a
      // no-op, not an error. Disclosed, real, low-risk behavior change
      // (final whole-branch review finding): this JSON-parse pass applies
      // to ANY matched route with a non-empty body, not just the new POST
      // /api/v1/query — a GET request that (unusually) carries a
      // non-JSON-parseable body now gets a clean 400 instead of the
      // pre-M5 behavior (body silently drained, request processed
      // normally). No real client sends a body on a GET here
      // (frontend/src/lib/api-client.js's own fetch() calls never do), so
      // this is not expected to affect any real caller — narrower
      // per-method gating was judged unnecessary complexity for a case
      // with no real-world traffic, but is a real, disclosed option if
      // this ever needs revisiting.
      let body;
      if (bodyChunks.length > 0) {
        try {
          body = JSON.parse(Buffer.concat(bodyChunks).toString('utf8'));
        } catch {
          _sendJson(res, 400, { error: 'malformed JSON request body' });
          finish(400);
          return;
        }
      }

      try {
        const result = matched.handler(graph, match, body);
        _sendJson(res, result.status, result.body);
        finish(result.status);
      } catch {
        _sendJson(res, 500, { error: 'internal error' });
        finish(500);
      }
    });

    req.on('error', () => {
      // A client that aborts mid-request — nothing to respond to.
      aborted = true;
    });
  });

  return new Promise((resolve, reject) => {
    const onError = (err) => reject(err);
    server.once('error', onError);
    // Bind explicitly to 127.0.0.1 — never omit the host argument (that is
    // NOT the same as 127.0.0.1 on every platform) and never 0.0.0.0.
    server.listen(port, '127.0.0.1', () => {
      server.removeListener('error', onError);
      const actualPort = server.address().port;
      _resetIdleTimer(); // start the idle clock even before the first request
      resolve({ server, port: actualPort });
    });
  });
}


/***/ }),

/***/ 4268:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Yo: () => (/* binding */ handleScan),
/* harmony export */   Yu: () => (/* binding */ handleEdge),
/* harmony export */   d5: () => (/* binding */ handleNode),
/* harmony export */   fn: () => (/* binding */ handleGraph),
/* harmony export */   jg: () => (/* binding */ handleFlow),
/* harmony export */   rR: () => (/* binding */ handleQuery)
/* harmony export */ });
/* unused harmony export wrapResponse */
/* harmony import */ var _lineage_export_json_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(859);
// routes.js — Milestone 3, sub-project Server, increment 1.
//
// Five pure GET-endpoint handlers, each `(graph, ...) -> {status, body}`.
// No req/res access anywhere in this file — that is what makes these
// handlers unit-testable without an HTTP layer at all. http-server.js is
// the only module that touches node:http and calls into these.
//
// Every response body is wrapped in `wrapResponse`, which adds the exact
// envelope fields PRD line 1326 names (quoted in the implementation plan):
// "base graph/snapshot digest, schema/extension versions, scope, coverage,
// limitations, and contributing canonical IDs."



/**
 * Shared response envelope. Maps PRD line 1326's required fields onto the
 * graph's own real fields:
 *   - digest              -> graph.graphId (the base graph/snapshot digest)
 *   - schemaVersion        -> graph.schemaVersion
 *   - extensions           -> graph.extensions (schema/extension versions —
 *                             today always `{}`; see schema.js)
 *   - scope                -> graph.scope
 *   - coverage              -> graph.coverage
 *   - limitations           -> graph.limitations
 *   - canonicalIds          -> see the design note below
 *
 * "contributing canonical IDs" design decision (disclosed per the plan):
 * for `handleScan`/`handleGraph`, which describe the WHOLE graph rather
 * than one entity, `canonicalIds` is `null` — the response body for
 * `handleGraph` already IS the full nodes/edges/flows arrays, so echoing
 * every id again here would be pure duplication with no informational
 * gain, and for a large graph would materially bloat the response for
 * zero benefit. For `handleNode`/`handleEdge`, `canonicalIds` is the
 * single id the response is about. For `handleFlow`, `canonicalIds` is
 * the flow's own id PLUS the node/edge ids that flow's evidence draws
 * from (source, sink, edgeIds) — a flow is a derived record referencing
 * several underlying entities, and naming all of them here is genuinely
 * useful metadata a client would otherwise have to re-derive from the
 * flow body itself.
 */
function wrapResponse(data, graph, { canonicalIds = null } = {}) {
  return {
    digest: graph?.graphId ?? null,
    schemaVersion: graph?.schemaVersion ?? null,
    extensions: graph?.extensions ?? {},
    scope: graph?.scope ?? null,
    coverage: graph?.coverage ?? null,
    limitations: graph?.limitations ?? [],
    canonicalIds,
    data,
  };
}

function _findById(list, id) {
  if (!Array.isArray(list)) return null;
  return list.find((item) => item && item.id === id) ?? null;
}

/** Scan/graph metadata — NOT the full node/edge arrays. */
function handleScan(graph) {
  const data = {
    schemaVersion: graph?.schemaVersion ?? null,
    graphId: graph?.graphId ?? null,
    generatedAt: graph?.generatedAt ?? null,
    scope: graph?.scope ?? null,
    scanHealth: graph?.scanHealth ?? null,
    coverage: graph?.coverage ?? null,
  };
  return { status: 200, body: wrapResponse(data, graph, { canonicalIds: null }) };
}

/** The full graph document, unfiltered. For a scoped/narrowed projection, use `handleQuery` (`POST /api/v1/query`, Milestone 5) below instead. */
function handleGraph(graph) {
  return { status: 200, body: wrapResponse(graph, graph, { canonicalIds: null }) };
}

/**
 * A deterministic typed projection query — Milestone 5's own
 * `POST /api/v1/query`, the S2 endpoint `handleGraph`'s own header
 * comment named and deferred. `filter` is the exact `{nodeIds, edgeIds}`
 * shape `dataflow export --filter`/`exportGraphJSON` already use — reused
 * via `_filterGraph`, never reimplemented. Final whole-branch review
 * finding: `undefined` (filter omitted entirely) returns the WHOLE graph,
 * identical to `handleGraph` — but `{}` (an empty, well-formed filter
 * object) is NOT the same thing, and does NOT mean "no restriction": both
 * `nodeIds`/`edgeIds` default to empty Sets inside `_filterGraph`, so `{}`
 * narrows the graph down to EMPTY node/edge/flow/dataElement arrays. A
 * caller that wants the whole graph must omit `filter` entirely, never
 * pass `{}` meaning "everything." A malformed filter is a 400, never a
 * thrown exception reaching the caller.
 */
function handleQuery(graph, filter) {
  const check = (0,_lineage_export_json_js__WEBPACK_IMPORTED_MODULE_0__.validateFilterShape)(filter);
  if (!check.valid) {
    return { status: 400, body: { error: check.error } };
  }
  return { status: 200, body: wrapResponse((0,_lineage_export_json_js__WEBPACK_IMPORTED_MODULE_0__/* ._filterGraph */ .e)(graph, filter), graph, { canonicalIds: null }) };
}

/** Look up one node by id. 404 with a clear body if not found. */
function handleNode(graph, id) {
  const node = _findById(graph?.nodes, id);
  if (!node) {
    return { status: 404, body: wrapResponse({ error: `node not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  return { status: 200, body: wrapResponse(node, graph, { canonicalIds: [id] }) };
}

/** Look up one edge by id. 404 with a clear body if not found. */
function handleEdge(graph, id) {
  const edge = _findById(graph?.edges, id);
  if (!edge) {
    return { status: 404, body: wrapResponse({ error: `edge not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  return { status: 200, body: wrapResponse(edge, graph, { canonicalIds: [id] }) };
}

/** Look up one flow by id. 404 with a clear body if not found. */
function handleFlow(graph, id) {
  const flow = _findById(graph?.flows, id);
  if (!flow) {
    return { status: 404, body: wrapResponse({ error: `flow not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  const contributing = new Set([id]);
  if (flow.source) contributing.add(flow.source);
  if (flow.sink) contributing.add(flow.sink);
  for (const eid of (flow.edgeIds || [])) contributing.add(eid);
  return { status: 200, body: wrapResponse(flow, graph, { canonicalIds: [...contributing] }) };
}


/***/ }),

/***/ 6944:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   HO: () => (/* binding */ isValidHost),
/* harmony export */   SK: () => (/* binding */ constantTimeEqual),
/* harmony export */   Xv: () => (/* binding */ CSP_HEADER_VALUE),
/* harmony export */   generateSessionToken: () => (/* binding */ generateSessionToken)
/* harmony export */ });
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(7598);
// security.js — Milestone 3, sub-project Server, increment 1.
//
// Security primitives for the `explore` loopback HTTP server: session-token
// generation/comparison and Host-header validation (the T2 DNS-rebinding
// defense — see docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md). No node:http
// usage here — this module is pure and independently unit-testable.



/** 32 random bytes, hex-encoded (64 hex chars) — the per-session token. */
function generateSessionToken() {
  return node_crypto__WEBPACK_IMPORTED_MODULE_0__.randomBytes(32).toString('hex');
}

/**
 * Constant-time string comparison. Wraps crypto.timingSafeEqual, which
 * THROWS on unequal-length buffers — guarded here the same way
 * posture/integrity.js's verifyLastScan guards its own HMAC comparison
 * (`stored.length !== expected.length`), which this function mirrors as
 * its template. Never throws; returns false on any malformed input.
 */
function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  try {
    return node_crypto__WEBPACK_IMPORTED_MODULE_0__.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

// Loopback hostnames this server ever legitimately answers to. Anything
// else in a Host header is either a stray/misconfigured client or a
// DNS-rebinding attempt from a hostile page — reject it (T2).
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

/**
 * Validates a request's `Host` header against the port the server is
 * actually listening on. Accepts only `127.0.0.1`/`localhost`/`::1`
 * (`::1` written either bare or bracketed, `[::1]`), each carrying the
 * expected port explicitly — this is the ENTIRE T2 (DNS rebinding)
 * defense: a hostile page that points a fetch() at 127.0.0.1:<port> still
 * sends the ATTACKER'S origin's Host header value (its own hostname), not
 * "127.0.0.1", so this check rejects it regardless of same-origin policy
 * quirks in any particular browser.
 *
 * A bare host with no port suffix is accepted ONLY when expectedPort is
 * the default HTTP port (80) — browsers omit :80 for a default-port
 * http:// request. In practice this server always listens on a
 * non-default port, so that branch is effectively unreachable but is kept
 * for RFC-correctness rather than special-cased away.
 *
 * @param {string|undefined} hostHeader
 * @param {number} expectedPort
 * @returns {boolean}
 */
function isValidHost(hostHeader, expectedPort) {
  if (typeof hostHeader !== 'string' || hostHeader.length === 0) return false;
  if (typeof expectedPort !== 'number' || !Number.isInteger(expectedPort) || expectedPort <= 0) return false;

  const host = hostHeader.trim();
  if (host.length !== hostHeader.length) return false; // reject leading/trailing whitespace outright
  if (/\s/.test(host)) return false; // no embedded whitespace/control chars in a well-formed Host header

  let hostname;
  let port = null;

  if (host.startsWith('[')) {
    // Bracketed IPv6 literal form: [::1] or [::1]:port
    const closeIdx = host.indexOf(']');
    if (closeIdx === -1) return false;
    hostname = host.slice(1, closeIdx); // strip brackets
    const rest = host.slice(closeIdx + 1);
    if (rest.length) {
      if (!rest.startsWith(':')) return false;
      const portStr = rest.slice(1);
      if (!/^\d+$/.test(portStr)) return false;
      port = Number(portStr);
    }
  } else {
    const parts = host.split(':');
    if (parts.length === 1) {
      hostname = parts[0];
    } else if (parts.length === 2) {
      hostname = parts[0];
      if (!/^\d+$/.test(parts[1])) return false;
      port = Number(parts[1]);
    } else {
      // More than one colon with no brackets: either a malformed header or
      // a bare (unbracketed) IPv6 literal, which is not valid Host syntax
      // (RFC 7230 §5.4 requires brackets for an IPv6 literal). Reject.
      return false;
    }
  }

  hostname = hostname.toLowerCase();
  if (!LOOPBACK_HOSTS.has(hostname)) return false;

  if (port === null) return expectedPort === 80;
  return port === expectedPort;
}

// This server serves JSON only in this increment (no HTML, no inline
// script/style, no static assets) — `frontend/`'s own static assets are a
// later increment's (Wire's) job, not S1's. `default-src 'none'` is
// therefore the correct, maximally-restrictive policy: nothing this
// server ever returns should load or execute ANY sub-resource. Revisit
// only when a future increment starts serving HTML/JS itself.
const CSP_HEADER_VALUE = "default-src 'none'; frame-ancestors 'none'";


/***/ })

};
