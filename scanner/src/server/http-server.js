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

import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { isValidHost, constantTimeEqual, CSP_HEADER_VALUE } from './security.js';
import { handleScan, handleGraph, handleNode, handleEdge, handleFlow, handleQuery } from './routes.js';
import { resolveStaticAsset, FRONTEND_ROOT, STATIC_CSP_HEADER_VALUE } from './static-assets.js';

// Idle-timeout default. No PRD-specified duration exists (confirmed by the
// scoping doc's own search) — 30 minutes is a reasoned, disclosed default:
// long enough that a human actually exploring a graph in a browser tab
// won't get cut off mid-session, short enough that a forgotten terminal
// doesn't leave a loopback server (and its session token, printed once to
// stdout/scrollback) listening indefinitely.
export const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000;

// Request-size cap. S1 ships GET-only endpoints with no meaningful request
// body, so this mostly matters for S2's future POST endpoints — but the
// cap-checking middleware exists NOW, applied uniformly to every request,
// so S2 does not have to retrofit it. 64KB is generous for any header/body
// this server should ever legitimately receive.
export const MAX_REQUEST_BODY_BYTES = 64 * 1024;

// Session token header. A custom header (never a query param) so the
// token never ends up in server access logs, browser history, or a
// Referer header the way a query-string token could.
export const TOKEN_HEADER = 'x-agentic-security-token';

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
      'Content-Security-Policy': CSP_HEADER_VALUE,
      'Cache-Control': 'no-store',
      'Content-Length': Buffer.byteLength(body),
      // Access-Control-Allow-Origin is intentionally NEVER set anywhere in
      // this file. CORS stays disabled by the absence of this header.
    });
  }
  res.end(body);
}

const ROUTES = [
  { method: 'GET', pattern: /^\/api\/v1\/scan\/?$/, handler: (graph) => handleScan(graph) },
  { method: 'GET', pattern: /^\/api\/v1\/graph\/?$/, handler: (graph) => handleGraph(graph) },
  { method: 'GET', pattern: /^\/api\/v1\/nodes\/([^/]+)\/?$/, handler: (graph, m) => handleNode(graph, decodeURIComponent(m[1])) },
  { method: 'GET', pattern: /^\/api\/v1\/edges\/([^/]+)\/?$/, handler: (graph, m) => handleEdge(graph, decodeURIComponent(m[1])) },
  { method: 'GET', pattern: /^\/api\/v1\/flows\/([^/]+)\/?$/, handler: (graph, m) => handleFlow(graph, decodeURIComponent(m[1])) },
  { method: 'POST', pattern: /^\/api\/v1\/query\/?$/, handler: (graph, m, body) => handleQuery(graph, body?.filter) },
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
    body = fs.readFileSync(path.join(FRONTEND_ROOT, resolved.relativePath));
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
export function createExploreServer({
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

  const server = http.createServer((req, res) => {
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
    if (!isValidHost(hostHeader, boundPort)) {
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
    if (typeof provided !== 'string' || !constantTimeEqual(provided, sessionToken)) {
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
      // no-op, not an error.
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
