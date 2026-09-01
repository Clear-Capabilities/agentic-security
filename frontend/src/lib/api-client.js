// api-client.js — Milestone 3, sub-project Wire.
//
// The frontend's entire integration surface with the `explore` server
// (scanner/src/server/). Two small functions: extract the session token
// once from the URL fragment, then use it to fetch the graph. Every other
// view's own rendering code stays untouched — this file is the whole
// integration point (see the M3-Wire scoping doc's Decision 3).
//
// The session token travels via the URL FRAGMENT (`#token=<hex>`), never a
// query string or a cookie — a URL fragment is never sent to the server in
// any HTTP request, so the initial page-load request itself cannot leak the
// token into a server access log, yet the fragment IS readable by this
// page's own JS via `location.hash` (see Decision 1).

const TOKEN_HEADER = 'x-agentic-security-token';

/**
 * Parses `location.hash` (or an explicitly-supplied hash string, for
 * testing) for a `#token=<64-hex-char>` parameter. Other params (e.g.
 * `view`/`selected`/`filters`, which shell.js starts writing into the same
 * hash after the first render) are ignored here — this function only ever
 * cares about `token`.
 *
 * @param {string} [hash] - defaults to the real `location.hash` in a browser
 * @returns {string|null} the token, or null if absent/malformed
 */
export function extractTokenFromFragment(hash = (typeof location !== 'undefined' ? location.hash : '')) {
  const raw = String(hash ?? '').replace(/^#/, '');
  if (!raw) return null;

  let params;
  try {
    params = new URLSearchParams(raw);
  } catch {
    return null;
  }

  const token = params.get('token');
  if (!token || !/^[0-9a-f]{64}$/i.test(token)) return null;
  return token;
}

/**
 * Fetches the full graph from the explore server's `GET /api/v1/graph`
 * endpoint, authenticating via the `x-agentic-security-token` header (never
 * a query string), and unwraps the response envelope's `.data` field (see
 * scanner/src/server/routes.js's `wrapResponse`) to hand back the plain
 * graph object `bootstrap()` already expects.
 *
 * @param {object} opts
 * @param {string} opts.token - required
 * @param {string} [opts.baseUrl=''] - defaults to a relative fetch against
 *   the page's own origin, which is the ONLY thing a real browser page is
 *   ever expected to pass (same-origin, per the M3-Wire scoping doc's
 *   load-bearing CORS-disabled correction). Overridable so a real live-HTTP
 *   test can point this at a real running server without a headless
 *   browser — never used by the shipped frontend itself.
 * @returns {Promise<object>} the plain graph object
 */
export async function fetchGraph({ token, baseUrl = '' } = {}) {
  if (!token) {
    throw new Error('fetchGraph: a session token is required');
  }

  const res = await fetch(`${baseUrl}/api/v1/graph`, {
    headers: { [TOKEN_HEADER]: token },
  });

  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.json();
      if (body && typeof body.error === 'string') detail = `: ${body.error}`;
    } catch {
      /* non-JSON error body — report the status alone */
    }
    throw new Error(`fetchGraph: request failed with status ${res.status}${detail}`);
  }

  let envelope;
  try {
    envelope = await res.json();
  } catch {
    throw new Error('fetchGraph: response was not valid JSON');
  }

  if (!envelope || typeof envelope !== 'object' || !('data' in envelope)) {
    throw new Error('fetchGraph: unexpected response shape (missing .data)');
  }

  return envelope.data;
}
