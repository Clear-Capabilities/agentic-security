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

import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// Located the SAME way scanner/src/mcp/server.js locates files relative to
// its own module (path.dirname(fileURLToPath(import.meta.url))) — the real,
// existing precedent for this pattern in this codebase, not a new one.
// scanner/src/server/ -> ../../../frontend, computed (not guessed) and
// confirmed to resolve to the real frontend/ directory.
const _here = path.dirname(fileURLToPath(import.meta.url));
export const FRONTEND_ROOT = path.resolve(_here, '..', '..', '..', 'frontend');

export const CONTENT_TYPE_MAP = Object.freeze({
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
export const STATIC_CSP_HEADER_VALUE =
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
export function resolveStaticAsset(requestPath) {
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
  const normalized = path.posix.normalize(candidate);

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
