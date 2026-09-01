// security.js — Milestone 3, sub-project Server, increment 1.
//
// Security primitives for the `explore` loopback HTTP server: session-token
// generation/comparison and Host-header validation (the T2 DNS-rebinding
// defense — see docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md). No node:http
// usage here — this module is pure and independently unit-testable.

import * as crypto from 'node:crypto';

/** 32 random bytes, hex-encoded (64 hex chars) — the per-session token. */
export function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Constant-time string comparison. Wraps crypto.timingSafeEqual, which
 * THROWS on unequal-length buffers — guarded here the same way
 * posture/integrity.js's verifyLastScan guards its own HMAC comparison
 * (`stored.length !== expected.length`), which this function mirrors as
 * its template. Never throws; returns false on any malformed input.
 */
export function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  try {
    return crypto.timingSafeEqual(bufA, bufB);
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
export function isValidHost(hostHeader, expectedPort) {
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
export const CSP_HEADER_VALUE = "default-src 'none'; frame-ancestors 'none'";
