// Outbound payload filtering and denial records (X-504.AC02, X-504.AC03).
//
// `redactOutbound` is the structured counterpart of egress/redact.js: that module
// redacts prompt TEXT bound for a model endpoint, this one redacts a whole
// request (URL, headers, body) bound for a declared network destination. It
// reuses the same secret detector (`redactSecrets`), then adds what a request has
// that prose does not: credentials in URL userinfo, secret-named query
// parameters and header names, and secret-named keys in JSON and form bodies.
// Exact canary values (and their URL-encoded and base64 forms) are removed
// wherever they appear, which is what the canary fixtures assert.
//
// What it cannot do is look inside an encrypted tunnel. A CONNECT tunnel to a
// declared https destination is opaque to the proxy; the control for that path is
// that the task was never handed a secret to put in it (secret-free environment,
// protected paths, no secrets in arguments), and the capability report says
// `payloadFiltering: plaintext-http-only`.
import crypto from 'node:crypto';
import { redactSecretShapes } from '../mcp/redact.js';
import { scrubSecretText } from './secrets.js';
import { recordEgressCall } from '../egress/audit.js';
import { normalizeHost, classifyAddress } from './address.js';

const PLACEHOLDER = '[REDACTED-SECRET]';
const SECRET_NAME = /(?:^|[^a-z])(?:token|secret|passw(?:or)?d|api[-_]?key|apikey|auth(?:orization)?|credential|private[-_]?key|session|cookie|signature|sig|bearer)(?:[^a-z]|$)/i;
const MAX_DEPTH = 32;

export function isSecretName(name) {
  return typeof name === 'string' && SECRET_NAME.test(name);
}

/** The forms in which a canary value could travel: raw, URL-encoded, base64 and its URL-safe variant. */
function canaryForms(canaries) {
  const out = new Set();
  for (const c of canaries || []) {
    if (typeof c !== 'string' || c.length < 6) continue;
    out.add(c);
    out.add(encodeURIComponent(c));
    const b64 = Buffer.from(c, 'utf8').toString('base64');
    out.add(b64);
    out.add(b64.replace(/=+$/, ''));
    out.add(b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  }
  return [...out].filter((x) => x.length >= 6);
}

function scrubText(text, forms, stats) {
  let out = String(text);
  for (const f of forms) {
    if (out.includes(f)) { out = out.split(f).join(PLACEHOLDER); stats.canary += 1; }
  }
  const r = scrubSecretText(out);
  if (r.redactions > 0) { stats.secrets += r.redactions; out = r.text; }
  return out;
}

function walk(value, forms, stats, depth = 0) {
  if (depth > MAX_DEPTH) { stats.truncated = true; return PLACEHOLDER; }
  if (typeof value === 'string') return scrubText(value, forms, stats);
  if (Array.isArray(value)) return value.map((v) => walk(v, forms, stats, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      const key = scrubText(k, forms, stats);
      if (isSecretName(k) && (typeof v === 'string' || typeof v === 'number')) { out[key] = PLACEHOLDER; stats.keys += 1; }
      else out[key] = walk(v, forms, stats, depth + 1);
    }
    return out;
  }
  return value;
}

function scrubParams(params, forms, stats) {
  const out = new URLSearchParams();
  for (const [k, v] of params) {
    if (isSecretName(k) && v !== '') { out.append(scrubText(k, forms, stats), PLACEHOLDER); stats.keys += 1; }
    else out.append(scrubText(k, forms, stats), scrubText(v, forms, stats));
  }
  return out;
}

/**
 * Filter a request before it leaves.
 * @param {{url?: string, headers?: object, body?: string|Buffer|object, contentType?: string}} req
 * @param {{canaries?: string[]}} [opts]
 * @returns {{url: string|null, headers: object, body: string|null, redactions: number,
 *            categories: {userinfo:number, secrets:number, keys:number, canary:number}, uninspectable: boolean}}
 *   `uninspectable` is true for a binary body, which is returned untouched and
 *   must not be sent by a caller that requires filtering.
 */
export function redactOutbound(req = {}, opts = {}) {
  const forms = canaryForms(opts.canaries);
  const stats = { secrets: 0, keys: 0, canary: 0, userinfo: 0, truncated: false };
  let url = null;
  if (typeof req.url === 'string') {
    try {
      const u = new URL(req.url);
      if (u.username || u.password) { stats.userinfo += 1; u.username = ''; u.password = ''; }
      u.search = scrubParams(u.searchParams, forms, stats).toString();
      u.pathname = u.pathname.split('/').map((seg) => scrubText(decodeURIComponent(seg), forms, stats)).map(encodeURIComponent).join('/');
      u.hash = '';
      url = u.toString();
    } catch {
      url = scrubText(req.url.replace(/\/\/[^/@\s]*@/, '//'), forms, stats);
    }
  }
  const headers = {};
  for (const [name, raw] of Object.entries(req.headers || {})) {
    const values = Array.isArray(raw) ? raw : [raw];
    const cleaned = values.map((v) => {
      if (isSecretName(name)) { stats.keys += 1; return PLACEHOLDER; }
      return scrubText(String(v), forms, stats);
    });
    headers[name.toLowerCase()] = Array.isArray(raw) ? cleaned : cleaned[0];
  }
  let body = null;
  let uninspectable = false;
  if (req.body !== undefined && req.body !== null) {
    const ct = String(req.contentType || headers['content-type'] || '').toLowerCase();
    if (Buffer.isBuffer(req.body) && req.body.includes(0)) {
      uninspectable = true; body = req.body;
    } else if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      body = JSON.stringify(walk(req.body, forms, stats));
    } else {
      const text = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body);
      if (ct.includes('json')) {
        try { body = JSON.stringify(walk(JSON.parse(text), forms, stats)); } catch { body = scrubText(text, forms, stats); }
      } else if (ct.includes('x-www-form-urlencoded')) {
        body = scrubParams(new URLSearchParams(text), forms, stats).toString();
      } else body = scrubText(text, forms, stats);
    }
  }
  const categories = { userinfo: stats.userinfo, secrets: stats.secrets, keys: stats.keys, canary: stats.canary };
  return {
    url, headers, body, categories, uninspectable,
    redactions: stats.userinfo + stats.secrets + stats.keys + stats.canary,
  };
}

/** Log-safe text: canary values and secret shapes removed. Never used to build a decision reason. */
export function sanitizeLogText(text, canaries = []) {
  let out = typeof text === 'string' ? text : JSON.stringify(text) ?? '';
  for (const f of canaryForms(canaries)) out = out.split(f).join(PLACEHOLDER);
  // Provider-shaped credentials only. The high-entropy-literal heuristic is for
  // payloads, where over-redaction is acceptable; here it would rewrite ordinary
  // quoted paths in a task's output.
  return redactSecretShapes(out).text;
}

// ---------------------------------------------------------------- denial records

/** Class of a destination for the audit trail: an address class, or `hostname`. */
export function destinationClass(host) {
  const h = normalizeHost(host);
  if (!h.ok) return 'invalid';
  if (h.kind === 'name') return h.host === 'localhost' || h.host.endsWith('.localhost') ? 'loopback' : 'hostname';
  return classifyAddress(h.host);
}

/**
 * What a denied egress leaves behind: the destination CLASS, a short digest of
 * the host (a host name can itself carry data, so it is never stored), the port,
 * the scheme and the policy code. No path, query, header or body, ever.
 */
export function denialRecord({ taskId, host, port, scheme, code }) {
  const h = normalizeHost(host);
  const digest = crypto.createHash('sha256').update(h.ok ? h.host : String(host)).digest('hex').slice(0, 12);
  return Object.freeze({
    taskId: taskId ?? null, outcome: 'deny', code, destinationClass: destinationClass(host),
    hostDigest: digest, port: Number.isInteger(port) ? port : null, scheme: scheme === 'http' || scheme === 'https' ? scheme : null,
  });
}

/**
 * Append a denial to the existing tamper-evident egress audit chain
 * (egress/audit.js). The chain records provider, purpose, outcome and reason, so
 * the destination class is carried as the provider and the policy code as the
 * reason; nothing else is passed in.
 */
export function recordNetworkDenial(scanRoot, record) {
  if (!scanRoot || !record) return;
  recordEgressCall({
    scanRoot,
    decision: {
      allowed: false, decision: 'deny', reason: record.code, provider: record.destinationClass,
      policySource: 'capability-manifest', purpose: 'capability-network',
    },
    ctx: {},
  });
}
