// The one HTTP transport for model calls (GA-06.3).
//
// Every path that sends a prompt to a model endpoint evaluates the egress policy first (policy.js) and then sends the request through
// `modelFetch` here. The policy decides WHETHER a call goes out; this module decides HOW, and the "how" is the same for every caller:
//
//   1. no redirects. A loopback endpoint that answers 3xx to a remote host would carry the prompt off the machine; `redirect: 'error'`
//      makes fetch reject instead. A redirect is reported as its own error code, never followed.
//   2. a per-call deadline. Every call is aborted after `timeoutMs` (default AGENTIC_SECURITY_LLM_TIMEOUT_MS, else 60 s); a caller's own
//      signal is combined with it, so the stricter of the two wins. A connection that is accepted and never answers cannot hold a scan open.
//   3. a response cap. The body is read as a stream and the request is aborted once `maxResponseBytes` (default
//      AGENTIC_SECURITY_LLM_MAX_RESPONSE_BYTES, else 4 MiB) have arrived, so a server cannot exhaust memory; the cap is applied while
//      reading, not after `text()` has already buffered everything.
//   4. a process-wide wall budget. With AGENTIC_SECURITY_LLM_WALL_BUDGET_MS set, the total time spent inside model calls in this process
//      is accounted and a call that would start past the budget is refused with `budget-exhausted`. Unset, there is no global limit and
//      the per-call deadline is the only bound; the dollar ceiling (`posture/cost-ceiling.js`) is separate and applies to the validator.
//   5. no proxy. Node's fetch does not read HTTP_PROXY/HTTPS_PROXY, and this module installs no dispatcher, so a proxy variable in the
//      environment never changes where a prompt goes. A loopback promise therefore stays a promise about the endpoint literal.
//
// The result mimics the part of a `Response` the callers use (`ok`, `status`, `statusText`, `headers`, `text()`, `json()`) over the
// already-capped body, so a call site changes one identifier. Failures are thrown as `ModelTransportError` with a `code` in
// `TRANSPORT_ERROR_CODES`, which the callers map to their own unavailable states; nothing here retries or falls back.

//   6. a connect deadline (0.195.31, GA-06 §3). With `opts.connectTimeoutMs` set, a TCP connection to the endpoint's host and port is
//      opened and closed BEFORE the request, bounded by that value: a dead port is `connect-refused` and an unroutable host is
//      `connect-timeout`, each within the connect deadline instead of the whole call timeout (minutes for a local model). A server
//      that accepts the connection and then takes its time is the per-call deadline's business, because a non-streaming model answers
//      with its headers only when generation is done. The probe is skipped when a test injects `fetchImpl`: it is about the real network.

import net from 'node:net';

export const DEFAULT_TIMEOUT_MS = 60_000;
export const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const TRANSPORT_ERROR_CODES = Object.freeze(['redirect', 'timeout', 'response-too-large', 'budget-exhausted', 'network', 'connect-timeout', 'connect-refused']);

/** One bounded TCP connect to the endpoint's host and port, closed as soon as it opens; rejects with a transport error. */
function probeConnect(endpoint, ms) {
  let u;
  try { u = new URL(String(endpoint)); } catch { return Promise.reject(new ModelTransportError('network', `not a URL: ${endpoint}`)); }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port });
    const done = (err) => { sock.destroy(); clearTimeout(t); err ? reject(err) : resolve(); };
    const t = setTimeout(() => done(new ModelTransportError('connect-timeout', `no connection to ${host}:${port} within ${ms} ms`, { connectTimeoutMs: ms })), ms);
    sock.once('connect', () => done(null));
    sock.once('error', (e) => done(new ModelTransportError('connect-refused', `cannot connect to ${host}:${port}: ${e?.code || e?.message || e}`, { connectTimeoutMs: ms, cause: e })));
  });
}

export class ModelTransportError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'ModelTransportError';
    this.code = code;
    Object.assign(this, extra);
  }
}

const budget = { spentMs: 0, calls: 0 };

/** Positive integer from the environment, else the fallback. */
function envInt(name, fallback, env = process.env) {
  const n = Number(env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

/** The process-wide model wall budget: `{ limitMs|null, spentMs, calls }`. */
export function modelBudget(env = process.env) {
  const raw = Number(env.AGENTIC_SECURITY_LLM_WALL_BUDGET_MS);
  return { limitMs: Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : null, spentMs: budget.spentMs, calls: budget.calls };
}

/** Reset the accounted wall time (a new scan, or a test). */
export function resetModelBudget() { budget.spentMs = 0; budget.calls = 0; }

function isAbort(e) { return e && (e.name === 'AbortError' || e.name === 'TimeoutError'); }

/**
 * Read a body stream, refusing more than `max` bytes. Aborts the request through `abort` so the server stops sending.
 * @returns {Promise<string>}
 */
async function readCapped(res, max, abort) {
  if (!res.body || typeof res.body.getReader !== 'function') {
    // a response without a readable stream (an injected fake in a test): read it whole, then apply the cap. The parsed form is
    // preferred, because a fake's `json()` is the reply its author meant and its `text()` may be a different, raw string.
    const text = typeof res.json === 'function' ? JSON.stringify(await res.json()) : await res.text();
    if (Buffer.byteLength(text, 'utf8') > max) throw new ModelTransportError('response-too-large', `response is over the ${max} byte limit`, { limit: max });
    return text;
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      try { await reader.cancel(); } catch { /* the request is being torn down */ }
      abort();
      throw new ModelTransportError('response-too-large', `response exceeded the ${max} byte limit`, { limit: max });
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))).toString('utf8');
}

/**
 * Send one model request. `init` is a fetch init without `redirect` or `signal` (both are set here);
 * `opts`: `{ timeoutMs, maxResponseBytes, signal, env, fetchImpl }`.
 *
 * @returns {Promise<{ok:boolean,status:number,statusText:string,headers:Headers,bytes:number,text:()=>Promise<string>,json:()=>Promise<any>}>}
 */
export async function modelFetch(endpoint, init = {}, opts = {}) {
  const env = opts.env || process.env;
  const timeoutMs = Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0 ? opts.timeoutMs : envInt('AGENTIC_SECURITY_LLM_TIMEOUT_MS', DEFAULT_TIMEOUT_MS, env);
  const maxBytes = Number.isFinite(opts.maxResponseBytes) && opts.maxResponseBytes > 0 ? opts.maxResponseBytes : envInt('AGENTIC_SECURITY_LLM_MAX_RESPONSE_BYTES', DEFAULT_MAX_RESPONSE_BYTES, env);
  const b = modelBudget(env);
  if (b.limitMs !== null && b.spentMs >= b.limitMs) {
    throw new ModelTransportError('budget-exhausted', `the model wall budget of ${b.limitMs} ms is spent (${b.spentMs} ms over ${b.calls} call(s))`, { limitMs: b.limitMs, spentMs: b.spentMs });
  }
  const ac = new AbortController();
  // the remaining budget, when one is set, caps this call too
  const callMs = b.limitMs === null ? timeoutMs : Math.min(timeoutMs, Math.max(1, b.limitMs - b.spentMs));
  const timer = setTimeout(() => ac.abort(new ModelTransportError('timeout', `no response within ${callMs} ms`)), callMs);
  // the connect deadline (header bullet 6): a bounded TCP probe before the request, only when asked for and only on the real network
  const connectMs = Number.isFinite(opts.connectTimeoutMs) && opts.connectTimeoutMs > 0 ? Math.min(opts.connectTimeoutMs, callMs) : null;
  const onOuter = () => ac.abort(opts.signal?.reason);
  if (opts.signal) {
    if (opts.signal.aborted) onOuter();
    else opts.signal.addEventListener('abort', onOuter, { once: true });
  }
  const started = Date.now();
  const doFetch = opts.fetchImpl || fetch;
  try {
    const { redirect: _r, signal: _s, ...rest } = init;
    let res;
    try {
      // The caller already evaluated the egress policy for this endpoint; this is the only place a model request leaves the process.
      if (connectMs !== null && !opts.fetchImpl) await probeConnect(endpoint, connectMs);
      res = await doFetch(endpoint, { ...rest, redirect: 'error', signal: ac.signal }); // agentic-security-ignore: CWE-918
    } catch (e) {
      if (e instanceof ModelTransportError) throw e;
      if (ac.signal.aborted && ac.signal.reason instanceof ModelTransportError) throw ac.signal.reason;
      if (isAbort(e) || ac.signal.aborted) throw new ModelTransportError('timeout', `aborted after ${Date.now() - started} ms`, { cause: e });
      const msg = String(e?.cause?.message || e?.message || e);
      if (/redirect/i.test(msg)) throw new ModelTransportError('redirect', `the endpoint answered with a redirect, which is never followed: ${msg}`, { cause: e });
      throw new ModelTransportError('network', msg, { cause: e });
    }
    if (res.status >= 300 && res.status < 400) {
      // `redirect: 'error'` rejects before this point; a non-standard client or a 3xx without Location lands here
      ac.abort();
      throw new ModelTransportError('redirect', `the endpoint answered ${res.status}, which is never followed`, { status: res.status });
    }
    let body;
    try {
      body = await readCapped(res, maxBytes, () => ac.abort());
    } catch (e) {
      if (e instanceof ModelTransportError) throw e;
      if (ac.signal.aborted && ac.signal.reason instanceof ModelTransportError) throw ac.signal.reason;
      if (isAbort(e) || ac.signal.aborted) throw new ModelTransportError('timeout', `the response stalled after ${Date.now() - started} ms`, { cause: e });
      throw new ModelTransportError('network', String(e?.message || e), { cause: e });
    }
    const bytes = Buffer.byteLength(body, 'utf8');
    return {
      ok: res.ok, status: res.status, statusText: res.statusText, headers: res.headers, bytes,
      text: async () => body,
      json: async () => JSON.parse(body),
    };
  } finally {
    clearTimeout(timer);
    if (opts.signal) opts.signal.removeEventListener('abort', onOuter);
    budget.spentMs += Date.now() - started;
    budget.calls += 1;
  }
}
