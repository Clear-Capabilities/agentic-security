// Bounded I/O and the single route for new model/network calls (CORE-004).
//
// There is deliberately NO HTTP client in this module. `guardedModelCall` takes
// the transport as an argument (`call`), so it cannot become a way around the
// existing egress layer: before `call` is ever invoked, the request is
//   1. gated by the feature configuration (disabled, killed, unsupported),
//   2. checked for a configured endpoint (never defaulted, never a cloud fallback),
//   3. evaluated by egress/policy.js evaluateEgress(), BEFORE any payload is built,
//   4. redacted by egress/redact.js redactPayload(), so `call` only ever sees
//      redacted text,
//   5. size-checked against the finite request limit.
// Only then is it run under a deadline with a bounded retry count, and its output
// is capped. Every decision is appended to the existing egress audit chain.
//
// Every limit named here is enforced by a function in this file; limits that this
// layer cannot enforce are disclosed as such by config.js, not claimed.

import * as fs from 'node:fs';
import { evaluateEgress } from '../../egress/policy.js';
import { redactPayload } from '../../egress/redact.js';
import { recordEgressCall, payloadMetrics } from '../../egress/audit.js';
import { typed, featureStatus, evaluateRequirements, limitValues } from './config.js';

/** Read a file, refusing anything larger than `maxBytes`. Reads at most maxBytes+1, so a file that grows after the size check cannot exhaust memory. */
export function readFileBounded(filePath, maxBytes) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) return typed('blocked', 'invalid-config', 'maxBytes must be a positive integer');
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return typed('blocked', 'limit-exceeded', 'not a regular file');
    if (st.size > maxBytes) return typed('blocked', 'limit-exceeded', `file is ${st.size} bytes, over the ${maxBytes} byte limit`, { bytes: st.size });
    const buf = Buffer.alloc(maxBytes + 1);
    const n = fs.readSync(fd, buf, 0, maxBytes + 1, 0);
    if (n > maxBytes) return typed('blocked', 'limit-exceeded', `file grew past the ${maxBytes} byte limit while reading`);
    return typed('ok', null, 'read', { text: buf.subarray(0, n).toString('utf8'), bytes: n });
  } catch (e) {
    return typed('blocked', 'missing-dependency', `cannot read ${filePath}: ${e.code || e.message}`);
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* already closed */ } }
  }
}

/** Cap a string to `maxBytes` of UTF-8 without splitting a character. */
export function capOutput(text, maxBytes) {
  const s = typeof text === 'string' ? text : String(text ?? '');
  const bytes = Buffer.byteLength(s, 'utf8');
  if (bytes <= maxBytes) return { text: s, truncated: false, bytes };
  let cut = Buffer.from(s, 'utf8').subarray(0, maxBytes).toString('utf8');
  if (cut.endsWith('�')) cut = cut.slice(0, -1); // a multi-byte character was split at the boundary
  return { text: cut, truncated: true, bytes };
}

/** Run `fn(signal)` under a hard deadline. The timer is always cleared; a timeout aborts the signal and resolves to a typed result. */
export async function withDeadline(fn, ms) {
  const ac = new AbortController();
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => { ac.abort(); resolve(typed('blocked', 'timeout', `no result within ${ms} ms`)); }, ms);
  });
  try {
    const run = Promise.resolve().then(() => fn(ac.signal)).then(
      (value) => ({ ok: true, value }),
      (error) => ({ ok: false, error }),
    );
    const winner = await Promise.race([run, timeout]);
    if (winner && winner.ok === true) return typed('ok', null, 'completed', { value: winner.value });
    if (winner && winner.ok === false) return { status: 'error', error: winner.error };
    return winner;
  } finally { clearTimeout(timer); }
}

/** At most `retries` extra attempts, and only for failures the callee marks `retryable`. */
export async function retryBounded(fn, { retries, backoffMs = 0 } = {}) {
  const max = Math.max(0, Math.min(Number.isInteger(retries) ? retries : 0, 10));
  let attempts = 0;
  for (;;) {
    attempts += 1;
    const r = await fn(attempts);
    if (r.status !== 'error' || !r.error?.retryable || attempts > max) return { ...r, attempts };
    if (backoffMs > 0) await new Promise(res => setTimeout(res, Math.min(backoffMs * attempts, 5000)));
  }
}

/**
 * The only way a new feature makes a model or network call.
 *
 * @param {object} p
 * @param {object} p.config      resolveAssuranceConfig() result
 * @param {string} p.featureId
 * @param {string} p.scanRoot
 * @param {string|null} p.endpoint   MUST come from operator configuration; null yields `missing-provider`
 * @param {string} p.purpose
 * @param {string} p.text            the prompt/payload, BEFORE redaction
 * @param {string|null} [p.filePath]
 * @param {string|null} [p.model]
 * @param {Array} [p.requirements]   extra requirements (e.g. a credential), evaluated before any call
 * @param {(req:{endpoint:string,text:string,signal:AbortSignal,timeoutMs:number})=>Promise<string>} p.call  injected transport
 */
export async function guardedModelCall({ config, featureId, scanRoot, endpoint, purpose, text, filePath = null, model = null, requirements = [], call }) {
  const gate = featureStatus(config, featureId);
  if (gate.status !== 'ok') return gate;
  const limits = limitValues(config);

  if (!endpoint || typeof endpoint !== 'string') {
    return typed('blocked', 'missing-provider', `${featureId} has no model endpoint configured; there is no default and no cloud fallback`, { feature: featureId });
  }
  const { missingRequired } = evaluateRequirements(requirements);
  if (missingRequired.length) {
    const m = missingRequired[0];
    return typed('blocked', m.code, `${featureId} needs ${m.kind} '${m.name}', which is not available`, { feature: featureId, missing: missingRequired });
  }
  if (typeof call !== 'function') return typed('blocked', 'missing-dependency', 'no transport supplied', { feature: featureId });

  // egress policy BEFORE the prompt is built or any client is touched
  const ctx = { scanRoot, purpose, endpoint, model, path: filePath };
  const decision = evaluateEgress(ctx);
  if (!decision.allowed) {
    recordEgressCall({ scanRoot, decision, ctx });
    return typed('blocked', 'egress-denied', decision.reason || 'egress policy denied the call', { feature: featureId, decision });
  }

  // redaction BEFORE request construction
  const redacted = redactPayload({ text: String(text ?? ''), filePath, scanRoot });
  const metrics = payloadMetrics(redacted.text);
  if (metrics.byteCount > limits.maxRequestBytes) {
    recordEgressCall({ scanRoot, decision: { ...decision, allowed: false, decision: 'deny', reason: 'request over maxRequestBytes' }, ctx });
    return typed('blocked', 'limit-exceeded', `request is ${metrics.byteCount} bytes, over the ${limits.maxRequestBytes} byte limit`, { feature: featureId });
  }
  recordEgressCall({ scanRoot, decision, ctx, metrics });

  const run = await retryBounded(
    () => withDeadline((signal) => call({ endpoint, text: redacted.text, signal, timeoutMs: limits.timeoutMs }), limits.timeoutMs),
    { retries: limits.retries },
  );
  if (run.status === 'error') {
    return typed('blocked', 'missing-dependency', `model call failed: ${String(run.error?.message || run.error)}`, { feature: featureId, attempts: run.attempts });
  }
  if (run.status !== 'ok') return { ...run, feature: featureId, attempts: run.attempts };
  const out = capOutput(run.value, limits.maxOutputBytes);
  const status = out.truncated ? 'degraded' : 'ok';
  return typed(status, out.truncated ? 'limit-exceeded' : null, out.truncated ? `output truncated to ${limits.maxOutputBytes} bytes` : 'completed', {
    feature: featureId, text: out.text, truncated: out.truncated, attempts: run.attempts, redactions: redacted.redactions,
  });
}
