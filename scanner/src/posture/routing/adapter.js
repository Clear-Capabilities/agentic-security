// Provider adapter with auditable telemetry (X-602.AC03).
//
// One function turns a task run into an outcome record. It owns NO network client. Every call goes through guardedModelCall
// (assurance/bounded-io.js), which gates on the `model-routing` feature, evaluates the egress policy BEFORE the prompt exists, redacts
// the payload, enforces the request-size limit, runs the injected transport under a deadline with bounded retries, and appends each
// decision to the egress audit chain. The transport is the caller's: a test passes a fake, production passes whatever the operator
// configured. There is no default transport and no cloud fallback.
//
// The telemetry this module emits is built from an ALLOWLIST. It carries the provider id, model, endpoint HOST (no userinfo, path or
// query), status, a fixed failure code, token counts, cache state, latency and byte counts. It never carries the prompt, the response
// text, a transport error message (which can echo a request) or any credential, and nothing is added to it by spreading an object.
// The prompt/response stay with the caller; telemetry is what is safe to log, hash and calibrate on.
//
// Outcomes: provider failures, partial responses, cancellation, timeouts and cache hits are all kept as outcome records. A failed call
// yields a record with unknown (null) usage, never zero tokens and never a dropped row.

import { guardedModelCall } from '../assurance/bounded-io.js';
import { envPresent } from '../assurance/config.js';
import { payloadMetrics } from '../../egress/audit.js';
import { buildRoutingOutcome } from './outcomes.js';
import { costOf } from './economics.js';

/** Failure codes a provider error may carry into telemetry. Anything else becomes `unknown-failure`; the message is never kept. */
export const PROVIDER_FAILURE_CODES = Object.freeze(['rate-limit', 'server-error', 'overloaded', 'auth', 'bad-request', 'network', 'unknown-failure']);
const FINISH_REASONS = Object.freeze(['stop', 'length', 'content-filter', 'tool-use', 'error']);

const nonNegInt = (v) => (Number.isInteger(v) && v >= 0 ? v : null);

/** The endpoint reduced to scheme and host. A URL with userinfo or a query string (a common place for a key) loses both. */
export function endpointHost(endpoint) {
  try { const u = new URL(String(endpoint)); return `${u.protocol}//${u.host}`; } catch { return null; }
}

function usageOf(raw) {
  if (!raw || typeof raw !== 'object') return { inputTokens: null, outputTokens: null, cachedInputTokens: null, source: 'unknown' };
  const inputTokens = nonNegInt(raw.inputTokens);
  const outputTokens = nonNegInt(raw.outputTokens);
  let cachedInputTokens = nonNegInt(raw.cachedInputTokens);
  if (cachedInputTokens !== null && inputTokens !== null && cachedInputTokens > inputTokens) cachedInputTokens = null; // inconsistent: unknown, not clamped
  const reported = inputTokens !== null || outputTokens !== null;
  return { inputTokens, outputTokens, cachedInputTokens, source: reported ? 'measured' : 'unknown' };
}

function cacheStateOf(usage, hint) {
  if (usage.cachedInputTokens !== null && usage.inputTokens !== null) {
    if (usage.cachedInputTokens === 0) return 'miss';
    return usage.cachedInputTokens >= usage.inputTokens ? 'hit' : 'partial';
  }
  return ['hit', 'partial', 'miss', 'ineligible'].includes(hint) ? hint : 'unknown';
}

/**
 * Create an adapter for one provider model.
 *
 * @param {object} o
 * @param {object} o.config        resolveAssuranceConfig() result (the `model-routing` feature must be enabled)
 * @param {string} o.scanRoot
 * @param {string} o.provider      provider slot id (for example 'provider-a'), recorded in telemetry
 * @param {string} o.model
 * @param {string|null} [o.modelVersion]
 * @param {string|null} o.endpoint operator-configured; null yields a typed `missing-provider` outcome, never a default
 * @param {(req)=>Promise<{text:string, finishReason?:string, usage?:object, cacheState?:string}>} o.transport  injected; receives redacted text only
 * @param {object} [o.priceBook]
 * @param {{name:string, env?:object}|null} [o.credential]  names the environment variable the transport needs; only presence is checked
 * @param {()=>number} [o.clock]   monotonic milliseconds, injectable for tests
 */
export function createProviderAdapter({ config, scanRoot, provider, model, modelVersion = null, endpoint, transport, priceBook = null, credential = null, clock = () => Number(process.hrtime.bigint() / 1_000_000n) }) {
  return {
    provider, model, modelVersion,
    /**
     * Run one task. Always resolves to `{ outcome, telemetry, text }`: `outcome` is a validated routing-outcome record (or null if the
     * task itself was malformed), `telemetry` the allowlisted record, `text` the redacted-side response for the caller only.
     * `signal` lets the caller cancel; a cancelled run is recorded as `cancelled`, not dropped.
     */
    async invoke({ task, runId, prompt, filePath = null, signal = null, group = null, observedAt = null, purpose = 'routing-task' }) {
      const requirements = credential ? [{ kind: 'credential', name: credential.name, present: envPresent(credential.name, credential.env || process.env) }] : [];
      let captured = null; let failure = null; let cancelled = false; let calls = 0;
      const t0 = clock();
      const res = await guardedModelCall({
        config, featureId: 'model-routing', scanRoot, endpoint, purpose, text: prompt, filePath, model, requirements,
        call: async (req) => {
          calls += 1;
          if (signal?.aborted) { cancelled = true; const e = new Error('cancelled'); e.retryable = false; throw e; }
          const inner = signal ? AbortSignal.any([signal, req.signal]) : req.signal;
          let out;
          try {
            out = await Promise.race([
              transport({ endpoint: req.endpoint, text: req.text, signal: inner, timeoutMs: req.timeoutMs }),
              new Promise((_, rej) => { if (signal) signal.addEventListener('abort', () => { cancelled = true; const e = new Error('cancelled'); e.retryable = false; rej(e); }, { once: true }); }),
            ]);
          } catch (e) {
            if (!cancelled) failure = { code: PROVIDER_FAILURE_CODES.includes(e?.code) ? e.code : 'unknown-failure', retryable: !!e?.retryable };
            throw Object.assign(new Error(cancelled ? 'cancelled' : 'provider failure'), { retryable: !cancelled && !!e?.retryable });
          }
          captured = out && typeof out === 'object' ? out : { text: String(out ?? '') };
          return typeof captured.text === 'string' ? captured.text : '';
        },
      });
      const latencyMs = Math.max(0, clock() - t0);
      const promptMetrics = payloadMetrics(String(prompt ?? ''));

      let status; let code = res.code ?? null; let usage = usageOf(null); let finish = null; let hint = 'unknown';
      if (cancelled) { status = 'cancelled'; code = 'cancelled'; }
      else if (res.status === 'ok' || res.status === 'degraded') {
        usage = usageOf(captured?.usage);
        finish = FINISH_REASONS.includes(captured?.finishReason) ? captured.finishReason : null;
        hint = captured?.cacheState;
        status = res.truncated || finish === 'length' || finish === 'content-filter' ? 'partial' : 'completed';
      } else if (res.code === 'timeout') status = 'timeout';
      else if (failure) { status = 'provider-error'; code = failure.code; }
      else if (['egress-denied', 'missing-provider', 'missing-credential', 'limit-exceeded', 'disabled', 'kill-switch', 'platform-unsupported', 'invalid-config'].includes(res.code) || res.status === 'disabled') status = 'blocked';
      else status = 'failed';

      const attempts = Number.isInteger(res.attempts) ? res.attempts : calls;
      const retries = Math.max(0, attempts - 1);
      usage = { ...usage, retries };
      const cacheState = cacheStateOf(usage, hint);

      // Retries that reported no usage are bounded by the request size, never priced at zero.
      const cost = priceBook ? costOf({
        usage, model, priceBook, retries: Array.from({ length: retries }, () => ({})), estimatedRequestTokens: promptMetrics.tokenCount || null,
        toolExecutionUsd: 0, // this adapter runs no tools: a known zero, not an unmeasured one
      }) : null;
      const costUsd = cost && cost.totalStatus === 'measured' ? cost.totalUsd : null;
      const costStatus = cost ? cost.totalStatus : 'unknown';

      const built = buildRoutingOutcome({
        runId, task, model, modelVersion, status, outcome: status === 'completed' || status === 'partial' ? 'delayed' : 'unknown',
        group, usage, costUsd, costStatus, latencyMs, cacheState, observedAt, synthetic: !!task?.synthetic,
      });
      const telemetry = Object.freeze({
        provider, model, modelVersion, endpoint: endpointHost(endpoint), status, code, finishReason: finish, attempts, cacheState,
        usage: { inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, cachedInputTokens: usage.cachedInputTokens, retries, source: usage.source },
        latencyMs, requestBytes: promptMetrics.byteCount, requestTokensEstimated: promptMetrics.tokenCount, redactions: res.redactions ?? 0,
        cost: cost ? { priceVersion: cost.priceVersion, currency: cost.currency, billingBasis: cost.billingBasis, status: cost.totalStatus, lowerUsd: cost.totalLowerUsd, upperUsd: cost.totalUpperUsd } : null,
      });
      return { outcome: built.ok ? built.outcome : null, outcomeErrors: built.errors, telemetry, text: status === 'completed' || status === 'partial' ? (res.text ?? '') : '' };
    },
  };
}
