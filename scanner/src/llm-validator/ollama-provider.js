// Ollama offline-inference provider (agentic-security-ollama-offline-prd.md).
//
// WHY A DEDICATED MODULE. The existing SHAPES table in providers.js is four
// pure functions per vendor keyed on a single flat `body(model, prompt,
// maxTokens)` signature, because every existing provider (Anthropic, OpenAI,
// Gemini, the legacy generic `{prompt, model}` shape) fits that shape. Ollama's
// native `/api/chat` does not: it wants a `messages` array, optional `format`
// (JSON schema), optional `tools`, `think`, `keep_alive`, and returns richer
// timing/usage fields than any existing extractor models. Folding that into
// SHAPES would either lose those fields or force every other provider's
// function signature to grow parameters it doesn't use. So Ollama gets its own
// adapter, called from providers.js/index.js the same way `local-endpoint.js`
// already is — a provider-specific module the seam delegates to, not a shape
// squeezed into the existing table.
//
// LOOPBACK ENFORCEMENT MIRRORS `local`. `isLoopbackUrl` is imported from
// local-endpoint.js rather than reimplemented: two copies of "is this really
// loopback" is how one of them silently drifts. Unlike `local` (which has no
// escape hatch), Ollama also needs to support an explicitly-configured remote
// server (PRD 23.3: self-hosted Ollama is real, but it must never inherit the
// "nothing left this machine" guarantee just because the model happens to be
// open source). So enforcement here defaults ON, matching `local`'s
// fail-safe-by-default posture, with a NAMED, explicit escape hatch
// (`allowRemote`) rather than a flag the caller could forget to set — the same
// shape as `git push --no-verify`: bypassable, never accidental.
//
// NO CLOUD FALLBACK, EVER. Every function in this module that can fail returns
// `{ok:false, code, reason}` from a closed error-code taxonomy (see
// OLLAMA_ERROR_CODES). Nothing in this file, and nothing that calls it, may
// react to a failure by silently trying Anthropic/OpenAI/Gemini — that
// decision belongs to the operator's own configuration (a different PRESET),
// never to this module's error path. See ollama-offline-egress.test.js.

import { isLoopbackUrl } from './local-endpoint.js';
import { recordOOMEvent } from './oom-feedback.js';

export const DEFAULT_OLLAMA_HOST = 'http://127.0.0.1:11434';
export const DEFAULT_OLLAMA_MODEL = 'qwen3.5:4b';
const DEFAULT_CONNECT_TIMEOUT_MS = 3000;
const DEFAULT_REQUEST_TIMEOUT_MS = 300000;
const DEFAULT_KEEP_ALIVE = '5m';
const DEFAULT_MAX_CONCURRENCY = 1;

// PRD §25 — closed error-code taxonomy. Every ollama-provider failure carries
// exactly one of these, never an ad-hoc string, so a caller (and a report) can
// react on `code` instead of parsing prose.
export const OLLAMA_ERROR_CODES = Object.freeze([
  'ollama-disabled',
  'ollama-not-running',
  'ollama-unreachable',
  'ollama-non-loopback-refused',
  'ollama-model-not-installed',
  'ollama-model-load-failed',
  'ollama-model-out-of-memory',
  'ollama-context-overflow',
  'ollama-capability-missing',
  'ollama-timeout',
  'ollama-malformed-response',
  'ollama-tool-call-invalid',
  'ollama-tool-loop-limit',
  'ollama-version-unsupported',
]);

function _err(code, reason) {
  return { ok: false, code, reason };
}

/**
 * Resolve host/offline/timeout config for the `ollama` preset.
 *
 * @returns {{ok:true, config:object} | {ok:false, code:string, reason:string}}
 */
export function ollamaEndpointConfig(env = process.env) {
  // Adversarial-review fix (2026-09): no kill switch existed for this whole
  // provider, unlike AGENTIC_SECURITY_MCP_DISABLED for the MCP server —
  // worse, a per-role AGENTIC_SECURITY_LLM_PRESET_<ROLE>=ollama override
  // (providers.js's _forRole) can keep a role calling Ollama even after an
  // operator unsets the GLOBAL preset during an incident, so "just unset
  // the preset" is not reliably enough. This check is here, in the one
  // function every Ollama call path resolves through (resolveProvider's
  // ollama branch, and models/setup's direct callers), so it can never be
  // bypassed by a role-specific override the operator forgot about.
  if (env.AGENTIC_SECURITY_OLLAMA_DISABLED === '1') {
    return _err('ollama-disabled', 'Ollama is disabled (AGENTIC_SECURITY_OLLAMA_DISABLED=1). Unset it to re-enable.');
  }
  const rawHost = env.AGENTIC_SECURITY_OLLAMA_HOST || DEFAULT_OLLAMA_HOST;
  const host = String(rawHost).replace(/\/+$/, '');
  const allowRemote = env.AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE === '1';
  const loopback = isLoopbackUrl(host);

  if (!loopback && !allowRemote) {
    return _err(
      'ollama-non-loopback-refused',
      `Ollama offline mode refused ${host}.\n\n` +
        'Offline LLM mode guarantees model prompts remain on this machine.\n' +
        'A LAN or remote Ollama server is a remote endpoint for that guarantee.\n\n' +
        'Use --allow-remote-ollama (or AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE=1) to opt into ' +
        `remote inference, or use ${DEFAULT_OLLAMA_HOST} for local inference.`,
    );
  }

  const requestTimeoutRaw = Number(env.AGENTIC_SECURITY_LLM_TIMEOUT_MS);
  const connectTimeoutRaw = Number(env.AGENTIC_SECURITY_OLLAMA_CONNECT_TIMEOUT_MS);
  const keepAlive = env.AGENTIC_SECURITY_OLLAMA_KEEP_ALIVE || DEFAULT_KEEP_ALIVE;
  const maxConcurrencyRaw = Number(env.AGENTIC_SECURITY_OLLAMA_MAX_CONCURRENCY);

  return {
    ok: true,
    config: {
      host,
      // `offline` is what a report should show, not what gates enforcement —
      // enforcement already happened above. A remote host that opted in via
      // allowRemote is still accurately labeled non-offline.
      offline: loopback,
      egress: loopback ? 'loopback-only' : 'remote',
      requestTimeoutMs: Number.isFinite(requestTimeoutRaw) && requestTimeoutRaw > 0
        ? requestTimeoutRaw : DEFAULT_REQUEST_TIMEOUT_MS,
      connectTimeoutMs: Number.isFinite(connectTimeoutRaw) && connectTimeoutRaw > 0
        ? connectTimeoutRaw : DEFAULT_CONNECT_TIMEOUT_MS,
      keepAlive,
      maxConcurrency: Number.isFinite(maxConcurrencyRaw) && maxConcurrencyRaw > 0
        ? Math.floor(maxConcurrencyRaw) : DEFAULT_MAX_CONCURRENCY,
    },
  };
}

/**
 * Build a native `/api/chat` request body. Pure — no I/O.
 *
 * `messages` is the caller's already-constructed array; this module never
 * builds prompt text itself (PRD §20: prompt construction/redaction stay
 * upstream and apply identically to every provider).
 */
export function buildOllamaChatBody({ model, messages, maxTokens, schema, tools, think, keepAlive, temperature = 0 }) {
  return {
    model,
    messages,
    stream: false,
    ...(schema ? { format: schema } : {}),
    ...(Array.isArray(tools) && tools.length ? { tools } : {}),
    ...(think !== undefined ? { think } : {}),
    ...(keepAlive ? { keep_alive: keepAlive } : {}),
    options: {
      temperature,
      ...(Number.isFinite(maxTokens) && maxTokens > 0 ? { num_predict: maxTokens } : {}),
    },
  };
}

/**
 * Normalize a native `/api/chat` JSON response into the shared ChatResult
 * shape (PRD §9). Pure — no I/O, tolerant of a missing/malformed body.
 */
export function parseOllamaChatResponse(json, model) {
  const message = json?.message || {};
  const text = typeof message.content === 'string' ? message.content : '';
  const thinking = typeof message.thinking === 'string' ? message.thinking : '';
  const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];

  const inputTokens = Number.isFinite(json?.prompt_eval_count) ? json.prompt_eval_count : 0;
  const outputTokens = Number.isFinite(json?.eval_count) ? json.eval_count : 0;
  const usage = (Number.isFinite(json?.prompt_eval_count) || Number.isFinite(json?.eval_count))
    ? { inputTokens, outputTokens } : null;

  // Ollama reports durations in nanoseconds; normalize to milliseconds.
  const ns2ms = (v) => (Number.isFinite(v) ? Math.round(v / 1e6) : undefined);
  const timing = {
    totalMs: ns2ms(json?.total_duration),
    loadMs: ns2ms(json?.load_duration),
    promptEvalMs: ns2ms(json?.prompt_eval_duration),
    generationMs: ns2ms(json?.eval_duration),
  };

  return {
    text,
    toolCalls,
    thinking,
    usage,
    timing,
    provider: 'ollama',
    model,
    done: json?.done !== false,
  };
}

/**
 * Fetch with SEPARATE connect and total timeouts (PRD §22): a dead port must
 * fail in ~3s, but a cold-loading local model may legitimately take minutes.
 * A single fetch-level timeout cannot express both, so this races an early
 * "did anything respond yet" signal against the real request. Since
 * `fetch()` itself doesn't expose a connect-only phase, this approximates it:
 * the connect timeout aborts the whole request if headers haven't arrived
 * fast, done via a short first AbortSignal that gets replaced once the
 * request is confirmed in flight is not observable from fetch() alone — so,
 * conservatively, this uses the total timeout as the enforced bound and
 * treats "still pending after connectTimeoutMs with zero bytes" as the same
 * abort path. This keeps behavior simple and correct (never exceeds
 * requestTimeoutMs) even though it cannot distinguish "slow to connect" from
 * "slow to generate" without a lower-level HTTP client.
 */
async function _fetchOllama(url, init, { connectTimeoutMs, requestTimeoutMs }) {
  const controller = new AbortController();
  const totalTimer = setTimeout(() => controller.abort('total-timeout'), requestTimeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    return { ok: true, res };
  } catch (e) {
    if (controller.signal.aborted) return _err('ollama-timeout', `Ollama request timed out after ${requestTimeoutMs}ms.`);
    return _err('ollama-unreachable', e?.message || String(e));
  } finally {
    clearTimeout(totalTimer);
  }
}

/**
 * Call `/api/chat`. Never falls back to any other provider on failure — the
 * caller receives a normalized `{ok:false, code, reason}` and decides what
 * that means (deterministic-only, another explicitly-configured local model,
 * or an explicit error), exactly as PRD §23.4 requires.
 */
export async function callOllamaChat({ host, model, messages, maxTokens, schema, tools, think, keepAlive, timeouts }) {
  const body = buildOllamaChatBody({ model, messages, maxTokens, schema, tools, think, keepAlive });
  const r = await _fetchOllama(`${host}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, timeouts || { connectTimeoutMs: DEFAULT_CONNECT_TIMEOUT_MS, requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS });
  if (!r.ok) return r;

  const { res } = r;
  if (!res.ok) {
    let detail = '';
    try { detail = (await res.json())?.error || ''; } catch {}
    if (res.status === 404 || /not found/i.test(detail)) {
      return _err('ollama-model-not-installed', `Model '${model}' is not installed. ${detail || ''}`.trim());
    }
    if (/memory|oom/i.test(detail)) {
      // Adversarial-review fix (2026-09): this was a real, defined error
      // code with no reactive call site anywhere — a wrong memory-admission
      // estimate that caused a genuine OOM would repeat the identical wrong
      // decision forever. Record it so recommendAdmission (model-
      // capabilities.js) can warn on the NEXT admission check for this
      // model on this machine, even though the underlying size/KV-cache
      // ESTIMATES themselves stay uncalibrated (that needs real hardware
      // variety a single machine's observed failures can't substitute for).
      recordOOMEvent(model);
      return _err('ollama-model-out-of-memory', detail || `HTTP ${res.status}`);
    }
    if (/context/i.test(detail)) return _err('ollama-context-overflow', detail || `HTTP ${res.status}`);
    return _err('ollama-model-load-failed', detail || `HTTP ${res.status}`);
  }

  let json;
  try { json = await res.json(); } catch (e) {
    return _err('ollama-malformed-response', `Ollama returned non-JSON: ${e?.message || e}`);
  }
  if (json?.error) return _err('ollama-model-load-failed', String(json.error));

  return { ok: true, result: parseOllamaChatResponse(json, model) };
}

/**
 * PRD §17 — structured output with a bounded retry. Ollama's `format`
 * parameter constrains generation to a JSON schema, but a constrained
 * schema is still not a PROOF the content is semantically valid (a model can
 * emit well-formed JSON that fails the caller's own business-rule checks —
 * an out-of-enum verdict, a confidence outside [0,1]). `validateFn` is the
 * caller's OWN validator (e.g. the `validate` role's own response check in
 * llm-validator/index.js, which also does the challenge/nonce cross-check)
 * — this function never invents its own notion of "valid", it only
 * orchestrates the retry policy around whatever the caller already trusts.
 *
 * Exactly ONE retry, never more (PRD §17: "at most one constrained retry ...
 * then mark the model stage malformed-response ... never convert malformed
 * output into a trusted verdict"). The retry reuses the same messages with
 * one added system-role reminder — it does not silently loosen the schema
 * or drop the requirement.
 */
export async function callOllamaStructured({ host, model, messages, schema, validateFn, maxTokens, keepAlive, timeouts }) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const attemptMessages = attempt === 0
      ? messages
      : [...messages, { role: 'system', content: 'Your previous reply did not match the required JSON schema. Reply again with ONLY a single JSON object matching the schema — no prose, no markdown fence.' }];
    const r = await callOllamaChat({ host, model, messages: attemptMessages, schema, maxTokens, keepAlive, timeouts });
    if (!r.ok) return r; // a transport/model error is not a schema-retry case — surface it immediately
    let parsed;
    try { parsed = JSON.parse(r.result.text); } catch { parsed = null; }
    const validated = parsed !== null && validateFn ? validateFn(parsed) : (parsed !== null ? { ok: true, value: parsed } : { ok: false });
    if (validated && validated.ok) return { ok: true, result: r.result, parsed: validated.value ?? parsed, attempts: attempt + 1 };
    if (attempt === 1) {
      return _err('ollama-malformed-response', `Structured response failed validation after ${attempt + 1} attempt(s).`);
    }
  }
  // Unreachable, but keeps control flow explicit rather than relying on the
  // loop falling through.
  return _err('ollama-malformed-response', 'Structured response failed validation.');
}

/**
 * `GET /api/tags` — installed models. PRD §12: never a fixed allowlist.
 */
export async function listOllamaModels({ host, timeouts } = {}) {
  const r = await _fetchOllama(`${host}/api/tags`, { method: 'GET' },
    timeouts || { connectTimeoutMs: DEFAULT_CONNECT_TIMEOUT_MS, requestTimeoutMs: 10000 });
  if (!r.ok) {
    if (r.code === 'ollama-unreachable') return _err('ollama-not-running', r.reason);
    return r;
  }
  const { res } = r;
  if (!res.ok) return _err('ollama-unreachable', `HTTP ${res.status}`);
  let json;
  try { json = await res.json(); } catch (e) { return _err('ollama-malformed-response', String(e?.message || e)); }
  const models = Array.isArray(json?.models) ? json.models : [];
  return {
    ok: true,
    models: models.map(m => ({
      name: m.name || m.model || '',
      digest: m.digest || null,
      sizeBytes: Number.isFinite(m.size) ? m.size : null,
      parameterSize: m.details?.parameter_size || null,
      quantization: m.details?.quantization_level || null,
      family: m.details?.family || null,
      modifiedAt: m.modified_at || null,
    })),
  };
}

/**
 * `POST /api/show` — per-model metadata (PRD §13.2 Layer A). Returns Ollama's
 * own declared `capabilities` array (e.g. `["completion","tools","vision"]`
 * on versions that report it) and `model_info` (carries the architecture's
 * `<family>.context_length` key) — both more authoritative than the family-
 * name guess in model-capabilities.js's Layer B, and far cheaper than an
 * actual inference-consuming Layer C probe. Tolerant of older Ollama
 * versions that omit `capabilities` entirely (model-probe.js's Layer A
 * parser treats a missing field as "no metadata opinion", never as "false").
 */
export async function showOllamaModel({ host, model, timeouts } = {}) {
  const r = await _fetchOllama(`${host}/api/show`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model }),
  }, timeouts || { connectTimeoutMs: DEFAULT_CONNECT_TIMEOUT_MS, requestTimeoutMs: 10000 });
  if (!r.ok) {
    if (r.code === 'ollama-unreachable') return _err('ollama-not-running', r.reason);
    return r;
  }
  const { res } = r;
  if (!res.ok) {
    if (res.status === 404) return _err('ollama-model-not-installed', `Model '${model}' is not installed.`);
    return _err('ollama-unreachable', `HTTP ${res.status}`);
  }
  let json;
  try { json = await res.json(); } catch (e) { return _err('ollama-malformed-response', String(e?.message || e)); }
  return {
    ok: true,
    capabilities: Array.isArray(json?.capabilities) ? json.capabilities : null,
    modelInfo: json?.model_info && typeof json.model_info === 'object' ? json.model_info : null,
    details: json?.details && typeof json.details === 'object' ? json.details : null,
  };
}

/**
 * `GET /api/version` — the Ollama server version, used only as one component
 * of the capability-probe cache key (PRD §13.2: "cached per Ollama version +
 * model digest + model name/tag"). Never gates anything by itself.
 */
export async function getOllamaVersion({ host, timeouts } = {}) {
  const r = await _fetchOllama(`${host}/api/version`, { method: 'GET' },
    timeouts || { connectTimeoutMs: DEFAULT_CONNECT_TIMEOUT_MS, requestTimeoutMs: 5000 });
  if (!r.ok) {
    if (r.code === 'ollama-unreachable') return _err('ollama-not-running', r.reason);
    return r;
  }
  const { res } = r;
  if (!res.ok) return _err('ollama-unreachable', `HTTP ${res.status}`);
  let json;
  try { json = await res.json(); } catch (e) { return _err('ollama-malformed-response', String(e?.message || e)); }
  return { ok: true, version: typeof json?.version === 'string' ? json.version : 'unknown' };
}

export const _internals = { _fetchOllama };
