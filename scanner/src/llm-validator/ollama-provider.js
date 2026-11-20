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
import { modelFetch } from '../egress/transport.js';
import { recordOOMEvent } from './oom-feedback.js';
import { isCloudModelName, remoteModelRefusal } from './cloud-model.js';

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
  'ollama-cancelled',
  'ollama-malformed-response',
  'ollama-tool-call-invalid',
  'ollama-tool-loop-limit',
  'ollama-version-unsupported',
  'ollama-remote-model-refused',
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
 * Since 0.195.31 (GA-06 §3) the shared transport enforces the connect
 * deadline for real: `connectTimeoutMs` aborts the request if no response
 * HEADERS arrive in time (a dead port, a stalled handshake), and is cleared
 * once they do, so a slow generation is bounded by `requestTimeoutMs` alone.
 * Before, the connect value was accepted and ignored. A caller's `signal`
 * reaches the transport too, so cancellation ends the request instead of
 * leaving it to run to its own timeout.
 */
async function _fetchOllama(url, init, { connectTimeoutMs, requestTimeoutMs, signal }) {
  try {
    // the shared transport: no redirect is followed, the reply is capped while it is read, the deadline is the total timeout
    const res = await modelFetch(url, init, { timeoutMs: requestTimeoutMs, connectTimeoutMs, signal });
    return { ok: true, res };
  } catch (e) {
    if (e?.code === 'connect-timeout' || e?.code === 'connect-refused') return _err('ollama-unreachable', `Ollama could not be connected to within the ${connectTimeoutMs}ms connect timeout (${e.message}).`);
    if (e?.code === 'timeout' && signal?.aborted) return _err('ollama-cancelled', 'the request was cancelled by its caller');
    if (e?.code === 'timeout') return _err('ollama-timeout', `Ollama request timed out after ${requestTimeoutMs}ms.`);
    if (e?.code === 'redirect') return _err('ollama-unreachable', `Ollama answered with a redirect, which is never followed: ${e.message}`);
    if (e?.code === 'response-too-large') return _err('ollama-malformed-response', e.message);
    if (e?.code === 'budget-exhausted') return _err('ollama-timeout', e.message);
    return _err('ollama-unreachable', e?.message || String(e));
  }
}

/**
 * Call `/api/chat`. Never falls back to any other provider on failure — the
 * caller receives a normalized `{ok:false, code, reason}` and decides what
 * that means (deterministic-only, another explicitly-configured local model,
 * or an explicit error), exactly as PRD §23.4 requires.
 */
export async function callOllamaChat({ host, model, messages, maxTokens, schema, tools, think, keepAlive, timeouts, signal, shortAnswer = false }) {
  // A loopback host promises local inference; refuse a model the server forwards elsewhere before any prompt is sent.
  const local = await verifyLocalOllamaModel({ host, model, timeouts, signal });
  if (!local.ok) return local;
  // A caller that wants a short structured answer turns a reasoning model's thinking off, where the model supports it
  // (Ollama's documented `think` field on /api/chat). An explicit `think` from the caller always wins.
  let effectiveThink = think;
  if (effectiveThink === undefined && shortAnswer && local.checked) {
    const caps = await _capabilitiesOf(host, model, timeouts);
    if (Array.isArray(caps) && caps.includes('thinking')) effectiveThink = false;
  }
  const body = buildOllamaChatBody({ model, messages, maxTokens, schema, tools, think: effectiveThink, keepAlive });
  const r = await _fetchOllama(`${host}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, { ...(timeouts || { connectTimeoutMs: DEFAULT_CONNECT_TIMEOUT_MS, requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS }), signal });
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

  const result = parseOllamaChatResponse(json, model);
  // Ollama truncates a prompt longer than the loaded context window without saying so; the evaluated prompt token count then
  // equals the window. Compare against the window the server reports for the loaded model and say so on the result.
  const contextLength = result.usage?.inputTokens >= 256 ? await _loadedContextLength(host, model, timeouts) : null;
  if (contextLength && result.usage.inputTokens >= contextLength - 1) {
    result.promptTruncated = true;
    result.contextLength = contextLength;
  }
  return { ok: true, result };
}

// ── local-only enforcement and per-model metadata ─────────────────────────────────────────────────────────────────────────────
// Listings are cached briefly per host so a pipeline of many calls does not double its request count; only a successful listing
// is cached, so a refusal or an outage is re-checked on the next call.
const LISTING_TTL_MS = 30 * 1000;
const _tagsCache = new Map();
const _capsCache = new Map();
const _psCache = new Map();
const _notOllama = new Map();

async function _rawTags(host, timeouts, signal) {
  const hit = _tagsCache.get(host);
  if (hit && Date.now() - hit.at < LISTING_TTL_MS) return { ok: true, models: hit.models };
  const r = await _fetchOllama(`${host}/api/tags`, { method: 'GET' },
    // the caller's connect setting as given (the chat it precedes uses the same), with the listing's own shorter deadline
    timeouts ? { connectTimeoutMs: timeouts.connectTimeoutMs, requestTimeoutMs: Math.min(10000, timeouts.requestTimeoutMs ?? 10000), signal }
      : { connectTimeoutMs: DEFAULT_CONNECT_TIMEOUT_MS, requestTimeoutMs: 10000, signal });
  if (!r.ok) return r;
  if (!r.res.ok) return { ..._err('ollama-unreachable', `the model listing (GET /api/tags) answered HTTP ${r.res.status}`), status: r.res.status };
  let json;
  try { json = await r.res.json(); } catch (e) { return _err('ollama-malformed-response', `the model listing was not JSON: ${e?.message || e}`); }
  const models = Array.isArray(json?.models) ? json.models : [];
  _tagsCache.set(host, { at: Date.now(), models });
  return { ok: true, models };
}

/**
 * Before a prompt is sent to a model on a LOOPBACK host, confirm from the server's own listing that the model runs here.
 * Fails closed: a model the listing marks remote, a cloud-tagged name, a model the listing does not contain, and a listing that
 * cannot be read are all refused. A non-loopback host (reachable only with AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE=1) is remote
 * inference by the operator's explicit choice and is not checked. Returns `{ok:true, checked}` or an error result.
 */
export async function verifyLocalOllamaModel({ host, model, timeouts, signal } = {}) {
  if (!isLoopbackUrl(host)) return { ok: true, checked: false };
  if (isCloudModelName(model)) return _err('ollama-remote-model-refused', remoteModelRefusal('ollama', model, 'cloud model tag'));
  const listing = await _rawTags(host, timeouts, signal);
  if (!listing.ok) {
    // a cancellation, a deadline and a malformed reply keep their own codes; anything else is an unreachable server
    const code = ['ollama-cancelled', 'ollama-timeout', 'ollama-malformed-response'].includes(listing.code) ? listing.code : 'ollama-unreachable';
    return _err(code, `could not confirm that model '${model}' runs on this machine: ${listing.reason}`);
  }
  const want = String(model || '');
  const entry = listing.models.find((m) => {
    const name = m?.name || m?.model || '';
    return name === want || (!want.includes(':') && name === `${want}:latest`);
  });
  if (!entry) return _err('ollama-model-not-installed', `Model '${model}' is not installed in this Ollama server, so it cannot be confirmed to run on this machine.`);
  if (entry.remote_host || entry.remote_model) {
    return _err('ollama-remote-model-refused', remoteModelRefusal('ollama', entry.name || model, `remote host ${entry.remote_host || 'reported by Ollama'}`));
  }
  return { ok: true, checked: true };
}

/**
 * The legacy `local` preset speaks an OpenAI-compatible shape to a loopback endpoint, which is often Ollama's own `/v1` API.
 * When the endpoint's server answers Ollama's listing, the same check applies; a loopback server that does not (another local
 * runtime) has no remote models to report, and only the name check (already applied in providers.js) holds.
 */
export async function verifyLocalPresetModel({ endpoint, model, timeouts, signal } = {}) {
  if (isCloudModelName(model)) return _err('ollama-remote-model-refused', remoteModelRefusal('local', model, 'cloud model tag'));
  let origin;
  try { origin = new URL(endpoint).origin; } catch { return { ok: true, checked: false }; }
  if (!isLoopbackUrl(origin)) return { ok: true, checked: false };
  const known = _notOllama.get(origin);
  if (known && Date.now() - known < LISTING_TTL_MS) return { ok: true, checked: false };
  const listing = await _rawTags(origin, timeouts, signal);
  if (!listing.ok) {
    // A caller's cancellation is not evidence about the server: stop here rather than go on to send the prompt.
    if (signal?.aborted || listing.code === 'ollama-cancelled') return _err('ollama-cancelled', 'the request was cancelled by its caller');
    // A server that answers but has no Ollama listing is another local runtime; remember it so each call does not ask again.
    if (listing.status) _notOllama.set(origin, Date.now());
    return { ok: true, checked: false };
  }
  const entry = listing.models.find((m) => (m?.name || m?.model) === model || (m?.name || m?.model) === `${model}:latest`);
  if (entry && (entry.remote_host || entry.remote_model)) {
    return _err('ollama-remote-model-refused', remoteModelRefusal('local', entry.name || model, `remote host ${entry.remote_host || 'reported by Ollama'}`));
  }
  return { ok: true, checked: !!entry };
}

async function _capabilitiesOf(host, model, timeouts) {
  const key = `${host}\0${model}`;
  if (_capsCache.has(key)) return _capsCache.get(key);
  const r = await showOllamaModel({ host, model, timeouts: { connectTimeoutMs: timeouts?.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS, requestTimeoutMs: 10000 } });
  const caps = r.ok ? r.capabilities : null;
  if (r.ok) _capsCache.set(key, caps);
  return caps;
}

async function _loadedContextLength(host, model, timeouts) {
  const key = `${host}\0${model}`;
  const hit = _psCache.get(key);
  if (hit && Date.now() - hit.at < LISTING_TTL_MS) return hit.contextLength;
  const r = await _fetchOllama(`${host}/api/ps`, { method: 'GET' }, { connectTimeoutMs: timeouts?.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS, requestTimeoutMs: 5000 });
  if (!r.ok || !r.res.ok) return null;
  let json;
  try { json = await r.res.json(); } catch { return null; }
  const entry = (Array.isArray(json?.models) ? json.models : []).find((m) => (m?.name || m?.model) === model || (m?.name || m?.model) === `${model}:latest`);
  const contextLength = Number.isInteger(entry?.context_length) && entry.context_length > 0 ? entry.context_length : null;
  if (contextLength) _psCache.set(key, { at: Date.now(), contextLength });
  return contextLength;
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
    const r = await callOllamaChat({ host, model, messages: attemptMessages, schema, maxTokens, keepAlive, timeouts, shortAnswer: true });
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
      // A model Ollama serves from a remote host (an Ollama "cloud" model) answers on the loopback port but forwards every
      // prompt off this machine. Reported so a caller that promises local-only inference can refuse it; null for a local model.
      remoteHost: typeof m.remote_host === 'string' && m.remote_host ? m.remote_host : null,
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

export const _internals = { _fetchOllama, resetModelCaches: () => { _tagsCache.clear(); _capsCache.clear(); _psCache.clear(); _notOllama.clear(); } };
