// PRD §13.2 — the three-layer model capability detection strategy.
//
// LAYER A (metadata) is the cheapest and most authoritative: Ollama's own
// `/api/show` response, when it reports a `capabilities` array, is not a
// guess. LAYER B (model-capabilities.js's family hint) is a non-authoritative
// default used only where Layer A is silent. LAYER C (this module's
// `probeStructuredOutput`/`probeToolCalling`) is the most expensive — it
// consumes real inference time — so it is OPT-IN (the caller decides when
// "necessary" per the PRD's own wording), never run implicitly on every
// `models doctor`/`models inspect` invocation.
//
// PRECEDENCE: Layer C overrides Layer A overrides Layer B, field by field. A
// field only ever gets overridden by a MORE authoritative layer that actually
// has an opinion — a probe that couldn't run (offline/timeout) leaves the
// field exactly as the layer below it set it, it never downgrades to
// 'unknown'.
//
// CACHE KEY = Ollama version + model digest + model name (PRD §13.2 exactly).
// Digest is load-bearing: `ollama pull` replacing a tag's underlying weights
// must invalidate the cache even though the name/tag string is unchanged.
// Same disk-cache directory convention as sca/sigstore-verify.js and
// engine.js's OSV cache (`~/.claude/agentic-security/<name>/`).
//
// TTL + force-reprobe (adversarial-review fix, 2026-09). The key-based
// invalidation above is real but not complete: this module's own comment
// used to claim the entry is safe "forever" because the key changes when
// the model does — but `/api/show` doesn't expose a digest on every Ollama
// version (falls back to model NAME alone then, a few lines below), so a
// same-tag re-pull, or simply an unlucky single-trial probe the first time
// (see probeStructuredOutput/probeToolCalling's own single-call design),
// had no way to ever self-correct short of a user manually deleting a file
// under `~/.claude/agentic-security/`. Two independent fixes, since either
// alone leaves a real gap: a default TTL as a safety net for the case
// nobody notices, and an explicit `force` option (`models test --force`)
// for the case someone DOES suspect a stale answer and wants it right now.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { callOllamaStructured, callOllamaChat, showOllamaModel, getOllamaVersion } from './ollama-provider.js';
import { capabilitiesFromFamilyHint } from './model-capabilities.js';

const CACHE_DIR = path.join(os.homedir(), '.claude', 'agentic-security', 'ollama-capability-cache');

// Default safety-net TTL: 30 days. Not the primary invalidation mechanism
// (the key is) — a backstop for the cases the key can't see: a same-tag
// re-pull on an Ollama version that doesn't expose a digest, or a single
// unlucky probe trial that happened to pass/fail against the model's true
// behavior. Overridable for anyone who wants a tighter or looser bound.
export const DEFAULT_CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function _ensureCacheDir() { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); } catch {} }
function _cacheKey(ollamaVersion, modelDigest, modelName) {
  return crypto.createHash('sha256').update(`${ollamaVersion}::${modelDigest}::${modelName}`).digest('hex');
}
function _cachePath(key) { return path.join(CACHE_DIR, key + '.json'); }

/**
 * @returns {object|null} the cached probe RESULT (not the envelope), or
 *   `null` on a miss, a parse failure, OR an entry older than `ttlMs`.
 */
function _readProbeCache(key, ttlMs) {
  let envelope;
  try { envelope = JSON.parse(fs.readFileSync(_cachePath(key), 'utf8')); } catch { return null; }
  // Backward-compatible with a pre-TTL cache file that was just the bare
  // result object (no `probedAt`) — treat an entry with no timestamp as
  // fresh rather than discarding every cache written before this fix.
  if (envelope && typeof envelope === 'object' && 'probedAt' in envelope && 'result' in envelope) {
    if (Number.isFinite(ttlMs) && ttlMs > 0 && Date.now() - envelope.probedAt > ttlMs) return null;
    return envelope.result;
  }
  return envelope;
}
function _writeProbeCache(key, value) {
  _ensureCacheDir();
  try { fs.writeFileSync(_cachePath(key), JSON.stringify({ probedAt: Date.now(), result: value })); } catch {}
}

/**
 * PRD §13.2 Layer A — parse `/api/show`'s response into the subset of
 * ModelCapabilities it can actually speak to. A field this layer has no
 * opinion on is omitted (not set to `false`) so the caller's merge never
 * mistakes silence for a negative.
 */
export function capabilitiesFromShowMetadata(show) {
  const out = { source: { metadata: true } };
  if (Array.isArray(show?.capabilities) && show.capabilities.length > 0) {
    const caps = show.capabilities;
    out.chat = caps.includes('completion') || caps.includes('chat');
    out.tools = caps.includes('tools');
    out.vision = caps.includes('vision');
    out.thinking = caps.includes('thinking');
  }
  const modelInfo = show?.modelInfo;
  if (modelInfo && typeof modelInfo === 'object') {
    const ctxKey = Object.keys(modelInfo).find((k) => k.endsWith('.context_length'));
    if (ctxKey && Number.isFinite(modelInfo[ctxKey])) out.contextTokens = modelInfo[ctxKey];
  }
  return out;
}

/**
 * PRD §13.2 Layer C — structured-output probe. A tiny schema, a request for
 * `{"ok": true}`, verified end to end through the SAME
 * callOllamaStructured() bounded-retry path every real structured call uses
 * (not a bespoke lighter-weight check that could disagree with production
 * behavior).
 */
const PROBE_SCHEMA = { type: 'object', required: ['ok'], properties: { ok: { type: 'boolean' } } };

export async function probeStructuredOutput({ host, model, timeouts, keepAlive } = {}) {
  const r = await callOllamaStructured({
    host, model,
    messages: [{ role: 'user', content: 'Reply with ONLY a JSON object: {"ok": true}' }],
    schema: PROBE_SCHEMA,
    validateFn: (obj) => (obj && obj.ok === true ? { ok: true, value: obj } : { ok: false }),
    keepAlive, timeouts,
  });
  if (r.ok) return { supported: true };
  // A transport-level failure (server unreachable, timed out) tells us
  // nothing about the MODEL's capability — leave it 'unknown' rather than
  // reporting a false negative for an offline/slow server.
  if (['ollama-unreachable', 'ollama-not-running', 'ollama-timeout', 'ollama-model-not-installed'].includes(r.code)) {
    return { supported: 'unknown', reason: r.reason || r.code };
  }
  return { supported: false, reason: r.reason || r.code };
}

/**
 * PRD §13.2 Layer C — tool-calling probe. One harmless `echo_capability_probe`
 * function; success is Ollama returning a structured `tool_calls` entry
 * naming it, not a check on what the model chose to reply with in prose.
 */
const PROBE_TOOL = {
  type: 'function',
  function: {
    name: 'echo_capability_probe',
    description: 'Echo back the given value. Used only to test whether this model supports tool calling.',
    parameters: { type: 'object', required: ['value'], properties: { value: { type: 'string' } } },
  },
};

export async function probeToolCalling({ host, model, timeouts, keepAlive } = {}) {
  const r = await callOllamaChat({
    host, model,
    messages: [{ role: 'user', content: 'Call the echo_capability_probe function with value set to "probe-ok". Reply with nothing else.' }],
    tools: [PROBE_TOOL],
    keepAlive, timeouts,
  });
  if (!r.ok) {
    if (['ollama-unreachable', 'ollama-not-running', 'ollama-timeout', 'ollama-model-not-installed'].includes(r.code)) {
      return { supported: 'unknown', reason: r.reason || r.code };
    }
    return { supported: false, reason: r.reason || r.code };
  }
  const calls = r.result.toolCalls || [];
  const called = calls.some((c) => c?.function?.name === 'echo_capability_probe');
  return called ? { supported: true } : { supported: false, reason: 'model did not emit a tool_calls entry for the probe function' };
}

function _mergeLayer(base, overlay, sourceFlag) {
  const merged = { ...base };
  let touched = false;
  for (const field of ['chat', 'structuredJson', 'tools', 'thinking', 'vision', 'contextTokens']) {
    if (overlay[field] !== undefined) { merged[field] = overlay[field]; touched = true; }
  }
  if (touched) merged.source = { ...merged.source, [sourceFlag]: true };
  return merged;
}

/**
 * Orchestrates all three layers (PRD §13.2) with caching (PRD: "so startup
 * does not repeatedly consume inference time"). `probe: true` opts into
 * Layer C — omitted or false, this returns Layer A+B only, which is what
 * every non-probing caller (models list/inspect/doctor's default path)
 * should use, since Layer C spends real inference time on the user's
 * machine.
 *
 * `force: true` (adversarial-review fix, 2026-09 — `models test --force`)
 * skips reading the cache — always runs a fresh probe and overwrites
 * whatever was there. `ttlMs` (default 30 days, `DEFAULT_CACHE_TTL_MS`)
 * bounds how long a cached entry is trusted without either; pass `0`/
 * `Infinity` to disable the TTL safety net entirely and rely on the key
 * alone, matching this module's original design intent.
 *
 * @returns {{ok:true, capabilities:object, cached:boolean} | {ok:false, code, reason}}
 */
export async function getModelCapabilities({ host, model, env = process.env, probe = false, force = false, ttlMs = DEFAULT_CACHE_TTL_MS, timeouts, keepAlive } = {}) {
  let capabilities = capabilitiesFromFamilyHint(model);

  const show = await showOllamaModel({ host, model, timeouts });
  if (show.ok) {
    capabilities = _mergeLayer(capabilities, capabilitiesFromShowMetadata(show), 'metadata');
  }

  if (!probe) {
    return { ok: true, capabilities, cached: false };
  }

  const versionResult = await getOllamaVersion({ host, timeouts });
  const ollamaVersion = versionResult.ok ? versionResult.version : 'unknown-version';
  // The digest is whatever Layer A's /api/show reported under `details`
  // (Ollama does not expose it on /api/show consistently across versions —
  // fall back to the model name alone, which still invalidates on a tag
  // change, just not on a same-tag re-pull).
  const modelDigest = show.ok && show.details?.digest ? show.details.digest : 'unknown-digest';
  const cacheKey = _cacheKey(ollamaVersion, modelDigest, model);

  const cached = force ? null : _readProbeCache(cacheKey, ttlMs);
  if (cached) {
    return { ok: true, capabilities: _mergeLayer(capabilities, cached, 'runtimeProbe'), cached: true };
  }

  const [structured, tools] = await Promise.all([
    probeStructuredOutput({ host, model, timeouts, keepAlive }),
    probeToolCalling({ host, model, timeouts, keepAlive }),
  ]);

  const probeResult = {};
  if (structured.supported !== 'unknown') probeResult.structuredJson = structured.supported;
  if (tools.supported !== 'unknown') probeResult.tools = tools.supported;

  // Only cache a probe that actually resolved something — an all-'unknown'
  // result (server unreachable mid-probe) would otherwise poison the cache
  // with a permanent non-answer.
  if (Object.keys(probeResult).length > 0) _writeProbeCache(cacheKey, probeResult);

  return { ok: true, capabilities: _mergeLayer(capabilities, probeResult, 'runtimeProbe'), cached: false };
}

export const _internals = { CACHE_DIR, _cacheKey, _cachePath };
