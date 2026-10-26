export const id = 7039;
export const ids = [7039,4399];
export const modules = {

/***/ 54399:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   MEMORY_PROFILES: () => (/* binding */ MEMORY_PROFILES),
/* harmony export */   capabilitiesFromFamilyHint: () => (/* binding */ capabilitiesFromFamilyHint),
/* harmony export */   classifyModelFamily: () => (/* binding */ classifyModelFamily),
/* harmony export */   detectMemoryTier: () => (/* binding */ detectMemoryTier),
/* harmony export */   detectSystemMemory: () => (/* binding */ detectSystemMemory),
/* harmony export */   recommendAdmission: () => (/* binding */ recommendAdmission)
/* harmony export */ });
/* unused harmony exports KNOWN_MODEL_SIZE_GB, evaluateMemoryAdmission */
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(48161);
/* harmony import */ var _oom_feedback_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6782);
// Model family hints, RAM-aware memory profiles, and the memory-admission
// check for the Ollama provider (agentic-security-ollama-offline-prd.md
// §13, §14, §15, §22.3, §30).
//
// FAMILY HINTS ARE DEFAULTS, NEVER AUTHORITY (PRD §12/§13). A name like
// `gemma4:e2b` tells us nothing Ollama itself won't confirm — it only lets the
// harness suggest a sane default before any network call. If a model actually
// installed under a family-hinted name lacks a capability the hint implied,
// the runtime probe (model-probe.js, added when tool-calling/structured-output
// probing lands) always wins. This module only classifies and estimates; it
// never asserts a capability is present.
//
// MEMORY NUMBERS ARE ESTIMATES, NOT PROMISES (PRD §22.3, §14.1). Ollama
// artifact sizes and this module's headroom reserves are best-effort figures
// sourced from what Ollama currently publishes; they exist so the harness can
// fail BEFORE an OS-level OOM, not so it can claim an exact answer. Every
// admission decision leaves a stated safety margin rather than trying to pack
// memory to the byte.




// PRD §12/§13 FR-1203 — non-authoritative family hint from a model name.
// Longest/most-specific pattern first so `qwen3.5:4b` doesn't fall through to
// the bare `qwen` bucket.
const FAMILY_PATTERNS = [
  [/^qwen3\.5/i, 'qwen3.5'],
  [/^qwen3-coder-next/i, 'qwen3-coder-next'],
  [/^qwen3-coder/i, 'qwen3-coder'],
  [/^qwen2\.5-coder/i, 'qwen2.5-coder'],
  [/^qwen3/i, 'qwen3'],
  [/^qwen/i, 'qwen'],
  [/^gemma4/i, 'gemma4'],
  [/^functiongemma/i, 'functiongemma'],
  [/^gemma3/i, 'gemma3'],
  [/^gemma/i, 'gemma'],
];

/** Non-authoritative family classification for defaults/messaging only. */
function classifyModelFamily(modelName) {
  const name = String(modelName || '').trim();
  for (const [re, family] of FAMILY_PATTERNS) if (re.test(name)) return family;
  return 'unknown';
}

// PRD §13.1 — non-authoritative defaults per family, overridden by any real
// runtime probe result (model-probe.js). `tools`/`structuredJson`/`thinking`
// are 'unknown' where Ollama's own behavior varies by specific tag/quant
// rather than by family alone.
const FAMILY_CAPABILITY_HINTS = {
  'qwen3.5': { chat: true, structuredJson: true, tools: true, thinking: 'unknown' },
  qwen3: { chat: true, structuredJson: true, tools: true, thinking: 'unknown' },
  'qwen3-coder': { chat: true, structuredJson: true, tools: true, thinking: false },
  'qwen3-coder-next': { chat: true, structuredJson: true, tools: true, thinking: false },
  'qwen2.5-coder': { chat: true, structuredJson: true, tools: 'unknown', thinking: false },
  qwen: { chat: true, structuredJson: 'unknown', tools: 'unknown', thinking: 'unknown' },
  gemma4: { chat: true, structuredJson: true, tools: true, thinking: 'unknown' },
  functiongemma: { chat: true, structuredJson: 'unknown', tools: true, thinking: false },
  gemma3: { chat: true, structuredJson: true, tools: false, thinking: false },
  gemma: { chat: true, structuredJson: 'unknown', tools: 'unknown', thinking: 'unknown' },
  unknown: { chat: true, structuredJson: 'unknown', tools: 'unknown', thinking: 'unknown' },
};

/**
 * Build the PRD §13.1 ModelCapabilities object from a family hint alone
 * (Layer B). Layer A (Ollama's own /api/show metadata) and Layer C (runtime
 * probes) are applied by the caller and override these fields — this
 * function only ever sets `source.familyHint: true`.
 */
function capabilitiesFromFamilyHint(modelName) {
  const family = classifyModelFamily(modelName);
  const hint = FAMILY_CAPABILITY_HINTS[family] || FAMILY_CAPABILITY_HINTS.unknown;
  return {
    chat: hint.chat,
    structuredJson: hint.structuredJson,
    tools: hint.tools,
    thinking: hint.thinking,
    vision: false,
    contextTokens: undefined,
    source: { metadata: false, familyHint: true, runtimeProbe: false },
  };
}

// ── RAM-aware memory profiles (PRD §14.4, §15.2, §22.3, §30) ───────────────

const MB = 1024 * 1024;
const GB = 1024 * MB;

// Best-effort artifact sizes as currently distributed by Ollama, used only to
// pick a SENSIBLE STARTING recommendation — the real admission decision below
// uses actually-free memory, not this table. Keep in sync with the PRD's own
// cited figures; a stale entry only affects the suggested default, never the
// admission math (which reads real os.freemem()).
const KNOWN_MODEL_SIZE_GB = Object.freeze({
  'qwen3.5:2b': 1.7,
  'qwen3.5:4b': 3.4,
  'qwen3.5:9b': 6.6,
  'gemma4:e2b': 7.2,
  'gemma4:12b': 7.6,
  'gemma4:latest': 9.6,
});

/** PRD §30 profile presets. `auto` picks between these by detected RAM. */
const MEMORY_PROFILES = Object.freeze({
  '8gb': {
    label: '8gb',
    preferredModel: 'qwen3.5:4b',
    fallbackModel: 'qwen3.5:2b',
    initialContextTokens: 4096,
    targetContextTokens: 8192,
    maxConcurrency: 1,
    minFreeRamMb: 1536,
  },
  '16gb-qwen': {
    label: '16gb-qwen',
    preferredModel: 'qwen3.5:9b',
    fallbackModel: 'qwen3.5:4b',
    initialContextTokens: 16384,
    targetContextTokens: 32768,
    maxConcurrency: 1,
    minFreeRamMb: 2048,
  },
  '16gb-gemma': {
    label: '16gb-gemma',
    preferredModel: 'gemma4:e2b',
    fallbackModel: 'qwen3.5:4b',
    initialContextTokens: 8192,
    targetContextTokens: 16384,
    maxConcurrency: 1,
    minFreeRamMb: 2048,
  },
});

/**
 * PRD §22.3 — detect total/available system RAM. Thin wrapper over `os` so
 * tests can inject fake values without mocking the `os` module globally.
 */
function detectSystemMemory({ totalBytes, freeBytes } = {}) {
  return {
    totalBytes: Number.isFinite(totalBytes) ? totalBytes : node_os__WEBPACK_IMPORTED_MODULE_0__.totalmem(),
    freeBytes: Number.isFinite(freeBytes) ? freeBytes : node_os__WEBPACK_IMPORTED_MODULE_0__.freemem(),
  };
}

/**
 * Pick the RAM tier ('8gb' | '16gb') a machine falls into. Anything under
 * ~9 GB total is treated as the 8 GB tier — real "8 GB" machines report
 * slightly less than 8*1024^3 bytes to userspace (firmware/GPU reservations),
 * so a hard `< 8*GB` cutoff would misclassify real 8 GB hardware as unknown.
 */
function detectMemoryTier(totalBytes) {
  if (!Number.isFinite(totalBytes) || totalBytes <= 0) return 'unknown';
  if (totalBytes < 9 * GB) return '8gb';
  return '16gb';
}

/**
 * PRD §22.3 admission algorithm: does `contextTokens` at `model` fit in
 * currently-free memory with the configured reserve intact?
 *
 * This is deliberately conservative and coarse (PRD "avoid pretending memory
 * estimates are exact"): model residency is estimated from KNOWN_MODEL_SIZE_GB
 * when available (falling back to a pessimistic 8 GB assumption for an
 * unrecognized tag so an unknown model never LOOKS safer than a known large
 * one), and KV-cache growth is approximated as a fixed per-1K-token cost
 * rather than modeled per-architecture — real KV cache size depends on layer
 * count/head count/quantization the harness cannot know without Ollama's own
 * runtime numbers.
 */
const ESTIMATED_KV_CACHE_MB_PER_1K_TOKENS = 32; // conservative, model-independent approximation
const RUNTIME_OVERHEAD_MB = 512; // Ollama server + OS scheduler slack, independent of model size

function evaluateMemoryAdmission({
  modelName,
  contextTokens,
  freeBytes,
  minFreeRamMb,
  modelSizeGb,
} = {}) {
  const sizeGb = Number.isFinite(modelSizeGb) ? modelSizeGb : (KNOWN_MODEL_SIZE_GB[modelName] ?? 8);
  const modelMb = sizeGb * 1024;
  const kvCacheMb = (Number(contextTokens) || 0) / 1000 * ESTIMATED_KV_CACHE_MB_PER_1K_TOKENS;
  const requiredMb = modelMb + kvCacheMb + RUNTIME_OVERHEAD_MB + (Number(minFreeRamMb) || 0);
  const freeMb = (Number(freeBytes) || 0) / MB;
  const admitted = freeMb >= requiredMb;
  return {
    admitted,
    freeMb: Math.round(freeMb),
    requiredMb: Math.round(requiredMb),
    modelEstimateMb: Math.round(modelMb),
    kvCacheEstimateMb: Math.round(kvCacheMb),
    reserveMb: Number(minFreeRamMb) || 0,
  };
}

/**
 * Full recommendation flow (PRD §22 "Memory admission algorithm"):
 * try the profile's preferred context, shrink it, then fall back to the
 * profile's smaller model, before ever declaring the profile unusable.
 * Never recommends cloud — the worst outcome this function can return is
 * `{admitted:false}` with a human-readable explanation, which callers treat
 * as "run deterministic-only" (PRD §23.4).
 */
function recommendAdmission(opts = {}) {
  const result = _recommendAdmissionCore(opts);
  // Adversarial-review fix (2026-09): a memory-admission ESTIMATE that
  // actually caused a real OOM (ollama-provider.js's callOllamaChat now
  // records this via oom-feedback.js) used to have no way to affect a
  // future admission decision for the SAME model on the SAME machine — the
  // exact same "admitted: true" would repeat forever. This does not
  // recalibrate the underlying estimate (that needs real hardware variety
  // one machine's observed failures can't substitute for); it attaches an
  // honest warning so the decision is no longer presented with unqualified
  // confidence.
  const chosenModel = result.model || opts.requestedModel;
  const prior = chosenModel ? (0,_oom_feedback_js__WEBPACK_IMPORTED_MODULE_1__/* .priorOOMFor */ .NL)(chosenModel) : null;
  if (prior) {
    return {
      ...result,
      priorOOMWarning: `'${chosenModel}' has previously failed with an out-of-memory error on this machine ` +
        `(${prior.count} time${prior.count === 1 ? '' : 's'}, most recently ${new Date(prior.lastAt).toISOString()}). ` +
        'The memory estimate below may be optimistic for your hardware.',
    };
  }
  return result;
}

function _recommendAdmissionCore({ profile, freeBytes, requestedContextTokens, requestedModel } = {}) {
  const p = MEMORY_PROFILES[profile];
  if (!p) return { admitted: false, reason: `unknown memory profile '${profile}'` };

  const model = requestedModel || p.preferredModel;
  const attempts = [];

  // 1. Requested (or target) context at the requested/preferred model.
  const primaryContext = Number.isFinite(requestedContextTokens) ? requestedContextTokens : p.targetContextTokens;
  let check = evaluateMemoryAdmission({ modelName: model, contextTokens: primaryContext, freeBytes, minFreeRamMb: p.minFreeRamMb });
  attempts.push({ model, contextTokens: primaryContext, ...check });
  if (check.admitted) return { admitted: true, model, contextTokens: primaryContext, attempts };

  // 2. Reduce context to the profile's conservative initial value first —
  //    PRD FR-2104: "shrink context before declaring an otherwise compatible
  //    model unusable."
  if (primaryContext !== p.initialContextTokens) {
    check = evaluateMemoryAdmission({ modelName: model, contextTokens: p.initialContextTokens, freeBytes, minFreeRamMb: p.minFreeRamMb });
    attempts.push({ model, contextTokens: p.initialContextTokens, ...check });
    if (check.admitted) return { admitted: true, model, contextTokens: p.initialContextTokens, attempts, reducedContext: true };
  }

  // 3. Fall back to the profile's smaller model at its initial context.
  if (p.fallbackModel && p.fallbackModel !== model) {
    check = evaluateMemoryAdmission({ modelName: p.fallbackModel, contextTokens: p.initialContextTokens, freeBytes, minFreeRamMb: p.minFreeRamMb });
    attempts.push({ model: p.fallbackModel, contextTokens: p.initialContextTokens, ...check });
    if (check.admitted) {
      return {
        admitted: true, model: p.fallbackModel, contextTokens: p.initialContextTokens, attempts,
        reducedContext: true, fellBackToSmallerModel: true,
      };
    }
  }

  // 4. Nothing fits — deterministic-only, never cloud.
  return {
    admitted: false,
    attempts,
    reason: `No local model/context combination fit in available memory with the configured reserve. ` +
      `Recommend deterministic-only scanning, or free memory before retrying.`,
  };
}


/***/ }),

/***/ 27039:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getModelCapabilities: () => (/* binding */ getModelCapabilities)
/* harmony export */ });
/* unused harmony exports DEFAULT_CACHE_TTL_MS, capabilitiesFromShowMetadata, probeStructuredOutput, probeToolCalling, _internals */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(48161);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(77598);
/* harmony import */ var _ollama_provider_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(23837);
/* harmony import */ var _model_capabilities_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(54399);
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








const CACHE_DIR = node_path__WEBPACK_IMPORTED_MODULE_1__.join(node_os__WEBPACK_IMPORTED_MODULE_2__.homedir(), '.claude', 'agentic-security', 'ollama-capability-cache');

// Default safety-net TTL: 30 days. Not the primary invalidation mechanism
// (the key is) — a backstop for the cases the key can't see: a same-tag
// re-pull on an Ollama version that doesn't expose a digest, or a single
// unlucky probe trial that happened to pass/fail against the model's true
// behavior. Overridable for anyone who wants a tighter or looser bound.
const DEFAULT_CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function _ensureCacheDir() { try { node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(CACHE_DIR, { recursive: true }); } catch {} }
function _cacheKey(ollamaVersion, modelDigest, modelName) {
  return node_crypto__WEBPACK_IMPORTED_MODULE_3__.createHash('sha256').update(`${ollamaVersion}::${modelDigest}::${modelName}`).digest('hex');
}
function _cachePath(key) { return node_path__WEBPACK_IMPORTED_MODULE_1__.join(CACHE_DIR, key + '.json'); }

/**
 * @returns {object|null} the cached probe RESULT (not the envelope), or
 *   `null` on a miss, a parse failure, OR an entry older than `ttlMs`.
 */
function _readProbeCache(key, ttlMs) {
  let envelope;
  try { envelope = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(_cachePath(key), 'utf8')); } catch { return null; }
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
  try { node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(_cachePath(key), JSON.stringify({ probedAt: Date.now(), result: value })); } catch {}
}

/**
 * PRD §13.2 Layer A — parse `/api/show`'s response into the subset of
 * ModelCapabilities it can actually speak to. A field this layer has no
 * opinion on is omitted (not set to `false`) so the caller's merge never
 * mistakes silence for a negative.
 */
function capabilitiesFromShowMetadata(show) {
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

async function probeStructuredOutput({ host, model, timeouts, keepAlive } = {}) {
  const r = await (0,_ollama_provider_js__WEBPACK_IMPORTED_MODULE_4__/* .callOllamaStructured */ .uM)({
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

async function probeToolCalling({ host, model, timeouts, keepAlive } = {}) {
  const r = await (0,_ollama_provider_js__WEBPACK_IMPORTED_MODULE_4__/* .callOllamaChat */ .L5)({
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
async function getModelCapabilities({ host, model, env = process.env, probe = false, force = false, ttlMs = DEFAULT_CACHE_TTL_MS, timeouts, keepAlive } = {}) {
  let capabilities = (0,_model_capabilities_js__WEBPACK_IMPORTED_MODULE_5__.capabilitiesFromFamilyHint)(model);

  const show = await (0,_ollama_provider_js__WEBPACK_IMPORTED_MODULE_4__/* .showOllamaModel */ .$G)({ host, model, timeouts });
  if (show.ok) {
    capabilities = _mergeLayer(capabilities, capabilitiesFromShowMetadata(show), 'metadata');
  }

  if (!probe) {
    return { ok: true, capabilities, cached: false };
  }

  const versionResult = await (0,_ollama_provider_js__WEBPACK_IMPORTED_MODULE_4__/* .getOllamaVersion */ .zm)({ host, timeouts });
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

const _internals = { CACHE_DIR, _cacheKey, _cachePath };


/***/ })

};
