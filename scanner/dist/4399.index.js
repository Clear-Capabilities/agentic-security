export const id = 4399;
export const ids = [4399];
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


/***/ })

};
