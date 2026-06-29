// Multi-provider model + pricing + cache catalog (PRD CACHE_ECONOMICS_V2, P2).
//
// One abstraction over four very different frameworks so the cost/cache advisor
// (sast/llm-cost-advisor.js) and the economics modules work uniformly. Captures,
// per provider: the model ladder (cheap→capable, with $/1M rates), the "depth"
// knob (Anthropic effort / OpenAI+xAI reasoning_effort / Gemini thinkingBudget),
// and the cache model (explicit vs automatic vs implicit; read/write economics).
//
// ⚠️ PRICES + MODEL NAMES DRIFT MONTHLY — this is a DATED snapshot, not truth.
// Anything that needs a live number must read it here and treat `sourcedAt` as
// the staleness signal; refresh from each provider's pricing/models API (or the
// claude-api skill for Anthropic) at implementation time. No network at runtime.
export const SOURCED_AT = '2026-06-29';

// $/1M tokens. `cached` = effective cached-input rate (Anthropic = read multiplier
// applied to `in`; others publish a cached-input price directly).
export const PROVIDERS = {
  anthropic: {
    label: 'Anthropic (Claude)',
    importMarkers: [/@anthropic-ai\b/, /\banthropic\b/, /\bClaude\b/],
    modelMarkers: [/\bclaude-/i, /\bopus\b/i, /\bsonnet\b/i, /\bhaiku\b/i],
    depth: { knob: 'effort', cheap: 'low', expensive: ['high', 'xhigh', 'max'], levels: ['low', 'medium', 'high', 'xhigh', 'max'] },
    cache: { kind: 'explicit', readMult: 0.1, writeMult: 1.25, minPrefixTokens: 1024, modelScoped: true, manualControl: true },
    models: [
      { id: 'claude-haiku-4-5',  match: /haiku/i,  tier: 0, in: 1, out: 5,  cached: 0.10 },
      { id: 'claude-sonnet-4-6', match: /sonnet/i, tier: 1, in: 3, out: 15, cached: 0.30 },
      { id: 'claude-opus-4-8',   match: /opus/i,   tier: 2, in: 5, out: 25, cached: 0.50 },
    ],
  },
  openai: {
    label: 'OpenAI',
    importMarkers: [/\bfrom openai\b/, /\bimport openai\b/, /@?openai\b/, /\bAzureOpenAI\b/],
    modelMarkers: [/\bgpt-/i, /\bo[34]-?mini\b/i, /\bo3\b/i],
    depth: { knob: 'reasoning_effort', cheap: 'low', expensive: ['high'], levels: ['minimal', 'low', 'medium', 'high'] },
    cache: { kind: 'automatic', cachedDiscount: 0.90, minPrefixTokens: 1024, modelScoped: true, manualControl: false },
    models: [
      { id: 'gpt-4.1-nano', match: /gpt-4\.1-nano/i, tier: 0, in: 0.10, out: 0.40, cached: 0.025 },
      { id: 'gpt-5-mini',   match: /gpt-5[.\d]*-mini/i, tier: 1, in: 0.60, out: 2.40, cached: 0.06 },
      { id: 'gpt-5.4',      match: /gpt-5\.4(?!-mini)/i, tier: 2, in: 2.50, out: 15, cached: 0.25 },
      { id: 'gpt-5.5',      match: /gpt-5\.5/i, tier: 3, in: 5, out: 30, cached: 0.50 },
    ],
    reasoningModels: [/\bo3\b/i, /\bo4-?mini\b/i],
  },
  google: {
    label: 'Google (Gemini)',
    importMarkers: [/google\.generativeai/, /\bgenai\b/, /@google\/genai/, /\bGenerativeModel\b/],
    modelMarkers: [/\bgemini-/i],
    depth: { knob: 'thinkingBudget', cheap: 'low budget', expensive: ['high budget'], levels: ['0', 'low', 'high', 'dynamic'] },
    cache: { kind: 'implicit-explicit', cachedDiscount: 0.90, minPrefixTokens: 1024, modelScoped: true, manualControl: 'optional', storagePriced: true },
    models: [
      { id: 'gemini-flash-lite',  match: /flash-lite/i, tier: 0, in: 0.10, out: 0.40, cached: 0.025 },
      { id: 'gemini-3.5-flash',   match: /3\.5-flash|2\.5-flash(?!-lite)/i, tier: 1, in: 1.50, out: 9, cached: 0.15 },
      { id: 'gemini-3.1-pro',     match: /3\.1-pro|2\.5-pro/i, tier: 2, in: 2, out: 12, cached: 0.30 },
    ],
  },
  xai: {
    label: 'xAI (Grok)',
    importMarkers: [/\bxai\b/i, /api\.x\.ai/, /\bGROK\b/i],
    modelMarkers: [/\bgrok-/i],
    depth: { knob: 'reasoning_effort', cheap: 'low', expensive: ['high'], levels: ['none', 'low', 'medium', 'high'] },
    cache: { kind: 'automatic', cachedDiscount: 0.85, minPrefixTokens: 1024, modelScoped: true, manualControl: false },
    models: [
      { id: 'grok-4.1-fast', match: /grok-4\.1-fast/i, tier: 0, in: 0.20, out: 0.50, cached: 0.05 },
      { id: 'grok-4.3',      match: /grok-4\.(3|20)/i, tier: 1, in: 1.25, out: 2.50, cached: 0.20 },
    ],
  },
};

// Detect the provider a file targets, from SDK import markers (preferred) then
// model-string markers. Returns a provider key or null.
export function detectProvider(raw) {
  if (typeof raw !== 'string' || !raw) return null;
  for (const [key, p] of Object.entries(PROVIDERS)) {
    if (p.importMarkers.some(re => re.test(raw))) return key;
  }
  for (const [key, p] of Object.entries(PROVIDERS)) {
    if (p.modelMarkers.some(re => re.test(raw))) return key;
  }
  return null;
}

// Which model-ladder entry does a model string map to (within a provider)?
export function modelEntry(provider, modelStr) {
  const p = PROVIDERS[provider];
  if (!p || typeof modelStr !== 'string') return null;
  return p.models.find(m => m.match.test(modelStr)) || null;
}

// A cheaper model in the same provider's ladder (one tier down), or null if the
// model is already the cheapest / unknown.
export function cheaperModel(provider, modelStr) {
  const p = PROVIDERS[provider];
  const cur = modelEntry(provider, modelStr);
  if (!p || !cur || cur.tier === 0) return null;
  const below = p.models.filter(m => m.tier < cur.tier).sort((a, b) => b.tier - a.tier)[0];
  return below || null;
}

export function depthAxis(provider) {
  return PROVIDERS[provider]?.depth || null;
}
export function cacheModel(provider) {
  return PROVIDERS[provider]?.cache || null;
}
