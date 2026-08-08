// PRD Epic 3 — the model-neutral seam.
//
// The deterministic engine has never depended on a model. The only coupling was
// here, in how an AI call is shaped: one hardcoded pair of request builders and
// one `endpointConfig` that knew about exactly two presets. This module makes
// the provider a parameter instead, so an OpenAI or Gemini shop — or a
// regulated org that cannot send code to any vendor — is a configuration
// change rather than a fork.
//
// WHAT A PROVIDER IS. Endpoint, auth header shape, request body, and how to
// read text and token usage back out. Nothing else. Prompt construction,
// redaction, response validation, the challenge/nonce cross-check and the cost
// ceiling all stay upstream and apply identically to every provider — those are
// the security properties, and they must not become per-vendor.
//
// PER-ROLE PINNING. The strong pipelines route cheap models at triage and
// frontier models at synthesis. `resolveProvider({ role })` reads a per-role
// override before the global one, so `AGENTIC_SECURITY_LLM_MODEL_VERIFY` can
// point at something cheap while `..._FIX` points at something capable. Roles
// are a closed set: an unknown role would silently fall back to the global
// model, which is how a "cheap verify" quietly becomes an expensive one.
//
// GRACEFUL DEGRADATION IS THE DEFAULT. No provider configured means no AI
// stages — the engine still returns its deterministic findings. That is the
// existing behaviour and it is load-bearing: adding providers must not make the
// scanner require one.
//
// THE LOCAL PATH KEEPS ITS GUARANTEE. `local` still routes through
// `local-endpoint.js`, which enforces loopback on the host literal. A provider
// abstraction must not become a way to smuggle a remote endpoint into the mode
// whose entire promise is that nothing leaves the machine.

import { localEndpointConfig } from './local-endpoint.js';

// Roles the pipeline dispatches under. Closed set on purpose — see above.
export const ROLES = Object.freeze([
  'validate',   // the FP-suppression validator (the original caller)
  'verify',     // adversarial verification (Epic 2) — cheap tier by default
  'explain',    // human-facing explanation
  'fix',        // patch synthesis
  'poc',        // proof-of-concept synthesis (Epic 1)
  'logic',      // cross-file business-logic reasoning (Epic 6)
]);

const ANTHROPIC_VERSION = '2023-06-01';

// ── Request/response shapes, one per wire protocol ──────────────────────────
//
// Kept as data rather than subclasses: each is four small functions, and a flat
// table makes it obvious what a new provider must supply.
const SHAPES = {
  anthropic: {
    headers: () => ({ 'Content-Type': 'application/json', 'anthropic-version': ANTHROPIC_VERSION }),
    auth: (h, key) => { if (key) h['x-api-key'] = key; },
    body: (model, prompt, maxTokens) => ({ model, max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] }),
    text: (j) => (Array.isArray(j?.content) ? j.content.filter(b => b?.type === 'text').map(b => b.text || '').join('') : ''),
    usage: (j) => (j?.usage && Number.isFinite(j.usage.input_tokens)
      ? { inputTokens: j.usage.input_tokens, outputTokens: j.usage.output_tokens || 0 } : null),
  },
  // OpenAI-compatible: also what most local servers speak, which is why the
  // `local` provider reuses it rather than inventing a third shape.
  openai: {
    headers: () => ({ 'Content-Type': 'application/json' }),
    auth: (h, key) => { if (key) h.Authorization = `Bearer ${key}`; },
    body: (model, prompt, maxTokens) => ({ model, max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] }),
    text: (j) => j?.choices?.[0]?.message?.content || j?.choices?.[0]?.text || '',
    usage: (j) => {
      const u = j?.usage; if (!u) return null;
      const inputTokens = u.prompt_tokens ?? u.input_tokens;
      const outputTokens = u.completion_tokens ?? u.output_tokens ?? 0;
      return Number.isFinite(inputTokens) ? { inputTokens, outputTokens } : null;
    },
  },
  // The LEGACY generic shape: `{prompt, model}` with a permissive extractor.
  // This is what BYO endpoints and local servers have always been sent, and
  // existing deployments speak it. Assuming OpenAI-compatibility here would
  // silently break every one of them, so the OpenAI shape is used ONLY when the
  // operator explicitly asks for the openai preset.
  generic: {
    headers: () => ({ 'Content-Type': 'application/json' }),
    auth: (h, key) => { if (key) h.Authorization = `Bearer ${key}`; },
    body: (model, prompt) => ({ prompt, model }),
    text: (j) => (j && (j.response || j.text || j.content || j.output
      || j.choices?.[0]?.message?.content || j.message?.content)) || '',
    usage: (j) => {
      const u = j?.usage; if (!u) return null;
      const inputTokens = u.prompt_tokens ?? u.input_tokens;
      const outputTokens = u.completion_tokens ?? u.output_tokens ?? 0;
      return Number.isFinite(inputTokens) ? { inputTokens, outputTokens } : null;
    },
  },
  gemini: {
    headers: () => ({ 'Content-Type': 'application/json' }),
    // Gemini takes the key on the query string; the caller appends it, so the
    // header set stays empty rather than carrying a bearer token that the API
    // would ignore.
    auth: () => {},
    body: (model, prompt, maxTokens) => ({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: maxTokens },
    }),
    text: (j) => (j?.candidates?.[0]?.content?.parts || []).map(p => p?.text || '').join(''),
    usage: (j) => {
      const u = j?.usageMetadata; if (!u) return null;
      return Number.isFinite(u.promptTokenCount)
        ? { inputTokens: u.promptTokenCount, outputTokens: u.candidatesTokenCount || 0 } : null;
    },
  },
};

const DEFAULT_MODEL = {
  anthropic: 'claude-haiku-4-5',
  openai: 'gpt-4o-mini',
  gemini: 'gemini-2.0-flash',
  local: 'local-model',
};

function _envKey(role, suffix) {
  return `AGENTIC_SECURITY_LLM_${suffix}_${String(role).toUpperCase()}`;
}

/** Per-role override, falling back to the global setting. */
function _forRole(env, role, suffix) {
  if (role && ROLES.includes(role)) {
    const v = env[_envKey(role, suffix)];
    if (v) return v;
  }
  return env[`AGENTIC_SECURITY_LLM_${suffix}`];
}

/**
 * Resolve the provider for a role.
 *
 * @returns {{ok:true, config:object} | {ok:false, reason:string|null}}
 *   `ok:false` with `reason:null` means "no AI configured", which is the normal
 *   default and NOT an error. A non-null reason means a configuration was
 *   supplied and refused — those must be surfaced, not silently treated the
 *   same as "off".
 */
export function resolveProvider({ role = 'validate', env = process.env } = {}) {
  const explicit = (_forRole(env, role, 'PRESET') || '').toLowerCase();
  const model = _forRole(env, role, 'MODEL');

  // 1. Local — checked first because it is the only mode that makes a promise
  //    about where data goes, and a stray endpoint must not override it.
  if (explicit === 'local') {
    const r = localEndpointConfig(env);
    if (!r.ok) return { ok: false, reason: r.reason };
    return {
      ok: true,
      config: {
        provider: 'local', shape: SHAPES.generic, endpoint: r.config.endpoint,
        apiKey: r.config.apiKey, model: model || r.config.model,
        egress: 'loopback-only', role,
      },
    };
  }

  // 2. Explicit BYO endpoint — checked BEFORE the vendor presets because that
  //    is the documented precedence: an operator who names an endpoint means
  //    that endpoint, even with a preset also set. Reversing it would silently
  //    redirect traffic to a vendor.
  const byoEndpoint = _forRole(env, role, 'ENDPOINT');
  if (byoEndpoint) {
    return {
      ok: true,
      config: {
        provider: 'byo', shape: SHAPES.generic, endpoint: byoEndpoint,
        apiKey: _forRole(env, role, 'API_KEY') || null,
        model: model || 'unknown', egress: 'remote', role,
      },
    };
  }

  // 3. Explicit vendor presets.
  if (explicit === 'anthropic' || explicit === 'openai' || explicit === 'gemini') {
    const apiKey = _forRole(env, role, 'API_KEY')
      || (explicit === 'anthropic' ? env.ANTHROPIC_API_KEY
        : explicit === 'openai' ? env.OPENAI_API_KEY
          : env.GEMINI_API_KEY || env.GOOGLE_API_KEY);
    // No key -> the tier is off, not broken. Same offline-degrading rule the
    // anthropic preset has always had.
    if (!apiKey) return { ok: false, reason: null };
    const m = model || DEFAULT_MODEL[explicit];
    const endpoint = (
      explicit === 'anthropic' ? 'https://api.anthropic.com/v1/messages'
        : explicit === 'openai' ? 'https://api.openai.com/v1/chat/completions'
          : `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${encodeURIComponent(apiKey)}`
    );
    return {
      ok: true,
      config: {
        provider: explicit, shape: SHAPES[explicit], endpoint,
        apiKey: explicit === 'gemini' ? null : apiKey, model: m, egress: 'remote', role,
      },
    };
  }

  // 4. Nothing configured — deterministic engine only.
  return { ok: false, reason: null };
}

/** Build the HTTP call for a resolved provider. Pure. */
export function buildProviderRequest(config, prompt, maxTokens) {
  const headers = config.shape.headers();
  config.shape.auth(headers, config.apiKey);
  return {
    headers,
    body: config.shape.body(config.model, prompt, maxTokens),
    extractText: config.shape.text,
    extractUsage: config.shape.usage,
  };
}

/** Which provider each role would use, for reporting. Never includes keys. */
export function providerMatrix(env = process.env) {
  const out = {};
  for (const role of ROLES) {
    const r = resolveProvider({ role, env });
    out[role] = r.ok
      ? { provider: r.config.provider, model: r.config.model, egress: r.config.egress }
      : { provider: null, reason: r.reason || 'not configured' };
  }
  return out;
}

export const _internals = { SHAPES, DEFAULT_MODEL, _forRole };
