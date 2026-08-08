// PRD Epic 3 — the model-neutral seam.
//
// The properties worth pinning are not "does it build a request" but the ones
// that keep the security story intact while the provider becomes a parameter:
// no AI configured must still mean a working deterministic scan, the local
// preset must keep its loopback guarantee, keys must never leak into reports,
// and a per-role pin must actually take effect (otherwise "cheap verify"
// silently becomes an expensive one).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveProvider, buildProviderRequest, providerMatrix, ROLES, _internals,
} from '../src/llm-validator/providers.js';

test('nothing configured is OFF, not an error', () => {
  // Load-bearing: adding providers must not make the scanner require one.
  const r = resolveProvider({ env: {} });
  assert.equal(r.ok, false);
  assert.equal(r.reason, null, 'an absent config must not read as a refusal');
});

test('a vendor preset with no key is off, not broken', () => {
  for (const preset of ['anthropic', 'openai', 'gemini']) {
    const r = resolveProvider({ env: { AGENTIC_SECURITY_LLM_PRESET: preset } });
    assert.equal(r.ok, false, `${preset} resolved without a key`);
    assert.equal(r.reason, null);
  }
});

test('each vendor preset resolves with its own wire shape', () => {
  const cases = [
    ['anthropic', { AGENTIC_SECURITY_LLM_API_KEY: 'k' }, /api\.anthropic\.com/],
    ['openai', { OPENAI_API_KEY: 'k' }, /api\.openai\.com/],
    ['gemini', { GEMINI_API_KEY: 'k' }, /generativelanguage\.googleapis\.com/],
  ];
  for (const [preset, extra, endpointRe] of cases) {
    const r = resolveProvider({ env: { AGENTIC_SECURITY_LLM_PRESET: preset, ...extra } });
    assert.equal(r.ok, true, `${preset} did not resolve`);
    assert.match(r.config.endpoint, endpointRe);
    assert.equal(r.config.provider, preset);
    assert.ok(r.config.shape, 'no wire shape attached');
  }
});

test('each shape can build a request and read text back', () => {
  const replies = {
    anthropic: { content: [{ type: 'text', text: 'hello' }], usage: { input_tokens: 5, output_tokens: 2 } },
    openai: { choices: [{ message: { content: 'hello' } }], usage: { prompt_tokens: 5, completion_tokens: 2 } },
    gemini: { candidates: [{ content: { parts: [{ text: 'hello' }] } }], usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 2 } },
  };
  for (const [name, shape] of Object.entries(_internals.SHAPES)) {
    const req = buildProviderRequest({ shape, model: 'm', apiKey: 'k' }, 'prompt', 512);
    assert.ok(req.body, `${name} built no body`);
    assert.equal(req.extractText(replies[name]), 'hello', `${name} could not read text`);
    assert.deepEqual(req.extractUsage(replies[name]), { inputTokens: 5, outputTokens: 2 },
      `${name} could not read usage — the cost ceiling would fall back to estimates`);
  }
});

test('a missing usage report yields null, not zero', () => {
  // Zero would read as "this call was free" and understate spend.
  for (const shape of Object.values(_internals.SHAPES)) {
    assert.equal(shape.usage({}), null);
  }
});

test('per-role pinning takes effect and falls back to the global model', () => {
  const env = {
    AGENTIC_SECURITY_LLM_PRESET: 'openai',
    OPENAI_API_KEY: 'k',
    AGENTIC_SECURITY_LLM_MODEL: 'global-model',
    AGENTIC_SECURITY_LLM_MODEL_VERIFY: 'cheap-model',
  };
  assert.equal(resolveProvider({ role: 'verify', env }).config.model, 'cheap-model');
  assert.equal(resolveProvider({ role: 'fix', env }).config.model, 'global-model');
});

test('an unknown role cannot silently pick up a per-role pin', () => {
  // Roles are a closed set: a typo must fall back to the global model rather
  // than resolving to something nobody configured.
  const env = {
    AGENTIC_SECURITY_LLM_PRESET: 'openai', OPENAI_API_KEY: 'k',
    AGENTIC_SECURITY_LLM_MODEL: 'global-model',
    AGENTIC_SECURITY_LLM_MODEL_TRIAGE: 'typo-model',
  };
  assert.ok(!ROLES.includes('triage'), 'test premise: triage is not a declared role');
  assert.equal(resolveProvider({ role: 'triage', env }).config.model, 'global-model');
});

test('a role can use a DIFFERENT provider from the global one', () => {
  const env = {
    AGENTIC_SECURITY_LLM_PRESET: 'anthropic', AGENTIC_SECURITY_LLM_API_KEY: 'k',
    AGENTIC_SECURITY_LLM_PRESET_VERIFY: 'local',
  };
  assert.equal(resolveProvider({ role: 'fix', env }).config.provider, 'anthropic');
  assert.equal(resolveProvider({ role: 'verify', env }).config.provider, 'local');
});

// --- the local guarantee must survive the abstraction ----------------------

test('the local preset still refuses a remote endpoint', () => {
  const r = resolveProvider({
    role: 'validate',
    env: { AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1' },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /non-loopback/, 'a provider abstraction must not become a way to smuggle a remote endpoint into local mode');
});

test('local resolves loopback-only and reports its egress', () => {
  const r = resolveProvider({ env: { AGENTIC_SECURITY_LLM_PRESET: 'local' } });
  assert.equal(r.ok, true);
  assert.equal(r.config.egress, 'loopback-only');
  assert.match(r.config.endpoint, /^http:\/\/127\.0\.0\.1/);
});

test('a refusal is distinguishable from "nothing configured"', () => {
  const off = resolveProvider({ env: {} });
  const refused = resolveProvider({
    env: { AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'https://evil.example' },
  });
  assert.equal(off.reason, null);
  assert.ok(refused.reason, 'a refused configuration must carry its reason');
});

// --- reporting -------------------------------------------------------------

test('the provider matrix never contains an API key', () => {
  const env = {
    AGENTIC_SECURITY_LLM_PRESET: 'openai',
    OPENAI_API_KEY: 'sk-super-secret-value',
    AGENTIC_SECURITY_LLM_API_KEY: 'another-secret',
  };
  const m = providerMatrix(env);
  const blob = JSON.stringify(m);
  assert.ok(!blob.includes('sk-super-secret-value'), 'an API key leaked into the reported matrix');
  assert.ok(!blob.includes('another-secret'));
  assert.equal(m.validate.provider, 'openai');
});

test('the matrix covers every declared role and says why a role is off', () => {
  const m = providerMatrix({});
  for (const role of ROLES) {
    assert.ok(role in m, `role ${role} missing from the matrix`);
    assert.equal(m[role].provider, null);
    assert.match(m[role].reason, /not configured/);
  }
});

test('BYO endpoint still works and is treated as OpenAI-compatible', () => {
  const r = resolveProvider({ env: { AGENTIC_SECURITY_LLM_ENDPOINT: 'https://internal.example/v1/chat' } });
  assert.equal(r.ok, true);
  assert.equal(r.config.provider, 'byo');
  assert.equal(r.config.endpoint, 'https://internal.example/v1/chat');
});
