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
  resolveProvider, buildProviderRequest, providerMatrix, otherRemoteRoles, NO_CLOUD_FALLBACK, ROLES, _internals,
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
    generic: { response: 'hello', usage: { prompt_tokens: 5, completion_tokens: 2 } },
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

// --- otherRemoteRoles (AI Assistance report scope-disclosure fix) ---------

test('NO_CLOUD_FALLBACK is a single asserted constant, not per-caller duplicated', () => {
  assert.equal(NO_CLOUD_FALLBACK, true);
});

test('otherRemoteRoles: a role on ollama/local is excluded even when checking a different excludeRole', () => {
  const env = { AGENTIC_SECURITY_LLM_PRESET: 'ollama' };
  const others = otherRemoteRoles('validate', env);
  assert.deepEqual(others, [], 'every role shares the same loopback ollama preset — nothing remote to disclose');
});

test('otherRemoteRoles: a per-role override to a cloud vendor is reported by name, excluded role is not', () => {
  // 'hunt' is deliberately NOT in providers.js's ROLES (it has no per-role
  // override at all — see discovery/hunter.js, which always falls back to
  // the global preset). Use 'fix', which genuinely supports one.
  const env = {
    AGENTIC_SECURITY_LLM_PRESET: 'ollama',
    AGENTIC_SECURITY_LLM_PRESET_FIX: 'anthropic',
    AGENTIC_SECURITY_LLM_API_KEY_FIX: 'k',
  };
  const others = otherRemoteRoles('validate', env);
  assert.ok(others.some((o) => o.role === 'fix' && o.provider === 'anthropic'), `expected fix/anthropic in ${JSON.stringify(others)}`);
  assert.ok(!others.some((o) => o.role === 'validate'), 'the excluded role must never appear in its own disclosure list');
});

// Precise version of the same real scenario for 'hunt' specifically: since
// hunt has no per-role preset of its own, it can only diverge from validate
// via the GLOBAL preset while validate has ITS OWN override — not the other
// way around. Still a genuine way for the two to disagree in practice.
//
// Second-round adversarial-review fix (2026-09): the FIRST version of this
// test explicitly did NOT assert hunt by name ("hunt is not one of
// providerMatrix's iterated ROLES... this documents the boundary rather
// than asserting hunt by name") — because at the time, it genuinely never
// could appear: `providerMatrix()` only iterates the six roles in `ROLES`,
// and `hunt` is deliberately absent from that list. A fresh adversarial
// pass caught that this made the exact scenario below — hunt following a
// remote global preset while validate has its own local override — silently
// invisible to the one mechanism built to catch it. `otherRemoteRoles` now
// checks `hunt` explicitly (see `ROLES_WITH_NO_PER_ROLE_OVERRIDE`). This
// test now asserts hunt BY NAME, where the original deliberately couldn't.
test('otherRemoteRoles: hunt (no per-role override) is now reported by name when the GLOBAL preset is cloud and validate has its own ollama override', () => {
  const env = {
    AGENTIC_SECURITY_LLM_PRESET: 'anthropic',
    ANTHROPIC_API_KEY: 'k',
    AGENTIC_SECURITY_LLM_PRESET_VALIDATE: 'ollama',
  };
  const others = otherRemoteRoles('validate', env);
  assert.ok(others.every((o) => o.role !== 'validate'));
  assert.ok(others.some((o) => o.role === 'hunt' && o.provider === 'anthropic'),
    `expected hunt/anthropic in ${JSON.stringify(others)} — hunt is the role most likely to silently diverge`);
  assert.ok(others.every((o) => o.provider === 'anthropic'));
});

test('otherRemoteRoles: hunt is excluded from its OWN disclosure list when it is the scoped role', () => {
  const env = {
    AGENTIC_SECURITY_LLM_PRESET: 'anthropic',
    ANTHROPIC_API_KEY: 'k',
  };
  const others = otherRemoteRoles('hunt', env);
  assert.ok(!others.some((o) => o.role === 'hunt'), 'hunt must never appear in its own exclusion-scoped list');
});

test('otherRemoteRoles: hunt following the SAME loopback ollama global preset as every other role reports nothing', () => {
  const env = { AGENTIC_SECURITY_LLM_PRESET: 'ollama' };
  const others = otherRemoteRoles('validate', env);
  assert.ok(!others.some((o) => o.role === 'hunt'), 'hunt sharing the loopback preset must not be flagged as remote');
});

test('otherRemoteRoles: never includes an API key', () => {
  const env = {
    AGENTIC_SECURITY_LLM_PRESET: 'ollama',
    AGENTIC_SECURITY_LLM_PRESET_FIX: 'openai',
    OPENAI_API_KEY: 'sk-super-secret-value',
  };
  const others = otherRemoteRoles('validate', env);
  assert.ok(!JSON.stringify(others).includes('sk-super-secret-value'));
});

test('BYO keeps the LEGACY wire shape, not OpenAI\'s', () => {
  // Existing BYO servers speak `{prompt, model}`. Assuming OpenAI-compatibility
  // would have silently broken every one of them — caught by the default-on
  // test, whose fake endpoint reads body.prompt and returns {response}.
  const r = resolveProvider({ env: { AGENTIC_SECURITY_LLM_ENDPOINT: 'https://internal.example/v1/chat' } });
  assert.equal(r.ok, true);
  assert.equal(r.config.provider, 'byo');
  const req = buildProviderRequest(r.config, 'PROMPT', 512);
  assert.equal(req.body.prompt, 'PROMPT', 'BYO body must carry `prompt`');
  assert.equal(req.extractText({ response: 'hi' }), 'hi');
});

test('a BYO endpoint WINS over a vendor preset', () => {
  // Documented precedence: naming an endpoint means that endpoint. Reversing it
  // would silently redirect traffic to a vendor.
  const r = resolveProvider({ env: {
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://byo/x',
    AGENTIC_SECURITY_LLM_PRESET: 'anthropic', ANTHROPIC_API_KEY: 'k',
  } });
  assert.equal(r.config.endpoint, 'http://byo/x');
  assert.equal(r.config.provider, 'byo');
});

test('the local preset still wins over a BYO endpoint', () => {
  // Local is the only mode that makes a promise about egress; BYO precedence
  // must not override it.
  const r = resolveProvider({ env: {
    AGENTIC_SECURITY_LLM_PRESET: 'local',
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:11434/v1',
  } });
  assert.equal(r.config.provider, 'local');
  assert.equal(r.config.egress, 'loopback-only');
});
