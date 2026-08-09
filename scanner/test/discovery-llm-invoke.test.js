// scanner/test/discovery-llm-invoke.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveLlmInvoke, defaultLlmInvoke } from '../src/discovery/llm-invoke.js';

const ENV_KEY = 'AGENTIC_SECURITY_LLM_ENDPOINT';

test('resolveLlmInvoke({}) returns null when the endpoint env var is unset', () => {
  const prev = process.env[ENV_KEY];
  delete process.env[ENV_KEY];
  try {
    assert.equal(resolveLlmInvoke({}), null);
  } finally {
    if (prev !== undefined) process.env[ENV_KEY] = prev;
  }
});

test('resolveLlmInvoke reads the env var at call time, not at module load', () => {
  // The module was already imported above, before this test set the env var.
  const prev = process.env[ENV_KEY];
  delete process.env[ENV_KEY];
  try {
    assert.equal(resolveLlmInvoke({}), null, 'must be null before the env var is set');

    process.env[ENV_KEY] = 'https://example.invalid/llm';
    const invoke = resolveLlmInvoke({});
    assert.equal(typeof invoke, 'function', 'must become a function once the env var is set');

    delete process.env[ENV_KEY];
    assert.equal(resolveLlmInvoke({}), null, 'must revert to null once the env var is unset again');
  } finally {
    if (prev !== undefined) process.env[ENV_KEY] = prev;
    else delete process.env[ENV_KEY];
  }
});

test('resolveLlmInvoke({ llmInvoke }) returns the injected function regardless of the env var', () => {
  const prev = process.env[ENV_KEY];
  const fn = async () => 'injected';
  try {
    delete process.env[ENV_KEY];
    assert.equal(resolveLlmInvoke({ llmInvoke: fn }), fn);

    process.env[ENV_KEY] = 'https://example.invalid/llm';
    assert.equal(resolveLlmInvoke({ llmInvoke: fn }), fn);
  } finally {
    if (prev !== undefined) process.env[ENV_KEY] = prev;
    else delete process.env[ENV_KEY];
  }
});

test('resolveLlmInvoke passes opts.timeoutMs through to defaultLlmInvoke', async () => {
  const prev = process.env[ENV_KEY];
  const prevFetch = globalThis.fetch;
  let seenSignal = null;
  process.env[ENV_KEY] = 'https://example.invalid/llm';
  globalThis.fetch = async (url, init) => {
    seenSignal = init?.signal ?? null;
    return { ok: true, json: async () => ({ text: 'ok' }) };
  };
  try {
    const invoke = resolveLlmInvoke({ timeoutMs: 5 });
    const result = await invoke('some prompt');
    assert.equal(result, 'ok');
    assert.ok(seenSignal, 'a signal must be passed to fetch so the call is bounded');
  } finally {
    globalThis.fetch = prevFetch;
    if (prev !== undefined) process.env[ENV_KEY] = prev;
    else delete process.env[ENV_KEY];
  }
});

test('defaultLlmInvoke surfaces a non-ok response as a thrown error, never a live network call in tests', async () => {
  const prev = process.env[ENV_KEY];
  const prevFetch = globalThis.fetch;
  process.env[ENV_KEY] = 'https://example.invalid/llm';
  globalThis.fetch = async () => ({ ok: false, status: 503, json: async () => ({}) });
  try {
    await assert.rejects(() => defaultLlmInvoke('prompt'), /llm endpoint returned 503/);
  } finally {
    globalThis.fetch = prevFetch;
    if (prev !== undefined) process.env[ENV_KEY] = prev;
    else delete process.env[ENV_KEY];
  }
});
