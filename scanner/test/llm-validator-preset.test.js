// Tests for the Layer-3 validator's first-class Anthropic preset (#18). No live
// network — endpointConfig resolution and the pure request adapter are the
// testable surface; the preset stays opt-in and offline-degrading.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { _internal } from '../src/llm-validator/index.js';

const { endpointConfig, buildRequest } = _internal;

function withEnv(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) {
    saved[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k];
  }
  try { return fn(); }
  finally {
    for (const k of Object.keys(env)) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
  }
}

test('#18 endpointConfig: anthropic preset + key → messages endpoint, haiku default', () => {
  withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: undefined, AGENTIC_SECURITY_LLM_PRESET: 'anthropic',
    AGENTIC_SECURITY_LLM_API_KEY: undefined, ANTHROPIC_API_KEY: 'sk-ant-test',
    AGENTIC_SECURITY_LLM_MODEL: undefined,
  }, () => {
    const cfg = endpointConfig();
    assert.ok(cfg);
    assert.equal(cfg.preset, 'anthropic');
    assert.match(cfg.endpoint, /api\.anthropic\.com\/v1\/messages/);
    assert.equal(cfg.model, 'claude-haiku-4-5');
    assert.equal(cfg.apiKey, 'sk-ant-test');
  });
});

test('#18 endpointConfig: preset but NO key → null (opt-in, offline-degrading)', () => {
  withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: undefined, AGENTIC_SECURITY_LLM_PRESET: 'anthropic',
    AGENTIC_SECURITY_LLM_API_KEY: undefined, ANTHROPIC_API_KEY: undefined,
  }, () => {
    assert.equal(endpointConfig(), null);
  });
});

test('#18 endpointConfig: a BYO endpoint still wins over the preset', () => {
  withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://byo/x', AGENTIC_SECURITY_LLM_PRESET: 'anthropic',
    ANTHROPIC_API_KEY: 'k', AGENTIC_SECURITY_LLM_MODEL: undefined,
  }, () => {
    const cfg = endpointConfig();
    assert.equal(cfg.endpoint, 'http://byo/x');
    assert.equal(cfg.preset, null);
  });
});

test('#18 buildRequest: anthropic shape (messages body + content[].text extraction)', () => {
  const { headers, body, extractText } = buildRequest('claude-haiku-4-5', 'PROMPT', 'anthropic');
  assert.equal(headers['anthropic-version'], '2023-06-01');
  assert.equal(body.model, 'claude-haiku-4-5');
  assert.equal(body.messages[0].content, 'PROMPT');
  assert.ok(body.max_tokens > 0);
  assert.equal(extractText({ content: [{ type: 'text', text: 'hello ' }, { type: 'text', text: 'world' }] }), 'hello world');
});

test('#18 buildRequest: generic (BYO) shape unchanged', () => {
  const { body, extractText } = buildRequest('m', 'P', null);
  assert.deepEqual(body, { prompt: 'P', model: 'm' });
  assert.equal(extractText({ response: 'r' }), 'r');
  assert.equal(extractText({ choices: [{ message: { content: 'c' } }] }), 'c');
});
