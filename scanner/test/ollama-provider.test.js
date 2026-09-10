// agentic-security-ollama-offline-prd.md §40.1/§40.2/§40.6 — unit + fake-
// server contract tests for the Ollama provider adapter. No real Ollama
// install or model weights required: the fake server below implements just
// enough of /api/chat and /api/tags to exercise the real wire format.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import {
  ollamaEndpointConfig, buildOllamaChatBody, parseOllamaChatResponse,
  callOllamaChat, callOllamaStructured, listOllamaModels, DEFAULT_OLLAMA_HOST, DEFAULT_OLLAMA_MODEL,
  OLLAMA_ERROR_CODES,
} from '../src/llm-validator/ollama-provider.js';
import { resolveProvider, buildProviderRequest, _internals as providerInternals } from '../src/llm-validator/providers.js';

// ── ollamaEndpointConfig — loopback enforcement ─────────────────────────────

test('ollamaEndpointConfig defaults to 127.0.0.1:11434, offline, loopback-only', () => {
  const r = ollamaEndpointConfig({});
  assert.equal(r.ok, true);
  assert.equal(r.config.host, DEFAULT_OLLAMA_HOST);
  assert.equal(r.config.offline, true);
  assert.equal(r.config.egress, 'loopback-only');
});

test('ollamaEndpointConfig accepts an explicit loopback host', () => {
  const r = ollamaEndpointConfig({ AGENTIC_SECURITY_OLLAMA_HOST: 'http://localhost:11434' });
  assert.equal(r.ok, true);
  assert.equal(r.config.egress, 'loopback-only');
});

test('ollamaEndpointConfig REFUSES a LAN host by default', () => {
  const r = ollamaEndpointConfig({ AGENTIC_SECURITY_OLLAMA_HOST: 'http://192.168.1.50:11434' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'ollama-non-loopback-refused');
  assert.match(r.reason, /192\.168\.1\.50/);
  assert.match(r.reason, /allow-remote-ollama|ALLOW_REMOTE/);
});

test('ollamaEndpointConfig REFUSES a remote hostname by default', () => {
  const r = ollamaEndpointConfig({ AGENTIC_SECURITY_OLLAMA_HOST: 'http://ollama.example.com:11434' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'ollama-non-loopback-refused');
});

test('ollamaEndpointConfig admits a remote host ONLY with the explicit escape hatch, and labels it remote', () => {
  const r = ollamaEndpointConfig({
    AGENTIC_SECURITY_OLLAMA_HOST: 'http://192.168.1.50:11434',
    AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE: '1',
  });
  assert.equal(r.ok, true);
  assert.equal(r.config.offline, false);
  assert.equal(r.config.egress, 'remote');
});

test('ollamaEndpointConfig respects AGENTIC_SECURITY_LLM_TIMEOUT_MS and keep-alive overrides', () => {
  const r = ollamaEndpointConfig({
    AGENTIC_SECURITY_LLM_TIMEOUT_MS: '45000',
    AGENTIC_SECURITY_OLLAMA_KEEP_ALIVE: '0',
  });
  assert.equal(r.config.requestTimeoutMs, 45000);
  assert.equal(r.config.keepAlive, '0');
});

test('ollamaEndpointConfig defaults concurrency to 1 (PRD §22.1)', () => {
  const r = ollamaEndpointConfig({});
  assert.equal(r.config.maxConcurrency, 1);
});

// ── buildOllamaChatBody / parseOllamaChatResponse — wire shape (§38) ────────

test('buildOllamaChatBody produces the native /api/chat shape with messages, not {prompt}', () => {
  const body = buildOllamaChatBody({ model: 'qwen3.5:4b', messages: [{ role: 'user', content: 'hi' }] });
  assert.equal(body.model, 'qwen3.5:4b');
  assert.deepEqual(body.messages, [{ role: 'user', content: 'hi' }]);
  assert.equal(body.stream, false);
  assert.equal(body.options.temperature, 0);
  assert.equal('prompt' in body, false);
});

test('buildOllamaChatBody includes format/tools/think/keep_alive only when provided', () => {
  const minimal = buildOllamaChatBody({ model: 'm', messages: [] });
  assert.equal('format' in minimal, false);
  assert.equal('tools' in minimal, false);
  assert.equal('think' in minimal, false);
  assert.equal('keep_alive' in minimal, false);

  const full = buildOllamaChatBody({
    model: 'm', messages: [], schema: { type: 'object' }, tools: [{ type: 'function' }],
    think: true, keepAlive: '5m', maxTokens: 512,
  });
  assert.deepEqual(full.format, { type: 'object' });
  assert.equal(full.tools.length, 1);
  assert.equal(full.think, true);
  assert.equal(full.keep_alive, '5m');
  assert.equal(full.options.num_predict, 512);
});

test('parseOllamaChatResponse extracts message.content, thinking, tool_calls, usage, timing', () => {
  const json = {
    message: { content: 'the answer', thinking: 'reasoning trace', tool_calls: [{ function: { name: 'x' } }] },
    prompt_eval_count: 100, eval_count: 40,
    total_duration: 2_000_000_000, load_duration: 500_000_000,
    prompt_eval_duration: 300_000_000, eval_duration: 1_200_000_000,
  };
  const r = parseOllamaChatResponse(json, 'qwen3.5:4b');
  assert.equal(r.text, 'the answer');
  assert.equal(r.thinking, 'reasoning trace');
  assert.equal(r.toolCalls.length, 1);
  assert.deepEqual(r.usage, { inputTokens: 100, outputTokens: 40 });
  assert.equal(r.timing.totalMs, 2000);
  assert.equal(r.timing.loadMs, 500);
  assert.equal(r.provider, 'ollama');
  assert.equal(r.model, 'qwen3.5:4b');
});

test('parseOllamaChatResponse tolerates a missing/malformed body without throwing', () => {
  const r = parseOllamaChatResponse(null, 'm');
  assert.equal(r.text, '');
  assert.equal(r.usage, null);
  const r2 = parseOllamaChatResponse({}, 'm');
  assert.equal(r2.text, '');
});

// ── Error taxonomy is closed (§25) ──────────────────────────────────────────

test('every OLLAMA_ERROR_CODES entry is a distinct ollama-* string', () => {
  assert.ok(OLLAMA_ERROR_CODES.length > 5);
  for (const c of OLLAMA_ERROR_CODES) assert.match(c, /^ollama-/);
  assert.equal(new Set(OLLAMA_ERROR_CODES).size, OLLAMA_ERROR_CODES.length);
});

// ── Fake Ollama server — real HTTP round trip over loopback ─────────────────

function startFakeOllama(handlers) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const key = `${req.method} ${req.url}`;
      const handler = handlers[key];
      if (!handler) { res.writeHead(404); res.end('{}'); return; }
      handler(req, res, body ? JSON.parse(body) : null);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, host: `http://127.0.0.1:${port}` });
    });
  });
}

test('callOllamaChat: real request/response round trip over loopback', async () => {
  let receivedBody = null;
  const { server, host } = await startFakeOllama({
    'POST /api/chat': (req, res, json) => {
      receivedBody = json;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        message: { role: 'assistant', content: '{"ok":true}' },
        done: true, prompt_eval_count: 12, eval_count: 4,
      }));
    },
  });
  try {
    const r = await callOllamaChat({
      host, model: 'qwen3.5:4b', messages: [{ role: 'user', content: 'test' }],
      timeouts: { connectTimeoutMs: 2000, requestTimeoutMs: 5000 },
    });
    assert.equal(r.ok, true);
    assert.equal(r.result.text, '{"ok":true}');
    assert.deepEqual(r.result.usage, { inputTokens: 12, outputTokens: 4 });
    assert.equal(receivedBody.model, 'qwen3.5:4b');
    assert.equal(receivedBody.messages[0].content, 'test');
  } finally {
    server.close();
  }
});

test('callOllamaChat: model-not-installed maps to ollama-model-not-installed, never throws', async () => {
  const { server, host } = await startFakeOllama({
    'POST /api/chat': (req, res) => {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: "model 'ghost:1b' not found" }));
    },
  });
  try {
    const r = await callOllamaChat({ host, model: 'ghost:1b', messages: [{ role: 'user', content: 'x' }] });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'ollama-model-not-installed');
  } finally {
    server.close();
  }
});

test('callOllamaChat: unreachable port fails fast with ollama-unreachable, never hangs', async () => {
  // Nothing listening on this port.
  const r = await callOllamaChat({
    host: 'http://127.0.0.1:1', model: 'm', messages: [{ role: 'user', content: 'x' }],
    timeouts: { connectTimeoutMs: 1000, requestTimeoutMs: 2000 },
  });
  assert.equal(r.ok, false);
  assert.match(r.code, /ollama-unreachable|ollama-timeout/);
});

test('callOllamaChat: total timeout aborts a hanging server rather than waiting forever', async () => {
  const { server, host } = await startFakeOllama({
    'POST /api/chat': () => { /* never respond */ },
  });
  try {
    const start = Date.now();
    const r = await callOllamaChat({
      host, model: 'm', messages: [{ role: 'user', content: 'x' }],
      timeouts: { connectTimeoutMs: 200, requestTimeoutMs: 300 },
    });
    const elapsed = Date.now() - start;
    assert.equal(r.ok, false);
    assert.equal(r.code, 'ollama-timeout');
    assert.ok(elapsed < 5000, `expected a fast abort, took ${elapsed}ms`);
  } finally {
    server.close();
  }
});

test('listOllamaModels: parses /api/tags into normalized ModelInfo entries', async () => {
  const { server, host } = await startFakeOllama({
    'GET /api/tags': (req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        models: [
          { name: 'qwen3.5:4b', digest: 'sha256:abc', size: 3_400_000_000, details: { parameter_size: '4B', quantization_level: 'Q4_K_M', family: 'qwen3' }, modified_at: '2026-01-01' },
          { name: 'gemma4:e2b', digest: 'sha256:def', size: 7_200_000_000, details: { parameter_size: '2B', quantization_level: 'Q4_K_M', family: 'gemma' } },
        ],
      }));
    },
  });
  try {
    const r = await listOllamaModels({ host });
    assert.equal(r.ok, true);
    assert.equal(r.models.length, 2);
    assert.equal(r.models[0].name, 'qwen3.5:4b');
    assert.equal(r.models[0].parameterSize, '4B');
    assert.equal(r.models[1].name, 'gemma4:e2b');
  } finally {
    server.close();
  }
});

test('listOllamaModels: Ollama not running reports ollama-not-running, not a raw fetch error', async () => {
  const r = await listOllamaModels({ host: 'http://127.0.0.1:1', timeouts: { connectTimeoutMs: 500, requestTimeoutMs: 1000 } });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'ollama-not-running');
});

// ── callOllamaStructured — schema + one bounded retry (§17) ─────────────────

function _schemaValidate(obj) {
  if (!obj || typeof obj !== 'object') return { ok: false };
  if (!['confirmed', 'refuted'].includes(obj.verdict)) return { ok: false };
  return { ok: true, value: obj };
}

test('callOllamaStructured: a valid first response is accepted with attempts:1, no retry', async () => {
  let calls = 0;
  const { server, host } = await startFakeOllama({
    'POST /api/chat': (req, res) => {
      calls++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: { content: '{"verdict":"confirmed"}' }, done: true }));
    },
  });
  try {
    const r = await callOllamaStructured({
      host, model: 'm', messages: [{ role: 'user', content: 'x' }],
      schema: { type: 'object' }, validateFn: _schemaValidate,
    });
    assert.equal(r.ok, true);
    assert.equal(r.attempts, 1);
    assert.equal(calls, 1);
  } finally {
    server.close();
  }
});

test('callOllamaStructured: an invalid first response gets exactly ONE retry, then succeeds', async () => {
  let calls = 0;
  const { server, host } = await startFakeOllama({
    'POST /api/chat': (req, res) => {
      calls++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const content = calls === 1 ? 'not even json' : '{"verdict":"refuted"}';
      res.end(JSON.stringify({ message: { content }, done: true }));
    },
  });
  try {
    const r = await callOllamaStructured({
      host, model: 'm', messages: [{ role: 'user', content: 'x' }],
      schema: { type: 'object' }, validateFn: _schemaValidate,
    });
    assert.equal(r.ok, true);
    assert.equal(r.attempts, 2);
    assert.equal(calls, 2);
  } finally {
    server.close();
  }
});

test('callOllamaStructured: NEVER retries more than once — two bad responses mark malformed, never a trusted verdict', async () => {
  let calls = 0;
  const { server, host } = await startFakeOllama({
    'POST /api/chat': (req, res) => {
      calls++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: { content: 'still not valid json' }, done: true }));
    },
  });
  try {
    const r = await callOllamaStructured({
      host, model: 'm', messages: [{ role: 'user', content: 'x' }],
      schema: { type: 'object' }, validateFn: _schemaValidate,
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'ollama-malformed-response');
    assert.equal(calls, 2, 'must attempt exactly twice — no unbounded retry loop');
  } finally {
    server.close();
  }
});

test('callOllamaStructured: a well-formed but schema-violating verdict is rejected, not trusted', async () => {
  const { server, host } = await startFakeOllama({
    'POST /api/chat': (req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      // Valid JSON, but "maybe" is not in the caller's allowed enum.
      res.end(JSON.stringify({ message: { content: '{"verdict":"maybe"}' }, done: true }));
    },
  });
  try {
    const r = await callOllamaStructured({
      host, model: 'm', messages: [{ role: 'user', content: 'x' }],
      schema: { type: 'object' }, validateFn: _schemaValidate,
      timeouts: { connectTimeoutMs: 2000, requestTimeoutMs: 5000 },
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'ollama-malformed-response');
  } finally {
    server.close();
  }
});

test('callOllamaStructured: a transport error surfaces immediately, no retry attempted', async () => {
  const r = await callOllamaStructured({
    host: 'http://127.0.0.1:1', model: 'm', messages: [{ role: 'user', content: 'x' }],
    schema: { type: 'object' }, validateFn: _schemaValidate,
    timeouts: { connectTimeoutMs: 500, requestTimeoutMs: 1000 },
  });
  assert.equal(r.ok, false);
  assert.match(r.code, /ollama-unreachable|ollama-timeout/);
});

// ── Provider resolution + regression tests (§40.6) ──────────────────────────

test('resolveProvider: PRESET=ollama resolves provider ollama with no SHAPES entry', () => {
  const r = resolveProvider({ role: 'validate', env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama' } });
  assert.equal(r.ok, true);
  assert.equal(r.config.provider, 'ollama');
  assert.equal(r.config.shape, null);
  assert.equal(r.config.model, DEFAULT_OLLAMA_MODEL);
  assert.equal(r.config.egress, 'loopback-only');
  assert.ok(r.config.ollama, 'ollama sub-config must be attached for the caller to use');
});

test('resolveProvider: PRESET=ollama with a remote host refuses (not silently local)', () => {
  const r = resolveProvider({
    role: 'validate',
    env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: 'http://10.0.0.5:11434' },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /10\.0\.0\.5/);
});

test('regression: PRESET=local still resolves the untouched legacy generic shape', () => {
  const r = resolveProvider({ role: 'validate', env: { AGENTIC_SECURITY_LLM_PRESET: 'local' } });
  assert.equal(r.ok, true);
  assert.equal(r.config.provider, 'local');
  assert.equal(r.config.shape, providerInternals.SHAPES.generic);
  const req = buildProviderRequest(r.config, 'hello', 512);
  assert.deepEqual(req.body, { prompt: 'hello', model: r.config.model });
  assert.equal('messages' in req.body, false);
});

test('per-role model override still works for ollama (AGENTIC_SECURITY_LLM_MODEL_VALIDATE)', () => {
  const r = resolveProvider({
    role: 'validate',
    env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_LLM_MODEL_VALIDATE: 'qwen3:14b' },
  });
  assert.equal(r.ok, true);
  assert.equal(r.config.model, 'qwen3:14b');
});
