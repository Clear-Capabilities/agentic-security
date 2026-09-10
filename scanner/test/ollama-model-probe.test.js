// agentic-security-ollama-offline-prd.md §13.2 — the three-layer model
// capability detection strategy (metadata / family hint / runtime probe),
// plus the probe cache keyed by Ollama version + model digest + name.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as fs from 'node:fs';
import {
  capabilitiesFromShowMetadata, probeStructuredOutput, probeToolCalling,
  getModelCapabilities, _internals,
} from '../src/llm-validator/model-probe.js';

function startFakeOllama(routes) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const parsed = body ? JSON.parse(body) : null;
      const handler = routes[req.url] || routes.default;
      handler(req, res, parsed);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, host: `http://127.0.0.1:${port}` });
    });
  });
}

function json(res, body, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

test('capabilitiesFromShowMetadata: reads the capabilities array and *.context_length, sets source.metadata', () => {
  const caps = capabilitiesFromShowMetadata({
    capabilities: ['completion', 'tools', 'vision'],
    modelInfo: { 'qwen3.context_length': 32768, 'general.architecture': 'qwen3' },
  });
  assert.equal(caps.chat, true);
  assert.equal(caps.tools, true);
  assert.equal(caps.vision, true);
  assert.equal(caps.thinking, false);
  assert.equal(caps.contextTokens, 32768);
  assert.equal(caps.source.metadata, true);
});

test('capabilitiesFromShowMetadata: no capabilities array leaves fields unset (silence, not false)', () => {
  const caps = capabilitiesFromShowMetadata({ capabilities: null, modelInfo: null });
  assert.equal(caps.chat, undefined);
  assert.equal(caps.tools, undefined);
  assert.equal(caps.contextTokens, undefined);
});

test('probeStructuredOutput: a compliant fake server reports supported:true', async () => {
  const { server, host } = await startFakeOllama({
    '/api/chat': (req, res) => json(res, { message: { content: '{"ok": true}' }, done: true }),
  });
  try {
    const r = await probeStructuredOutput({ host, model: 'qwen3.5:4b' });
    assert.equal(r.supported, true);
  } finally { server.close(); }
});

test('probeStructuredOutput: a model that ignores the schema reports supported:false, not thrown', async () => {
  const { server, host } = await startFakeOllama({
    '/api/chat': (req, res) => json(res, { message: { content: 'sure, here you go: {"ok": true} maybe' }, done: true }),
  });
  try {
    const r = await probeStructuredOutput({ host, model: 'some-model' });
    assert.equal(r.supported, false);
  } finally { server.close(); }
});

test('probeStructuredOutput: an unreachable server reports supported:"unknown", not false', async () => {
  const r = await probeStructuredOutput({ host: 'http://127.0.0.1:1', model: 'qwen3.5:4b', timeouts: { connectTimeoutMs: 200, requestTimeoutMs: 200 } });
  assert.equal(r.supported, 'unknown');
});

test('probeToolCalling: a server returning a matching tool_calls entry reports supported:true', async () => {
  const { server, host } = await startFakeOllama({
    '/api/chat': (req, res) => json(res, {
      message: { content: '', tool_calls: [{ function: { name: 'echo_capability_probe', arguments: { value: 'probe-ok' } } }] },
      done: true,
    }),
  });
  try {
    const r = await probeToolCalling({ host, model: 'qwen3.5:4b' });
    assert.equal(r.supported, true);
  } finally { server.close(); }
});

test('probeToolCalling: a server that never calls the tool reports supported:false', async () => {
  const { server, host } = await startFakeOllama({
    '/api/chat': (req, res) => json(res, { message: { content: 'I cannot call functions.' }, done: true }),
  });
  try {
    const r = await probeToolCalling({ host, model: 'gemma3:4b' });
    assert.equal(r.supported, false);
  } finally { server.close(); }
});

test('getModelCapabilities: probe:false (default) never calls /api/chat, only /api/show', async () => {
  let chatCalled = false;
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'], details: { digest: 'sha256:abc' } }),
    '/api/chat': (req, res) => { chatCalled = true; json(res, { message: { content: '{}' }, done: true }); },
  });
  try {
    const r = await getModelCapabilities({ host, model: 'qwen3.5:4b', probe: false });
    assert.equal(r.ok, true);
    assert.equal(r.capabilities.tools, true);
    assert.equal(chatCalled, false);
    assert.equal(r.cached, false);
  } finally { server.close(); }
});

test('getModelCapabilities: probe:true runs both probes, merges as runtimeProbe, and writes a cache entry keyed by version+digest+name', async () => {
  const model = 'probe-cache-test-model:unique-' + Date.now();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion'], details: { digest: 'sha256:cache-test-digest' } }),
    '/api/version': (req, res) => json(res, { version: '0.9.9-test' }),
    '/api/chat': (req, res, body) => {
      if (Array.isArray(body?.tools)) {
        json(res, { message: { content: '', tool_calls: [{ function: { name: 'echo_capability_probe', arguments: {} } }] }, done: true });
      } else {
        json(res, { message: { content: '{"ok": true}' }, done: true });
      }
    },
  });
  const cacheKey = _internals._cacheKey('0.9.9-test', 'sha256:cache-test-digest', model);
  const cachePath = _internals._cachePath(cacheKey);
  try {
    const r = await getModelCapabilities({ host, model, probe: true });
    assert.equal(r.ok, true);
    assert.equal(r.capabilities.tools, true);
    assert.equal(r.capabilities.structuredJson, true);
    assert.equal(r.capabilities.source.runtimeProbe, true);
    assert.equal(r.cached, false);
    assert.ok(fs.existsSync(cachePath), 'a probe result must be persisted to the cache file');

    // Second call with the SAME version+digest+name must hit the cache and
    // never re-invoke /api/chat's probe path (only /api/show, which does not
    // count toward "did a probe run again").
    let chatCalledAgain = false;
    const { server: server2, host: host2 } = await startFakeOllama({
      '/api/show': (req, res) => json(res, { capabilities: ['completion'], details: { digest: 'sha256:cache-test-digest' } }),
      '/api/version': (req, res) => json(res, { version: '0.9.9-test' }),
      '/api/chat': (req, res, body) => { chatCalledAgain = true; json(res, { message: { content: '{}' }, done: true }); },
    });
    try {
      const r2 = await getModelCapabilities({ host: host2, model, probe: true });
      assert.equal(r2.cached, true);
      assert.equal(r2.capabilities.tools, true);
      assert.equal(chatCalledAgain, false, 'a cache hit must not re-run the inference-consuming probe');
    } finally { server2.close(); }
  } finally {
    server.close();
    try { fs.unlinkSync(cachePath); } catch {}
  }
});
