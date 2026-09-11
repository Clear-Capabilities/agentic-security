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

// Adversarial-review fix (2026-09): the cache used to be trusted forever
// once written, with no way for a stale single-trial result to ever
// self-correct short of manually deleting a file under
// ~/.claude/agentic-security/. Two independent, separately-tested fixes.

test('getModelCapabilities: a cache entry older than ttlMs is treated as a miss and re-probed', async () => {
  const model = 'probe-ttl-test-model:unique-' + Date.now();
  let chatCalls = 0;
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion'], details: { digest: 'sha256:ttl-test-digest' } }),
    '/api/version': (req, res) => json(res, { version: '0.9.9-ttl' }),
    '/api/chat': (req, res, body) => {
      chatCalls++;
      if (Array.isArray(body?.tools)) json(res, { message: { content: '', tool_calls: [] }, done: true });
      else json(res, { message: { content: '{"ok": true}' }, done: true });
    },
  });
  const cacheKey = _internals._cacheKey('0.9.9-ttl', 'sha256:ttl-test-digest', model);
  const cachePath = _internals._cachePath(cacheKey);
  try {
    fs.mkdirSync(_internals.CACHE_DIR, { recursive: true });
    // A stale entry, 60 days old, well past any reasonable TTL.
    fs.writeFileSync(cachePath, JSON.stringify({ probedAt: Date.now() - 60 * 24 * 60 * 60 * 1000, result: { tools: true, structuredJson: true } }));
    const r = await getModelCapabilities({ host, model, probe: true, ttlMs: 30 * 24 * 60 * 60 * 1000 });
    assert.equal(r.cached, false, 'a stale entry must be re-probed, not trusted');
    assert.ok(chatCalls > 0, 'a fresh probe must actually call /api/chat');
  } finally { server.close(); try { fs.unlinkSync(cachePath); } catch {} }
});

test('getModelCapabilities: an entry within ttlMs is still trusted (the TTL is a backstop, not a replacement for the key)', async () => {
  const model = 'probe-ttl-fresh-model:unique-' + Date.now();
  let chatCalls = 0;
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion'], details: { digest: 'sha256:ttl-fresh-digest' } }),
    '/api/version': (req, res) => json(res, { version: '0.9.9-ttl-fresh' }),
    '/api/chat': (req, res) => { chatCalls++; json(res, { message: { content: '{}' }, done: true }); },
  });
  const cacheKey = _internals._cacheKey('0.9.9-ttl-fresh', 'sha256:ttl-fresh-digest', model);
  const cachePath = _internals._cachePath(cacheKey);
  try {
    fs.mkdirSync(_internals.CACHE_DIR, { recursive: true });
    fs.writeFileSync(cachePath, JSON.stringify({ probedAt: Date.now() - 1000, result: { tools: true, structuredJson: true } }));
    const r = await getModelCapabilities({ host, model, probe: true, ttlMs: 30 * 24 * 60 * 60 * 1000 });
    assert.equal(r.cached, true);
    assert.equal(chatCalls, 0, 'a fresh cache entry must not trigger a re-probe');
  } finally { server.close(); try { fs.unlinkSync(cachePath); } catch {} }
});

test('getModelCapabilities: force:true always re-probes, even with a fresh cache entry', async () => {
  const model = 'probe-force-test-model:unique-' + Date.now();
  let chatCalls = 0;
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion'], details: { digest: 'sha256:force-test-digest' } }),
    '/api/version': (req, res) => json(res, { version: '0.9.9-force' }),
    '/api/chat': (req, res, body) => {
      chatCalls++;
      if (Array.isArray(body?.tools)) json(res, { message: { content: '', tool_calls: [{ function: { name: 'echo_capability_probe', arguments: {} } }] }, done: true });
      else json(res, { message: { content: '{"ok": true}' }, done: true });
    },
  });
  const cacheKey = _internals._cacheKey('0.9.9-force', 'sha256:force-test-digest', model);
  const cachePath = _internals._cachePath(cacheKey);
  try {
    fs.mkdirSync(_internals.CACHE_DIR, { recursive: true });
    fs.writeFileSync(cachePath, JSON.stringify({ probedAt: Date.now(), result: { tools: false, structuredJson: false } }));
    const r = await getModelCapabilities({ host, model, probe: true, force: true });
    assert.equal(r.cached, false, 'force:true must never report a cache hit');
    assert.ok(chatCalls > 0, 'force:true must actually re-run the probe');
    assert.equal(r.capabilities.tools, true, 'the fresh (correct) result must win over the stale cached (wrong) one');
  } finally { server.close(); try { fs.unlinkSync(cachePath); } catch {} }
});

test('getModelCapabilities: a pre-TTL cache file (bare result, no probedAt envelope) is still read as fresh — backward compatible', async () => {
  const model = 'probe-legacy-cache-model:unique-' + Date.now();
  let chatCalls = 0;
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion'], details: { digest: 'sha256:legacy-digest' } }),
    '/api/version': (req, res) => json(res, { version: '0.9.9-legacy' }),
    '/api/chat': (req, res) => { chatCalls++; json(res, { message: { content: '{}' }, done: true }); },
  });
  const cacheKey = _internals._cacheKey('0.9.9-legacy', 'sha256:legacy-digest', model);
  const cachePath = _internals._cachePath(cacheKey);
  try {
    fs.mkdirSync(_internals.CACHE_DIR, { recursive: true });
    // The OLD cache shape, before this fix: a bare result object, no envelope.
    fs.writeFileSync(cachePath, JSON.stringify({ tools: true, structuredJson: true }));
    const r = await getModelCapabilities({ host, model, probe: true });
    assert.equal(r.cached, true, 'a legacy bare-result cache file must still be read as a hit');
    assert.equal(chatCalls, 0);
    assert.equal(r.capabilities.tools, true);
  } finally { server.close(); try { fs.unlinkSync(cachePath); } catch {} }
});
