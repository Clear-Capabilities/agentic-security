// R11 — the local / offline model path.
//
// The feature is the GUARANTEE, not the convenience: under this preset the
// prompt must not be able to leave the machine. So most of these tests are
// attempts to make it leave.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isLoopbackUrl, localEndpointConfig, renderLocalPath,
  DEFAULT_LOCAL_ENDPOINT, DEFAULT_LOCAL_TIMEOUT_MS,
} from '../src/llm-validator/local-endpoint.js';

test('literal loopback addresses are accepted', () => {
  for (const u of [
    'http://127.0.0.1:11434/v1/chat/completions',
    'http://localhost:8080/v1',
    'https://127.0.0.1/x',
    'http://127.1.2.3:1234/v1',
    'http://[::1]:9999/v1',
  ]) {
    assert.equal(isLoopbackUrl(u), true, `rejected loopback ${u}`);
  }
});

test('anything not literally loopback is refused', () => {
  for (const u of [
    'https://api.anthropic.com/v1/messages',
    'http://10.0.0.5:11434/v1',
    'http://192.168.1.10/v1',
    'http://example.com/v1',
    // The dangerous near-misses: names and encodings that LOOK local.
    'http://localhost.evil.com/v1',
    'http://127.0.0.1.evil.com/v1',
    'http://not-localhost/v1',
    'ftp://127.0.0.1/v1',
    'file:///etc/passwd',
    'not a url',
    '',
    null,
  ]) {
    assert.equal(isLoopbackUrl(u), false, `accepted non-loopback ${u}`);
  }
});

test('a hostname that could resolve to loopback is still refused', () => {
  // Accepting names would mean trusting a resolver: a name answering 127.0.0.1
  // today can answer a public address tomorrow, and the guarantee would be
  // silently void. Only literals count.
  assert.equal(isLoopbackUrl('http://my-local-llm/v1'), false);
  assert.equal(isLoopbackUrl('http://localhost4/v1'), false);
});

test('the default endpoint is loopback', () => {
  assert.equal(isLoopbackUrl(DEFAULT_LOCAL_ENDPOINT), true);
  const r = localEndpointConfig({});
  assert.equal(r.ok, true);
  assert.equal(r.config.endpoint, DEFAULT_LOCAL_ENDPOINT);
  assert.equal(r.config.egress, 'loopback-only');
  assert.equal(r.config.timeoutMs, DEFAULT_LOCAL_TIMEOUT_MS);
});

test('a remote endpoint under the local preset is refused, not used', () => {
  const r = localEndpointConfig({ AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /refuses a non-loopback endpoint/);
  assert.match(r.reason, /never leaves this machine/);
});

test('no API key is invented for the local path', () => {
  const r = localEndpointConfig({});
  assert.equal(r.config.apiKey, null);
  // An inherited cloud key must not be attached to a local call either.
  const r2 = localEndpointConfig({ ANTHROPIC_API_KEY: 'sk-should-not-be-used' });
  assert.equal(r2.config.apiKey, null);
});

test('an explicitly supplied key is still honoured for local servers that want one', () => {
  const r = localEndpointConfig({ AGENTIC_SECURITY_LLM_API_KEY: 'local-token' });
  assert.equal(r.config.apiKey, 'local-token');
});

test('the timeout is overridable but never zero or negative', () => {
  assert.equal(localEndpointConfig({ AGENTIC_SECURITY_LLM_TIMEOUT_MS: '5000' }).config.timeoutMs, 5000);
  for (const bad of ['0', '-1', 'abc', '']) {
    assert.equal(
      localEndpointConfig({ AGENTIC_SECURITY_LLM_TIMEOUT_MS: bad }).config.timeoutMs,
      DEFAULT_LOCAL_TIMEOUT_MS,
      `bad timeout ${bad} did not fall back`,
    );
  }
});

test('the model name is overridable and defaulted', () => {
  assert.equal(localEndpointConfig({}).config.model, 'local-model');
  assert.equal(localEndpointConfig({ AGENTIC_SECURITY_LLM_MODEL: 'qwen' }).config.model, 'qwen');
});

test('the rendered line states the guarantee', () => {
  const line = renderLocalPath(localEndpointConfig({}).config);
  assert.match(line, /loopback-enforced/);
  assert.match(line, /no egress/);
  assert.equal(renderLocalPath(null), null);
});

test('the local preset beats a stray remote BYO endpoint', async () => {
  // The scenario: an inherited AGENTIC_SECURITY_LLM_ENDPOINT pointing at a
  // cloud provider while the operator asked for `local`. The tier must switch
  // OFF, not quietly call the remote host.
  const { _internal } = await import('../src/llm-validator/index.js');
  const saved = { ...process.env };
  try {
    process.env.AGENTIC_SECURITY_LLM_PRESET = 'local';
    process.env.AGENTIC_SECURITY_LLM_ENDPOINT = 'https://api.example.com/v1/messages';
    assert.equal(_internal.endpointConfig(), null, 'a remote endpoint was accepted under the local preset');

    process.env.AGENTIC_SECURITY_LLM_ENDPOINT = 'http://127.0.0.1:11434/v1/chat/completions';
    const cfg = _internal.endpointConfig();
    assert.equal(cfg.preset, 'local');
    assert.equal(cfg.endpoint, 'http://127.0.0.1:11434/v1/chat/completions');
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});

test('findings are left unvalidated with the refusal reason, never dropped', async () => {
  const { validateMany } = await import('../src/llm-validator/index.js');
  const saved = { ...process.env };
  try {
    process.env.AGENTIC_SECURITY_LLM_PRESET = 'local';
    process.env.AGENTIC_SECURITY_LLM_ENDPOINT = 'https://api.example.com/v1/messages';
    const findings = [{ id: 'a', severity: 'high', file: 'x.js', line: 1 }];
    const out = await validateMany(findings, { fileContents: {}, scanRoot: null });
    assert.equal(out.length, 1, 'a refusal must not drop findings');
    assert.equal(out[0].validator_verdict, 'unvalidated');
    assert.match(out[0].validator_skipped_reason, /non-loopback/);
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});
