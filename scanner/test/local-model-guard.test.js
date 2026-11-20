// The `ollama` and `local` presets promise that no prompt leaves this machine. A loopback host is not enough for that promise:
// Ollama also serves "cloud" models, listed beside local ones and answering on the same port, that forward every prompt to a
// remote service. These tests pin the refusal in both directions at each place a model is resolved or called (provider
// resolution, the Ollama client used by discovery, the validator, the proposals and repair, the consensus list, and the
// `local` preset's OpenAI-compatible path), plus the two client behaviours added beside it: thinking turned off for a short
// structured answer where the model supports it, and a silently truncated prompt reported instead of answered.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { resolveProvider } from '../src/llm-validator/providers.js';
import { callOllamaChat, verifyLocalPresetModel, OLLAMA_ERROR_CODES, _internals } from '../src/llm-validator/ollama-provider.js';
import { isCloudModelName } from '../src/llm-validator/cloud-model.js';
import { resolveLlmInvokeWithDecision, defaultLlmInvoke } from '../src/discovery/llm-invoke.js';
import { validateMany } from '../src/llm-validator/index.js';
import { proposeOllamaFix } from '../src/llm-validator/fix-proposal.js';

beforeEach(() => _internals.resetModelCaches());

/**
 * A fake Ollama: `models` is the listing (`remote: true` marks a cloud-forwarded one), `show` the capabilities, `ps` the
 * loaded context length, `chat` the reply. Every request is recorded.
 */
function fakeOllama({ models = [], capabilities = null, contextLength = null, promptEvalCount = 12, content = '{"ok":true}' } = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => {
      const body = b ? JSON.parse(b) : null;
      seen.push({ method: req.method, url: req.url, body });
      const json = (o) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (req.url === '/api/tags') return json({ models: models.map((m) => (m.remote ? { name: m.name, model: m.name, remote_host: 'https://remote.example', remote_model: m.name, size: 300 } : { name: m.name, model: m.name, size: 1000 })) });
      if (req.url === '/api/show') return capabilities ? json({ capabilities }) : (res.writeHead(404), res.end('{}'));
      if (req.url === '/api/ps') return json({ models: contextLength ? models.map((m) => ({ name: m.name, model: m.name, context_length: contextLength })) : [] });
      if (req.url === '/api/chat') return json({ message: { role: 'assistant', content }, done: true, prompt_eval_count: promptEvalCount, eval_count: 3 });
      if (req.url === '/v1/chat/completions') return json({ choices: [{ message: { content: '{"challenge":"x","verdict":"escalate","confidence":0.5,"reasoning":"r","file":"a.js","line":3}' } }] });
      res.writeHead(404); res.end('{}');
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, host: `http://127.0.0.1:${server.address().port}` })));
}

async function withEnv(vars, fn) {
  const keys = Object.keys(process.env).filter((k) => k.startsWith('AGENTIC_SECURITY_LLM_') || k.startsWith('AGENTIC_SECURITY_OLLAMA_'));
  const saved = Object.fromEntries([...new Set([...keys, ...Object.keys(vars)])].map((k) => [k, process.env[k]]));
  for (const k of keys) delete process.env[k];
  Object.assign(process.env, vars);
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}
const chats = (seen) => seen.filter((r) => r.url === '/api/chat' || r.url === '/v1/chat/completions');

// ── the name check, at resolution ─────────────────────────────────────────────────────────────────────────────────────────────
test('cloud-tagged names are recognised; ordinary tags are not', () => {
  for (const n of ['minimax-m3.1-flash:cloud', 'gpt-oss:120b-cloud', 'x:CLOUD', 'cloud']) assert.equal(isCloudModelName(n), true, n);
  for (const n of ['qwen3.5:4b', 'cloudy:1b', 'my-cloud-tools:7b', 'soundcloud', '', null]) assert.equal(isCloudModelName(n), false, String(n));
});

test('provider resolution refuses a cloud-tagged model under the ollama and local presets, and accepts a local one', () => {
  const ollama = resolveProvider({ role: 'hunt', env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_LLM_MODEL: 'minimax-m3.1-flash:cloud' } });
  assert.equal(ollama.ok, false);
  assert.match(ollama.reason, /minimax-m3\.1-flash:cloud/);
  assert.match(ollama.reason, /keeps every prompt on this machine/);
  const local = resolveProvider({ role: 'validate', env: { AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_MODEL: 'gpt-oss:120b-cloud' } });
  assert.equal(local.ok, false);
  assert.match(local.reason, /gpt-oss:120b-cloud/);
  // a per-role model is checked too
  assert.equal(resolveProvider({ role: 'fix', env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_LLM_MODEL_FIX: 'big:cloud' } }).ok, false);
  assert.equal(resolveProvider({ role: 'hunt', env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_LLM_MODEL: 'qwen3.5:4b' } }).ok, true);
  assert.equal(resolveProvider({ role: 'validate', env: { AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_MODEL: 'local-model' } }).ok, true);
  // an operator who opted into a remote Ollama host gave the local promise up; the name is not checked there
  assert.equal(resolveProvider({ role: 'hunt', env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: 'http://10.0.0.5:11434', AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE: '1', AGENTIC_SECURITY_LLM_MODEL: 'big:cloud' } }).ok, true);
});

// ── the listing check, before the request ─────────────────────────────────────────────────────────────────────────────────────
test('the Ollama client refuses a model the server lists as remote, under any name, and sends no prompt', async () => {
  const { server, seen, host } = await fakeOllama({ models: [{ name: 'renamed-remote:latest', remote: true }, { name: 'qwen3.5:4b' }] });
  try {
    const r = await callOllamaChat({ host, model: 'renamed-remote', messages: [{ role: 'user', content: 'secret code' }] });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'ollama-remote-model-refused');
    assert.ok(OLLAMA_ERROR_CODES.includes(r.code));
    assert.match(r.reason, /renamed-remote/);
    assert.match(r.reason, /remote host https:\/\/remote\.example/);
    assert.equal(chats(seen).length, 0, 'no prompt was sent');
    const ok = await callOllamaChat({ host, model: 'qwen3.5:4b', messages: [{ role: 'user', content: 'x' }] });
    assert.equal(ok.ok, true, 'a locally installed model is called');
    assert.equal(chats(seen).length, 1);
  } finally { server.close(); }
});

test('the Ollama client fails closed when it cannot confirm the model is local', async () => {
  const { server, seen, host } = await fakeOllama({ models: [{ name: 'qwen3.5:4b' }] });
  try {
    const missing = await callOllamaChat({ host, model: 'not-listed:7b', messages: [{ role: 'user', content: 'x' }] });
    assert.equal(missing.ok, false);
    assert.equal(missing.code, 'ollama-model-not-installed');
    const tagged = await callOllamaChat({ host, model: 'anything:cloud', messages: [{ role: 'user', content: 'x' }] });
    assert.equal(tagged.code, 'ollama-remote-model-refused');
    assert.equal(chats(seen).length, 0);
  } finally { server.close(); }
});

test('discovery: a remote model under the ollama preset degrades the hunt with the refusal, and a refused preset refuses the consensus list too', async () => {
  const { server, seen, host } = await fakeOllama({ models: [{ name: 'renamed-remote:latest', remote: true }] });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: 'renamed-remote' }, async () => {
      await assert.rejects(defaultLlmInvoke('hunt prompt', { role: 'hunt' }), /remote-model-refused/);
    });
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: 'x:cloud' }, async () => {
      const single = resolveLlmInvokeWithDecision({ role: 'hunt' });
      assert.equal(single.invoke, null);
      assert.match(single.decision.reason, /x:cloud/);
      const consensus = resolveLlmInvokeWithDecision({ role: 'hunt', endpoints: `${host}/a,https://remote.example/v1` });
      assert.equal(consensus.invoke, null, 'no voter is called when the preset itself was refused');
      assert.match(consensus.decision.reason, /x:cloud/);
    });
    assert.equal(chats(seen).length, 0);
  } finally { server.close(); }
});

test('repair proposals: a cloud-forwarded fix model is refused before any prompt, a local one is used', async () => {
  const { server, seen, host } = await fakeOllama({ models: [{ name: 'renamed-remote:latest', remote: true }, { name: 'qwen3.5:4b' }], content: '{"patch":"x"}' });
  try {
    const finding = { file: 'app.js', line: 1, vuln: 'Weak hash (MD5)', cwe: 'CWE-328', severity: 'medium' };
    const refused = await proposeOllamaFix({ finding, fileContent: 'x', scanRoot: '.', env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: 'renamed-remote' } });
    assert.equal(refused.ok, false);
    assert.match(String(refused.reason), /renamed-remote/);
    assert.equal(chats(seen).length, 0);
    await proposeOllamaFix({ finding, fileContent: 'x', scanRoot: '.', env: { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: 'qwen3.5:4b' } });
    assert.ok(chats(seen).length >= 1, 'the local model is called');
  } finally { server.close(); }
});

test('the local preset: a model the loopback Ollama lists as remote is refused by the validator, a local one is called', async () => {
  const scanRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'local-guard-'));
  const { server, seen, host } = await fakeOllama({ models: [{ name: 'renamed-remote:latest', remote: true }, { name: 'local-model:latest' }] });
  const finding = () => [{ id: 'f1', severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', file: 'a.js', line: 3, family: 'sqli', snippet: 'db.query(q)' }];
  const fileContents = { 'a.js': 'const q = 1;\nconst r = 2;\ndb.query(q);\n' };
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: `${host}/v1/chat/completions`, AGENTIC_SECURITY_LLM_MODEL: 'renamed-remote' }, async () => {
      const out = await validateMany(finding(), { fileContents, scanRoot });
      assert.equal(out.length, 1, 'the finding is kept');
      assert.notEqual(out[0].validator_verdict, 'accept');
      assert.notEqual(out[0].validator_verdict, 'reject');
      assert.equal(chats(seen).length, 0, 'no prompt reached the forwarding model');
    });
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: `${host}/v1/chat/completions`, AGENTIC_SECURITY_LLM_MODEL: 'local-model' }, async () => {
      await validateMany(finding(), { fileContents, scanRoot });
      assert.ok(chats(seen).length >= 1, 'a local model is called');
    });
  } finally { server.close(); fs.rmSync(scanRoot, { recursive: true, force: true }); }
});

test('the local preset against a loopback server that is not Ollama is not blocked by the listing check', async () => {
  const server = http.createServer((req, res) => { res.writeHead(404); res.end('{}'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const r = await verifyLocalPresetModel({ endpoint: `http://127.0.0.1:${server.address().port}/v1/chat/completions`, model: 'local-model' });
    assert.equal(r.ok, true);
    assert.equal(r.checked, false);
    assert.equal((await verifyLocalPresetModel({ endpoint: 'http://127.0.0.1:1/v1', model: 'x:cloud' })).ok, false, 'the name check still holds');
  } finally { server.close(); }
});

// ── think:false for a short structured answer ──────────────────────────────────────────────────────────────────────────────────
test('a short structured answer turns thinking off for a model that supports it, and only then', async () => {
  const thinking = await fakeOllama({ models: [{ name: 'reasoner:4b' }], capabilities: ['completion', 'thinking'] });
  const plain = await fakeOllama({ models: [{ name: 'coder:1b' }], capabilities: ['completion'] });
  try {
    await callOllamaChat({ host: thinking.host, model: 'reasoner:4b', messages: [{ role: 'user', content: 'x' }], shortAnswer: true });
    assert.equal(chats(thinking.seen).at(-1).body.think, false);
    await callOllamaChat({ host: thinking.host, model: 'reasoner:4b', messages: [{ role: 'user', content: 'x' }] });
    assert.equal('think' in chats(thinking.seen).at(-1).body, false, 'not asked for a short answer: the model default stands');
    await callOllamaChat({ host: thinking.host, model: 'reasoner:4b', messages: [{ role: 'user', content: 'x' }], shortAnswer: true, think: true });
    assert.equal(chats(thinking.seen).at(-1).body.think, true, 'an explicit caller choice wins');
    await callOllamaChat({ host: plain.host, model: 'coder:1b', messages: [{ role: 'user', content: 'x' }], shortAnswer: true });
    assert.equal('think' in chats(plain.seen).at(-1).body, false, 'a model without thinking gets no think field');
  } finally { thinking.server.close(); plain.server.close(); }
});

// ── silent truncation ──────────────────────────────────────────────────────────────────────────────────────────────────────────
test('a prompt that filled the loaded context window is reported as truncated, and discovery degrades instead of parsing the answer', async () => {
  const cut = await fakeOllama({ models: [{ name: 'small-ctx:1b' }], contextLength: 4096, promptEvalCount: 4096 });
  const fits = await fakeOllama({ models: [{ name: 'small-ctx:1b' }], contextLength: 4096, promptEvalCount: 1500 });
  try {
    const r = await callOllamaChat({ host: cut.host, model: 'small-ctx:1b', messages: [{ role: 'user', content: 'x'.repeat(50000) }] });
    assert.equal(r.ok, true);
    assert.equal(r.result.promptTruncated, true);
    assert.equal(r.result.contextLength, 4096);
    const f = await callOllamaChat({ host: fits.host, model: 'small-ctx:1b', messages: [{ role: 'user', content: 'x' }] });
    assert.equal(f.result.promptTruncated, undefined);
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: cut.host, AGENTIC_SECURITY_LLM_MODEL: 'small-ctx:1b' }, async () => {
      await assert.rejects(defaultLlmInvoke('hunt prompt', { role: 'hunt' }), /prompt truncated: 4096 prompt tokens filled the loaded model's 4096-token context window/);
    });
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: fits.host, AGENTIC_SECURITY_LLM_MODEL: 'small-ctx:1b' }, async () => {
      assert.equal(await defaultLlmInvoke('hunt prompt', { role: 'hunt' }), '{"ok":true}');
    });
  } finally { cut.server.close(); fits.server.close(); }
});
