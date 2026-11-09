// GA-06 §3 (0.195.31): the local endpoint audit. Pinned in both directions:
//   - the loopback spellings the contract table lists, including the ones it did not (IPv6 long form, a trailing dot, upper case,
//     the IPv4-mapped IPv6 form) decide exactly as documented, and the lab arm validator agrees with the one shared rule;
//   - under the `local` or `ollama` preset a consensus endpoint list cannot reach a remote host: the remote voter is refused with a
//     decision, the loopback voters still vote, and an all-remote list calls nothing;
//   - a caller's cancellation reaches the transport from the discovery invoke, the Ollama client and the validator;
//   - a connection that never sends headers fails within the connect timeout, while a slow body does not;
//   - under the process-wide wall budget a later finding is left unvalidated and kept, never dropped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { isLoopbackUrl } from '../src/llm-validator/local-endpoint.js';
import { validateArm } from '../src/posture/evaluation/lab/arms.js';
import { modelFetch, resetModelBudget, ModelTransportError } from '../src/egress/transport.js';
import { callOllamaChat } from '../src/llm-validator/ollama-provider.js';
import { defaultLlmInvoke, resolveLlmInvokeWithDecision } from '../src/discovery/llm-invoke.js';
import { validateMany } from '../src/llm-validator/index.js';

const KEYS = ['AGENTIC_SECURITY_LLM_ENDPOINT', 'AGENTIC_SECURITY_LLM_PRESET', 'AGENTIC_SECURITY_LLM_API_KEY', 'AGENTIC_SECURITY_LLM_ENDPOINTS', 'AGENTIC_SECURITY_LLM_WALL_BUDGET_MS', 'AGENTIC_SECURITY_LLM_VALIDATE', 'AGENTIC_SECURITY_EGRESS_MODE', 'AGENTIC_SECURITY_OLLAMA_HOST', 'AGENTIC_SECURITY_LLM_TIMEOUT_MS'];
async function withEnv(vars, fn) {
  const saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  for (const k of KEYS) delete process.env[k];
  Object.assign(process.env, vars);
  try { return await fn(); } finally { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } }
}
async function withFetch(impl, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = impl;
  try { return await fn(); } finally { globalThis.fetch = orig; }
}
/** A fetch that never answers but honours its abort signal, as a dead port or a stalled handshake does. */
const stalled = (seen = []) => (url, init) => new Promise((_, reject) => {
  seen.push({ url: String(url), init });
  const fail = () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
  if (init?.signal?.aborted) fail(); else init?.signal?.addEventListener('abort', fail, { once: true });
});

test('loopback spellings: the documented forms decide as documented, including the ones the table did not list', () => {
  const table = [
    ['http://127.0.0.1:11434', true], ['http://127.1.2.3', true], ['http://[::1]:11434', true], ['http://localhost:11434/v1', true], ['https://localhost', true],
    ['http://LOCALHOST:11434', true], ['http://[0:0:0:0:0:0:0:1]:11434', true],
    ['http://0x7f.0.0.1', true], ['http://0.0.0.0:11434', false], ['http://[::]:11434', false], ['http://0/', false],
    ['http://evil.example@127.0.0.1', true], ['http://127.0.0.1@evil.example', false], ['http://localhost.evil.example', false], ['http://127.0.0.1.evil.example', false],
    ['http://localhost.', false], ['http://192.168.1.5:11434', false], ['http://[::ffff:127.0.0.1]', false], ['http://127.999.0.1', false],
    ['ftp://127.0.0.1', false], ['file:///x', false], ['', false], ['not a url', false],
  ];
  for (const [url, expected] of table) assert.equal(isLoopbackUrl(url), expected, url);
});

test('the lab arm validator applies the one shared loopback rule, bare host:port included', () => {
  const arm = (host) => ({ id: 'm', kind: 'model', tasks: ['detect'], adapter: { type: 'ollama', host }, model: { id: 'x', provider: 'ollama', local: true } });
  for (const [host, ok] of [['127.0.0.1:11434', true], ['http://127.0.0.1:11434', true], ['http://[::1]:11434', true], ['localhost:11434', true], ['http://127.999.0.1', false], ['http://localhost.evil.example', false], ['http://192.168.1.5:11434', false], ['http://[::ffff:127.0.0.1]', false]]) {
    const r = validateArm(arm(host));
    assert.equal(r.ok, ok, `${host}: ${r.errors.join('; ')}`);
    assert.equal(r.ok, isLoopbackUrl(/^https?:\/\//.test(host) ? host : `http://${host}`), `${host} agrees with isLoopbackUrl`);
  }
});

test('under the local preset a consensus list cannot reach a remote host: the remote voter is refused with a decision and only loopback voters are called', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:11434/v1', AGENTIC_SECURITY_EGRESS_MODE: 'allow' }, async () => {
    const seen = [];
    await withFetch(async (url) => { seen.push(String(url)); return new Response('{"text":"loop"}', { status: 200 }); }, async () => {
      const { invoke, decision, decisions } = resolveLlmInvokeWithDecision({ endpoints: 'http://127.0.0.1:1/v1,https://remote.example/v1', role: 'hunt' });
      assert.equal(typeof invoke, 'function', 'the loopback voter still votes');
      assert.equal(await invoke('p'), 'loop');
      assert.deepEqual(seen, ['http://127.0.0.1:1/v1'], 'the remote endpoint was never called');
      const refused = decisions.find((d) => d.endpoint === 'https://remote.example/v1');
      assert.equal(refused.allowed, false);
      assert.match(refused.reason, /'local' preset keeps every prompt on this machine/);
      assert.equal(decision, refused, 'the aggregate decision names the refusal');
    });
    const all = resolveLlmInvokeWithDecision({ endpoints: 'https://a.example/v1,https://b.example/v1', role: 'hunt' });
    assert.equal(all.invoke, null, 'an all-remote list calls nothing');
    assert.match(all.decision.reason, /non-loopback consensus endpoint is refused/);
  });
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1', AGENTIC_SECURITY_LLM_API_KEY: 'k', AGENTIC_SECURITY_EGRESS_MODE: 'allow' }, async () => {
    const seen = [];
    await withFetch(async (url) => { seen.push(String(url)); return new Response('{"text":"r"}', { status: 200 }); }, async () => {
      const { invoke } = resolveLlmInvokeWithDecision({ endpoints: 'https://remote.example/v1', role: 'hunt' });
      assert.equal(await invoke('p'), 'r', 'with no local preset the consensus list is unchanged');
      assert.deepEqual(seen, ['https://remote.example/v1']);
    });
  });
});

test('cancellation reaches the transport from the discovery invoke, the Ollama client and the validator', async () => {
  const seen = [];
  await withFetch(stalled(seen), async () => {
    const ac = new AbortController();
    const p = defaultLlmInvoke('prompt', { endpoint: 'http://127.0.0.1:1/v1', timeoutMs: 10_000, signal: ac.signal });
    setTimeout(() => ac.abort(new Error('caller cancelled')), 20);
    await assert.rejects(p, (e) => e instanceof ModelTransportError && e.code === 'timeout');
    assert.equal(seen[0].init.signal.aborted, true, 'the request the transport made was aborted');

    const ac2 = new AbortController();
    // no connect timeout here: the probe is about the real network, and this case stubs the fetch
    const q = callOllamaChat({ host: 'http://127.0.0.1:1', model: 'm', messages: [{ role: 'user', content: 'x' }], timeouts: { requestTimeoutMs: 10_000 }, signal: ac2.signal });
    setTimeout(() => ac2.abort(), 20);
    const r = await q;
    assert.equal(r.ok, false);
    assert.equal(r.code, 'ollama-cancelled');
    assert.equal(seen[1].init.signal.aborted, true);
  });
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:1/v1/chat/completions', AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_TIMEOUT_MS: '10000' }, async () => {
    const calls = [];
    await withFetch(stalled(calls), async () => {
      const ac = new AbortController();
      const findings = [{ id: 'f1', severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', file: 'a.js', line: 3, family: 'sqli', snippet: 'db.query(q)' }];
      setTimeout(() => ac.abort(), 30);
      const out = await validateMany(findings, { fileContents: { 'a.js': 'const q = 1;\nconst r = 2;\ndb.query(q);\n' }, scanRoot: process.cwd(), signal: ac.signal });
      assert.equal(out.length, 1, 'the finding is kept');
      assert.notEqual(out[0].validator_verdict, 'reject');
      assert.notEqual(out[0].validator_verdict, 'accept');
      assert.equal(calls.length, 1);
      assert.equal(calls[0].init.signal.aborted, true, 'the validator passed the cancellation through to the request');
    });
  });
});

test('a dead port fails within the connect deadline as connect-refused, a server that accepts and stalls is the call deadline\'s business, and an injected fetch skips the probe', async () => {
  // a port nothing listens on: found by listening and closing, so it is closed for certain
  const closed = await new Promise((resolve) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
  const t0 = Date.now();
  await assert.rejects(modelFetch(`http://127.0.0.1:${closed}/v1`, { method: 'POST', body: '{}' }, { timeoutMs: 60_000, connectTimeoutMs: 500 }), (e) => e instanceof ModelTransportError && e.code === 'connect-refused' && e.connectTimeoutMs === 500);
  assert.ok(Date.now() - t0 < 5000, 'failed on the connect deadline, not the call deadline');
  const r = await callOllamaChat({ host: `http://127.0.0.1:${closed}`, model: 'm', messages: [{ role: 'user', content: 'x' }], timeouts: { connectTimeoutMs: 500, requestTimeoutMs: 60_000 } });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'ollama-unreachable');
  assert.match(r.reason, /connect timeout/);

  // a server that accepts the connection and never answers: the probe passes, the CALL deadline ends it (a non-streaming model
  // sends its headers only when generation is done, so a headers deadline would abort every real generation)
  const silent = net.createServer(() => { /* accept, say nothing */ });
  await new Promise((res) => silent.listen(0, '127.0.0.1', res));
  try {
    const t1 = Date.now();
    await assert.rejects(modelFetch(`http://127.0.0.1:${silent.address().port}/v1`, { method: 'GET' }, { timeoutMs: 150, connectTimeoutMs: 50 }), (e) => e.code === 'timeout');
    assert.ok(Date.now() - t1 >= 100, 'the connect probe passed; the call timeout decided');
  } finally { silent.close(); }

  // an injected fetch means no real network: the probe is skipped and a slow body completes under the call timeout
  const slowBody = async () => {
    const body = new ReadableStream({ async start(c) { await new Promise((res) => setTimeout(res, 120)); c.enqueue(new TextEncoder().encode('{"text":"slow"}')); c.close(); } });
    return new Response(body, { status: 200 });
  };
  const ok = await modelFetch('http://127.0.0.1:1/v1', { method: 'GET' }, { fetchImpl: slowBody, timeoutMs: 10_000, connectTimeoutMs: 40 });
  assert.deepEqual(await ok.json(), { text: 'slow' });
});

test('the process-wide wall budget leaves a later finding unvalidated and kept, never dropped', async () => {
  resetModelBudget();
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:1/v1/chat/completions', AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_WALL_BUDGET_MS: '30' }, async () => {
    let n = 0;
    await withFetch(async () => { n += 1; await new Promise((res) => setTimeout(res, 40)); return new Response(JSON.stringify({ choices: [{ message: { content: '{"verdict":"accept"}' } }] }), { status: 200 }); }, async () => {
      const findings = [1, 2, 3].map((i) => ({ id: `f${i}`, severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', file: 'a.js', line: i, family: 'sqli', snippet: 'db.query(q)' }));
      const out = await validateMany(findings, { fileContents: { 'a.js': 'db.query(q);\ndb.query(q);\ndb.query(q);\n' }, scanRoot: process.cwd() });
      assert.equal(out.length, 3, 'every finding is kept');
      assert.equal(n, 1, 'after the first call spent the budget no further request was made');
      assert.ok(out.slice(1).every((f) => f.validator_verdict !== 'accept' && f.validator_verdict !== 'reject'), 'the later findings carry no model verdict');
    });
  });
  resetModelBudget();
});
