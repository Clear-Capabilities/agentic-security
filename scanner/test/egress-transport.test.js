// The shared model transport (GA-06.3): every model request leaves the process through `modelFetch`, which never follows a
// redirect, caps the reply while it is read, bounds every call with a deadline, accounts a process-wide wall budget, and ignores
// proxy variables. Each property is pinned against a real loopback server in both directions.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import { modelFetch, modelBudget, resetModelBudget, ModelTransportError, DEFAULT_MAX_RESPONSE_BYTES, TRANSPORT_ERROR_CODES } from '../src/egress/transport.js';

const servers = [];
after(() => { for (const s of servers) s.close(); });

/** A loopback server whose handler decides the reply; returns its base URL. */
function serve(handler) {
  const s = http.createServer(handler);
  servers.push(s);
  return new Promise((resolve) => s.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${s.address().port}`)));
}

const json = (res, obj, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

test('an ordinary reply comes back with status, text and json over the same capped body', async () => {
  const base = await serve((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => json(res, { echoed: JSON.parse(body).prompt, choices: [{ message: { content: 'hello' } }] }));
  });
  const r = await modelFetch(`${base}/v1`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ prompt: 'hi' }) });
  assert.equal(r.ok, true);
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.echoed, 'hi');
  assert.equal(JSON.parse(await r.text()).choices[0].message.content, 'hello');
  assert.ok(r.bytes > 0);
});

test('a redirect is never followed: the call fails with the redirect code and the target is never reached', async () => {
  let targetHits = 0;
  const target = await serve((req, res) => { targetHits++; json(res, { leaked: true }); });
  const base = await serve((req, res) => { res.writeHead(302, { location: `${target}/elsewhere` }); res.end(); });
  await assert.rejects(modelFetch(`${base}/v1`, { method: 'POST', body: '{}' }), (e) => e instanceof ModelTransportError && e.code === 'redirect');
  assert.equal(targetHits, 0, 'the redirect target must never see the request');
});

test('a 3xx without a location is a redirect too, not a success', async () => {
  const base = await serve((req, res) => { res.writeHead(304); res.end(); });
  await assert.rejects(modelFetch(`${base}/v1`, { method: 'GET' }), (e) => e.code === 'redirect');
});

test('a reply over the byte cap is refused while it is read, and the request is aborted', async () => {
  let ended = false;
  const base = await serve((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"text":"' + 'x'.repeat(2000));
    req.on('close', () => { ended = true; });
    // keep sending past the cap until the client goes away
    const t = setInterval(() => { if (res.destroyed || ended) { clearInterval(t); return; } res.write('x'.repeat(2000)); }, 2);
  });
  await assert.rejects(modelFetch(`${base}/v1`, { method: 'GET' }, { maxResponseBytes: 5000 }), (e) => e.code === 'response-too-large' && e.limit === 5000);
});

test('a reply inside the cap is accepted, so the cap is a cap and not a truncation', async () => {
  const base = await serve((req, res) => json(res, { text: 'y'.repeat(4000) }));
  const r = await modelFetch(`${base}/v1`, { method: 'GET' }, { maxResponseBytes: 5000 });
  assert.equal((await r.json()).text.length, 4000);
});

test('a stalled connection is aborted at the deadline with the timeout code', async () => {
  const base = await serve(() => { /* never answers */ });
  const t0 = Date.now();
  await assert.rejects(modelFetch(`${base}/v1`, { method: 'GET' }, { timeoutMs: 150 }), (e) => e.code === 'timeout');
  assert.ok(Date.now() - t0 < 5000, 'the deadline, not a socket default, ended the call');
});

test('a reply whose body stalls after the headers is aborted at the deadline too', async () => {
  const base = await serve((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{"text":"'); /* never ends */ });
  await assert.rejects(modelFetch(`${base}/v1`, { method: 'GET' }, { timeoutMs: 150 }), (e) => e.code === 'timeout');
});

test('a caller signal aborts the call; the stricter of the two bounds wins', async () => {
  const base = await serve(() => { /* never answers */ });
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 50);
  const t0 = Date.now();
  await assert.rejects(modelFetch(`${base}/v1`, { method: 'GET' }, { timeoutMs: 10_000, signal: ac.signal }), (e) => e.code === 'timeout');
  assert.ok(Date.now() - t0 < 5000);
});

test('the wall budget: a spent budget refuses the next call before any request is made, and the remaining budget caps a call', async () => {
  let hits = 0;
  const base = await serve((req, res) => { hits++; json(res, { ok: 1 }); });
  resetModelBudget();
  const env = { AGENTIC_SECURITY_LLM_WALL_BUDGET_MS: '1' };
  // the first call fits (nothing spent yet) and is capped by the remaining 1 ms or the server's speed, whichever comes first
  try { await modelFetch(`${base}/v1`, { method: 'GET' }, { env }); } catch (e) { assert.equal(e.code, 'timeout'); }
  const b = modelBudget(env);
  assert.equal(b.limitMs, 1);
  assert.ok(b.calls === 1 && b.spentMs >= 1, `one call accounted: ${JSON.stringify(b)}`);
  const before = hits;
  await assert.rejects(modelFetch(`${base}/v1`, { method: 'GET' }, { env }), (e) => e.code === 'budget-exhausted');
  assert.equal(hits, before, 'a refused call never reaches the server');
  resetModelBudget();
  assert.equal(modelBudget({}).limitMs, null, 'no budget variable means no global limit');
});

test('proxy variables change nothing: a loopback call with a bogus proxy configured still reaches the endpoint', async () => {
  const base = await serve((req, res) => json(res, { reached: true }));
  const saved = { HTTP_PROXY: process.env.HTTP_PROXY, HTTPS_PROXY: process.env.HTTPS_PROXY, http_proxy: process.env.http_proxy };
  process.env.HTTP_PROXY = 'http://127.0.0.1:1';
  process.env.HTTPS_PROXY = 'http://127.0.0.1:1';
  process.env.http_proxy = 'http://127.0.0.1:1';
  try {
    const r = await modelFetch(`${base}/v1`, { method: 'GET' });
    assert.equal((await r.json()).reached, true);
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
});

test('a caller cannot re-enable redirects or replace the deadline through the init', async () => {
  const seen = [];
  const fetchImpl = async (url, init) => { seen.push(init); return new Response('{"a":1}', { status: 200 }); };
  const r = await modelFetch('http://127.0.0.1:1/v1', { method: 'POST', redirect: 'follow', signal: null, body: '{}' }, { fetchImpl });
  assert.equal(r.ok, true);
  assert.equal(seen[0].redirect, 'error');
  assert.ok(seen[0].signal instanceof AbortSignal);
});

test('an injected fake without a stream body is still capped', async () => {
  const fetchImpl = async () => ({ ok: true, status: 200, statusText: 'OK', headers: new Headers(), json: async () => ({ text: 'z'.repeat(100) }) });
  await assert.rejects(modelFetch('http://127.0.0.1:1/v1', { method: 'GET' }, { fetchImpl, maxResponseBytes: 50 }), (e) => e.code === 'response-too-large');
  const r = await modelFetch('http://127.0.0.1:1/v1', { method: 'GET' }, { fetchImpl, maxResponseBytes: 500 });
  assert.equal((await r.json()).text.length, 100);
});

test('a connection refusal is a network error with the cause kept', async () => {
  const s = http.createServer(() => {});
  const port = await new Promise((resolve) => s.listen(0, '127.0.0.1', () => resolve(s.address().port)));
  await new Promise((resolve) => s.close(resolve));
  await assert.rejects(modelFetch(`http://127.0.0.1:${port}/v1`, { method: 'GET' }, { timeoutMs: 2000 }), (e) => e.code === 'network' && Boolean(e.cause));
});

test('the defaults and the error vocabulary are the documented ones', () => {
  assert.equal(DEFAULT_MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
  assert.deepEqual([...TRANSPORT_ERROR_CODES], ['redirect', 'timeout', 'response-too-large', 'budget-exhausted', 'network', 'connect-timeout', 'connect-refused']);
});
