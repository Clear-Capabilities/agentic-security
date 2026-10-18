// The built-in local-model arm (PRD 6), against a stand-in Ollama server that speaks the /api/chat protocol. It proves the request
// the lab sends, the leakage guard, the loopback-only rule, error and timeout mapping and the validation of the model's answer. It does
// NOT say anything about how a real model performs.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { runArmTask, validateArm } from '../../src/posture/evaluation/lab/arms.js';

async function ollama(handler) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let b = ''; req.on('data', (d) => { b += d; });
    req.on('end', () => { const body = b ? JSON.parse(b) : null; seen.push({ url: req.url, body }); handler(req, res, body); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { host: `http://127.0.0.1:${server.address().port}`, seen, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
const chat = (content, extra = {}) => (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ message: { content: typeof content === 'string' ? content : JSON.stringify(content) }, done: true, prompt_eval_count: 120, eval_count: 30, ...extra })); };
const arm = (host, over = {}) => ({ id: 'local-qwen', kind: 'model', tasks: ['detect', 'falsify', 'exploit', 'patch'], model: { id: 'qwen3:4b', provider: 'ollama', local: true, endpoint: host }, adapter: { type: 'ollama', host, timeoutMs: 5000 }, price: { inputPerMTok: 0, outputPerMTok: 0 }, ...over });
const ws = () => { const d = mkTestTmp('ollama-ws-'); fs.writeFileSync(path.join(d, 'app.js'), "const q = 'SELECT * FROM t WHERE id = ' + req.query.id;\ndb.query(q);\n"); return d; };
const req = (task, extra = {}) => ({ schema: 'agentic-security/eval-request', task, language: 'javascript', ...extra });

test('validation: the ollama adapter must be a local model on a loopback host', () => {
  assert.equal(validateArm(arm('http://127.0.0.1:11434')).ok, true);
  assert.match(validateArm(arm('http://127.0.0.1:11434', { model: { id: 'm', provider: 'ollama', local: false, endpoint: 'https://x.example' } })).errors.join(), /model\.local must be true/);
  assert.match(validateArm({ ...arm('http://127.0.0.1:11434'), adapter: { type: 'ollama', host: 'https://models.example.com' } }).errors.join(), /loopback/);
  assert.match(validateArm({ ...arm('http://127.0.0.1:11434'), kind: 'deterministic' }).errors.join(), /model arm/);
});

test('detect: the prompt carries the numbered source, the schema constrains the answer, usage is reported tokens', async () => {
  const s = await ollama(chat({ findings: [{ file: 'app.js', line: 1, cwe: 'CWE-89', confidence: 0.9 }] }));
  try {
    const r = await runArmTask({ arm: arm(s.host), task: 'detect', request: req('detect'), workspaceDir: ws() });
    assert.equal(r.status, 'completed', r.reason);
    assert.deepEqual(r.output.findings, [{ file: 'app.js', line: 1, cwe: 'CWE-89', confidence: 0.9 }]);
    assert.equal(r.usage.inputTokens, 120); assert.equal(r.usage.outputTokens, 30); assert.equal(r.usage.usdSource, 'computed-from-reported-tokens'); assert.equal(r.usage.usd, 0);
    const sent = s.seen[0].body;
    assert.equal(s.seen[0].url, '/api/chat'); assert.equal(sent.model, 'qwen3:4b'); assert.equal(sent.stream, false); assert.equal(sent.options.temperature, 0);
    assert.ok(sent.format?.properties?.findings, 'a JSON schema constrains the model');
    assert.match(sent.messages[0].content, /1\| const q = 'SELECT/); assert.match(sent.messages[0].content, /### app\.js/);
  } finally { await s.close(); }
});

test('falsify, patch and exploit answers go through the same validation as a command arm', async () => {
  const cases = [
    ['falsify', { verdicts: { c1: 'confirmed', c2: 'nonsense' } }, (o) => assert.deepEqual(o.verdicts, { c1: 'confirmed', c2: 'uncertain' }), { candidates: [{ id: 'c1', file: 'app.js', line: 1, cwe: 'CWE-89' }] }],
    ['patch', { files: { 'app.js': 'fixed', bad: 5 } }, (o) => assert.deepEqual(o.files, { 'app.js': 'fixed' }), { target: { file: 'app.js', line: 1, cwe: 'CWE-89' } }],
    ['exploit', { reproducer: { lang: 'javascript' } }, (o) => assert.equal(o.reproducer.lang, 'javascript'), { target: { file: 'app.js', line: 1, cwe: 'CWE-89' } }],
  ];
  for (const [task, answer, check, extra] of cases) {
    const s = await ollama(chat(answer));
    try {
      const r = await runArmTask({ arm: arm(s.host), task, request: req(task, extra), workspaceDir: ws() });
      assert.equal(r.status, 'completed', `${task}: ${r.reason}`); check(r.output);
    } finally { await s.close(); }
  }
});

test('typed failures: not installed, unreachable, not JSON, wrong shape, timeout and cancellation are statuses, never scores', async () => {
  const miss = await ollama((q, res) => { res.writeHead(404, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: "model 'qwen3:4b' not found" })); });
  try { const r = await runArmTask({ arm: arm(miss.host), task: 'detect', request: req('detect'), workspaceDir: ws() }); assert.equal(r.status, 'unavailable'); assert.match(r.reason, /ollama-model-not-installed/); } finally { await miss.close(); }

  const dead = await ollama(chat({})); const host = dead.host; await dead.close();
  assert.equal((await runArmTask({ arm: arm(host), task: 'detect', request: req('detect'), workspaceDir: ws() })).status, 'unavailable');

  for (const [answer, re] of [['I think there is an injection', /did not return JSON/], [['a'], /expected a JSON object/], [{ nope: 1 }, /detect needs "findings"/]]) {
    const s = await ollama(chat(answer));
    try { const r = await runArmTask({ arm: arm(s.host), task: 'detect', request: req('detect'), workspaceDir: ws() }); assert.equal(r.status, 'error'); assert.match(r.reason, re); } finally { await s.close(); }
  }
  const slow = await ollama(() => {});
  try {
    const r = await runArmTask({ arm: arm(slow.host, { adapter: { type: 'ollama', host: slow.host, timeoutMs: 1000 } }), task: 'detect', request: req('detect'), workspaceDir: ws() });
    assert.equal(r.status, 'timeout');
    const ac = new AbortController(); setTimeout(() => ac.abort(), 200);
    const c = await runArmTask({ arm: arm(slow.host), task: 'detect', request: req('detect'), workspaceDir: ws(), signal: ac.signal });
    assert.equal(c.status, 'error'); assert.match(c.reason, /cancelled/);
  } finally { await slow.close(); }
});

test('the leakage guard stops a prompt that carries a protected term before anything is sent; no request reaches the server', async () => {
  const s = await ollama(chat({ findings: [] }));
  try {
    const dir = ws(); fs.writeFileSync(path.join(dir, 'app.js'), '// see GHSA-aaaa-bbbb-cccc for details\nexec(x);\n');
    const r = await runArmTask({ arm: arm(s.host), task: 'detect', request: req('detect'), workspaceDir: dir, terms: ['GHSA-aaaa-bbbb-cccc'] });
    assert.equal(r.status, 'blocked'); assert.match(r.reason, /leakage guard/);
    assert.equal(s.seen.length, 0);
  } finally { await s.close(); }
});

test('a non-loopback host is blocked at run time too, and a failed local model is never retried against any other provider', async () => {
  const r = await runArmTask({ arm: { ...arm('http://127.0.0.1:1'), adapter: { type: 'ollama', host: 'https://models.example.com' } }, task: 'detect', request: req('detect'), workspaceDir: ws() });
  assert.equal(r.status, 'blocked'); assert.match(r.reason, /only talks to a loopback server/);
  let calls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (...a) => { calls++; assert.match(String(a[0]), /^http:\/\/127\.0\.0\.1:/, 'every request stays on the loopback host'); throw new Error('connection refused'); };
  try {
    const u = await runArmTask({ arm: arm('http://127.0.0.1:9'), task: 'detect', request: req('detect'), workspaceDir: ws() });
    assert.equal(u.status, 'unavailable'); assert.equal(calls, 1, 'exactly one attempt and no fallback');
  } finally { globalThis.fetch = originalFetch; }
});
