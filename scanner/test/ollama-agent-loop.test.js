// agentic-security-ollama-offline-prd.md §18.2/§18.4 — the bounded local
// agent loop's orchestration: tool-capability gating, the loop bound, and
// every termination condition.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runAgentLoop, AGENT_LOOP_ERROR, DEFAULT_MAX_TOOL_ITERATIONS } from '../src/llm-validator/agent-loop.js';

function withEnv(vars, fn) {
  const prev = {};
  for (const k of Object.keys(vars)) prev[k] = process.env[k];
  Object.assign(process.env, vars);
  return Promise.resolve(fn()).finally(() => {
    for (const k of Object.keys(vars)) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  });
}

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

function json(res, body) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); }

function mkFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-loop-'));
  fs.writeFileSync(path.join(root, 'app.js'), 'console.log("hi")\n');
  return root;
}
function fakeStatePath(scanRoot, ...parts) { return path.join(scanRoot, '.agentic-security', ...parts); }

// Every scenario needs Layer A/B to report tools:true so the loop doesn't
// refuse before it even reaches the model. A qwen3.5-family name satisfies
// the family hint (Layer B) without needing a working /api/show route.
const TOOL_CAPABLE_MODEL = 'qwen3.5:4b';

test('runAgentLoop: not configured (no PRESET) returns NOT_CONFIGURED without any network call', async () => {
  const root = mkFixture();
  try {
    const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath });
    assert.equal(r.ok, false);
    assert.equal(r.code, AGENT_LOOP_ERROR.NOT_CONFIGURED);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: a model whose capability says tools:false is refused before any /api/chat call', async () => {
  const root = mkFixture();
  let chatCalled = false;
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: null }), // Layer A silent -> falls to Layer B family hint
    '/api/chat': (req, res) => { chatCalled = true; json(res, { message: { content: '{}' }, done: true }); },
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: 'gemma3:4b' }, async () => {
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath });
      assert.equal(r.ok, false);
      assert.equal(r.code, AGENT_LOOP_ERROR.TOOLS_UNSUPPORTED);
    });
    assert.equal(chatCalled, false);
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: no tool_calls on the first turn ends the loop with stopReason "complete"', async () => {
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': (req, res) => json(res, { message: { content: 'No security issues found.' }, done: true }),
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL }, async () => {
      const r = await runAgentLoop({ goal: 'Summarize the project.', scanRoot: root, statePath: fakeStatePath });
      assert.equal(r.ok, true);
      assert.equal(r.stopReason, 'complete');
      assert.equal(r.iterations, 1);
      assert.match(r.finalText, /No security issues/);
      assert.deepEqual(r.toolCalls, []);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: a tool call is executed, its result fed back, and the loop completes on the next turn', async () => {
  const root = mkFixture();
  let turn = 0;
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': (req, res) => {
      turn++;
      if (turn === 1) {
        json(res, { message: { content: '', tool_calls: [{ function: { name: 'list_files', arguments: {} } }] }, done: true });
      } else {
        json(res, { message: { content: 'The project has one file: app.js.' }, done: true });
      }
    },
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL }, async () => {
      const r = await runAgentLoop({ goal: 'What files are in this project?', scanRoot: root, statePath: fakeStatePath });
      assert.equal(r.ok, true);
      assert.equal(r.stopReason, 'complete');
      assert.equal(r.iterations, 2);
      assert.equal(r.toolCalls.length, 1);
      assert.equal(r.toolCalls[0].name, 'list_files');
      assert.equal(r.toolCalls[0].ok, true);
      assert.match(r.finalText, /app\.js/);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: a model calling an unregistered tool ends the loop with stopReason "policy-violation"', async () => {
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': (req, res) => json(res, { message: { content: '', tool_calls: [{ function: { name: 'run_shell', arguments: { cmd: 'rm -rf /' } } }] }, done: true }),
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL }, async () => {
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath });
      assert.equal(r.ok, true);
      assert.equal(r.stopReason, 'policy-violation');
      assert.equal(r.iterations, 1);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: a model that keeps calling tools forever is stopped at maxToolIterations, never runs unbounded', async () => {
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': (req, res) => json(res, { message: { content: '', tool_calls: [{ function: { name: 'list_files', arguments: {} } }] }, done: true }),
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL }, async () => {
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath });
      assert.equal(r.ok, true);
      assert.equal(r.stopReason, 'max-iterations');
      assert.equal(r.iterations, DEFAULT_MAX_TOOL_ITERATIONS);
      assert.equal(r.toolCalls.length, DEFAULT_MAX_TOOL_ITERATIONS);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: a caller-requested maxToolIterations above the hard ceiling is clamped, not honored', async () => {
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': (req, res) => json(res, { message: { content: '', tool_calls: [{ function: { name: 'list_files', arguments: {} } }] }, done: true }),
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL }, async () => {
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath, maxToolIterations: 9999 });
      assert.equal(r.iterations, DEFAULT_MAX_TOOL_ITERATIONS);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: a wall-clock timeout stops the loop even with iterations remaining', async () => {
  const root = mkFixture();
  let turn = 0;
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': (req, res) => {
      turn++;
      const body = { message: { content: '', tool_calls: [{ function: { name: 'list_files', arguments: {} } }] }, done: true };
      if (turn === 1) { json(res, body); return; }
      // Second call: delay past the wall-clock budget so the THIRD
      // iteration's pre-check catches an already-expired deadline.
      setTimeout(() => json(res, body), 120);
    },
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL }, async () => {
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath, wallClockTimeoutMs: 60 });
      assert.equal(r.ok, true);
      assert.equal(r.stopReason, 'wall-clock-timeout');
      assert.ok(r.iterations >= 1 && r.iterations < DEFAULT_MAX_TOOL_ITERATIONS);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

// Adversarial-review regression (2026-09), confirmed against a real, slow
// Ollama server: a call already IN FLIGHT when the wall clock would expire
// used to run to completion regardless (its own timeout could be minutes
// longer), only getting caught on the NEXT iteration's pre-check — meaning
// raising the per-call timeout for a genuinely slow model could not help,
// since a single call could already exceed the whole loop budget.
test('runAgentLoop: a single call that would outlive the remaining wall-clock budget is cut off by it, not by its own longer per-call timeout', async () => {
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    // Never actually responds within the test's lifetime — if the deadline
    // cap on requestTimeoutMs did NOT apply, this call would hang for the
    // full (much larger) per-call timeout instead of being cut off quickly.
    '/api/chat': () => {},
  });
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL,
      AGENTIC_SECURITY_LLM_TIMEOUT_MS: '300000', // a large per-call timeout, deliberately much bigger than the wall clock below
    }, async () => {
      const started = Date.now();
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath, wallClockTimeoutMs: 100 });
      const elapsedMs = Date.now() - started;
      assert.equal(r.ok, true, 'a wall-clock-driven timeout must be a graceful stop, not a hard failure');
      assert.equal(r.stopReason, 'wall-clock-timeout');
      assert.ok(elapsedMs < 5000, `expected the wall-clock cap to cut the call off quickly, took ${elapsedMs}ms`);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: AGENTIC_SECURITY_LLM_AGENT_TIMEOUT_MS sets the wall-clock budget when wallClockTimeoutMs is not passed explicitly', async () => {
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': () => {},
  });
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL,
      AGENTIC_SECURITY_LLM_TIMEOUT_MS: '300000',
      AGENTIC_SECURITY_LLM_AGENT_TIMEOUT_MS: '100',
    }, async () => {
      const started = Date.now();
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath }); // no wallClockTimeoutMs override
      const elapsedMs = Date.now() - started;
      assert.equal(r.ok, true);
      assert.equal(r.stopReason, 'wall-clock-timeout');
      assert.ok(elapsedMs < 5000, `expected the env-configured wall clock to apply, took ${elapsedMs}ms`);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

// A timeout that is NOT wall-clock-driven — the operator's own per-call
// setting is what's tight, with plenty of loop budget left — must still
// surface as a real, hard failure, not be silently reclassified as a
// graceful stop just because the error code happens to be 'ollama-timeout'.
test('runAgentLoop: a per-call timeout that is NOT wall-clock-driven remains a hard failure', async () => {
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': () => {}, // never responds
  });
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: TOOL_CAPABLE_MODEL,
      AGENTIC_SECURITY_LLM_TIMEOUT_MS: '100', // the tight setting here
    }, async () => {
      // Plenty of wall-clock budget (60s) — the per-call setting alone is
      // what's binding, so this must NOT be reported as wall-clock-timeout.
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath, wallClockTimeoutMs: 60000 });
      assert.equal(r.ok, false);
      assert.equal(r.code, AGENT_LOOP_ERROR.FAILED);
    });
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('runAgentLoop: a non-loopback host is refused before any network call, same as every other role', async () => {
  const root = mkFixture();
  const real = global.fetch;
  let called = false;
  global.fetch = async (...a) => { called = true; return real(...a); };
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: 'http://198.51.100.13:11434' }, async () => {
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath });
      assert.equal(r.ok, false);
      assert.match(r.reason, /Ollama offline mode refused/);
    });
    assert.equal(called, false);
  } finally { global.fetch = real; fs.rmSync(root, { recursive: true, force: true }); }
});

// Second-round adversarial-review fix (2026-09): Round 1's OOM-feedback fix
// only surfaced in `models doctor` — a user who never runs `doctor` would
// OOM again identically via `ask` with no warning. `runAgentLoop` now
// surfaces the SAME `priorOOMWarning` on any outcome where a real call was
// actually attempted.
test('runAgentLoop: a model with a prior recorded OOM on this machine gets priorOOMWarning attached on success', async () => {
  const { recordOOMEvent, _internals: oomInternals } = await import('../src/llm-validator/oom-feedback.js');
  const fsMod = await import('node:fs');
  const model = 'agent-loop-oom-test-model:unique-' + Date.now();
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': (req, res) => json(res, { message: { content: 'done' }, done: true }),
  });
  try {
    recordOOMEvent(model);
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: model }, async () => {
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath });
      assert.equal(r.ok, true);
      assert.ok(r.priorOOMWarning, 'expected a priorOOMWarning field');
      assert.match(r.priorOOMWarning, new RegExp(model.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    });
  } finally {
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
    try {
      const log = JSON.parse(fsMod.readFileSync(oomInternals.LOG_PATH, 'utf8'));
      delete log[model];
      fsMod.writeFileSync(oomInternals.LOG_PATH, JSON.stringify(log));
    } catch {}
  }
});

test('runAgentLoop: a model with NO prior OOM history has no warning field, and a refusal before any call is never decorated', async () => {
  const root = mkFixture();
  const { server, host } = await startFakeOllama({
    '/api/show': (req, res) => json(res, { capabilities: ['completion', 'tools'] }),
    '/api/chat': (req, res) => json(res, { message: { content: 'done' }, done: true }),
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: 'agent-loop-oom-clean-model:unique-' + Date.now() }, async () => {
      const r = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath });
      assert.equal(r.priorOOMWarning, undefined);
    });
    // A NOT_CONFIGURED refusal (no PRESET at all) never attempted a real call.
    const r2 = await runAgentLoop({ goal: 'x', scanRoot: root, statePath: fakeStatePath });
    assert.equal(r2.priorOOMWarning, undefined);
  } finally { server.close(); fs.rmSync(root, { recursive: true, force: true }); }
});
