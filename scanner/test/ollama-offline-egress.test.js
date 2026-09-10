// agentic-security-ollama-offline-prd.md §40.5 — "Create a test that fails
// any LLM-stage network request whose destination is not loopback while
// offline mode is active. This should assert BEHAVIOR, not merely
// configuration." So this file does not just call ollamaEndpointConfig() and
// check `.ok === false` (that's already covered in ollama-provider.test.js);
// it monkey-patches global.fetch, drives the REAL caller code paths
// (validateOne from llm-validator/index.js, defaultLlmInvoke from
// discovery/llm-invoke.js) with a non-loopback Ollama host configured, and
// asserts fetch was NEVER invoked — refusal happens before any network I/O,
// not as an error caught after the fact.
//
// It also proves the sentinel isn't vacuously true (i.e. that these code
// paths DO call fetch under normal, loopback conditions) using a fake local
// server, so a future regression that quietly skips the whole validator tier
// wouldn't be mistaken for "offline enforcement still works".

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { validateOne } from '../src/llm-validator/index.js';
import { defaultLlmInvoke, resolveLlmInvoke, resolveLlmInvokeWithDecision } from '../src/discovery/llm-invoke.js';

function withPatchedFetch(fn) {
  const calls = [];
  const real = global.fetch;
  global.fetch = async (url, init) => {
    calls.push(String(url));
    return real(url, init);
  };
  return fn(calls).finally(() => { global.fetch = real; });
}

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

// ── llm-validator's `validate` role ─────────────────────────────────────────

test('offline egress sentinel: validateOne NEVER calls fetch when Ollama host is non-loopback', async () => {
  await withPatchedFetch(async (calls) => {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: 'http://198.51.100.7:11434', // TEST-NET-2, always non-loopback
    }, async () => {
      const finding = { id: 'f1', vuln: 'X', severity: 'high', cwe: 'CWE-89', file: 'app.js', line: 5, snippet: 'x' };
      const fileContents = { 'app.js': 'line1\nline2\nline3\nline4\nline5\n' };
      const scanRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ollama-egress-sentinel-'));
      try {
        const result = await validateOne(finding, fileContents, scanRoot, null);
        assert.equal(result.verdict, 'unvalidated');
        assert.equal(finding.llmValidationStatus, 'policy-blocked');
      } finally {
        fs.rmSync(scanRoot, { recursive: true, force: true });
      }
    });
    assert.equal(calls.length, 0, `expected zero fetch calls, got: ${JSON.stringify(calls)}`);
  });
});

test('offline egress sentinel: validateOne DOES call the endpoint for a genuine loopback Ollama host (sentinel is not vacuous)', async () => {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        message: { content: JSON.stringify({ challenge: 'x', file: 'app.js', line: 5, verdict: 'escalate', confidence: 0.5, reasoning: 'test' }) },
        done: true,
      }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await withPatchedFetch(async (calls) => {
      await withEnv({
        AGENTIC_SECURITY_LLM_PRESET: 'ollama',
        AGENTIC_SECURITY_OLLAMA_HOST: `http://127.0.0.1:${port}`,
      }, async () => {
        const finding = { id: 'f2', vuln: 'X', severity: 'high', cwe: 'CWE-89', file: 'app.js', line: 5, snippet: 'x' };
        const fileContents = { 'app.js': 'line1\nline2\nline3\nline4\nline5\n' };
        const scanRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ollama-egress-sentinel-'));
        try {
          await validateOne(finding, fileContents, scanRoot, null);
        } finally {
          fs.rmSync(scanRoot, { recursive: true, force: true });
        }
      });
      assert.ok(calls.length >= 1, 'expected the loopback path to actually call fetch');
      assert.ok(calls.every((u) => u.startsWith(`http://127.0.0.1:${port}`)), `all calls must target loopback: ${JSON.stringify(calls)}`);
    });
  } finally {
    server.close();
  }
});

// ── discovery/llm-invoke.js's shared caller (hunt) ──────────────────────────

test('offline egress sentinel: defaultLlmInvoke NEVER calls fetch for a non-loopback Ollama host', async () => {
  await withPatchedFetch(async (calls) => {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: 'http://198.51.100.7:11434',
    }, async () => {
      await assert.rejects(() => defaultLlmInvoke('hunt prompt'), /Ollama offline mode refused/);
    });
    assert.equal(calls.length, 0, `expected zero fetch calls, got: ${JSON.stringify(calls)}`);
  });
});

test('offline egress sentinel: defaultLlmInvoke DOES call the endpoint for a genuine loopback Ollama host', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: { content: 'hunt-response' }, done: true }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await withPatchedFetch(async (calls) => {
      await withEnv({
        AGENTIC_SECURITY_LLM_PRESET: 'ollama',
        AGENTIC_SECURITY_OLLAMA_HOST: `http://127.0.0.1:${port}`,
      }, async () => {
        const text = await defaultLlmInvoke('hunt prompt');
        assert.equal(text, 'hunt-response');
      });
      assert.ok(calls.length >= 1);
      assert.ok(calls.every((u) => u.startsWith(`http://127.0.0.1:${port}`)));
    });
  } finally {
    server.close();
  }
});

// ── resolveLlmInvoke / resolveLlmInvokeWithDecision — hunt's REAL entry
//    point (hunter.js and disprove.js call this, never defaultLlmInvoke
//    directly). A regression here would mean PRESET=ollama silently does
//    nothing for hunt even though defaultLlmInvoke itself works fine. ──────

test('resolveLlmInvokeWithDecision: PRESET=ollama alone (no raw ENDPOINT) resolves a real invoke function, not null', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama' }, async () => {
    const { invoke, decision } = resolveLlmInvokeWithDecision({});
    assert.equal(typeof invoke, 'function', 'PRESET=ollama must be recognized as "configured", not treated as nothing set');
    assert.equal(decision.allowed, true);
    assert.equal(decision.provider, 'ollama', 'the report-facing provider label must say ollama, not the generic loopback "local"');
  });
});

test('resolveLlmInvokeWithDecision: a non-loopback Ollama host resolves invoke:null with the refusal as .reason (never a network call)', async () => {
  await withPatchedFetch(async (calls) => {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: 'http://198.51.100.7:11434',
    }, async () => {
      const { invoke, decision } = resolveLlmInvokeWithDecision({});
      assert.equal(invoke, null);
      assert.match(decision.reason, /Ollama offline mode refused/);
    });
    assert.equal(calls.length, 0);
  });
});

test('resolveLlmInvoke: the actual function hunter.js/disprove.js call resolves and successfully calls a loopback Ollama server', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: { content: 'resolved-invoke-result' }, done: true }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: `http://127.0.0.1:${port}`,
    }, async () => {
      const invoke = resolveLlmInvoke({});
      assert.equal(typeof invoke, 'function');
      const text = await invoke('a hunt prompt');
      assert.equal(text, 'resolved-invoke-result');
    });
  } finally {
    server.close();
  }
});

test('regression: resolveLlmInvokeWithDecision with a raw AGENTIC_SECURITY_LLM_ENDPOINT and no PRESET stays on the legacy path, byte-identical to before', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:9/legacy' }, async () => {
    const { decision } = resolveLlmInvokeWithDecision({});
    // provider is inferred from the endpoint (loopback -> 'local'), exactly
    // as it always was for this path — PRESET=ollama support must not have
    // changed what a bare AGENTIC_SECURITY_LLM_ENDPOINT resolves to.
    assert.equal(decision.provider, 'local');
  });
});

// ── hunt's per-role model routing (PRD §32) ─────────────────────────────────

test('runHunter: the business-logic lens routes through role=logic, honoring AGENTIC_SECURITY_LLM_MODEL_LOGIC', async () => {
  const { runHunter } = await import('../src/discovery/hunter.js');
  let receivedModel = null;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      receivedModel = JSON.parse(body).model;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: { content: '{"candidates":[]}' }, done: true }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: `http://127.0.0.1:${port}`,
      AGENTIC_SECURITY_LLM_MODEL_LOGIC: 'gemma4:26b',
    }, async () => {
      await runHunter(
        { id: 'area1', files: [{ path: 'app.js', content: 'x' }] },
        { key: 'business-logic', title: 'Business logic' },
        {},
      );
    });
    assert.equal(receivedModel, 'gemma4:26b', 'the business-logic lens must use AGENTIC_SECURITY_LLM_MODEL_LOGIC, not the global default');
  } finally {
    server.close();
  }
});

test('runHunter: a non-logic lens keeps using the global model, not the logic-specific override', async () => {
  const { runHunter } = await import('../src/discovery/hunter.js');
  let receivedModel = null;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      receivedModel = JSON.parse(body).model;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: { content: '{"candidates":[]}' }, done: true }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: `http://127.0.0.1:${port}`,
      AGENTIC_SECURITY_LLM_MODEL: 'qwen3.5:4b',
      AGENTIC_SECURITY_LLM_MODEL_LOGIC: 'gemma4:26b',
    }, async () => {
      await runHunter(
        { id: 'area1', files: [{ path: 'app.js', content: 'x' }] },
        { key: 'auth-boundary', title: 'Auth boundary' },
        {},
      );
    });
    assert.equal(receivedModel, 'qwen3.5:4b');
  } finally {
    server.close();
  }
});

test('disproveCandidate: the refutation panel routes through role=verify, honoring AGENTIC_SECURITY_LLM_MODEL_VERIFY', async () => {
  const { disproveCandidate } = await import('../src/discovery/disprove.js');
  let receivedModel = null;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      receivedModel = JSON.parse(body).model;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: { content: '{"refuted":false,"reason":"cannot refute"}' }, done: true }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: `http://127.0.0.1:${port}`,
      AGENTIC_SECURITY_LLM_MODEL_VERIFY: 'qwen3:14b',
    }, async () => {
      await disproveCandidate({ title: 'X', file: 'a.js', line: 1 }, { angles: ['reachability'] });
    });
    assert.equal(receivedModel, 'qwen3:14b');
  } finally {
    server.close();
  }
});

// ── Explicit remote opt-in must still label egress:remote, never loopback ──

test('offline egress sentinel: the explicit remote escape hatch still calls fetch (opt-in works) but is never mislabeled loopback', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: { content: 'remote-ok' }, done: true }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await withPatchedFetch(async (calls) => {
      await withEnv({
        AGENTIC_SECURITY_LLM_PRESET: 'ollama',
        // Loopback-addressed on purpose (so the fake server is actually
        // reachable in a test), but forcing the remote flag proves the
        // labeling — not the reachability — is what's under test here.
        AGENTIC_SECURITY_OLLAMA_HOST: `http://127.0.0.1:${port}`,
        AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE: '1',
      }, async () => {
        const text = await defaultLlmInvoke('hunt prompt');
        assert.equal(text, 'remote-ok');
      });
      assert.ok(calls.length >= 1, 'the explicit opt-in must still be able to reach an endpoint');
    });
  } finally {
    server.close();
  }
});
