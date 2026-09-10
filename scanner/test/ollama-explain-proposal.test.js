// agentic-security-ollama-offline-prd.md §34 — Ollama-assisted `explain`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import { buildExplainPrompt, proposeOllamaExplanation, EXPLAIN_ERROR } from '../src/llm-validator/explain-proposal.js';

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

function startFakeOllama(handler) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => handler(req, res, body ? JSON.parse(body) : null));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, host: `http://127.0.0.1:${port}` });
    });
  });
}

const FINDING = { file: 'app.js', line: 5, vuln: 'SQL Injection', cwe: 'CWE-89', severity: 'critical' };

test('buildExplainPrompt: forbids fabricating exploit/cost/compliance claims (PRD §34), frames snippet as untrusted', () => {
  const prompt = buildExplainPrompt(FINDING, "db.query('SELECT * FROM x WHERE id=' + id)", '.');
  assert.match(prompt, /do NOT decide whether the finding is a\ntrue positive, invent an exploit/);
  assert.match(prompt, /estimate a dollar cost, or claim compliance coverage/);
  assert.match(prompt, /BEGIN-UNTRUSTED-CODE-SNIPPET/);
});

test('proposeOllamaExplanation: not configured returns NOT_CONFIGURED, no network call', async () => {
  const r = await proposeOllamaExplanation({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
  assert.equal(r.ok, false);
  assert.equal(r.code, EXPLAIN_ERROR.NOT_CONFIGURED);
});

test('proposeOllamaExplanation: a valid response returns explanation and confidenceNote as SEPARATE fields from deterministic evidence', async () => {
  const { server, host } = await startFakeOllama((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      message: { content: JSON.stringify({
        explanation: 'User input is concatenated directly into a SQL query, letting an attacker alter the query logic.',
        confidence_note: 'The deterministic scanner flagged this with high confidence based on a direct source-to-sink path.',
      }) },
      done: true,
    }));
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host }, async () => {
      const r = await proposeOllamaExplanation({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
      assert.equal(r.ok, true);
      assert.match(r.modelExplanation, /concatenated/);
      assert.match(r.confidenceNote, /deterministic scanner/);
      assert.equal(r.model, 'qwen3.5:4b');
    });
  } finally {
    server.close();
  }
});

test('proposeOllamaExplanation: an empty explanation is rejected as malformed, not returned as an empty string', async () => {
  const { server, host } = await startFakeOllama((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: { content: JSON.stringify({ explanation: '   ' }) }, done: true }));
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host }, async () => {
      const r = await proposeOllamaExplanation({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
      assert.equal(r.ok, false);
      assert.equal(r.code, EXPLAIN_ERROR.FAILED);
    });
  } finally {
    server.close();
  }
});

test('proposeOllamaExplanation: AGENTIC_SECURITY_LLM_MODEL_EXPLAIN overrides the global model', async () => {
  let receivedModel = null;
  const { server, host } = await startFakeOllama((req, res, json) => {
    receivedModel = json.model;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: { content: JSON.stringify({ explanation: 'x' }) }, done: true }));
  });
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host,
      AGENTIC_SECURITY_LLM_MODEL: 'qwen3.5:4b', AGENTIC_SECURITY_LLM_MODEL_EXPLAIN: 'gemma4:12b',
    }, async () => {
      await proposeOllamaExplanation({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
    });
    assert.equal(receivedModel, 'gemma4:12b');
  } finally {
    server.close();
  }
});

test('proposeOllamaExplanation: a non-loopback host is refused before any network call', async () => {
  const real = global.fetch;
  let called = false;
  global.fetch = async (...a) => { called = true; return real(...a); };
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: 'http://198.51.100.11:11434' }, async () => {
      const r = await proposeOllamaExplanation({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
      assert.equal(r.ok, false);
      assert.match(r.reason, /Ollama offline mode refused/);
    });
    assert.equal(called, false);
  } finally {
    global.fetch = real;
  }
});
