// agentic-security-ollama-offline-prd.md §18.1 — Ollama-assisted `poc` role.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import { buildPocPrompt, proposeOllamaPoc, POC_PROPOSAL_ERROR } from '../src/llm-validator/poc-proposal.js';

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

test('buildPocPrompt: frames the sketch as unverified, forbids claiming execution, frames snippet as untrusted', () => {
  const prompt = buildPocPrompt(FINDING, "db.query('SELECT * FROM x WHERE id=' + id)", '.');
  assert.match(prompt, /You do NOT claim to have executed anything/);
  assert.match(prompt, /as a SKETCH not a confirmed exploit/);
  assert.match(prompt, /BEGIN-UNTRUSTED-CODE-SNIPPET/);
});

test('proposeOllamaPoc: not configured returns NOT_CONFIGURED, no network call', async () => {
  const r = await proposeOllamaPoc({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
  assert.equal(r.ok, false);
  assert.equal(r.code, POC_PROPOSAL_ERROR.NOT_CONFIGURED);
});

test('proposeOllamaPoc: a valid response returns pocNarrative/exampleInput/expectedResult as separate fields', async () => {
  const { server, host } = await startFakeOllama((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      message: { content: JSON.stringify({
        poc_narrative: 'An attacker could append a crafted id parameter to alter the SQL query and read other users\' rows.',
        example_input: "id=1 OR 1=1",
        expected_result: 'The query returns rows beyond the intended single record.',
      }) },
      done: true,
    }));
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host }, async () => {
      const r = await proposeOllamaPoc({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
      assert.equal(r.ok, true);
      assert.match(r.pocNarrative, /alter the SQL query/);
      assert.equal(r.exampleInput, 'id=1 OR 1=1');
      assert.match(r.expectedResult, /returns rows/);
      assert.equal(r.model, 'qwen3.5:4b');
    });
  } finally {
    server.close();
  }
});

test('proposeOllamaPoc: an empty narrative is rejected as malformed', async () => {
  const { server, host } = await startFakeOllama((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: { content: JSON.stringify({ poc_narrative: '   ' }) }, done: true }));
  });
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host }, async () => {
      const r = await proposeOllamaPoc({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
      assert.equal(r.ok, false);
      assert.equal(r.code, POC_PROPOSAL_ERROR.FAILED);
    });
  } finally {
    server.close();
  }
});

test('proposeOllamaPoc: AGENTIC_SECURITY_LLM_MODEL_POC overrides the global model', async () => {
  let receivedModel = null;
  const { server, host } = await startFakeOllama((req, res, json) => {
    receivedModel = json.model;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: { content: JSON.stringify({ poc_narrative: 'x' }) }, done: true }));
  });
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host,
      AGENTIC_SECURITY_LLM_MODEL: 'qwen3.5:4b', AGENTIC_SECURITY_LLM_MODEL_POC: 'qwen3-coder:30b',
    }, async () => {
      await proposeOllamaPoc({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
    });
    assert.equal(receivedModel, 'qwen3-coder:30b');
  } finally {
    server.close();
  }
});

test('proposeOllamaPoc: a non-loopback host is refused before any network call', async () => {
  const real = global.fetch;
  let called = false;
  global.fetch = async (...a) => { called = true; return real(...a); };
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: 'http://198.51.100.12:11434' }, async () => {
      const r = await proposeOllamaPoc({ finding: FINDING, contextSnippet: 'x', scanRoot: '.' });
      assert.equal(r.ok, false);
      assert.match(r.reason, /Ollama offline mode refused/);
    });
    assert.equal(called, false);
  } finally {
    global.fetch = real;
  }
});
