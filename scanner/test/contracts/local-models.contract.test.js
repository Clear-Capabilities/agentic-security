// Contract test for local model support (docs/reference/local-models-contract.md): the loopback rule against the page's table in both
// directions, the configuration shapes, the closed error-code set, and the guarantees that a refused or failed local model makes no
// request and never falls back to another provider.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isLoopbackUrl, localEndpointConfig } from '../../src/llm-validator/local-endpoint.js';
import { ollamaEndpointConfig, OLLAMA_ERROR_CODES } from '../../src/llm-validator/ollama-provider.js';
import { validateMany } from '../../src/llm-validator/index.js';
import { runHunter } from '../../src/discovery/hunter.js';
import { LENSES } from '../../src/discovery/lenses.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { mkTestTmp } from '../helpers/tmp.js';

const PAGE = readPage('docs/reference/local-models-contract.md');

/** Rows of the loopback table: the endpoint in backticks (or a list of them) and whether the page says it is accepted. */
function loopbackRows() {
  const lines = PAGE.split('\n');
  const at = lines.findIndex(l => l.startsWith('**Loopback endpoints'));
  assert.ok(at >= 0);
  const rows = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (lines[i].startsWith('**') || lines[i].startsWith('#')) break;
    const m = /^\| (.+?) \| (Yes|No)\b/.exec(lines[i]);
    if (m && !m[1].startsWith('Endpoint')) rows.push({ cell: m[1], accepted: m[2] === 'Yes' });
  }
  return rows;
}

test('contract: the loopback rule agrees with every row of the page, in both directions', () => {
  const rows = loopbackRows();
  assert.ok(rows.length >= 12);
  for (const { cell, accepted } of rows) {
    const urls = [...cell.matchAll(/`([^`]*)`/g)].map(m => m[1]);
    for (const u of urls) assert.equal(isLoopbackUrl(u), accepted, `${u} is ${accepted ? 'accepted' : 'refused'} on the page`);
  }
  assert.ok(rows.some(r => r.accepted) && rows.some(r => !r.accepted), 'the table has both directions');
  for (const bad of ['', 'not a url', 'http://192.168.1.5:11434', 'http://localhost.evil.example']) assert.equal(isLoopbackUrl(bad), false);
});

test('contract: the local preset reports exactly the documented fields, and a non-loopback endpoint is refused', () => {
  const ok = localEndpointConfig({});
  assert.equal(ok.ok, true);
  sameFields(ok.config, fieldsUnder(PAGE, '`local` configuration'), 'local configuration');
  assert.equal(ok.config.egress, 'loopback-only');
  assert.equal(ok.config.apiKey, null, 'the preset never invents a credential');
  const refused = localEndpointConfig({ AGENTIC_SECURITY_LLM_ENDPOINT: 'http://models.example.com/v1/chat/completions' });
  assert.equal(refused.ok, false);
  assert.match(refused.reason, /refuses a non-loopback endpoint/);
});

test('contract: the ollama preset reports exactly the documented fields, labels a remote host remote, and refuses one without the opt-in', () => {
  const ok = ollamaEndpointConfig({});
  assert.equal(ok.ok, true);
  sameFields(ok.config, fieldsUnder(PAGE, '`ollama` configuration'), 'ollama configuration');
  assert.equal(ok.config.egress, 'loopback-only');
  assert.equal(ok.config.offline, true);
  const refused = ollamaEndpointConfig({ AGENTIC_SECURITY_OLLAMA_HOST: 'http://192.168.1.50:11434' });
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'ollama-non-loopback-refused');
  const optedIn = ollamaEndpointConfig({ AGENTIC_SECURITY_OLLAMA_HOST: 'http://192.168.1.50:11434', AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE: '1' });
  assert.equal(optedIn.ok, true);
  assert.equal(optedIn.config.egress, 'remote', 'a remote host is never reported as loopback-only');
  assert.equal(optedIn.config.offline, false);
  assert.equal(ollamaEndpointConfig({ AGENTIC_SECURITY_OLLAMA_DISABLED: '1' }).code, 'ollama-disabled');
});

test('contract: the documented error codes are the implementation\'s closed set, and the comparison itself fails when one is added', () => {
  const documented = fieldsUnder(PAGE, 'Error codes');
  assert.deepEqual([...documented].sort(), [...OLLAMA_ERROR_CODES].sort());
  assert.notDeepEqual([...documented, 'ollama-invented'].sort(), [...OLLAMA_ERROR_CODES].sort());
});

async function withEnv(env, fn) {
  const was = {};
  for (const k of Object.keys(env)) { was[k] = process.env[k]; if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  try { return await fn(); } finally { for (const k of Object.keys(was)) { if (was[k] === undefined) delete process.env[k]; else process.env[k] = was[k]; } }
}
async function countingFetch(fn) {
  const urls = [];
  const original = global.fetch;
  global.fetch = async (u) => { urls.push(String(u)); throw new Error('no request may be made'); };
  try { await fn(); } finally { global.fetch = original; }
  return urls;
}
const finding = () => ({ id: 'F1', file: 'a.js', line: 5, severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', parser: 'SAST' });

test('contract: a refused endpoint makes no request under either preset, and the finding is policy-blocked', async () => {
  for (const env of [
    { AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'http://models.example.com/v1/chat/completions' },
    { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: 'http://198.51.100.7:11434' },
  ]) {
    const f = [finding()];
    const urls = await countingFetch(() => withEnv({ ...env, AGENTIC_SECURITY_LLM_VALIDATE: undefined }, () => validateMany(f, { fileContents: { 'a.js': 'x\n'.repeat(10) }, scanRoot: mkTestTmp('agsec-local-contract-') })));
    assert.deepEqual(urls, [], JSON.stringify(env));
    assert.equal(f[0].validator_verdict, 'unvalidated');
    assert.equal(f[0].llmValidationStatus, 'policy-blocked');
  }
});

test('contract: an unreachable local server leaves the finding unvalidated and calls only the configured loopback host, never another provider', async () => {
  const urls = [];
  const original = global.fetch;
  global.fetch = async (u) => { urls.push(String(u)); throw new Error('connect ECONNREFUSED 127.0.0.1:1'); };
  const f = [finding()];
  try {
    await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:1/v1/chat/completions', AGENTIC_SECURITY_LLM_VALIDATE: undefined, ANTHROPIC_API_KEY: 'k', OPENAI_API_KEY: 'k' },
      () => validateMany(f, { fileContents: { 'a.js': 'x\n'.repeat(10) }, scanRoot: mkTestTmp('agsec-local-contract-') }));
  } finally { global.fetch = original; }
  assert.ok(urls.length >= 1);
  assert.ok(urls.every(u => isLoopbackUrl(u)), `every request went to loopback: ${urls.join(', ')}`);
  assert.equal(f[0].validator_verdict, 'unvalidated');
  assert.equal(f[0].llmValidationStatus, 'unavailable');
});

test('contract: hunt under a refused host makes no request and degrades the run with the reason', async () => {
  const urls = await countingFetch(async () => {
    const run = await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: 'http://198.51.100.7:11434', AGENTIC_SECURITY_LLM_ENDPOINT: undefined },
      () => runHunter({ id: 'a1', label: 'a', files: ['a.js'], functions: [], size: 1 }, LENSES[0], { fileContents: { 'a.js': 'x' } }, {}));
    assert.equal(run.degraded, true);
    assert.match(run.reason, /egress policy denied|not set|refused/i);
  });
  assert.deepEqual(urls, []);
});
