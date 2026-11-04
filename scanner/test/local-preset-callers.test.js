// GA-06.3: the `local` preset's loopback promise holds on every caller, not only the validator. Before 0.195.23 the flow narration,
// the dependency function extractor and the adversary agent read AGENTIC_SECURITY_LLM_ENDPOINT directly, so with PRESET=local and a
// remote endpoint set they called it. Each now resolves its provider the way the validator does and refuses without a request.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const KEYS = ['AGENTIC_SECURITY_LLM_ENDPOINT', 'AGENTIC_SECURITY_LLM_PRESET', 'AGENTIC_SECURITY_LLM_API_KEY', 'OPENAI_API_KEY', 'AGENTIC_SECURITY_LLM_SCA', 'AGENTIC_SECURITY_EGRESS_DENY', 'AGENTIC_SECURITY_LLM_MODEL'];

async function withEnv(vars, fn) {
  const saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  for (const k of KEYS) delete process.env[k];
  Object.assign(process.env, vars);
  const origFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => { calls.push({ url: String(url), init }); return new Response('{"text":"never"}', { status: 200 }); };
  try { return await fn(calls); } finally {
    globalThis.fetch = origFetch;
    for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  }
}

const REMOTE = { AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat', AGENTIC_SECURITY_LLM_API_KEY: 'k' };

test('flow narration under the local preset with a remote endpoint: no request, the template is used', async () => {
  await withEnv(REMOTE, async (calls) => {
    const { annotateNarration } = await import('../src/posture/flow-narration.js');
    const findings = [{ id: 'f1', severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', file: 'a.js', line: 3, family: 'sqli', snippet: 'db.query(q)' }];
    await annotateNarration(findings, { scanRoot: os.tmpdir() });
    assert.equal(calls.length, 0, 'a non-loopback endpoint under the local preset is never called');
    assert.ok(typeof findings[0].narration === 'string' && findings[0].narration.length > 0);
  });
});

test('the dependency function extractor under the local preset with a remote endpoint: no request, no enrichment', async () => {
  await withEnv({ ...REMOTE, AGENTIC_SECURITY_LLM_SCA: '1' }, async (calls) => {
    const { extractVulnFunctionsViaLLM } = await import('../src/sca/llm-function-extract.js');
    const sc = [{ type: 'vulnerable_dep', name: 'left-pad', version: '1.0.0', osvId: 'GHSA-test-local-preset', noKnownCallSite: true, description: 'a bug' }];
    const out = await extractVulnFunctionsViaLLM(sc, { scanRoot: os.tmpdir() });
    assert.deepEqual(out, []);
    assert.equal(calls.length, 0);
  });
});

test('the adversary agent under the local preset with a remote endpoint: no request, outcome stays unverified', async () => {
  await withEnv(REMOTE, async (calls) => {
    const { runAgent, _agentProvider } = await import('../src/posture/adversary-agent.js');
    assert.equal(_agentProvider(), null, 'the provider resolution refuses the remote endpoint');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adv-local-'));
    const r = await runAgent({ id: 'f1', vuln: 'x', file: 'a.js', line: 1 }, { scanRoot: dir, target: 'http://127.0.0.1:9' });
    assert.equal(r.outcome, 'unverified-no-llm-endpoint');
    assert.equal(calls.length, 0);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

test('a bare OPENAI_API_KEY is never attached to an arbitrary endpoint by the adversary agent', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:11434/v1', OPENAI_API_KEY: 'sk-should-not-leave' }, async () => {
    const { _agentProvider } = await import('../src/posture/adversary-agent.js');
    const p = _agentProvider();
    assert.ok(p && p.endpoint === 'http://127.0.0.1:11434/v1');
    assert.equal(p.apiKey, null, 'the BYO endpoint gets only AGENTIC_SECURITY_LLM_API_KEY');
  });
});

test('the same callers under the local preset with a loopback endpoint do resolve a provider', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:11434/v1' }, async () => {
    const { _agentProvider } = await import('../src/posture/adversary-agent.js');
    const p = _agentProvider();
    assert.equal(p?.provider, 'local');
    assert.equal(p?.egress, 'loopback-only');
  });
});
