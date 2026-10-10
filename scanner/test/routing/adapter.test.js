// X-602.AC03: the provider adapter, exercised with INJECTED fake transports only. No network, no credentials, no paid call.
// Provider ids are generic slots. A test replaces globalThis.fetch with a stub that fails the test if anything reaches for it.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { createProviderAdapter, endpointHost, PROVIDER_FAILURE_CODES } from '../../src/posture/routing/adapter.js';
import { priceBookFromCatalog } from '../../src/posture/routing/economics.js';
import { validateRoutingOutcome } from '../../src/posture/routing/outcomes.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { verifyEgressAuditLog } from '../../src/egress/audit.js';
import { taskOf } from '../helpers/routing-fixtures.js';

const CANARY_KEY = 'sk_' + 'live_' + '0123456789' + 'abcdefghij' + 'ABCD';
const SOURCE_BODY = 'function proprietaryScoringAlgorithm(x) { return x * 7919 + 31337; }';
const CRED_VALUE = 'cred-' + 'value-' + 'do-not-log-123456';
const MODEL = 'claude-haiku-4-5';
const book = priceBookFromCatalog();
const LOCAL = 'http://127.0.0.1:11434';

let realFetch; let fetchCalls = 0;
before(() => { realFetch = globalThis.fetch; globalThis.fetch = () => { fetchCalls += 1; throw new Error('the adapter must not use the network client'); }; });
after(() => { globalThis.fetch = realFetch; });

function setup({ limits, policy } = {}) {
  const root = mkTestTmp('routing-adapter-');
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"t"}');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  if (policy) fs.writeFileSync(path.join(root, '.agentic-security', 'egress-policy.yml'), policy);
  const config = resolveAssuranceConfig({ scanRoot: root, env: {}, platform: 'linux', overrides: { features: { 'model-routing': true }, ...(limits ? { limits } : {}) } });
  return { root, config };
}
const adapterOf = (o) => createProviderAdapter({ provider: 'provider-a', model: MODEL, modelVersion: 'v1', endpoint: LOCAL, priceBook: book, clock: (() => { let t = 0; return () => (t += 50); })(), ...o });
const prompt = `// review ${SOURCE_BODY}\nconst apiKey = "${CANARY_KEY}";`;
const noLeak = (value, extra = []) => {
  const text = JSON.stringify(value);
  for (const s of [CANARY_KEY, SOURCE_BODY, 'proprietaryScoringAlgorithm', CRED_VALUE, ...extra]) assert.ok(!text.includes(s), `leaked: ${s.slice(0, 12)}`);
};

describe('[X-602.AC03] adapters pass fixtures for provider failures, partial responses, cancellation and cache hits without exposing credentials or source', () => {
  test('a cache hit is recorded as measured usage, a hit state and a priced cost; nothing but metadata is in the telemetry', async () => {
    const { root, config } = setup();
    const a = adapterOf({ config, scanRoot: root, transport: async () => ({ text: 'patched', finishReason: 'stop', usage: { inputTokens: 5000, outputTokens: 300, cachedInputTokens: 5000 } }) });
    const r = await a.invoke({ task: taskOf(1), runId: 'r1', prompt, group: 'g1', observedAt: '2026-05-01T00:00:00Z' });
    assert.equal(r.telemetry.status, 'completed');
    assert.equal(r.telemetry.cacheState, 'hit');
    assert.equal(r.telemetry.usage.source, 'measured');
    assert.equal(r.telemetry.cost.status, 'measured');
    assert.equal(r.telemetry.cost.billingBasis, 'list-price');
    assert.equal(r.outcome.outcome, 'delayed', 'an unadjudicated completed run is delayed, not correct');
    assert.equal(validateRoutingOutcome(r.outcome).ok, true);
    assert.equal(r.outcome.cacheState, 'hit');
    assert.equal(r.text, 'patched');
    noLeak(r.telemetry); noLeak(r.outcome);
  });

  test('a provider failure keeps an outcome with unknown usage, a fixed failure code, and none of the error text', async () => {
    const { root, config } = setup();
    const a = adapterOf({ config, scanRoot: root, transport: async () => { throw Object.assign(new Error(`401 for key ${CANARY_KEY} on ${SOURCE_BODY}`), { code: 'auth', retryable: false }); } });
    const r = await a.invoke({ task: taskOf(2), runId: 'r2', prompt });
    assert.equal(r.telemetry.status, 'provider-error');
    assert.equal(r.telemetry.code, 'auth');
    assert.ok(PROVIDER_FAILURE_CODES.includes(r.telemetry.code));
    assert.equal(r.outcome.status, 'provider-error');
    assert.equal(r.outcome.usage.inputTokens, null, 'a failed call has unknown usage, not zero');
    assert.equal(r.outcome.outcome, 'unknown');
    assert.equal(r.text, '');
    noLeak(r.telemetry); noLeak(r.outcome);
  });

  test('an unrecognised failure code collapses to unknown-failure', async () => {
    const { root, config } = setup();
    const a = adapterOf({ config, scanRoot: root, transport: async () => { throw Object.assign(new Error('x'), { code: `custom-${CANARY_KEY}` }); } });
    const r = await a.invoke({ task: taskOf(3), runId: 'r3', prompt });
    assert.equal(r.telemetry.code, 'unknown-failure');
    noLeak(r.telemetry);
  });

  test('retryable failures are retried a bounded number of times and the retries are counted, bounded in cost and never free', async () => {
    const { root, config } = setup({ limits: { retries: 2 } });
    let calls = 0;
    const a = adapterOf({ config, scanRoot: root, transport: async () => { calls += 1; throw Object.assign(new Error('busy'), { code: 'overloaded', retryable: true }); } });
    const r = await a.invoke({ task: taskOf(4), runId: 'r4', prompt });
    assert.equal(calls, 3, 'one call plus two retries, no more');
    assert.equal(r.telemetry.attempts, 3);
    assert.equal(r.outcome.usage.retries, 2);
    assert.equal(r.telemetry.cost.status, 'unknown', 'the final attempt reported no usage, so the total is unknown, not zero');
    assert.equal(r.outcome.costUsd, null);
  });

  test('a partial response (output cut off) is kept as partial with its measured usage', async () => {
    const { root, config } = setup();
    const a = adapterOf({ config, scanRoot: root, transport: async () => ({ text: 'half a patch', finishReason: 'length', usage: { inputTokens: 1000, outputTokens: 4096, cachedInputTokens: 0 } }) });
    const r = await a.invoke({ task: taskOf(5), runId: 'r5', prompt });
    assert.equal(r.telemetry.status, 'partial');
    assert.equal(r.telemetry.finishReason, 'length');
    assert.equal(r.telemetry.cacheState, 'miss');
    assert.equal(r.outcome.status, 'partial');
    assert.equal(r.outcome.usage.outputTokens, 4096);
    assert.equal(r.text, 'half a patch');
  });

  test('output over the configured cap is truncated and recorded as partial', async () => {
    const { root, config } = setup({ limits: { maxOutputBytes: 16 } });
    const a = adapterOf({ config, scanRoot: root, transport: async () => ({ text: 'x'.repeat(500), finishReason: 'stop', usage: { inputTokens: 10, outputTokens: 500, cachedInputTokens: 0 } }) });
    const r = await a.invoke({ task: taskOf(6), runId: 'r6', prompt });
    assert.equal(r.telemetry.status, 'partial');
    assert.ok(r.text.length <= 16);
  });

  test('cancellation mid-call is recorded as cancelled and the transport is told to stop', async () => {
    const { root, config } = setup();
    const ac = new AbortController();
    let sawAbort = false;
    const a = adapterOf({ config, scanRoot: root, transport: ({ signal }) => new Promise((_, reject) => { signal.addEventListener('abort', () => { sawAbort = true; reject(Object.assign(new Error('aborted'), { retryable: false })); }); }) });
    const pending = a.invoke({ task: taskOf(7), runId: 'r7', prompt, signal: ac.signal });
    setTimeout(() => ac.abort(), 10);
    const r = await pending;
    assert.equal(r.telemetry.status, 'cancelled');
    assert.equal(r.outcome.status, 'cancelled');
    assert.equal(r.outcome.usage.inputTokens, null);
    assert.equal(sawAbort, true);
  });

  test('a caller that was already cancelled never reaches the transport', async () => {
    const { root, config } = setup();
    const ac = new AbortController(); ac.abort();
    let calls = 0;
    const a = adapterOf({ config, scanRoot: root, transport: async () => { calls += 1; return { text: 'x' }; } });
    const r = await a.invoke({ task: taskOf(8), runId: 'r8', prompt, signal: ac.signal });
    assert.equal(r.telemetry.status, 'cancelled');
    assert.equal(calls, 0);
  });

  test('a call that outruns its deadline is a timeout outcome', async () => {
    const { root, config } = setup({ limits: { timeoutMs: 30 } });
    const a = adapterOf({ config, scanRoot: root, transport: ({ signal }) => new Promise((_, reject) => { signal.addEventListener('abort', () => reject(Object.assign(new Error('late'), { retryable: false }))); }) });
    const r = await a.invoke({ task: taskOf(9), runId: 'r9', prompt });
    assert.equal(r.telemetry.status, 'timeout');
    assert.equal(r.outcome.status, 'timeout');
  });

  test('the transport only receives redacted text; the credential, source and request never reach telemetry', async () => {
    const { root, config } = setup();
    let seen = null;
    const a = adapterOf({
      config, scanRoot: root, endpoint: `https://user:${CRED_VALUE}@api.provider-a.example/v1/chat?key=${CANARY_KEY}`,
      credential: { name: 'PROVIDER_A_KEY', env: { PROVIDER_A_KEY: CRED_VALUE } },
      transport: async (req) => { seen = req.text; return { text: 'ok', finishReason: 'stop', usage: { inputTokens: 100, outputTokens: 10, cachedInputTokens: 0 } }; },
    });
    const r = await a.invoke({ task: taskOf(10), runId: 'r10', prompt });
    assert.equal(r.telemetry.status, 'completed');
    assert.ok(seen && !seen.includes(CANARY_KEY), 'secret reached the transport');
    assert.equal(r.telemetry.endpoint, 'https://api.provider-a.example');
    assert.ok(r.telemetry.redactions >= 1);
    noLeak(r.telemetry); noLeak(r.outcome);
    assert.equal(endpointHost('not a url'), null);
  });

  test('a missing credential blocks before any call, with a typed reason and no leak', async () => {
    const { root, config } = setup();
    let calls = 0;
    const a = adapterOf({ config, scanRoot: root, credential: { name: 'PROVIDER_A_KEY', env: {} }, transport: async () => { calls += 1; return { text: 'x' }; } });
    const r = await a.invoke({ task: taskOf(11), runId: 'r11', prompt });
    assert.equal(calls, 0);
    assert.equal(r.telemetry.status, 'blocked');
    assert.equal(r.telemetry.code, 'missing-credential');
    assert.equal(r.outcome.status, 'blocked');
  });

  test('the egress policy is consulted first: a denied endpoint never reaches the transport, and the decision is audited', async () => {
    const { root, config } = setup({ policy: 'mode: local-only\n' });
    let calls = 0;
    const a = adapterOf({ config, scanRoot: root, endpoint: 'https://api.provider-a.example/v1', transport: async () => { calls += 1; return { text: 'x' }; } });
    const r = await a.invoke({ task: taskOf(12), runId: 'r12', prompt });
    assert.equal(calls, 0);
    assert.equal(r.telemetry.status, 'blocked');
    assert.equal(r.telemetry.code, 'egress-denied');
    const log = path.join(root, '.agentic-security', 'egress-audit.log');
    assert.equal(fs.existsSync(log), true, 'the denial is in the egress audit chain');
    assert.equal(verifyEgressAuditLog(log).ok, true);
    noLeak(fs.readFileSync(log, 'utf8'));
  });

  test('with no endpoint configured there is no default and no cloud fallback', async () => {
    const { root, config } = setup();
    let calls = 0;
    const a = adapterOf({ config, scanRoot: root, endpoint: null, transport: async () => { calls += 1; return { text: 'x' }; } });
    const r = await a.invoke({ task: taskOf(13), runId: 'r13', prompt });
    assert.equal(calls, 0);
    assert.equal(r.telemetry.code, 'missing-provider');
  });

  test('with the model-routing feature off nothing is called and the outcome says it was blocked', async () => {
    const root = mkTestTmp('routing-adapter-off-');
    const config = resolveAssuranceConfig({ scanRoot: root, env: {}, platform: 'linux' });
    let calls = 0;
    const a = adapterOf({ config, scanRoot: root, transport: async () => { calls += 1; return { text: 'x' }; } });
    const r = await a.invoke({ task: taskOf(14), runId: 'r14', prompt });
    assert.equal(calls, 0);
    assert.equal(r.telemetry.status, 'blocked');
    assert.equal(r.outcome.status, 'blocked');
  });

  test('an inconsistent usage report (cached over total) is unknown for the cache split, not clamped', async () => {
    const { root, config } = setup();
    const a = adapterOf({ config, scanRoot: root, transport: async () => ({ text: 'x', finishReason: 'stop', usage: { inputTokens: 100, outputTokens: 5, cachedInputTokens: 900 } }) });
    const r = await a.invoke({ task: taskOf(15), runId: 'r15', prompt });
    assert.equal(r.telemetry.usage.cachedInputTokens, null);
    assert.equal(r.telemetry.cacheState, 'unknown');
  });

  test('no network client was touched by any fixture above', () => {
    assert.equal(fetchCalls, 0);
  });
});
