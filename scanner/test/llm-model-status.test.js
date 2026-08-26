// FR-606 (assurance-hardening PRD): surface model unavailability or
// refusal without converting it into a clean deterministic conclusion.
// Reports distinguish model-disabled, policy-blocked, unavailable,
// malformed, and completed.
//
// Before this requirement, every degrade path in llm-validator/index.js
// set the SAME finding.validator_verdict ('unvalidated'), with the actual
// reason scattered across an inconsistently-populated free-text field —
// sometimes present ('egress-policy-denied', 'cost-ceiling'), sometimes
// entirely absent (the "nothing configured at all" case). A reader had no
// reliable way to distinguish "the tier is off" from "it tried and
// failed" from "it answered garbage" from "no endpoint was ever
// reachable in the first place."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { validateMany } from '../src/llm-validator/index.js';
import { MODEL_STATUS, summarizeModelStatus } from '../src/llm-validator/model-status.js';

function makeFinding(overrides = {}) {
  return {
    id: 'test-1', stableId: 'test-1',
    file: 'a.js', line: 10,
    severity: 'high', confidence: 0.9, parser: 'AST',
    vuln: 'SQL Injection', cwe: 'CWE-89',
    ...overrides,
  };
}

function withEnv(overrides, body) {
  const snapshot = {};
  for (const k of Object.keys(overrides)) snapshot[k] = process.env[k];
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  return (async () => {
    try { return await body(); }
    finally {
      for (const [k, v] of Object.entries(snapshot)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  })();
}

test('MODEL_STATUS is exactly the 5 values the PRD names, no more, no fewer', () => {
  assert.deepEqual(Object.values(MODEL_STATUS).sort(), [
    'completed', 'malformed', 'model-disabled', 'policy-blocked', 'unavailable',
  ]);
});

test('DISABLED: nothing configured at all', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: undefined, AGENTIC_SECURITY_LLM_VALIDATE: undefined }, async () => {
    const findings = [makeFinding()];
    await validateMany(findings, { fileContents: {}, scanRoot: os.tmpdir() });
    assert.equal(findings[0].llmValidationStatus, MODEL_STATUS.DISABLED);
  });
});

test('DISABLED: an explicit operator opt-out (VALIDATE=0) with an endpoint otherwise configured', async () => {
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_VALIDATE: '0',
  }, async () => {
    const findings = [makeFinding()];
    await validateMany(findings, { fileContents: {}, scanRoot: os.tmpdir() });
    assert.equal(findings[0].llmValidationStatus, MODEL_STATUS.DISABLED);
  });
});

test('POLICY_BLOCKED: the local preset refuses a configured but non-loopback endpoint', async () => {
  await withEnv({
    AGENTIC_SECURITY_LLM_PRESET: 'local',
    AGENTIC_SECURITY_LLM_ENDPOINT: 'https://not-loopback.example.com/v1/chat',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const findings = [makeFinding()];
    await validateMany(findings, { fileContents: {}, scanRoot: os.tmpdir() });
    assert.equal(findings[0].llmValidationStatus, MODEL_STATUS.POLICY_BLOCKED);
  });
});

test('POLICY_BLOCKED: the egress policy denies the endpoint', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-status-egress-'));
  await fs.promises.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  await fs.promises.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fs.promises.writeFile(path.join(dir, '.agentic-security', 'egress-policy.yml'), 'mode: deny\n');
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
      AGENTIC_SECURITY_LLM_API_KEY: 'fake',
      AGENTIC_SECURITY_LLM_MODEL: 'test-model',
      AGENTIC_SECURITY_LLM_VALIDATE: undefined,
    }, async () => {
      const findings = [makeFinding()];
      let fetchCalled = false;
      const origFetch = global.fetch;
      global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
      try {
        await validateMany(findings, { fileContents: { 'a.js': 'x\n'.repeat(20) }, scanRoot: dir });
      } finally { global.fetch = origFetch; }
      assert.equal(fetchCalled, false);
      assert.equal(findings[0].llmValidationStatus, MODEL_STATUS.POLICY_BLOCKED);
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('UNAVAILABLE: the endpoint is reached but returns a non-2xx status', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-status-unavail-'));
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_MODEL: 'test-model',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const findings = [makeFinding()];
    const origFetch = global.fetch;
    global.fetch = async () => ({ ok: false, status: 503 });
    try {
      await validateMany(findings, { fileContents: { 'a.js': 'x\n'.repeat(20) }, scanRoot: dir });
    } finally { global.fetch = origFetch; }
    assert.equal(findings[0].llmValidationStatus, MODEL_STATUS.UNAVAILABLE);
  });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('UNAVAILABLE: a network/fetch exception (connection refused, timeout, etc.)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-status-neterr-'));
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_MODEL: 'test-model',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const findings = [makeFinding()];
    const origFetch = global.fetch;
    global.fetch = async () => { throw new Error('ECONNREFUSED'); };
    try {
      await validateMany(findings, { fileContents: { 'a.js': 'x\n'.repeat(20) }, scanRoot: dir });
    } finally { global.fetch = origFetch; }
    assert.equal(findings[0].llmValidationStatus, MODEL_STATUS.UNAVAILABLE);
  });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('MALFORMED: a 2xx response whose body cannot be parsed into a usable verdict', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-status-malformed-'));
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_MODEL: 'test-model',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const findings = [makeFinding()];
    const origFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ response: 'not json at all, just prose' }) });
    try {
      await validateMany(findings, { fileContents: { 'a.js': 'x\n'.repeat(20) }, scanRoot: dir });
    } finally { global.fetch = origFetch; }
    assert.equal(findings[0].validator_verdict, 'escalate');
    assert.equal(findings[0].llmValidationStatus, MODEL_STATUS.MALFORMED);
  });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('COMPLETED: a real, validated verdict was produced', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-status-completed-'));
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_MODEL: 'test-model',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const findings = [makeFinding()];
    const origFetch = global.fetch;
    global.fetch = async (url, opts) => {
      const body = JSON.parse(opts.body);
      const m = body.prompt.match(/"challenge": "([a-f0-9]+)"/);
      const challenge = m ? m[1] : '00000000';
      const fm = body.prompt.match(/"file": "([^"]+)"/);
      const file = fm ? fm[1] : '';
      const lm = body.prompt.match(/"line": (\d+)/);
      const line = lm ? Number(lm[1]) : 0;
      const obj = { challenge, file, line, verdict: 'accept', confidence: 0.85, reasoning: 'looks real' };
      return { ok: true, json: async () => ({ response: 'final answer:\n' + JSON.stringify(obj) }) };
    };
    try {
      await validateMany(findings, { fileContents: { 'a.js': 'line1\n'.repeat(20) }, scanRoot: dir });
    } finally { global.fetch = origFetch; }
    assert.equal(findings[0].validator_verdict, 'accept');
    assert.equal(findings[0].llmValidationStatus, MODEL_STATUS.COMPLETED);
  });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('COMPLETED: a cache hit is COMPLETED, not a sixth status', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-status-cache-'));
  // A project marker is required for state-dir.js's isSafeStateDir to treat
  // <dir>/.agentic-security as a valid state root at all — without it,
  // writeCache silently no-ops and every call re-fetches. (Confirmed this
  // cycle: an existing, superficially-similar test elsewhere in this suite
  // that also omits the marker is order-dependent — it only passes when an
  // earlier test in the same file happens to run first. Not chased down
  // further here; out of scope for FR-606.)
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t"}');
  const fileContents = { 'a.js': 'line1\n'.repeat(20) };
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_MODEL: 'test-model',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const origFetch = global.fetch;
    let fetchCalls = 0;
    global.fetch = async (url, opts) => {
      fetchCalls++;
      const body = JSON.parse(opts.body);
      const m = body.prompt.match(/"challenge": "([a-f0-9]+)"/);
      const challenge = m ? m[1] : '00000000';
      const obj = { challenge, file: 'a.js', line: 10, verdict: 'accept', confidence: 0.85, reasoning: 'x' };
      return { ok: true, json: async () => ({ response: 'final answer:\n' + JSON.stringify(obj) }) };
    };
    try {
      const first = [makeFinding()];
      await validateMany(first, { fileContents, scanRoot: dir });
      assert.equal(fetchCalls, 1);
      const second = [makeFinding()];
      await validateMany(second, { fileContents, scanRoot: dir });
      assert.equal(fetchCalls, 1, 'second run should hit the cache, not fetch again');
      assert.equal(second[0].llmValidationStatus, MODEL_STATUS.COMPLETED);
    } finally { global.fetch = origFetch; }
  });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a finding skipped for suitability reasons (SCA locator, no precise location) is NOT stamped with any of the 5 statuses', async () => {
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_MODEL: 'test-model',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-status-na-'));
    const scaFinding = makeFinding({ parser: 'SCA', line: 0, pkg: 'lodash' });
    const origFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({}) });
    try {
      await validateMany([scaFinding], { fileContents: {}, scanRoot: dir });
    } finally { global.fetch = origFetch; fs.rmSync(dir, { recursive: true, force: true }); }
    assert.equal(scaFinding.validator_verdict, 'not-applicable');
    assert.equal(scaFinding.llmValidationStatus, undefined, 'a suitability skip is not a model-availability state');
  });
});

// ── summarizeModelStatus ──────────────────────────────────────────────

test('summarizeModelStatus: counts each of the 5 statuses plus notApplicable, never double-counting', () => {
  const findings = [
    { llmValidationStatus: MODEL_STATUS.COMPLETED },
    { llmValidationStatus: MODEL_STATUS.COMPLETED },
    { llmValidationStatus: MODEL_STATUS.UNAVAILABLE },
    { llmValidationStatus: MODEL_STATUS.MALFORMED },
    { llmValidationStatus: MODEL_STATUS.POLICY_BLOCKED },
    { llmValidationStatus: MODEL_STATUS.DISABLED },
    { /* no status — not applicable */ },
  ];
  const summary = summarizeModelStatus(findings);
  assert.equal(summary.counts[MODEL_STATUS.COMPLETED], 2);
  assert.equal(summary.counts[MODEL_STATUS.UNAVAILABLE], 1);
  assert.equal(summary.counts[MODEL_STATUS.MALFORMED], 1);
  assert.equal(summary.counts[MODEL_STATUS.POLICY_BLOCKED], 1);
  assert.equal(summary.counts[MODEL_STATUS.DISABLED], 1);
  assert.equal(summary.notApplicable, 1);
  assert.equal(summary.total, 7);
});

test('summarizeModelStatus: an empty or missing findings array degrades to all-zero, never throws', () => {
  assert.deepEqual(summarizeModelStatus([]).total, 0);
  assert.deepEqual(summarizeModelStatus(null).total, 0);
  assert.deepEqual(summarizeModelStatus(undefined).total, 0);
});

test('validateMany attaches findings.llmValidatorStatus as a scan-level aggregate, both on the disabled path and the enabled path', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: undefined, AGENTIC_SECURITY_LLM_VALIDATE: undefined }, async () => {
    const findings = [makeFinding()];
    await validateMany(findings, { fileContents: {}, scanRoot: os.tmpdir() });
    assert.ok(findings.llmValidatorStatus);
    assert.equal(findings.llmValidatorStatus.counts[MODEL_STATUS.DISABLED], 1);
  });
});
