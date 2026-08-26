// Egress policy integration tests (assurance-hardening PRD FR-601).
//
// FR-601's literal acceptance criterion: "A denied call results in no
// network request and a machine-readable policy decision." Unit tests on
// evaluateEgress() alone don't prove that — they only prove the function
// returns the right verdict. These tests exercise the REAL call sites
// (hunter, disprove, llm-validator, adversary-agent, llm-redteam,
// flow-narration, sca-llm-function-extract) with AGENTIC_SECURITY_EGRESS_DENY
// set, stub global.fetch, and assert it is NEVER invoked — proving the
// denial actually reaches the network boundary at every wired site, not
// just the policy function in isolation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function withEnv(overrides, body) {
  const snapshot = {};
  for (const k of Object.keys(overrides)) snapshot[k] = process.env[k];
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  return Promise.resolve().then(body).finally(() => {
    for (const [k, v] of Object.entries(snapshot)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
}

function stubFetch() {
  const orig = global.fetch;
  let called = 0;
  global.fetch = async () => { called++; return { ok: true, json: async () => ({}), text: async () => '{}' }; };
  return { restore: () => { global.fetch = orig; }, count: () => called };
}

test('discovery hunter: denied endpoint -> no fetch, degraded with the policy reason', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat', AGENTIC_SECURITY_EGRESS_DENY: '1' }, async () => {
    const { runHunter } = await import('../src/discovery/hunter.js');
    const fetchStub = stubFetch();
    let run;
    try {
      run = await runHunter(
        { id: 'area-1', label: 'area', files: ['a.js'] },
        { key: 'auth', label: 'Auth' },
        { fileContents: { 'a.js': 'x' } },
        {},
      );
    } finally { fetchStub.restore(); }
    assert.equal(fetchStub.count(), 0, 'a denied call must produce no network request');
    assert.equal(run.degraded, true);
    assert.match(run.reason, /egress policy denied/);
    assert.ok(run.egressDecision && run.egressDecision.decision === 'deny');
  });
});

test('discovery disprove: denied endpoint -> no fetch, panel undecided (silence never refutes)', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat', AGENTIC_SECURITY_EGRESS_DENY: '1' }, async () => {
    const { disproveCandidate } = await import('../src/discovery/disprove.js');
    const fetchStub = stubFetch();
    let result;
    try {
      result = await disproveCandidate({ title: 'x', file: 'a.js', line: 1, rationale: 'r' }, {});
    } finally { fetchStub.restore(); }
    assert.equal(fetchStub.count(), 0);
    assert.equal(result.refutation.undecided, true);
    assert.equal(result.refutation.refuted, false, 'a denied endpoint must never look like an argued refutation');
    assert.ok(result.refutation.egressDecision && result.refutation.egressDecision.decision === 'deny');
  });
});

test('llm-validator: denied endpoint -> no fetch, finding tagged with a distinct egress-policy-denied error', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-lv-'));
  try {
    await withEnv({
      AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat',
      AGENTIC_SECURITY_LLM_API_KEY: 'fake', AGENTIC_SECURITY_LLM_MODEL: 'test-model',
      AGENTIC_SECURITY_EGRESS_DENY: '1',
    }, async () => {
      const { validateOne } = await import('../src/llm-validator/index.js');
      const finding = { id: 'f1', stableId: 'f1', file: 'a.js', line: 10, severity: 'high', confidence: 0.9, parser: 'AST', vuln: 'SQLi', cwe: 'CWE-89' };
      const fetchStub = stubFetch();
      let result;
      try {
        result = await validateOne(finding, { 'a.js': 'line\n'.repeat(20) }, dir);
      } finally { fetchStub.restore(); }
      assert.equal(fetchStub.count(), 0);
      assert.equal(result.verdict, 'unvalidated');
      assert.equal(result.error, 'egress-policy-denied');
      assert.equal(finding._validatorError, 'egress-policy-denied');
      assert.ok(finding._egressDecision && finding._egressDecision.decision === 'deny');
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FR-602: llm-validator threads role/model through to evaluateEgress — a deniedModels rule reaches the real call path, not just the policy function in isolation', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-lv-model-'));
  try {
    fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.agentic-security', 'egress-policy.yml'), 'deniedModels:\n  - test-model\n');
    await withEnv({
      AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat',
      AGENTIC_SECURITY_LLM_API_KEY: 'fake', AGENTIC_SECURITY_LLM_MODEL: 'test-model',
      AGENTIC_SECURITY_EGRESS_DENY: undefined,
    }, async () => {
      const { validateOne } = await import('../src/llm-validator/index.js');
      const finding = { id: 'f1', stableId: 'f1', file: 'a.js', line: 10, severity: 'high', confidence: 0.9, parser: 'AST', vuln: 'SQLi', cwe: 'CWE-89' };
      const fetchStub = stubFetch();
      let result;
      try {
        result = await validateOne(finding, { 'a.js': 'line\n'.repeat(20) }, dir);
      } finally { fetchStub.restore(); }
      assert.equal(fetchStub.count(), 0, 'the model rule must block the call before any fetch');
      assert.equal(result.verdict, 'unvalidated');
      assert.equal(result.error, 'egress-policy-denied');
      assert.match(finding._egressDecision.reason, /model 'test-model' is in deniedModels/);
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FR-603: llm-validator\'s real prompt-building path redacts secrets/PII/customer-data/proprietary-path content, not just the policy function in isolation', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-lv-redact-'));
  try {
    fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, '.agentic-security', 'egress-policy.yml'),
      'customerDataPatterns:\n  - "CUST-\\\\d{6}"\n',
    );
    await withEnv({
      AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat',
      AGENTIC_SECURITY_LLM_API_KEY: 'fake', AGENTIC_SECURITY_LLM_MODEL: 'test-model',
      AGENTIC_SECURITY_EGRESS_DENY: undefined,
    }, async () => {
      const { validateOne } = await import('../src/llm-validator/index.js');
      const secretValue = 'sk-live-abcdefghijklmnopqrstuvwx0123456789';
      const ssnValue = '123-45-6789';
      const custId = 'CUST-000123';
      const fileContents = {
        'a.js': Array.from({ length: 20 }, (_, i) => {
          if (i === 9) return `  const apiKey = "${secretValue}"; const ssn = "${ssnValue}"; // ${custId}`;
          return `line${i}`;
        }).join('\n'),
      };
      const finding = { id: 'f1', stableId: 'f1', file: 'a.js', line: 10, severity: 'high', confidence: 0.9, parser: 'AST', vuln: 'SQLi', cwe: 'CWE-89', snippet: `const apiKey = "${secretValue}"; const ssn = "${ssnValue}"; // ${custId}` };
      let capturedBody = null;
      const origFetch = global.fetch;
      global.fetch = async (_url, opts) => {
        capturedBody = opts.body;
        return { ok: true, json: async () => ({}), text: async () => '{}' };
      };
      try {
        await validateOne(finding, fileContents, dir);
      } finally { global.fetch = origFetch; }
      assert.ok(capturedBody, 'the call must have reached the real fetch boundary (not denied for an unrelated reason)');
      assert.ok(!capturedBody.includes(secretValue), 'the secret value must not appear in the actual outbound HTTP body');
      assert.ok(!capturedBody.includes(ssnValue), 'the PII value must not appear in the actual outbound HTTP body');
      assert.ok(!capturedBody.includes(custId), 'the operator-configured customer-data value must not appear in the actual outbound HTTP body');
      assert.ok(capturedBody.includes('apiKey'), 'structure (variable name) should still survive for the validator to reason about');
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FR-604: llm-validator\'s real call path writes a persisted egress-audit entry for both a denied and an allowed call, with byte/token/hash metadata but never the prompt text', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-lv-audit-'));
  try {
    fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '{}');
    const { verifyEgressAuditLog, _internals: auditInternals } = await import('../src/egress/audit.js');
    const auditLogPath = path.join(dir, '.agentic-security', auditInternals.LOG_FILE_NAME);

    // Deny leg — no endpoint configured at all is a different (DISABLED) branch,
    // so use mode: deny to reach the real FR-601 egress-deny branch.
    fs.writeFileSync(path.join(dir, '.agentic-security', 'egress-policy.yml'), 'mode: deny\n');
    await withEnv({
      AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat',
      AGENTIC_SECURITY_LLM_API_KEY: 'fake', AGENTIC_SECURITY_LLM_MODEL: 'test-model',
      AGENTIC_SECURITY_EGRESS_DENY: undefined,
    }, async () => {
      const { validateOne } = await import('../src/llm-validator/index.js');
      const finding = { id: 'f1', stableId: 'f1', file: 'a.js', line: 10, severity: 'high', confidence: 0.9, parser: 'AST', vuln: 'SQLi', cwe: 'CWE-89' };
      const fetchStub = stubFetch();
      try { await validateOne(finding, { 'a.js': 'line\n'.repeat(20) }, dir); }
      finally { fetchStub.restore(); }
    });

    let lines = fs.readFileSync(auditLogPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    let entry = JSON.parse(lines[0]);
    assert.equal(entry.outcome, 'deny');
    assert.equal(entry.purpose, 'llm-validator');
    assert.equal(entry.byteCount, null, 'a denied call never builds a payload, so nothing to measure');

    // Allow leg — remove the denial, let the real prompt get built and the
    // (stubbed) fetch actually fire.
    fs.writeFileSync(path.join(dir, '.agentic-security', 'egress-policy.yml'), '');
    const secretValue = 'sk-live-abcdefghijklmnopqrstuvwx0123456789';
    await withEnv({
      AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat',
      AGENTIC_SECURITY_LLM_API_KEY: 'fake', AGENTIC_SECURITY_LLM_MODEL: 'test-model',
      AGENTIC_SECURITY_EGRESS_DENY: undefined,
    }, async () => {
      const { validateOne } = await import('../src/llm-validator/index.js');
      const finding = { id: 'f2', stableId: 'f2', file: 'a.js', line: 10, severity: 'high', confidence: 0.9, parser: 'AST', vuln: 'SQLi', cwe: 'CWE-89', snippet: `const apiKey = "${secretValue}";` };
      const fileContents = { 'a.js': Array.from({ length: 20 }, (_, i) => i === 9 ? `const apiKey = "${secretValue}";` : `line${i}`).join('\n') };
      const origFetch = global.fetch;
      global.fetch = async () => ({ ok: true, json: async () => ({}), text: async () => '{}' });
      try { await validateOne(finding, fileContents, dir); }
      finally { global.fetch = origFetch; }
    });

    lines = fs.readFileSync(auditLogPath, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2, 'the second call appends a second entry, chained to the first');
    entry = JSON.parse(lines[1]);
    assert.equal(entry.outcome, 'allow');
    assert.ok(entry.byteCount > 0);
    assert.ok(entry.tokenCount > 0);
    assert.equal(typeof entry.contentHash, 'string');
    assert.ok(!lines[1].includes(secretValue), 'the audit log line itself must never contain the secret that was in the prompt');

    const verified = verifyEgressAuditLog(auditLogPath);
    assert.deepEqual(verified, { ok: true, entries: 2 });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FR-607: llm-validator\'s real call path is blocked by a regulated profile with no approved-provider metadata, not just the policy function in isolation', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-lv-r607-'));
  try {
    fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, '.agentic-security', 'egress-policy.yml'),
      'regulatedProfile:\n  requireApprovedProviders: true\n',
    );
    await withEnv({
      AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat',
      AGENTIC_SECURITY_LLM_API_KEY: 'fake', AGENTIC_SECURITY_LLM_MODEL: 'test-model',
      AGENTIC_SECURITY_EGRESS_DENY: undefined,
    }, async () => {
      const { validateOne } = await import('../src/llm-validator/index.js');
      const finding = { id: 'f1', stableId: 'f1', file: 'a.js', line: 10, severity: 'high', confidence: 0.9, parser: 'AST', vuln: 'SQLi', cwe: 'CWE-89' };
      const fetchStub = stubFetch();
      let result;
      try {
        result = await validateOne(finding, { 'a.js': 'line\n'.repeat(20) }, dir);
      } finally { fetchStub.restore(); }
      assert.equal(fetchStub.count(), 0, 'a regulated profile with no approved provider must block the call before any fetch');
      assert.equal(result.verdict, 'unvalidated');
      assert.equal(result.error, 'egress-policy-denied');
      assert.match(finding._egressDecision.reason, /has no approved-provider metadata configured/);
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('adversary-agent: denied endpoint -> no fetch, outcome unverified-no-llm-endpoint with the policy reason', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat', AGENTIC_SECURITY_EGRESS_DENY: '1' }, async () => {
    const { runAgent } = await import('../src/posture/adversary-agent.js');
    const fetchStub = stubFetch();
    let result;
    try {
      result = await runAgent({ id: 'f1', vuln: 'SQLi' }, {});
    } finally { fetchStub.restore(); }
    assert.equal(fetchStub.count(), 0);
    assert.equal(result.outcome, 'unverified-no-llm-endpoint');
    assert.ok(result.egressDecision && result.egressDecision.decision === 'deny');
  });
});

test('llm-redteam runActiveRedteam: denied endpoint -> no fetch, throws a clear egress-policy error', async () => {
  await withEnv({ AGENTIC_SECURITY_EGRESS_DENY: '1' }, async () => {
    const { runActiveRedteam } = await import('../src/posture/llm-redteam.js');
    const fetchStub = stubFetch();
    try {
      await assert.rejects(
        () => runActiveRedteam({ endpoint: 'https://api.example.com/v1/chat' }),
        /egress policy denied/,
      );
    } finally { fetchStub.restore(); }
    assert.equal(fetchStub.count(), 0);
  });
});

test('flow-narration: denied endpoint -> no fetch, falls back to the deterministic template', async () => {
  await withEnv({ AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat', AGENTIC_SECURITY_EGRESS_DENY: '1' }, async () => {
    const { annotateNarration } = await import('../src/posture/flow-narration.js');
    const findings = [{ id: 'f1', severity: 'high', vuln: 'SQL Injection', family: 'sql-injection', cwe: 'CWE-89' }];
    const fetchStub = stubFetch();
    try {
      await annotateNarration(findings, { useLlm: true });
    } finally { fetchStub.restore(); }
    assert.equal(fetchStub.count(), 0);
    assert.ok(typeof findings[0].narration === 'string' && findings[0].narration.length > 0, 'must still get the template fallback narration, not a missing field');
  });
});

test('sca llm-function-extract: denied endpoint -> no fetch, returns empty enrichment (same as no-endpoint degrade)', async () => {
  await withEnv({
    AGENTIC_SECURITY_LLM_SCA: '1',
    AGENTIC_SECURITY_LLM_ENDPOINT: 'https://api.example.com/v1/chat',
    AGENTIC_SECURITY_EGRESS_DENY: '1',
  }, async () => {
    const { extractVulnFunctionsViaLLM } = await import('../src/sca/llm-function-extract.js');
    const supplyChain = [{
      type: 'vulnerable_dep', name: 'left-pad', version: '1.0.0',
      osvId: 'GHSA-test-0001', noKnownCallSite: true, description: 'a vulnerable function exists',
      osvVulnFunctions: [],
    }];
    const fetchStub = stubFetch();
    let result;
    try {
      result = await extractVulnFunctionsViaLLM(supplyChain, {});
    } finally { fetchStub.restore(); }
    assert.equal(fetchStub.count(), 0);
    assert.deepEqual(result, []);
  });
});
