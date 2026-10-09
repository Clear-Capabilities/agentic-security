// Pass^k consistency harness tests.
//
// We can't depend on a live LLM endpoint in unit tests, so we exercise the
// harness with the validator disabled — every trial returns 'unvalidated',
// stability is trivially 100%. The harness still has to handle the shape
// correctly (no crash, structured report, per-finding detail).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { measureConsistency, summarize } from '../src/llm-validator/consistency.js';
import { mkTestTmp } from './helpers/tmp.js';

test('measureConsistency runs cleanly with validator off (all unvalidated)', async () => {
  const scanRoot = mkTestTmp('consist-');
  const findings = [
    { id: 'f1', stableId: 'abc', file: 'app.js', line: 10, vuln: 'X', cwe: 'CWE-89', severity: 'high' },
    { id: 'f2', stableId: 'def', file: 'app.js', line: 20, vuln: 'Y', cwe: 'CWE-78', severity: 'critical' },
  ];
  const fileContents = { 'app.js': '// dummy\n'.repeat(30) };
  // Ensure the validator is OFF.
  delete process.env.AGENTIC_SECURITY_LLM_VALIDATE;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const r = await measureConsistency({ findings, fileContents, scanRoot, trials: 3 });
  assert.equal(r.ok, true);
  assert.equal(r.trials, 3);
  assert.equal(r.findingCount, 2);
  // With validator off, every trial returns 'unvalidated' → trivially stable.
  assert.equal(r.passK_unanimous, 1);
  for (const f of r.findings) {
    assert.equal(f.stable, true);
    assert.equal(f.dominantVerdict, 'unvalidated');
    assert.equal(f.verdicts.length, 3);
  }
});

test('measureConsistency refuses zero findings', async () => {
  const r = await measureConsistency({ findings: [], trials: 3 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-findings-supplied');
});

test('measureConsistency rejects trials out of range', async () => {
  const r = await measureConsistency({
    findings: [{ id: 'f', file: 'a', line: 1, vuln: 'X' }],
    trials: 1,
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'trials-out-of-range');
  const r2 = await measureConsistency({
    findings: [{ id: 'f', file: 'a', line: 1, vuln: 'X' }],
    trials: 999,
  });
  assert.equal(r2.ok, false);
});

test('summarize produces a multi-line human report', async () => {
  const findings = [{ id: 'f1', file: 'a.js', line: 1, vuln: 'X' }];
  const r = await measureConsistency({ findings, fileContents: { 'a.js': '' }, trials: 2 });
  const s = summarize(r);
  assert.match(s, /llm-validator consistency/);
  assert.match(s, /pass\^2/);
});
