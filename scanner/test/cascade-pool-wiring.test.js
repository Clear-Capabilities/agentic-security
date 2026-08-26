// FR-202 phase 3b (D-0050): proves createCascadePool is genuinely wired into
// runFullScan's real per-file loop, not just tested as an isolated primitive.
// Three properties, each against a REAL scan through the real parser:
//   1. AGENTIC_SECURITY_WORKER_CASCADE unset -> today's synchronous path, unchanged.
//   2. ...=1 with a generous timeout -> the SAME real findings as the sync path.
//   3. ...=1 with an impossibly low per-file timeout -> the scan still completes
//      (no crash, no hang) and the affected file gets a real file-timeout marker
//      instead of a real result -- the literal FR-202 acceptance criterion,
//      now proven through the actual engine, not just the pool primitive alone.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const { runFullScan } = await import('../src/engine.js');

const VULNERABLE_APP = `
const express = require('express');
const app = express();
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query);
  res.send('ok');
});
`;

async function scanOnce(envOverrides = {}) {
  const prior = {};
  for (const k of Object.keys(envOverrides)) prior[k] = process.env[k];
  Object.assign(process.env, envOverrides);
  process.env.AGENTIC_SECURITY_NO_STATE = '1';
  try {
    return await runFullScan({ fileContents: { 'app.js': VULNERABLE_APP }, scanRoot: null });
  } finally {
    for (const k of Object.keys(envOverrides)) {
      if (prior[k] === undefined) delete process.env[k]; else process.env[k] = prior[k];
    }
    delete process.env.AGENTIC_SECURITY_NO_STATE;
  }
}

test('worker cascade OFF by default: AGENTIC_SECURITY_WORKER_CASCADE unset uses the synchronous path', async () => {
  assert.equal(process.env.AGENTIC_SECURITY_WORKER_CASCADE, undefined);
  const result = await scanOnce();
  const sqli = (result.findings || []).find(f => /sql/i.test(f.vuln || ''));
  assert.ok(sqli, 'expected the real SQL injection finding from the synchronous path');
});

test('worker cascade ON with a generous timeout produces the SAME real findings as the synchronous path', async () => {
  const sync = await scanOnce();
  const pooled = await scanOnce({ AGENTIC_SECURITY_WORKER_CASCADE: '1', AGENTIC_SECURITY_PER_FILE_TIMEOUT_MS: '10000' });

  const syncVulns = (sync.findings || []).map(f => f.vuln).sort();
  const pooledVulns = (pooled.findings || []).map(f => f.vuln).sort();
  assert.deepEqual(pooledVulns, syncVulns, 'the pool-dispatched cascade must produce the same findings as the direct synchronous call');

  const pooledSqli = pooled.findings.find(f => /sql/i.test(f.vuln || ''));
  assert.ok(pooledSqli, 'expected the real SQL injection finding through the pool path too');
  assert.ok(!pooled.findings.some(f => f._timeout), 'a generous timeout must not produce a spurious file-timeout marker');
});

test('worker cascade ON with an impossibly low per-file timeout: the scan still completes and marks the file as timed out, per FR-202\'s acceptance criterion', async () => {
  const result = await scanOnce({ AGENTIC_SECURITY_WORKER_CASCADE: '1', AGENTIC_SECURITY_PER_FILE_TIMEOUT_MS: '1' });
  assert.ok(result, 'the scan call itself must resolve, not hang or throw');
  const timeoutFinding = (result.findings || []).find(f => f._timeout === true && f.file === 'app.js');
  assert.ok(timeoutFinding, 'expected a real file-timeout marker finding for the impossibly-tight-deadline file');
  assert.equal(timeoutFinding.parser, 'ENGINE');
});
