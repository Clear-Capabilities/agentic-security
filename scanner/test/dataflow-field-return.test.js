// Field-sensitive return records (round 7 of the Haskell real-code work, language neutral): a function that returns an object whose fields
// differ in taint hands each field its own taint to the caller. `const v = view(req)` then `v.j` (a literal path) is clean and `v.q`
// (a query value) is tainted; the object read whole is tainted. Before, the callee's summary carried one bit (`returnTainted`) and the
// caller's whole result was tainted, so a file operation on the clean field was a request flow (hledger-web's `getViewData` record).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { mkTestTmp } from './helpers/tmp.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
delete process.env.CI;

async function scanJs(src) {
  const { runScan } = await import('../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp('field-return'), 'p-'));
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { express: '4.18.2' } }));
  writeFileSync(join(dir, 'src/app.js'), src);
  const { scan } = await runScan(dir, { deep: true });
  return scan.findings.filter((f) => f.parser === 'IR-TAINT');
}

const APP = (use) => `const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');
const app = express();

function view(req) {
  const jf = '/var/lib/app/journal.ledger';
  return { j: jf, q: req.query.q };
}

app.get('/view', (req, res) => {
  const v = view(req);
  ${use}
  res.send('ok');
});
`;

test('a returned object with one tainted field: the clean field is not a flow, the tainted field is, and the whole object still is', async () => {
  // control: the sink is live for the tainted field
  const control = await scanJs(APP('fs.readFile(v.q, () => {});'));
  assert.ok(control.some((f) => f.cwe === 'CWE-22'), `control: ${JSON.stringify(control.map((f) => [f.line, f.cwe]))}`);
  const onPath = await scanJs(APP('fs.readFile(v.j, () => {});'));
  assert.equal(onPath.filter((f) => f.cwe === 'CWE-22').length, 0, JSON.stringify(onPath.map((f) => [f.line, f.cwe, f.severity])));
  const onQuery = await scanJs(APP("exec('echo ' + v.q);"));
  assert.ok(onQuery.some((f) => f.cwe === 'CWE-78'), JSON.stringify(onQuery.map((f) => [f.line, f.cwe])));
  const whole = await scanJs(APP("exec('echo ' + JSON.stringify(v));"));
  assert.ok(whole.some((f) => f.cwe === 'CWE-78'), JSON.stringify(whole.map((f) => [f.line, f.cwe])));
});
