// PRD R15 (docs/DETECTION_GAP_REMEDIATION_PRD.md): dropGuardedFindings hard-
// removes a CWE-918 (SSRF) or CWE-22 (path traversal) finding whenever a
// guard-shaped token appears ANYWHERE in a -25/+5-line window around the
// sink, with no check that the guard actually applies to the variable
// flowing into the sink. An allow-list/guard for a completely unrelated
// purpose sitting in the same screenful of code silently killed a real,
// unguarded finding.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-guardcorr-${name}-`));
  fs.writeFileSync(path.join(dir, 'app.js'), content);
  return dir;
}

test('SSRF: a guard token protecting an UNRELATED variable does not suppress the finding', async () => {
  const dir = mkTmp('ssrf-unrelated', `
const fetch = require('node-fetch');
const express = require('express');
const app = express();
const allowedHosts = ['example.com', 'api.example.com'];
function isKnownPartner(name) {
  return allowedHosts.includes(name);
}
app.get('/fetch', (req, res) => {
  const target = req.query.url;
  fetch(target);
});
`);
  const { scan } = await runScan(dir);
  const ssrf = (scan.findings || []).filter((f) => f.cwe === 'CWE-918');
  assert.ok(ssrf.length >= 1,
    `expected the SSRF finding to survive an unrelated guard (allowedHosts, never mentioned near the sink or its tainted variable "target"), got: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
});

test('SSRF: a guard token that DOES reference the sink\'s own variable still suppresses (mechanism still works)', async () => {
  const dir = mkTmp('ssrf-related', `
const fetch = require('node-fetch');
const express = require('express');
const app = express();
const allowedHosts = ['example.com', 'api.example.com'];
app.get('/fetch', (req, res) => {
  const target = req.query.url;
  if (!allowedHosts.includes(target)) { return res.status(400).end(); }
  fetch(target);
});
`);
  const { scan } = await runScan(dir);
  const ssrf = (scan.findings || []).filter((f) => f.cwe === 'CWE-918');
  assert.equal(ssrf.length, 0,
    `expected the SSRF finding to still be suppressed when the guard genuinely references "target", got: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
});
