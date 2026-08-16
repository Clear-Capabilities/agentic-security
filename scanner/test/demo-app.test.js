// node --test  — pins the demo app's promised findings.
//
// examples/demo-app is the deliberately-vulnerable project every tutorial in
// docs/guides/ scans. The quickstart shows a reader specific findings and
// fixes one of them. If a detector change silently stopped one of those
// findings from firing, the tutorial would lie and nobody would notice.
//
// This test is a CONTRACT, not a precision measurement: it asserts each
// promised vulnerability CLASS still fires (by family/vuln substring), not an
// exact count — so ordinary detector tuning that adds or merges findings does
// not break it, but dropping a whole class the docs promise does.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { normalizeFindings, exitCodeFor } from '../src/report/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEMO = path.resolve(__dirname, '..', '..', 'examples', 'demo-app');

test('demo-app: every vulnerability class the tutorials promise still fires', async () => {
  const { scan } = await runScan(DEMO);
  const findings = normalizeFindings(scan);
  const has = (re, label) =>
    assert.ok(findings.some(f => re.test(`${f.vuln} ${f.description || ''}`)), `missing: ${label}`);

  // server.js
  has(/SQL Injection/i, 'SQL injection (server.js db.query)');
  has(/Code Injection|eval/i, 'code injection (server.js eval)');
  has(/IDOR|Object Level Authorization|Missing (Authentication|auth)/i,
    'missing auth / BOLA on DELETE /orders/:id');

  // auth.js
  has(/MD5|Weak hash|Password Hashing/i, 'weak password hashing (auth.js MD5)');
  has(/Hardcoded credential|secret/i, 'hardcoded API key (auth.js)');

  // ai-assistant.js
  has(/Prompt Injection|Prompt Template/i, 'prompt injection (ai-assistant.js)');

  // report.py
  assert.ok(
    findings.some(f => /report\.py$/.test(f.file) && /SQL Injection/i.test(f.vuln)),
    'missing: Python SQL injection (report.py)');

  // Dockerfile
  has(/Dockerfile/i, 'Dockerfile hygiene finding');

  // package.json — SCA over the vulnerable dependency pins
  assert.ok(
    findings.some(f => /package\.json$/.test(f.file) && /(CVE-|GHSA-)/.test(`${f.vuln} ${f.description || ''}`)),
    'missing: SCA CVE finding on a pinned dependency');
});

test('demo-app: the verdict is "not safe to deploy" (critical present)', async () => {
  const { scan } = await runScan(DEMO);
  // report.py's SQL injection is critical; exit code 3 is the critical verdict.
  assert.equal(exitCodeFor(scan), 3, 'demo app should exit 3 (critical findings present)');
});
