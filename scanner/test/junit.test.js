// JUnit XML report tests — verify shape and escaping.
import { test } from 'node:test';
import * as assert from 'node:assert';
import { toJUnit } from '../src/report/index.js';

test('toJUnit emits valid testsuites/testsuite/testcase structure', () => {
  const scan = {
    findings: [
      { id: 'a1', vuln: 'SQL Injection', severity: 'critical', cwe: 'CWE-89', file: 'app.js', line: 12, snippet: 'q', fix: { description: 'param', code: 'db.query(...)' } },
      { id: 'a2', vuln: 'XSS', severity: 'high', cwe: 'CWE-79', file: 'view.js', line: 5 },
    ],
    secrets: [
      { id: 's1', vuln: 'Hardcoded API Key', severity: 'high', cwe: 'CWE-798', file: '.env', line: 1 },
    ],
  };
  const xml = toJUnit(scan, { startedAt: '2026-05-11T00:00:00Z' });
  assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.match(xml, /<testsuites name="agentic-security" tests="3" failures="3"/);
  assert.match(xml, /<testsuite name="agentic-security" tests="3" failures="3"/);
  assert.match(xml, /<testcase classname="CWE-89" name="app.js:12 SQL Injection">/);
  assert.match(xml, /<failure type="critical" message="SQL Injection">/);
  assert.match(xml, /<testcase classname="CWE-79"/);
  assert.match(xml, /<testcase classname="CWE-798"/);
  assert.match(xml, /<\/testsuite>/);
  assert.match(xml, /<\/testsuites>/);
});

test('toJUnit escapes XML special characters in attributes', () => {
  const scan = {
    findings: [
      { id: 'x', vuln: 'XSS via <script> & "stuff"', severity: 'high', cwe: 'CWE-79', file: 'a<b>.js', line: 1 },
    ],
  };
  const xml = toJUnit(scan, {});
  assert.ok(xml.includes('&lt;script&gt;'), 'angle brackets escaped');
  assert.ok(xml.includes('&amp;'), 'ampersand escaped');
  assert.ok(xml.includes('&quot;'), 'quotes escaped');
  assert.ok(!/<script>/.test(xml), 'no raw <script>');
});

test('toJUnit closes ]]> sequences inside CDATA payloads', () => {
  const scan = {
    findings: [
      { id: 'c', vuln: 'demo', severity: 'low', file: 'x.js', line: 1,
        fix: { description: 'see ]]> escape' } },
    ],
  };
  const xml = toJUnit(scan, {});
  // The literal ]]> sequence must not appear inside CDATA — it would close it early.
  // We allow it once: as the closing ]]> of the <failure> CDATA itself.
  const closingMatches = xml.match(/]]>/g) || [];
  // One ]]> per failure (closes CDATA) — and the escaped sequence inside.
  assert.equal(closingMatches.length, 1, 'only one literal ]]> (the CDATA closer)');
});

test('toJUnit returns empty <testsuite> when there are no findings', () => {
  const xml = toJUnit({ findings: [], secrets: [], supplyChain: [] }, {});
  assert.match(xml, /tests="0" failures="0"/);
  assert.ok(!xml.includes('<testcase'), 'no testcase elements');
});
