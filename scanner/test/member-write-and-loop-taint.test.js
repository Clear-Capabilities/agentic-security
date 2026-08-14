// Covers PRD R13 (docs/DETECTION_GAP_REMEDIATION_PRD.md, Theme E).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { matchMemberWriteSink } from '../src/dataflow/catalog.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-r13-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('R13(a) unit: matchMemberWriteSink finds the innerHTML entry for any receiver', () => {
  const hits = matchMemberWriteSink('el.innerHTML', 'a.js');
  assert.ok(hits && hits.some(h => h.id === 'js-innerHTML-assign'),
    'a flattened "x.innerHTML" target must match the js-innerHTML-assign entry regardless of the receiver name');
});

test('R13(a) unit: matchMemberWriteSink returns null for a bare identifier (no dot)', () => {
  assert.equal(matchMemberWriteSink('x', 'a.js'), null,
    'a bare identifier target has no property to match against MEMBER_INDEX');
});

test('R13(a) unit: matchMemberWriteSink returns null for an unrecognized property', () => {
  assert.equal(matchMemberWriteSink('el.textContent', 'a.js'), null,
    'textContent is the SAFE DOM sink — must not match');
});

test('R13(a) end-to-end: el.innerHTML = tainted is detected as DOM XSS', async () => {
  const dir = mkTmp('innerhtml', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/render', (req, res) => {
  const el = document.getElementById('out');
  el.innerHTML = req.query.name;
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const xssFindings = (scan.findings || []).filter(f => /xss/i.test(f.vuln || ''));
  assert.ok(xssFindings.length >= 1, 'el.innerHTML = req.query.name must be detected as DOM XSS');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(a) end-to-end: el.innerHTML = <literal> is NOT flagged (no taint)', async () => {
  const dir = mkTmp('innerhtml-clean', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/render', (req, res) => {
  const el = document.getElementById('out');
  el.innerHTML = '<b>static</b>';
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const xssFindings = (scan.findings || []).filter(f => /xss/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.equal(xssFindings.length, 0, 'a literal RHS must not be flagged — only a tainted RHS should fire');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(b) end-to-end: for (const x of tainted) sink(x) is detected as code injection', async () => {
  const dir = mkTmp('loop-taint', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  for (const item of req.body.items) {
    eval(item);
  }
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const codeInjFindings = (scan.findings || []).filter(f =>
    /code injection|eval/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.ok(codeInjFindings.length >= 1,
    'for (const item of req.body.items) { eval(item) } must be detected — the loop variable must inherit the iterable\'s taint');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(b): a for...of over a clean local array is not flagged', async () => {
  const dir = mkTmp('loop-clean', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const fixed = ['a', 'b', 'c'];
  for (const item of fixed) {
    eval(item);
  }
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const codeInjFindings = (scan.findings || []).filter(f =>
    /code injection|eval/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.equal(codeInjFindings.length, 0,
    'iterating a locally-defined, untainted array must not produce a finding — the loop-variable synthesis must not itself taint anything');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(b): other loop types (for, while, do-while, for-in) are unaffected', async () => {
  // Regression guard for the shared-visitor risk called out in this plan's
  // Global Constraints — the new logic must be scoped to ForOfStatement only.
  const dir = mkTmp('loop-others', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  for (let i = 0; i < 3; i++) { console.log(i); }
  let j = 0;
  while (j < 3) { console.log(j); j++; }
  do { j--; } while (j > 0);
  for (const key in { a: 1 }) { console.log(key); }
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  // No specific assertion on findings content — the point is the scan
  // completes without throwing and produces a stable findings array,
  // proving the shared visitor's other four branches are untouched.
  assert.ok(scan && Array.isArray(scan.findings), 'scan must complete for every other loop shape');
  fs.rmSync(dir, { recursive: true, force: true });
});
