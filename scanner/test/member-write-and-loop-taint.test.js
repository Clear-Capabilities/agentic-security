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
