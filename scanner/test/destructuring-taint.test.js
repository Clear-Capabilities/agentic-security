// Stage 3 correctness audit (detection depth, path-feasibility): both
// object and array destructuring assignments completely lost taint.
// parser-js.js emitted a SINGLE 'assign' CFG node whose `target` was the
// whole {kind:'object-pattern'|'array-pattern', ...} descriptor object,
// not a plain string. dataflow/engine.js's step() 'assign' case reads
// `node.target` directly and requires `typeof node.target === 'string'`
// to do anything — for a destructuring target that's always false, so
// `target` was silently `null` and NONE of the destructured bindings
// ever became tainted, for every project using this extremely common
// pattern (`const {cmd} = req.body`, `const [a, b] = arr`).
//
// parser-js.js's own recordWrite()/fn.writes bookkeeping DID attempt to
// record object-pattern properties — but nothing in dataflow/ ever reads
// fn.writes; only real CFG 'assign' nodes reach the taint walk.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-destr-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('object destructuring off a tainted source propagates taint to the bound name', async () => {
  const dir = mkTmp('obj', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const { cmd } = req.body;
  cp.exec(cmd);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected object destructuring of req.body to propagate taint to cmd, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('a renamed object-destructuring binding (`const { a: renamed } = ...`) also propagates taint', async () => {
  const dir = mkTmp('renamed', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const { cmd: userCmd } = req.body;
  cp.exec(userCmd);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected a renamed destructuring binding to propagate taint, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('array destructuring off a tainted variable propagates taint to the bound name', async () => {
  const dir = mkTmp('arr', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const arr = [req.body.cmd];
  const [cmd] = arr;
  cp.exec(cmd);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected array destructuring off a tainted variable to propagate taint, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('object destructuring of a clean literal does not fire (control)', async () => {
  const dir = mkTmp('control', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const { cmd } = { cmd: 'echo hello' };
  cp.exec(cmd);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.equal(cmdFindings.length, 0, 'a clean literal must not trigger a finding');
});
