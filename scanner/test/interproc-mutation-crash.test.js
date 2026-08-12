// Stage 3 correctness audit (detection depth): `step()`'s taint-state
// binding was `const state = new Set(stateIn)`, but the 'call' case's
// built-in-mutation branch (Object.assign/_.merge/...) and mutated-param
// branch both REASSIGN it (`state = addPath(state, v)` /
// `state = _addPathAliasAware(...)`). That throws "Assignment to constant
// variable" at runtime. Every analyzeFunction() call site wraps in a blanket
// try/catch with no logging, so the exception silently unwinds past every
// finding already pushed for OTHER, unrelated sinks earlier in the same
// function body — one Object.assign call anywhere in a function could
// silently erase every finding in that function, not just miss the
// mutation-taint case.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-mutcrash-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('a bare Object.assign(target, tainted) call does not crash the analyzer and erase an unrelated finding in the same function', async () => {
  const dir = mkTmp('assign', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  cp.exec(req.body.unrelatedCmd);   // unrelated, direct command-injection sink
  const target = {};
  Object.assign(target, req.body);  // bare-statement call — previously crashed step()
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  // Filtered to the deep engine's own findings (parser: 'IR-TAINT') — a
  // plain regex/structural SAST detector would also catch this direct
  // cp.exec(req.body.x) pattern regardless of whether step() crashed, which
  // would mask the bug this test exists to catch.
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected the unrelated cp.exec(req.body.unrelatedCmd) IR-TAINT finding to survive the Object.assign call in the same function, got IR-TAINT findings: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('the same unrelated finding fires when the Object.assign call is removed (control)', async () => {
  const dir = mkTmp('control', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  cp.exec(req.body.unrelatedCmd);
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1, 'control case must fire the same IR-TAINT finding');
});
