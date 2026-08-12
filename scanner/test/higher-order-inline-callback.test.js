// Stage 3 correctness audit (detection depth): higher-order taint flow
// (dataflow/CLAUDE.md's P1.3, "arr.map(fn)"/"promise.then(fn)") was
// entirely dead for JS/TS, and — separately — inline callbacks were never
// recognized even in principle. Two independent root causes:
//
//   1. higher-order.js's higherOrderTaintFlow() requires a flattened STRING
//      callee (`typeof callee !== 'string'` guard). engine.js's call site
//      passed the raw CFG node, whose `.callee` for JS/TS is always a
//      structured `{kind:'member',...}` expr (parser-js.js's exprOf never
//      flattens to a string) — never a JS/TS call passed the guard.
//   2. Even with #1 fixed, the callback-recognition gate only accepted
//      `cb.kind === 'ident'` (a by-reference callback, `arr.map(processItem)`)
//      or `cb.kind === 'function-value'` — but parser-js.js's exprOf had no
//      case for ArrowFunctionExpression/FunctionExpression, so an inline
//      callback (`arr.map(x => ...)`, by far the most common real-world
//      shape) always fell through to `{kind:'unknown'}`.
//
// Both fixed: engine.js now flattens the callee before calling
// higherOrderTaintFlow; parser-js.js's CallExpression visitor now converts
// an inline function-literal argument to {kind:'function-value', qid},
// with the qid computed to match exactly what that same node's own
// ArrowFunctionExpression/FunctionExpression visitor will independently
// assign it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-ho-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('an inline arrow callback passed to .forEach() on a tainted array propagates taint into its own parameter', async () => {
  const dir = mkTmp('forEach', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const items = req.body.items;
  items.forEach(x => cp.exec(x));
});
`,
  });
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected cp.exec(x) inside the inline .forEach callback to fire, got IR-TAINT findings: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('an inline arrow callback passed to .map() on a CLEAN array does not fire', async () => {
  const dir = mkTmp('clean', {
    'app.js': `
const cp = require('child_process');
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  const items = ['a', 'b', 'c'];
  const out = items.map(x => cp.exec(x));
  res.json(out);
});
`,
  });
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.equal(cmdFindings.length, 0,
    `a clean literal array must not trigger a finding via the higher-order path, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});
