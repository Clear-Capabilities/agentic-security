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

test('R13(b): a destructuring for-of binding still shadows/kills a same-named outer taint (regression — the guard must not suppress destructuring handling)', async () => {
  const dir = mkTmp('loop-destructure-shadow', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  let cmd = req.query.c;
  const SAFE = [{ cmd: 'echo hello' }];
  for (const { cmd } of SAFE) {
    eval(cmd);
  }
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const codeInjFindings = (scan.findings || []).filter(f =>
    /code injection|eval/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.equal(codeInjFindings.length, 0,
    'the destructured cmd shadows the outer tainted cmd — the pre-existing destructuring taint-kill handling must not be suppressed by the ForOfStatement guard');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(b): a block-scoped for-of binding\'s taint does not leak past the loop onto a same-named OUTER variable', async () => {
  // Mirror image of the destructuring regression above. `const item` inside
  // the for-of head is a BLOCK-SCOPED binding — the outer `item` is a
  // different variable that was never assigned anything tainted, so the
  // post-loop eval(item) must be clean. The synthesized loop binding (which
  // replaced the generic VariableDeclarator's taint-KILL for this shape) has
  // to be killed again on the loop's exit edge or it flows straight out of
  // the loop and over-taints the outer name.
  const dir = mkTmp('loop-shadow-leak', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  let item = 'safe';
  for (const item of req.body.items) { console.log(item); }
  eval(item);
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const codeInjFindings = (scan.findings || []).filter(f =>
    /code injection|eval/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.equal(codeInjFindings.length, 0,
    'the outer `item` is a separate block-scoped binding that was never tainted — the for-of loop variable\'s synthesized taint must not survive the loop exit');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(b): the bare-assignment for-of form (`for (x of ...)`) keeps its taint AFTER the loop', async () => {
  // The counterpart guard for the kill added above: `for (x of ...)` with no
  // const/let declares nothing — it assigns to an existing, function-scoped
  // `x` whose value legitimately survives the loop. Killing that on exit
  // would be a real detection regression, so the exit-kill must fire only
  // for the VariableDeclaration (const/let) shape.
  const dir = mkTmp('loop-bare-assign', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/run', (req, res) => {
  let x;
  for (x of req.body.items) { console.log(x); }
  eval(x);
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const codeInjFindings = (scan.findings || []).filter(f =>
    /code injection|eval/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.ok(codeInjFindings.length >= 1,
    '`for (x of tainted)` rebinds a function-scoped x — its taint must still reach a post-loop sink');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R13(a)+(b) composition: a loop-bound value reaches a member-write sink', async () => {
  const dir = mkTmp('compose', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/render', (req, res) => {
  const el = document.getElementById('out');
  for (const item of req.body.items) {
    el.innerHTML = item;
  }
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const xssFindings = (scan.findings || []).filter(f => /xss/i.test(f.vuln || '') && f.parser === 'IR-TAINT');
  assert.ok(xssFindings.length >= 1, 'a loop-bound value flowing into el.innerHTML must be detected — R13(a) and R13(b) must compose');
  fs.rmSync(dir, { recursive: true, force: true });
});
