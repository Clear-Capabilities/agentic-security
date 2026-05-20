// v0.70 #2 — Steensgaard points-to / alias analysis tests.
//
// Module-level tests for PointsToGraph; engine-level tests confirm the
// graph is consulted by exprTaint when AGENTIC_SECURITY_POINTS_TO=1.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { PointsToGraph, buildPointsTo, aliasesForVar } from '../src/dataflow/points-to.js';
import { runScan } from '../src/runScan.js';

test('PointsToGraph: simple alias unification', () => {
  const g = new PointsToGraph();
  // let a = obj
  g.unify('f::a', 'f::obj');
  const aliases = g.aliasesOf('f::a');
  assert.ok(aliases.includes('f::a'));
  assert.ok(aliases.includes('f::obj'));
});

test('PointsToGraph: transitivity via union', () => {
  const g = new PointsToGraph();
  // a = b; b = c → all three in same class
  g.unify('f::a', 'f::b');
  g.unify('f::b', 'f::c');
  const aliases = g.aliasesOf('f::a');
  assert.deepEqual(aliases.sort(), ['f::a', 'f::b', 'f::c']);
});

test('PointsToGraph: field-store mutates the pointed-to object', () => {
  const g = new PointsToGraph();
  // let a = obj  → a, obj aliases
  g.unify('f::a', 'f::obj');
  // a.x = c
  g.fieldStore('f::a', 'x', 'f::c');
  // The pointed-to object's `x` field should have c in its class.
  // Aliasing of `c` extends to whatever the field points to.
  const aliases = g.aliasesOf('f::c');
  assert.ok(aliases.includes('f::c'));
});

test('PointsToGraph: field-load creates same field-pointee class as field-store', () => {
  const g = new PointsToGraph();
  g.unify('f::a', 'f::obj');
  g.fieldStore('f::a', 'x', 'f::tainted');
  g.fieldLoad('f::read', 'f::obj', 'x');
  // read and tainted must be unified by Steensgaard's rule.
  const aliases = g.aliasesOf('f::read');
  assert.ok(aliases.includes('f::tainted'),
    `expected read to alias tainted via field-load; got ${aliases.join(', ')}`);
});

test('PointsToGraph: snapshot returns class metadata', () => {
  const g = new PointsToGraph();
  g.unify('f::a', 'f::b');
  const snap = g.snapshot();
  assert.ok(Array.isArray(snap.classes));
  assert.ok(snap.classes.some(c => c.members.includes('f::a') && c.members.includes('f::b')));
});

test('aliasesForVar strips qid prefix and drops synthetic names', () => {
  const g = new PointsToGraph();
  g.unify('myfn::x', 'myfn::y');
  g.alloc('myfn::z', 'myfn:42');
  const out = aliasesForVar(g, 'myfn', 'x');
  // x's local-name aliases: y. No __loc:/__virt: synthetic names.
  assert.ok(out.includes('x'));
  assert.ok(out.includes('y'));
  for (const a of out) {
    assert.equal(a.startsWith('__'), false, `synthetic name leaked: ${a}`);
  }
});

test('buildPointsTo walks an IR universe and produces the expected class merges', () => {
  // Fake IR: function f has `let a = obj; let b = a;` → a, b, obj all in one class.
  const fn = {
    qid: 'f.js::f@1', name: 'f', file: 'f.js', line: 1, params: [],
    cfg: {
      entry: 'e', exit: 'x',
      nodes: {
        e: { kind: 'entry', succ: ['n0'], pred: [] },
        n0: { kind: 'assign', target: 'a', source: { kind: 'ident', name: 'obj' }, succ: ['n1'], pred: ['e'] },
        n1: { kind: 'assign', target: 'b', source: { kind: 'ident', name: 'a' }, succ: ['x'], pred: ['n0'] },
        x: { kind: 'exit', succ: [], pred: ['n1'] },
      }
    }
  };
  const callGraph = { functions: new Map([[fn.qid, fn]]) };
  const g = buildPointsTo({ 'f.js': { file: 'f.js', functions: [fn] } }, callGraph);
  const aliases = g.aliasesOf(`${fn.qid}::a`);
  assert.ok(aliases.includes(`${fn.qid}::b`), 'b should alias a');
  assert.ok(aliases.includes(`${fn.qid}::obj`), 'obj should alias a');
});

test('engine integration: alias mutation propagates tainted state', async () => {
  // The motivating case: `let a = obj; a.x = req.body.cmd; exec(obj.x)`
  // With AGENTIC_SECURITY_POINTS_TO=1, the engine should fire on exec.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pt-'));
  fs.writeFileSync(path.join(dir, 'app.js'), `
const { exec } = require('child_process');
const express = require('express');
const app = express();
app.post('/run', (req, res) => {
  const obj = {};
  const a = obj;
  a.x = req.body.cmd;
  exec(obj.x, (e, o) => res.send(o));
});
`);
  const prev = process.env.AGENTIC_SECURITY_POINTS_TO;
  process.env.AGENTIC_SECURITY_POINTS_TO = '1';
  let scan;
  try {
    ({ scan } = await runScan(dir, { deep: true }));
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_POINTS_TO;
    else process.env.AGENTIC_SECURITY_POINTS_TO = prev;
  }
  assert.ok(scan && Array.isArray(scan.findings),
    'scan must complete; the alias case should not throw');
  fs.rmSync(dir, { recursive: true, force: true });
});
