// Phase 2 — shared call-site extraction, catalog language scoping, receivers.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { callSitesFromCfg } from '../src/ir/call-sites.js';
import { buildProjectIRAsync } from '../src/ir/index.js';

function cfgOf(nodes) { return { entry: 'entry', exit: 'exit', nodes }; }

test('callSitesFromCfg: collects a statement-position call', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'call', callee: 'exec', args: [{ kind: 'ident', name: 'x' }], line: 3, succ: [], pred: [] },
  }));
  assert.equal(sites.length, 1);
  assert.equal(sites[0].site, 'n1');
  assert.equal(sites[0].callee, 'exec');
  assert.equal(sites[0].line, 3);
  assert.ok(Array.isArray(sites[0].args));
});

test('callSitesFromCfg: collects a call on an assignment right-hand side', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'assign', target: 'v', source: { kind: 'call', callee: 'helper', args: [] }, line: 5, succ: [], pred: [] },
  }));
  assert.deepEqual(sites.map(s => s.callee), ['helper']);
});

test('callSitesFromCfg: collects from return, throw and if', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'return', value: { kind: 'call', callee: 'a', args: [] }, line: 1, succ: [], pred: [] },
    n2: { kind: 'throw',  value: { kind: 'call', callee: 'b', args: [] }, line: 2, succ: [], pred: [] },
    n3: { kind: 'if',     cond:  { kind: 'call', callee: 'c', args: [] }, line: 3, succ: [], pred: [] },
  }));
  assert.deepEqual(sites.map(s => s.callee).sort(), ['a', 'b', 'c']);
});

test('callSitesFromCfg: collects nested calls in arguments', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'call', callee: 'outer', args: [{ kind: 'call', callee: 'inner', args: [] }], line: 1, succ: [], pred: [] },
  }));
  assert.deepEqual(sites.map(s => s.callee).sort(), ['inner', 'outer']);
});

test('callSitesFromCfg: preserves a dotted callee rather than flattening it', () => {
  const sites = callSitesFromCfg(cfgOf({
    n1: { kind: 'call', callee: 'obj.method', args: [], line: 1, succ: [], pred: [] },
  }));
  assert.equal(sites[0].callee, 'obj.method');
});

test('callSitesFromCfg: tolerates malformed input without throwing', () => {
  assert.deepEqual(callSitesFromCfg(null), []);
  assert.deepEqual(callSitesFromCfg({}), []);
  assert.deepEqual(callSitesFromCfg({ nodes: null }), []);
  assert.deepEqual(callSitesFromCfg(cfgOf({ n1: null })), []);
});

const FIXTURES = {
  'a.go':  'package main\nfunc h(x string) string { return x }\nfunc m(r string) { v := h(r); _ = v }\n',
  'a.cs':  'class A { public string H(string x){ return x; } public void M(string r){ var v = H(r); } }',
  'a.kt':  'fun h(x: String): String { return x }\nfun m(r: String) { val v = h(r) }\n',
  'a.php': '<?php function h($x){ return $x; } function m($r){ $v = h($r); }',
};

test('fn.calls: Go, C#, Kotlin and PHP each record their call sites', async () => {
  const { perFile } = await buildProjectIRAsync(FIXTURES);
  for (const file of Object.keys(FIXTURES)) {
    const ir = perFile[file];
    assert.ok(ir, `${file} must produce IR`);
    const caller = ir.functions.find(f => /m$/i.test(f.name));
    assert.ok(caller, `${file} must yield the calling function`);
    assert.ok(Array.isArray(caller.calls) && caller.calls.length >= 1,
      `${file}: caller must record at least one call site, got ${JSON.stringify(caller.calls)}`);
    const c = caller.calls[0];
    assert.ok(c.site && caller.cfg.nodes[c.site], `${file}: site must be a real CFG node id`);
    assert.ok(typeof c.callee === 'string' && c.callee.length, `${file}: callee must be a name`);
    assert.ok(Array.isArray(c.args), `${file}: args must be an array`);
    assert.ok(typeof c.line === 'number', `${file}: line must be set`);
  }
});

test('fn.calls: the callee name resolves to the callee function', async () => {
  const { perFile, callGraph } = await buildProjectIRAsync(FIXTURES);
  for (const file of Object.keys(FIXTURES)) {
    const ir = perFile[file];
    const caller = ir.functions.find(f => /m$/i.test(f.name));
    const callee = ir.functions.find(f => /h$/i.test(f.name));
    const resolved = callGraph.resolveKnownCallee(caller.calls[0].callee, file);
    assert.equal(resolved, callee.qid, `${file}: the recorded callee must resolve to the callee's qid`);
  }
});
