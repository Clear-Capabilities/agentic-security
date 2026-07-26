// Phase 2 — shared call-site extraction, catalog language scoping, receivers.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { callSitesFromCfg } from '../src/ir/call-sites.js';

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
