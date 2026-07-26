// Tests for the Phase 1 engine-reconnect work.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR } from '../src/ir/index.js';
import { functionRecord } from '../src/ir/callgraph.js';
import { runTaintEngine } from '../src/dataflow/engine.js';
import { runScan } from '../src/runScan.js';
import * as path from 'node:path';

const FIXTURES = path.resolve('../bench/engine-reconnect/fixtures');

async function scanFixture(rel) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  const { scan } = await runScan(path.join(FIXTURES, rel));
  return [...(scan.findings || []), ...(scan.logicVulns || [])];
}

test('functionRecord: resolves a qid string to its record', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function helper(x){ return x; }\nfunction main(r){ return helper(r.query.q); }\n',
  });
  const helperQid = perFile['a.js'].functions.find(f => f.name === 'helper').qid;
  const rec = functionRecord(callGraph, helperQid);
  assert.ok(rec, 'a qid string must resolve to a record');
  assert.equal(rec.qid, helperQid);
  assert.ok(Array.isArray(rec.params), 'the record must carry params so binding can happen');
});

test('functionRecord: passes a record through unchanged', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function helper(x){ return x; }\n',
  });
  const rec = perFile['a.js'].functions[0];
  assert.equal(functionRecord(callGraph, rec), rec);
});

test('functionRecord: null, unknown qid and bad input yield null, never throw', () => {
  const { callGraph } = buildProjectIR({ 'a.js': 'function f(){}\n' });
  assert.equal(functionRecord(callGraph, null), null);
  assert.equal(functionRecord(callGraph, 'no-such-qid'), null);
  assert.equal(functionRecord(callGraph, 42), null);
  assert.equal(functionRecord(null, 'x'), null);
  assert.equal(functionRecord(undefined, undefined), null);
});

// Blocker A regression (found after the initial functionRecord fix landed):
// parser-js.js always emits a CFG call node's callee as an expression object
// ({kind:'ident',name} or {kind:'member',...}), never a bare string. Several
// engine.js sites derived the name to feed callGraph.resolve() via
// `typeof callee === 'string' ? callee : null`, which is always null for JS
// — so the interprocedural resolve path was never even entered for JS,
// independent of the functionRecord fix. This test calls runTaintEngine
// directly (bypassing runScan) so a regression here is localized to the
// callee-flattening logic in engine.js, not conflated with the full pipeline
// or with Blocker B below.
test('engine: an object-shaped (JS) callee still resolves for interprocedural taint (Blocker A)', () => {
  const code = 'function readInput(req){ return req.query.cmd; }\n'
    + 'function runIt(req){ const cmd = readInput(req); require("child_process").exec(cmd); }\n';
  const { perFile, callGraph } = buildProjectIR({ 'app.js': code });
  const findings = runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 });
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.ok(ir.length >= 1,
    `expected at least one IR-TAINT finding from a bare-name JS call; got ${findings.length}`);
});

// Blocker B regression: exprTaint()'s only source-recognition check was
// `expr.kind === 'member' && exprIsSource(expr)` — a call-shaped source
// (e.g. `getenv("X")`, `request.args.get("x")`) was never recognized when it
// is the VALUE of a return statement, because the 'return' case's exprTaint
// call never reached exprIsSource for a 'call' expr (only the sibling
// 'assign' case did, via a separate `exprIsSource` call). A helper whose
// entire body is `return <source-call>(...)` therefore never had its summary
// marked returnTainted. Isolated here as a direct return-of-call-source case,
// independent of Blocker A (this snippet's callees are still plain idents).
test('engine: a call-shaped source returned from a helper taints the caller (Blocker B)', () => {
  const code = 'function readEnv(){ return getenv("CMD"); }\n'
    + 'function runIt(){ const cmd = readEnv(); require("child_process").exec(cmd); }\n';
  const { perFile, callGraph } = buildProjectIR({ 'app.js': code });
  const findings = runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 });
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.ok(ir.length >= 1,
    `expected at least one IR-TAINT finding from a call-shaped return source; got ${findings.length}`);
});

test('interprocedural: a JS source in one function reaches a sink in another', async () => {
  const findings = await scanFixture('js');
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.ok(ir.length >= 1,
    `expected at least one IR-TAINT finding; got ${findings.length} findings, none from the IR engine`);
});

test('interprocedural: the same holds for Python', async () => {
  const findings = await scanFixture('py');
  assert.ok(findings.filter(f => (f.parser || '') === 'IR-TAINT').length >= 1);
});

test('interprocedural: the same holds for C++', async () => {
  const findings = await scanFixture('cpp');
  assert.ok(findings.filter(f => (f.parser || '') === 'IR-TAINT').length >= 1);
});

// Finding 1 (engine-reconnect review): a member call's flattened name
// (`loader.read()` -> "loader.read") must NOT be handed to
// callGraph.resolve() — resolve()'s generic dotted-name fallback strips it
// to the last segment ("read") and matches ANY same-named function
// project-wide, inventing a call edge that does not exist. Here `read()` is
// a wholly unrelated local function; `loader.read()` should produce no
// interprocedural finding at all (a missing edge, not a wrong one).
test('engine: a member call does not resolve to an unrelated same-named local function', () => {
  const code = 'function read(){ return getenv("CMD"); }\n'
    + 'function f(){ const c = loader.read(); require("child_process").exec(c); }\n';
  const { perFile, callGraph } = buildProjectIR({ 'app.js': code });
  const findings = runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 });
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.equal(ir.length, 0,
    `expected no IR-TAINT finding for an unrelated member call; got ${ir.length}: ${JSON.stringify(ir.map(f => f.vuln))}`);
});
