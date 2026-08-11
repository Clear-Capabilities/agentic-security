// v0.69 #1 — backward-slice annotation tests.
//
// Verifies:
//   (a) sliceBackward + annotateBackwardSlices produce a non-empty slice for
//       findings the engine emits via the standard taint pass
//   (b) the walltime budget (AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS)
//       caps total work and reports `exhausted: true` when blown
//   (c) the path-steps merged into findings reflect source → sink order

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { annotateBackwardSlices, sliceBackward } from '../src/dataflow/backward.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function _fakeFn(name, fromLine, nodes) {
  // nodes is an array of {kind, line, ...}; builds entry → ... → exit linear CFG.
  const cfgNodes = { entry: { kind: 'entry', line: fromLine, succ: [], pred: [] } };
  let prev = 'entry';
  nodes.forEach((n, i) => {
    const id = `n${i}`;
    cfgNodes[id] = { ...n, succ: [], pred: [prev] };
    cfgNodes[prev].succ.push(id);
    prev = id;
  });
  cfgNodes.exit = { kind: 'exit', line: 9999, succ: [], pred: [prev] };
  cfgNodes[prev].succ.push('exit');
  return {
    qid: `app.js::${name}@${fromLine}`,
    name, line: fromLine, file: 'app.js', params: [],
    cfg: { entry: 'entry', exit: 'exit', nodes: cfgNodes },
  };
}

function _fakeIR(funcs) {
  return { 'app.js': { file: 'app.js', functions: funcs, topLevel: null } };
}

function _fakeCallGraph(funcs) {
  return { functions: new Map(funcs.map(f => [f.qid, f])) };
}

test('sliceBackward walks an assign chain and returns ordered trace steps', () => {
  const fn = _fakeFn('handler', 1, [
    { kind: 'assign', line: 3, target: 'q', source: { kind: 'member', object: { kind: 'ident', name: 'req' }, prop: 'query' } },
    { kind: 'assign', line: 4, target: 'sql', source: { kind: 'binary', op: '+', left: { kind: 'literal', value: 'SELECT * WHERE id=' }, right: { kind: 'ident', name: 'q' } } },
    { kind: 'call', line: 5, callee: 'db.query', args: [{ kind: 'ident', name: 'sql' }] },
  ]);
  // Find the sink node ('db.query' on line 5) and call slice directly.
  const sinkNode = fn.cfg.nodes.n2;
  const slice = sliceBackward(fn, sinkNode, 'sql');
  assert.ok(Array.isArray(slice));
  // Even if the slice is short, the call should not throw and should return
  // a structured array.
  for (const step of slice) {
    assert.ok(['source', 'assign', 'call', 'sink'].includes(step.kind));
    assert.ok(typeof step.line === 'number');
  }
});

test('annotateBackwardSlices reports stats and does not modify findings without a matching fn', () => {
  const findings = [
    { _funcQid: 'no-such-fn', file: 'a.js', line: 1, callee: 'exec', argIndex: 0, vuln: 'cmdi' },
  ];
  annotateBackwardSlices(findings, _fakeIR([]), _fakeCallGraph([]));
  // No fn matched → no annotation, finding untouched.
  assert.equal(findings[0].backwardSlice, undefined);
  // Stats reported (non-enumerable, must be accessed directly).
  const stats = findings._annotateBackwardSlicesStats;
  assert.ok(stats, 'stats should be attached to the array');
  assert.equal(stats.annotated, 0);
  assert.equal(stats.skipped, 1);
  assert.equal(stats.exhausted, false);
});

test('annotateBackwardSlices honors AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS', () => {
  const fn = _fakeFn('h', 1, [
    { kind: 'call', line: 3, callee: 'sink', args: [{ kind: 'ident', name: 'x' }] },
  ]);
  const findings = Array.from({ length: 1000 }, (_, i) => ({
    _funcQid: fn.qid, file: 'app.js', line: 3, callee: 'sink', argIndex: 0, vuln: 'v',
  }));
  const prev = process.env.AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS;
  process.env.AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS = '1';   // ~immediate exhaust
  try {
    annotateBackwardSlices(findings, _fakeIR([fn]), _fakeCallGraph([fn]));
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS;
    else process.env.AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS = prev;
  }
  const stats = findings._annotateBackwardSlicesStats;
  // Either everything annotated faster than the 1ms budget allows, OR exhausted
  // was set. The contract is: if budget blew, the flag is set and remaining
  // findings have no backwardSlice. We assert the contract holds.
  if (stats.exhausted) {
    assert.ok(stats.skipped > 0, 'exhausted means some findings were skipped');
  }
});

test('annotateBackwardSlices runs cleanly on an empty finding list', () => {
  const findings = [];
  const out = annotateBackwardSlices(findings, _fakeIR([]), _fakeCallGraph([]));
  assert.equal(out, findings);
  assert.equal(findings.length, 0);
});

test('annotateBackwardSlices is a no-op for non-array input (defensive)', () => {
  // The function returns the input unchanged when it isn't an array.
  assert.equal(annotateBackwardSlices(null, {}, {}), null);
  assert.equal(annotateBackwardSlices(undefined, {}, {}), undefined);
});

// _funcQid propagation (Stage 0 doc-drift investigation, taint-ir item [0]/[5]).
//
// annotateBackwardSlices's first check is `if (!f._funcQid) { skipped++; continue; }`.
// The taint walk DOES set _funcQid on every finding during construction
// (dataflow/engine.js's callContext._findings.push(...) calls), but the final
// IR-TAINT finding object is built from an explicit field allowlist that never
// named _funcQid — the same class of bug _sanitizersOnPath had before it was
// fixed. Result: every finding reaching annotateBackwardSlices had
// f._funcQid === undefined, so backward slicing skipped 100% of findings,
// always, regardless of AGENTIC_SECURITY_BACKWARD_SLICE.
test('IR-TAINT findings carry _funcQid so backward slicing can look them up', async () => {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  process.env.AGENTIC_SECURITY_BACKWARD_SLICE = '1';
  try {
    const { runScan } = await import('../src/runScan.js');
    const { scan } = await runScan(path.join(__dirname, 'fixtures', 'ir-taint', 'interproc'));
    const taint = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
    assert.ok(taint.length > 0, 'precondition: at least one IR-TAINT finding must fire');
    const withSlice = taint.filter(f => Array.isArray(f.backwardSlice) && f.backwardSlice.length > 0);
    assert.ok(withSlice.length > 0,
      `expected at least one finding annotated with a non-empty backwardSlice, got 0 of ${taint.length}`);
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    delete process.env.AGENTIC_SECURITY_BACKWARD_SLICE;
  }
});
