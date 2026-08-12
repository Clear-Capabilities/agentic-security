// v0.68 — proven-clean SQL injection tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { proveSqlClean, annotateProvenClean, _internal } from '../src/dataflow/proven-clean.js';

function _fakeIR(funcs) {
  return {
    'app.js': {
      file: 'app.js',
      functions: funcs,
      topLevel: null,
    }
  };
}

function _fakeFn(name, fromLine, calls) {
  const nodes = { entry: { kind: 'entry', line: fromLine, succ: [], pred: [] } };
  let prev = 'entry';
  calls.forEach((c, i) => {
    const id = `n${i}`;
    nodes[id] = { kind: 'call', line: c.line, callee: c.callee, args: [], succ: [], pred: [prev] };
    nodes[prev].succ.push(id);
    prev = id;
  });
  nodes.exit = { kind: 'exit', line: 9999, succ: [], pred: [prev] };
  nodes[prev].succ.push('exit');
  return { qid: `app.js::${name}@${fromLine}`, name, line: fromLine, file: 'app.js', params: [], cfg: { entry: 'entry', exit: 'exit', nodes } };
}

test('_isSqlParameterizer recognizes catalog + extras', () => {
  assert.equal(_internal._isSqlParameterizer('addWithValue'), true);
  assert.equal(_internal._isSqlParameterizer('cmd.addWithValue'), true);
  assert.equal(_internal._isSqlParameterizer('setString'), true);
  assert.equal(_internal._isSqlParameterizer('bindParam'), true);
  // Things that are clearly NOT parameterizers — string-concat helpers.
  assert.equal(_internal._isSqlParameterizer('concat'), false);
  assert.equal(_internal._isSqlParameterizer('toString'), false);
});

test('proveSqlClean returns proven=true when a setString call sits between source and sink', () => {
  const fn = _fakeFn('find', 1, [
    { line: 3, callee: 'getParameter' },         // source-ish
    { line: 5, callee: 'setString' },            // parameterizer
    { line: 7, callee: 'executeQuery' },         // sink
  ]);
  const finding = {
    parser: 'IR-TAINT',
    sinkId: 'java-stmt-executeQuery',
    file: 'app.js',
    line: 7,
    trace: [{ line: 3, sourceLabel: 'request.getParameter' }],
  };
  const proof = proveSqlClean(finding, _fakeIR([fn]));
  assert.equal(proof.proven, true);
  assert.ok(proof.sanitizers.includes('setString'));
  assert.equal(proof.proofKind, 'path-existence-v1');
});

test('proveSqlClean returns proven=false when no parameterizer is on the path', () => {
  const fn = _fakeFn('find', 1, [
    { line: 3, callee: 'getParameter' },
    { line: 5, callee: 'concat' },                // not a parameterizer
    { line: 7, callee: 'executeQuery' },
  ]);
  const finding = {
    parser: 'IR-TAINT',
    sinkId: 'java-stmt-executeQuery',
    file: 'app.js',
    line: 7,
    trace: [{ line: 3, sourceLabel: 'request.getParameter' }],
  };
  const proof = proveSqlClean(finding, _fakeIR([fn]));
  assert.equal(proof.proven, false);
  assert.equal(proof.reason, 'no-parameterizer-on-path');
});

// Stage 3 correctness audit (detection depth): _allCallNodesBetween used to
// be a pure line-range filter — ANY call node between the source and sink
// lines, regardless of whether it could ever actually execute before the
// sink. This fixture puts a real parameterizer call inside an `if` branch
// that RETURNS before ever reaching the sink — a completely different,
// non-converging path — so it must NOT count as proof for the sink, which
// is only reachable via the OTHER branch.
//
//   entry -> source(2) -> if(3) -+-> setString(4) -> return(5) -> exit
//                                 \-> query(7, SINK) --------------> exit
test('proveSqlClean does not accept a parameterizer from a branch that never reaches the sink', () => {
  const nodes = {
    entry:  { kind: 'entry', line: 1, succ: ['source'], pred: [] },
    source: { kind: 'call', line: 2, callee: 'getParameter', args: [], succ: ['if'], pred: ['entry'] },
    if:     { kind: 'if', line: 3, cond: { kind: 'ident', name: 'someFlag' }, succ: ['setString', 'query'], pred: ['source'] },
    setString: { kind: 'call', line: 4, callee: 'setString', args: [], succ: ['return'], pred: ['if'] },
    return: { kind: 'return', line: 5, value: null, succ: ['exit'], pred: ['setString'] },
    query:  { kind: 'call', line: 7, callee: 'executeQuery', args: [], succ: ['exit'], pred: ['if'] },
    exit:   { kind: 'exit', line: 8, succ: [], pred: ['return', 'query'] },
  };
  const fn = { qid: 'app.js::find@1', name: 'find', line: 1, file: 'app.js', params: [], cfg: { entry: 'entry', exit: 'exit', nodes } };
  const finding = {
    parser: 'IR-TAINT',
    sinkId: 'java-stmt-executeQuery',
    file: 'app.js',
    line: 7,
    trace: [{ line: 2, sourceLabel: 'request.getParameter' }],
  };
  const proof = proveSqlClean(finding, _fakeIR([fn]));
  assert.equal(proof.proven, false,
    `a parameterizer on a branch that returns before the sink must not prove the sink clean, got: ${JSON.stringify(proof)}`);
  assert.equal(proof.reason, 'no-parameterizer-on-path');
});

test('annotateProvenClean tags findings in place', () => {
  const fn = _fakeFn('find', 1, [
    { line: 3, callee: 'getParameter' },
    { line: 5, callee: 'addWithValue' },
    { line: 7, callee: 'executeQuery' },
  ]);
  const findings = [{
    parser: 'IR-TAINT',
    sinkId: 'java-stmt-executeQuery',
    file: 'app.js',
    line: 7,
    trace: [{ line: 3, sourceLabel: 'request.getParameter' }],
  }];
  annotateProvenClean(findings, _fakeIR([fn]));
  assert.equal(findings[0].provenClean, true);
  assert.ok(findings[0].provenanceProof);
});

test('annotateProvenClean skips non-SQL-sink findings without altering them', () => {
  const findings = [{
    parser: 'IR-TAINT',
    sinkId: 'js-innerHTML-assign',  // XSS, not SQL
    file: 'app.js',
    line: 10,
  }];
  annotateProvenClean(findings, _fakeIR([]));
  assert.equal(findings[0].provenClean, undefined);
});

test('annotateProvenClean leaves findings without IR untouched', () => {
  const findings = [{
    parser: 'IR-TAINT',
    sinkId: 'java-stmt-executeQuery',
    file: 'no-such.js',
    line: 5,
  }];
  annotateProvenClean(findings, _fakeIR([]));
  assert.equal(findings[0].provenClean, undefined);
  assert.equal(findings[0].provenanceProofFailedReason, 'no-ir-for-fn');
});
