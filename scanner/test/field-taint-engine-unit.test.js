// Unit-level proof that runTaintEngine's cross-method field-taint pass
// (dataflow/engine.js) works correctly against a hand-built IR + class
// hierarchy — independent of any single language parser actually emitting
// `ir.classes[].fields` yet. test/field-taint-cross-method.test.js is the
// end-to-end proof once a parser does; this file isolates the engine
// mechanism itself so a parser gap can never mask an engine bug or vice versa.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runTaintEngine } from '../src/dataflow/engine.js';
import { buildClassHierarchy } from '../src/ir/class-hierarchy.js';
import { buildCallGraph } from '../src/ir/callgraph.js';

function fn(qid, file, params, nodes, entry = 'n0', exit = 'nX') {
  return { qid, file, name: qid.split('::').pop().split('@')[0], line: 1, params, calls: [], cfg: { entry, exit, nodes } };
}

test('cross-method field taint: static field write in one method reaches a sink in another', () => {
  const perFileIR = {
    'A.cs': {
      classes: [{ name: 'A', bases: [], fields: ['sf'] }],
      functions: [
        fn('A.cs::A::Bad@1', 'A.cs', [], {
          n0: { kind: 'entry', succ: ['n1'] },
          n1: { kind: 'assign', target: 'data', source: { kind: 'call', callee: 'Environment.GetEnvironmentVariable', args: [{ kind: 'literal', value: 'X' }] }, succ: ['n2'] },
          n2: { kind: 'assign', target: 'sf', source: { kind: 'ident', name: 'data' }, succ: ['nX'] },
          nX: { kind: 'exit' },
        }),
        fn('A.cs::A::BadSink@10', 'A.cs', [], {
          n0: { kind: 'entry', succ: ['n1'] },
          n1: { kind: 'assign', target: 'data', source: { kind: 'ident', name: 'sf' }, succ: ['n2'] },
          n2: { kind: 'call', callee: 'Process.Start', args: [{ kind: 'literal', value: 'cmd.exe' }, { kind: 'ident', name: 'data' }], succ: ['nX'] },
          nX: { kind: 'exit' },
        }),
      ],
    },
  };
  const cha = buildClassHierarchy(perFileIR);
  assert.deepEqual([...cha.classes.get('A').fields], ['sf'], 'sanity: CHA must actually pick up the declared field');
  const callGraph = buildCallGraph(perFileIR, {});
  const findings = runTaintEngine(perFileIR, callGraph, { _cha: cha });
  const hits = findings.filter(f => f.file === 'A.cs' && f.line === 10 || (f.cwe === 'CWE-78'));
  assert.ok(findings.some(f => f.parser === 'IR-TAINT' && f.cwe === 'CWE-78'),
    `expected a CWE-78 finding via the static field, got: ${JSON.stringify(findings.map(f => ({ parser: f.parser, cwe: f.cwe, line: f.line })))}`);
});

test('cross-method field taint: a field written only from a literal does not taint its readers', () => {
  const perFileIR = {
    'B.cs': {
      classes: [{ name: 'B', bases: [], fields: ['sf'] }],
      functions: [
        fn('B.cs::B::Good@1', 'B.cs', [], {
          n0: { kind: 'entry', succ: ['n1'] },
          n1: { kind: 'assign', target: 'sf', source: { kind: 'literal', value: 'constant' }, succ: ['nX'] },
          nX: { kind: 'exit' },
        }),
        fn('B.cs::B::GoodSink@10', 'B.cs', [], {
          n0: { kind: 'entry', succ: ['n1'] },
          n1: { kind: 'assign', target: 'data', source: { kind: 'ident', name: 'sf' }, succ: ['n2'] },
          n2: { kind: 'call', callee: 'Process.Start', args: [{ kind: 'literal', value: 'cmd.exe' }, { kind: 'ident', name: 'data' }], succ: ['nX'] },
          nX: { kind: 'exit' },
        }),
      ],
    },
  };
  const cha = buildClassHierarchy(perFileIR);
  const callGraph = buildCallGraph(perFileIR, {});
  const findings = runTaintEngine(perFileIR, callGraph, { _cha: cha });
  assert.equal(findings.filter(f => f.cwe === 'CWE-78').length, 0,
    `a literal-only field write must not taint readers, got: ${JSON.stringify(findings.map(f => ({ parser: f.parser, cwe: f.cwe, line: f.line })))}`);
});

test('cross-method field taint: a same-named field in an UNRELATED class does not cross-contaminate', () => {
  const perFileIR = {
    'C.cs': {
      classes: [
        { name: 'C1', bases: [], fields: ['sf'] },
        { name: 'C2', bases: [], fields: ['sf'] },
      ],
      functions: [
        fn('C.cs::C1::Bad@1', 'C.cs', [], {
          n0: { kind: 'entry', succ: ['n1'] },
          n1: { kind: 'assign', target: 'data', source: { kind: 'call', callee: 'Environment.GetEnvironmentVariable', args: [{ kind: 'literal', value: 'X' }] }, succ: ['n2'] },
          n2: { kind: 'assign', target: 'sf', source: { kind: 'ident', name: 'data' }, succ: ['nX'] },
          nX: { kind: 'exit' },
        }),
        fn('C.cs::C2::GoodSink@10', 'C.cs', [], {
          n0: { kind: 'entry', succ: ['n1'] },
          n1: { kind: 'assign', target: 'data', source: { kind: 'ident', name: 'sf' }, succ: ['n2'] },
          n2: { kind: 'call', callee: 'Process.Start', args: [{ kind: 'literal', value: 'cmd.exe' }, { kind: 'ident', name: 'data' }], succ: ['nX'] },
          nX: { kind: 'exit' },
        }),
      ],
    },
  };
  const cha = buildClassHierarchy(perFileIR);
  const callGraph = buildCallGraph(perFileIR, {});
  const findings = runTaintEngine(perFileIR, callGraph, { _cha: cha });
  assert.equal(findings.filter(f => f.cwe === 'CWE-78').length, 0,
    `C1.sf being tainted must not taint C2.sf, got: ${JSON.stringify(findings.map(f => ({ parser: f.parser, cwe: f.cwe, line: f.line })))}`);
});
