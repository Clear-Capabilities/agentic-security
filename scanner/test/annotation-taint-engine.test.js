// PRD R14(a) (docs/DETECTION_GAP_REMEDIATION_PRD.md, Theme E): annotation/
// decorator-shaped framework sources. Task 1 added `matchAnnotationParams` to
// catalog.js; this task wires it into engine.js so a function whose IR
// carries a `paramAnnotations` field has those parameters treated as tainted
// at entry — at every site in the engine that starts analyzing a function,
// not just the ones a caller happens to exercise.
//
// This test hand-constructs a Java-shaped IR fixture directly (no real
// java-parser involved — Tasks 3-5 give real parsers the ability to populate
// paramAnnotations). It proves engine.js's CONSUMPTION of the field.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runTaintEngine } from '../src/dataflow/engine.js';

test('R14(a): a paramAnnotations-tainted parameter reaches a sink even with no caller-supplied taint', () => {
  // Simulates: public String show(@RequestParam String q) { Statement.execute(q); }
  // No in-repo caller passes tainted data — this is exactly the shape of a
  // Spring controller method invoked by the framework via reflection, which
  // the empty-entry base pass (engine.js's main analysis loop) must catch.
  const fn = {
    qid: 'UserController.java::UserController::show@3',
    name: 'UserController.show',
    line: 3,
    params: ['q'],
    paramAnnotations: [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    file: 'UserController.java',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 3, succ: ['n3'], pred: ['n1'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'q' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 4, succ: [], pred: ['n2'] },
      },
    },
  };
  const perFileIR = { 'UserController.java': { file: 'UserController.java', functions: [fn], topLevel: null } };
  const callGraph = { functions: new Map([[fn.qid, fn]]), edges: [], callersOf: new Map() };
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hit = findings.find(f => f.file === 'UserController.java' && /command injection|sql injection/i.test(f.vuln || ''));
  assert.ok(hit, `expected an annotation-sourced finding, got: ${JSON.stringify(findings.map(f => f.vuln))}`);
});

test('R14(a): a function with no paramAnnotations is unaffected (no false positive)', () => {
  const fn = {
    qid: 'Helper.java::Helper::show@3',
    name: 'Helper.show',
    line: 3,
    params: ['q'],
    // no paramAnnotations field at all
    file: 'Helper.java',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 3, succ: ['n3'], pred: ['n1'],
          callee: 'executeQuery',
          args: [{ kind: 'ident', name: 'q' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 4, succ: [], pred: ['n2'] },
      },
    },
  };
  const perFileIR = { 'Helper.java': { file: 'Helper.java', functions: [fn], topLevel: null } };
  const callGraph = { functions: new Map([[fn.qid, fn]]), edges: [], callersOf: new Map() };
  const findings = runTaintEngine(perFileIR, callGraph, {});
  const hit = findings.find(f => f.file === 'Helper.java');
  assert.equal(hit, undefined, 'q is an untainted local parameter with no annotation and no caller-supplied taint — must not fire');
});
