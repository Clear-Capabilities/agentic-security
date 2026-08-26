// FR-403 step 3 (assurance-hardening PRD, D-0047): the standalone privacy
// taint walker. Uses the SAME hand-constructed-fn/callGraph pattern as
// test/annotation-taint-engine.test.js (an established, accepted way to
// test engine consumption of a specific IR shape directly, without a real
// parser in the loop) — proves the walker's OWN logic in isolation.
//
// This file does NOT test wiring into runScan()/AGENTIC_SECURITY_PRIVACY_DEEP
// — that is a separate, real-fixture, real-parser end-to-end test (mirrors
// test/deep-taint.test.js's own established pattern), tracked as separate
// follow-up once the wiring itself lands.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPrivacyTaintEngine, analyzePrivacyFunction, exprPrivacyTaint } from '../src/dataflow/privacy-deep-walker.js';

function callGraphOf(fn) {
  return { functions: new Map([[fn.qid, fn]]), edges: [], callersOf: new Map() };
}

// FR-403 step 3, item (b): a MINIMAL, honest resolveKnownCallee for tests
// that specifically exercise interprocedural resolution/recursion — the
// real one (ir/callgraph.js#buildCallGraph) resolves by more than bare
// name, but this file's own qid convention (`file::name@line`) makes a
// name-segment match a faithful-enough stand-in for what these tests need
// to prove (recursion safety, cache reuse), without claiming to be a full
// re-implementation. Real end-to-end interprocedural coverage against the
// REAL resolver lives in test/privacy-deep-e2e.test.js.
function multiCallGraph(fns) {
  const functions = new Map(fns.map((fn) => [fn.qid, fn]));
  const byName = new Map();
  for (const fn of fns) {
    const name = String(fn.qid).split('::')[1]?.split('@')[0];
    if (name) byName.set(name, fn.qid);
  }
  return {
    functions,
    edges: [],
    callersOf: new Map(),
    resolveKnownCallee(name) {
      return byName.get(name) || null;
    },
  };
}

test('a parameter whose NAME classifies as PII reaches a real privacy sink — the literal step-3 scenario', () => {
  // Simulates: function logUser(ssn) { console.log(ssn); }
  const fn = {
    qid: 'app.js::logUser@1',
    name: 'logUser',
    line: 1,
    params: ['ssn'],
    file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 2, succ: ['n3'], pred: ['n1'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'ssn' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit, `expected a privacy-leak finding, got: ${JSON.stringify(findings)}`);
  assert.equal(hit.family, 'pii-exposure');
  assert.equal(hit.parser, 'IR-PRIVACY-TAINT');
});

test('a non-PII-shaped parameter reaching the same sink does NOT fire (no false positive)', () => {
  const fn = {
    qid: 'app.js::logCount@1',
    name: 'logCount',
    line: 1,
    params: ['count'],
    file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 2, succ: ['n3'], pred: ['n1'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'count' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  assert.equal(findings.find((f) => f.file === 'app.js'), undefined);
});

test('a PII-shaped value flows through a plain reassignment before reaching the sink', () => {
  // Simulates: function h(email) { const x = email; console.log(x); }
  const fn = {
    qid: 'app.js::h@1',
    name: 'h',
    line: 1,
    params: ['email'],
    file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n4',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'x', source: { kind: 'ident', name: 'email' },
        },
        n3: {
          id: 'n3', kind: 'call', line: 3, succ: ['n4'], pred: ['n2'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'x' }],
        },
        n4: { id: 'n4', kind: 'exit', line: 4, succ: [], pred: ['n3'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit, `expected taint to propagate through reassignment, got: ${JSON.stringify(findings)}`);
});

test('a clean reassignment clears privacy taint (recall-preserving-shaped test, but for a TRUE negative)', () => {
  // Simulates: function h(email) { let x = email; x = "redacted"; console.log(x); }
  const fn = {
    qid: 'app.js::h2@1',
    name: 'h2',
    line: 1,
    params: ['email'],
    file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n5',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'x', source: { kind: 'ident', name: 'email' },
        },
        n3: {
          id: 'n3', kind: 'assign', line: 3, succ: ['n4'], pred: ['n2'],
          target: 'x', source: { kind: 'literal', value: 'redacted' },
        },
        n4: {
          id: 'n4', kind: 'call', line: 4, succ: ['n5'], pred: ['n3'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'x' }],
        },
        n5: { id: 'n5', kind: 'exit', line: 5, succ: [], pred: ['n4'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  assert.equal(findings.find((f) => f.file === 'app.js'), undefined,
    'a clean literal reassignment must clear privacy taint from x');
});

test('a DECLARATION whose name is PII-shaped is itself a source, independent of what value it holds', () => {
  // Simulates: function h() { const medicalRecordNumber = computeSomething(); console.log(medicalRecordNumber); }
  const fn = {
    qid: 'app.js::h3@1',
    name: 'h3',
    line: 1,
    params: [],
    file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n4',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'medicalRecordNumber', source: { kind: 'call', callee: 'computeSomething', args: [] },
        },
        n3: {
          id: 'n3', kind: 'call', line: 3, succ: ['n4'], pred: ['n2'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'medicalRecordNumber' }],
        },
        n4: { id: 'n4', kind: 'exit', line: 4, succ: [], pred: ['n3'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit, `expected the declaration-name-classified source to reach the sink, got: ${JSON.stringify(findings)}`);
});

test('runPrivacyTaintEngine: a malformed callGraph degrades to an empty array, never throws', () => {
  assert.deepEqual(runPrivacyTaintEngine(null), []);
  assert.deepEqual(runPrivacyTaintEngine({}), []);
  assert.deepEqual(runPrivacyTaintEngine({ functions: new Map() }), []);
});

test('runPrivacyTaintEngine: one function throwing during analysis does not prevent another function\'s findings', () => {
  const bad = {
    qid: 'app.js::bad@1', name: 'bad', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n2',
      // node.succ is a non-iterable number, not an array -- `for (const s of
      // (node.succ || []))` throws a real TypeError here (5 is truthy, so
      // the `|| []` fallback never kicks in), a genuine per-function crash
      // this test proves does not take down the whole privacy-deep pass.
      nodes: { n1: { id: 'n1', kind: 'entry', line: 1, succ: 5, pred: [] } },
    },
  };
  const good = {
    qid: 'app.js::good@1', name: 'good', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 2, succ: ['n3'], pred: ['n1'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'ssn' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const callGraph = { functions: new Map([[bad.qid, bad], [good.qid, good]]), edges: [], callersOf: new Map() };
  const findings = runPrivacyTaintEngine(callGraph);
  assert.ok(findings.some((f) => f.line === 2), `expected good() to still be analyzed, got: ${JSON.stringify(findings)}`);
});

test('exprPrivacyTaint: exported directly for reuse/testing, handles all documented expression kinds without throwing', () => {
  const state = new Set(['ssn']);
  assert.equal(exprPrivacyTaint({ kind: 'ident', name: 'ssn' }, state), true);
  assert.equal(exprPrivacyTaint({ kind: 'ident', name: 'other' }, state), false);
  assert.equal(exprPrivacyTaint({ kind: 'literal', value: 1 }, state), false);
  assert.equal(exprPrivacyTaint({ kind: 'binary', left: { kind: 'ident', name: 'ssn' }, right: { kind: 'literal' } }, state), true);
  assert.equal(exprPrivacyTaint({ kind: 'tpl', parts: [{ kind: 'ident', name: 'ssn' }] }, state), true);
  assert.equal(exprPrivacyTaint({ kind: 'array', elements: [{ kind: 'ident', name: 'ssn' }] }, state), true);
  assert.equal(exprPrivacyTaint({ kind: 'object', props: [{ key: 'a', value: { kind: 'ident', name: 'ssn' } }] }, state), true);
  assert.equal(exprPrivacyTaint(null, state), false);
  assert.doesNotThrow(() => exprPrivacyTaint({ kind: 'unknown-shape' }, state));
});

test('analyzePrivacyFunction: a malformed fn (no cfg) degrades to an empty array, never throws', () => {
  assert.deepEqual(analyzePrivacyFunction(null), []);
  assert.deepEqual(analyzePrivacyFunction({}), []);
  assert.deepEqual(analyzePrivacyFunction({ file: 'a.js' }), []);
});

// FR-403 step 3, item (d): safe-transformation recognition. Recall-
// preserving per dataflow/CLAUDE.md's own documented philosophy — a
// transform DEMOTES confidence, it never suppresses the finding.

test('a value hashed via a named transform callee before the sink still fires, but at demoted confidence with _privacyTransformsOnPath recorded', () => {
  // Simulates: function h(ssn) { const hashed = crypto.createHash(ssn); console.log(hashed); }
  const fn = {
    qid: 'app.js::h4@1', name: 'h4', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n4',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'hashed',
          source: { kind: 'call', callee: { kind: 'member', prop: 'createHash', object: { kind: 'ident', name: 'crypto' } }, args: [{ kind: 'ident', name: 'ssn' }] },
        },
        n3: {
          id: 'n3', kind: 'call', line: 3, succ: ['n4'], pred: ['n2'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'hashed' }],
        },
        n4: { id: 'n4', kind: 'exit', line: 4, succ: [], pred: ['n3'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit, `expected the finding to still fire (recall-preserving), got: ${JSON.stringify(findings)}`);
  assert.ok(hit.confidence < 0.6, `expected demoted confidence, got ${hit.confidence}`);
  assert.equal(hit.confidenceTier, 'low');
  assert.ok(Array.isArray(hit._privacyTransformsOnPath) && hit._privacyTransformsOnPath.length > 0,
    `expected _privacyTransformsOnPath to be recorded, got: ${JSON.stringify(hit)}`);
});

test('a value with NO transform applied fires at the normal, non-demoted confidence', () => {
  const fn = {
    qid: 'app.js::h5@1', name: 'h5', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 2, succ: ['n3'], pred: ['n1'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'ssn' }],
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit);
  assert.equal(hit.confidence, 0.6);
  assert.equal(hit.confidenceTier, 'medium');
  assert.equal(hit._privacyTransformsOnPath, undefined);
});

// FR-403 step 3, item (a): simple same-function aliasing.

test('a member WRITE through an alias reaches a later sink read through the ORIGINAL name', () => {
  // Simulates: function h(ssn) {
  //   const record = {};        // "record" is NOT PII-shaped by name
  //   const a = record;         // a aliases record
  //   a.value = ssn;            // write through the ALIAS
  //   console.log(record.value); // read through the ORIGINAL name
  // }
  // "ssn" is the real, PII-shaped SOURCE here (a param, tainted at entry) --
  // "record" is deliberately a neutral name so its own declaration does NOT
  // independently taint the whole object (which would make this test pass
  // for the wrong reason). Only alias-aware member-write propagation can
  // connect the write (via `a`) to the read (via `record`).
  const fn = {
    qid: 'app.js::h7@1', name: 'h7', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n5',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'record', source: { kind: 'object', props: [] },
        },
        n3: {
          id: 'n3', kind: 'assign', line: 3, succ: ['n4'], pred: ['n2'],
          target: 'a', source: { kind: 'ident', name: 'record' },
        },
        n4: {
          id: 'n4', kind: 'assign', line: 4, succ: ['n5'], pred: ['n3'],
          target: 'a.value', source: { kind: 'ident', name: 'ssn' },
        },
        n5: {
          id: 'n5', kind: 'call', line: 5, succ: ['n6'], pred: ['n4'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'member', object: { kind: 'ident', name: 'record' }, prop: 'value' }],
        },
        n6: { id: 'n6', kind: 'exit', line: 6, succ: [], pred: ['n5'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit, `expected the alias-connected write to reach the sink under the original name, got: ${JSON.stringify(findings)}`);
});

test('a sink READ through an alias sees a member write made under the ORIGINAL name', () => {
  // Same shape, reversed direction: write via the ORIGINAL name ("record"),
  // read via the alias ("a").
  const fn = {
    qid: 'app.js::h8@1', name: 'h8', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n5',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'record', source: { kind: 'object', props: [] },
        },
        n3: {
          id: 'n3', kind: 'assign', line: 3, succ: ['n4'], pred: ['n2'],
          target: 'a', source: { kind: 'ident', name: 'record' },
        },
        n4: {
          id: 'n4', kind: 'assign', line: 4, succ: ['n5'], pred: ['n3'],
          target: 'record.value', source: { kind: 'ident', name: 'ssn' },
        },
        n5: {
          id: 'n5', kind: 'call', line: 5, succ: ['n6'], pred: ['n4'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'member', object: { kind: 'ident', name: 'a' }, prop: 'value' }],
        },
        n6: { id: 'n6', kind: 'exit', line: 6, succ: [], pred: ['n5'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit, `expected reading via the alias to see the write made under the original name, got: ${JSON.stringify(findings)}`);
});

test('reassigning the alias variable to something unrelated ends the alias relationship (no false positive)', () => {
  // function h(ssn, other) {
  //   const record = {};
  //   let a = record;
  //   a = other;         // `a` no longer aliases `record`
  //   a.value = ssn;
  //   console.log(record.value);  // must NOT fire -- `a` moved on
  // }
  const fn = {
    qid: 'app.js::h9@1', name: 'h9', line: 1, params: ['ssn', 'other'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n6',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'record', source: { kind: 'object', props: [] },
        },
        n3: {
          id: 'n3', kind: 'assign', line: 3, succ: ['n4'], pred: ['n2'],
          target: 'a', source: { kind: 'ident', name: 'record' },
        },
        n4: {
          id: 'n4', kind: 'assign', line: 4, succ: ['n5'], pred: ['n3'],
          target: 'a', source: { kind: 'ident', name: 'other' },
        },
        n5: {
          id: 'n5', kind: 'assign', line: 5, succ: ['n6'], pred: ['n4'],
          target: 'a.value', source: { kind: 'ident', name: 'ssn' },
        },
        n6: {
          id: 'n6', kind: 'call', line: 6, succ: ['n7'], pred: ['n5'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'member', object: { kind: 'ident', name: 'record' }, prop: 'value' }],
        },
        n7: { id: 'n7', kind: 'exit', line: 7, succ: [], pred: ['n6'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.equal(hit, undefined, `reassigning "a" away from "record" must end the alias -- got: ${JSON.stringify(findings)}`);
});

test('a re-assignment from a NON-transform source clears an earlier transform credit for the same variable name', () => {
  // Simulates: function h(ssn) { let x = crypto.createHash(ssn); x = ssn; console.log(x); }
  // -- x was hashed once, then overwritten with the RAW value again; the
  // transform credit must not survive the reassignment (that would be a
  // false confidence-demotion on a genuinely raw leak).
  const fn = {
    qid: 'app.js::h6@1', name: 'h6', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n5',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'x',
          source: { kind: 'call', callee: { kind: 'member', prop: 'createHash', object: { kind: 'ident', name: 'crypto' } }, args: [{ kind: 'ident', name: 'ssn' }] },
        },
        n3: {
          id: 'n3', kind: 'assign', line: 3, succ: ['n4'], pred: ['n2'],
          target: 'x', source: { kind: 'ident', name: 'ssn' },
        },
        n4: {
          id: 'n4', kind: 'call', line: 4, succ: ['n5'], pred: ['n3'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'ident', name: 'x' }],
        },
        n5: { id: 'n5', kind: 'exit', line: 5, succ: [], pred: ['n4'] },
      },
    },
  };
  const findings = runPrivacyTaintEngine(callGraphOf(fn));
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit);
  assert.equal(hit.confidence, 0.6, 'the transform credit from the FIRST assignment must not survive the second, non-transform reassignment');
  assert.equal(hit._privacyTransformsOnPath, undefined);
});

// FR-403 step 3, item (b): interprocedural flow. `getSSN`'s own body
// classifies a LOCAL declaration as PII independent of what its caller
// passed in -- isolating interprocedural resolution from the pre-existing
// "this call's own arguments are tainted" check.

function makeGetSSN() {
  return {
    qid: 'app.js::getSSN@1', name: 'getSSN', line: 1, params: ['rawInput'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'ssn', source: { kind: 'ident', name: 'rawInput' },
        },
        n3: { id: 'n3', kind: 'return', line: 3, succ: ['n4'], pred: ['n2'], value: { kind: 'ident', name: 'ssn' } },
        n4: { id: 'n4', kind: 'exit', line: 4, succ: [], pred: ['n3'] },
      },
    },
  };
}

function makeGetCount() {
  return {
    qid: 'app.js::getCount@1', name: 'getCount', line: 1, params: ['rawInput'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'assign', line: 2, succ: ['n3'], pred: ['n1'],
          target: 'count', source: { kind: 'ident', name: 'rawInput' },
        },
        n3: { id: 'n3', kind: 'return', line: 3, succ: ['n4'], pred: ['n2'], value: { kind: 'ident', name: 'count' } },
        n4: { id: 'n4', kind: 'exit', line: 4, succ: [], pred: ['n3'] },
      },
    },
  };
}

test('a privacy-tainted value produced INSIDE a called helper reaches the sink through the callGraph, even though the call-site argument is not itself PII-shaped', () => {
  const getSSN = makeGetSSN();
  const caller = {
    qid: 'app.js::logViaHelper@1', name: 'logViaHelper', line: 1, params: ['count'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 2, succ: ['n3'], pred: ['n1'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'call', callee: { kind: 'ident', name: 'getSSN' }, args: [{ kind: 'ident', name: 'count' }] }],
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const callGraph = multiCallGraph([getSSN, caller]);
  const findings = runPrivacyTaintEngine(callGraph);
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.ok(hit, `expected getSSN's internal PII to reach the sink via interprocedural resolution, got: ${JSON.stringify(findings)}`);
});

test('a genuinely clean helper (no PII anywhere in its own body) does NOT fire, even called with the same shape (no false positive from interprocedural resolution)', () => {
  const getCount = makeGetCount();
  const caller = {
    qid: 'app.js::logCleanViaHelper@1', name: 'logCleanViaHelper', line: 1, params: ['other'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 2, succ: ['n3'], pred: ['n1'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'call', callee: { kind: 'ident', name: 'getCount' }, args: [{ kind: 'ident', name: 'other' }] }],
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const callGraph = multiCallGraph([getCount, caller]);
  const findings = runPrivacyTaintEngine(callGraph);
  const hit = findings.find((f) => f.file === 'app.js' && f.cwe === 'CWE-359');
  assert.equal(hit, undefined, `expected no finding for a genuinely clean helper, got: ${JSON.stringify(findings)}`);
});

test('a self-recursive function does not crash or hang -- the recursion guard bottoms out safely', () => {
  // function recurse(ssn) { return recurse(ssn); }  -- pathological, but a
  // realistic shape a helper could accidentally take (or a mutual-recursion
  // cycle collapsed to its simplest single-function case).
  const recurse = {
    qid: 'app.js::recurse@1', name: 'recurse', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n2',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'return', line: 2, succ: ['n3'], pred: ['n1'],
          value: { kind: 'call', callee: { kind: 'ident', name: 'recurse' }, args: [{ kind: 'ident', name: 'ssn' }] },
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const caller = {
    qid: 'app.js::useRecurse@1', name: 'useRecurse', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n3',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'call', line: 2, succ: ['n3'], pred: ['n1'],
          callee: { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } },
          args: [{ kind: 'call', callee: { kind: 'ident', name: 'recurse' }, args: [{ kind: 'ident', name: 'ssn' }] }],
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const callGraph = multiCallGraph([recurse, caller]);
  assert.doesNotThrow(() => runPrivacyTaintEngine(callGraph));
  // The call's own argument (ssn) IS PII-shaped, so this fires via the
  // pre-existing "call args are tainted" path regardless of how the
  // recursion guard resolved the nested return -- the point of this test
  // is that analysis TERMINATES, not a specific verdict on the recursive
  // call's own return-taint.
  const findings = runPrivacyTaintEngine(callGraph);
  assert.ok(Array.isArray(findings));
});

test('mutually recursive functions do not crash or hang', () => {
  // function ping(ssn) { return pong(ssn); }
  // function pong(ssn) { return ping(ssn); }
  const ping = {
    qid: 'app.js::ping@1', name: 'ping', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n2',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'return', line: 2, succ: ['n3'], pred: ['n1'],
          value: { kind: 'call', callee: { kind: 'ident', name: 'pong' }, args: [{ kind: 'ident', name: 'ssn' }] },
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const pong = {
    qid: 'app.js::pong@1', name: 'pong', line: 1, params: ['ssn'], file: 'app.js',
    cfg: {
      entry: 'n1', exit: 'n2',
      nodes: {
        n1: { id: 'n1', kind: 'entry', line: 1, succ: ['n2'], pred: [] },
        n2: {
          id: 'n2', kind: 'return', line: 2, succ: ['n3'], pred: ['n1'],
          value: { kind: 'call', callee: { kind: 'ident', name: 'ping' }, args: [{ kind: 'ident', name: 'ssn' }] },
        },
        n3: { id: 'n3', kind: 'exit', line: 3, succ: [], pred: ['n2'] },
      },
    },
  };
  const callGraph = multiCallGraph([ping, pong]);
  assert.doesNotThrow(() => runPrivacyTaintEngine(callGraph));
});
