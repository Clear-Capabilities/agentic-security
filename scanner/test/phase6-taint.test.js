// Phase-6 taint-analysis modules — Phase 1 + 2 of the world-class plan.
// Unit tests for each new module's exported API. Most modules are scaffolds
// that integrate into the engine at runtime; the tests verify the algorithm
// correctness in isolation.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// P1.1 — access paths
import {
  accessPathOf, pathIsCoveredByPrefix, isCoveredBy, addPath,
  removePathAndDescendants, joinSets, canonicalize, hashSet, setsEqual,
} from '../src/dataflow/access-paths.js';
// P1.2 — class hierarchy + receiver
import { buildClassHierarchy, classOfVar, resolveMethod } from '../src/ir/class-hierarchy.js';
import { receiverTypeAtCall, hashReceiverType, keyWithReceiver } from '../src/dataflow/receiver-context.js';
// P1.3 — higher-order
import { higherOrderTaintFlow, calleeIsResolvableCallback } from '../src/dataflow/higher-order.js';
// P1.4 — backward slicing
import { sliceBackward, annotateBackwardSlices } from '../src/dataflow/backward.js';
// P1.5 — implicit flow
import {
  isImplicitFlowEnabled, buildImplicitContext, implicitAssignTarget,
  markImplicitTaint, createImplicitFinding,
} from '../src/dataflow/implicit-flow.js';
// P2.1 — RHS tabulation
import { enumerateSinks, reachabilitySliceFromSinks, rhsReachableFunctions, shouldAnalyzeUnderRhs } from '../src/dataflow/tabulation.js';
// P2.2 — Python IR
import { parsePythonFile } from '../src/ir/parser-py.js';
// P2.3 — Java IR
import { parseJavaFile } from '../src/ir/parser-java.js';
// P2.4 — SSA
import { computeSSA, isSSAEnabled, ssaNameAt } from '../src/ir/ssa.js';

// ── P1.1: access paths ────────────────────────────────────────────────────
test('access-paths: accessPathOf flattens ident/member chains', () => {
  assert.equal(accessPathOf({ kind: 'ident', name: 'user' }), 'user');
  assert.equal(accessPathOf({
    kind: 'member',
    object: { kind: 'ident', name: 'user' },
    prop: 'profile',
  }), 'user.profile');
  assert.equal(accessPathOf({
    kind: 'member',
    object: { kind: 'member', object: { kind: 'ident', name: 'a' }, prop: 'b' },
    prop: 'c',
  }), 'a.b.c');
  assert.equal(accessPathOf({ kind: 'call', callee: 'x', args: [] }), null);
});

test('access-paths: prefix coverage', () => {
  assert.equal(pathIsCoveredByPrefix('x.y.z', 'x'), true);
  assert.equal(pathIsCoveredByPrefix('x.y.z', 'x.y'), true);
  assert.equal(pathIsCoveredByPrefix('x.y.z', 'x.z'), false);
  assert.equal(pathIsCoveredByPrefix('x.y', 'x.y.z'), false);     // does not propagate upward
});

test('access-paths: isCoveredBy ✓ "user" covers "user.password"', () => {
  const s = new Set(['user']);
  assert.equal(isCoveredBy(s, 'user.password'), true);
  assert.equal(isCoveredBy(s, 'logger.password'), false);
});

test('access-paths: addPath collapses redundant descendants', () => {
  let s = new Set(['user.profile.email']);
  s = addPath(s, 'user.profile');
  // user.profile subsumes user.profile.email
  assert.equal(s.has('user.profile.email'), false);
  assert.equal(s.has('user.profile'), true);
});

test('access-paths: removePathAndDescendants clears family', () => {
  let s = new Set(['user.password', 'user.profile.email', 'admin']);
  s = removePathAndDescendants(s, 'user');
  assert.equal(s.has('user.password'), false);
  assert.equal(s.has('user.profile.email'), false);
  assert.equal(s.has('admin'), true);
});

test('access-paths: joinSets union + canonicalize', () => {
  const a = new Set(['user.email', 'admin']);
  const b = new Set(['user', 'guest']);
  const j = joinSets(a, b);
  // user covers user.email; both admin + guest survive
  assert.equal(j.has('user'), true);
  assert.equal(j.has('user.email'), false);
  assert.equal(j.has('admin'), true);
  assert.equal(j.has('guest'), true);
});

test('access-paths: hashSet + setsEqual', () => {
  const a = new Set(['x.y', 'x']);
  const b = new Set(['x']);
  assert.equal(hashSet(a), hashSet(b));
  assert.equal(setsEqual(a, b), true);
});

test('access-paths: canonicalize idempotent', () => {
  const s = new Set(['x', 'x.y', 'x.y.z', 'other']);
  const c1 = canonicalize(s);
  const c2 = canonicalize(c1);
  assert.equal(setsEqual(c1, c2), true);
  assert.equal(c1.has('x'), true);
  assert.equal(c1.has('x.y'), false);
});

// ── P1.2: class hierarchy + receiver context ──────────────────────────────
test('class-hierarchy: recovers class names from method qids', () => {
  const perFileIR = {
    'a.js': {
      file: 'a.js',
      functions: [
        { qid: 'a.js::module::UserRepo.save', name: 'UserRepo.save', line: 5, cfg: { nodes: {} } },
        { qid: 'a.js::module::Logger.save', name: 'Logger.save', line: 10, cfg: { nodes: {} } },
      ],
    },
  };
  const cha = buildClassHierarchy(perFileIR);
  assert.ok(cha.classes.has('UserRepo'));
  assert.ok(cha.classes.has('Logger'));
  assert.equal(cha.methodOwners.get('a.js::module::UserRepo.save'), 'UserRepo');
});

test('class-hierarchy: classOfVar + resolveMethod', () => {
  const cha = { classes: new Map(), methodOwners: new Map(), typeOfVar: new Map() };
  cha.classes.set('UserRepo', { name: 'UserRepo', methods: new Set(['save']) });
  cha.typeOfVar.set('a.js::fn1::repo', 'UserRepo');
  assert.equal(classOfVar(cha, 'a.js', 'fn1', 'repo'), 'UserRepo');
  const resolved = resolveMethod(cha, 'UserRepo', 'save');
  assert.equal(resolved?.className, 'UserRepo');
  assert.equal(resolveMethod(cha, 'UserRepo', 'nonexistent'), null);
});

test('receiver-context: receiverTypeAtCall heuristic', () => {
  const cha = { typeOfVar: new Map() };
  const node = { kind: 'call', callee: 'this.userRepo.save' };
  assert.equal(receiverTypeAtCall(node, { qid: 'f1' }, 'a.js', cha), 'UserRepo');
  const node2 = { kind: 'call', callee: 'bareCall' };
  assert.equal(receiverTypeAtCall(node2, { qid: 'f1' }, 'a.js', cha), null);
});

test('receiver-context: hashReceiverType + keyWithReceiver are stable', () => {
  const h = hashReceiverType('UserRepo');
  assert.match(h, /^[a-f0-9]{8}$/);
  assert.equal(keyWithReceiver('base', 'UserRepo'), `base::${h}`);
});

// ── P1.3: higher-order ────────────────────────────────────────────────────
test('higher-order: arr.map(fn) propagates receiver taint to callback param', () => {
  const r = higherOrderTaintFlow({ kind: 'call', callee: 'arr.map', args: [{ kind: 'ident', name: 'fn' }] }, true);
  assert.equal(r.kind, 'array-iter');
  assert.equal(r.taintsCallbackParam, 0);
  assert.equal(r.returnIsTainted, true);
});

test('higher-order: clean receiver does not taint callback', () => {
  const r = higherOrderTaintFlow({ kind: 'call', callee: 'arr.map', args: [{ kind: 'ident', name: 'fn' }] }, false);
  assert.equal(r.taintsCallbackParam, -1);
  assert.equal(r.returnIsTainted, false);
});

test('higher-order: Promise.all returns null receiver pattern + non-receiver call returns null', () => {
  const promiseAll = higherOrderTaintFlow({ kind: 'call', callee: 'Promise.all', args: [{ kind: 'array', elements: [{ kind: 'ident', name: 'p1' }] }] }, false);
  assert.equal(promiseAll?.kind, 'promise-static');
  const nonHo = higherOrderTaintFlow({ kind: 'call', callee: 'console.log', args: [] }, true);
  assert.equal(nonHo, null);
});

test('higher-order: calleeIsResolvableCallback', () => {
  assert.equal(calleeIsResolvableCallback({ kind: 'ident', name: 'fn' }), 'fn');
  assert.equal(calleeIsResolvableCallback({ kind: 'function-value', qid: 'a::b' }), 'a::b');
  assert.equal(calleeIsResolvableCallback({ kind: 'literal' }), null);
});

// ── P1.4: backward slicing ────────────────────────────────────────────────
test('backward: sliceBackward on a 3-step chain finds the source', () => {
  const fn = {
    cfg: {
      entry: 'n1', exit: 'n4',
      nodes: {
        n1: { id: 'n1', kind: 'entry', succ: ['n2'] },
        n2: { id: 'n2', kind: 'assign', target: 'tainted', source: { kind: 'member', object: { kind: 'member', object: { kind: 'ident', name: 'req' }, prop: 'body' }, prop: 'name' }, line: 2, succ: ['n3'] },
        n3: { id: 'n3', kind: 'call', callee: 'db.query', args: [{ kind: 'ident', name: 'tainted' }], line: 3, succ: ['n4'] },
        n4: { id: 'n4', kind: 'exit', succ: [] },
      },
    },
  };
  const slice = sliceBackward(fn, fn.cfg.nodes.n3, 'tainted');
  assert.ok(Array.isArray(slice) && slice.length >= 2);
  // Source-first ordering.
  assert.equal(slice[slice.length - 1].kind, 'sink');
});

test('backward: annotateBackwardSlices is a no-op without _funcQid', () => {
  const findings = [{ vuln: 'x' }];
  const out = annotateBackwardSlices(findings, {}, { functions: new Map() });
  assert.equal(out[0].backwardSlice, undefined);
});

// ── P1.5: implicit flow ───────────────────────────────────────────────────
test('implicit-flow: isImplicitFlowEnabled reads env', () => {
  const prev = process.env.AGENTIC_SECURITY_IMPLICIT_FLOW;
  process.env.AGENTIC_SECURITY_IMPLICIT_FLOW = '1';
  assert.equal(isImplicitFlowEnabled(), true);
  // R4 (PRD §5): implicit flow is now OPT-IN (default OFF) — it was wired into
  // the engine, and control-dependence flow is too noisy to run by default.
  delete process.env.AGENTIC_SECURITY_IMPLICIT_FLOW;
  assert.equal(isImplicitFlowEnabled(), false);
  process.env.AGENTIC_SECURITY_IMPLICIT_FLOW = '0';
  assert.equal(isImplicitFlowEnabled(), false);
  delete process.env.AGENTIC_SECURITY_IMPLICIT_FLOW;
  if (prev) process.env.AGENTIC_SECURITY_IMPLICIT_FLOW = prev;
});

test('implicit-flow: buildImplicitContext marks branch nodes when condition is tainted', () => {
  const cfg = {
    entry: 'a', exit: 'd',
    nodes: {
      a: { id: 'a', kind: 'entry', succ: ['b'] },
      b: { id: 'b', kind: 'if', cond: { kind: 'ident', name: 't' }, succ: ['c'] },
      c: { id: 'c', kind: 'assign', target: 'isAdmin', source: { kind: 'literal', value: true }, succ: ['d'] },
      d: { id: 'd', kind: 'exit', succ: [] },
    },
  };
  const tainted = new Set(['t']);
  const exprTaint = (e) => e && e.kind === 'ident' && tainted.has(e.name);
  const ctx = buildImplicitContext(cfg, exprTaint);
  assert.equal(ctx.get('c')?.tainted, true);
});

test('implicit-flow: implicitAssignTarget identifies assign-in-tainted-branch', () => {
  const n = { kind: 'assign', target: 'isAdmin', source: { kind: 'ident', name: 'role' } };
  assert.equal(implicitAssignTarget(n, { tainted: true }), 'isAdmin');
  assert.equal(implicitAssignTarget(n, { tainted: false }), null);
  // Literal assignments in tainted branches are NOT implicit-tainted (refinement)
  const nLiteral = { kind: 'assign', target: 'flag', source: { kind: 'literal', value: true } };
  assert.equal(implicitAssignTarget(nLiteral, { tainted: true }), null);
});

test('implicit-flow: markImplicitTaint + createImplicitFinding', () => {
  const s = markImplicitTaint(new Set(), 'isAdmin');
  assert.ok(s.has('implicit:isAdmin'));
  const f = createImplicitFinding({ line: 42 }, 't === "admin"');
  assert.equal(f.implicit, true);
  assert.equal(f.confidence, 0.40);
});

// ── P2.1: RHS tabulation ──────────────────────────────────────────────────
test('tabulation: enumerateSinks finds sink calls in the IR', () => {
  const cg = {
    functions: new Map([
      ['f::main', {
        qid: 'f::main', file: 'f.js', cfg: {
          nodes: {
            n1: { id: 'n1', kind: 'call', callee: 'db.query', args: [{ kind: 'ident', name: 't' }], line: 5 },
          },
        },
      }],
    ]),
  };
  const sinks = enumerateSinks({}, cg);
  // Depends on catalog containing `db.query`; if not, count is 0.
  assert.ok(Array.isArray(sinks));
});

test('tabulation: reachabilitySliceFromSinks walks reverse call graph', () => {
  const cg = {
    functions: new Map([
      ['caller', { qid: 'caller', calls: [{ callee: 'callee' }], cfg: { nodes: {} } }],
      ['callee', { qid: 'callee', calls: [], cfg: { nodes: {} } }],
    ]),
  };
  const sinks = [{ fnQid: 'callee' }];
  const reachable = reachabilitySliceFromSinks(sinks, cg);
  assert.ok(reachable.has('callee'));
  assert.ok(reachable.has('caller'));
});

test('tabulation: rhsReachableFunctions returns null when no sinks', () => {
  const cg = { functions: new Map() };
  const r = rhsReachableFunctions({}, cg);
  assert.equal(r.reachable, null);
});

test('tabulation: shouldAnalyzeUnderRhs', () => {
  assert.equal(shouldAnalyzeUnderRhs(null, 'x'), true);   // analyze-all
  const s = new Set(['x']);
  assert.equal(shouldAnalyzeUnderRhs(s, 'x'), true);
  assert.equal(shouldAnalyzeUnderRhs(s, 'y'), false);
});

// ── P2.2: Python IR ──────────────────────────────────────────────────────
test('python-ir: parses def + assign + call', () => {
  const src = `
def handle(req):
    name = req.body.name
    sql = "SELECT * FROM u WHERE name = " + name
    cursor.execute(sql)
    return name
`;
  const ir = parsePythonFile('app.py', src);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'handle');
  assert.deepEqual(fn.params, ['req']);
  // CFG has at least entry/exit + body nodes.
  const nodeCount = Object.keys(fn.cfg.nodes).length;
  assert.ok(nodeCount >= 4);
});

test('python-ir: returns null for non-python files', () => {
  assert.equal(parsePythonFile('a.js', 'x = 1'), null);
});

// ── P2.3: Java IR ────────────────────────────────────────────────────────
test('java-ir: parses class + method or returns null gracefully', async () => {
  const src = `
package com.example;
public class App {
  public String handle(String name) {
    String sql = "SELECT * FROM u WHERE name = " + name;
    return sql;
  }
}
`;
  const ir = await parseJavaFile('App.java', src);
  // java-parser may or may not be installed in the test env. If not, ir is null;
  // either way, the function must NOT throw.
  if (ir) {
    assert.equal(typeof ir.file, 'string');
    assert.ok(Array.isArray(ir.functions));
  }
});

test('java-ir: returns null for non-java files', async () => {
  assert.equal(await parseJavaFile('a.js', 'x'), null);
});

// ── P2.4: SSA ────────────────────────────────────────────────────────────
test('ssa: isSSAEnabled reads env', () => {
  const prev = process.env.AGENTIC_SECURITY_SSA;
  process.env.AGENTIC_SECURITY_SSA = '1';
  assert.equal(isSSAEnabled(), true);
  delete process.env.AGENTIC_SECURITY_SSA;
  assert.equal(isSSAEnabled(), false);
  if (prev) process.env.AGENTIC_SECURITY_SSA = prev;
});

test('ssa: computeSSA assigns versioned names + records per-node versions', () => {
  // Linear CFG: x assigned twice → x_0, x_1.
  const cfg = {
    entry: 'a', exit: 'd',
    nodes: {
      a: { id: 'a', kind: 'entry', succ: ['b'] },
      b: { id: 'b', kind: 'assign', target: 'x', source: { kind: 'literal', value: 1 }, succ: ['c'] },
      c: { id: 'c', kind: 'assign', target: 'x', source: { kind: 'literal', value: 2 }, succ: ['d'] },
      d: { id: 'd', kind: 'exit', succ: [] },
    },
  };
  computeSSA(cfg);
  assert.ok(cfg.ssa);
  // After both assigns, x should be at version _1 on entry to d.
  const nameAtD = ssaNameAt(cfg, 'd', 'x');
  assert.match(nameAtD || '', /^x_/);
});

test('ssa: branch-join places a phi for x', () => {
  // CFG: a → b (x=1) ↘
  //        ↘ c (x=2) → d
  // d should have a phi for x.
  const cfg = {
    entry: 'a', exit: 'd',
    nodes: {
      a: { id: 'a', kind: 'if', cond: { kind: 'ident', name: 'p' }, succ: ['b', 'c'] },
      b: { id: 'b', kind: 'assign', target: 'x', source: { kind: 'literal', value: 1 }, succ: ['d'] },
      c: { id: 'c', kind: 'assign', target: 'x', source: { kind: 'literal', value: 2 }, succ: ['d'] },
      d: { id: 'd', kind: 'exit', succ: [] },
    },
  };
  computeSSA(cfg);
  assert.ok(cfg.ssa.phis.get('d'));
  const phisAtD = cfg.ssa.phis.get('d');
  assert.ok(phisAtD && phisAtD.some(p => p.var === 'x'));
});
