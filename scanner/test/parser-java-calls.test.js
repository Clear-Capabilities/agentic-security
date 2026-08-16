// PRD R9: parseJavaFile never emitted `fn.calls` at all — ir/CLAUDE.md
// documents this only for Ruby and the Python regex fallback; Java had it
// unconditionally too, for every Java file, always. tabulation.js,
// dataflow/index.js and callgraph.js all read `fn.calls` to build
// cross-function call edges — an absent array is indistinguishable from
// "this function calls nothing," which left callgraph.js's edges/
// callersOf/resolveKnownCallee permanently empty for Java, disabling
// dead-code-demotion accuracy and any interprocedural signal that
// specifically depends on call-graph resolution (rather than the generic
// tainted-call-argument fallback in engine.js's exprTaint).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJavaFile } from '../src/ir/parser-java.js';
import { buildCallGraph } from '../src/ir/callgraph.js';

test('parseJavaFile emits fn.calls for both statement-position and RHS-embedded calls', async () => {
  const ir = await parseJavaFile('App.java', `
public class App {
  String buildQuery(String id) {
    return "SELECT * FROM t WHERE id=" + id;
  }
  void handler(String uid) {
    String sql = buildQuery(uid);
    db.execute(sql);
  }
}
`);
  assert.ok(ir, 'expected a parsed IR');
  const handler = ir.functions.find(f => f.name === 'App.handler');
  assert.ok(handler, 'expected a handler function');
  assert.ok(Array.isArray(handler.calls), 'fn.calls must be an array, not absent');
  const callees = handler.calls.map(c => c.callee);
  assert.ok(callees.includes('buildQuery'), `expected buildQuery in fn.calls, got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('db.execute'), `expected db.execute in fn.calls, got: ${JSON.stringify(callees)}`);
});

test('buildCallGraph resolves a bare same-class call (taint-engine PRD P1)', async () => {
  // buildCallGraph's actual signature (confirmed by reading callgraph.js
  // and mirroring test/parser-rb-calls.test.js's identical Ruby test):
  // buildCallGraph(perFileIR, fileContents) where perFileIR is a
  // { [filename]: ir } map — NOT an array, and NOT called with just [ir].
  // It returns { functions, edges, callersOf, resolve, resolveKnownCallee }
  // — edges is an ARRAY of { caller, site, callee, calleeName, line }
  // objects, and callersOf is a Map<calleeQid, edge[]>, not a Set.
  //
  // Java's class-qualified fn.name ('App.buildCmd') never matched a bare
  // call site's callee ('buildCmd') — this test used to document that gap
  // as "though unresolved due to class qualification". callgraph.js now
  // carries a per-file bare-tail fallback (mirroring the existing
  // ~bare~-key collision-refusal pattern C++ already used), so the most
  // idiomatic Java call shape — private-helper delegation — resolves.
  const ir = await parseJavaFile('App.java', `
public class App {
  void buildCmd(String id) {
    Runtime.getRuntime().exec("echo " + id);
  }
  void handler(String id) {
    buildCmd(id);
  }
}
`);
  const callGraph = buildCallGraph({ 'App.java': ir }, {});
  const handlerFn = ir.functions.find(f => f.name === 'App.handler');
  const buildCmdFn = ir.functions.find(f => f.name === 'App.buildCmd');
  assert.ok(handlerFn, 'expected handler function');
  assert.ok(buildCmdFn, 'expected buildCmd function');
  const handlerEdges = callGraph.edges.filter(e => e.caller === handlerFn.qid);
  const buildCmdEdge = handlerEdges.find(e => e.calleeName === 'buildCmd');
  assert.ok(buildCmdEdge,
    `expected a buildCmd edge from handler; handler edges: ${JSON.stringify(handlerEdges)}`);
  assert.equal(buildCmdEdge.callee, buildCmdFn.qid,
    `expected the bare same-class call to RESOLVE to the real callee qid, not stay unresolved (got callee: ${buildCmdEdge.callee})`);
});

test('buildCallGraph resolves a this.-qualified same-class call, not a fabricated "unknown" callee', async () => {
  // parser-java.js's primaryPrefix/primarySuffix call-lowering had no
  // fqnOrRefType branch for `this.foo(x)` (prefix is a ThisExpression, not
  // an FQN) and fell back to the literal callee string "unknown" — worse
  // than unresolved, since it fabricates a wrong name rather than failing
  // closed. The method name lives in a SIBLING primarySuffix (Dot +
  // Identifier), not the invocation suffix itself.
  const ir = await parseJavaFile('App.java', `
public class App {
  void buildCmd(String id) {
    Runtime.getRuntime().exec("echo " + id);
  }
  void handler(String id) {
    this.buildCmd(id);
  }
}
`);
  const callGraph = buildCallGraph({ 'App.java': ir }, {});
  const handlerFn = ir.functions.find(f => f.name === 'App.handler');
  const buildCmdFn = ir.functions.find(f => f.name === 'App.buildCmd');
  const handlerEdges = callGraph.edges.filter(e => e.caller === handlerFn.qid);
  assert.ok(handlerEdges.some(e => e.calleeName === 'unknown') === false,
    `this.buildCmd(id) must never fabricate calleeName "unknown"; edges: ${JSON.stringify(handlerEdges)}`);
  const buildCmdEdge = handlerEdges.find(e => e.calleeName === 'buildCmd');
  assert.ok(buildCmdEdge, `expected a buildCmd edge from handler; handler edges: ${JSON.stringify(handlerEdges)}`);
  assert.equal(buildCmdEdge.callee, buildCmdFn.qid,
    `expected this.buildCmd(id) to resolve to the real callee qid (got callee: ${buildCmdEdge.callee})`);
});

test('buildCallGraph refuses to guess when a bare name is ambiguous across two classes in the same file', async () => {
  // The bare-tail fallback must mirror the ~bare~-key collision-refusal
  // pattern: two different classes with a same-named method in ONE file
  // must resolve to null, never a guess — a wrong edge invents a data-flow
  // path that doesn't exist, worse than a missing one.
  const ir = await parseJavaFile('App.java', `
class A {
  void run() { helper(); }
  void helper() { System.out.println("A"); }
}
class B {
  void helper() { System.out.println("B"); }
}
`);
  const callGraph = buildCallGraph({ 'App.java': ir }, {});
  const runFn = ir.functions.find(f => f.name === 'A.run');
  assert.ok(runFn, 'expected A.run function');
  const runEdges = callGraph.edges.filter(e => e.caller === runFn.qid);
  const helperEdge = runEdges.find(e => e.calleeName === 'helper');
  assert.ok(helperEdge, `expected a helper edge from A.run; edges: ${JSON.stringify(runEdges)}`);
  assert.equal(helperEdge.callee, null,
    `ambiguous bare name "helper" (A.helper vs B.helper) must refuse to resolve, not guess (got: ${helperEdge.callee})`);
});

test('buildCallGraph resolves a cross-class Java call to the real target qid', async () => {
  // The other two callgraph tests above only ever check an UNRESOLVED edge
  // (the same-class bare-call gap this file documents) — that leaves the
  // whole suite unable to distinguish "Java call resolution works" from
  // "Java call resolution is completely broken." This test proves the
  // positive case: a qualified cross-class call (`Helper.sanitize(id)`,
  // extracted as callee `"Helper.sanitize"`) resolves via callgraph.js's
  // `classMethods` index to the real callee qid, not just a calleeName.
  const helperIr = await parseJavaFile('Helper.java', `
public class Helper {
  static String sanitize(String s) {
    return s.trim();
  }
}
`);
  const appIr = await parseJavaFile('App.java', `
public class App {
  void handler(String id) {
    Helper.sanitize(id);
  }
}
`);
  const callGraph = buildCallGraph({ 'Helper.java': helperIr, 'App.java': appIr }, {});
  const handlerFn = appIr.functions.find(f => f.name === 'App.handler');
  const sanitizeFn = helperIr.functions.find(f => f.name === 'Helper.sanitize');
  assert.ok(handlerFn, 'expected handler function');
  assert.ok(sanitizeFn, 'expected sanitize function');
  const edge = callGraph.edges.find(e => e.caller === handlerFn.qid && e.calleeName === 'Helper.sanitize');
  assert.ok(edge, `expected a Helper.sanitize edge from handler; edges: ${JSON.stringify(callGraph.edges)}`);
  assert.equal(edge.callee, sanitizeFn.qid, 'expected the edge to resolve to the real callee qid, not stay unresolved');
});

test('a call inside a control-flow body (R8 shape) is still captured in fn.calls', async () => {
  // R9 is only useful because R8 already made sure calls inside if/for/
  // try/switch bodies are reachable in the CFG at all — this test pins
  // the R8+R9 combination end-to-end, not just a bare-statement call.
  const ir = await parseJavaFile('App.java', `
public class App {
  void handler(String id, boolean flag) {
    if (flag) {
      db.execute(id);
    }
  }
}
`);
  const handler = ir.functions.find(f => f.name === 'App.handler');
  assert.ok(handler, 'expected a handler function');
  const callees = handler.calls.map(c => c.callee);
  assert.ok(callees.includes('db.execute'), `expected db.execute (inside if-body) in fn.calls, got: ${JSON.stringify(callees)}`);
});
