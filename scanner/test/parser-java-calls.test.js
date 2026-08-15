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

test('buildCallGraph records a call edge from handler to buildCmd (though unresolved due to class qualification)', async () => {
  // buildCallGraph's actual signature (confirmed by reading callgraph.js
  // and mirroring test/parser-rb-calls.test.js's identical Ruby test):
  // buildCallGraph(perFileIR, fileContents) where perFileIR is a
  // { [filename]: ir } map — NOT an array, and NOT called with just [ir].
  // It returns { functions, edges, callersOf, resolve, resolveKnownCallee }
  // — edges is an ARRAY of { caller, site, callee, calleeName, line }
  // objects, and callersOf is a Map<calleeQid, edge[]>, not a Set.
  //
  // NOTE: Java's class-qualified names ('App.buildCmd') don't match bare
  // method calls ('buildCmd'), so the call site cannot be resolved by
  // callgraph's name matching. This test verifies that the call edge is
  // AT LEAST CREATED with calleeName intact, which is the critical change
  // this PR makes — previously, fn.calls was absent entirely, so no edge
  // would be created at all. A bare call to 'buildCmd' in Java will
  // resolve as null, leaving it to the generic taint-on-call-args fallback.
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
  assert.ok(handlerFn, 'expected handler function');
  // The critical observable: an edge exists from handler, with the call
  // name recorded, even if unresolved.
  const handlerEdges = callGraph.edges.filter(e => e.caller === handlerFn.qid);
  assert.ok(handlerEdges.length > 0,
    `expected at least one edge from handler; all edges: ${JSON.stringify(callGraph.edges)}`);
  const buildCmdEdge = handlerEdges.find(e => e.calleeName === 'buildCmd');
  assert.ok(buildCmdEdge,
    `expected a buildCmd edge from handler; handler edges: ${JSON.stringify(handlerEdges)}`);
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
