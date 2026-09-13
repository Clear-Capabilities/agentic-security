// Roadmap #3 — same-file-preference call resolution.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildCallGraph } from '../src/ir/callgraph.js';
import { buildProjectIR } from '../src/ir/index.js';

// Two files each define a function named `handler` (a common collision).
function twoFileGraph() {
  const perFileIR = {
    'a.js': { functions: [{ qid: 'a.js::handler@1#aaa', name: 'handler', file: 'a.js', calls: [] }] },
    'b.js': { functions: [{ qid: 'b.js::handler@1#bbb', name: 'handler', file: 'b.js', calls: [] }] },
  };
  return buildCallGraph(perFileIR, { 'a.js': '', 'b.js': '' });
}

test('resolve prefers the caller\'s own file on a cross-file name collision', () => {
  const g = twoFileGraph();
  assert.equal(g.resolve('handler', 'a.js'), 'a.js::handler@1#aaa');
  assert.equal(g.resolve('handler', 'b.js'), 'b.js::handler@1#bbb');
});

test('resolve without a callerFile is backward-compatible (still resolves)', () => {
  const g = twoFileGraph();
  const r = g.resolve('handler');
  // Returns one of the two (original first-match behavior) — never null.
  assert.ok(r === 'a.js::handler@1#aaa' || r === 'b.js::handler@1#bbb');
});

test('callerFile with no local match falls back to global resolution (no dropped edge)', () => {
  const perFileIR = {
    'a.js': { functions: [{ qid: 'a.js::caller@1#x', name: 'caller', file: 'a.js', calls: [] }] },
    'util.js': { functions: [{ qid: 'util.js::escape@1#y', name: 'escape', file: 'util.js', calls: [] }] },
  };
  const g = buildCallGraph(perFileIR, { 'a.js': '', 'util.js': '' });
  // `escape` isn't defined in a.js → still resolves to util.js, not null.
  assert.equal(g.resolve('escape', 'a.js'), 'util.js::escape@1#y');
});

test('unknown name still returns null', () => {
  assert.equal(twoFileGraph().resolve('nope', 'a.js'), null);
});

// PRD R7 (docs/DETECTION_GAP_REMEDIATION_PRD.md): buildCallGraph's re-export
// map (`export { x as y } from './z'`, `module.exports = require('./z')`)
// only populates when `fileContents` is passed as the second argument — but
// both real callers (ir/index.js's buildProjectIR/buildProjectIRAsync) called
// buildCallGraph(perFile) with one argument, so the map was always empty and
// this resolution path was dead in production. An ALIASED re-export is the
// case this actually matters for: a bare-name search across every file
// cannot find a call to the ALIAS (no function is literally named that), and
// without the re-export map redirecting to the real function's name, the
// call is silently unresolved — a dropped edge, not just an imprecise one.
test('an aliased re-export resolves via the source function, when fileContents is supplied', () => {
  const perFileIR = {
    'impl.js': { functions: [{ qid: 'impl.js::helper@1#ccc', name: 'helper', file: 'impl.js', calls: [] }] },
    'router.js': { functions: [{ qid: 'router.js::main@2#ddd', name: 'main', file: 'router.js', calls: [{ callee: 'processInput', line: 2 }] }] },
  };
  const fileContents = {
    'impl.js': 'function helper(x) {}\n',
    'router.js': "export { helper as processInput } from './impl.js';\nfunction main(req) { processInput(req.query.cmd); }\n",
  };
  const withoutContents = buildCallGraph(perFileIR);
  assert.equal(withoutContents.resolveKnownCallee('processInput', 'router.js'), null,
    'control: without fileContents the alias genuinely cannot resolve (confirms the test fixture exercises the re-export path, not some other resolution rule)');
  const withContents = buildCallGraph(perFileIR, fileContents);
  const resolved = withContents.resolveKnownCallee('processInput', 'router.js');
  assert.equal(resolved, 'impl.js::helper@1#ccc',
    `expected the aliased re-export to resolve to impl.js's helper, got ${JSON.stringify(resolved)}`);
});

// Taint-recall: `this.method(arg)` same-instance calls. Found via the SARD
// C# benchmark — a hand-rolled parser (parser-cs.js) lowers `this.foo(x)` to
// the flat dotted callee string "this.foo", but `fn.name` for the target
// method is bare ("foo", not class-qualified) — the OPPOSITE asymmetry from
// Java's documented class-qualified-name bug, and unhandled by the existing
// bareTailInFile fallback (which explicitly skips any callee containing a
// dot). Confirmed empirically: this same-class delegation pattern silently
// blocked ALL interprocedural taint into the callee, for every sink inside
// it, across LDAP/XPath/response-splitting/code-injection/command-injection
// — not a narrow case.
test('resolveKnownCallee resolves a `this.method(...)` call to the same-file bare-named method', () => {
  const perFileIR = {
    'Api.cs': { functions: [
      { qid: 'Api.cs::bad@1#a', name: 'bad', file: 'Api.cs', calls: [{ callee: 'this.badSink', line: 3 }] },
      { qid: 'Api.cs::badSink@10#b', name: 'badSink', file: 'Api.cs', calls: [] },
    ] },
  };
  const g = buildCallGraph(perFileIR, { 'Api.cs': '' });
  assert.equal(g.resolveKnownCallee('this.badSink', 'Api.cs'), 'Api.cs::badSink@10#b');
});

test('edges[] also resolves a `this.method(...)` call site (not just resolveKnownCallee)', () => {
  const perFileIR = {
    'Api.cs': { functions: [
      { qid: 'Api.cs::bad@1#a', name: 'bad', file: 'Api.cs', calls: [{ callee: 'this.badSink', site: 's1', line: 3 }] },
      { qid: 'Api.cs::badSink@10#b', name: 'badSink', file: 'Api.cs', calls: [] },
    ] },
  };
  const g = buildCallGraph(perFileIR, { 'Api.cs': '' });
  const edge = g.edges.find(e => e.caller === 'Api.cs::bad@1#a');
  assert.ok(edge, 'expected an edge from bad()');
  assert.equal(edge.callee, 'Api.cs::badSink@10#b');
});

test('`this.method(...)` does NOT resolve across files (same-file only, never a cross-file guess)', () => {
  const perFileIR = {
    'Api.cs': { functions: [{ qid: 'Api.cs::bad@1#a', name: 'bad', file: 'Api.cs', calls: [{ callee: 'this.badSink', line: 3 }] }] },
    'Other.cs': { functions: [{ qid: 'Other.cs::badSink@1#c', name: 'badSink', file: 'Other.cs', calls: [] }] },
  };
  const g = buildCallGraph(perFileIR, { 'Api.cs': '', 'Other.cs': '' });
  assert.equal(g.resolveKnownCallee('this.badSink', 'Api.cs'), null,
    'a same-instance call must never resolve to a method defined in a DIFFERENT file/class');
});

test('a `this.`-prefixed name that matches nothing in the file still returns null (no false edge)', () => {
  const perFileIR = {
    'Api.cs': { functions: [{ qid: 'Api.cs::bad@1#a', name: 'bad', file: 'Api.cs', calls: [] }] },
  };
  const g = buildCallGraph(perFileIR, { 'Api.cs': '' });
  assert.equal(g.resolveKnownCallee('this.nonExistent', 'Api.cs'), null);
});

test('buildProjectIR (the real call site) resolves an aliased re-export end to end', () => {
  const fileContents = {
    'impl.js': 'function helper(x) {}\n',
    'router.js': "export { helper as processInput } from './impl.js';\nfunction main(req) { processInput(req.query.cmd); }\n",
  };
  const { callGraph } = buildProjectIR(fileContents);
  const resolved = callGraph.resolveKnownCallee('processInput', 'router.js');
  assert.ok(resolved, `expected buildProjectIR's own call graph to resolve the aliased re-export, got ${JSON.stringify(resolved)}`);
  assert.match(String(resolved), /impl\.js.*helper/, `expected resolution into impl.js's helper, got ${JSON.stringify(resolved)}`);
});
