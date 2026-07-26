// C/C++ integration: dispatch, cross-TU call resolution, class hierarchy, taint.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR, buildProjectIRAsync } from '../src/ir/index.js';
import { parseCppFile } from '../src/ir/parser-cpp.js';
import { buildClassHierarchy, resolveMethod } from '../src/ir/class-hierarchy.js';

test('buildProjectIR: dispatches every C/C++ extension', () => {
  const files = {
    'a.cpp': 'void f() { int x = 1; }\n',
    'b.cc': 'void g() { int x = 1; }\n',
    'c.cxx': 'void h() { int x = 1; }\n',
    'd.c': 'void i() { int x = 1; }\n',
    'e.hpp': 'class E { public: int m(); };\n',
    'f.h': 'class F { public: int m(); };\n',
    'g.hh': 'class G { public: int m(); };\n',
    'h.hxx': 'class H { public: int m(); };\n',
  };
  const { perFile } = buildProjectIR(files);
  for (const name of Object.keys(files)) {
    assert.ok(perFile[name], `${name} must produce an IR record`);
    assert.ok(perFile[name].functions.length >= 1, `${name} must yield a function`);
  }
});

test('buildProjectIRAsync: dispatches C/C++ alongside Java', async () => {
  const { perFile } = await buildProjectIRAsync({
    'a.cpp': 'void f() { int x = 1; }\n',
    'b.js': 'function g(){ var y = 1; }\n',
  });
  assert.ok(perFile['a.cpp'], 'C++ must be dispatched in the async path too');
  assert.ok(perFile['b.js'], 'JS must still be dispatched');
});

test('buildProjectIR: C++ does not disturb other languages', () => {
  const { perFile } = buildProjectIR({
    'a.cpp': 'void f() { int x = 1; }\n',
    'b.py': 'def g():\n    y = 1\n',
    'c.go': 'package main\nfunc h() {\n\tx := 1\n}\n',
  });
  assert.ok(perFile['a.cpp']);
  assert.ok(perFile['b.py']);
  assert.ok(perFile['c.go']);
});

test('call graph: resolves a cross-translation-unit method call', () => {
  const files = {
    'buf.h': 'class Buffer {\npublic:\n  void fill(char* src);\n};\n',
    'buf.cpp': 'void Buffer::fill(char* src) {\n  int n = 1;\n}\n',
    'main.cpp': 'void run(Buffer* b, char* p) {\n  b->fill(p);\n}\n',
  };
  const { callGraph } = buildProjectIR(files);
  const resolved = callGraph.edges.filter(e => e.callee);
  assert.ok(resolved.length >= 1, 'at least one edge must resolve across files');
  const target = callGraph.functions.get(resolved[0].callee);
  assert.ok(target, 'the resolved callee must be a known function');
});

test('call graph: a definition wins over a header declaration', () => {
  const files = {
    'buf.h': 'class Buffer {\npublic:\n  void fill(char* src);\n};\n',
    'buf.cpp': 'void Buffer::fill(char* src) {\n  int n = 1;\n}\n',
    'main.cpp': 'void run(Buffer* b, char* p) {\n  b->fill(p);\n}\n',
  };
  const { perFile, callGraph } = buildProjectIR(files);
  const defQid = perFile['buf.cpp'].functions[0].qid;
  const declQid = perFile['buf.h'].functions[0].qid;
  const edge = callGraph.edges.find(e => e.callee);
  assert.equal(edge.callee, defQid, 'must resolve to the definition');
  assert.notEqual(edge.callee, declQid, 'must not resolve to the declaration');
});

test('call graph: a free function resolves across files by qualified name', () => {
  const files = {
    'util.cpp': 'namespace util {\nvoid helper(char* s) {\n  int n = 1;\n}\n}\n',
    'main.cpp': 'void go(char* p) {\n  util::helper(p);\n}\n',
  };
  const { callGraph } = buildProjectIR(files);
  assert.ok(callGraph.edges.some(e => e.callee), 'namespaced free function must resolve');
});

test('call graph: a JS call must not resolve to a same-named C++ function (no cross-language binding)', () => {
  const files = {
    'native.cpp': 'class File {\npublic:\n  void read(char* buf) {\n    int n = 1;\n  }\n};\n',
    'app.js': 'function handle(req) {\n  const f = getFile();\n  f.read(req.query.p);\n}\n',
  };
  const { callGraph } = buildProjectIR(files);
  const jsCallSites = callGraph.edges.filter(e => e.calleeName === 'f.read');
  assert.ok(jsCallSites.length >= 1, 'the JS call site must be present in the graph');
  assert.ok(jsCallSites.every(e => e.callee === null),
    'a JS call must never resolve to a C++ definition just because the bare method name collides');
});

test('call graph: resolve() with no callerFile must not leak a C++ definition to an unrelated bare name', () => {
  const files = {
    'native.cpp': 'class File {\npublic:\n  void read(char* buf) {\n    int n = 1;\n  }\n};\n',
    'app.js': 'function handle(req) {\n  const f = getFile();\n  f.read(req.query.p);\n}\n',
  };
  const { callGraph } = buildProjectIR(files);
  // No callerFile at all — the taint-engine call sites that omit it
  // (ifds.js, async-sequencing.js, points-to.js) must not fabricate a
  // cross-language edge just because a bare/tail name happens to collide.
  assert.equal(callGraph.resolve('read'), null, 'bare "read" with no caller context must not resolve to the C++ definition');
  assert.equal(callGraph.resolve('f.read'), null, 'dotted "f.read" with no caller context must not resolve to the C++ definition');
});

test('call graph: two same-named unqualified C definitions in different files refuse to resolve', () => {
  const files = {
    'a.cpp': 'void helper(char* s) {\n  int n = 1;\n}\n',
    'b.cpp': 'void helper(char* s) {\n  int n = 2;\n}\n',
    'main.cpp': 'void go(char* p) {\n  helper(p);\n}\n',
  };
  const { callGraph } = buildProjectIR(files);
  const call = callGraph.edges.find(e => e.calleeName === 'helper');
  assert.ok(call, 'the call site must be present');
  assert.equal(call.callee, null, 'an ambiguous unqualified name must not resolve to either definition');
});

test('parseCppFile: fn.calls is populated with the parser-js-documented shape, including assignment-position calls', () => {
  const code = 'void run(char* out) {\n  char* p = getenv("CMD");\n  memcpy(out, p, 8);\n}\n';
  const ir = parseCppFile('a.cpp', code);
  const fn = ir.functions[0];
  assert.ok(Array.isArray(fn.calls) && fn.calls.length >= 2,
    'both the assignment-position call and the statement-position call must be captured');

  // Statement-position call: memcpy(out, p, 8).
  const memcpyCall = fn.calls.find(c => c.callee === 'memcpy');
  assert.ok(memcpyCall, 'statement-position call must be present');
  assert.ok(fn.cfg.nodes[memcpyCall.site], 'site must be a real CFG node id');
  assert.equal(fn.cfg.nodes[memcpyCall.site].callee, 'memcpy', 'callee must match the node it points at');
  assert.equal(typeof memcpyCall.line, 'number');
  assert.ok(memcpyCall.line > 0);

  // Assignment-position call: char* p = getenv("CMD") — the source-introducing
  // shape the taint engine needs; must not be missed just because it sits on
  // an assignment's RHS rather than being its own statement.
  const getenvCall = fn.calls.find(c => c.callee === 'getenv');
  assert.ok(getenvCall, 'assignment-position call must be present');
  assert.ok(fn.cfg.nodes[getenvCall.site], 'site must be a real CFG node id');
  assert.equal(fn.cfg.nodes[getenvCall.site].kind, 'assign');
  assert.equal(fn.cfg.nodes[getenvCall.site].source.callee, 'getenv', 'callee must match the assign node\'s call source');
  assert.equal(typeof getenvCall.line, 'number');
  assert.ok(getenvCall.line > 0);
});

test('class hierarchy: recovers C++ classes and their base classes', () => {
  const { perFile } = buildProjectIR({
    'a.cpp': 'class Base {\npublic:\n  int run() { return 1; }\n};\nclass Derived : public Base {\npublic:\n  int extra() { return 2; }\n};\n',
  });
  const cha = buildClassHierarchy(perFile);
  assert.ok(cha.classes.get('Base'), 'Base must be recovered');
  assert.ok(cha.classes.get('Derived'), 'Derived must be recovered');
  assert.equal(cha.classes.get('Derived').extends, 'Base');
});

test('class hierarchy: the recovered method name is bare, not suffixed', () => {
  // Regression guard. class-hierarchy.js recovers methodName as
  // tail.slice(dotIdx + 1), which for a qid tail of `Class.method@line#sha`
  // yields `method@line#sha`. Class recovery was always correct; method
  // recovery was not, which silently broke every resolveMethod() lookup.
  const { perFile } = buildProjectIR({
    'a.cpp': 'class Base {\npublic:\n  int run() { return 1; }\n};\n',
  });
  const cha = buildClassHierarchy(perFile);
  const methods = [...cha.classes.get('Base').methods];
  assert.deepEqual(methods, ['run'],
    'method names must be bare — no @line#sha suffix');
});

test('class hierarchy: an inherited method resolves through the extends chain', () => {
  const { perFile } = buildProjectIR({
    'a.cpp': 'class Base {\npublic:\n  int run() { return 1; }\n};\nclass Derived : public Base {\npublic:\n  int extra() { return 2; }\n};\n',
  });
  const cha = buildClassHierarchy(perFile);
  const hit = resolveMethod(cha, 'Derived', 'run');
  assert.ok(hit, 'run must resolve on Derived via Base');
  assert.equal(hit.className, 'Base');
});

test('class hierarchy: multiple inheritance keeps the first base and does not throw', () => {
  const { perFile } = buildProjectIR({
    'a.cpp': 'class A { public: int m() { return 1; } };\nclass B { public: int n() { return 2; } };\nclass C : public A, public B { public: int o() { return 3; } };\n',
  });
  const cha = buildClassHierarchy(perFile);
  assert.ok(['A', 'B'].includes(cha.classes.get('C').extends));
});

test('class hierarchy: languages without ir.classes are unaffected', () => {
  const { perFile } = buildProjectIR({ 'b.js': 'class Foo { bar(){ return 1; } }\n' });
  const cha = buildClassHierarchy(perFile);
  assert.ok(cha.classes instanceof Map, 'still returns the documented shape');
});
