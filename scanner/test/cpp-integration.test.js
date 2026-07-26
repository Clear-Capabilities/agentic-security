// C/C++ integration: dispatch, cross-TU call resolution, class hierarchy, taint.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR, buildProjectIRAsync } from '../src/ir/index.js';

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
