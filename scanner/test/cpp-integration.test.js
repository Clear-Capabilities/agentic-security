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
