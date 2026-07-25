// Tests for the C/C++ IR frontend.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCppFile } from '../src/ir/parser-cpp.js';

test('parseCppFile: captures a free function with params', () => {
  const code = `
#include <string>
void handle(const std::string& name, int count) {
  int total = count;
  return;
}
`;
  const ir = parseCppFile('a.cpp', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'handle');
  assert.equal(fn.qname, 'handle');
  assert.deepEqual(fn.params, ['name', 'count']);
  assert.equal(fn.isDeclaration, false);
  assert.equal(fn.file, 'a.cpp');
  assert.ok(fn.cfg && fn.cfg.nodes.entry && fn.cfg.nodes.exit);
});

test('parseCppFile: captures an out-of-line method definition with qualified name', () => {
  const code = `
void Parser::consume(char* buf) {
  int x = 1;
}
`;
  const ir = parseCppFile('p.cpp', code);
  assert.equal(ir.functions.length, 1);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'consume');
  assert.equal(fn.qname, 'Parser::consume');
  assert.match(fn.qid, /^p\.cpp::Parser\.consume@\d+#[0-9a-f]{8}$/,
    'qid tail must join class and method with a dot so CHA can recover the class');
});

test('parseCppFile: captures a namespaced out-of-line method', () => {
  const code = `
int core::Buffer::size(int n) {
  return n;
}
`;
  const ir = parseCppFile('b.cpp', code);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'size');
  assert.equal(fn.qname, 'core::Buffer::size');
  assert.match(fn.qid, /::Buffer\.size@/, 'qid uses the immediate class, not the namespace');
});

test('parseCppFile: captures in-class method definitions and the class record', () => {
  const code = `
class Reader : public Base, private Mixin {
public:
  int read(int fd) {
    int n = fd;
    return n;
  }
};
`;
  const ir = parseCppFile('r.cpp', code);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'read');
  assert.equal(ir.functions[0].qname, 'Reader::read');
  assert.equal(ir.classes.length, 1);
  assert.equal(ir.classes[0].name, 'Reader');
  assert.deepEqual(ir.classes[0].bases.sort(), ['Base', 'Mixin']);
});

test('parseCppFile: records header declarations without bodies as declarations', () => {
  const code = `
class Reader {
public:
  int read(int fd);
  void close();
};
`;
  const ir = parseCppFile('r.h', code);
  const names = ir.functions.map(f => f.name).sort();
  assert.deepEqual(names, ['close', 'read']);
  assert.ok(ir.functions.every(f => f.isDeclaration === true));
  assert.equal(ir.functions[0].qname, 'Reader::read');
});

test('parseCppFile: handles reference, pointer, const and defaulted params', () => {
  const code = `
void f(const char* src, std::string& dst, int n = 10, Foo<Bar> baz) {
  int y = n;
}
`;
  const ir = parseCppFile('f.cpp', code);
  assert.deepEqual(ir.functions[0].params, ['src', 'dst', 'n', 'baz']);
});

test('parseCppFile: constructors and destructors are captured', () => {
  const code = `
Widget::Widget(int size) {
  int s = size;
}
Widget::~Widget() {
  int z = 0;
}
`;
  const ir = parseCppFile('w.cpp', code);
  const names = ir.functions.map(f => f.name).sort();
  assert.deepEqual(names, ['Widget', '~Widget']);
});

test('parseCppFile: control-flow keywords are not mistaken for functions', () => {
  const code = `
void f(int n) {
  if (n > 0) { int a = 1; }
  while (n) { int b = 2; }
  for (int i = 0; i < n; i++) { int c = 3; }
  switch (n) { case 1: break; }
}
`;
  const ir = parseCppFile('c.cpp', code);
  assert.equal(ir.functions.length, 1, 'only f is a function');
  assert.equal(ir.functions[0].name, 'f');
});

test('parseCppFile: comments and strings containing braces do not break splitting', () => {
  const code = `
// a comment with { and }
void f() {
  const char* s = "a { brace } in a string";
  int x = 1;
}
`;
  const ir = parseCppFile('s.cpp', code);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'f');
});

test('parseCppFile: qid is stable for unchanged bodies and differs when the body changes', () => {
  const a = parseCppFile('x.cpp', 'void f() {\n int x = 1;\n}\n');
  const b = parseCppFile('x.cpp', 'void f() {\n int x = 1;\n}\n');
  const c = parseCppFile('x.cpp', 'void f() {\n int x = 2;\n}\n');
  assert.equal(a.functions[0].qid, b.functions[0].qid);
  assert.notEqual(a.functions[0].qid, c.functions[0].qid);
});

test('parseCppFile: rejects bad input without throwing', () => {
  assert.equal(parseCppFile(null, 'void f(){}'), null);
  assert.equal(parseCppFile('a.cpp', null), null);
  assert.equal(parseCppFile('a.cpp', 42), null);
  const empty = parseCppFile('a.cpp', '');
  assert.ok(empty);
  assert.deepEqual(empty.functions, []);
});

test('parseCppFile: an unterminated body does not hang or throw', () => {
  const ir = parseCppFile('u.cpp', 'void f() {\n int x = 1;\n');
  assert.ok(ir, 'must return a record rather than throwing');
});

test('parseCppFile: a backslash-newline continuation inside a string does not corrupt line numbers', () => {
  // Line-by-line (counting the literal template rows):
  //   1: '' (blank line right after the opening backtick)
  //   2: const char* s = "abc\        <- backslash immediately followed by a
  //                                      real newline: valid C++ line-continuation
  //   3: def";
  //   4: void f() {
  //   5:   int x = 1;
  //   6: }
  //   7: '' (trailing)
  const code = `
const char* s = "abc\\
def";
void f() {
  int x = 1;
}
`;
  const ir = parseCppFile('cont.cpp', code);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'f');
  assert.equal(ir.functions[0].line, 4,
    'the real newline inside the string continuation must not be blanked away, ' +
    'or every line number after it undercounts by one');
});

test('parseCppFile: an unmatched paren does not truncate scanning of the rest of the file', () => {
  const code = `
void bad(int a
void f() {
  int x = 1;
}
`;
  const ir = parseCppFile('unmatched.cpp', code);
  assert.equal(ir.functions.length, 1, 'the unmatched "(" must be skipped, not abort the scan');
  assert.equal(ir.functions[0].name, 'f');
});
