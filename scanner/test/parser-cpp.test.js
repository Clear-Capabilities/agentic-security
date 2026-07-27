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

function nodesOf(ir, idx = 0) {
  return Object.values(ir.functions[idx].cfg.nodes);
}

test('lowering: assignments capture target and source', () => {
  const ir = parseCppFile('a.cpp', 'void f(int n) {\n  int x = n;\n  y = 3;\n}\n');
  const assigns = nodesOf(ir).filter(n => n.kind === 'assign');
  assert.ok(assigns.some(a => a.target === 'x' && a.source.kind === 'ident' && a.source.name === 'n'));
  assert.ok(assigns.some(a => a.target === 'y' && a.source.kind === 'literal'));
});

test('lowering: calls emit a dotted string callee and lowered args', () => {
  const ir = parseCppFile('a.cpp', 'void f(char* p) {\n  system(p);\n  obj.run(p);\n  ptr->exec(p);\n  ns::go(p);\n}\n');
  const calls = nodesOf(ir).filter(n => n.kind === 'call');
  const callees = calls.map(c => c.callee).sort();
  assert.deepEqual(callees, ['ns::go', 'obj.run', 'ptr.exec', 'system'],
    'member and arrow access both normalise to dotted form; :: is preserved');
  assert.ok(calls.every(c => Array.isArray(c.args)));
});

test('lowering: assignment from a call keeps the call as the source', () => {
  const ir = parseCppFile('a.cpp', 'void f() {\n  char* p = getenv("PATH");\n}\n');
  const a = nodesOf(ir).find(n => n.kind === 'assign');
  assert.equal(a.target, 'p');
  assert.equal(a.source.kind, 'call');
  assert.equal(a.source.callee, 'getenv');
});

test('lowering: return and throw carry their value', () => {
  const ir = parseCppFile('a.cpp', 'int f(int n) {\n  if (n) { throw n; }\n  return n;\n}\n');
  const ns = nodesOf(ir);
  assert.ok(ns.some(n => n.kind === 'return' && n.value && n.value.name === 'n'));
  assert.ok(ns.some(n => n.kind === 'throw'));
});

test('lowering: if produces an if node carrying the condition', () => {
  const ir = parseCppFile('a.cpp', 'void f(int n) {\n  if (n > 0) {\n    int a = n;\n  }\n}\n');
  const ns = nodesOf(ir);
  const iff = ns.find(n => n.kind === 'if');
  assert.ok(iff, 'expected an if node');
  assert.ok(iff.cond);
  assert.ok(ns.some(n => n.kind === 'assign' && n.target === 'a'),
    'the if body must be lowered, not dropped');
});

test('lowering: loop bodies are lowered', () => {
  const ir = parseCppFile('a.cpp', 'void f(int n) {\n  for (int i = 0; i < n; i++) {\n    int b = n;\n  }\n  while (n) {\n    int c = n;\n  }\n}\n');
  const targets = nodesOf(ir).filter(n => n.kind === 'assign').map(n => n.target);
  assert.ok(targets.includes('b'), 'for-body assignment must be lowered');
  assert.ok(targets.includes('c'), 'while-body assignment must be lowered');
});

test('lowering: string concatenation becomes a template so taint flows through', () => {
  const ir = parseCppFile('a.cpp', 'void f(std::string user) {\n  std::string q = "SELECT " + user;\n}\n');
  const a = nodesOf(ir).find(n => n.kind === 'assign' && n.target === 'q');
  assert.equal(a.source.kind, 'tpl');
  assert.ok(a.source.parts.some(p => p.kind === 'ident' && p.name === 'user'));
});

test('lowering: sprintf-family calls lower their arguments', () => {
  const ir = parseCppFile('a.cpp', 'void f(char* user) {\n  char buf[64];\n  sprintf(buf, "%s", user);\n}\n');
  const c = nodesOf(ir).find(n => n.kind === 'call' && n.callee === 'sprintf');
  assert.ok(c);
  assert.ok(c.args.some(a => a.kind === 'ident' && a.name === 'user'));
});

test('lowering: every node is reachable from entry and the CFG is well formed', () => {
  const ir = parseCppFile('a.cpp', 'void f(int n) {\n  int x = n;\n  g(x);\n  return;\n}\n');
  const cfg = ir.functions[0].cfg;
  const seen = new Set();
  const stack = [cfg.entry];
  while (stack.length) {
    const id = stack.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    for (const s of cfg.nodes[id].succ) {
      assert.ok(cfg.nodes[s], `succ ${s} must exist`);
      assert.ok(cfg.nodes[s].pred.includes(id), `pred link back from ${s} to ${id}`);
      stack.push(s);
    }
  }
  assert.ok(seen.has(cfg.exit), 'exit must be reachable from entry');
  assert.equal(seen.size, Object.keys(cfg.nodes).length, 'no orphan nodes');
});

test('lowering: a declaration has an empty but valid CFG', () => {
  const ir = parseCppFile('r.h', 'class R {\npublic:\n  int read(int fd);\n};\n');
  const cfg = ir.functions[0].cfg;
  assert.equal(cfg.entry, 'entry');
  assert.equal(cfg.nodes.entry.succ[0], 'exit');
});

// ── regression: structure must come from the blanked body, not the raw one ──
// (a brace or paren inside a string literal must not swallow later code)

test('lowering regression: a brace inside a string literal does not swallow the following call', () => {
  const ir = parseCppFile('a.cpp', 'void f(char* u) {\n  printf("}");\n  system(u);\n}\n');
  const calls = nodesOf(ir).filter(n => n.kind === 'call').map(n => n.callee).sort();
  assert.deepEqual(calls, ['printf', 'system'],
    'the "}" inside the string must not be read as the function\'s closing brace');
});

test('lowering regression: a stray "(" inside a string literal does not swallow the following call', () => {
  const ir = parseCppFile('a.cpp', 'void f(char* x) {\n  printf("(");\n  system(x);\n}\n');
  const calls = nodesOf(ir).filter(n => n.kind === 'call').map(n => n.callee).sort();
  assert.deepEqual(calls, ['printf', 'system'],
    'the "(" inside the string must not desynchronize paren-depth tracking for later statements');
});

// ── regression: condition/header extraction must balance nested parens ─────

test('lowering regression: a while condition with nested calls is captured whole, not truncated at the first ")"', () => {
  const ir = parseCppFile('a.cpp', 'void f(char* buf) {\n  while (fgets(buf, sizeof(buf), stdin)) {\n    sink(buf);\n  }\n}\n');
  const ns = nodesOf(ir);
  const iff = ns.find(n => n.kind === 'if');
  assert.ok(iff, 'expected an if node for the while');
  assert.equal(iff.cond.kind, 'call');
  assert.equal(iff.cond.callee, 'fgets', 'fgets must not be lost to the non-greedy-regex truncation bug');
  assert.ok(ns.some(n => n.kind === 'call' && n.callee === 'sink'),
    'the loop body must still be lowered, not dropped');
});

test('lowering regression: a brace-less for header with a nested-paren test still lowers its body', () => {
  const ir = parseCppFile('a.cpp', 'void f(char* s) {\n  for (int i = 0; i < strlen(s); i++) sink(s);\n}\n');
  const ns = nodesOf(ir);
  assert.ok(ns.some(n => n.kind === 'assign' && n.target === 'i'), 'the for-init must be lowered');
  assert.ok(ns.some(n => n.kind === 'call' && n.callee === 'sink'),
    'the brace-less body must be lowered, not absorbed into the header');
});

// ── regression: nested-block statements must report their true physical line ──

test('lowering regression: statements nested inside an if-block report their real line number, not the function start line', () => {
  const ir = parseCppFile('a.cpp', 'void f(){\n if(n){\n int a=n;\n system(a);\n}}');
  const ns = nodesOf(ir);
  const assign = ns.find(n => n.kind === 'assign' && n.target === 'a');
  const call = ns.find(n => n.kind === 'call' && n.callee === 'system');
  assert.ok(assign && call);
  assert.equal(assign.line, 3, '"int a=n;" is on physical line 3');
  assert.equal(call.line, 4, '"system(a);" is on physical line 4');
});

// ── performance regression: line-number lookup must not be O(n) per statement ──
// A per-statement rescan-from-zero for line numbers made _buildCfg quadratic
// in function-body size (fine for many small functions, catastrophic for one
// huge one — generated code, big switch tables, unity builds). This must
// stay comfortably sub-quadratic: a bound picked to be generous enough not
// to flake on a loaded machine, but tight enough that a regression back to
// O(n^2) behavior fails loudly rather than merely showing up in a benchmark
// nobody runs in CI.
test('lowering performance: a large function body parses in near-linear time, not quadratic', () => {
  const STATEMENTS = 8000;
  let body = 'void f(int n) {\n';
  for (let i = 0; i < STATEMENTS; i++) body += `  int x${i} = n;\n`;
  body += '}\n';

  const t0 = Date.now();
  const ir = parseCppFile('perf.cpp', body);
  const elapsedMs = Date.now() - t0;

  const assigns = nodesOf(ir).filter(n => n.kind === 'assign');
  assert.equal(assigns.length, STATEMENTS, 'every statement must still be lowered, not just fast');
  assert.ok(elapsedMs < 5000,
    `expected 8000 statements to parse in well under 5s (quadratic behavior took ~3.6s at 5000 ` +
    `statements pre-fix and would take tens of seconds here); took ${elapsedMs}ms`);
});

// ── regression: C++14 digit separators must not be read as char literals ─────
// `'` was unconditionally a char-literal opener, so `1'000'000` started a
// "literal" that blanked everything up to the next quote anywhere later in
// the file — silently deleting whole functions while the file still counted
// as parsed. Measured on Godot's editor/editor_node.cpp: 298 functions with
// the bug, 302 with it fixed (and 302 for a control copy with the separators
// textually removed).
test('parseCppFile: a C++14 digit separator does not swallow the functions that follow it', () => {
  const code = [
    "int limit = 1'000'000;",
    "int mask = 0xFF'FF;",
    'void handle(char* p) {',
    '  system(p);',
    '}',
  ].join('\n');
  const ir = parseCppFile('sep.cpp', code);
  assert.deepEqual(ir.functions.map(f => f.name), ['handle'],
    'the function after a digit-separated literal must still be found');
  assert.ok(nodesOf(ir).some(n => n.kind === 'call' && n.callee === 'system'),
    'its body must lower normally too');
});

test('parseCppFile: an ordinary char literal is still blanked as a literal', () => {
  const code = "void f(char c) {\n  if (c == '\"') { g(c); }\n}\n";
  const ir = parseCppFile('chr.cpp', code);
  assert.deepEqual(ir.functions.map(f => f.name), ['f']);
});

// ── regression: raw string literals must not desynchronise the blanker ──────
// `R"delim(...)delim"` was not modelled, so a raw string containing a `"` or
// `'` blanked from there to the next quote and yielded ZERO functions for the
// whole file.
test('parseCppFile: a raw string literal containing quotes does not lose the file', () => {
  const code = [
    'const char* q = R"(he said "hi" and it\'s fine)";',
    'void g(char* p) {',
    '  system(p);',
    '}',
  ].join('\n');
  const ir = parseCppFile('raw.cpp', code);
  assert.deepEqual(ir.functions.map(f => f.name), ['g'],
    'the function after a raw string must still be found');
});

test('parseCppFile: a delimited / prefixed raw string is handled too', () => {
  const code = [
    'const char* a = R"sql(SELECT ")sql";',
    'const char* b = u8R"(x")";',
    'void h(char* p) { system(p); }',
  ].join('\n');
  const ir = parseCppFile('raw2.cpp', code);
  assert.deepEqual(ir.functions.map(f => f.name), ['h']);
});

// ── performance regression: paren scanning and expression lowering ──────────
// Both bounds are wall-clock and generous; they exist so a return to the
// pre-fix algorithms fails loudly rather than being noticed only in a
// multi-million-line customer tree.
test('parseCppFile performance: unmatched parens do not go quadratic', () => {
  // Pre-fix: each `(` rescanned to EOF looking for its close, so 200k
  // unmatched parens took 32.9s. `_MAX_FUNCTIONS` does not bound this because
  // an unmatched paren pushes nothing into the result.
  const src = '('.repeat(200_000);
  const t0 = Date.now();
  parseCppFile('parens.cpp', src);
  const elapsedMs = Date.now() - t0;
  assert.ok(elapsedMs < 3000,
    `200k unmatched parens must parse in well under 3s (32.9s pre-fix); took ${elapsedMs}ms`);
});

test('parseCppFile performance: a long binary chain does not blow the stack', () => {
  // Pre-fix: `_lowerExpr` recursed once per term, so this threw RangeError
  // after 11.4s — the crash class ir/index.js's per-file guard now swallows.
  const chain = Array(20_000).fill('a').join('-');
  const t0 = Date.now();
  const ir = parseCppFile('chain.cpp', `void f(int a) {\n  int x = ${chain};\n}\n`);
  const elapsedMs = Date.now() - t0;
  assert.equal(ir.functions.length, 1, 'the function must survive, not be dropped by a thrown parse');
  assert.ok(elapsedMs < 3000,
    `a 20,000-term chain must lower in well under 3s (RangeError after 11.4s pre-fix); took ${elapsedMs}ms`);
});
