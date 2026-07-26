// C/C++ integration: dispatch, cross-TU call resolution, class hierarchy, taint.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR, buildProjectIRAsync } from '../src/ir/index.js';
import { parseCppFile } from '../src/ir/parser-cpp.js';
import { buildClassHierarchy, resolveMethod } from '../src/ir/class-hierarchy.js';
import { matchSource, matchSinkOrSanitizer, CATALOG } from '../src/dataflow/catalog.js';

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

// Helper: find the C-specific entry for a callee. Asserting on `cpp-` ids is
// what keeps these tests non-vacuous — `getenv`, `system`, `popen` and
// `realpath` already match via other languages' entries, so a bare
// "something matched" assertion would pass with no new code at all.
function cppEntry(callee, kind) {
  return CATALOG.find(e =>
    e.language === 'cpp' &&
    e.kind === kind &&
    e.match && e.match.type === 'call' && e.match.callee === callee);
}

test('catalog: C/C++ sources exist as C-specific entries', () => {
  for (const callee of ['getenv', 'recv', 'recvfrom', 'read', 'fread', 'fgets', 'gets', 'scanf']) {
    const e = cppEntry(callee, 'source');
    assert.ok(e, `a cpp source entry for ${callee} must exist`);
    assert.ok(e.id.startsWith('cpp-'), `${callee} entry id must be namespaced cpp-`);
    assert.ok(e.provenance, `${callee} must declare a provenance`);
  }
});

test('catalog: non-colliding C sources are returned by matchSource', () => {
  // These four have no pre-existing entry under another language, so the C
  // entry is the one matchSource returns — a real end-to-end check.
  for (const callee of ['recv', 'recvfrom', 'fread', 'fgets']) {
    const hit = matchSource({ kind: 'call', callee, args: [] });
    assert.ok(hit, `${callee} must be a recognised source`);
    assert.equal(hit.kind, 'source');
    assert.equal(hit.language, 'cpp', `${callee} must resolve to the C entry`);
  }
});

test('catalog: C/C++ sinks exist as C-specific entries with the right CWE', () => {
  const cases = [
    ['system', 'CWE-78'], ['popen', 'CWE-78'], ['execl', 'CWE-78'],
    ['strcpy', 'CWE-120'], ['strcat', 'CWE-120'], ['sprintf', 'CWE-120'],
    ['memcpy', 'CWE-787'], ['fopen', 'CWE-22'], ['dlopen', 'CWE-114'],
  ];
  for (const [callee, cwe] of cases) {
    const e = cppEntry(callee, 'sink');
    assert.ok(e, `a cpp sink entry for ${callee} must exist`);
    assert.equal(e.vuln.cwe, cwe, `${callee} must carry ${cwe}`);
  }
});

test('catalog: the C sink is reachable through matchSinkOrSanitizer', () => {
  // matchSinkOrSanitizer returns ALL hits, so the C entry must be among them
  // even for a callee another language already claims.
  for (const callee of ['system', 'strcpy', 'memcpy']) {
    const hits = matchSinkOrSanitizer(callee);
    assert.ok(hits, `${callee} must match`);
    assert.ok(hits.some(h => h.language === 'cpp' && h.kind === 'sink'),
      `the cpp sink for ${callee} must be among the returned hits`);
  }
});

test('catalog: every C/C++ sink carries a complete vuln descriptor', () => {
  const cppSinks = CATALOG.filter(e => e.language === 'cpp' && e.kind === 'sink');
  assert.ok(cppSinks.length >= 9, 'expected at least nine C/C++ sinks');
  for (const s of cppSinks) {
    for (const key of ['name', 'severity', 'cwe', 'remediation']) {
      assert.ok(s.vuln && s.vuln[key], `${s.id}: vuln.${key} is required by the findings schema`);
    }
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(s.vuln.severity),
      `${s.id}: severity must be one of the five documented values`);
    assert.ok('argIndex' in s, `${s.id}: argIndex is required so the engine knows which argument matters`);
  }
});

test('catalog: C/C++ sanitizers exist and declare an effect', () => {
  // Only realpath() is listed — it genuinely canonicalises a path. snprintf()
  // and strncpy() bound copy LENGTH, not content, so they are deliberately
  // NOT sanitizers (see the comment above the C/C++ sanitizer block in
  // catalog.js): marking them so would make a truncated-but-still-malicious
  // payload read as sanitized.
  for (const callee of ['realpath']) {
    const e = cppEntry(callee, 'sanitizer');
    assert.ok(e, `a cpp sanitizer entry for ${callee} must exist`);
    assert.ok(e.effect, `${callee} must declare an effect`);
  }
  for (const callee of ['snprintf', 'strncpy']) {
    assert.ok(!cppEntry(callee, 'sanitizer'), `${callee} must NOT be marked as a sanitizer`);
  }
});

test('end-to-end: taint flows from a C++ source to a sink across the call graph', () => {
  const files = {
    'util.h': 'class Util {\npublic:\n  void execute(char* cmd);\n};\n',
    'util.cpp': 'void Util::execute(char* cmd) {\n  system(cmd);\n}\n',
    'main.cpp': 'void run(Util* u) {\n  char* p = getenv("CMD");\n  u->execute(p);\n}\n',
  };
  const { perFile, callGraph } = buildProjectIR(files);
  // The source is recognised at the assignment RHS.
  const runFn = perFile['main.cpp'].functions.find(f => f.name === 'run');
  const asg = Object.values(runFn.cfg.nodes).find(n => n.kind === 'assign' && n.target === 'p');
  assert.ok(matchSource(asg.source), 'getenv must be recognised as a source');
  // The sink is recognised inside the callee.
  const execFn = perFile['util.cpp'].functions[0];
  const sinkCall = Object.values(execFn.cfg.nodes).find(n => n.kind === 'call' && n.callee === 'system');
  assert.ok(sinkCall, 'system(cmd) must be lowered as a call node');
  const sinkHits = matchSinkOrSanitizer(sinkCall.callee);
  assert.ok(sinkHits, 'system must be a catalog sink');
  // `system` also matches other languages' entries (php-system, rb-system,
  // py-os-system*), so this task's own contribution is only proven by
  // requiring the cpp-language sink specifically to be among the hits.
  assert.ok(sinkHits.some(h => h.language === 'cpp' && h.kind === 'sink'),
    'the cpp-language sink for system must be among the returned hits');
  // The two are connected by a resolved call-graph edge.
  const edge = callGraph.edges.find(e => e.callee === execFn.qid);
  assert.ok(edge, 'the call from run() to Util::execute must resolve across files');
});

// ─── Regression: C entries must not fire on non-C/C++ files ────────────────
// A prior version of these catalog entries matched purely on callee name with
// no file-extension guard, so `getenv`/`system`/etc. matching a JS/PHP/Python
// call of the same name (already true for cross-language collisions like
// getenv/system/popen/realpath) is expected and fine — but the C-only names
// (`read`, `memcpy`, `sprintf`, `fopen`, `gets`, `scanf`, ...) have no
// pre-existing entry from another language, so before the file-scope guard
// they turned every `.read()` call in a JS file, or every `sprintf()`/
// `fopen()` call in ordinary PHP, into a recognised C source/sink. That is
// the false-positive regression this block guards against.
test('catalog language scoping: a JS .read() call is not treated as a C source', () => {
  const hit = matchSource({ kind: 'call', callee: 'read', args: [] }, 'stream.js');
  assert.equal(hit, null, 'read() in a .js file must not match the cpp source entry');
});

test('catalog language scoping: a .c file calling read() still matches the C source', () => {
  const hit = matchSource({ kind: 'call', callee: 'read', args: [] }, 'io.c');
  assert.ok(hit, 'read() in a .c file must still be recognised as a source');
  assert.equal(hit.language, 'cpp');
});

test('catalog language scoping: PHP sprintf() is not treated as a C buffer-overflow sink', () => {
  const hits = matchSinkOrSanitizer('sprintf', 'template.php');
  const cppHit = hits && hits.find(h => h.language === 'cpp' && h.kind === 'sink');
  assert.ok(!cppHit, 'sprintf() in a .php file must not match the cpp sink entry');
});

test('catalog language scoping: a .cpp file calling sprintf() still matches the C sink', () => {
  const hits = matchSinkOrSanitizer('sprintf', 'format.cpp');
  const cppHit = hits && hits.find(h => h.language === 'cpp' && h.kind === 'sink');
  assert.ok(cppHit, 'sprintf() in a .cpp file must still match the cpp sink entry');
  assert.equal(cppHit.vuln.cwe, 'CWE-120');
});

test('catalog language scoping: no file argument preserves prior unscoped behavior', () => {
  // Callers that don't pass a file (or older call sites not yet updated) must
  // see exactly the same result as before this guard existed.
  const hit = matchSource({ kind: 'call', callee: 'read', args: [] });
  assert.ok(hit, 'omitting the file argument must not suppress the cpp source match');
  assert.equal(hit.language, 'cpp');
});

test('end-to-end regression: an ordinary JS stream.read() produces no C-sourced finding', () => {
  // The exact snippet from the regression report. Before the file-scope
  // guard, cpp-read matched this and taint flowed into exec() as a
  // C-sourced finding even though nothing here is C/C++.
  const files = {
    'app.js': 'function g(stream){ const d = stream.read(); require("child_process").exec(d); }',
  };
  const { perFile } = buildProjectIR(files);
  const fn = perFile['app.js'].functions.find(f => f.name === 'g');
  const asg = fn && Object.values(fn.cfg.nodes).find(n => n.kind === 'assign' && n.target === 'd');
  if (asg) {
    const hit = matchSource(asg.source, 'app.js');
    assert.ok(!hit || hit.language !== 'cpp',
      'stream.read() in a .js file must not resolve to the cpp source entry');
  }
});
