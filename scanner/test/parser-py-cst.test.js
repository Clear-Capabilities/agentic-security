// AST-backed Python parser tests.
//
// These exercise the constructs the regex parser explicitly drops (per its
// own comments): comprehensions, decorators, match statements, async/await,
// lambdas, nested calls in defaults, walrus, type hints. For each, we assert
// that the CST parser captures the function (even when its body's CFG is
// partial), where the regex parser would have dropped it entirely.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parsePythonFile as parsePythonFileCst,
  parsePythonFilesBatch,
  probePythonAvailable,
  _resetCapabilityCacheForTests,
} from '../src/ir/parser-py-cst.js';
import { parsePythonFile as parsePythonFileRegex } from '../src/ir/parser-py.js';
import { buildProjectIR } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';

const cap = probePythonAvailable();
const cstAvailable = cap.ok;

// Skip every test in this file when python3 isn't on the test machine.
// CI runners typically have it; if a contributor doesn't, the regex
// fallback covers them in production.
function _maybe(name, fn) {
  if (!cstAvailable) {
    test.skip(`${name} (skipped: ${cap.reason})`, () => {});
    return;
  }
  test(name, fn);
}

_maybe('capability probe reports the python version', () => {
  _resetCapabilityCacheForTests();
  const c = probePythonAvailable();
  assert.equal(c.ok, true);
  assert.match(c.version, /^3\.\d+\.\d+/);
});

_maybe('CST parser captures functions with decorators (regex parser drops)', () => {
  const code = `
@some_decorator
@another(with_args=True)
def handler(req):
    return req.body
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst, 'CST parser returned null');
  assert.equal(cst.functions.length, 1);
  assert.equal(cst.functions[0].name, 'handler');
  assert.deepEqual(cst.functions[0].params, ['req']);
});

_maybe('CST parser captures async def', () => {
  const code = `
async def fetch_user(req):
    user = await db.get(req.params.id)
    return user
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst);
  assert.equal(cst.functions.length, 1);
  assert.equal(cst.functions[0].name, 'fetch_user');
});

_maybe('CST parser captures functions with default-arg containing nested call', () => {
  // The regex parser's signature regex `\(([^)]*)\)` rejected this entirely.
  const code = `
def with_default(x=Foo(1, 2), y=None) -> str:
    return str(x) + str(y)
`;
  const cst = parsePythonFileCst('t.py', code);
  assert.ok(cst);
  assert.equal(cst.functions.length, 1);
  assert.equal(cst.functions[0].name, 'with_default');
  assert.deepEqual(cst.functions[0].params, ['x', 'y']);
});

_maybe('CST parser captures functions containing match statements', () => {
  const code = `
def route(req):
    match req.method:
        case "POST":
            return req.body
        case "GET":
            return req.query
        case _:
            return None
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst);
  assert.equal(cst.functions.length, 1);
  assert.equal(cst.functions[0].name, 'route');
});

_maybe('CST parser tracks taint through a list comprehension', () => {
  // `[x.upper() for x in req.body]` — the regex parser treats comprehensions
  // as opaque (per its comments). The CST parser surfaces the elt as an
  // array element so taint propagates.
  const code = `
def upper_all(req):
    result = [x.upper() for x in req.body]
    return result
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst);
  const fn = cst.functions[0];
  // The assign-from-comprehension node should exist with an array source.
  const nodes = Object.values(fn.cfg.nodes);
  const assignNode = nodes.find(n => n.kind === 'assign' && n.target === 'result');
  assert.ok(assignNode, 'expected an assign node for the comprehension result');
  assert.equal(assignNode.source.kind, 'array');
});

// #16 — end-to-end TAINT FLOW through constructs the docs once listed as "not
// modelled". The parser lowers them AND taint reaches the sink through them.
// (A variable-bound source → sink is the flow the deep engine resolves.)
_maybe('#16 taint flows through a match case body to a sink', () => {
  const code = `
def route(req):
    match req.path:
        case _:
            c = req.args.get("cmd")
            __import__("os").system(c)
`;
  const { perFile, callGraph } = buildProjectIR({ 'app.py': code });
  const f = runDeepAnalysis(perFile, callGraph, {});
  assert.ok(f.length >= 1, `expected a finding through the match case body, got ${f.length}`);
});

_maybe('#16 taint flows through a walrus binding to a sink', () => {
  const code = `
def h(req):
    if (c := req.args.get("x")):
        __import__("os").system(c)
`;
  const { perFile, callGraph } = buildProjectIR({ 'app.py': code });
  const f = runDeepAnalysis(perFile, callGraph, {});
  assert.ok(f.length >= 1, `expected a finding through the walrus binding, got ${f.length}`);
});

_maybe('CST parser captures nested function defs', () => {
  const code = `
def outer(req):
    def inner(x):
        return x.upper()
    return inner(req.body)
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst);
  const names = cst.functions.map(f => f.name).sort();
  assert.deepEqual(names, ['inner', 'outer']);
});

_maybe('regex parser drops the constructs CST captures', () => {
  // Demonstrates the gap CST closes. The regex parser's signature regex
  // bails on `def with_default(x=Foo(1, 2)):` — proves the original problem.
  const code = 'def with_default(x=Foo(1, 2)):\n    return x\n';
  const regex = parsePythonFileRegex('t.py', code);
  const cst = parsePythonFileCst('t.py', code);
  // CST should always return a function; regex may or may not depending on
  // whether the balanced-paren fix from earlier round handles this case.
  assert.ok(cst);
  assert.equal(cst.functions.length, 1);
  if (regex) {
    // If the regex parser DID capture it (after the earlier balanced-paren
    // fix), both should agree on the params. This guards against regression.
    assert.equal(regex.functions.length, 1, 'regex parser found ' + regex.functions.length + ' fns');
    assert.deepEqual(regex.functions[0].params, ['x']);
  }
});

_maybe('batch parser handles multiple files in one subprocess call', () => {
  const r = parsePythonFilesBatch([
    { file: 'a.py', content: 'def a(x):\n    return x\n' },
    { file: 'b.py', content: 'def b(y):\n    return y\n' },
    { file: 'c.py', content: 'async def c(z):\n    return z\n' },
  ]);
  assert.ok(Array.isArray(r));
  assert.equal(r.length, 3);
  const names = r.flatMap(e => e.functions.map(f => f.name)).sort();
  assert.deepEqual(names, ['a', 'b', 'c']);
});

_maybe('batch parser returns syntax error per-file without crashing the batch', () => {
  const r = parsePythonFilesBatch([
    { file: 'good.py', content: 'def good(x):\n    return x\n' },
    { file: 'broken.py', content: 'def broken(x:\n    return x\n' },     // unterminated signature
    { file: 'other-good.py', content: 'def other(y):\n    return y\n' },
  ]);
  assert.equal(r.length, 3);
  // Files with syntax errors get _error and no functions; the rest are intact.
  const broken = r.find(e => e.file === 'broken.py');
  assert.ok(broken._error, 'expected a syntax-error annotation');
  const good = r.find(e => e.file === 'good.py');
  assert.equal(good.functions.length, 1);
});

_maybe('batch parser ignores entries that are not .py files', () => {
  const r = parsePythonFilesBatch([
    { file: 'a.js', content: 'function a(x) { return x; }' },
    { file: 'b.py', content: 'def b(x):\n    return x\n' },
  ]);
  assert.equal(r.length, 1);
  assert.equal(r[0].file, 'b.py');
});

_maybe('parsePythonFile single-file shim mirrors the regex shape exactly', () => {
  const code = 'def f(req):\n    x = req.body\n    return x\n';
  const ir = parsePythonFileCst('app.py', code);
  // Top-level shape contract.
  assert.equal(ir.file, 'app.py');
  assert.equal(Array.isArray(ir.functions), true);
  assert.equal(ir.topLevel, null);
  const fn = ir.functions[0];
  // Per-function contract.
  assert.equal(typeof fn.qid, 'string');
  assert.equal(typeof fn.name, 'string');
  assert.equal(typeof fn.line, 'number');
  assert.equal(Array.isArray(fn.params), true);
  assert.equal(typeof fn.cfg, 'object');
  assert.equal(typeof fn.cfg.entry, 'string');
  assert.equal(typeof fn.cfg.exit, 'string');
  assert.equal(typeof fn.cfg.nodes, 'object');
});

_maybe('CST parser: destructuring assignment produces per-element assigns', () => {
  const code = `
def handler(request):
    a, b = request.form, request.args
    return b
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst);
  const nodes = Object.values(cst.functions[0].cfg.nodes);
  const assigns = nodes.filter(n => n.kind === 'assign' && n.target);
  const targets = assigns.map(n => n.target);
  assert.ok(targets.includes('a'), 'expected assign for destructured target "a"');
  assert.ok(targets.includes('b'), 'expected assign for destructured target "b"');
});

_maybe('CST parser: walrus operator tracks named binding', () => {
  const code = `
import re
def f(text):
    if (m := re.match(r"pat", text)):
        return m.group(0)
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst);
  const nodes = Object.values(cst.functions[0].cfg.nodes);
  const walrusAssign = nodes.find(n => n.kind === 'assign' && n.target === 'm');
  assert.ok(walrusAssign, 'expected a synthetic assign node for walrus target "m"');
  assert.equal(walrusAssign.source.kind, 'call');
});

_maybe('CST parser: match-case bodies are lowered as if-chain', () => {
  const code = `
def route(cmd):
    match cmd:
        case "start":
            return 1
        case "stop":
            return 0
        case other:
            return -1
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst);
  const nodes = Object.values(cst.functions[0].cfg.nodes);
  const ifNodes = nodes.filter(n => n.kind === 'if');
  assert.ok(ifNodes.length >= 3, `expected at least 3 if-nodes for match cases, got ${ifNodes.length}`);
  const returnNodes = nodes.filter(n => n.kind === 'return');
  assert.ok(returnNodes.length >= 3, 'expected at least 3 return nodes in match-case branches');
  const otherAssign = nodes.find(n => n.kind === 'assign' && n.target === 'other');
  assert.ok(otherAssign, 'expected assign for MatchAs capture "other"');
});

_maybe('CST parser: comprehension if-filters produce if nodes', () => {
  const code = `
def f(items):
    result = [x for x in items if x.valid]
    return result
`;
  const cst = parsePythonFileCst('app.py', code);
  assert.ok(cst);
  const nodes = Object.values(cst.functions[0].cfg.nodes);
  const loopAssign = nodes.find(n => n.kind === 'assign' && n.target === 'x');
  assert.ok(loopAssign, 'expected assign node for comprehension loop variable');
  const ifNode = nodes.find(n => n.kind === 'if');
  assert.ok(ifNode, 'expected if node for comprehension filter');
});
