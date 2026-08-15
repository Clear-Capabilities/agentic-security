import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';
import { parseRubyFile } from '../src/ir/parser-rb.js';

// ── PHP parser ───────────────────────────────────────────────────────────────

test('parsePhpFile: captures function with params', () => {
  const code = `<?php
function getUser($id) {
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    return $result;
}
`;
  const ir = parsePhpFile('app.php', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'getUser');
  assert.deepEqual(ir.functions[0].params, ['$id']);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assigns = nodes.filter(n => n.kind === 'assign');
  assert.ok(assigns.some(a => a.target === '$result'), 'expected $result assignment');
});

test('parsePhpFile: captures class method with modifiers', () => {
  const code = `<?php
class UserController {
    public function show($request) {
        $name = $request->input('name');
        return $name;
    }
}
`;
  const ir = parsePhpFile('controller.php', code);
  assert.ok(ir);
  assert.equal(ir.functions[0].name, 'show');
  assert.deepEqual(ir.functions[0].params, ['$request']);
});

test('parsePhpFile: lowers method calls', () => {
  const code = `<?php
function process($data) {
    $db->query("INSERT INTO logs VALUES (" . $data . ")");
    return true;
}
`;
  const ir = parsePhpFile('app.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.length >= 1, 'expected a call node');
});

test('parsePhpFile: returns null for non-PHP files', () => {
  assert.equal(parsePhpFile('app.js', 'function f(){}'), null);
});

test('parsePhpFile: IR shape matches universal contract', () => {
  const code = `<?php
function f($x) {
    $y = $x + 1;
    return $y;
}
`;
  const ir = parsePhpFile('test.php', code);
  assert.ok(ir);
  assert.equal(ir.file, 'test.php');
  assert.equal(ir.topLevel, null);
  const fn = ir.functions[0];
  assert.equal(typeof fn.qid, 'string');
  assert.ok(Array.isArray(fn.params));
  assert.equal(typeof fn.cfg.nodes, 'object');
  for (const [, node] of Object.entries(fn.cfg.nodes)) {
    assert.ok(node.kind);
    assert.ok(Array.isArray(node.succ));
    assert.ok(Array.isArray(node.pred));
  }
});

// R14(b) final whole-branch review, Finding 1 (CRITICAL), function-body half:
// `_lowerExpr`'s dot-concat branch recursed on its own unchanged input
// forever whenever every `.` in the expression is nested inside
// brackets/quotes (e.g. an array literal with a dotted string value), since
// `_splitTopLevelDot` then returns the input as a single un-split part. This
// was always reachable from inside a function body, even before R14(b) — the
// module-level lowering (see parser-php-module-level.test.js) just widened
// its reach enormously. Same pattern as parser-cs.js's `new Type(concat)`
// stack-overflow guard.
test('parsePhpFile: an array literal with a dotted string value inside a function body does not recurse infinitely', () => {
  const code = `<?php
function getRoutes() {
    $routes = ["health" => "check.status"];
    return $routes;
}
`;
  const out = parsePhpFile('routes.php', code); // must not throw
  assert.ok(out && out.functions.length === 1);
});

test('parsePhpFile: a top-level concat still lowers to a tpl (the recursion guard must not disable real concatenation)', () => {
  const code = `<?php
function f($id) {
    $q = "SELECT * FROM t WHERE id=" . $id;
    return $q;
}
`;
  const out = parsePhpFile('concat.php', code);
  const assign = Object.values(out.functions[0].cfg.nodes).find(n => n.kind === 'assign');
  assert.equal(assign.source.kind, 'tpl');
});

// ── Ruby parser ──────────────────────────────────────────────────────────────

test('parseRubyFile: captures def with params', () => {
  const code = `
def show(id)
  user = User.find(id)
  return user
end
`;
  const ir = parseRubyFile('app.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'show');
  assert.deepEqual(ir.functions[0].params, ['id']);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assigns = nodes.filter(n => n.kind === 'assign');
  assert.ok(assigns.some(a => a.target === 'user'), 'expected user assignment');
});

test('parseRubyFile: captures def self.method', () => {
  const code = `
def self.find_by_name(name)
  sql = "SELECT * FROM users WHERE name = '" + name + "'"
  return User.find_by_sql(sql)
end
`;
  const ir = parseRubyFile('user.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions[0].name, 'find_by_name');
  assert.deepEqual(ir.functions[0].params, ['name']);
});

test('parseRubyFile: handles string interpolation', () => {
  const code = `
def greet(name)
  msg = "Hello, #{name}!"
  return msg
end
`;
  const ir = parseRubyFile('app.rb', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === 'msg');
  assert.ok(assign);
  assert.equal(assign.source.kind, 'tpl');
});

test('parseRubyFile: handles bare method calls', () => {
  const code = `
def create(params)
  cmd = params[:cmd]
  system cmd
  return
end
`;
  const ir = parseRubyFile('app.rb', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.some(c => c.callee === 'system'), 'expected system call node');
});

test('parseRubyFile: returns null for non-Ruby files', () => {
  assert.equal(parseRubyFile('app.js', 'function f(){}'), null);
});

test('parseRubyFile: multiple defs in one file', () => {
  const code = `
def a(x)
  return x
end

def b(y)
  return y
end
`;
  const ir = parseRubyFile('app.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2);
  assert.equal(ir.functions[0].name, 'a');
  assert.equal(ir.functions[1].name, 'b');
});

// ── Ruby: the first body statement must not be swallowed ────────────────────
// DEF_RE's `\s*` before the optional parameter list matched across the newline,
// so `m[0]` for `def show\n  c = params[:c]` ended at the next line's indent.
// `indexOf('\n', ...)` then found the newline at the END of the first statement,
// and the body was sliced from there — silently dropping statement 1 of EVERY
// Ruby method. In a Rails controller that statement is almost always the one
// that reads `params`, which is why bench/layer-recall measured Ruby at 0/20
// IR-TAINT recall while all 20 corpus entries passed on other layers.
test('rb: the first statement of a method body is lowered', async () => {
  const { parseRubyFile } = await import('../src/ir/parser-rb.js');
  const out = parseRubyFile('a.rb', 'def show\n  c = params[:c]\n  system(c)\nend\n');
  const kinds = Object.values(out.functions[0].cfg.nodes).map(n => n.kind);
  assert.ok(kinds.includes('assign'),
    `first statement dropped — got nodes: ${kinds.join(',')}`);
});

test('rb: a single-statement method body is not emptied', async () => {
  const { parseRubyFile } = await import('../src/ir/parser-rb.js');
  const out = parseRubyFile('a.rb', 'def show\n  b = 2\nend\n');
  const kinds = Object.values(out.functions[0].cfg.nodes).map(n => n.kind);
  assert.ok(kinds.includes('assign'), `body emptied — got nodes: ${kinds.join(',')}`);
});

test('rb: a method with a parameter list still parses its params and body', async () => {
  // Guard on the fix: DEF_RE must still reach `(a, b)` on the same line.
  const { parseRubyFile } = await import('../src/ir/parser-rb.js');
  const out = parseRubyFile('a.rb', 'def show(a, b)\n  c = a\n  system(c)\nend\n');
  const fn = out.functions[0];
  assert.deepEqual(fn.params, ['a', 'b']);
  const kinds = Object.values(fn.cfg.nodes).map(n => n.kind);
  assert.ok(kinds.includes('assign') && kinds.includes('call'), `got: ${kinds.join(',')}`);
});
