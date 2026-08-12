import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseGoFile } from '../src/ir/parser-go.js';

test('parseGoFile: captures top-level func with params', () => {
  const code = `package main

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	db.Query("SELECT * FROM users WHERE id = " + id)
}
`;
  const ir = parseGoFile('main.go', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'handler');
  assert.ok(ir.functions[0].params.includes('w'));
  assert.ok(ir.functions[0].params.includes('r'));
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assigns = nodes.filter(n => n.kind === 'assign');
  assert.ok(assigns.some(a => a.target === 'id'), 'expected := assignment for id');
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.some(c => c.callee === 'db.Query'), 'expected db.Query call');
});

test('parseGoFile: captures method receiver', () => {
  const code = `package main

func (s *Server) Handle(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	return
}
`;
  const ir = parseGoFile('server.go', code);
  assert.ok(ir);
  assert.equal(ir.functions[0].name, 'Handle');
  assert.ok(ir.functions[0].params.includes('s'), 'receiver should be in params');
  assert.ok(ir.functions[0].params.includes('w'));
  assert.ok(ir.functions[0].params.includes('r'));
});

test('parseGoFile: handles defer and go statements as calls', () => {
  const code = `package main

func cleanup(db *sql.DB) {
	defer db.Close()
	go worker(db)
	return
}
`;
  const ir = parseGoFile('main.go', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.some(c => c.callee === 'db.Close'), 'defer should produce a call node');
  assert.ok(calls.some(c => c.callee === 'worker'), 'go should produce a call node');
});

test('parseGoFile: handles fmt.Sprintf as template literal', () => {
  const code = `package main

func greet(name string) string {
	msg := fmt.Sprintf("Hello, %s!", name)
	return msg
}
`;
  const ir = parseGoFile('main.go', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === 'msg');
  assert.ok(assign);
  assert.equal(assign.source.kind, 'tpl');
});

test('parseGoFile: handles var declaration with type', () => {
  const code = `package main

func f() {
	var name string = r.FormValue("name")
	db.Exec(name)
}
`;
  const ir = parseGoFile('main.go', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === 'name');
  assert.ok(assign, 'var declaration should produce assign node');
});

test('parseGoFile: multiple functions in one file', () => {
  const code = `package main

func a(x int) int {
	return x
}

func b(y string) string {
	return y
}
`;
  const ir = parseGoFile('main.go', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2);
  assert.equal(ir.functions[0].name, 'a');
  assert.equal(ir.functions[1].name, 'b');
});

test('parseGoFile: if statement produces branching CFG', () => {
  const code = `package main

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	if id != "" {
		db.Query("SELECT * FROM t WHERE id = " + id)
	} else {
		db.Query("SELECT * FROM t")
	}
	return
}
`;
  const ir = parseGoFile('main.go', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const ifNodes = nodes.filter(n => n.kind === 'if');
  assert.ok(ifNodes.length >= 1, `expected at least 1 if-node, got ${ifNodes.length}`);
  const ifNode = ifNodes[0];
  assert.ok(ifNode.succ.length >= 2, `if-node should have 2+ successors, got ${ifNode.succ.length}`);
});

test('parseGoFile: for-range produces loop-header with back-edge', () => {
  const code = `package main

func process(items []string) {
	for _, item := range items {
		fmt.Println(item)
	}
}
`;
  const ir = parseGoFile('main.go', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const headers = nodes.filter(n => n.kind === 'loop-header');
  assert.ok(headers.length >= 1, 'expected a loop-header node');
  const assigns = nodes.filter(n => n.kind === 'assign' && n.target === 'item');
  assert.ok(assigns.length >= 1, 'expected range variable assignment');
});

test('parseGoFile: returns null for non-Go files', () => {
  assert.equal(parseGoFile('app.js', 'function f(){}'), null);
});

test('parseGoFile: returns null for files with no functions', () => {
  const ir = parseGoFile('constants.go', 'package main\n\nconst X = 42\n');
  assert.equal(ir, null);
});

// Stage 3 correctness audit (detection depth, per-language-IR): _lowerExpr
// has TWO occurrences of the same "string concat with +" check. The first
// (near the top, after fmt.Sprintf) correctly guards on
// `_splitTopLevelPlus(s).length > 1` before mapping _lowerExpr over the
// parts. The second — reached when nothing else matched in between —  was
// missing that guard. When the `+` sits inside an extra pair of parens
// (`("SELECT " + name)`, e.g. an over-parenthesized call argument),
// _splitTopLevelPlus's depth tracking never returns to 0 at the `+`, so it
// returns the input UNCHANGED as one part — and `.map(_lowerExpr)` then
// recurses on the identical string forever. Same bug class, same fix, as
// the already-guarded C# `new Type(concat)` case (test/parser-cs-kt.test.js).
test('parseGoFile: a concat expression wrapped in an extra pair of parens does not recurse infinitely', () => {
  const code = `package main
func handle(name string) {
	db.Query(("SELECT " + name))
}
`;
  const ir = parseGoFile('app.go', code); // must not throw RangeError
  assert.ok(ir && ir.functions.length === 1);
});

test('parseGoFile: IR shape matches universal contract', () => {
  const code = `package main
func f(x int) int {
	y := x + 1
	return y
}
`;
  const ir = parseGoFile('test.go', code);
  assert.ok(ir);
  assert.equal(ir.file, 'test.go');
  assert.equal(ir.topLevel, null);
  const fn = ir.functions[0];
  assert.equal(typeof fn.qid, 'string');
  assert.equal(typeof fn.name, 'string');
  assert.equal(typeof fn.line, 'number');
  assert.ok(Array.isArray(fn.params));
  assert.equal(typeof fn.cfg, 'object');
  assert.equal(typeof fn.cfg.entry, 'string');
  assert.equal(typeof fn.cfg.exit, 'string');
  assert.equal(typeof fn.cfg.nodes, 'object');
  // Every node has kind, succ, pred
  for (const [, node] of Object.entries(fn.cfg.nodes)) {
    assert.ok(node.kind, 'node missing kind');
    assert.ok(Array.isArray(node.succ), 'node missing succ');
    assert.ok(Array.isArray(node.pred), 'node missing pred');
  }
});
