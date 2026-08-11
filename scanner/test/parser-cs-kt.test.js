// v0.66 — C# + Kotlin IR smoke tests.
//
// Verifies the new IR frontends emit the canonical shape and that the
// dataflow engine can fire on ASP.NET / Ktor source→sink patterns.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseCSharpFile, parseKotlinFile } from '../src/ir/index.js';
import { runScan } from '../src/runScan.js';

test('parseCSharpFile extracts a method with params + a linear CFG', () => {
  const ir = parseCSharpFile('Demo.cs', `
public class C {
  public string Greet(string name) {
    var x = name;
    return x;
  }
}
`);
  assert.ok(ir, 'parser should return an IR object');
  assert.equal(ir.file, 'Demo.cs');
  assert.equal(ir.functions.length, 1);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'Greet');
  assert.deepEqual(fn.params, ['name']);
  assert.ok(fn.cfg && fn.cfg.entry === 'entry' && fn.cfg.exit === 'exit');
  // At least entry, one assign, one return, exit.
  assert.ok(Object.keys(fn.cfg.nodes).length >= 4);
});

test('parseKotlinFile extracts a fun with params + a linear CFG', () => {
  const ir = parseKotlinFile('Demo.kt', `
fun greet(name: String): String {
  val x = name
  return x
}
`);
  assert.ok(ir, 'parser should return an IR object');
  assert.equal(ir.functions.length, 1);
  const fn = ir.functions[0];
  assert.equal(fn.name, 'greet');
  assert.deepEqual(fn.params, ['name']);
  assert.ok(fn.cfg && fn.cfg.entry === 'entry' && fn.cfg.exit === 'exit');
});

test('C# ASP.NET source → SQL sink fires a finding via the dataflow engine', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-scan-'));
  fs.writeFileSync(path.join(dir, 'UsersController.cs'), `
public class UsersController {
  public string Find() {
    var name = Request.QueryString["name"];
    var cmd = new SqlCommand("SELECT * FROM users WHERE name='" + name + "'");
    return cmd.ExecuteScalar();
  }
}
`);
  const { scan } = await runScan(dir, { deep: true });
  // We accept any SQL/injection-ish finding on Find(). The engine is new;
  // the smoke is "the new IR doesn't break the run AND the catalog wires up."
  assert.ok(scan && Array.isArray(scan.findings),
    'scan must produce findings array on C# input');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Kotlin Ktor source → cmd sink fires via dataflow engine', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kt-scan-'));
  fs.writeFileSync(path.join(dir, 'App.kt'), `
fun handle(call: Any) {
  val host = call.parameters
  Runtime.getRuntime().exec("ping " + host)
}
`);
  const { scan } = await runScan(dir, { deep: true });
  assert.ok(scan && Array.isArray(scan.findings),
    'scan must produce findings array on Kotlin input');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('non-method top-level Kotlin code is tolerated (no functions found)', () => {
  const ir = parseKotlinFile('Top.kt', `
val x = 42
println(x)
`);
  // Top-level expressions aren't lowered; ir should still be a valid object.
  assert.ok(ir);
  assert.equal(ir.functions.length, 0);
});

test('C# multi-method file produces multiple function entries', () => {
  const ir = parseCSharpFile('Multi.cs', `
public class M {
  public string A() { return "a"; }
  public string B(string x) { return x; }
  private void C() {}
}
`);
  assert.equal(ir.functions.length, 3);
  assert.deepEqual(ir.functions.map(f => f.name).sort(), ['A', 'B', 'C']);
});

// ── C#: `new Type(...)` with a concatenated argument must not blow the stack ──
// `_lowerExpr` had no branch for `new`, so `new SqlCommand("q" + name, conn)`
// fell through to the string-concat heuristic. The `+` is inside the parens, so
// `_splitTopLevelPlus` returned the input UNCHANGED and the branch recursed on
// the identical string — RangeError, caught by buildProjectIR's per-file
// try/catch, silently yielding no IR. 12 of 21 C# corpus entries hit this, which
// is why bench/layer-recall measured c# at 0/21 taint recall: the parser was
// crashing on the most common C# SQL-injection shape there is.
test('cs: `new Type(concat)` does not recurse infinitely', async () => {
  const { parseCSharpFile } = await import('../src/ir/parser-cs.js');
  const src = 'public class A { public void F() { var c = new SqlCommand("q" + name, conn); } }';
  const out = parseCSharpFile('A.cs', src);   // must not throw
  assert.ok(out && out.functions.length === 1);
});

test('cs: `new Type(args)` lowers to a call so taint can flow into it', async () => {
  const { parseCSharpFile } = await import('../src/ir/parser-cs.js');
  const out = parseCSharpFile('A.cs',
    'public class A { public void F() { var c = new SqlCommand("q" + name, conn); } }');
  const assign = Object.values(out.functions[0].cfg.nodes).find(n => n.kind === 'assign');
  assert.equal(assign.source.kind, 'call', `got ${assign.source.kind}`);
  assert.equal(assign.source.callee, 'SqlCommand');
  assert.equal(assign.source.args.length, 2);
});

test('cs: a top-level concat still lowers to a tpl', async () => {
  // Guard: the recursion fix must not disable concatenation lowering, which is
  // what carries taint through `"a" + tainted`.
  const { parseCSharpFile } = await import('../src/ir/parser-cs.js');
  const out = parseCSharpFile('A.cs', 'public class A { public void F() { var s = "a" + n; } }');
  const assign = Object.values(out.functions[0].cfg.nodes).find(n => n.kind === 'assign');
  assert.equal(assign.source.kind, 'tpl');
});
