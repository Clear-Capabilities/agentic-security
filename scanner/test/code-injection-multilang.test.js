// Cross-language code-injection detector (CWE-94) — Java/C#/Go/Kotlin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCodeInjectionMultilang as s } from '../src/sast/code-injection-multilang.js';

const fires = (fp, code) => s(fp, code).some((f) => f.cwe === 'CWE-94');
const clean = (fp, code) => s(fp, code).every((f) => f.cwe !== 'CWE-94');

test('Java — ScriptEngine.eval / Groovy / SpEL / MVEL on non-literal fire; literal clean', () => {
  assert.ok(fires('E.java', 'import javax.script.*;\nclass E { Object r(String c) throws Exception { return new ScriptEngineManager().getEngineByName("js").eval(c); } }'));
  assert.ok(fires('E.java', 'import groovy.lang.GroovyShell;\nclass E { Object r(String c){ return new GroovyShell().evaluate(c); } }'));
  assert.ok(fires('E.java', 'import org.springframework.expression.spel.standard.SpelExpressionParser;\nclass E { Object r(String c){ return new SpelExpressionParser().parseExpression(c).getValue(); } }'));
  assert.ok(fires('E.java', 'import org.mvel2.MVEL;\nclass E { Object r(String c){ return MVEL.eval(c); } }'));
  assert.ok(clean('E.java', 'import javax.script.*;\nclass E { Object r() throws Exception { return new ScriptEngineManager().getEngineByName("js").eval("1+1"); } }'));
  assert.ok(clean('E.java', 'class E { int add(int a,int b){ return a+b; } }'));
});

test('C# — CSharpScript.EvaluateAsync / DataTable.Compute on non-literal fire; literal clean', () => {
  assert.ok(fires('E.cs', 'using Microsoft.CodeAnalysis.CSharp.Scripting;\nclass E { async void r(string c){ await CSharpScript.EvaluateAsync(c); } }'));
  assert.ok(fires('E.cs', 'using System.Data;\nclass E { object r(string expr){ return new DataTable().Compute(expr, ""); } }'));
  assert.ok(clean('E.cs', 'using System.Data;\nclass E { object r(){ return new DataTable().Compute("1+1", ""); } }'));
  // Compute without a DataTable gate must not fire.
  assert.ok(clean('E.cs', 'class E { object r(string x){ return Helper.Compute(x); } }'));
});

test('Go — yaegi interp.Eval / template.Parse of non-literal fire; literal template clean', () => {
  assert.ok(fires('e.go', 'package main\nimport "github.com/traefik/yaegi/interp"\nfunc r(code string){ i := interp.New(interp.Options{}); i.Eval(code) }'));
  assert.ok(fires('e.go', 'package main\nimport "text/template"\nfunc r(in string, w io.Writer){ t,_ := template.New("x").Parse(in); t.Execute(w, nil) }'));
  assert.ok(clean('e.go', 'package main\nimport "text/template"\nfunc r(w io.Writer){ t,_ := template.New("x").Parse("hello {{.Name}}"); t.Execute(w, nil) }'));
  assert.ok(clean('e.go', 'package main\nfunc add(a,b int) int { return a+b }'));
});

test('Kotlin — ScriptEngine.eval / Groovy on non-literal fire', () => {
  assert.ok(fires('E.kt', 'import javax.script.ScriptEngineManager\nclass E { fun r(c: String): Any? { return ScriptEngineManager().getEngineByName("js").eval(c) } }'));
  assert.ok(fires('E.kt', 'import groovy.lang.GroovyShell\nclass E { fun r(c: String): Any? { return GroovyShell().evaluate(c) } }'));
});

test('non-target languages produce nothing', () => {
  // JS moved INTO scope — see the js branch below. Python is still handled by
  // the python-specific detectors, not here.
  assert.deepEqual(s('e.py', 'eval(user_input)'), []);
  assert.deepEqual(s('e.rb', 'eval(params[:x])'), []);
});

// --- JavaScript / TypeScript --------------------------------------------
//
// Added because the independent population measured CWE-94 at 0/6. The missed
// sink in GHSA-3769-jgqc-cxm7 was `vm.run(...)` — the NodeVM/vm2 family. eval
// and new Function were covered for BROWSER contexts elsewhere; a library whose
// entire purpose is executing supplied code was covered nowhere.

test('JS — the vm2 / NodeVM sandbox family fires on a non-literal', () => {
  // The shape from the advisory, verbatim in structure.
  assert.ok(fires('a.ts', 'const v = new NodeVM({});\nconst r = await v.run(`module.exports = async function(){${code}}()`, __dirname)'));
  assert.ok(fires('a.js', 'const { VM } = require("vm2"); new VM().run(userSrc)'));
});

test('JS — node:vm evaluators fire on a non-literal', () => {
  assert.ok(fires('a.js', 'vm.runInNewContext(userCode, ctx)'));
  assert.ok(fires('a.js', 'vm.runInThisContext(userCode)'));
  assert.ok(fires('a.js', 'const vm = require("vm"); const s = new vm.Script(userSrc);'));
});

test('JS — server-side eval and new Function fire', () => {
  assert.ok(fires('a.js', 'eval(req.body.expr)'));
  assert.ok(fires('a.js', 'const f = new Function(req.query.body)'));
});

test('JS — a LITERAL argument is not a sink, in any of the forms', () => {
  // The whole module rests on this: a hardcoded string is the developer's own
  // code, not injection. Losing it would make every vm/eval call a finding.
  assert.ok(clean('a.js', 'const { VM } = require("vm2"); new VM().run("1+1")'));
  assert.ok(clean('a.js', 'eval("1+1")'));
  assert.ok(clean('a.js', 'vm.runInNewContext("2+2", ctx)'));
});

test('JS — an unrelated .run() does not fire without a vm gate', () => {
  // `.run(` is far too common to match on its own; the gate is what makes this
  // safe to ship.
  assert.ok(clean('a.js', 'await migration.run(options)'));
  assert.ok(clean('a.js', 'await queue.run(job)'));
});
