// C# IR shapes found missing while working the SARD/Juliet C# corpus.
// Each case here is a synthetic reproduction of a documented Juliet flow
// variant, never corpus text: a parenthesised inline-instantiate-and-call
// statement (variants 51-54), a cast losing its operand, and the
// `using (T v = expr)` resource declaration hiding a constructor sink.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCSharpFile } from '../src/ir/parser-cs.js';

function bareTail(name) { return String(name || '').split('.').pop(); }
function nodesOf(ir, fnName) {
  const fn = ir.functions.find(f => bareTail(f.name) === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes);
}

test('parseCSharpFile: parenthesised `(new X()).M(arg)` statement lowers to a Class.Method call', () => {
  const code = `
public class A {
    public void Bad() {
        string data = Console.ReadLine();
        (new B()).BadSink(data);
    }
}
public class B { public void BadSink(string data) { Process.Start(data); } }
`;
  const ir = parseCSharpFile('A.cs', code);
  const calls = nodesOf(ir, 'Bad').filter(n => n.kind === 'call');
  const sink = calls.find(n => n.callee === 'B.BadSink');
  assert.ok(sink, `expected a B.BadSink call node, got ${JSON.stringify(calls.map(c => c.callee))}`);
  assert.deepEqual(sink.args, [{ kind: 'ident', name: 'data' }]);
});

test('parseCSharpFile: a cast `(string)o` lowers to its operand, not unknown', () => {
  const code = `
public class A {
    public void Bad() {
        object o = Console.ReadLine();
        string d = (string)o;
        string e = (string) o;
        Process.Start(d);
    }
}
`;
  const ir = parseCSharpFile('A.cs', code);
  const assigns = nodesOf(ir, 'Bad').filter(n => n.kind === 'assign');
  const d = assigns.find(n => n.target === 'd');
  const e = assigns.find(n => n.target === 'e');
  assert.deepEqual(d.source, { kind: 'ident', name: 'o' });
  assert.deepEqual(e.source, { kind: 'ident', name: 'o' });
});

test('parseCSharpFile: `using (T v = expr) {…}` emits an assign for the resource declaration before the body', () => {
  const code = `
public class A {
    public void Bad() {
        string q = Console.ReadLine();
        using (SqlConnection c = IO.GetDBConnection()) {
            using (SqlCommand cmd = new SqlCommand(q, c)) {
                cmd.ExecuteNonQuery();
            }
        }
    }
}
`;
  const ir = parseCSharpFile('A.cs', code);
  const assigns = nodesOf(ir, 'Bad').filter(n => n.kind === 'assign');
  const c = assigns.find(n => n.target === 'c');
  const cmd = assigns.find(n => n.target === 'cmd');
  assert.ok(c, 'expected an assign for the using-declared connection');
  assert.ok(cmd, 'expected an assign for the using-declared command');
  assert.equal(cmd.source.kind, 'call');
  assert.equal(cmd.source.callee, 'SqlCommand');
  assert.deepEqual(cmd.source.args[0], { kind: 'ident', name: 'q' });
  assert.equal(cmd.line, 6);
});

test('parseCSharpFile: `using var v = expr;` declaration form also emits an assign', () => {
  const code = `
public class A {
    public void Bad() {
        string q = Console.ReadLine();
        using var cmd = new SqlCommand(q, conn);
        cmd.ExecuteNonQuery();
    }
}
`;
  const ir = parseCSharpFile('A.cs', code);
  const assigns = nodesOf(ir, 'Bad').filter(n => n.kind === 'assign');
  const cmd = assigns.find(n => n.target === 'cmd');
  assert.ok(cmd, 'expected an assign for the using-var declaration');
  assert.equal(cmd.source.callee, 'SqlCommand');
});

test('parseCSharpFile: assigns survive inside try/catch/finally, lock, and switch bodies', () => {
  const code = `
public class A {
    public void Bad() {
        string data = "";
        try { data = Console.ReadLine(); } catch (IOException e) { data = "x"; } finally { data = data + "!"; }
        lock (this) { data = data + "?"; }
        switch (data) { case "a": data = "b"; break; default: data = "c"; break; }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('A.cs', code);
  const assigns = nodesOf(ir, 'Bad').filter(n => n.kind === 'assign' && n.target === 'data');
  assert.ok(assigns.length >= 7, `expected at least 7 data assigns, got ${assigns.length}`);
});

test('parseCSharpFile: ir.classes carries name, line, bases, and declared fields', () => {
  const code = `
using System;
namespace T {
public abstract class Base81 { public abstract void Action(string data); }
public class Impl81 : Base81, IDisposable {
    private static string sf;
    public string inst = "";
    protected int a, b;
    public string Name { get; set; }
    public override void Action(string data) { sf = data; }
    public void Dispose() { }
}
public struct Point { public int X; public int Y; }
}
`;
  const ir = parseCSharpFile('A.cs', code);
  assert.ok(Array.isArray(ir.classes), 'expected ir.classes');
  const byName = Object.fromEntries(ir.classes.map(c => [c.name, c]));
  assert.deepEqual(byName.Base81.bases, []);
  assert.equal(byName.Base81.line, 4);
  assert.deepEqual(byName.Impl81.bases, ['Base81', 'IDisposable']);
  assert.deepEqual([...byName.Impl81.fields].sort(), ['Name', 'a', 'b', 'inst', 'sf']);
  assert.deepEqual([...byName.Point.fields].sort(), ['X', 'Y']);
});

test('parseCSharpFile: generic base list is recorded by simple name', () => {
  const code = `
public class Repo<T> : BaseRepo<T>, IRepo<T> where T : class {
    private readonly List<T> items = new List<T>();
    public void Add(T x) { items.Add(x); }
}
`;
  const ir = parseCSharpFile('A.cs', code);
  const repo = ir.classes.find(c => c.name === 'Repo');
  assert.deepEqual(repo.bases, ['BaseRepo', 'IRepo']);
  assert.deepEqual(repo.fields, ['items']);
});

test('parseCSharpFile: declaration assigns carry decl:true, reassignments do not', () => {
  const code = `
public class A {
    public void Bad() {
        string data;
        data = "";
        string other = Console.ReadLine();
        var third = other;
        data = other;
        using (SqlCommand cmd = new SqlCommand(data, conn)) { cmd.ExecuteNonQuery(); }
        this.inst = data;
    }
}
`;
  const ir = parseCSharpFile('A.cs', code);
  const assigns = nodesOf(ir, 'Bad').filter(n => n.kind === 'assign');
  const byLine = Object.fromEntries(assigns.map(n => [n.line, n]));
  assert.equal(byLine[4].target, 'data');
  assert.equal(byLine[4].decl, true);
  assert.equal(byLine[4].source.kind, 'unknown');
  assert.equal(byLine[5].decl, undefined);
  assert.equal(byLine[6].decl, true);
  assert.equal(byLine[7].decl, true);
  assert.equal(byLine[8].decl, undefined);
  assert.equal(byLine[9].decl, true);
  assert.equal(byLine[9].target, 'cmd');
  assert.equal(byLine[10].target, 'this.inst');
  assert.equal(byLine[10].decl, undefined);
});
