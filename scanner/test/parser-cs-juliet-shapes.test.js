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
