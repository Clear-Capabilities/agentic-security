import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJavaFile } from '../src/ir/parser-java.js';

// Expression-statement assignments (`data = source();`) are the canonical
// Java shape for anything declared first and assigned later: a `String data;`
// declaration followed by `data = ...;` in a branch, a field write, a
// compound `+=`. Before this file existed, parser-java.js lowered ONLY the
// initializer of a localVariableDeclaration to an assign node, so every
// expression-statement assignment produced no CFG node at all and the taint
// walker never saw the source. Pinned per shape below.

async function fnNodes(code, fnName) {
  const ir = await parseJavaFile('A.java', code);
  const fn = ir.functions.find(f => f.name.includes(fnName));
  assert.ok(fn, `expected a function matching "${fnName}"`);
  return Object.values(fn.cfg.nodes);
}

function assigns(nodes) { return nodes.filter(n => n.kind === 'assign'); }
function calls(nodes) { return nodes.filter(n => n.kind === 'call'); }

test('bare `x = expr;` statement lowers to an assign node', async () => {
  const nodes = await fnNodes(`
public class A {
  void m() {
    String data;
    data = "";
    data = System.getenv("ADD");
  }
}`, 'm');
  const a = assigns(nodes).filter(n => n.target === 'data');
  assert.equal(a.length, 3, 'declaration + two statement assigns');
  assert.equal(a[1].source.kind, 'literal');
  assert.equal(a[2].source.kind, 'call');
  assert.equal(a[2].source.callee, 'System.getenv');
  assert.equal(a[2].line, 6);
});

test('assignment inside an if/else body is lowered', async () => {
  const nodes = await fnNodes(`
public class A {
  void m() {
    String data;
    if (IO.staticTrue) {
      data = System.getenv("ADD");
    } else {
      data = null;
    }
    sink(data);
  }
}`, 'm');
  const a = assigns(nodes).filter(n => n.target === 'data' && n.source.kind === 'call');
  assert.equal(a.length, 1);
  assert.equal(a[0].source.callee, 'System.getenv');
});

test('static field and this.field writes lower with both the qualified and bare target', async () => {
  const nodes = await fnNodes(`
public class A {
  private static String sf;
  private String inst;
  void m(String data) {
    sf = data;
    this.inst = data;
    A.sf = data;
  }
}`, 'm');
  const targets = assigns(nodes).map(n => n.target);
  assert.ok(targets.includes('sf'), `bare static field write; got ${targets}`);
  assert.ok(targets.includes('inst'), `bare alias of this.field write; got ${targets}`);
  assert.ok(targets.includes('this.inst'), `qualified this.field write; got ${targets}`);
  assert.ok(targets.includes('A.sf'), `class-qualified static write; got ${targets}`);
});

test('compound `+=` lowers to an assign whose source carries the target and rhs', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(String data) {
    String out = "";
    out += data;
  }
}`, 'm');
  const a = assigns(nodes).filter(n => n.target === 'out');
  assert.equal(a.length, 2);
  const src = a[1].source;
  assert.equal(src.kind, 'tpl');
  assert.ok(src.parts.some(p => p.kind === 'ident' && p.name === 'out'));
  assert.ok(src.parts.some(p => p.kind === 'ident' && p.name === 'data'));
});

test('array element write taints the whole array; element read lowers to the array', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(String data) {
    String[] arr = new String[5];
    arr[2] = data;
    String d = arr[2];
  }
}`, 'm');
  const a = assigns(nodes);
  assert.ok(a.some(n => n.target === 'arr' && n.source.kind === 'ident' && n.source.name === 'data'));
  const read = a.find(n => n.target === 'd');
  assert.ok(read);
  assert.equal(read.source.kind, 'ident');
  assert.equal(read.source.name, 'arr');
});

test('assignment nested inside a while condition is emitted before the loop header', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(java.io.BufferedReader r) throws Exception {
    String line = null;
    String data = "";
    while ((line = r.readLine()) != null) {
      data = line;
    }
  }
}`, 'm');
  const a = assigns(nodes).filter(n => n.target === 'line' && n.source.kind === 'call');
  assert.equal(a.length, 1, 'the assignment inside the loop condition');
  assert.equal(a[0].source.callee, 'r.readLine');
  const inner = assigns(nodes).find(n => n.target === 'data' && n.source.kind === 'ident');
  assert.ok(inner, 'loop body assign');
});

test('assignment nested inside an if condition is emitted', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(java.io.BufferedReader r) throws Exception {
    String line = null;
    if ((line = r.readLine()) != null) { use(line); }
  }
}`, 'm');
  const a = assigns(nodes).filter(n => n.target === 'line' && n.source.kind === 'call');
  assert.equal(a.length, 1);
});

test('(new X()).m(args) lowers to the class-qualified callee X.m', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(String data) {
    (new B()).badSink(data);
    new B().badSink2(data);
    B.staticSink(data);
  }
}`, 'm');
  const c = calls(nodes).map(n => n.callee);
  assert.ok(c.includes('B.badSink'), `got ${c}`);
  assert.ok(c.includes('B.badSink2'), `got ${c}`);
  assert.ok(c.includes('B.staticSink'), `got ${c}`);
  const first = calls(nodes).find(n => n.callee === 'B.badSink');
  assert.equal(first.args.length, 1);
  assert.equal(first.args[0].name, 'data');
  // A method call chained onto a constructor is NOT itself a constructor
  // call — isNew must not leak past the point a real invocation is made.
  assert.ok(!first.isNew, 'chained method call must not carry isNew');
});

test('a bare `new X(args)` constructor call node carries isNew: true', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(String data) {
    A_81_base b = new A_81_bad();
    B c = new B(data);
  }
}`, 'm');
  const a = assigns(nodes);
  const b = a.find(n => n.target === 'b');
  assert.equal(b.source.kind, 'call');
  assert.equal(b.source.callee, 'A_81_bad');
  assert.equal(b.source.isNew, true);
  const c = a.find(n => n.target === 'c');
  assert.equal(c.source.isNew, true);
  assert.equal(c.source.args.length, 1);
});

test('parseJavaFile emits ir.classes with bases and fields', async () => {
  const ir = await parseJavaFile('A.java', `
public abstract class A_81_base { public abstract void action(String data); }
class A_81_bad extends A_81_base implements Runnable {
  private static String sf;
  private String inst, other;
  public void action(String data) {}
  public void run() {}
}`);
  assert.ok(Array.isArray(ir.classes), 'ir.classes must be present');
  const base = ir.classes.find(c => c.name === 'A_81_base');
  assert.ok(base);
  assert.deepEqual(base.bases, []);
  const bad = ir.classes.find(c => c.name === 'A_81_bad');
  assert.ok(bad);
  assert.deepEqual(bad.bases.sort(), ['A_81_base', 'Runnable']);
  assert.deepEqual(bad.fields.sort(), ['inst', 'other', 'sf']);
});

test('a local variable DECLARATION assign carries decl: true; a plain reassignment does not', async () => {
  const nodes = await fnNodes(`
public class A {
  void m() {
    String data = "";
    data = "x";
    for (String s : java.util.List.of("a")) { }
  }
}`, 'm');
  const decl = assigns(nodes).find(n => n.target === 'data' && n.source.value === '""');
  assert.ok(decl);
  assert.equal(decl.decl, true);
  const reassign = assigns(nodes).find(n => n.target === 'data' && n.source.value === '"x"');
  assert.ok(reassign);
  assert.ok(!reassign.decl, 'plain reassignment must not carry decl');
});

test('a fully-qualified constructor lowers to the simple class name with generics stripped', async () => {
  const nodes = await fnNodes(`
public class A {
  void m() {
    java.util.LinkedList<String> l = new java.util.LinkedList<String>();
    java.util.HashMap<Integer, String> h = new java.util.HashMap<Integer, String>();
  }
}`, 'm');
  const a = assigns(nodes);
  assert.equal(a.find(n => n.target === 'l').source.callee, 'LinkedList');
  assert.equal(a.find(n => n.target === 'h').source.callee, 'HashMap');
});

test('a local variable constructed as a concrete type resolves method calls to that concrete class (abstract-dispatch shape)', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(String data) {
    A_81_base b = new A_81_bad();
    b.action(data);
  }
}`, 'm');
  const c = calls(nodes).map(n => n.callee);
  assert.ok(c.includes('A_81_bad.action'), `expected the rewritten concrete-class callee, got ${c}`);
});

test('ambiguous constructed types (two distinct classes assigned to the same variable) are not rewritten', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(String data, boolean cond) {
    A_81_base b = new A_81_bad();
    if (cond) { b = new A_81_bad2(); }
    b.action(data);
  }
}`, 'm');
  const c = calls(nodes).map(n => n.callee);
  assert.ok(c.includes('b.action'), `ambiguous var must stay unrewritten, got ${c}`);
});

test('Juliet-shaped source reads all lower to assigns with a call source', async () => {
  const nodes = await fnNodes(`
public class A {
  void m(javax.servlet.http.HttpServletRequest request, java.util.Properties properties,
         java.io.BufferedReader readerBuffered, byte[] bytes, javax.servlet.http.Cookie[] cookies) throws Exception {
    String data;
    data = (String) request.getAttribute("x");
    data = readerBuffered.readLine();
    data = (String) properties.get("data");
    data = System.getProperty("user.home");
    data = cookies[0].getValue();
    data = request.getParameter("name");
    data = request.getQueryString();
    data = new String(bytes, "UTF-8");
    data = Integer.toString(5);
  }
}`, 'm');
  const srcs = assigns(nodes).filter(n => n.target === 'data' && n.source.kind === 'call').map(n => n.source.callee);
  for (const want of ['request.getAttribute', 'readerBuffered.readLine', 'properties.get', 'System.getProperty',
    'cookies.getValue', 'request.getParameter', 'request.getQueryString', 'String', 'Integer.toString']) {
    assert.ok(srcs.includes(want), `missing ${want} in ${srcs}`);
  }
});
