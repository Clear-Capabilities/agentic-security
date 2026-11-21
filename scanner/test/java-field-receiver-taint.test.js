// Java taint through the shapes of a service layer: a call on a FIELD whose declared type is a project class,
// an overloaded method chosen by arity, a lambda body inlined into its method, and the PostgreSQL CopyManager
// sink. Each positive case has a refusing twin, because every one of these widens what resolves.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIRAsync } from '../src/ir/index.js';
import { runTaintEngine } from '../src/dataflow/engine.js';
import { buildClassHierarchy, annotateRTA, classOfVar } from '../src/ir/class-hierarchy.js';

const VULN = `  public String run(String name) throws Exception { java.sql.Statement st = conn.createStatement(); st.executeQuery("SELECT " + name); return "ok"; }`;
const CLEAN = `  public String run(String name, int n) throws Exception { return "x"; }`;

async function flows(files) {
  const ir = await buildProjectIRAsync(files);
  const cha = buildClassHierarchy(ir.perFile, ir.callGraph);
  annotateRTA(cha, ir.perFile);
  const r = runTaintEngine(ir.perFile, ir.callGraph, { fileContents: files, _cha: cha });
  const list = Array.isArray(r) ? r : (r.findings || []);
  return { ir, cha, findings: list.filter((f) => f.cwe === 'CWE-89').map((f) => `${f.file}:${f.line}`) };
}
const res = (body, extra = '') => `import org.springframework.web.bind.annotation.*;
public class Res {
  protected final Svc svc;
${extra}
  @GetMapping("/x") public String export(@RequestParam String name) throws Exception { ${body} return "ok"; }
}`;
const svc = (...methods) => `public class Svc {\n${methods.join('\n')}\n}`;

test('a request parameter reaches a sink through a call on a field whose declared type is a project class', async () => {
  const { findings } = await flows({ 'Res.java': res('svc.run(name);'), 'Svc.java': svc(VULN) });
  assert.deepEqual([...new Set(findings)], ['Svc.java:2']);
});

test('the overload is chosen by arity, in either declaration order', async () => {
  const a = await flows({ 'Res.java': res('svc.run(name);'), 'Svc.java': svc(VULN, CLEAN) });
  const b = await flows({ 'Res.java': res('svc.run(name);'), 'Svc.java': svc(CLEAN, VULN) });
  assert.deepEqual([...new Set(a.findings)], ['Svc.java:2'], 'vulnerable overload declared first');
  assert.deepEqual([...new Set(b.findings)], ['Svc.java:3'], 'vulnerable overload declared second');
});

test('REFUSES: a call to the clean two-argument overload is not credited with the one-argument overload\'s sink', async () => {
  const { findings } = await flows({ 'Res.java': res('svc.run(name, 1);'), 'Svc.java': svc(VULN, CLEAN) });
  assert.deepEqual(findings, []);
});

test('this.field.method() resolves the same way', async () => {
  const { findings } = await flows({ 'Res.java': res('this.svc.run(name);'), 'Svc.java': svc(VULN, CLEAN) });
  assert.deepEqual([...new Set(findings)], ['Svc.java:2']);
});

test('REFUSES: a local that shadows the field, even an untyped one, blocks the field-type fallback', async () => {
  const { ir, cha, findings } = await flows({ 'Res.java': res('Object svc = other(); svc.run(name);'), 'Svc.java': svc(VULN) });
  const fn = ir.perFile['Res.java'].functions.find((f) => /export/.test(f.name));
  assert.equal(classOfVar(cha, 'Res.java', fn.qid, 'svc'), 'Object', 'the local declaration wins');
  assert.deepEqual(findings, []);
});

test('REFUSES: a field of an unknown (library) type resolves to nothing', async () => {
  const { ir, cha } = await flows({ 'Res.java': `public class Res { protected final Foo svc; public String export(String name) { svc.run(name); return "ok"; } }` });
  const fn = ir.perFile['Res.java'].functions[0];
  assert.equal(classOfVar(cha, 'Res.java', fn.qid, 'svc'), 'Foo');
  assert.equal(ir.callGraph.resolveKnownCallee('Foo.run', 'Res.java', 1), null);
});

test('same-class overloads: the arity picks the helper, in either order, and the clean arity stays clean', async () => {
  const HV = `  String helper(String name) throws Exception { java.sql.Statement st = conn.createStatement(); st.executeQuery("SELECT " + name); return "ok"; }`;
  const HC = `  String helper(String name, int n) throws Exception { return "x"; }`;
  const a = await flows({ 'Res.java': res('helper(name);', HV + '\n' + HC) });
  const b = await flows({ 'Res.java': res('helper(name);', HC + '\n' + HV) });
  const c = await flows({ 'Res.java': res('helper(name, 1);', HV + '\n' + HC) });
  assert.deepEqual([...new Set(a.findings)], ['Res.java:4']);
  assert.deepEqual([...new Set(b.findings)], ['Res.java:5']);
  assert.deepEqual(c.findings, []);
});

test('a lambda body is lowered into the enclosing method: a captured request parameter reaches the sink inside it', async () => {
  const { ir, findings } = await flows({ 'Svc.java': `import org.springframework.web.bind.annotation.*;
public class Svc {
  @GetMapping("/x") public String export(@RequestParam String name) throws Exception {
    ex.schedule(() -> {
      String q = "SELECT " + name;
      java.sql.Statement st = conn.createStatement();
      st.executeQuery(q);
    }, 1, java.util.concurrent.TimeUnit.SECONDS);
    return "ok";
  }
}` });
  assert.deepEqual([...new Set(findings)], ['Svc.java:7']);
  const kinds = Object.values(ir.perFile['Svc.java'].functions[0].cfg.nodes).map((n) => n.kind);
  assert.ok(kinds.filter((k) => k === 'assign').length >= 2, 'the lambda block\'s declarations are CFG nodes');
});

test('an expression-bodied lambda and a lambda inside a lambda are both lowered', async () => {
  const { findings } = await flows({ 'Svc.java': `import org.springframework.web.bind.annotation.*;
public class Svc {
  @GetMapping("/x") public String export(@RequestParam String name) throws Exception {
    java.sql.Statement st = conn.createStatement();
    ex.submit(() -> ex.submit(() -> st.executeQuery("SELECT " + name)));
    return "ok";
  }
}` });
  assert.deepEqual([...new Set(findings)], ['Svc.java:5']);
});

test('REFUSES: a lambda parameter is not a tainted value (xs.forEach(s -> sink(s)) fabricates nothing)', async () => {
  const { findings } = await flows({ 'Svc.java': `public class Svc {
  public void export(java.util.List<String> xs) throws Exception {
    java.sql.Statement st = conn.createStatement();
    xs.forEach(s -> st.executeQuery("SELECT " + s));
  }
}` });
  assert.deepEqual(findings, []);
});

test('PostgreSQL CopyManager.copyOut and copyIn are SQL sinks; an unrelated copyOut is not', async () => {
  const body = (call) => `import org.springframework.web.bind.annotation.*;
public class Svc {
  @GetMapping("/x") public String export(@RequestParam String name) throws Exception {
    String q = "COPY (SELECT " + name + ") TO STDOUT";
    ${call}
    return "ok";
  }
}`;
  const out = await flows({ 'Svc.java': body('org.postgresql.copy.CopyManager copyManager = pg.getCopyAPI(); copyManager.copyOut(q, System.out);') });
  const inn = await flows({ 'Svc.java': body('pg.getCopyAPI().copyIn(q, System.in);') });
  const unrelated = await flows({ 'Svc.java': body('fileSync.copyOut(q, System.out);') });
  assert.deepEqual([...new Set(out.findings)], ['Svc.java:5']);
  assert.deepEqual([...new Set(inn.findings)], ['Svc.java:5']);
  assert.deepEqual(unrelated.findings, []);
});
