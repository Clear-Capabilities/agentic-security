// Java deep-taint recall.
//
// `bench/layer-recall` measured java at 0/25 IR-TAINT recall. The cause was not
// the catalog (7 Java sources, 15 Java sinks) and not the parser: it was the
// call site. `parser-java.js` exports an ASYNC `parseJavaFile` (java-parser
// needs a dynamic import), so the sync `buildProjectIR` has no Java branch at
// all — and the deep path called the sync builder. `buildProjectIRAsync` is a
// full mirror plus Java, and had zero callers anywhere in scanner/.
//
// Consequence: no .java file had ever produced an IR function in deep mode, so
// Java taint was structurally impossible rather than merely weak.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { buildProjectIR, buildProjectIRAsync } from '../src/ir/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (n) => path.join(__dirname, 'fixtures', n);

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-java-intraclass-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

async function deepScan(dir) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  }
}

const JAVA = `public class A {
  public void h(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {
    String q = req.getParameter("q");
    stmt.executeUpdate("SELECT * FROM t WHERE a = '" + q + "'");
  }
}
`;

test('the sync IR builder still has no Java branch (the documented split)', async () => {
  // Pins WHY the async path is required, so a future refactor that adds Java to
  // the sync builder has to update this deliberately rather than by accident.
  const { callGraph } = buildProjectIR({ 'A.java': JAVA });
  assert.equal([...callGraph.functions.values()].length, 0);
});

test('the async IR builder produces Java functions', async () => {
  const { callGraph } = await buildProjectIRAsync({ 'A.java': JAVA });
  assert.ok([...callGraph.functions.values()].length > 0,
    'java-parser must yield at least one function');
});

test('IR-TAINT: a java request param flowing into executeUpdate is reported', async () => {
  const taint = (await deepScan(FIX('java-taint-flow/vulnerable')))
    .filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /sql/i.test(`${f.vuln} ${f.cwe}`)),
    `expected an IR-TAINT SQL finding for Java, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: the same java sink with a constant does not fire', async () => {
  const taint = (await deepScan(FIX('java-taint-flow/clean')))
    .filter(f => f.parser === 'IR-TAINT');
  assert.equal(taint.filter(f => /sql/i.test(`${f.vuln} ${f.cwe}`)).length, 0,
    `constant-built SQL must not produce an IR-TAINT finding, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// Every other IR frontend (parser-js.js, parser-py-cst.js, ...) computes a
// real source line for every node — parser-java.js hardcoded `line: 0`
// everywhere (buildCfgFromBody was always called with a literal `0`, and
// every `emit()` call site used `line || 0`), contradicting its own module
// header's "The implementation is line-aware" claim. A finding at line 0
// can never be suppressed (agentic-security-ignore matches on a real line
// number — see the root CLAUDE.md suppression-pragma bullet) and is
// misattributed for anything that reads f.line (IDE gutter markers,
// PR-comment file:line links, this exact fixture's sink on line 8).
test('IR-TAINT: a java finding is attributed to its real source line, not 0', async () => {
  const taint = (await deepScan(FIX('java-taint-flow/vulnerable')))
    .filter(f => f.parser === 'IR-TAINT' && /sql/i.test(`${f.vuln} ${f.cwe}`));
  assert.ok(taint.length > 0, 'expected at least one Java IR-TAINT SQL finding');
  for (const f of taint) {
    assert.notEqual(f.line, 0, `finding at file ${f.file} must not be attributed to line 0`);
  }
  assert.ok(taint.some(f => f.line === 8), `expected a finding at the real sink line (8), got: ${taint.map(f => f.line).join(', ')}`);
});

// Java qids omitted the line number every other frontend includes
// (parser-js.js's qid ends `@${line}`), so two overloaded methods with the
// same name in the same class collided in callgraph.js's `functions` Map —
// the second declaration silently overwrote the first, dropping its CFG
// (and any vulnerability inside it) from the IR entirely.
test('two overloaded Java methods with the same name both survive into the call graph', async () => {
  const src = `public class A {
  public void h(java.sql.Statement stmt) throws Exception {
    stmt.executeUpdate("SELECT 1");
  }
  public void h(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {
    String q = req.getParameter("q");
    stmt.executeUpdate("SELECT * FROM t WHERE a = '" + q + "'");
  }
}
`;
  const { buildProjectIRAsync } = await import('../src/ir/index.js');
  const { callGraph } = await buildProjectIRAsync({ 'A.java': src });
  const fns = [...callGraph.functions.values()].filter(f => f.file === 'A.java');
  assert.equal(fns.length, 2, `expected both overloads to survive, got ${fns.length}: ${fns.map(f => f.qid).join(', ')}`);
});

// Taint-engine PRD P1 — the real payoff of callgraph.js's bare-tail
// resolution fix: a private-helper delegation (the single most idiomatic
// Java call shape) now carries interprocedural taint end to end, not just
// an unresolved edge.
//
// Sink deliberately uses a pre-bound receiver (`stmt.executeUpdate(query)`),
// not a chained call like `Runtime.getRuntime().exec(x)` — parser-java.js
// has a SEPARATE, pre-existing bug where a chained call's outer invocation
// is dropped from the CFG entirely (only the inner call survives, with its
// own empty arg list), confirmed by direct inspection while writing this
// test and unrelated to the intra-class resolution fix these tests cover.
// Logged as a real, separate finding — not fixed here, to keep this task
// scoped to the resolution bug it was written for.
test('IR-TAINT: tainted data flows through a same-class bare-call helper into a sink', async () => {
  const dir = mkTmp('bare', {
    'App.java': `
public class App {
  void buildQuery(String id, java.sql.Statement stmt) throws Exception {
    stmt.executeUpdate("SELECT * FROM t WHERE id=" + id);
  }
  void handler(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {
    String id = req.getParameter("id");
    buildQuery(id, stmt);
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /sql/i.test(`${f.vuln} ${f.cwe}`)),
    `expected buildQuery(id, stmt) called bare from handler to fire SQL Injection via IR-TAINT, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: tainted data flows through a this.-qualified same-class call into a sink', async () => {
  const dir = mkTmp('this', {
    'App.java': `
public class App {
  void buildQuery(String id, java.sql.Statement stmt) throws Exception {
    stmt.executeUpdate("SELECT * FROM t WHERE id=" + id);
  }
  void handler(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {
    String id = req.getParameter("id");
    this.buildQuery(id, stmt);
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /sql/i.test(`${f.vuln} ${f.cwe}`)),
    `expected this.buildQuery(id, stmt) called from handler to fire SQL Injection via IR-TAINT, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// Taint-recall PRD (80%): `(String) xp.evaluate(...)` — a reference-type cast
// wrapping a sink call as a return value — fell through exprFromCst's
// generic "recurse the first child" branch, which for a castExpression's
// shape hit its own raw LBrace token first (sorted before the actual
// operand in the CST's key order) and corrupted the parse into
// `{kind:'ident', name:'('}`, silently losing the entire call and its
// tainted argument. Confirmed against the real corpus fixture
// (CVE-2018-1320-xpath-injection). Casts are semantically transparent for
// taint purposes.
test('IR-TAINT: a reference-type cast wrapping a sink call as a return value does not corrupt the parse', async () => {
  const dir = mkTmp('cast-ref', {
    'Lookup.java': `
import javax.xml.xpath.*;
import org.w3c.dom.Document;
public class Lookup {
  public String find(Document doc, String name) throws Exception {
    XPath xp = XPathFactory.newInstance().newXPath();
    return (String) xp.evaluate("//user[@name='" + name + "']", doc, XPathConstants.STRING);
  }
  void handler(javax.servlet.http.HttpServletRequest req, Document doc) throws Exception {
    XPath xp = XPathFactory.newInstance().newXPath();
    find(doc, req.getParameter("name"));
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected an XPath Injection finding through the cast expression, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: a primitive-type cast wrapping a sink call as a return value does not corrupt the parse', async () => {
  const dir = mkTmp('cast-prim', {
    'Calc.java': `
public class Calc {
  int update(String id, java.sql.Statement stmt) throws Exception {
    return (int) stmt.executeUpdate("SELECT * FROM t WHERE id=" + id);
  }
  void handler(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {
    update(req.getParameter("id"), stmt);
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /sql/i.test(`${f.vuln} ${f.cwe}`)),
    `expected a SQL Injection finding through the primitive-type cast, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// Taint-recall PRD (80%): java-parser models a chained call
// (`X().Y().Z(tainted)`) as one `primary` node with a FLAT array of
// primarySuffix entries (each either a call `(...)` or a `.member` access,
// in source order). exprFromCst's old code grabbed only the FIRST
// methodInvocationSuffix in that array via `.find(Boolean)` and stopped —
// `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(s)`
// collapsed to just `newInstance()`, args: [], silently dropping
// `.newDocumentBuilder().parse(s)` (and its tainted argument) entirely.
// This is the SAME defect class as the earlier-documented, never-fixed
// `Runtime.getRuntime().exec(...)` gap (ir/CLAUDE.md) — confirmed here to
// now resolve correctly, though note: Runtime.exec's OWN corpus entry
// remains separately blocked by an unrelated, pre-existing precision
// filter (literalSkeletonMatchesFamily's _SHELL_META check requires the
// STATIC portion of a concat to contain a shell metacharacter — `"ping "
// + host` has none, so CWE-78 findings on this exact realistic shape are
// filtered regardless of taint; out of scope for this fix, not touched).
test('IR-TAINT: a 2-level chained call (X().Y(tainted)) resolves the OUTER call, not just the first invocation in the chain', async () => {
  const dir = mkTmp('chain2', {
    'Parser.java': `
import javax.xml.parsers.*;
import org.springframework.web.bind.annotation.RequestBody;
public class Parser {
  public org.w3c.dom.Document parse(java.io.InputStream xml) throws Exception {
    return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml);
  }
  void handler(@RequestBody java.io.InputStream xml) throws Exception {
    parse(xml);
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /xxe/i.test(`${f.vuln} ${f.cwe}`)),
    `expected an XXE finding through the 3-level chain, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: a chained call where a NEW SqlCommand() constructor starts the chain resolves the outer call', async () => {
  const dir = mkTmp('chain-new', {
    'Query.java': `
public class Query {
  Object run(String expr) throws Exception {
    return new org.springframework.expression.spel.standard.SpelExpressionParser().parseExpression(expr).getValue();
  }
  void handler(javax.servlet.http.HttpServletRequest req) throws Exception {
    run(req.getParameter("expr"));
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /code injection/i.test(f.vuln)),
    `expected a Code Injection finding through the new-expression-started chain, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// SARD_AGENTIC_SECURITY_PRD.md bench work (bench/sard/scripts/
// analyze-errors.mjs) clustered Java false negatives by Juliet's own
// filename descriptor and found "console_readLine" as one of the largest
// clusters, spanning multiple unrelated CWEs — the signature of a missing
// SOURCE model, confirmed by grep: catalog.js had no `readLine` entry at
// all before this. Real-world relevant (any CLI tool reading interactive
// input), not SARD-specific.
test('IR-TAINT: BufferedReader.readLine() flowing into Runtime.exec is reported', async () => {
  const dir = mkTmp('readline-source', {
    'App.java': `
import java.io.*;
public class App {
  void handler() throws Exception {
    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
    String cmd = br.readLine();
    Runtime.getRuntime().exec(cmd);
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /command injection/i.test(f.vuln)),
    `expected a Command Injection finding from BufferedReader.readLine(), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// Same bench work found "database" (ResultSet-sourced values) as another
// large, multi-CWE false-negative cluster. Scoped to a resolved
// ResultSet-shaped receiver (receiverTypeIn) rather than left bare, since
// `getString`/`getObject` are common enough method names elsewhere that an
// unscoped match would be a real precision risk.
test('IR-TAINT: ResultSet.getString() flowing into executeUpdate is reported (second-order SQLi)', async () => {
  const dir = mkTmp('resultset-source', {
    'App.java': `
import java.sql.*;
public class App {
  void handler(Statement stmt) throws Exception {
    ResultSet rs = stmt.executeQuery("SELECT name FROM users");
    String name = rs.getString("name");
    stmt.executeUpdate("SELECT * FROM t WHERE n = '" + name + "'");
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /sql/i.test(`${f.vuln} ${f.cwe}`)),
    `expected a SQL Injection finding from ResultSet.getString(), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// NOT a precision guarantee — a documented CURRENT LIMITATION, pinned so it
// can't regress silently in the other direction (a future engine change
// making `getString()` NEWLY receiver-type-aware without anyone noticing
// this test's assumption flipped). `java-resultset-getstring`'s
// `receiverTypeIn: ['resultset']` LOOKS like a precision scope but is
// actually inert today: class-hierarchy.js's CHA is JS/TS-only (walks Babel
// ASTs), so `_receiverTypeFor` returns null for any Java call site and
// `_receiverTypeAllowed`'s documented "unknown != clean" rule then permits
// the match regardless of the receiver's real type. Confirmed here with a
// receiver (`Config.Properties`) that is unambiguously NOT a ResultSet —
// the source still fires. If Java ever gains CHA support, this test should
// be revisited (and would then need to assert the OPPOSITE).
test('IR-TAINT: getString() fires regardless of receiver type today (Java has no CHA yet — documented limitation, not a target)', async () => {
  const dir = mkTmp('resultset-precision', {
    'App.java': `
public class Config {
  static class Properties {
    String getString(String key) { return "default"; }
  }
  void handler(java.sql.Statement stmt) throws Exception {
    Properties p = new Properties();
    String name = p.getString("name");
    stmt.executeUpdate("SELECT * FROM t WHERE n = '" + name + "'");
  }
}
`,
  });
  const taint = (await deepScan(dir)).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /sql/i.test(`${f.vuln} ${f.cwe}`)),
    `expected getString() to still fire (Java receiver-type scoping is currently inert), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
