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
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { buildProjectIR, buildProjectIRAsync } from '../src/ir/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (n) => path.join(__dirname, 'fixtures', n);

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
