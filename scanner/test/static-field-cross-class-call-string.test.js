// Cross-class static-field call-string precision (SARD_80_F1 W5.48). Builds
// on field-taint-cross-method.test.js's SAME-CLASS static-field pass:
// Juliet's own Flow Variant 65-68 idiom splits the write and the read across
// TWO DIFFERENT CLASSES/FILES — `bad()`/`goodG2B()`/`goodB2G()` in class A
// each write A's OWN static field then immediately call THEIR OWN uniquely
// named sink method in class B (`badSink`/`goodG2BSink`/`goodB2GSink`).
//
// Before this fix, `engine.js`'s cross-class pass tracked only a per-CLASS
// union ("is this field EVER tainted anywhere in A"), so `goodG2BSink()` was
// seeded as tainted purely because `bad()` (a completely different caller
// chain) taints the same field elsewhere in the class — a real false
// positive on Juliet's own designated-safe variant, confirmed via a direct
// runFullScan reproduction against the real public-mirror shape
// (`connect_tcp_execute_68a.java`/`_68b.java`) showing `parser: 'IR-TAINT'`
// surviving at the goodG2BSink call site even after the independent
// structural-detector fix (W5.47, java-structural.js) correctly suppressed
// its own copy of the same finding.
//
// Every test asserts `parser === 'IR-TAINT'`: a pattern rule firing on the
// same line would otherwise mask a taint-layer miss.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { mkTestTmp } from './helpers/tmp.js';

async function scanFiles(files) {
  const dir = mkTestTmp('as-static-field-xclass-');
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  for (const [name, body] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, 'src', name), body);
  }
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
}

const sqli = (findings) => findings.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-89');

test('a static field read in a DIFFERENT class fires only for the caller that actually writes it tainted', async () => {
  const A = `import java.sql.*;
public class A {
    public static String data;
    public void bad() throws Exception {
        data = System.getenv("QUERY");
        new B().badSink();
    }
    public void goodG2B() throws Exception {
        data = "constant";
        new B().goodG2BSink();
    }
    public void goodB2G() throws Exception {
        data = "constant";
        new B().goodB2GSink();
    }
}
`;
  const B = `import java.sql.*;
public class B {
    public void badSink() throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + A.data + "'";
        Connection conn = null;
        Statement stmt = conn.createStatement();
        stmt.execute(query);
    }
    public void goodG2BSink() throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + A.data + "'";
        Connection conn = null;
        Statement stmt = conn.createStatement();
        stmt.execute(query);
    }
    public void goodB2GSink() throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + A.data + "'";
        Connection conn = null;
        Statement stmt = conn.createStatement();
        stmt.execute(query);
    }
}
`;
  const findings = await scanFiles({ 'A.java': A, 'B.java': B });
  const hits = sqli(findings);
  // Attribute by line ranges instead of method name (findings don't carry a
  // method name) — badSink spans lines 3-8, goodG2BSink 9-14, goodB2GSink 15-20.
  const inBadSink = hits.some((f) => f.line >= 3 && f.line <= 8);
  const inGoodG2BSink = hits.some((f) => f.line >= 9 && f.line <= 14);
  const inGoodB2GSink = hits.some((f) => f.line >= 15 && f.line <= 20);
  assert.ok(inBadSink, `expected badSink (the only caller that writes A.data tainted) to still fire: ${JSON.stringify(hits.map(f => f.line))}`);
  assert.ok(!inGoodG2BSink, `expected goodG2BSink (its only caller writes A.data as a literal) NOT to fire: ${JSON.stringify(hits.map(f => f.line))}`);
  assert.ok(!inGoodB2GSink, `expected goodB2GSink (its only caller writes A.data as a literal) NOT to fire: ${JSON.stringify(hits.map(f => f.line))}`);
});

test('a static field read with NO discoverable caller fails closed (stays tainted)', async () => {
  // No file anywhere calls B.origSink(); the cross-class pass cannot find a
  // caller to reason about at all, so it must keep the conservative,
  // pre-W5.48 behavior (seed as tainted) rather than silently going quiet.
  const A = `public class A {
    public static String data;
    public void bad() throws Exception {
        data = System.getenv("QUERY");
    }
}
`;
  const B = `import java.sql.*;
public class B {
    public void orphanSink() throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + A.data + "'";
        Connection conn = null;
        Statement stmt = conn.createStatement();
        stmt.execute(query);
    }
}
`;
  const findings = await scanFiles({ 'A.java': A, 'B.java': B });
  const hits = sqli(findings);
  assert.ok(hits.length >= 1, `expected fail-closed (still tainted) with no discoverable caller: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('a static field read reachable from BOTH a tainting and a non-tainting caller still fires (any caller taints)', async () => {
  const A = `public class A {
    public static String data;
    public void bad() throws Exception {
        data = System.getenv("QUERY");
        new B().sharedSink();
    }
    public void good() throws Exception {
        data = "constant";
        new B().sharedSink();
    }
}
`;
  const B = `import java.sql.*;
public class B {
    public void sharedSink() throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + A.data + "'";
        Connection conn = null;
        Statement stmt = conn.createStatement();
        stmt.execute(query);
    }
}
`;
  const findings = await scanFiles({ 'A.java': A, 'B.java': B });
  const hits = sqli(findings);
  assert.ok(hits.length >= 1, `expected the shared sink to still fire since one real caller (bad()) writes it tainted: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});
