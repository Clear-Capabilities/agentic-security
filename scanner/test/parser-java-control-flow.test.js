import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJavaFile } from '../src/ir/parser-java.js';

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name.includes(fnName));
  assert.ok(fn, `expected a function matching "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}

// Method calls with an explicit receiver (`stmt.executeQuery(...)`) lower to
// a dotted callee ("stmt.executeQuery"), not the bare method name — this is
// established, pre-existing parser-java.js behavior (confirmed against the
// already-shipped `ifStatement` branch, and the same convention
// test/parser-go.test.js pins for Go's `db.Query`), unrelated to this task's
// new branches. Assertions below match against the dotted form for any call
// with a receiver.
function hasCallEndingIn(calls, suffix) {
  return calls.some(c => c.callee === suffix || c.callee?.endsWith(`.${suffix}`));
}

// A resource declaration in try-with-resources (`Statement stmt =
// conn.createStatement()`) lowers the same way any other local-variable
// declaration with an initializer does: one 'assign' CFG node whose
// `source` is the nested call expression, not a separate top-level 'call'
// node. This mirrors the pre-existing localVariableDeclarationStatement
// lowering elsewhere in parser-java.js.
function hasAssignedCallEndingIn(ir, fnName, suffix) {
  const fn = ir.functions.find(f => f.name.includes(fnName));
  assert.ok(fn, `expected a function matching "${fnName}"`);
  return Object.values(fn.cfg.nodes).some(n =>
    n.kind === 'assign' && n.source?.kind === 'call' &&
    (n.source.callee === suffix || n.source.callee?.endsWith(`.${suffix}`)));
}

test('parseJavaFile: a sink inside a for-loop body is captured', async () => {
  const code = `
public class C {
    public void run(String[] ids) throws Exception {
        java.sql.Statement stmt = null;
        for (String id : ids) {
            stmt.executeQuery(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  assert.ok(ir);
  const calls = callNodes(ir, 'run');
  assert.ok(hasCallEndingIn(calls, 'executeQuery'), 'expected an executeQuery call node inside the for-loop body');
});

test('parseJavaFile: a sink inside a basic (three-clause) for-loop body is captured', async () => {
  const code = `
public class C {
    public void run(String[] ids) throws Exception {
        java.sql.Statement stmt = null;
        for (int i = 0; i < ids.length; i++) {
            stmt.executeQuery(ids[i]);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(hasCallEndingIn(calls, 'executeQuery'));
});

test('parseJavaFile: a sink inside a plain try/catch/finally body is captured', async () => {
  const code = `
public class C {
    public void run(String id) {
        java.sql.Statement stmt = null;
        try {
            stmt.executeQuery(id);
        } catch (Exception e) {
            log(id);
        } finally {
            cleanup(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(hasCallEndingIn(calls, 'executeQuery'), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the catch-body call');
  assert.ok(calls.some(c => c.callee === 'cleanup'), 'expected the finally-body call');
});

test('parseJavaFile: a sink inside try-with-resources is captured (the idiomatic JDBC shape)', async () => {
  const code = `
public class C {
    public void run(java.sql.Connection conn, String id) throws Exception {
        try (java.sql.Statement stmt = conn.createStatement()) {
            stmt.executeQuery(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(hasCallEndingIn(calls, 'executeQuery'), 'expected the try-with-resources body sink');
  assert.ok(hasAssignedCallEndingIn(ir, 'run', 'createStatement'), 'expected the resource-opening call itself to be lowered');
});

test('parseJavaFile: a sink inside a switch-case body is captured', async () => {
  const code = `
public class C {
    public void run(int n, String id) {
        switch (n) {
            case 1:
                log(id);
                break;
            default:
                cleanup(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the case-1 body call');
  assert.ok(calls.some(c => c.callee === 'cleanup'), 'expected the default body call');
});

// R8 Task 1 fix round 1: arrow-form switch (`case 1 -> ...;`, Java 14+) is a
// structurally distinct CST rule (switchBlock.children.switchRule) from the
// colon-form this file's other switch test exercises
// (switchBlock.children.switchBlockStatementGroup) — Java's grammar allows
// either form but never mixes them in one switch block, so this needed its
// own branch, not a fallback off the existing one. Before this fix, arrow
// bodies were entirely unwalked (0 call nodes), degrading modern-Java
// switch expressions to regex-only detection.
test('parseJavaFile: a sink inside an arrow-form switch-case body is captured', async () => {
  const code = `
public class C {
    public void run(int n, String id) {
        switch (n) {
            case 1 -> log(id);
            default -> cleanup(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the arrow case-1 body call');
  assert.ok(calls.some(c => c.callee === 'cleanup'), 'expected the arrow default body call');
});

test('parseJavaFile: a sink inside a do-while body is captured', async () => {
  const code = `
public class C {
    public void run(String id) {
        int i = 0;
        do {
            log(id);
            i++;
        } while (i < 3);
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the do-while body call');
});

test('parseJavaFile: a sink inside a bare nested block (no keyword) is captured', async () => {
  const code = `
public class C {
    public void run(String id) {
        {
            log(id);
        }
    }
}
`;
  const ir = await parseJavaFile('C.java', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the bare-block body call');
});

test('parseJavaFile: an end-to-end runScan detects a source flowing through a for-loop into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-java-'));
  // This fixture is intra-procedural by design (source and sink live in the
  // same method), not the plan draft's cross-function `handle() -> run(ids)`
  // shape. Confirmed by direct probing during implementation: that
  // cross-function shape hits two separate, pre-existing, documented Java
  // IR gaps that are out of scope for this task —
  // (1) `fn.calls` is not populated for Java at all yet (scanner/src/ir/CLAUDE.md),
  //     so interprocedural taint across a call boundary never fires for
  //     Java regardless of this fix, and
  // (2) array-initializer syntax (`String[] ids = { expr };`) lowers to
  //     `{ kind: 'unknown' }` in `exprFromCst` (a different, unmodeled CST
  //     shape), so `ids` was never actually tainted in that fixture even
  //     before crossing the call boundary.
  // Using an intra-procedural flow isolates the capability this task
  // actually delivers: a sink reachable only through the newly-walked
  // for-loop body.
  fs.writeFileSync(path.join(dir, 'C.java'), `
public class C {
    public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt, String[] names) throws Exception {
        String id = req.getParameter("id");
        for (String n : names) {
            stmt.executeQuery(id);
        }
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for a sink inside a for-loop, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});

// R8 Task 1 fix round 1: this is the canonical R8 for-loop success-metric
// shape — a tainted COLLECTION reaching a sink through the loop variable,
// not (as the test above intentionally is) a variable tainted outside the
// loop that merely happens to be read inside a loop body over an unrelated
// collection. Before this fix, `for (T x : xs)` never bound `x` to `xs`, so
// even with the loop body now reachable in the CFG, `id` here carried no
// taint provenance and this produced zero IR-TAINT findings.
//
// The iterated array is tainted via the existing, already-registered
// `@RequestParam` annotation-source mechanism (R14(a)), applied to an
// array-typed parameter — deliberately NOT `req.getParameterValues(...)`
// (no catalog source entry for it) and NOT an array-initializer literal
// (`String[] ids = { req.getParameter("id") };`, which lowers to
// `{ kind: 'unknown' }` in exprFromCst — a separate, unrelated gap), so this
// test isolates the for-each variable-binding fix alone.
test('parseJavaFile: an end-to-end runScan detects a tainted collection flowing through its for-each loop variable into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-java-foreach-'));
  fs.writeFileSync(path.join(dir, 'C.java'), `
public class C {
    public void run(@RequestParam String[] ids, java.sql.Statement stmt) throws Exception {
        for (String id : ids) {
            stmt.executeQuery(id);
        }
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for a tainted collection reaching a sink via its for-each loop variable, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
