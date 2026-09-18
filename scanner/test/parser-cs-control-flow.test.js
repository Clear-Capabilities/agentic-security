// C# — R8 braced control-flow body recursion.
//
// Before this task, parseCSharpFile built a flat, single-pass CFG over
// top-level-split statements — control flow was never recursed into, so a
// sink inside an if/for/try/switch body was invisible to the taint engine.
// This file pins the new recursive `_buildCfg` (ported from parser-cpp.js's
// proven pattern), including the two highest-risk safety cases (a C#
// collection/object initializer and a lambda argument, both of which use
// `{}` for something that is NOT a control-flow body) and exact line-number
// attribution through a multi-line condition with an interleaved comment.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCSharpFile } from '../src/ir/parser-cs.js';

// Matches by bare tail, not exact equality: `fn.name` is class-qualified
// (`"ClassName.method"`, the same convention parser-java.js/parser-js.js
// already use) whenever the method sits inside a class — which every
// fixture in this file does — so an exact-name match would never find
// anything. These tests only care that a function named `fnName` exists
// with the right shape, not which class it's in.
function bareTail(name) { return String(name || '').split('.').pop(); }

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => bareTail(f.name) === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}

test('parseCSharpFile: a sink inside an if-block is captured, including a statement following it', () => {
  const code = `
public class C {
    public string Find(string id) {
        if (id != null) {
            var cmd = new SqlCommand("SELECT * FROM users WHERE id=" + id);
            db.Execute(cmd);
        }
        return null;
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const calls = callNodes(ir, 'Find');
  assert.ok(calls.some(c => c.callee === 'Execute' || c.callee === 'db.Execute'), 'expected the if-body sink call, got: ' + JSON.stringify(calls));
});

test('parseCSharpFile: a sink inside a for-loop body is captured', () => {
  const code = `
public class C {
    public void Run(string[] ids) {
        for (int i = 0; i < ids.Length; i++) {
            db.Execute(ids[i]);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee?.endsWith('Execute')));
});

test('parseCSharpFile: a sink inside a try/catch body is captured', () => {
  const code = `
public class C {
    public void Run(string id) {
        try {
            db.Execute(id);
        } catch (Exception e) {
            Log(id);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee?.endsWith('Execute')), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'Log'), 'expected the catch-body call');
});

test('parseCSharpFile: a sink inside a switch-case body is captured', () => {
  const code = `
public class C {
    public void Run(int n, string id) {
        switch (n) {
            case 1:
                Log(id);
                break;
            default:
                Cleanup(id);
                break;
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee === 'Log'));
  assert.ok(calls.some(c => c.callee === 'Cleanup'));
});

test('parseCSharpFile: a collection/object initializer is NOT mis-split by the new brace-aware recursion', () => {
  const code = `
public class C {
    public void Run() {
        var list = new List<int> { 1, 2, 3 };
        var opts = new Options { Name = "x", Value = 1 };
        Process(list, opts);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee === 'Process'), 'expected Process to be captured as one clean call, not fragmented by the collection/object initializer braces');
});

test('parseCSharpFile: a lambda passed as a call argument is NOT mis-split', () => {
  const code = `
public class C {
    public void Run(List<int> xs) {
        xs.ForEach(x => { Process(x); });
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  assert.ok(calls.some(c => c.callee === 'ForEach' || c.callee === 'xs.ForEach'), 'expected the ForEach call itself to be captured as one node');
});

test('parseCSharpFile: existing straight-line ASP.NET source-to-sink shape is unaffected', () => {
  const code = `
public class PingController {
    public string Ping([FromQuery] string host) {
        System.Diagnostics.Process.Start("ping", host);
        return "ok";
    }
}
`;
  const ir = parseCSharpFile('PingController.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Ping');
  assert.ok(fn);
  assert.deepEqual(fn.params, ['host']);
  assert.ok(fn.paramAnnotations);
  const calls = Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
  assert.ok(calls.length >= 1, 'expected the straight-line body to still lower correctly, unaffected by this task\'s recursive-builder rewrite');
});

test('parseCSharpFile: end-to-end runScan detects a source flowing through an if-block into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-cs-'));
  // The brief's illustrative version of this test used a bare `string id`
  // parameter with no annotation as the "source". Verified empirically
  // (not assumed) that this does NOT work for C# regardless of any CFG
  // change: the dataflow engine's C# entry-taint model only treats a
  // parameter as tainted when it carries a recognized framework
  // annotation (`[FromQuery]` etc., via `matchAnnotationParams` /
  // `_unionAnnotationTaint` — see `src/dataflow/CLAUDE.md`'s
  // `match.type: 'annotation'` section) or when the value itself is a
  // catalog-recognized source expression (`Request.QueryString[...]`,
  // as parser-cs-kt.test.js already uses). A bare unannotated param
  // produced ZERO findings even in a straight-line body with no control
  // flow at all — confirmed by direct comparison before touching this
  // test, so this is a pre-existing characteristic of the C# source
  // model, not a gap this task's CFG-recursion work is responsible for.
  // `[FromQuery]` is added here so this test actually exercises what it
  // claims to: a source flowing THROUGH the if-block's recursion into the
  // sink.
  fs.writeFileSync(path.join(dir, 'C.cs'), `
public class C {
    public void Run([FromQuery] string id) {
        if (id != null) {
            var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
            db.ExecuteQuery(cmd);
        }
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});

// ── Line-number exactness ───────────────────────────────────────────────
//
// R8 lesson from the PHP port of this same task (3 fix rounds, all
// ultimately about line-number precision): a multi-line condition AND an
// interleaved comment are exactly the two shapes that broke an
// approximate/reconstructed-newline-counting line computation. This test
// pins the EXACT line of a sink several lines deep inside a multi-line `if`
// condition, with an unrelated comment earlier in the same body.
test('parseCSharpFile: a sink is reported on its EXACT line through a multi-line if-condition and an interleaved comment', () => {
  const code = `
public class C {
    public void Run(string id, string other) {
        if (id != null &&
            other != null) {
            // this comment explains the guard
            var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
            db.Execute(cmd);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  const sink = calls.find(c => c.callee === 'Execute' || c.callee === 'db.Execute');
  assert.ok(sink, 'expected the sink call to be captured, got: ' + JSON.stringify(calls));
  // Line-count the fixture by hand: the template literal's leading '\n' is
  // line 1, so `public class C {` is line 2, ..., `db.Execute(cmd);` is
  // line 8.
  const lines = code.split('\n');
  const expectedLine = lines.findIndex(l => l.includes('db.Execute(cmd)')) + 1; // 1-indexed
  assert.equal(sink.line, expectedLine, `expected db.Execute at exact source line ${expectedLine}, got ${sink.line}`);
});

// ── foreach loop-variable taint provenance ──────────────────────────────
//
// R8 gap-check (per Task 1's analogous Java for-each finding): C#'s
// `foreach (var x in xs)` declares a fresh loop variable that the body then
// reads. The body being reachable is not enough — without binding `x` to
// `xs`, a genuinely tainted collection flowing through the loop variable
// into a sink could never fire.
test('parseCSharpFile: foreach binds the loop variable to the iterated collection', () => {
  const code = `
public class C {
    public void Run(List<string> ids) {
        foreach (var id in ids) {
            db.Execute(id);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Run');
  assert.ok(fn);
  const nodes = Object.values(fn.cfg.nodes);
  const bind = nodes.find(n => n.kind === 'assign' && n.target === 'id');
  assert.ok(bind, 'expected an assign node binding the foreach loop variable "id"');
  assert.equal(bind.source?.name, 'ids', 'loop variable should be sourced from the iterated collection, got: ' + JSON.stringify(bind.source));
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.some(c => c.callee?.endsWith('Execute')), 'expected the foreach-body sink call');
});

test('parseCSharpFile: end-to-end runScan detects a source flowing through a foreach loop variable into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-cs-foreach-'));
  // See the comment on the if-block end-to-end test above: `[FromQuery]`
  // is required for C#'s dataflow engine to treat a parameter as tainted
  // at all — a bare parameter is not a recognized source.
  fs.writeFileSync(path.join(dir, 'C.cs'), `
public class C {
    public void Run([FromQuery] string[] ids) {
        foreach (var id in ids) {
            var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
            db.ExecuteQuery(cmd);
        }
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding through the foreach loop variable, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});

// ── for-loop init clause ────────────────────────────────────────────────
//
// R8 gap-check: a C# `for (int i = 0; ...; ...)` header's init clause must
// surface as a real assign node (not just the test clause as the loop's
// condition), matching parser-cpp.js's treatment of the same 3-clause
// C-style for-loop shape.
test('parseCSharpFile: for-loop init clause is captured as a real assign node', () => {
  const code = `
public class C {
    public void Run(string[] ids) {
        for (int i = 0; i < ids.Length; i++) {
            db.Execute(ids[i]);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Run');
  assert.ok(fn);
  const nodes = Object.values(fn.cfg.nodes);
  const initAssign = nodes.find(n => n.kind === 'assign' && n.target === 'i');
  assert.ok(initAssign, 'expected the for-loop init clause `int i = 0` to lower to an assign node');
  assert.equal(initAssign.source?.value, '0');
});

// ── R8 fix round 1: using/lock statement bodies ─────────────────────────
//
// `using (...) { }` and `lock (...) { }` were missing from `_buildCfg`'s
// keyword-match alternation entirely — both fell through to `_lowerStmt`'s
// generic statement-form-call recognizer, which happily matched
// `using(conn)`/`lock(this)` as a bogus `call:using`/`call:lock` node and
// discarded the `{...}` body text outright (the closing `)` of the
// "call" is exactly where the real body starts). `using` is THE canonical
// C#/ADO.NET wrapper around the sinks this task targets — this dropped an
// enormous fraction of real-world SQL/command/file sinks even after this
// task's main if/for/try/switch fix landed.
test('parseCSharpFile: a sink inside a using (...) { } body is captured, with the exact line', () => {
  const code = `
public class C {
    public void Run(string id) {
        using (var conn = OpenConnection()) {
            var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
            conn.Execute(cmd);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  const sink = calls.find(c => c.callee === 'Execute' || c.callee === 'conn.Execute');
  assert.ok(sink, 'expected the using-body sink call, got: ' + JSON.stringify(calls));
  const lines = code.split('\n');
  const expectedLine = lines.findIndex(l => l.includes('conn.Execute(cmd)')) + 1;
  assert.equal(sink.line, expectedLine, `expected conn.Execute at exact source line ${expectedLine}, got ${sink.line}`);
});

test('parseCSharpFile: a sink inside a lock (...) { } body is captured, with the exact line', () => {
  const code = `
public class C {
    public void Run(string id) {
        lock (this) {
            var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
            db.Execute(cmd);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const calls = callNodes(ir, 'Run');
  const sink = calls.find(c => c.callee === 'Execute' || c.callee === 'db.Execute');
  assert.ok(sink, 'expected the lock-body sink call, got: ' + JSON.stringify(calls));
  const lines = code.split('\n');
  const expectedLine = lines.findIndex(l => l.includes('db.Execute(cmd)')) + 1;
  assert.equal(sink.line, expectedLine, `expected db.Execute at exact source line ${expectedLine}, got ${sink.line}`);
});

test('parseCSharpFile: the braceless C# 8 `using var x = ...;` declaration form still lowers normally', () => {
  // Distinct from the braced `using (...) { }` statement form above: this
  // is a plain local-variable declaration with a `using` modifier (no
  // parens, no body) — unaffected by this fix-round's regex change, since
  // it never matches `s[p] === '('` and falls through to ordinary
  // statement lowering. Pinned explicitly so a future change to the
  // keyword-match regex can't silently regress this unrelated shape.
  const code = `
public class C {
    public void Run(string id) {
        using var conn = new SqlConnection("cs" + id);
        conn.Open();
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Run');
  assert.ok(fn);
  const nodes = Object.values(fn.cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === 'conn');
  assert.ok(assign, 'expected `using var conn = new SqlConnection(...)` to lower to an assign node, got: ' + JSON.stringify(nodes));
  assert.equal(assign.source?.kind, 'call');
  assert.equal(assign.source?.callee, 'SqlConnection');
  const calls = nodes.filter(n => n.kind === 'call');
  // `conn.Open` — or, since `conn`'s constructed type (`SqlConnection`) is
  // now tracked (a separate, later fix; see parser-cs.js's
  // `_applyVarTypeRewrite`), the rewritten `SqlConnection.Open` form.
  assert.ok(calls.some(c => c.callee === 'conn.Open' || c.callee === 'SqlConnection.Open'), 'expected the following statement to still lower correctly, got: ' + JSON.stringify(calls));
});

// Taint-engine PRD P1: METHOD_RE required a mandatory leading modifier
// keyword (public/private/static/...), so a bare, implicitly-private method
// — legal and common in C# for private helpers, e.g. `void Render() { ... }`
// — never matched at all: the whole method, and any sink inside it, was
// invisible to the IR.
test('parseCSharpFile: a method with no modifier keyword is still captured', () => {
  const code = `
public class C {
    void Render(string id) {
        var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
        db.Execute(cmd);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Render');
  assert.ok(fn, `expected an IR function for the no-modifier method "Render", got: ${JSON.stringify(ir.functions.map(f => f.name))}`);
  const calls = callNodes(ir, 'Render');
  assert.ok(calls.some(c => c.callee === 'Execute' || c.callee === 'db.Execute'),
    `expected the sink call inside the no-modifier method, got: ${JSON.stringify(calls)}`);
});

test('parseCSharpFile: a no-modifier method does not swallow a sibling method that follows it', () => {
  // The real risk of loosening METHOD_RE: a control-flow statement or other
  // two-token-then-parens shape matching by accident and corrupting the
  // scan position for everything after it in the file.
  const code = `
public class C {
    void Helper(string id) {
        Log(id);
    }
    public void Handler(string id) {
        var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
        db.Execute(cmd);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const names = ir.functions.map(f => bareTail(f.name));
  assert.ok(names.includes('Helper'), `expected Helper to be captured, got: ${JSON.stringify(names)}`);
  assert.ok(names.includes('Handler'), `expected Handler to still be captured after a no-modifier method precedes it, got: ${JSON.stringify(names)}`);
  const handlerCalls = callNodes(ir, 'Handler');
  assert.ok(handlerCalls.some(c => c.callee === 'Execute' || c.callee === 'db.Execute'),
    `expected Handler's own sink call to survive, got: ${JSON.stringify(handlerCalls)}`);
});

test('parseCSharpFile: control-flow keywords are never mis-captured as no-modifier methods', () => {
  // Precision half — if/for/while/using/catch have only ONE token before
  // their parens ("if", "for", ...), never the "type name(args)" two-token
  // shape a method declaration has, so loosening the modifier requirement
  // must not start matching them.
  const code = `
public class C {
    public void Handler(string id, bool flag) {
        if (flag) {
            Log("a");
        }
        for (int i = 0; i < 3; i++) {
            Log("b");
        }
        using (var conn = Open()) {
            Log("c");
        }
        try {
            Log("d");
        } catch (System.Exception ex) {
            Log("e");
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const names = ir.functions.map(f => bareTail(f.name));
  assert.deepEqual(names, ['Handler'],
    `control-flow keywords must never be captured as their own function, got: ${JSON.stringify(names)}`);
  const calls = callNodes(ir, 'Handler');
  const logCalls = calls.filter(c => c.callee === 'Log');
  assert.equal(logCalls.length, 5,
    `expected all 5 Log calls (one per control-flow body) inside Handler's own CFG, got ${logCalls.length}: ${JSON.stringify(calls)}`);
});

test('parseCSharpFile: end-to-end runScan detects taint through a no-modifier private helper', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-cs-nomodifier-'));
  fs.writeFileSync(path.join(dir, 'C.cs'), `
public class C {
    void RunQuery(string id) {
        var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
        conn.ExecuteQuery(cmd);
    }
    public void Handler([FromQuery] string id) {
        RunQuery(id);
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1,
    `expected an IR-TAINT finding through the no-modifier RunQuery helper, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});

test('parseCSharpFile: end-to-end runScan detects a source flowing through a using-wrapped ADO.NET block into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-cs-using-'));
  fs.writeFileSync(path.join(dir, 'C.cs'), `
public class C {
    public void Run([FromQuery] string id) {
        using (var conn = OpenConnection()) {
            var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);
            conn.ExecuteQuery(cmd);
        }
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for the using-wrapped ADO.NET shape, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});

// Juliet's `if (true) { … } else { … }` / `if (false) { … } else { … }`
// constant-condition idiom (its own "Flow Variant 02" naming convention,
// used across dozens of CWEs, not just command injection). Before this fix,
// bare `else` had no `needsCond` match at all, so it was never linked as a
// real second branch of the `if` node — it fell through to the generic
// bare-nested-block handling and was recursed into SEQUENTIALLY, straight
// after the if-body, unconditionally. For a genuine runtime condition that's
// a deliberate recall-preserving tradeoff (never drop a sink hidden in
// either arm) — but for a LITERAL true/false condition it actively loses
// taint: the dead arm's clean/null assignment always ran "after" the live
// arm and clobbered its variable by the time a later sink read it,
// regardless of which arm was actually live. Root-caused via the public C#
// Juliet mirror's own `CWE78_OS_Command_Injection__NetClient_02.cs`.
test('parseCSharpFile: if(true)/else — the live branch keeps its assignment, the dead else-branch is pruned entirely', () => {
  const code = `
public class C {
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (true) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  assert.ok(fn);
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(!nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'the dead else-branch\'s `data = null` must not appear anywhere in the CFG, got: ' + JSON.stringify(nodeList));
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'the live if-branch\'s `data = sr.ReadLine()` must still be present, got: ' + JSON.stringify(nodeList));
});

test('parseCSharpFile: if(false)/else — the dead if-branch is pruned, the live else-branch keeps its assignment', () => {
  const code = `
public class C {
    public void Good(System.IO.StreamReader sr) {
        string data;
        if (false) {
            data = sr.ReadLine();
        } else {
            data = "foo";
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Good');
  assert.ok(fn);
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(!nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'the dead if-branch\'s `data = sr.ReadLine()` must not appear anywhere in the CFG, got: ' + JSON.stringify(nodeList));
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'literal'),
    'the live else-branch\'s `data = "foo"` must still be present, got: ' + JSON.stringify(nodeList));
});

test('parseCSharpFile: end-to-end runScan detects taint through if(true)/else (Juliet NetClient shape), and does NOT fire on the if(false)/else good-source counterpart', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-cs-const-if-'));
  fs.writeFileSync(path.join(dir, 'Bad.cs'), `
using System;
using System.IO;
public class Bad {
    public void Run(StreamReader sr) {
        string data;
        if (true) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`);
  const badResult = await runScan(dir, { deep: true, deepInCi: true });
  const badFindings = (badResult.scan.findings || []).filter(f => f.cwe === 'CWE-78');
  assert.ok(badFindings.length >= 1,
    `expected a CWE-78 finding through if(true)/else, got: ${JSON.stringify(badResult.scan.findings)}`);

  fs.writeFileSync(path.join(dir, 'Bad.cs'), `
using System;
using System.IO;
public class Good {
    public void Run(StreamReader sr) {
        string data;
        if (false) {
            data = sr.ReadLine();
        } else {
            data = "foo";
        }
        Process.Start(data);
    }
}
`);
  const goodResult = await runScan(dir, { deep: true, deepInCi: true });
  const goodFindings = (goodResult.scan.findings || []).filter(f => f.cwe === 'CWE-78');
  assert.equal(goodFindings.length, 0,
    `expected no CWE-78 finding for the if(false)/else good-source counterpart, got: ${JSON.stringify(goodFindings)}`);
});

test('parseCSharpFile: a genuine (non-constant) runtime if/else condition is unaffected by the constant-condition special case', () => {
  const code = `
public class C {
    public void Run(System.IO.StreamReader sr, bool flag) {
        string data;
        if (flag) {
            data = sr.ReadLine();
        } else {
            data = "foo";
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Run');
  assert.ok(fn);
  const nodeList = Object.values(fn.cfg.nodes);
  // Both arms are still present — the general (non-literal) if/else path
  // must remain the same permissive straight-line shape it was before this
  // fix; only a literal true/false condition gets the new pruning behavior.
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'expected the if-branch assignment to still be present, got: ' + JSON.stringify(nodeList));
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'literal'),
    'expected the else-branch assignment to still be present, got: ' + JSON.stringify(nodeList));
  assert.ok(nodeList.some(n => n.kind === 'if'), 'expected a genuine `if` CFG node for the non-constant condition');
});

// SARD_80_F1 W4.C36 — Juliet's own "Flow Variant 04: Control flow:
// if(PRIVATE_CONST_TRUE) and if(PRIVATE_CONST_FALSE)" (confirmed via the
// public C# Juliet mirror's own CWE80_XSS__CWE182_Web_Connect_tcp_04.cs)
// is the SAME dead-code idiom as the literal if(true)/if(false) case above,
// except the condition is a `private const bool` field reference — a real,
// provable compile-time constant, but the literal-only guard above never
// resolved it, so this whole flow-variant family fell through to the
// general if/else path and lost taint entirely (the exact W4.C27-documented
// "NetClient" failure mode). Confirmed by direct reproduction: the real
// corpus file produced ZERO findings at all before this fix (not just a
// suppressed good() — bad()'s own genuine sink was invisible too).
test('parseCSharpFile: if(CONST_FIELD)/else — a private const bool field is resolved and folded exactly like a literal', () => {
  const code = `
public class C {
    private const bool PRIVATE_CONST_TRUE = true;
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (PRIVATE_CONST_TRUE) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  assert.ok(fn);
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(!nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'the dead else-branch\'s `data = null` must not appear anywhere in the CFG, got: ' + JSON.stringify(nodeList));
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'the live if-branch\'s `data = sr.ReadLine()` must still be present, got: ' + JSON.stringify(nodeList));
});

test('parseCSharpFile: end-to-end runScan — a private const bool condition resolves through the full pipeline (real corpus shape)', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-cs-const-field-'));
  fs.writeFileSync(path.join(dir, 'Bad.cs'), `
using System;
using System.IO;
public class Bad {
    private const bool PRIVATE_CONST_TRUE = true;
    public void Run(StreamReader sr) {
        string data;
        if (PRIVATE_CONST_TRUE) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`);
  const badResult = await runScan(dir, { deep: true, deepInCi: true });
  const badFindings = (badResult.scan.findings || []).filter(f => f.cwe === 'CWE-78');
  assert.ok(badFindings.length >= 1,
    `expected a CWE-78 finding through if(PRIVATE_CONST_TRUE)/else, got: ${JSON.stringify(badResult.scan.findings)}`);

  fs.writeFileSync(path.join(dir, 'Bad.cs'), `
using System;
using System.IO;
public class Good {
    private const bool PRIVATE_CONST_FALSE = false;
    public void Run(StreamReader sr) {
        string data;
        if (PRIVATE_CONST_FALSE) {
            data = sr.ReadLine();
        } else {
            data = "foo";
        }
        Process.Start(data);
    }
}
`);
  const goodResult = await runScan(dir, { deep: true, deepInCi: true });
  const goodFindings = (goodResult.scan.findings || []).filter(f => f.cwe === 'CWE-78');
  assert.equal(goodFindings.length, 0,
    `expected no CWE-78 finding for the if(PRIVATE_CONST_FALSE)/else good-source counterpart, got: ${JSON.stringify(goodFindings)}`);
});

// Juliet's own "Flow Variant 13: if(IO.STATIC_FINAL_FIVE==5) and
// if(IO.STATIC_FINAL_FIVE!=5)" sibling shape (same-file version, since
// cross-file constant resolution is out of scope) — an int constant
// compared with `==`/`!=`.
test('parseCSharpFile: if(CONST_FIELD == N)/else — an int const field compared with == is resolved', () => {
  const code = `
public class C {
    private const int PRIVATE_CONST_FIVE = 5;
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (PRIVATE_CONST_FIVE == 5) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  assert.ok(fn);
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(!nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'the dead else-branch must not appear, got: ' + JSON.stringify(nodeList));
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'the live if-branch must still be present, got: ' + JSON.stringify(nodeList));
});

// Precision control: a `static readonly` (not `const`) field is the OTHER
// real C# immutable-field idiom Juliet's own naming convention uses
// elsewhere ("if(IO.staticTrue)" flow variants) and must resolve the same
// way; an ordinary MUTABLE field with the same name/shape must NOT.
test('parseCSharpFile: a `static readonly bool` field folds; a plain mutable field with the same shape does NOT', () => {
  const readonlyCode = `
public class C {
    private static readonly bool STATIC_READONLY_TRUE = true;
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (STATIC_READONLY_TRUE) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const roIr = parseCSharpFile('C.cs', readonlyCode);
  const roFn = roIr.functions.find(f => bareTail(f.name) === 'Bad');
  const roNodes = Object.values(roFn.cfg.nodes);
  assert.ok(!roNodes.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'a static readonly field must be folded, dead branch must not appear');

  // A field of this same shape that IS actually reassigned elsewhere in the
  // file must NOT be folded — this is the precision guarantee W4.C38's
  // "effectively final" extension must preserve (see the dedicated test
  // below for the never-reassigned counterpart, which — correctly, as of
  // W4.C38 — now DOES fold).
  const mutableCode = `
public class C {
    private static bool notActuallyReadonly = true;
    public void Toggle() {
        notActuallyReadonly = false;
    }
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (notActuallyReadonly) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const mutIr = parseCSharpFile('C.cs', mutableCode);
  const mutFn = mutIr.functions.find(f => bareTail(f.name) === 'Bad');
  const mutNodes = Object.values(mutFn.cfg.nodes);
  assert.ok(mutNodes.some(n => n.kind === 'if'),
    'a genuinely-reassigned field must NOT be folded — a genuine `if` CFG node is still expected, got: ' + JSON.stringify(mutNodes));
});

test('parseCSharpFile: W4.C38 — a plain (non-const, non-readonly) private bool field that is never reassigned is "effectively final" and folds like a literal (Juliet Flow Variant 05)', () => {
  const code = `
public class C {
    private bool privateTrue = true;
    private bool privateFalse = false;
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (privateTrue) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        if (privateFalse) {
            data = null;
        } else {
            Process.Start(data);
        }
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  const nodes = Object.values(fn.cfg.nodes);
  assert.ok(!nodes.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'an effectively-final plain private bool field must be folded, dead branches must not appear');
});

test('parseCSharpFile: W4.C38 — a plain private int field compared with == is resolved (Juliet Flow Variant 07)', () => {
  const code = `
public class C {
    private int privateFive = 5;
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (privateFive == 5) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  const nodes = Object.values(fn.cfg.nodes);
  assert.ok(!nodes.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'an effectively-final plain private int field compared with == must be folded, dead branch must not appear');
});

test('parseCSharpFile: W4.C38 end-to-end runScan — Juliet Flow Variant 05 (plain private bool field) resolves through the full pipeline', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-cs-plain-bool-if-'));
  fs.writeFileSync(path.join(dir, 'Bad.cs'), `
using System;
using System.IO;
public class Bad {
    private bool privateTrue = true;
    public void Run(StreamReader sr) {
        string data;
        if (privateTrue) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`);
  const badResult = await runScan(dir, { deep: true, deepInCi: true });
  const badFindings = (badResult.scan.findings || []).filter(f => f.cwe === 'CWE-78');
  assert.ok(badFindings.length >= 1,
    `expected a CWE-78 finding through a plain effectively-final private bool field's if-branch, got: ${JSON.stringify(badResult.scan.findings)}`);
});

// SARD_80_F1 W5.28 — C#'s own counterpart to Java's W5.27. Juliet's "Flow
// Variant 08/11: Control flow: if(PrivateReturnsTrue()) and
// if(PrivateReturnsFalse())" (confirmed via the public C# mirror's own
// CWE80_XSS__CWE182_Web_Connect_tcp_08.cs) branches on a CALL to a
// same-class, zero-arg, single-`return true;`/`return false;`-bodied
// private helper — a shape `_resolveConstCondition` never modeled (literal/
// field/int-comparison only), so this whole flow-variant family fell
// through to the general if/else path and lost its dead-branch pruning.
test('parseCSharpFile: if(PrivateHelper())/else — a zero-arg method that always returns true is resolved and folded', () => {
  const code = `
public class C {
    private static bool PrivateReturnsTrue() {
        return true;
    }
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (PrivateReturnsTrue()) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  assert.ok(fn);
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(!nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'the dead else-branch\'s `data = null` must not appear anywhere in the CFG, got: ' + JSON.stringify(nodeList));
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'the live if-branch\'s `data = sr.ReadLine()` must still be present, got: ' + JSON.stringify(nodeList));
});

test('parseCSharpFile: if(PrivateHelper())/else — a zero-arg method that always returns false folds the if-branch as dead', () => {
  const code = `
public class C {
    private bool PrivateReturnsFalse() {
        return false;
    }
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (PrivateReturnsFalse()) {
            data = sr.ReadLine();
        } else {
            data = "foo";
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(!nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'the dead if-branch\'s `data = sr.ReadLine()` must not appear anywhere in the CFG, got: ' + JSON.stringify(nodeList));
});

test('parseCSharpFile: a zero-arg helper with a PARAMETER-influenced or multi-statement body is NOT folded', () => {
  const code = `
public class C {
    private bool Check() {
        System.Console.WriteLine("side effect");
        return true;
    }
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (Check()) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'a multi-statement helper body is ambiguous and must NOT be folded — the else-branch must remain in the CFG');
});

test('parseCSharpFile: W5.28 end-to-end runScan — Juliet Flow Variant 08/11 (if(PrivateReturnsX())) resolves through the full pipeline (real corpus shape)', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-cs-private-returns-'));
  fs.writeFileSync(path.join(dir, 'Bad.cs'), `
using System;
using System.IO;
public class Bad {
    private static bool PrivateReturnsTrue() {
        return true;
    }
    public void Run(StreamReader sr) {
        string data;
        if (PrivateReturnsTrue()) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`);
  const badResult = await runScan(dir, { deep: true, deepInCi: true });
  const badFindings = (badResult.scan.findings || []).filter(f => f.cwe === 'CWE-78');
  assert.ok(badFindings.length >= 1,
    `expected a CWE-78 finding through if(PrivateReturnsTrue())/else, got: ${JSON.stringify(badResult.scan.findings)}`);

  fs.writeFileSync(path.join(dir, 'Bad.cs'), `
using System;
using System.IO;
public class Good {
    private static bool PrivateReturnsFalse() {
        return false;
    }
    public void Run(StreamReader sr) {
        string data;
        if (PrivateReturnsFalse()) {
            data = sr.ReadLine();
        } else {
            data = "foo";
        }
        Process.Start(data);
    }
}
`);
  const goodResult = await runScan(dir, { deep: true, deepInCi: true });
  const goodFindings = (goodResult.scan.findings || []).filter(f => f.cwe === 'CWE-78');
  assert.equal(goodFindings.length, 0,
    `expected no CWE-78 finding for the if(PrivateReturnsFalse())/else good-source counterpart, got: ${JSON.stringify(goodFindings)}`);
});

// SARD_80_F1 W5.29 — Juliet's "Flow Variant 03: if(5==5) and if(5!=5)"
// (confirmed via the public C# mirror's own
// CWE80_XSS__CWE182_Web_Connect_tcp_03.cs): both sides are bare integer
// literals, needing no `classConsts` lookup — the pre-existing `cmp` regex
// required the LHS to be an identifier, so a pure literal-vs-literal
// comparison never resolved even though it needs no interprocedural
// evidence at all.
test('parseCSharpFile: if(5==5)/else — a literal-vs-literal int comparison is resolved without any classConsts lookup', () => {
  const code = `
public class C {
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (5 == 5) {
            data = sr.ReadLine();
        } else {
            data = null;
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(!nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.kind === 'ident' && n.source.name === 'null'),
    'the dead else-branch must not appear, got: ' + JSON.stringify(nodeList));
  assert.ok(nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'the live if-branch must still be present, got: ' + JSON.stringify(nodeList));
});

test('parseCSharpFile: if(5!=5)/else — a literal-vs-literal int comparison that is always false folds the if-branch as dead', () => {
  const code = `
public class C {
    public void Bad(System.IO.StreamReader sr) {
        string data;
        if (5 != 5) {
            data = sr.ReadLine();
        } else {
            data = "foo";
        }
        Process.Start(data);
    }
}
`;
  const ir = parseCSharpFile('C.cs', code);
  const fn = ir.functions.find(f => bareTail(f.name) === 'Bad');
  const nodeList = Object.values(fn.cfg.nodes);
  assert.ok(!nodeList.some(n => n.kind === 'assign' && n.target === 'data' && n.source && n.source.callee === 'sr.ReadLine'),
    'the dead if-branch must not appear, got: ' + JSON.stringify(nodeList));
});
