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

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name === fnName);
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
  const fn = ir.functions.find(f => f.name === 'Ping');
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
  const fn = ir.functions.find(f => f.name === 'Run');
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
  const fn = ir.functions.find(f => f.name === 'Run');
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
  const fn = ir.functions.find(f => f.name === 'Run');
  assert.ok(fn);
  const nodes = Object.values(fn.cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === 'conn');
  assert.ok(assign, 'expected `using var conn = new SqlConnection(...)` to lower to an assign node, got: ' + JSON.stringify(nodes));
  assert.equal(assign.source?.kind, 'call');
  assert.equal(assign.source?.callee, 'SqlConnection');
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.some(c => c.callee === 'conn.Open'), 'expected the following statement to still lower correctly');
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
  const fn = ir.functions.find(f => f.name === 'Render');
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
  const names = ir.functions.map(f => f.name);
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
  const names = ir.functions.map(f => f.name);
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
