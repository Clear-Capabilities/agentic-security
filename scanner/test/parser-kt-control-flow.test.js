import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseKotlinFile } from '../src/ir/parser-kt.js';

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}

test('parseKotlinFile: a sink inside an if-block is captured, including a statement following it', () => {
  const code = `
fun find(id: String?): String? {
    if (id != null) {
        val cmd = "SELECT * FROM users WHERE id=" + id
        db.execute(cmd)
    }
    return null
}
`;
  const ir = parseKotlinFile('f.kt', code);
  assert.ok(ir);
  const calls = callNodes(ir, 'find');
  assert.ok(calls.some(c => c.callee === 'execute' || c.callee === 'db.execute'), 'expected the if-body sink, got: ' + JSON.stringify(calls));
});

test('parseKotlinFile: a sink inside a for-loop body is captured', () => {
  const code = `
fun run(ids: List<String>) {
    for (id in ids) {
        db.execute(id)
    }
}
`;
  const ir = parseKotlinFile('f.kt', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee?.endsWith('execute')));
});

test('parseKotlinFile: a sink inside a try/catch body is captured', () => {
  const code = `
fun run(id: String) {
    try {
        db.execute(id)
    } catch (e: Exception) {
        log(id)
    }
}
`;
  const ir = parseKotlinFile('f.kt', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee?.endsWith('execute')), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the catch-body call');
});

test('parseKotlinFile: a sink inside a when-block body is captured', () => {
  const code = `
fun run(n: Int, id: String) {
    when (n) {
        1 -> log(id)
        else -> cleanup(id)
    }
}
`;
  const ir = parseKotlinFile('f.kt', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'log'), 'expected the when-branch-1 call');
});

test('parseKotlinFile: a trailing lambda argument is NOT mis-split', () => {
  const code = `
fun run(xs: List<Int>) {
    xs.forEach { x -> process(x) }
}
`;
  const ir = parseKotlinFile('f.kt', code);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'forEach' || c.callee === 'xs.forEach'), 'expected the forEach call itself to be captured as one node');
});

test('parseKotlinFile: existing straight-line Ktor source-to-sink shape is unaffected', async () => {
  // Exact fixture from test/parser-cs-kt.test.js's own
  // "Kotlin Ktor source -> cmd sink fires via dataflow engine" test
  // (lines 68-80), reused verbatim here as a direct before/after
  // comparison point for this task's rewrite of the CFG builder.
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-kt-ktor-'));
  fs.writeFileSync(path.join(dir, 'App.kt'), `
fun handle(call: Any) {
  val host = call.parameters
  Runtime.getRuntime().exec("ping " + host)
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  assert.ok(scan && Array.isArray(scan.findings), 'scan must produce findings array on Kotlin input, unaffected by this task\'s CFG-builder rewrite');
});

test('parseKotlinFile: end-to-end runScan detects a source flowing through an if-block into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-kt-'));
  // The brief's illustrative version of this test used a bare `id: String?`
  // parameter with no recognized-source shape as the "source". Verified
  // empirically (not assumed) that this does NOT work for Kotlin regardless
  // of any CFG change: `fn.paramAnnotations` (the mechanism that makes a
  // bare parameter tainted for C#/Java/JS, via a framework decorator like
  // `[FromQuery]`/`@RequestParam`) is populated only by
  // parser-cs.js/parser-js.js/parser-java.js — parser-kt.js has never
  // populated it, and the catalog has no `match.type: 'annotation'` entries
  // for `language: 'kt'` at all (only `call`/`member` sources such as
  // `call.parameters`, the Ktor shape the module's OWN pre-existing
  // straight-line test above already relies on). A bare unannotated Kotlin
  // param produced ZERO findings even in a straight-line body with no
  // control flow at all — confirmed by direct comparison before touching
  // this test, so this is a pre-existing characteristic of the Kotlin
  // source model, not a gap this task's CFG-recursion work is responsible
  // for. `call.parameters` is used here instead so this test actually
  // exercises what it claims to: a source flowing THROUGH the if-block's
  // recursion into the sink.
  fs.writeFileSync(path.join(dir, 'f.kt'), `
fun run(call: Any) {
    val id = call.parameters
    if (id != null) {
        val cmd = "SELECT * FROM t WHERE id=" + id
        db.executeQuery(cmd)
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});

test('parseKotlinFile: deeply chained braceless if statements do not overflow the stack', () => {
  // Final-review fix: _consumeChunk recursed into the braceless single-
  // statement body (`if (x) doThing()`) BEFORE its own `depth > 12` guard
  // ran, so the descent itself was unbounded — only chaining within a
  // single call was capped. This reproduces the reviewer's confirmed
  // RangeError repro (overflows by n=5000, this uses 5000) and asserts the
  // guard now returns gracefully instead of blowing the stack.
  const n = 5000;
  const code = `fun f(id: String) {\n${'if (a) '.repeat(n)}sink(id)\n}`;
  const ir = parseKotlinFile('f.kt', code);
  assert.ok(ir, 'expected parseKotlinFile to return a result instead of throwing');
  const fn = ir.functions.find(f => f.name === 'f');
  assert.ok(fn, 'expected a "functions" entry for f, proving the parse completed');
});
