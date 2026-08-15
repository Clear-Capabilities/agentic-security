import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parsePhpFile } from '../src/ir/parser-php.js';

function mkTmp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-php-fix1-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}

// `$x = f(...)` lowers to ONE `assign` node whose `source` is the nested
// call expression, not a separate top-level `call`-kind node (pre-existing
// `_lowerStmt` behavior, unrelated to this task — confirmed by probing the
// same shape outside any control-flow construct). `callNodes` alone misses
// this; check both shapes, matching the precedent set by the Java R8 task's
// equivalent `hasAssignedCallEndingIn` helper for the same underlying gap.
function hasCallOrAssignedCall(ir, fnName, callee) {
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).some(n =>
    (n.kind === 'call' && n.callee === callee) ||
    (n.kind === 'assign' && n.source && n.source.kind === 'call' && n.source.callee === callee)
  );
}

test('parsePhpFile: a sink inside an if-block is captured even when a statement follows it', () => {
  const code = `<?php
function f($conn) {
    if (isset($_GET['id'])) {
        $id = $_GET['id'];
        mysqli_query($conn, $id);
    }
    return $id;
}
`;
  const ir = parsePhpFile('f.php', code);
  assert.ok(ir);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the if-body sink to survive a trailing return statement');
});

test('parsePhpFile: a second if-block in the same scope is not swallowed by the first', () => {
  const code = `<?php
function f($conn) {
    if (true) {
        $a = 1;
    }
    if (isset($_GET['id'])) {
        $id = $_GET['id'];
        mysqli_query($conn, $id);
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const fn = ir.functions.find(f => f.name === 'f');
  const ifNodes = Object.values(fn.cfg.nodes).filter(n => n.kind === 'if');
  assert.equal(ifNodes.length, 2, 'expected both if-blocks to produce their own if node');
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the second if-block\'s sink to be captured');
  const assigns = Object.values(fn.cfg.nodes).filter(n => n.kind === 'assign' && n.target === '$id');
  assert.ok(assigns.length >= 1, 'expected $id = $_GET[\'id\'] to be captured as a real assign node, establishing taint provenance');
});

test('parsePhpFile: a sink inside a try/catch body is captured', () => {
  const code = `<?php
function f($conn, $sql) {
    try {
        $x = mysqli_query($conn, $sql);
    } catch (Exception $e) {
        log_error($e);
    }
    return $x;
}
`;
  const ir = parsePhpFile('f.php', code);
  assert.ok(hasCallOrAssignedCall(ir, 'f', 'mysqli_query'), 'expected the try-body sink');
  assert.ok(hasCallOrAssignedCall(ir, 'f', 'log_error'), 'expected the catch-body call');
});

test('parsePhpFile: a sink inside a switch/case body is captured', () => {
  const code = `<?php
function f($x) {
    switch ($x) {
        case 1:
            $y = $_GET['cmd'];
            shell_exec($y);
            break;
        default:
            noop();
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'shell_exec'), 'expected the case-1 body sink');
  assert.ok(calls.some(c => c.callee === 'noop'), 'expected the default body call');
});

test('parsePhpFile: a lambda/closure passed as a call argument is NOT mis-split by the new brace-flush trigger', () => {
  const code = `<?php
function f($arr) {
    usort($arr, function($a, $b) {
        return $a - $b;
    });
    return $arr;
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'usort'), 'expected the usort call itself to still be captured as ONE call node, not fragmented by the closure\'s internal braces');
  assert.equal(calls.filter(c => c.callee === 'usort').length, 1, 'the closure body must not produce a spurious extra usort-adjacent node');
});

test('parsePhpFile: end-to-end runScan detects a source flowing through a try-block into a sink', async () => {
  const { runScan } = await import('../src/runScan.js');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r8-php-'));
  fs.writeFileSync(path.join(dir, 'index.php'), `<?php
function run($conn) {
    try {
        $id = $_GET['id'];
        mysqli_query($conn, $id);
    } catch (Exception $e) {
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an IR-TAINT finding for a sink inside try, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});

// --- R8 fix round 1 regressions ---------------------------------------
//
// A task review of the original commit found: (1) a Critical line-tracking
// off-by-one affecting every recursive `_buildCfg` call this task added or
// touched (the child body's `startLine` was `line + 1` instead of `line`,
// silently over-counting by one line for K&R-style control flow — the
// overwhelmingly common PHP style — which broke the `agentic-security-ignore`
// suppression pragma for control-flow-body findings); (2) `tryMatch`'s
// greedy catch-body regex capture group swallowed through to `finally`'s
// own closing `}`, making `finally` bodies dead code; (3) `try { } finally
// { }` with no `catch` clause was unrecognized entirely; (4) the new
// `:`-based case-label flush mis-fired on `::` (class-constant / PHP 8.1
// enum-case labels, e.g. `case Foo::BAR:`), mis-splitting mid-token and
// dropping that case's body. All four are fixed above; these tests pin
// each one directly.

test('parsePhpFile: a sink several lines into an if-body is reported at its EXACT source line', () => {
  const code = `<?php
function f($conn) {
    if (true) {
        $a = 1;
        $b = 2;
        mysqli_query($conn, 'x');
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  const call = calls.find(c => c.callee === 'mysqli_query');
  assert.ok(call, 'expected the if-body sink to be captured');
  assert.equal(call.line, 6, 'sink is on real source line 6 (1: <?php, 2: function, 3: if, 4: $a, 5: $b, 6: mysqli_query) — reporting line 7 was the R8 fix-round-1 Critical off-by-one');
});

test('parsePhpFile: sinks in the try, catch, AND finally bodies are all reported at their EXACT source lines', () => {
  const code = `<?php
function f($conn) {
    try {
        sink1($conn);
    } catch (Exception $e) {
        sink2($e);
    } finally {
        sink3($conn);
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  const byName = (name) => calls.find(c => c.callee === name);
  assert.ok(byName('sink1'), 'expected the try-body sink');
  assert.ok(byName('sink2'), 'expected the catch-body sink');
  assert.ok(byName('sink3'), 'expected the finally-body sink — previously dead code: the old regex\'s greedy catch-body capture group swallowed through finally\'s own closing brace, so `tryMatch[4]` (finally) could never match anything');
  assert.equal(byName('sink1').line, 4, 'try-body sink is on real source line 4');
  assert.equal(byName('sink2').line, 6, 'catch-body sink is on real source line 6');
  assert.equal(byName('sink3').line, 8, 'finally-body sink is on real source line 8');
});

test('parsePhpFile: try/finally with NO catch clause captures both bodies (previously unrecognized entirely)', () => {
  const code = `<?php
function f($conn) {
    try {
        sink1($conn);
    } finally {
        sink2($conn);
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'sink1'), 'expected the try-body sink for a catch-less try/finally');
  assert.ok(calls.some(c => c.callee === 'sink2'), 'expected the finally-body sink for a catch-less try/finally');
});

test('parsePhpFile: case labels using class-constant / enum-case syntax (Foo::BAR) are not mis-split by the `:` flush', () => {
  const code = `<?php
function f($x) {
    switch ($x) {
        case Foo::BAR:
            sink1($x);
            break;
        case Status::Active:
            sink2($x);
            break;
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'sink1'), 'expected the `case Foo::BAR:` body sink — the naive `:` flush treats the FIRST `:` of `::` as the label terminator, splitting mid-token and dropping this body');
  assert.ok(calls.some(c => c.callee === 'sink2'), 'expected the `case Status::Active:` (PHP 8.1 enum-case shape) body sink');
});

test('runScan + agentic-security-ignore on the TRUE source line of a sink inside an if-body suppresses the finding (R8 fix-round-1 regression for the Critical line-tracking bug)', async () => {
  const { runScan } = await import('../src/runScan.js');
  const phpFile = (pragma = '') => `<?php
function run($conn) {
    if (true) {
        $id = $_GET['id'];
        mysqli_query($conn, $id);${pragma}
    }
}
`;
  const controlDir = mkTmp({ 'index.php': phpFile() });
  const { scan: control } = await runScan(controlDir, { deep: true, deepInCi: true });
  const controlTaint = (control.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(controlTaint.length >= 1, 'positive control: deep mode must produce an IR-TAINT finding for the unsuppressed if-body sink');

  const suppressedDir = mkTmp({ 'index.php': phpFile(' // agentic-security-ignore') });
  const { scan: suppressed } = await runScan(suppressedDir, { deep: true, deepInCi: true });
  const suppressedTaint = (suppressed.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.equal(suppressedTaint.length, 0,
    'the pragma placed on the REAL sink line (line 5, inside the if-body) must suppress the finding — ' +
    'before the fix, the finding was reported one line too late (line 6) and this pragma placement was inert');
});

// --- R8 fix round 2 regressions --------------------------------------
//
// A second task review found fix round 1's line-tracking fix was still
// incomplete: it only handled the plain, comment-free, single-line-header
// case. Two independent undercounting sources remained live: (1)
// `_splitStatements`'s comment-skip handlers consumed a comment's
// newline(s) without contributing any newline back to the flushed
// statement text, so a body containing an unrelated comment lost exactly
// that many newlines from the count `_buildCfg` uses to compute a nested
// body's start line; (2) `if`/`while`/`foreach`/`switch` still used a flat
// `line` (the keyword's own line) for their body's start line, which is
// only correct when the header between the keyword and `{` is a single
// physical line — wrong for a multi-line condition. Both are fixed above
// (comment newline preservation in `_splitStatements`; `d`-flagged regex
// `.indices` + `_countNewlines` for all four recognizers, matching the
// technique fix round 1 already used for try/catch/finally). These tests
// pin all three previously-uncovered shapes: a `//` comment in the body, a
// `/* */` comment in the body, and a multi-line `if (...)` condition — the
// prior round's tests were all comment-free and single-line-header, which
// is exactly why they didn't catch this.

test('parsePhpFile: a sink in an if-body containing an unrelated // comment is reported at its EXACT source line', () => {
  const code = `<?php
function f($conn) {
    if (true) {
        // an unrelated comment
        $a = 1;
        mysqli_query($conn, 'x');
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  const call = calls.find(c => c.callee === 'mysqli_query');
  assert.ok(call, 'expected the if-body sink to be captured');
  assert.equal(call.line, 6, 'sink is on real source line 6 — a `//` comment on line 4 must not undercount the newline it displaces');
});

test('parsePhpFile: a sink in a try-body containing a multi-line /* */ comment is reported at its EXACT source line', () => {
  const code = `<?php
function f($conn) {
    try {
        /* a
           multi
           line
           comment */
        mysqli_query($conn, 'x');
    } catch (Exception $e) {
        log_error($e);
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  const call = calls.find(c => c.callee === 'mysqli_query');
  assert.ok(call, 'expected the try-body sink to be captured');
  assert.equal(call.line, 8, 'sink is on real source line 8 — a 4-line block comment (lines 4-7) must not undercount by any of its internal newlines');
});

test('parsePhpFile: a sink in a switch-body containing a /* */ comment is reported at its EXACT source line', () => {
  const code = `<?php
function f($x) {
    switch ($x) {
        /* explain the case */
        case 1:
            sink1($x);
            break;
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  const call = calls.find(c => c.callee === 'sink1');
  assert.ok(call, 'expected the case-body sink to be captured');
  assert.equal(call.line, 6, 'sink is on real source line 6');
});

test('parsePhpFile: a sink in the body of an if-statement with a multi-line condition is reported at its EXACT source line', () => {
  const code = `<?php
function f($conn, $a, $b) {
    if ($a &&
        $b) {
        mysqli_query($conn, 'x');
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  const call = calls.find(c => c.callee === 'mysqli_query');
  assert.ok(call, 'expected the if-body sink to be captured');
  assert.equal(call.line, 5, 'sink is on real source line 5 — a 2-line if condition (lines 3-4) must not shift the body-relative line count computed off a flat "line" approximation');
});

test('runScan + agentic-security-ignore on the TRUE source line of a sink inside an if-body that ALSO contains an unrelated comment suppresses the finding', async () => {
  const { runScan } = await import('../src/runScan.js');
  const phpFile = (pragma = '') => `<?php
function run($conn) {
    if (true) {
        // an unrelated comment that must not perturb line tracking
        $id = $_GET['id'];
        mysqli_query($conn, $id);${pragma}
    }
}
`;
  const controlDir = mkTmp({ 'index.php': phpFile() });
  const { scan: control } = await runScan(controlDir, { deep: true, deepInCi: true });
  const controlTaint = (control.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(controlTaint.length >= 1, 'positive control: deep mode must produce an IR-TAINT finding for the unsuppressed if-body sink');

  const suppressedDir = mkTmp({ 'index.php': phpFile(' // agentic-security-ignore') });
  const { scan: suppressed } = await runScan(suppressedDir, { deep: true, deepInCi: true });
  const suppressedTaint = (suppressed.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.equal(suppressedTaint.length, 0,
    'the pragma placed on the REAL sink line (line 6, inside the if-body, one line after an unrelated // comment) must suppress the finding — ' +
    'before the fix round 2 fix, the comment ate a newline from the line count and the finding was reported at the wrong line, making this pragma placement inert');
});
