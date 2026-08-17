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

// --- R8 fix round 3 regressions ----------------------------------------
//
// A third task review found two more problems: (1) a PRE-EXISTING bug (not
// introduced by this task, confirmed byte-identical across the original
// commit and both prior fix rounds) in `parsePhpFile`'s function-body base
// line — it used a flat `startLine + 1` offset from where `FUNC_RE`
// matched, correct only when the function's opening `{` sits on the very
// next physical line, which breaks for Allman brace style, multi-line
// signatures, and (very commonly) a function preceded by blank lines; and
// (2) a genuine REGRESSION this task's own round 1 introduced:
// `_continuationKeywordAhead` (the lookahead that keeps `}`+`else`/
// `catch`/`finally` glued together) only skipped whitespace when scanning
// ahead for the continuation keyword, not comments — so a comment between
// `}` and `else`/`catch`/`finally` (an unremarkable, real shape: explaining
// why a catch/finally clause exists) defeated the lookahead, the flush
// fired anyway, and the ENTIRE continuation body was silently dropped.
// Both are fixed above.

test('parsePhpFile: a sink inside an Allman-brace-style function\'s if-body is reported at its EXACT source line', () => {
  const code = `<?php
function f($conn)
{
    if (true) {
        mysqli_query($conn, 'x');
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  const call = calls.find(c => c.callee === 'mysqli_query');
  assert.ok(call, 'expected the if-body sink to be captured');
  assert.equal(call.line, 5, 'sink is on real source line 5 — Allman brace style (`{` on its own line, line 3) must not shift the function body\'s base line by assuming the brace sits on the `function` keyword\'s own line');
});

test('parsePhpFile: a sink inside a function preceded by blank lines is reported at its EXACT source line', () => {
  const code = `<?php


function f($conn) {
    if (true) {
        mysqli_query($conn, 'x');
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  const call = calls.find(c => c.callee === 'mysqli_query');
  assert.ok(call, 'expected the if-body sink to be captured');
  assert.equal(call.line, 6, 'sink is on real source line 6 — 2 blank lines (lines 2-3) before the function declaration must not be lost from the function body\'s base line computation');
});

test('parsePhpFile: a // comment between a try-body\'s closing brace and `catch` does not drop the catch body', () => {
  const code = `<?php
function f($conn) {
    try {
        sink1($conn);
    }
    // explain why we catch here
    catch (Exception $e) {
        sink2($e);
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'sink1'), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'sink2'), 'expected the catch-body sink — a `//` comment between `}` and `catch` must not defeat the continuation-keyword lookahead and cause the `}`-flush to fire early, which would silently drop this entire catch body');
});

test('parsePhpFile: a /* */ comment between a catch-body\'s closing brace and `finally` does not drop the finally body', () => {
  const code = `<?php
function f($conn) {
    try {
        sink1($conn);
    } catch (Exception $e) {
        sink2($e);
    } /* explain why we also need finally */ finally {
        sink3($conn);
    }
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'sink1'), 'expected the try-body sink');
  assert.ok(calls.some(c => c.callee === 'sink2'), 'expected the catch-body sink');
  assert.ok(calls.some(c => c.callee === 'sink3'), 'expected the finally-body sink — a `/* */` comment between `}` and `finally` must not defeat the continuation-keyword lookahead. This test uses `finally` rather than `else` for the `/* */` case because `_scanTryCatchFinally`\'s balanced-brace scanning (fix round 1) has no greedy-capture issue, cleanly isolating THIS fix from the separate, pre-existing, explicitly out-of-scope `ifMatch` greedy-capture bug documented below.');
});

test('parsePhpFile: a /* */ comment between an if-body\'s closing brace and `else` does not cause the `}`-flush to fire early (scoped assertion — see note)', () => {
  // NOTE on scope: this does NOT assert the else-body's own sink is
  // captured. `ifMatch`'s regex (`^if...\{([\s\S]*)\}(?:\s*else\s*\{
  // ([\s\S]*)\})?\s*$`) has a SEPARATE, pre-existing, already-reviewed-
  // and-explicitly-out-of-scope bug: its then-body capture group is
  // greedy and unconditionally swallows through to the LAST `}` in the
  // statement, leaving the optional else-group unmatched — this drops an
  // else-body's content regardless of whether a comment is present (
  // confirmed by direct regex tracing AND by testing commit `735ef63`,
  // the state before this task started, with the IDENTICAL comment-free
  // fixture: the else body was already dropped then, for the same
  // structural reason). Round 1 fixed the analogous bug for try/catch/
  // finally by replacing its regex with a balanced-brace scanner (see the
  // `finally` test above, which DOES assert its sink); `ifMatch` itself
  // was never touched by this task and fixing its greedy-capture bug is
  // out of this fix round's scope per the reviewer's explicit instruction
  // in an earlier round. What THIS test verifies is narrower and fully
  // within this fix round's actual scope: the comment must not defeat
  // `_continuationKeywordAhead`'s lookahead and cause the `}`-flush to
  // fire early — which would fragment the if/else into two orphaned
  // pieces and silently drop a TRAILING statement's sink too (verified:
  // before this fix round, `_continuationKeywordAhead` was whitespace-
  // only, but — separately confirmed — the trailing statement survived
  // regardless in this exact shape; this test still pins the composition
  // as a whole staying well-formed under the comment-aware lookahead).
  const code = `<?php
function f($x, $conn) {
    if ($x) {
        sink_a();
    } /* mid */ else {
        sink_b();
    }
    mysqli_query($conn, 'x');
}
`;
  const ir = parsePhpFile('f.php', code);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'sink_a'), 'expected the if-body sink to still be captured');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the statement AFTER the if/else to still be captured as its own node, proving the comment did not corrupt subsequent parsing');
  const fn = ir.functions.find(f => f.name === 'f');
  const ifNodes = Object.values(fn.cfg.nodes).filter(n => n.kind === 'if');
  assert.equal(ifNodes.length, 1, 'expected exactly ONE if-node for this single if/else construct — a premature `}`-flush caused by the comment defeating the lookahead would otherwise still parse cleanly here (this exact shape happens to survive either way), so this assertion is a stability pin, not proof of the fix by itself; see the `catch`/`finally` tests above for that proof');
});

// --- Taint-recall PRD (80%): _extractBody / _splitStatements comment-
// unawareness, and the "literal" . $var concat mis-parse -------------------
//
// `_extractBody` (the function-BODY brace-matcher, distinct from
// `_splitStatements`'s own body-internal comment handling above) had ZERO
// comment awareness at all: an apostrophe inside ANY comment ("don't",
// "it's" — extremely common in real PHP) toggled its string-tracking state
// exactly as if a string literal had started, corrupting brace-depth
// counting for everything after it. Depending on what followed, this either
// made `_extractBody` return null (silently dropping the ENTIRE FILE's IR —
// a single failed top-level function match corrupts every span downstream)
// or extracted a wrong body. Fixed by making `_extractBody` skip all three
// PHP comment forms (`//`, `#`, `/* */`) exactly like `_splitStatements`
// already did for two of them.

test('parsePhpFile: an apostrophe inside a // comment BEFORE a function does not drop the whole file\'s IR', () => {
  const code = `<?php
// This won't work if we don't handle apostrophes right.
function f($conn) {
    mysqli_query($conn, 'x');
}
`;
  const ir = parsePhpFile('f.php', code);
  assert.equal(ir.functions.length, 1, `expected function f to be found, got: ${JSON.stringify(ir.functions.map(fn => fn.name))}`);
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the sink inside the function to still be captured');
});

test('parsePhpFile: an apostrophe inside a // comment INSIDE a function body does not corrupt or drop that function\'s IR', () => {
  const code = `<?php
function f($conn) {
    // don't forget to sanitize this someday
    mysqli_query($conn, 'x');
}
`;
  const ir = parsePhpFile('f.php', code);
  assert.equal(ir.functions.length, 1, 'expected function f to still be found');
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the sink to still be captured despite the apostrophe in the preceding comment');
});

// `#`-style comments (PHP's third comment form) were entirely invisible to
// `_splitStatements` — only `//`/`/* */` were handled — so a `#`-comment's
// text (including any apostrophe, brace, or stray `;`) was parsed as
// literal code. PHP 8 attributes (`#[Attribute]`) share the leading `#` but
// are NOT a comment; `#[` is excluded from both the `_extractBody` and
// `_splitStatements` fixes.
test('parsePhpFile: a #-style comment (PHP\'s third comment form) with an apostrophe does not corrupt the CFG', () => {
  const code = `<?php
function f($conn) {
    # don't forget to sanitize this someday
    mysqli_query($conn, 'x');
}
`;
  const ir = parsePhpFile('f.php', code);
  assert.equal(ir.functions.length, 1, 'expected function f to still be found');
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the sink to still be captured despite the # comment');
});

test('parsePhpFile: a PHP 8 attribute (#[...]) immediately before a function is not mistaken for a comment', () => {
  const code = `<?php
#[Route("/users")]
function f($conn) {
    mysqli_query($conn, 'x');
}
`;
  const ir = parsePhpFile('f.php', code);
  assert.equal(ir.functions.length, 1, 'expected function f to still be found with a #[...] attribute preceding it');
  const calls = callNodes(ir, 'f');
  assert.ok(calls.some(c => c.callee === 'mysqli_query'), 'expected the sink inside the function to still be captured');
});

// `"literal" . $var` — arguably the single most common real-world PHP SQL
// injection shape — used to be swallowed whole into one opaque `literal`
// node (first by the double-quoted-interpolation branch misreading the
// concat's trailing ` . $var` as string content, then — once that was
// fixed — by the plain string-literal fallback doing the exact same
// unanchored-prefix mistake one layer down). Both `_lowerExpr` branches now
// require the FULL trimmed expression to be one CLOSED literal (anchored
// start and end) before treating it as a bare string, so a concat correctly
// falls through to the `.`-splitting branch instead.
test('parsePhpFile: "literal" . $var concat preserves $var\'s taint as a real ident node (not swallowed into one literal)', () => {
  const code = `<?php
function f($conn) {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = " . $id;
    $conn->query($sql);
}
`;
  const ir = parsePhpFile('f.php', code);
  const fn = ir.functions.find(fnc => fnc.name === 'f');
  const assign = Object.values(fn.cfg.nodes).find(n => n.kind === 'assign' && n.target === '$sql');
  assert.ok(assign, 'expected an assign node for $sql');
  assert.equal(assign.source.kind, 'tpl', `expected a tpl (concat) node, got kind: ${assign.source.kind}`);
  const identPart = assign.source.parts.find(p => p.kind === 'ident' && p.name === '$id');
  assert.ok(identPart, `expected $id to survive as a real ident part, got parts: ${JSON.stringify(assign.source.parts)}`);
});

test('parsePhpFile: end-to-end — "literal" . $_GET-derived $var into a PDO sink fires SQL Injection via IR-TAINT', async () => {
  const { runScan } = await import('../src/runScan.js');
  const dir = mkTmp({
    'run.php': `<?php
function handler($conn) {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = " . $id;
    $conn->query($sql);
}
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const taint = (scan.findings || []).filter(fd => fd.parser === 'IR-TAINT');
  assert.ok(taint.some(fd => /sql injection/i.test(fd.vuln)),
    `expected a SQL Injection finding, got: ${taint.map(fd => fd.vuln).join(', ') || '(none)'}`);
});
