import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';

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
