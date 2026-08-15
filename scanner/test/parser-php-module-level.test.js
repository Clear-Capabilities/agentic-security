import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';

test('parsePhpFile: a flat script with no function declarations still produces an IR via a synthetic <module>', () => {
  const code = `<?php
system($_GET['cmd']);
`;
  const ir = parsePhpFile('flat.php', code);
  assert.ok(ir, 'previously this returned null for the whole file — the exact R14(b) gap');
  assert.equal(ir.functions.length, 1);
  const mod = ir.functions[0];
  assert.equal(mod.name, '<module>');
  assert.equal(ir.topLevel, mod.qid);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'));
});

test('parsePhpFile: a function-only file gets no <module> entry (conditional inclusion, unchanged behavior)', () => {
  const code = `<?php
function getUser($id) {
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    return $result;
}
`;
  const ir = parsePhpFile('app.php', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1, 'no synthetic <module> entry should be added — no real top-level content in this fixture');
  assert.equal(ir.topLevel, null);
});

test('parsePhpFile: top-level statements before and after a function declaration are both captured', () => {
  const code = `<?php
$cmd = $_GET['cmd'];
function helper($x) {
    return $x;
}
system($cmd);
`;
  const ir = parsePhpFile('interleaved.php', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2, 'expected helper() plus the synthetic <module>');
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === '$cmd'), 'expected the pre-function assignment');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'), 'expected the post-function call');
  const helper = ir.functions.find(f => f.name === 'helper');
  assert.ok(helper, 'the real function must still be extracted unchanged');
});

test('parsePhpFile: interior gap between two functions is correctly captured (critical brace-leak scenario)', () => {
  const code = `<?php
function a() {
}
$x = mysqli_query($conn, $sql);
function b() {
}
`;
  const ir = parsePhpFile('twofunc.php', code);
  assert.ok(ir, 'IR should be produced for a file with functions and top-level statements');
  assert.equal(ir.functions.length, 3, 'expected functions a, b, and synthetic <module>');
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod, 'should have synthetic <module>');
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === '$x'), 'expected the interior assignment to be captured in the <module>');
  const a = ir.functions.find(f => f.name === 'a');
  const b = ir.functions.find(f => f.name === 'b');
  assert.ok(a && b, 'both real functions must be extracted unchanged');
});

// R14(b) final whole-branch review, Finding 1 (CRITICAL): a top-level array
// literal whose string values contain a `.` nested inside brackets/quotes
// (e.g. "check.status") made `_lowerExpr`'s dot-concat branch recurse on
// its own unchanged input forever, since `_splitTopLevelDot` returns the
// input as a single un-split part when every `.` is nested. Before R14(b)
// this was only reachable from inside a function body; the module-level
// lowering now feeds every top-level statement through the same code path,
// so a file with this shape anywhere at the top level crashed the WHOLE
// file out of Layer-2 analysis (caught by ir/index.js's per-file try/catch,
// silently, with no findings for anything else in the file either).
test('parsePhpFile: a top-level array literal with a dotted string value does not crash the parser, and the real sink alongside it is still captured', () => {
  const code = `<?php
$routes = ["health" => "check.status"];
system($_GET['cmd']);
`;
  const ir = parsePhpFile('routes.php', code);
  assert.ok(ir, 'must not throw / must not silently drop the whole file');
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod, 'expected a <module> entry');
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'), 'the real sink must still be captured despite the benign array literal alongside it');
});

// R14(b) final whole-branch review, Finding 2 (IMPORTANT): module-level CFG
// nodes must report their REAL source line, not an approximation derived
// from re-counting newlines in already-trimmed gap text (which silently
// loses any blank line, or blanked-out function span, that preceded the
// statement). This fixture places the sink several lines past a function
// declaration so an off-by-N error (not just off-by-1) would be caught.
test('parsePhpFile: a module-level statement past a function declaration reports its exact real source line', () => {
  const code = `<?php
function helper($x) {
    return $x;
}

$cmd = $_GET['cmd'];
system($cmd);
`;
  const ir = parsePhpFile('lines.php', code);
  assert.ok(ir);
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod);
  const nodes = Object.values(mod.cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === '$cmd');
  const call = nodes.find(n => n.kind === 'call' && n.callee === 'system');
  assert.ok(assign, 'expected the $cmd assignment');
  assert.ok(call, 'expected the system() call');
  assert.equal(assign.line, 6, 'assignment is on real source line 6');
  assert.equal(call.line, 7, 'call is on real source line 7');
});
