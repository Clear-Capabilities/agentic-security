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
