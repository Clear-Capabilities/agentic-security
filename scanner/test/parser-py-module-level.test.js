import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePythonFile } from '../src/ir/parser-py.js';

test('parsePythonFile (regex fallback): top-level statements lower into a synthetic <module> function', () => {
  const code = `import os

cmd = request.args
os.system(cmd)
`;
  const ir = parsePythonFile('flat.py', code);
  assert.ok(ir);
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod, 'expected a synthetic <module> function for top-level statements');
  assert.equal(ir.topLevel, mod.qid);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === 'cmd'));
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'os.system'));
});

test('parsePythonFile (regex fallback): a function-only file gets no <module> entry', () => {
  const code = `def f(x):
    return x + 1
`;
  const ir = parsePythonFile('funcs_only.py', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.topLevel, null);
});

test('parsePythonFile (regex fallback): top-level statements interleaved with a function are all captured', () => {
  const code = `x = request.args

def helper(y):
    return y

os.system(x)
`;
  const ir = parsePythonFile('interleaved.py', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2, 'expected helper() plus the synthetic <module>');
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === 'x'), 'expected the pre-function assignment');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'os.system'), 'expected the post-function call');
  const helper = ir.functions.find(f => f.name === 'helper');
  assert.ok(helper, 'the real function must still be extracted unchanged');
});
