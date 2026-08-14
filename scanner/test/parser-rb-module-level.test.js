import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRubyFile } from '../src/ir/parser-rb.js';

test('parseRubyFile: a flat script with no def declarations still produces an IR via a synthetic <module>', () => {
  const code = `system(params[:cmd])
`;
  const ir = parseRubyFile('flat.rb', code);
  assert.ok(ir, 'previously this returned null for the whole file — the exact R14(b) gap');
  assert.equal(ir.functions.length, 1);
  const mod = ir.functions[0];
  assert.equal(mod.name, '<module>');
  assert.equal(ir.topLevel, mod.qid);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'));
});

test('parseRubyFile: a def-only file gets no <module> entry (conditional inclusion, unchanged behavior)', () => {
  const code = `def show(request)
  name = request.input('name')
  return name
end
`;
  const ir = parseRubyFile('controller.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1, 'no synthetic <module> entry should be added — no real top-level content in this fixture');
  assert.equal(ir.topLevel, null);
});

test('parseRubyFile: top-level statements before and after a def are both captured', () => {
  const code = `cmd = params[:cmd]
def helper(x)
  return x
end
system(cmd)
`;
  const ir = parseRubyFile('interleaved.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2, 'expected helper() plus the synthetic <module>');
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod);
  const nodes = Object.values(mod.cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === 'cmd'), 'expected the pre-def assignment');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'system'), 'expected the post-def call');
  const helper = ir.functions.find(f => f.name === 'helper');
  assert.ok(helper, 'the real function must still be extracted unchanged');
});
