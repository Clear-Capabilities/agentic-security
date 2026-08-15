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

// R14(b) final whole-branch review, Finding 3 (IMPORTANT): `class`/`module`
// were missing from the bare-call exclusion list, so a `class Foo < Bar`
// wrapper (the single most common top-level Ruby idiom) lowered to a bogus
// `{kind:'call', callee:'class', ...}` node. Before R14(b), top-level text
// was never fed through `_lowerStmt` at all, so this never mattered; the
// module-level lowering now feeds every top-level statement through it,
// which falsified the plan's own "zero existing fixtures gain a <module>
// entry" constraint — a sweep of this repo's own Ruby files found 30 of 45
// gaining a spurious <module> whose CFG held only this one bogus node.
test('parseRubyFile: a class wrapper with no other top-level statements gets no <module> entry', () => {
  const code = `class FooController < ApplicationController
  def show(request)
    name = request.input('name')
    return name
  end
end
`;
  const ir = parseRubyFile('foo_controller.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1, 'no synthetic <module> entry should be added — the class wrapper is not real top-level content');
  assert.equal(ir.topLevel, null);
  const show = ir.functions.find(f => f.name === 'show');
  assert.ok(show, 'the wrapped method must still be extracted unchanged');
});

// R14(b) final whole-branch review, Finding 2 (IMPORTANT): module-level CFG
// nodes must report their REAL source line, not an approximation derived
// from re-counting newlines in already-joined, already-trimmed gap text
// (which silently loses any blank line, or blanked-out def span, that
// preceded the statement). This fixture places the sink several lines past
// a def declaration so an off-by-N error (not just off-by-1) would be
// caught.
test('parseRubyFile: a module-level statement past a def declaration reports its exact real source line', () => {
  const code = `def helper(x)
  return x
end

cmd = params[:cmd]
system(cmd)
`;
  const ir = parseRubyFile('lines.rb', code);
  assert.ok(ir);
  const mod = ir.functions.find(f => f.name === '<module>');
  assert.ok(mod);
  const nodes = Object.values(mod.cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === 'cmd');
  const call = nodes.find(n => n.kind === 'call' && n.callee === 'system');
  assert.ok(assign, 'expected the cmd assignment');
  assert.ok(call, 'expected the system() call');
  assert.equal(assign.line, 5, 'assignment is on real source line 5');
  assert.equal(call.line, 6, 'call is on real source line 6');
});
