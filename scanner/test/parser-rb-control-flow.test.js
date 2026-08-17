// Ruby — full CFG rebuild (taint-recall PRD 80%, Tier 4/P5).
//
// Before this task, parseRubyFile's _buildCfg only recursed into if/unless
// and while/until bodies — for, case/when, begin/rescue/ensure, and any
// trailing block attached to a call (`xs.each do |x| ... end`, the
// dominant Rails/ActiveRecord idiom) were silently dropped entirely (no
// _lowerStmt branch recognized them, so the whole chunk vanished with no
// CFG node at all). A `do` block's opener keyword also had to be at the
// START of a line to even be recognized as starting a depth-tracked chunk,
// so `xs.each do |x|` (trailing `do`, extremely common) wasn't just
// unrecursed — it split each of its own body lines into independent,
// nonsensical top-level statements. This file pins the rebuild.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRubyFile } from '../src/ir/parser-rb.js';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function callNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'call');
}
function assignNodes(ir, fnName) {
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected function "${fnName}"`);
  return Object.values(fn.cfg.nodes).filter(n => n.kind === 'assign');
}

test('parseRubyFile: a sink inside a for-loop body is captured, with the loop variable bound to the iterated expression', () => {
  const ir = parseRubyFile('f.rb', `
def run(ids)
  for id in ids
    db.execute(id)
  end
end
`);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'db.execute'),
    `expected the sink inside the for body, got: ${JSON.stringify(calls)}`);
  const assigns = assignNodes(ir, 'run');
  const bind = assigns.find(a => a.target === 'id');
  assert.ok(bind, `expected the loop variable bound, got: ${JSON.stringify(assigns)}`);
  assert.equal(bind.source.name, 'ids');
});

test('parseRubyFile: a sink inside a case/when arm is captured (every arm reachable from the case entry)', () => {
  const ir = parseRubyFile('f.rb', `
def run(mode, id)
  case mode
  when "a"
    db.execute(id)
  when "b"
    other_sink(id)
  else
    default_sink(id)
  end
end
`);
  const calls = callNodes(ir, 'run');
  const callees = calls.map(c => c.callee);
  assert.ok(callees.includes('db.execute'), `expected the "a" arm's sink, got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('other_sink'), `expected the "b" arm's sink, got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('default_sink'), `expected the else arm's sink, got: ${JSON.stringify(callees)}`);
});

test('parseRubyFile: case/when does not collide with a nested if/else\'s own else', () => {
  const ir = parseRubyFile('f.rb', `
def run(mode, cond, id)
  case mode
  when "a"
    if cond
      inner_then(id)
    else
      inner_else(id)
    end
  else
    outer_else(id)
  end
end
`);
  const calls = callNodes(ir, 'run');
  const callees = calls.map(c => c.callee);
  assert.ok(callees.includes('inner_then'), `expected inner_then, got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('inner_else'), `expected inner_else (not swallowed by the case's own else), got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('outer_else'), `expected the case's own else arm, got: ${JSON.stringify(callees)}`);
});

test('parseRubyFile: a sink inside begin/rescue/ensure is captured in all three clauses', () => {
  const ir = parseRubyFile('f.rb', `
def run(id)
  begin
    risky(id)
  rescue StandardError => e
    handle_error(id)
  ensure
    cleanup(id)
  end
end
`);
  const calls = callNodes(ir, 'run');
  const callees = calls.map(c => c.callee);
  assert.ok(callees.includes('risky'), `expected the begin body's call, got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('handle_error'), `expected the rescue clause's call, got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('cleanup'), `expected the ensure clause's call, got: ${JSON.stringify(callees)}`);
});

test('parseRubyFile: a trailing do...end block on a call is recursed into, with the receiver bound to the block parameter', () => {
  const ir = parseRubyFile('f.rb', `
def run(ids)
  ids.each do |id|
    db.execute(id)
  end
end
`);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'ids.each'), `expected the trigger call itself, got: ${JSON.stringify(calls.map(c=>c.callee))}`);
  assert.ok(calls.some(c => c.callee === 'db.execute'), `expected the sink inside the block body, got: ${JSON.stringify(calls.map(c=>c.callee))}`);
  const assigns = assignNodes(ir, 'run');
  const bind = assigns.find(a => a.target === 'id');
  assert.ok(bind, `expected "id" bound to the receiver, got: ${JSON.stringify(assigns)}`);
  assert.equal(bind.source.name, 'ids');
});

test('parseRubyFile: a trailing do...end block with a bare "do" (no line-initial keyword) is not mis-split line by line', () => {
  // Before the fix, only a LINE-INITIAL opener started a depth-tracked
  // chunk — `ids.each do |id|` has "do" mid-line, so each line of the
  // body (and the closing "end") were emitted as independent, nonsensical
  // top-level statements instead of one recursed-into block.
  const ir = parseRubyFile('f.rb', `
def run(ids)
  ids.each do |id|
    a(id)
    b(id)
  end
  c()
end
`);
  const calls = callNodes(ir, 'run');
  const callees = calls.map(c => c.callee);
  assert.ok(callees.includes('a'), `expected a(), got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('b'), `expected b(), got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('c'), `expected c() after the block to still parse correctly, got: ${JSON.stringify(callees)}`);
});

test('parseRubyFile: a trailing brace block { |x| ... } on a call is recognized as a call with its own real argument (not requiring body recursion for this shape)', () => {
  // Nokogiri::XML(xml) { |config| ... } — the vulnerability here is
  // entirely in the trigger call's own argument (xml); this test pins
  // that the "::"-scoped call itself is no longer swallowed or corrupted
  // by the trailing brace block, independent of whether the block BODY
  // is separately recursed into (brace-form body recursion is out of
  // scope for this task — do...end is the dominant Rails idiom and was
  // fixed; the brace form's call-recognition-with-trailing-content was
  // the part blocking a real corpus fixture).
  const ir = parseRubyFile('f.rb', `
def run(xml)
  Nokogiri::XML(xml) { |config| config.noent }
end
`);
  const calls = callNodes(ir, 'run');
  const trigger = calls.find(c => c.callee === 'Nokogiri.XML');
  assert.ok(trigger, `expected Nokogiri::XML(xml) normalized to Nokogiri.XML, got: ${JSON.stringify(calls)}`);
  assert.deepEqual(trigger.args, [{ kind: 'ident', name: 'xml' }]);
});

test('parseRubyFile: Ruby\'s "::" module-scope call operator is recognized (was previously invisible to matchBalancedCall entirely)', () => {
  const ir = parseRubyFile('f.rb', `
def run(xml)
  Nokogiri::XML(xml)
end
`);
  const calls = callNodes(ir, 'run');
  assert.ok(calls.some(c => c.callee === 'Nokogiri.XML'),
    `expected a Nokogiri.XML call node, got: ${JSON.stringify(calls)}`);
});

test('parseRubyFile: string concatenation with + starting with a quoted literal is not swallowed whole as one opaque literal', () => {
  const ir = parseRubyFile('f.rb', `
def run(name)
  path = "/var/data/" + name
  File.read(path)
end
`);
  const assigns = assignNodes(ir, 'run');
  const pathAssign = assigns.find(a => a.target === 'path');
  assert.ok(pathAssign, 'expected an assign to path');
  assert.equal(pathAssign.source.kind, 'tpl', `expected a tpl (concat), got: ${JSON.stringify(pathAssign.source)}`);
  assert.ok(pathAssign.source.parts.some(p => p.kind === 'ident' && p.name === 'name'),
    `expected "name" to survive as one of the concat parts, got: ${JSON.stringify(pathAssign.source)}`);
});

test('parseRubyFile: a plain string literal containing a "+" character is NOT incorrectly split', () => {
  const ir = parseRubyFile('f.rb', `
def run
  x = "a+b"
end
`);
  const assigns = assignNodes(ir, 'run');
  const xAssign = assigns.find(a => a.target === 'x');
  assert.equal(xAssign.source.kind, 'literal');
  assert.equal(xAssign.source.value, '"a+b"');
});

test('parseRubyFile: a subscript-assignment on a member chain (response.headers[key] = value) lowers to a synthetic [] = call', () => {
  const ir = parseRubyFile('f.rb', `
def run(trace)
  response.headers["X-Trace"] = trace
end
`);
  const calls = callNodes(ir, 'run');
  const setitem = calls.find(c => c.callee === 'response.headers.[]=');
  assert.ok(setitem, `expected a response.headers.[]= call, got: ${JSON.stringify(calls)}`);
  assert.equal(setitem.args.length, 2);
  assert.equal(setitem.args[1].kind, 'ident');
  assert.equal(setitem.args[1].name, 'trace');
});

test('parseRubyFile: deeply nested control flow does not overflow the stack (recursion depth guard)', () => {
  const n = 200;
  const code = `def f(id)\n${'if id\n'.repeat(n)}sink(id)\n${'end\n'.repeat(n)}end`;
  const ir = parseRubyFile('f.rb', code);
  assert.ok(ir, 'expected parseRubyFile to return a result instead of throwing');
  const fn = ir.functions.find(f => f.name === 'f');
  assert.ok(fn, 'expected a "functions" entry for f, proving the parse completed');
});

test('parseRubyFile: deeply nested trailing blocks do not overflow the stack (recursion depth guard)', () => {
  const n = 200;
  const code = `def f(id)\n${'xs.each do |id|\n'.repeat(n)}sink(id)\n${'end\n'.repeat(n)}end`;
  const ir = parseRubyFile('f.rb', code);
  assert.ok(ir, 'expected parseRubyFile to return a result instead of throwing');
  const fn = ir.functions.find(f => f.name === 'f');
  assert.ok(fn, 'expected a "functions" entry for f, proving the parse completed');
});

test('parseRubyFile: end-to-end runScan detects taint flowing through a case/when arm into a sink', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rb-case-'));
  fs.writeFileSync(path.join(dir, 'app.rb'), `
def run(mode, params)
  code = params[:code]
  case mode
  when "eval"
    eval(code)
  end
end
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1,
    `expected an IR-TAINT finding through the case/when arm, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});

test('parseRubyFile: end-to-end runScan detects taint flowing through a do...end block parameter into a sink', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rb-block-'));
  fs.writeFileSync(path.join(dir, 'app.rb'), `
def run(params)
  codes = params[:code]
  codes.each do |code|
    eval(code)
  end
end
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1,
    `expected an IR-TAINT finding through the do...end block's "code" binding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
