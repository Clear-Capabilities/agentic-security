// Stage 3 correctness audit (detection depth, per-language-IR): Ruby's
// parseRubyFile never emitted `fn.calls` at all — ir/CLAUDE.md documents
// only the Python regex fallback as having this gap; Ruby had it
// unconditionally, for every Ruby file, always. tabulation.js,
// dataflow/index.js and callgraph.js all read `fn.calls` to build
// cross-function call edges — an absent array is indistinguishable from
// "this function calls nothing," which left callgraph.js's edges/
// callersOf/resolveKnownCallee permanently empty for Ruby, in turn
// disabling dead-code-demotion accuracy and any interprocedural signal
// that specifically depends on call-graph resolution rather than the
// generic tainted-call-argument fallback in engine.js's exprTaint.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseRubyFile } from '../src/ir/parser-rb.js';
import { buildCallGraph } from '../src/ir/callgraph.js';
import { runScan } from '../src/runScan.js';

test('parseRubyFile emits fn.calls for both statement-position and RHS-embedded calls', () => {
  const ir = parseRubyFile('app.rb', `
def build_query(id)
  return 'SELECT * FROM t WHERE id=' + id
end

def handler
  uid = params[:id]
  sql = build_query(uid)
  db.execute(sql)
end
`);
  assert.ok(ir, 'expected a parsed IR');
  const handler = ir.functions.find(f => f.name === 'handler');
  assert.ok(handler, 'expected a handler function');
  assert.ok(Array.isArray(handler.calls), 'fn.calls must be an array, not absent');
  const callees = handler.calls.map(c => c.callee);
  assert.ok(callees.includes('build_query'), `expected build_query in fn.calls, got: ${JSON.stringify(callees)}`);
  assert.ok(callees.includes('db.execute'), `expected db.execute in fn.calls, got: ${JSON.stringify(callees)}`);
});

test('buildCallGraph resolves a real edge for a Ruby call site (was always empty for every Ruby function)', () => {
  // The most precisely-scoped observable: callgraph.js derives edges/
  // callersOf/resolveKnownCallee entirely from fn.calls (line 146,
  // `for (const c of (fn.calls || []))`) — with fn.calls always absent,
  // Ruby had ZERO edges, ZERO callersOf entries, and resolveKnownCallee
  // could never resolve a Ruby callee, for every Ruby project ever
  // scanned. This is the direct dependency the fix repairs; an
  // end-to-end taint test alone can't isolate it, since a separate,
  // legitimate fallback in engine.js's exprTaint (`case 'call': return
  // args.some(a => exprTaint(a, state))`) taints an assignment whose RHS
  // is ANY call with a tainted argument, which would mask this specific
  // bug in an end-to-end scenario built around a returned value.
  const ir = parseRubyFile('app.rb', `
def build_cmd(id)
  system('echo ' + id)
end

def handler
  uid = params[:id]
  build_cmd(uid)
end
`);
  const callGraph = buildCallGraph({ 'app.rb': ir }, {});
  const handlerFn = ir.functions.find(f => f.name === 'handler');
  const buildCmdFn = ir.functions.find(f => f.name === 'build_cmd');
  assert.ok(handlerFn && buildCmdFn, 'expected both functions in the IR');
  assert.ok(callGraph.callersOf.has(buildCmdFn.qid),
    `expected build_cmd to have a recorded caller; callersOf keys: ${JSON.stringify([...callGraph.callersOf.keys()])}`);
  const resolved = callGraph.resolveKnownCallee('build_cmd', 'app.rb');
  assert.equal(resolved, buildCmdFn.qid, 'resolveKnownCallee must resolve the Ruby call site to the real function');
});

test('a Ruby helper that returns a tainted value is detected interprocedurally at its caller\'s sink', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rbcalls-'));
  fs.writeFileSync(path.join(dir, 'app.rb'), `
def build_cmd(id)
  return 'echo ' + id
end

def handler
  uid = params[:id]
  cmd = build_cmd(uid)
  system(cmd)
end
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected system(cmd) to fire via interprocedural taint through build_cmd(id), got IR-TAINT findings: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('the same helper called with a literal argument does not fire (control)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rbcalls-control-'));
  fs.writeFileSync(path.join(dir, 'app.rb'), `
def build_cmd(id)
  return 'echo ' + id
end

def handler
  cmd = build_cmd('literal')
  system(cmd)
end
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.equal(cmdFindings.length, 0, 'a literal argument must not trigger a finding');
});
