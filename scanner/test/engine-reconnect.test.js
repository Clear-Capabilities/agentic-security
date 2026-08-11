// Tests for the Phase 1 engine-reconnect work.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR } from '../src/ir/index.js';
import { functionRecord } from '../src/ir/callgraph.js';
import { runTaintEngine } from '../src/dataflow/engine.js';
import { runScan } from '../src/runScan.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

// This suite scans fixture directories that live IN THE REPOSITORY. Without
// this, every run left `.agentic-security/` inside
// bench/engine-reconnect/fixtures/{js,py,cpp} — three directories that showed
// up in a stray-state audit long after the bench runners themselves had been
// fixed. A test that scans a tracked tree has the same obligation a benchmark
// does: observe it, do not modify it.
setStateWritesEnabled(false);
import * as path from 'node:path';

const FIXTURES = path.resolve('../bench/engine-reconnect/fixtures');

async function scanFixture(rel) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  const { scan } = await runScan(path.join(FIXTURES, rel));
  return [...(scan.findings || []), ...(scan.logicVulns || [])];
}

test('functionRecord: resolves a qid string to its record', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function helper(x){ return x; }\nfunction main(r){ return helper(r.query.q); }\n',
  });
  const helperQid = perFile['a.js'].functions.find(f => f.name === 'helper').qid;
  const rec = functionRecord(callGraph, helperQid);
  assert.ok(rec, 'a qid string must resolve to a record');
  assert.equal(rec.qid, helperQid);
  assert.ok(Array.isArray(rec.params), 'the record must carry params so binding can happen');
});

test('functionRecord: passes a record through unchanged', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function helper(x){ return x; }\n',
  });
  const rec = perFile['a.js'].functions[0];
  assert.equal(functionRecord(callGraph, rec), rec);
});

test('functionRecord: null, unknown qid and bad input yield null, never throw', () => {
  const { callGraph } = buildProjectIR({ 'a.js': 'function f(){}\n' });
  assert.equal(functionRecord(callGraph, null), null);
  assert.equal(functionRecord(callGraph, 'no-such-qid'), null);
  assert.equal(functionRecord(callGraph, 42), null);
  assert.equal(functionRecord(null, 'x'), null);
  assert.equal(functionRecord(undefined, undefined), null);
});

// Blocker A regression (found after the initial functionRecord fix landed):
// parser-js.js always emits a CFG call node's callee as an expression object
// ({kind:'ident',name} or {kind:'member',...}), never a bare string. Several
// engine.js sites derived the name to feed callGraph.resolve() via
// `typeof callee === 'string' ? callee : null`, which is always null for JS
// — so the interprocedural resolve path was never even entered for JS,
// independent of the functionRecord fix. This test calls runTaintEngine
// directly (bypassing runScan) so a regression here is localized to the
// callee-flattening logic in engine.js, not conflated with the full pipeline
// or with Blocker B below.
test('engine: an object-shaped (JS) callee still resolves for interprocedural taint (Blocker A)', () => {
  const code = 'function readInput(req){ return req.query.cmd; }\n'
    + 'function runIt(req){ const cmd = readInput(req); require("child_process").exec(cmd); }\n';
  const { perFile, callGraph } = buildProjectIR({ 'app.js': code });
  const findings = runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 });
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.ok(ir.length >= 1,
    `expected at least one IR-TAINT finding from a bare-name JS call; got ${findings.length}`);
});

// Blocker B regression: exprTaint()'s only source-recognition check was
// `expr.kind === 'member' && exprIsSource(expr)` — a call-shaped source
// (e.g. `getenv("X")`, `request.args.get("x")`) was never recognized when it
// is the VALUE of a return statement, because the 'return' case's exprTaint
// call never reached exprIsSource for a 'call' expr (only the sibling
// 'assign' case did, via a separate `exprIsSource` call). A helper whose
// entire body is `return <source-call>(...)` therefore never had its summary
// marked returnTainted. Isolated here as a direct return-of-call-source case,
// independent of Blocker A (this snippet's callees are still plain idents).
//
// Uses a Python fixture (`os.getenv`, catalogued as `py-os-getenv`) rather
// than the original bare `getenv("CMD")` tagged as `app.js`: the catalog has
// no call-shaped JS source at all, so that original fixture only ever
// "passed" because `getenv` matched cross-language (py/java/kt/cpp all
// declare a `getenv` source and, before Phase 2's table-driven
// `_languageAllowed`, none of those non-js/cpp entries were scoped by file
// extension). Now that every catalog language is scoped, the mechanism this
// test guards needs a fixture where the source is genuinely catalogued for
// the language it's tagged as.
test('engine: a call-shaped source returned from a helper taints the caller (Blocker B)', () => {
  const code = 'def read_env():\n    return os.getenv("CMD")\n\n'
    + 'def run_it():\n    cmd = read_env()\n    __import__("os").system(cmd)\n';
  const { perFile, callGraph } = buildProjectIR({ 'app.py': code });
  const findings = runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 });
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.ok(ir.length >= 1,
    `expected at least one IR-TAINT finding from a call-shaped return source; got ${findings.length}`);
});

// Stage 1 correctness audit: catalog.js labels every source with a
// `provenance` (e.g. 'http-body' for req.body) so findings can be
// attributed, and the engine faithfully tracks it per-source-instance while
// walking (`_taintSources`) and computes a `sourceProvenance` per finding —
// but the FINAL exported finding's `chain` array (built here in
// runTaintEngine) stripped `.provenance` down to {file,line,label}, and
// `sourceProvenance` was never copied onto the finding at all. Consumer:
// posture/exploitability-probability.js's 'source-from-network' factor reads
// `t.provenance` off `chain`/`trace` entries — with the field always
// missing from every finding in every real scan, that 1.3x exploitability
// boost for plainly network-controlled sources (req.body/headers/cookies)
// could never fire, for any finding, from any producer.
test('engine: a network-provenance source (req.body) survives onto the finding\'s chain and sourceProvenance', () => {
  const code = 'function h(req, db){ var q = req.body.q; db.query("SELECT * FROM t WHERE a = " + q); }\n';
  const { perFile, callGraph } = buildProjectIR({ 'app.js': code });
  const findings = runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 });
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.ok(ir.length >= 1, `expected at least one IR-TAINT finding; got ${findings.length}`);
  const f = ir[0];
  assert.equal(f.sourceProvenance, 'http-body', `expected sourceProvenance on the finding, got: ${JSON.stringify(f.sourceProvenance)}`);
  assert.ok(Array.isArray(f.chain) && f.chain.length > 0, 'expected a non-empty chain');
  assert.equal(f.chain[0].provenance, 'http-body', `expected chain[0].provenance to survive, got: ${JSON.stringify(f.chain[0])}`);
});

test('interprocedural: a JS source in one function reaches a sink in another', async () => {
  const findings = await scanFixture('js');
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.ok(ir.length >= 1,
    `expected at least one IR-TAINT finding; got ${findings.length} findings, none from the IR engine`);
});

test('interprocedural: the same holds for Python', async () => {
  const findings = await scanFixture('py');
  assert.ok(findings.filter(f => (f.parser || '') === 'IR-TAINT').length >= 1);
});

test('interprocedural: the same holds for C++', async () => {
  const findings = await scanFixture('cpp');
  assert.ok(findings.filter(f => (f.parser || '') === 'IR-TAINT').length >= 1);
});

// Finding 1 (engine-reconnect review): a member call's flattened name
// (`loader.read()` -> "loader.read") must NOT be handed to
// callGraph.resolve() — resolve()'s generic dotted-name fallback strips it
// to the last segment ("read") and matches ANY same-named function
// project-wide, inventing a call edge that does not exist. Here `read()` is
// a wholly unrelated local function; `loader.read()` should produce no
// interprocedural finding at all (a missing edge, not a wrong one).
test('engine: a member call does not resolve to an unrelated same-named local function', () => {
  const code = 'function read(){ return getenv("CMD"); }\n'
    + 'function f(){ const c = loader.read(); require("child_process").exec(c); }\n';
  const { perFile, callGraph } = buildProjectIR({ 'app.js': code });
  const findings = runTaintEngine(perFile, callGraph, { fnLimit: 5000, deadlineMs: Date.now() + 30000 });
  const ir = findings.filter(f => (f.parser || '') === 'IR-TAINT');
  assert.equal(ir.length, 0,
    `expected no IR-TAINT finding for an unrelated member call; got ${ir.length}: ${JSON.stringify(ir.map(f => f.vuln))}`);
});

test('reverse call map: keys are qids, not stringified objects', () => {
  const { perFile, callGraph } = buildProjectIR({
    'a.js': 'function helper(x){ return x; }\nfunction main(r){ return helper(r.query.q); }\n',
  });
  const helperQid = perFile['a.js'].functions.find(f => f.name === 'helper').qid;
  const callers = {};
  for (const fn of callGraph.functions.values()) {
    for (const c of (fn.calls || [])) {
      const key = c && c.callee ? (callGraph.resolve(c.callee, fn.file) || null) : null;
      if (!key) continue;
      (callers[key] = callers[key] || []).push(fn.qid);
    }
  }
  assert.ok(!Object.keys(callers).includes('[object Object]'),
    'an entry object must never be used as a key');
  assert.ok(callers[helperQid] && callers[helperQid].length >= 1,
    'helper must have at least one recorded caller, keyed by qid');
});

// Regression (post-Task-3 review): the reverse-call-map fix above
// reintroduced the exact member-call guess Task 2 had already fixed in
// dataflow/engine.js — both new call sites handed a flattened dotted name
// ("loader.read") straight to callGraph.resolve(), which still guesses via
// its bare-tail fallback. The fix moves the guard into callgraph.js itself
// (callGraph.resolveKnownCallee), the single place every caller — engine.js,
// dataflow/index.js, dataflow/tabulation.js — now shares, so it cannot be
// forgotten by a future call site the way it was here.
test('shared guard: resolveKnownCallee refuses to guess a member call to an unrelated same-named function (root-caused in callgraph.js)', () => {
  const code = 'function read(){ return 1; }\n'
    + 'function f(loader){ return loader.read(); }\n';
  const { perFile, callGraph } = buildProjectIR({ 'app.js': code });
  const fFn = perFile['app.js'].functions.find(fn => fn.name === 'f');
  const readQid = perFile['app.js'].functions.find(fn => fn.name === 'read').qid;
  const call = fFn.calls.find(c => c.callee === 'loader.read');
  assert.ok(call, 'expected the IR to record a loader.read call site in fn.calls');

  // The permissive resolve() still does the tail-guess by design (documents
  // the contrast — this is why every reverse-call-map builder must use the
  // guess-free entry point instead).
  assert.equal(callGraph.resolve(call.callee, fFn.file), readQid,
    'resolve() keeps its existing permissive tail-guess for callers that already accept it');

  // resolveKnownCallee — the shared, guess-free entry point — must refuse.
  assert.equal(callGraph.resolveKnownCallee(call.callee, fFn.file), null,
    'resolveKnownCallee must not guess loader.read() -> read()');

  // End-to-end: reproduce the exact reverse-map construction used by
  // dataflow/index.js and dataflow/tabulation.js and confirm no bogus
  // caller edge f -> read is fabricated.
  const callers = {};
  for (const fn of callGraph.functions.values()) {
    for (const c of (fn.calls || [])) {
      if (!c || !c.callee) continue;
      const qid = callGraph.resolveKnownCallee(c.callee, fn.file);
      if (!qid) continue;
      (callers[qid] = callers[qid] || []).push(fn.qid);
    }
  }
  assert.ok(!(callers[readQid] || []).includes(fFn.qid),
    'loader.read() must not be recorded as a caller edge to read()');
});

// Confirms the fix didn't overcorrect: a genuine cross-file bare-name call
// (no receiver, no guessing needed) must still register its caller in the
// same reverse-map construction. This is the case Task 3 exists to make
// work — a real reverse edge, not a fabricated one.
test('shared guard: a genuine cross-file bare-name call still registers its caller', () => {
  const { perFile, callGraph } = buildProjectIR({
    'b.js': 'function fill(x){ return x; }\nmodule.exports = { fill };\n',
    'a.js': 'function f(r){ return fill(r.query.q); }\n',
  });
  const fillQid = perFile['b.js'].functions.find(fn => fn.name === 'fill').qid;
  const fFn = perFile['a.js'].functions.find(fn => fn.name === 'f');

  const callers = {};
  for (const fn of callGraph.functions.values()) {
    for (const c of (fn.calls || [])) {
      if (!c || !c.callee) continue;
      const qid = callGraph.resolveKnownCallee(c.callee, fn.file);
      if (!qid) continue;
      (callers[qid] = callers[qid] || []).push(fn.qid);
    }
  }
  assert.ok(callers[fillQid] && callers[fillQid].includes(fFn.qid),
    'a genuine cross-file bare-name call must still produce a caller edge, keyed by qid');
});

test('python: fn.calls is populated with the documented shape', () => {
  const { perFile } = buildProjectIR({
    'a.py': 'def helper(x):\n    return x\n\n\ndef main(r):\n    v = helper(r)\n    return v\n',
  });
  const ir = perFile['a.py'];
  assert.ok(ir, 'the Python file must produce IR');
  const main = ir.functions.find(f => f.name === 'main');
  assert.ok(Array.isArray(main.calls) && main.calls.length >= 1,
    'main must record its call to helper');
  const c = main.calls.find(x => x.callee === 'helper');
  assert.ok(c, 'the callee name must be recorded');
  assert.ok(c.site && main.cfg.nodes[c.site], 'site must reference a real CFG node id');
  assert.ok(Array.isArray(c.args), 'args must be an array');
  assert.ok(typeof c.line === 'number' && c.line > 0, 'line must be set');
});

import { applySanitizerGate, _sanitizerFamilies } from '../src/dataflow/sanitizer-gate.js';

test('sanitizer gate: families beyond sql are recognised', () => {
  const fams = _sanitizerFamilies();
  for (const f of ['sql', 'xss', 'url', 'cmd']) {
    assert.ok(fams.includes(f), `${f} must be a recognised sanitizer family`);
  }
});

test('sanitizer gate: a sanitized finding is labelled, never removed', () => {
  const findings = [
    { id: 'a', vuln: 'Reflected XSS', cwe: 'CWE-79', file: 'a.js', line: 3, severity: 'high' },
  ];
  const out = applySanitizerGate(findings, {
    sanitizersOnPath: { a: ['escapeHtml'] },
  });
  assert.equal(out.length, 1, 'the finding must never be dropped');
  assert.equal(out[0].sanitized, true);
  assert.deepEqual(out[0].sanitizerProof.sanitizers, ['escapeHtml']);
  assert.equal(out[0].sanitizerProof.family, 'xss');
});

test('sanitizer gate: a mismatched family does not mark the finding', () => {
  const findings = [
    { id: 'a', vuln: 'SQL Injection', cwe: 'CWE-89', file: 'a.js', line: 3, severity: 'critical' },
  ];
  const out = applySanitizerGate(findings, { sanitizersOnPath: { a: ['escapeHtml'] } });
  assert.equal(out[0].sanitized, undefined,
    'an xss sanitizer must not clear a sql finding');
});

test('sanitizer gate: tolerates missing context without throwing', () => {
  const findings = [{ id: 'a', vuln: 'X', cwe: 'CWE-1', file: 'a.js', line: 1 }];
  assert.equal(applySanitizerGate(findings, {}).length, 1);
  assert.equal(applySanitizerGate(findings, null).length, 1);
  assert.equal(applySanitizerGate(null, null).length, 0);
});
