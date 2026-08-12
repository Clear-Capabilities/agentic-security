// R4 — collection-element taint (deep engine). Verifies array-element taint and
// the Object.assign mutated-param path (which const→let in engine.js repaired).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { buildProjectIR } from '../src/ir/index.js';

function deepFindings(code) {
  const { perFile, callGraph } = buildProjectIR({ 'h.js': code });
  return runDeepAnalysis(perFile, callGraph, {});
}

test('array push → index read is tainted (R4)', () => {
  const f = deepFindings('function h(req){ const a = []; a.push(req.query.id); eval(a[0]); }');
  assert.ok(f.length >= 1, `expected a finding via the array element, got ${f.length}`);
});

test('array unshift → later index read is tainted', () => {
  const f = deepFindings('function h(req){ const a = []; a.unshift(req.body.cmd); eval(a[3]); }');
  assert.ok(f.length >= 1);
});

test('precision: a clean push (no tainted element) does not fire', () => {
  assert.equal(deepFindings('function h(req){ const a = []; a.push("safe"); eval(a[0]); }').length, 0);
});

test('regression: object-property taint still works', () => {
  assert.ok(deepFindings('function h(req){ const o = {}; o.cmd = req.query.id; eval(o.cmd); }').length >= 1);
});

// R4 second half — implicit / control-dependence flow (OPT-IN, default off).
function implicitFindings(code, on) {
  const prev = process.env.AGENTIC_SECURITY_IMPLICIT_FLOW;
  if (on) process.env.AGENTIC_SECURITY_IMPLICIT_FLOW = '1';
  else delete process.env.AGENTIC_SECURITY_IMPLICIT_FLOW;
  try { return deepFindings(code).filter((f) => f.implicit); }
  finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_IMPLICIT_FLOW;
    else process.env.AGENTIC_SECURITY_IMPLICIT_FLOW = prev;
  }
}

test('implicit flow is OFF by default (no implicit findings)', () => {
  assert.equal(implicitFindings('function h(req){ let p; if(req.query.x){ p=config.path; } eval(p); }', false).length, 0);
});

test('implicit flow ON: var assigned in tainted branch → sink fires (implicit, capped confidence)', () => {
  const f = implicitFindings('function h(req){ let p; if(req.query.x){ p=config.path; } eval(p); }', true);
  assert.ok(f.length >= 1);
  assert.equal(f[0].implicit, true);
  assert.ok(f[0].confidence <= 0.55, `implicit confidence should be capped, got ${f[0].confidence}`);
});

test('implicit flow ON: constant sink inside a tainted branch fires', () => {
  assert.ok(implicitFindings('function h(req){ if(req.query.x){ eval("1"); } }', true).length >= 1);
});

test('implicit flow precision: a config-constant branch (FLAG===x) does NOT fire', () => {
  assert.equal(implicitFindings('function h(req){ if(FLAG === "x"){ eval("1"); } }', true).length, 0);
});

// Stage 6 correctness audit: buildImplicitContext used to compute branch
// membership via a path-dependent DFS depth counter with no join-point
// detection — once a path entered a tainted branch, EVERY node reachable
// afterward stayed marked "inside the branch" for the rest of the
// function, including everything textually after the if/else closes. A
// constant-arg sink call genuinely OUTSIDE the branch (unrelated to the
// tainted condition, reading no implicit-tainted variable) would have been
// falsely flagged. Fixed via proper dominance analysis (a node is inside
// the branch iff the branch root dominates it), reusing ir/ssa.js's
// existing dominator computation.
test('implicit flow precision: a constant-arg sink AFTER a tainted branch closes does NOT fire (regression: branch scope must end at the join, not leak past it)', () => {
  const f = implicitFindings(
    'function h(req){ if(req.query.x){ let q = 1; } eval("unrelated-constant"); }',
    true,
  );
  assert.equal(f.length, 0, `expected no implicit finding for a constant sink genuinely outside the tainted branch; got ${JSON.stringify(f)}`);
});

// Same bug, more realistic shape: two sequential, unrelated tainted-ifs.
// The second if's constant-arg sink must not be flagged just because an
// EARLIER, unrelated tainted branch appeared earlier in the function.
test('implicit flow precision: an unrelated later tainted-if\'s constant sink is judged on its OWN branch, not a leaked earlier one', () => {
  const f = implicitFindings(
    'function h(req){ if(req.query.a){ let q = 1; } if(req.query.b){ eval("2"); } }',
    true,
  );
  // The second if's `eval("2")` is genuinely inside ITS OWN tainted branch,
  // so exactly one finding is correct — not zero (under-fixed) and not
  // more than one from double-counting via the first branch's stale scope.
  assert.equal(f.length, 1, `expected exactly one implicit finding (from the second if's own branch); got ${JSON.stringify(f)}`);
});
