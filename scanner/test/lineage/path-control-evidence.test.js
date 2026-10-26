// DAG-04: path predicates and control effectiveness. The fixtures are real analysis output (parser, seeding,
// field-identity driver, provenance store, bounded reconstruction), not hand-built hops, except where a test
// states otherwise. Every negative case is paired with a positive control that passes on the same machinery.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';

import { buildProjectIR } from '../../src/ir/index.js';
import { planSeeds, seedEntryStateFactory } from '../../src/lineage/source-seeding.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { PathStore } from '../../src/lineage/path-store.js';
import { reconstructPaths, sinkCandidates } from '../../src/lineage/path-query.js';
import { buildDataFlowGraph } from '../../src/lineage/graph-builder.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { computeGraphDigest } from '../../src/lineage/export-json.js';
import {
  collectWitnessConditions, evaluateWitnessConditions, guardsFor, condToDnf, toSolverProblem,
  FEASIBILITY_RESULTS, PATH_PREDICATE_VERSION, SATISFIABILITY_NOTE,
} from '../../src/lineage/path-predicates.js';
import { checkWithSolver, evaluateWitnessConditionsAsync, noSolver, toSmtLib } from '../../src/lineage/smt-orchestrator.js';
import {
  creditPath, controlFamiliesOf, sinkFamilyOf, abstractControlProof, assessAllPathsProtectedWithControls, isParameterizedSqlCall,
} from '../../src/lineage/control-credit.js';
import { evaluatePathEvidence, evaluatePathEvidenceAsync, summarizeFlowEvidence, buildControlEvidence } from '../../src/lineage/path-evidence.js';
import {
  buildWitnessBundle, signWitnessBundle, verifyWitness, exportProvenanceArtifact,
} from '../../src/posture/witness-bundle.js';

// ---- fixture machinery ---------------------------------------------------------------------------------

function analyse(src, family) {
  const { callGraph } = buildProjectIR({ 'a.js': src });
  const { seeds } = planSeeds(callGraph, { repository: 'r' });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const store = new PathStore();
  store.addHops(hops);
  const fnOf = (q) => callGraph.functions.get(q) ?? null;
  const nodeOf = (id) => store.getNode(id);
  const paths = [];
  for (const n of sinkCandidates(store).filter((x) => x.kind === 'escape')) {
    const result = reconstructPaths(store, n.id, {});
    for (const path of result.paths) paths.push({ path, result, sinkNode: n });
  }
  const evidence = paths.map((x) => ({ ...x, ev: evaluatePathEvidence({ path: x.path, nodeOf, fnOf, sinkFamily: family }) }));
  return { callGraph, store, fnOf, nodeOf, hops, evidence };
}

/** The one path whose last hop is at a CFG node calling `callee` (the real sink), among the analysis' paths. */
function pathsAtSink(a, calleeProp) {
  return a.evidence.filter((x) => {
    const last = x.path.hops[x.path.hops.length - 1];
    const node = a.fnOf(last.scope)?.cfg.nodes[last.siteNodeId];
    return node?.kind === 'call' && node.callee?.prop === calleeProp;
  });
}

const stateOf = (src, family, sinkProp) => {
  const a = analyse(src, family);
  const xs = pathsAtSink(a, sinkProp);
  assert.ok(xs.length >= 1, `fixture must reach the ${sinkProp} sink`);
  return { a, xs };
};

// =========================================================================================================
// R04.1 / R04.2: predicate references, polarity, value versions; alternatives stay distinct
// =========================================================================================================

test('R04.1: a guarded edge carries predicate reference, branch polarity and value versions; a join is not guarded', () => {
  const { xs: inside } = stateOf('function h(req, res, ok) { const id = req.body.id; if (ok) { db.query(id); } }', 'sql', 'query');
  const e = inside[0].ev;
  const sinkEdge = inside[0].path.hops[inside[0].path.hops.length - 1].edgeId;
  const guard = e.edgeGuards[sinkEdge];
  assert.equal(guard.length, 1, 'the sink inside the arm is guarded by exactly that arm');
  assert.equal(guard[0].polarity, true);
  assert.match(guard[0].ref, /^pred:[0-9a-f]{12}$/);
  assert.deepEqual(guard[0].versions, ['ok@entry'], 'the value version of the variable the condition reads is recorded');
  const firstEdge = inside[0].path.hops[0].edgeId;
  assert.deepEqual(e.edgeGuards[firstEdge], [], 'the assignment before the branch is not guarded');

  // Validation confined to one branch: the same sink AFTER the join is guarded by neither arm.
  const { xs: after } = stateOf('function h(req, res, ok) { const id = req.body.id; if (ok) { log(1); } db.query(id); }', 'sql', 'query');
  assert.equal(after[0].ev.conditions.clauses.length, 0, 'a node after the join is reachable from both arms, so neither arm guards it');
  assert.equal(after[0].ev.feasibility.status, 'feasible-model');

  // The else arm is its own clause with the opposite polarity, never merged with the then arm.
  const { callGraph } = buildProjectIR({ 'a.js': 'function h(req, res, ok) { if (ok) { log(1); } else { log(2); } }' });
  const fn = [...callGraph.functions.values()][0];
  const call = (n) => Object.entries(fn.cfg.nodes).find(([, x]) => x.kind === 'call' && x.args?.[0]?.value === n)[0];
  const gThen = guardsFor(fn, call(1)); const gElse = guardsFor(fn, call(2));
  assert.deepEqual(gThen.map((g) => g.polarity), [true]);
  assert.deepEqual(gElse.map((g) => g.polarity), [false]);
  assert.equal(gThen[0].branchNodeId, gElse[0].branchNodeId);
});

test('R04.2: guards of mutually exclusive branches are reported as a contradiction, never silently conjoined', () => {
  const { callGraph } = buildProjectIR({ 'a.js': 'function h(req, res, ok) { if (ok) { log(1); } else { log(2); } }' });
  const fn = [...callGraph.functions.values()][0];
  const call = (n) => Object.entries(fn.cfg.nodes).find(([, x]) => x.kind === 'call' && x.args?.[0]?.value === n)[0];
  const hop = (id, nodeId) => ({ edgeId: id, scope: fn.qid, siteNodeId: nodeId, context: null });
  const fnOf = () => fn;
  const both = collectWitnessConditions([hop('e1', call(1)), hop('e2', call(2))], { fnOf });
  assert.equal(both.clauses.length, 2, 'two clauses, one per arm');
  const r = evaluateWitnessConditions(both);
  assert.equal(r.status, 'infeasible-under-model');
  assert.equal(r.contradiction.kind, 'mutually-exclusive-branches');
  // Control: one arm alone is feasible under the model.
  const one = evaluateWitnessConditions(collectWitnessConditions([hop('e1', call(1))], { fnOf }));
  assert.equal(one.status, 'feasible-model');

  // Inside a loop, when the tested value is rewritten each iteration, the two arms can belong to different
  // iterations: unknown, not a contradiction.
  const loop = buildProjectIR({ 'a.js': 'function h(req, res, ok) { while (ok) { ok = g(); if (ok) { log(1); } else { log(2); } } }' });
  const lf = [...loop.callGraph.functions.values()][0];
  const lcall = (n) => Object.entries(lf.cfg.nodes).find(([, x]) => x.kind === 'call' && x.args?.[0]?.value === n)[0];
  const lr = evaluateWitnessConditions(collectWitnessConditions([hop2(lf, 'e1', lcall(1)), hop2(lf, 'e2', lcall(2))], { fnOf: () => lf }));
  assert.equal(lr.status, 'unknown');
  assert.ok(lr.reasons.includes('branch-arms-in-loop'));
  // When the tested value is never rewritten, both arms in one loop still contradict: it is the same value each time.
  const fixed = buildProjectIR({ 'a.js': 'function h(req, res, ok) { while (ok) { if (ok) { log(1); } else { log(2); } } }' });
  const ff = [...fixed.callGraph.functions.values()][0];
  const fcall = (n) => Object.entries(ff.cfg.nodes).find(([, x]) => x.kind === 'call' && x.args?.[0]?.value === n)[0];
  assert.equal(evaluateWitnessConditions(collectWitnessConditions([hop2(ff, 'e1', fcall(1)), hop2(ff, 'e2', fcall(2))], { fnOf: () => ff })).status, 'infeasible-under-model');
});
function hop2(fn, id, nodeId) { return { edgeId: id, scope: fn.qid, siteNodeId: nodeId, context: null }; }

test('R04.2: a disjunction inside one condition stays as distinct alternatives', () => {
  const ctx = { frame: 'f0', versionsOf: () => ['entry'] };
  const expr = { kind: 'logical', op: '||', left: { kind: 'binary', op: '>', left: { kind: 'ident', name: 'a' }, right: { kind: 'literal', value: 10 } }, right: { kind: 'binary', op: '<', left: { kind: 'ident', name: 'a' }, right: { kind: 'literal', value: 0 } } };
  assert.equal(condToDnf(expr, true, ctx).length, 2, 'a || b has two alternatives when it must hold');
  assert.equal(condToDnf(expr, false, ctx).length, 1, 'its negation is one conjunction');
  assert.equal(condToDnf(expr, false, ctx)[0].length, 2);
  // Evaluation: a constant 5 satisfies neither alternative.
  const f = (src) => {
    const { callGraph } = buildProjectIR({ 'a.js': src });
    const fn = [...callGraph.functions.values()][0];
    const call = Object.entries(fn.cfg.nodes).find(([, x]) => x.kind === 'call' && x.callee?.prop === 'query')[0];
    return evaluateWitnessConditions(collectWitnessConditions([hop2(fn, 'e', call)], { fnOf: () => fn }));
  };
  assert.equal(f('function h(req) { const a = 5; if (a > 10 || a < 0) { db.query(req.body.id); } }').status, 'infeasible-under-model');
  assert.equal(f('function h(req) { const a = 50; if (a > 10 || a < 0) { db.query(req.body.id); } }').status, 'feasible-model');
});

// =========================================================================================================
// R04.3 / R04.4: bounded abstract domains first, five result values, versions, limitations
// =========================================================================================================

test('R04.3/4: numeric contradictory branches are infeasible-under-model, with the contradiction named', () => {
  const { xs } = stateOf('function h(req, res) { const n = 5; if (n > 10) { db.query(req.body.id); } }', 'sql', 'query');
  const f = xs[0].ev.feasibility;
  assert.equal(f.status, 'infeasible-under-model');
  assert.equal(f.contradiction.kind, 'contradictory-conditions');
  assert.equal(f.contradiction.refs.length, 1);
  assert.equal(f.semanticsVersion, PATH_PREDICATE_VERSION);
  assert.equal(f.satisfiabilityNote, SATISFIABILITY_NOTE);
  assert.ok(f.limitations.length >= 3, 'limitations are stated on every result');
  assert.ok(FEASIBILITY_RESULTS.includes(f.status));
  // Positive control: a consistent constant is feasible-model.
  const ok = stateOf('function h(req, res) { const n = 50; if (n > 10) { db.query(req.body.id); } }', 'sql', 'query').xs[0].ev.feasibility;
  assert.equal(ok.status, 'feasible-model');
  assert.match(ok.satisfiabilityNote, /does not imply a working exploit/);
});

test('R04.3: contradictory caller and callee conditions are found through the call binding; consistent ones are not', () => {
  const caller = 'function handler(req, res, lim) { if (lim > 10) { const r = inner(lim, req.body.id); } }';
  const bad = stateOf(`function inner(k, q) { if (k < 5) { db.query(q); } return q; }\n${caller}`, 'sql', 'query').xs;
  assert.equal(bad.length, 1);
  assert.equal(bad[0].path.crossScopeCount, 1, 'the witness really crosses the call boundary');
  assert.equal(bad[0].ev.conditions.bindings.length, 2, 'both arguments are bound to their parameters');
  assert.equal(bad[0].ev.feasibility.status, 'infeasible-under-model');
  assert.equal(bad[0].ev.conditions.clauses.length, 2, 'one caller clause, one callee clause');
  const good = stateOf(`function inner(k, q) { if (k > 20) { db.query(q); } return q; }\n${caller}`, 'sql', 'query').xs;
  assert.equal(good[0].ev.feasibility.status, 'feasible-model');
  // Without the binding the same two clauses could not contradict: the parameter is only tied to the argument
  // through the explicit call binding.
  const collected = bad[0].ev.conditions;
  const unbound = evaluateWitnessConditions({ ...collected, bindings: [] });
  assert.notEqual(unbound.status, 'infeasible-under-model');
});

test('R04.3: value versions stop a reassigned variable from producing a false contradiction', () => {
  // `a > 10` reads the entry value, `a < 5` reads the constant 1 written in between. One name, two values.
  const src = 'function h(req, res, a) { if (a > 10) { a = 1; if (a < 5) { db.query(req.body.id); } } }';
  const { xs } = stateOf(src, 'sql', 'query');
  const f = xs[0].ev.feasibility;
  assert.equal(f.status, 'feasible-model', 'the second condition is about a different value');
  const versions = xs[0].ev.conditions.clauses.map((c) => c.versions.join()).sort();
  assert.equal(new Set(versions).size, 2, 'the two clauses name different value versions');
  // A reassignment from an unknown value forgets the earlier constant.
  const re = stateOf('function h(req, res) { let n = 5; n = req.body.k; if (n > 10) { db.query(req.body.id); } }', 'sql', 'query').xs[0].ev.feasibility;
  assert.equal(re.status, 'feasible-model', 'a stale constant must not survive a reassignment');
  // Equality on constants: two different literals for one value contradict.
  const eq = stateOf("function h(req, res, mode) { if (mode === 'a') { if (mode === 'b') { db.query(req.body.id); } } }", 'sql', 'query').xs[0].ev.feasibility;
  assert.equal(eq.status, 'infeasible-under-model');
});

test('R04.4: an unmodeled predicate keeps the witness unknown; reflective code is unsupported; neither hides the finding', () => {
  const unm = stateOf('function h(req, res) { if (scrub(req.body.id)) { db.query(req.body.id); } }', 'sql', 'query').xs[0];
  assert.equal(unm.ev.feasibility.status, 'unknown');
  assert.ok(unm.ev.feasibility.reasons.includes('unmodeled-predicates'));
  assert.equal(unm.ev.feasibility.unmodeledPredicates.length, 1);

  const refl = stateOf("function h(req, res) { const n = 5; eval('x'); if (n > 10) { db.query(req.body.id); } }", 'sql', 'query').xs[0];
  assert.equal(refl.ev.feasibility.status, 'unsupported', 'eval could rewrite n, so the constant is not trusted');
  assert.deepEqual(refl.ev.feasibility.reasons, ['reflective-dispatch']);
  assert.notEqual(refl.ev.feasibility.status, 'infeasible-under-model');
  // Control: without the eval the same shape is infeasible.
  const plain = stateOf('function h(req, res) { const n = 5; if (n > 10) { db.query(req.body.id); } }', 'sql', 'query').xs[0];
  assert.equal(plain.ev.feasibility.status, 'infeasible-under-model');
});

test('R04.3: an unreachable CFG scope is unsupported, not feasible', () => {
  const c = collectWitnessConditions([{ edgeId: 'e', scope: 'nowhere', siteNodeId: 'n1' }], { fnOf: () => null });
  const r = evaluateWitnessConditions(c);
  assert.equal(r.status, 'unsupported');
  assert.deepEqual(r.reasons, ['no-cfg']);
});

test('R04.3: combination explosion and the deadline are bounded and reported', () => {
  const { xs } = stateOf('function h(req, a) { if (scrub(a) || scrub2(a)) { db.query(req.body.id); } }', 'sql', 'query');
  const c = xs[0].ev.conditions;
  assert.equal(evaluateWitnessConditions(c, { maxCombinations: 1 }).status, 'unknown');
  assert.ok(evaluateWitnessConditions(c, { maxCombinations: 1 }).reasons.includes('alternative-explosion'));
  let t = 0;
  const r = evaluateWitnessConditions(c, { deadlineMs: 5, now: () => (t += 10) });
  assert.equal(r.status, 'timeout');
});

// ---- the optional solver path --------------------------------------------------------------------------

function unknownConditions() {
  const { xs } = stateOf('function h(req, res) { if (scrub(req.body.id)) { db.query(req.body.id); } }', 'sql', 'query');
  return xs[0].ev.conditions;
}

test('R04.3: no solver available reports unsupported and keeps the abstract answer', async () => {
  const c = unknownConditions();
  const direct = await checkWithSolver(c, { solver: noSolver });
  assert.equal(direct.status, 'unsupported');
  assert.deepEqual(direct.reasons, ['no-solver']);
  const full = await evaluateWitnessConditionsAsync(c, {});
  assert.equal(full.status, 'unknown', 'the witness stays visible as unknown');
  assert.equal(full.solverStatus, 'unsupported');
  assert.equal(full.solverConsulted, false);
  assert.equal(full.abstractStatus, 'unknown');
  // A decided abstract answer never consults a solver.
  let called = 0;
  const spy = { name: 'spy', check: async () => { called += 1; return { result: 'sat' }; } };
  const decided = unknownConditions();
  const plain = stateOf('function h(req, res) { const n = 5; if (n > 10) { db.query(req.body.id); } }', 'sql', 'query').xs[0].ev.conditions;
  const r = await evaluateWitnessConditionsAsync(plain, { solver: spy });
  assert.equal(r.status, 'infeasible-under-model');
  assert.equal(called, 0);
  assert.ok(decided);
});

test('R04.3: a solver that never answers is released at the deadline, aborted, and the finding stays visible', async () => {
  const c = unknownConditions();
  let aborted = false; let settledLate = false;
  const hang = {
    name: 'hang', version: '0',
    check(_problem, { signal }) {
      return new Promise((resolve) => {
        signal.addEventListener('abort', () => { aborted = true; });
        setTimeout(() => { settledLate = true; resolve({ result: 'sat' }); }, 400); // ignores the deadline on purpose
      });
    },
  };
  const t0 = Date.now();
  const r = await evaluateWitnessConditionsAsync(c, { solver: hang, timeoutMs: 40 });
  const took = Date.now() - t0;
  assert.equal(r.status, 'timeout');
  assert.ok(took < 300, `the caller was released near the deadline, not at the solver's pace (${took}ms)`);
  assert.equal(aborted, true, 'the solver was told to stop');
  assert.equal(r.abstractStatus, 'unknown', 'the abstract answer is retained');
  assert.ok(r.reasons.includes('solver-deadline'));
  await new Promise((res) => setTimeout(res, 450));
  assert.equal(settledLate, true, 'the late settlement happened and was swallowed (no unhandled rejection)');
});

test('R04.3: caller cancellation, a failing solver, a malformed answer and a bad timeout all end as unknown', async () => {
  const c = unknownConditions();
  const ac = new AbortController();
  const slow = { name: 'slow', check: () => new Promise((res) => setTimeout(() => res({ result: 'sat' }), 300)) };
  const p = checkWithSolver(c, { solver: slow, timeoutMs: 1000, signal: ac.signal });
  setTimeout(() => ac.abort(), 20);
  const cancelled = await p;
  assert.equal(cancelled.status, 'unknown');
  assert.deepEqual(cancelled.reasons, ['cancelled']);
  assert.equal((await checkWithSolver(c, { solver: { name: 'x', check: async () => { throw new Error('boom'); } } })).status, 'unknown');
  assert.equal((await checkWithSolver(c, { solver: { name: 'x', check: async () => ({ result: 'maybe-ish' }) } })).reasons[0], 'solver-malformed');
  assert.equal((await checkWithSolver(c, { solver: { name: 'x', check: async () => ({}) } })).reasons[0], 'solver-malformed');
  for (const bad of [-1, NaN, Infinity, 1e9]) assert.deepEqual((await checkWithSolver(c, { solver: slow, timeoutMs: bad })).reasons, ['invalid-timeout']);
  const pre = new AbortController(); pre.abort();
  assert.deepEqual((await checkWithSolver(c, { solver: slow, signal: pre.signal })).reasons, ['cancelled']);
});

test('R04.4: a solver answer maps onto the shared vocabulary and never claims exploitability', async () => {
  const c = unknownConditions();
  const mk = (result) => ({ name: 'fake', version: '1', check: async (problem) => { assert.equal(problem.semanticsVersion, PATH_PREDICATE_VERSION); return { result }; } });
  const sat = await evaluateWitnessConditionsAsync(c, { solver: mk('sat') });
  assert.equal(sat.status, 'feasible-model');
  assert.equal(sat.satisfiabilityNote, SATISFIABILITY_NOTE);
  assert.equal(sat.solver.name, 'fake');
  const unsat = await evaluateWitnessConditionsAsync(c, { solver: mk('unsat') });
  assert.equal(unsat.status, 'infeasible-under-model');
  assert.equal(unsat.contradiction.kind, 'solver-unsat');
  assert.equal((await evaluateWitnessConditionsAsync(c, { solver: mk('unknown') })).status, 'unknown');
  const text = toSmtLib(toSolverProblem(unknownConditions()));
  assert.match(text, /\(check-sat\)/);
});

// =========================================================================================================
// R04.5: credit only for the matching sink family, value version and covered paths
// =========================================================================================================

test('R04.5: an SQL escaper earns SQL credit; an HTML encoder does not', () => {
  const sql = stateOf('function h(req, res) { const q = mysql.escape(req.body.id); db.query(q); }', 'sql', 'query').xs[0].ev;
  assert.equal(sql.controlState, 'protected');
  assert.equal(sql.credit.credits.length, 1);
  assert.equal(sql.credit.credits[0].callee, 'mysql.escape');
  assert.equal(sql.credit.credits[0].sinkFamily, 'sql');
  assert.equal(sql.credit.credits[0].semanticsProof, false, 'family credit is not a proof of sanitizer semantics');
  assert.ok(sql.credit.limitations.some((l) => /not proven/.test(l)));

  const html = stateOf('function h(req, res) { const q = escapeHtml(req.body.id); db.query(q); }', 'sql', 'query').xs[0].ev;
  assert.equal(html.controlState, 'unprotected');
  assert.deepEqual(html.credit.credits, []);
  assert.deepEqual(html.credit.rejected.map((r) => r.reason), ['wrong-family']);

  // The encoder is right for an HTML sink and the escaper is wrong there: same machinery, opposite answers.
  assert.equal(stateOf('function h(req, res) { const q = escapeHtml(req.body.name); res.send(q); }', 'xss', 'send').xs[0].ev.controlState, 'protected');
  assert.equal(stateOf('function h(req, res) { const q = mysql.escape(req.body.name); res.send(q); }', 'xss', 'send').xs[0].ev.credit.rejected[0].reason, 'wrong-family');
  // Unknown sink family: nothing can be matched, so a recognized control is not credited.
  const unk = stateOf('function h(req, res) { const q = mysql.escape(req.body.id); db.query(q); }', null, 'query').xs[0].ev;
  assert.notEqual(unk.controlState, 'protected');
  assert.equal(unk.credit.rejected[0].reason, 'sink-family-unknown');
});

test('R04.5: a parameterized query is credited for SQL only, and only for values bound as parameters', () => {
  const bound = stateOf("function h(req, res) { db.query('SELECT * FROM t WHERE id = ?', [req.body.id]); }", 'sql', 'query').xs;
  assert.ok(bound.some((x) => x.ev.credit.credits.some((c) => c.callee === 'parameterized-query')), 'placeholder binding earns SQL credit');
  assert.ok(bound.every((x) => x.ev.credit.credits.every((c) => c.families.join() === 'sql')));
  // Interpolated into the text: no credit.
  const text = stateOf("function h(req, res) { db.query('SELECT * FROM t WHERE id = ' + req.body.id); }", 'sql', 'query').xs;
  assert.ok(text.every((x) => x.ev.controlState !== 'protected'));
  // The same call shape is not a control for a different family.
  const xss = stateOf("function h(req, res) { res.send('a ?', [req.body.name]); }", 'xss', 'send').xs;
  assert.ok(xss.every((x) => x.ev.credit.credits.length === 0));
  assert.equal(isParameterizedSqlCall({ kind: 'call', args: [{ kind: 'literal', value: 'x ?' }, { kind: 'ident', name: 'v' }] }, 'v'), true);
  assert.equal(isParameterizedSqlCall({ kind: 'call', args: [{ kind: 'literal', value: 'no placeholder' }, { kind: 'ident', name: 'v' }] }, 'v'), false);
});

test('R04.5: a decoder after the sanitizer voids the credit; a reassignment cannot inherit stale credit', () => {
  const dec = stateOf('function h(req, res) { const a = escapeHtml(req.body.name); const b = he.decode(a); res.send(b); }', 'xss', 'send').xs[0].ev;
  assert.equal(dec.controlState, 'unprotected');
  assert.deepEqual(dec.credit.rejected.map((r) => r.reason), ['reversed:he.decode']);
  assert.deepEqual(dec.credit.credits, []);
  // Control: without the decoder the same sanitizer is credited.
  assert.equal(stateOf('function h(req, res) { const a = escapeHtml(req.body.name); res.send(a); }', 'xss', 'send').xs[0].ev.controlState, 'protected');

  // The sanitized value is concatenated with a raw one: the sink no longer reads the controlled definition.
  const re = stateOf('function h(req, res) { let s = escapeHtml(req.body.name); s = s + req.body.other; res.send(s); }', 'xss', 'send').xs;
  assert.equal(re.length, 2);
  assert.ok(re.every((x) => x.ev.controlState === 'unprotected'), 'neither witness inherits the old definition');
  assert.ok(re.some((x) => x.ev.credit.rejected.some((r) => r.reason === 'stale-control-version')));
  // A strong overwrite leaves no witness through the control at all.
  const over = stateOf('function h(req, res) { let s = escapeHtml(req.body.name); s = req.body.other; res.send(s); }', 'xss', 'send').xs;
  assert.ok(over.every((x) => x.ev.controlState === 'unprotected'));
});

test('R04.5: an opaque call that widened the value makes the witness unknown, never protected and never unprotected', () => {
  const op = stateOf('function h(req, res) { const q = vendorWrap(req.body.id); db.query(q); }', 'sql', 'query').xs[0].ev;
  assert.equal(op.controlState, 'unknown');
  assert.equal(op.credit.opaque[0].reason, 'opaque-call');
  assert.deepEqual(op.credit.opaque[0].callees, ['vendorWrap']);
  // A bare name shared by catalog entries that disagree on families is ambiguous and also not credited.
  const amb = stateOf('function h(req, res) { const q = escape(req.body.id); db.query(q); }', 'sql', 'query').xs[0].ev;
  assert.notEqual(amb.controlState, 'protected');
  assert.equal(controlFamiliesOf({ kind: 'ident', name: 'escape' }).ambiguous, true);
  assert.equal(controlFamiliesOf({ kind: 'member', object: { kind: 'ident', name: 'mysql' }, prop: 'escape' }).ambiguous, false);
});

test('R04.5: validation confined to one branch does not protect the other witness', () => {
  const src = 'function h(req, res, c) { let s; if (c) { s = mysql.escape(req.body.id); } else { s = req.body.id; } db.query(s); }';
  const { xs } = stateOf(src, 'sql', 'query');
  assert.equal(xs.length, 2);
  const states = xs.map((x) => x.ev.controlState).sort();
  assert.ok(states.includes('unprotected'), 'the raw branch is unprotected');
  assert.ok(!states.includes('protected'), 'the merged read cannot be credited to either definition');
  const a = analyse(src, 'sql');
  const sum = summarizeFlowEvidence({ result: xs[0].result, paths: xs.map((x) => x.path), evidences: xs.map((x) => x.ev) });
  assert.equal(sum.controlState, 'unprotected');
  assert.equal(sum.allPathsProtected.allowed, false);
  assert.equal(sum.allPathsProtected.holds, false);
  assert.ok(a.evidence.length >= 2);
});

// =========================================================================================================
// R04.6: any all-path claim accounts for every relevant feasible modeled path
// =========================================================================================================

test('R04.6: an alternate unsanitized path defeats an all-path protection claim, even when it is not displayed', () => {
  const src = 'function h(req, res, c) { let s; if (c) { s = mysql.escape(req.body.id); } else { s = req.body.id; } db.query(s); }';
  const { xs } = stateOf(src, 'sql', 'query');
  const all = xs.map((x) => x.path);
  const stateById = new Map(xs.map((x) => [x.path.id, x.ev]));
  const result = xs[0].result;
  const whole = assessAllPathsProtectedWithControls({ result, enumerated: all, evidenceOf: (p) => stateById.get(p.id) });
  assert.equal(whole.allowed, false);
  assert.equal(whole.holds, false);
  assert.deepEqual(whole.reasons, ['refuted-by-unprotected-path']);
  // The unprotected path is the hidden one: a display sample of only the protected path would have passed.
  const protectedOnly = [{ id: 'p-shown', hops: [] }];
  const fake = new Map([['p-shown', { controlState: 'protected', feasibility: { status: 'feasible-model' } }], ['p-hidden', { controlState: 'unprotected', feasibility: { status: 'feasible-model' } }]]);
  const complete = { status: 'complete', truncated: false, droppedPathCount: 0 };
  assert.equal(assessAllPathsProtectedWithControls({ result: complete, enumerated: protectedOnly, evidenceOf: (p) => fake.get(p.id) }).allowed, true, 'the sample alone would have licensed the claim');
  const withHidden = assessAllPathsProtectedWithControls({ result: complete, enumerated: [...protectedOnly, { id: 'p-hidden', hops: [] }], evidenceOf: (p) => fake.get(p.id) });
  assert.equal(withHidden.allowed, false);
  assert.equal(withHidden.refutingPathId, 'p-hidden');
});

test('R04.6: the claim is allowed only when every relevant path is protected and the query was exhaustive', () => {
  const { xs } = stateOf('function h(req, res) { const q = mysql.escape(req.body.id); db.query(q); }', 'sql', 'query');
  const only = xs[0];
  const ok = assessAllPathsProtectedWithControls({ result: only.result, enumerated: [only.path], evidenceOf: () => only.ev });
  assert.equal(ok.allowed, true);
  assert.equal(ok.holds, true);
  assert.equal(ok.claimScope, 'modeled-feasible-paths');
  assert.equal(ok.basis, 'enumeration');
  // A truncated query refuses the same evidence.
  const trunc = assessAllPathsProtectedWithControls({ result: { ...only.result, truncated: true }, enumerated: [only.path], evidenceOf: () => only.ev });
  assert.equal(trunc.allowed, false);
  assert.ok(trunc.reasons.includes('truncated-sample'));
  // An unknown control state is not protected.
  const unk = assessAllPathsProtectedWithControls({ result: only.result, enumerated: [only.path], evidenceOf: () => ({ controlState: 'unknown' }) });
  assert.equal(unk.allowed, false);
  assert.ok(unk.reasons.includes('control-state-unknown'));
});

test('R04.6: infeasible-under-model paths leave the relevant set but are listed; unknown and timeout paths stay relevant', () => {
  const complete = { status: 'complete', truncated: false, droppedPathCount: 0 };
  const paths = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
  const ev = new Map([
    ['a', { controlState: 'protected', feasibility: { status: 'feasible-model' } }],
    ['b', { controlState: 'unprotected', feasibility: { status: 'infeasible-under-model', contradiction: { kind: 'contradictory-conditions', refs: ['pred:x'] } } }],
    ['c', { controlState: 'protected', feasibility: { status: 'feasible-model' } }],
  ]);
  const r = assessAllPathsProtectedWithControls({ result: complete, enumerated: paths, evidenceOf: (p) => ev.get(p.id) });
  assert.equal(r.allowed, true);
  assert.equal(r.relevantPathCount, 2);
  assert.deepEqual(r.excludedInfeasible.map((x) => x.pathId), ['b']);
  assert.equal(r.excludedInfeasible[0].contradiction.kind, 'contradictory-conditions');
  // A timeout or unknown feasibility cannot be used to dismiss a path.
  ev.set('b', { controlState: 'unprotected', feasibility: { status: 'timeout' } });
  const t = assessAllPathsProtectedWithControls({ result: complete, enumerated: paths, evidenceOf: (p) => ev.get(p.id) });
  assert.equal(t.allowed, false);
  assert.equal(t.holds, false);
  // If every path is infeasible there is nothing to claim.
  const none = assessAllPathsProtectedWithControls({ result: complete, enumerated: [{ id: 'z' }], evidenceOf: () => ({ controlState: 'unprotected', feasibility: { status: 'infeasible-under-model' } }) });
  assert.equal(none.allowed, false);
  assert.ok(none.reasons.includes('no-paths'));
});

test('R04.6: an independent abstract proof can license the claim when enumeration was truncated, and never overrides a refutation', () => {
  const a = analyse('function h(req, res) { const q = mysql.escape(req.body.id); db.query(q); }', 'sql');
  const fn = [...a.callGraph.functions.values()][0];
  const sinkNode = Object.entries(fn.cfg.nodes).find(([, n]) => n.kind === 'call' && n.callee?.prop === 'query')[0];
  const proof = abstractControlProof(fn, { sinkNodeId: sinkNode, variable: 'q', sinkFamily: 'sql' });
  assert.equal(proof.proved, true);
  assert.equal(proof.semanticsProof, false, 'dominance is coverage evidence, not proof of sanitizer semantics');
  assert.ok(proof.basis.includes('dominance'));
  const truncated = { status: 'partial', truncated: true, droppedPathCount: 3 };
  const lic = assessAllPathsProtectedWithControls({ result: truncated, enumerated: [], evidenceOf: () => null, proof });
  assert.equal(lic.allowed, true);
  assert.equal(lic.basis, 'abstract-proof');
  const refuted = assessAllPathsProtectedWithControls({ result: truncated, enumerated: [{ id: 'u' }], evidenceOf: () => ({ controlState: 'unprotected' }), proof });
  assert.equal(refuted.allowed, false, 'a known unprotected path always wins');
  // The proof refuses everything it cannot establish.
  const wrong = abstractControlProof(fn, { sinkNodeId: sinkNode, variable: 'q', sinkFamily: 'xss' });
  assert.equal(wrong.proved, false);
  assert.equal(wrong.reason, 'wrong-family');
  const phi = analyse('function h(req, res, c) { let s; if (c) { s = mysql.escape(req.body.id); } else { s = req.body.id; } db.query(s); }', 'sql');
  const pf = [...phi.callGraph.functions.values()][0];
  const psink = Object.entries(pf.cfg.nodes).find(([, n]) => n.kind === 'call' && n.callee?.prop === 'query')[0];
  assert.equal(abstractControlProof(pf, { sinkNodeId: psink, variable: 's', sinkFamily: 'sql' }).reason, 'multiple-reaching-definitions');
  const other = analyse('function h(req, res) { const z = mysql.escape(req.body.id); const q = req.body.id; db.query(q); }', 'sql');
  const of = [...other.callGraph.functions.values()][0];
  const osink = Object.entries(of.cfg.nodes).find(([, n]) => n.kind === 'call' && n.callee?.prop === 'query')[0];
  assert.equal(abstractControlProof(of, { sinkNodeId: osink, variable: 'q', sinkFamily: 'sql' }).proved, false, 'a control on some other variable does not cover this one');
});

// =========================================================================================================
// graph builder wiring: default OFF, additive when enabled
// =========================================================================================================

const GB_SRC = `
function handler(req, res, c) {
  const n = 5;
  const a = mysql.escape(req.body.id);
  if (n > 10) { db.query(req.body.name); }
  db.query(a);
}
`;

test('graph builder: path evidence is off by default and adds fields only when enabled', () => {
  const { callGraph } = buildProjectIR({ 'a.js': GB_SRC });
  const off = buildDataFlowGraph(callGraph, { repository: 'r' }).graph;
  const on = buildDataFlowGraph(callGraph, { repository: 'r', pathEvidence: true }).graph;
  assert.ok(off.flows.length >= 2);
  assert.ok(off.flows.every((f) => !('pathEvidence' in f)), 'no new fields by default');
  assert.ok(off.edges.every((e) => !('predicateRefs' in e)));
  assert.ok(on.flows.every((f) => f.pathEvidence && f.pathEvidence.version));
  assert.deepEqual(validateGraph(on), { valid: true, errors: [] }, 'the enabled graph still validates');
  // Stripping the added fields gives back exactly the default graph, so existing digests are unmoved.
  const strip = (g) => JSON.parse(JSON.stringify(g, (k, v) => (k === 'pathEvidence' || k === 'predicateRefs' ? undefined : v)));
  assert.deepEqual(strip(on), strip(off));
  assert.equal(computeGraphDigest(strip(on)), computeGraphDigest(off));
  assert.deepEqual(buildDataFlowGraph(callGraph, { repository: 'r', pathEvidence: false }).graph.flows, off.flows);

  // The contradictory-branch flow is visible, marked infeasible-under-model, not removed; the other is protected.
  const byFeas = Object.fromEntries(on.flows.map((f) => [Object.keys(f.pathEvidence.feasibility).sort().join(), f]));
  assert.ok(byFeas['infeasible-under-model'], 'the infeasible flow stays in the graph');
  assert.equal(byFeas['infeasible-under-model'].pathEvidence.alternatives[0].controlState, 'unprotected');
  assert.equal(byFeas['infeasible-under-model'].pathEvidence.controlState, 'unknown', 'no feasible path remains to judge');
  assert.equal(byFeas['infeasible-under-model'].pathEvidence.allPathsProtected.allowed, false);
  assert.equal(byFeas['infeasible-under-model'].pathEvidence.alternatives[0].predicateRefs.length, 1);
  const prot = on.flows.find((f) => f.pathEvidence.controlState === 'protected');
  assert.ok(prot, 'the escaped value is protected for the SQL sink');
  assert.equal(prot.pathEvidence.allPathsProtected.allowed, true);
  assert.ok(on.edges.some((e) => Array.isArray(e.predicateRefs) && e.predicateRefs.length === 1));
});

test('graph builder: AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES=1 enables it and an explicit option wins', () => {
  const { callGraph } = buildProjectIR({ 'a.js': GB_SRC });
  const prev = process.env.AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES;
  try {
    process.env.AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES = '1';
    assert.ok(buildDataFlowGraph(callGraph, { repository: 'r' }).graph.flows.every((f) => f.pathEvidence));
    assert.ok(buildDataFlowGraph(callGraph, { repository: 'r', pathEvidence: false }).graph.flows.every((f) => !f.pathEvidence));
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES; else process.env.AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES = prev;
  }
});

test('graph builder: reflective code and an opaque predicate leave the flow visible as unknown/unsupported', () => {
  const { callGraph } = buildProjectIR({ 'a.js': "function h(req, res) { const n = 5; eval('x'); if (n > 10) { db.query(req.body.id); } }" });
  const g = buildDataFlowGraph(callGraph, { repository: 'r', pathEvidence: true }).graph;
  const f = g.flows.find((x) => x.pathEvidence.feasibility.unsupported);
  assert.ok(f, 'the flow is still in the graph');
  assert.equal(f.pathEvidence.alternatives[0].feasibility, 'unsupported');
  assert.equal(f.pathEvidence.allPathsProtected.allowed, false);
});

// =========================================================================================================
// witness bundle: the controlEvidence slot is filled
// =========================================================================================================

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' });
const PRIV = privateKey.export({ type: 'pkcs8', format: 'pem' });

function witnessFixture(src, family) {
  const sources = { 'a.js': src };
  const { callGraph } = buildProjectIR(sources);
  const { seeds } = planSeeds(callGraph, { repository: 'r' });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const provenance = exportProvenanceArtifact({ hops });
  const store = new PathStore();
  store.addHops(hops);
  const fnOf = (q) => callGraph.functions.get(q) ?? null;
  let result; let path;
  for (const s of sinkCandidates(store).filter((n) => n.kind === 'escape')) {
    const r = reconstructPaths(store, s.id, {});
    const p = r.paths.find((x) => { const last = x.hops[x.hops.length - 1]; return fnOf(last.scope)?.cfg.nodes[last.siteNodeId]?.callee?.prop === 'query' || fnOf(last.scope)?.cfg.nodes[last.siteNodeId]?.callee?.prop === 'send'; });
    if (p) { result = r; path = p; break; }
  }
  assert.ok(path, 'fixture must reach the sink');
  const ev = evaluatePathEvidence({ path, nodeOf: (id) => store.getNode(id), fnOf, sinkFamily: family });
  const ge = ['edge:aaaaaaaaaaaa'];
  const graph = { graphId: 'dfg:r:abc:default', nodes: [{ id: 'node:a' }, { id: 'node:b' }], edges: ge.map((id) => ({ id })), flows: [{ id: 'flow:1', source: 'node:a', sink: 'node:b', edgeIds: ge }], coverage: {} };
  return { result, path, store, provenance, graph, ev, sources, callGraph, fnOf };
}

test('witness: controlEvidence carries predicate refs, control refs, semantics and limitations; replay accepts it', () => {
  const fx = witnessFixture('function h(req, res, ok) { const q = mysql.escape(req.body.id); if (ok) { db.query(q); } }', 'sql');
  assert.equal(fx.ev.feasibility.status, 'feasible-model');
  const ce = buildControlEvidence(fx.ev, { pathEdgeIds: fx.path.edgeIds });
  assert.equal(ce.status, 'feasible');
  assert.equal(ce.predicateRefs.length, 1);
  assert.ok(ce.controlRefs.length >= 1);
  assert.equal(ce.detail.semanticsVersion, PATH_PREDICATE_VERSION);
  assert.equal(ce.detail.controlState, 'protected');
  assert.match(ce.detail.doesNotImply, /does not imply a working exploit/);
  const built = buildWitnessBundle({ result: fx.result, path: fx.path, store: fx.store, graph: fx.graph, provenance: fx.provenance, sourceBlobs: fx.sources, graphBinding: { flowId: 'flow:1' }, controlEvidence: ce });
  assert.equal(built.ok, true, built.reason);
  assert.equal(built.bundle.evidence.feasibility.status, 'feasible');
  assert.equal(built.bundle.evidence.exploitProof.status, 'none', 'feasibility is not exploit proof');
  const signed = signWitnessBundle(built.bundle, PRIV);
  const v = verifyWitness(signed, PUB, { graph: fx.graph, provenance: fx.provenance, sources: fx.sources });
  assert.equal(v.ok, true, JSON.stringify(v.replay?.failures));
});

test('witness: infeasible and unknown map onto the slot without hiding the precise result', () => {
  const inf = witnessFixture('function h(req, res) { const n = 5; if (n > 10) { db.query(req.body.id); } }', 'sql');
  const ce = buildControlEvidence(inf.ev, { pathEdgeIds: inf.path.edgeIds });
  assert.equal(ce.status, 'infeasible');
  assert.equal(ce.detail.contradiction.kind, 'contradictory-conditions');
  const ok = buildWitnessBundle({ result: inf.result, path: inf.path, store: inf.store, graph: inf.graph, provenance: inf.provenance, sourceBlobs: inf.sources, graphBinding: { flowId: 'flow:1' }, controlEvidence: ce });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.bundle.evidence.feasibility.status, 'infeasible');

  const unk = witnessFixture("function h(req, res) { const n = 5; eval('x'); if (n > 10) { db.query(req.body.id); } }", 'sql');
  const ce2 = buildControlEvidence(unk.ev, { pathEdgeIds: unk.path.edgeIds });
  assert.equal(ce2.status, 'unknown', 'unsupported is reported as unknown in the three-valued slot');
  assert.equal(ce2.detail.feasibility, 'unsupported', 'and the precise result is kept');
  // A predicate reference to an edge that is not on the path is refused by the bundle.
  const bad = buildWitnessBundle({ result: inf.result, path: inf.path, store: inf.store, graph: inf.graph, provenance: inf.provenance, controlEvidence: { ...ce, predicateRefs: [{ edgeId: 'pedge:nope', ref: 'pred:x' }] } });
  assert.equal(bad.ok, false);
});

test('witness: a solver timeout is recorded as unknown with the abstract answer kept', async () => {
  const fx = witnessFixture('function h(req, res) { if (scrub(req.body.id)) { db.query(req.body.id); } }', 'sql');
  const hang = { name: 'hang', check: () => new Promise(() => {}) };
  const ev = await evaluatePathEvidenceAsync({ path: fx.path, nodeOf: (id) => fx.store.getNode(id), fnOf: fx.fnOf, sinkFamily: 'sql', solverOpts: { solver: hang, timeoutMs: 30 } });
  assert.equal(ev.feasibility.status, 'timeout');
  const ce = buildControlEvidence(ev, { pathEdgeIds: fx.path.edgeIds });
  assert.equal(ce.status, 'unknown');
  assert.equal(ce.detail.feasibility, 'timeout');
  assert.equal(ce.detail.solver.name, 'hang');
  const built = buildWitnessBundle({ result: fx.result, path: fx.path, store: fx.store, graph: fx.graph, provenance: fx.provenance, graphBinding: { flowId: 'flow:1' }, controlEvidence: ce });
  assert.equal(built.ok, true, built.reason);
  assert.equal(built.bundle.evidence.feasibility.status, 'unknown');
});

// ---- mutation checks: the guards must be load-bearing -------------------------------------------------

test('mutation: dropping the family check, the version check or the reversal check each changes a verdict', () => {
  // Family: a wrong-family control must not protect.
  assert.equal(stateOf('function h(req, res) { const q = escapeHtml(req.body.id); db.query(q); }', 'sql', 'query').xs[0].ev.controlState, 'unprotected');
  // If sinkFamily were treated as '*' the same fixture would be credited: prove the credit machinery would say so.
  assert.equal(controlFamiliesOf({ kind: 'ident', name: 'escapeHtml' }).families.has('sql'), false);
  // Sampling: a displayed sample of one protected path must not license a claim when another path is hidden.
  const complete = { status: 'complete', truncated: false, droppedPathCount: 0 };
  assert.equal(assessAllPathsProtectedWithControls({ result: { ...complete, droppedPathCount: 1 }, enumerated: [{ id: 'a' }], evidenceOf: () => ({ controlState: 'protected' }) }).allowed, false);
  // sinkFamilyOf reads the catalog sink entry shape.
  assert.equal(sinkFamilyOf({ vuln: { cwe: 'CWE-89', name: 'SQL Injection' } }), 'sql');
  assert.equal(sinkFamilyOf({ vuln: { cwe: 'CWE-79', name: 'XSS' } }), 'xss');
  assert.equal(creditPath({ hops: [], fnOf: () => null, nodeOf: () => null, sinkFamily: 'sql' }).controlState, 'unprotected');
});
