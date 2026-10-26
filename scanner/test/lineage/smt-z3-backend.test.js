// DAG-04: the real z3 backend for the SMT orchestrator. Real-solver tests skip, loudly, when the optional
// `z3-solver` package cannot be loaded; the unavailable/timeout/encoding tests need no solver at all (a fake
// module is injected). Fixtures are real analysis output, as in path-control-evidence.test.js.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { buildProjectIR } from '../../src/ir/index.js';
import { planSeeds, seedEntryStateFactory } from '../../src/lineage/source-seeding.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { PathStore } from '../../src/lineage/path-store.js';
import { reconstructPaths, sinkCandidates } from '../../src/lineage/path-query.js';
import { collectWitnessConditions, evaluateWitnessConditions, toSolverProblem } from '../../src/lineage/path-predicates.js';
import { evaluateWitnessConditionsAsync, checkWithSolver, resolveSolver, noSolver } from '../../src/lineage/smt-orchestrator.js';
import { createZ3Solver, encodeProblem, sharedZ3Solver, smtBackendEnabled } from '../../src/lineage/smt-z3-backend.js';
import { evaluatePathEvidence, evaluatePathEvidenceAsync, summarizeFlowEvidence } from '../../src/lineage/path-evidence.js';

let z3Available = true;
try { const m = await import('z3-solver'); z3Available = typeof (m.init ?? m.default?.init) === 'function'; } catch { z3Available = false; }
const real = { skip: z3Available ? false : 'optional z3-solver is not installed (the real-solver tests are skipped, not passed)' };

const backends = [];
const mk = (o) => { const b = createZ3Solver(o); backends.push(b); return b; };
after(async () => { for (const b of backends) await b.shutdown(); });

// ---- fixtures ------------------------------------------------------------------------------------------

function analyse(src) {
  const { callGraph } = buildProjectIR({ 'a.js': src });
  const { seeds } = planSeeds(callGraph, { repository: 'r' });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const store = new PathStore();
  store.addHops(hops);
  const fnOf = (q) => callGraph.functions.get(q) ?? null;
  const out = [];
  for (const n of sinkCandidates(store).filter((x) => x.kind === 'escape')) {
    const result = reconstructPaths(store, n.id, {});
    for (const path of result.paths) {
      const last = path.hops[path.hops.length - 1];
      const node = fnOf(last.scope)?.cfg.nodes[last.siteNodeId];
      if (node?.kind === 'call' && node.callee?.prop === 'query') out.push({ path, result });
    }
  }
  assert.ok(out.length >= 1, 'fixture must reach the query sink');
  return { store, fnOf, found: out };
}

const argsOf = (a, x) => ({ path: x.path, nodeOf: (id) => a.store.getNode(id), fnOf: a.fnOf, sinkFamily: 'sql' });
const conditionsOf = (src) => { const a = analyse(src); return collectWitnessConditions(a.found[0].path.hops, { fnOf: a.fnOf }); };

// Three relational guards that cannot hold together, and an opaque call so the interval domain says `unknown`.
const CYCLE = 'function h(req, res, a, b, c) { const id = req.body.id; if (a < b) { if (b < c) { if (c < a) { if (chk(1)) { db.query(id); } } } } }';
const SAT = 'function h(req, res, a, b, c) { const id = req.body.id; if (a < b) { if (b < c) { if (c > a) { if (chk(1)) { db.query(id); } } } } }';
// No opaque call: the interval domain calls both feasible; only a relational solver tells them apart.
const CYCLE_PLAIN = 'function h(req, res, a, b, c) { const id = req.body.id; if (a < b) { if (b < c) { if (c < a) { db.query(id); } } } }';
const SAT_PLAIN = 'function h(req, res, a, b, c) { const id = req.body.id; if (a < b) { if (b < c) { if (c > a) { db.query(id); } } } }';

// ---- encoding (no solver needed) -----------------------------------------------------------------------

test('encoding: sound shape, Real sort, v0..vN renaming, deterministic text and digest', () => {
  const p = toSolverProblem(conditionsOf(CYCLE));
  const e1 = encodeProblem(p); const e2 = encodeProblem(JSON.parse(JSON.stringify(p)));
  assert.equal(e1.ok, true);
  assert.equal(e1.text, e2.text);
  assert.equal(e1.digest, e2.digest);
  assert.match(e1.text, /\(declare-const v0 Real\)/);
  assert.ok(!/\|/.test(e1.text), 'no raw variable names reach the solver text');
  assert.equal(e1.unmodeled, 1, 'the opaque predicate is counted, and encoded as no constraint');
  assert.equal(e1.assertions, p.assertions.length);
});

test('encoding: anything not faithfully translatable is refused, never guessed', () => {
  const lit = (l) => ({ vars: ['x'], constants: {}, assertions: [{ ref: 'r', alternatives: [[l]] }] });
  const num = (right) => lit({ t: 'num', op: '<', left: { var: 'x' }, right });
  assert.equal(encodeProblem(num({ const: 5 })).ok, true);
  assert.match(encodeProblem(num({ const: 1e21 })).reason, /number-not-encodable/);
  assert.match(encodeProblem(num({ const: Infinity })).reason, /number-not-encodable/);
  assert.match(encodeProblem(lit({ t: 'num', op: '<<', left: { var: 'x' }, right: { const: 1 } })).reason, /unknown-operator/);
  assert.match(encodeProblem(lit({ t: 'mystery' })).reason, /unknown-literal/);
  assert.match(encodeProblem(lit({ t: 'eq', var: 'x', value: 3, equal: true })).reason, /non-string-equality/);
  // One variable used as a number and as a string is a sort conflict.
  const mixed = { vars: ['x'], constants: {}, assertions: [{ ref: 'r', alternatives: [[{ t: 'num', op: '<', left: { var: 'x' }, right: { const: 1 } }, { t: 'eq', var: 'x', value: 'a', equal: true }]] }] };
  assert.match(encodeProblem(mixed).reason, /sort-conflict/);
  assert.match(encodeProblem(null).reason, /malformed-problem/);
  // A fractional bound keeps its fraction (Real, not Int): 0.5 < x < 1 must stay satisfiable in the encoding.
  const frac = { vars: ['x'], constants: {}, assertions: [{ ref: 'r', alternatives: [[{ t: 'num', op: '>', left: { var: 'x' }, right: { const: 0.5 } }, { t: 'num', op: '<', left: { var: 'x' }, right: { const: 1 } }]] }] };
  assert.match(encodeProblem(frac).text, /\(> v0 0\.5\)/);
  // String escaping: quote and backslash and non-ASCII cannot break out of the literal.
  const str = { vars: ['x'], constants: {}, assertions: [{ ref: 'r', alternatives: [[{ t: 'eq', var: 'x', value: 'a"b\\cé', equal: true }]] }] };
  assert.match(encodeProblem(str).text, /\(= v0 "a""b\\u\{5c\}c\\u\{e9\}"\)/);
});

// ---- the real solver -----------------------------------------------------------------------------------

test('z3: sat and unsat on hand-built problems, with the encoding digest reported', real, async () => {
  const z3 = mk();
  const sat = await z3.check({ vars: ['x'], constants: {}, assertions: [{ ref: 'r', alternatives: [[{ t: 'num', op: '>', left: { var: 'x' }, right: { const: 0.5 } }, { t: 'num', op: '<', left: { var: 'x' }, right: { const: 1 } }]] }] });
  assert.equal(sat.result, 'sat', 'a fractional interval is satisfiable over Real');
  const unsat = await z3.check({
    vars: ['x', 'y'], constants: {},
    assertions: [
      { ref: 'a', alternatives: [[{ t: 'num', op: '<', left: { var: 'x' }, right: { var: 'y' } }]] },
      { ref: 'b', alternatives: [[{ t: 'num', op: '<', left: { var: 'y' }, right: { var: 'x' } }]] },
    ],
  });
  assert.equal(unsat.result, 'unsat');
  assert.match(unsat.encodingDigest, /^[0-9a-f]{16}$/);
  const strUnsat = await z3.check({ vars: ['s'], constants: { s: 'a' }, assertions: [{ ref: 'r', alternatives: [[{ t: 'eq', var: 's', value: 'b', equal: true }]] }] });
  assert.equal(strUnsat.result, 'unsat', 'a constant-bound string contradicts a different literal');
  // An unmodeled predicate can only enlarge the formula: unsat stays sound, but a sat that leaned on it is not a model.
  const opaque = await z3.check({ vars: ['x'], constants: {}, assertions: [{ ref: 'r', alternatives: [[{ t: 'opaque', text: 'f(x)' }]] }] });
  assert.equal(opaque.result, 'unknown');
  assert.equal(opaque.reason, 'sat-with-unmodeled-predicates');
});

test('z3: an unverifiable encoding is unknown, never unsat', real, async () => {
  const z3 = mk();
  const r = await z3.check({ vars: ['x'], constants: {}, assertions: [{ ref: 'r', alternatives: [[{ t: 'num', op: '<', left: { var: 'x' }, right: { const: 1e30 } }, { t: 'num', op: '>', left: { var: 'x' }, right: { const: 1e31 } }]] }] });
  assert.equal(r.result, 'unknown');
  assert.match(r.reason, /number-not-encodable/);
  assert.equal(z3.stats().loads, 0, 'an encoding refusal does not even load the solver');
});

test('z3: hard problem within a tiny budget ends as unsat, timeout or unknown, never sat', real, async () => {
  // 9 pigeons in 8 holes: unsatisfiable, and expensive for a propositional engine.
  const n = 9; const vars = Array.from({ length: n }, (_, i) => `p${i}`);
  const assertions = vars.map((v) => ({ ref: `dom-${v}`, alternatives: Array.from({ length: n - 1 }, (_, k) => [{ t: 'num', op: '==', left: { var: v }, right: { const: k } }]) }));
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) assertions.push({ ref: `d-${i}-${j}`, alternatives: [[{ t: 'num', op: '!=', left: { var: vars[i] }, right: { var: vars[j] } }]] });
  const z3 = mk({ timeoutMs: 5 });
  const r = await z3.check({ vars, constants: {}, assertions });
  assert.ok(['unsat', 'timeout', 'unknown'].includes(r.result), `got ${r.result}`);
});

test('z3: the same problem gives the same answer and the second query is served from the cache', real, async () => {
  const a = mk(); const b = mk();
  const p = toSolverProblem(conditionsOf(CYCLE_PLAIN));
  const first = await a.check(p); const again = await a.check(p); const other = await b.check(p);
  assert.equal(first.result, 'unsat');
  assert.deepEqual([again.result, other.result], ['unsat', 'unsat']);
  assert.equal(first.encodingDigest, other.encodingDigest, 'identical text across independent backends');
  assert.equal(again.cached, true);
  assert.equal(a.stats().cacheHits, 1);
});

// ---- the solver as the orchestrator uses it ------------------------------------------------------------

test('orchestrator + z3: the interval domain says unknown, the solver proves the guards contradictory', real, async () => {
  const c = conditionsOf(CYCLE);
  assert.equal(evaluateWitnessConditions(c).status, 'unknown');
  const r = await evaluateWitnessConditionsAsync(c, { solver: mk() });
  assert.equal(r.status, 'infeasible-under-model');
  assert.equal(r.contradiction.kind, 'solver-unsat');
  assert.equal(r.abstractStatus, 'unknown');
  assert.equal(r.solver.name, 'z3');
  assert.match(r.satisfiabilityNote, /does not imply a working exploit/);
  // Control on the same machinery: flip one comparison and the conditions can hold, so nothing is reduced.
  const s = await evaluateWitnessConditionsAsync(conditionsOf(SAT), { solver: mk() });
  assert.equal(s.status, 'unknown', 'a sat that leaned on an unmodeled predicate keeps the finding unknown');
  assert.notEqual(s.status, 'infeasible-under-model');
});

test('orchestrator + z3: relational infeasibility on a decided-feasible answer needs consultOnFeasible', real, async () => {
  const c = conditionsOf(CYCLE_PLAIN);
  assert.equal(evaluateWitnessConditions(c).status, 'feasible-model', 'intervals cannot see a relational cycle');
  const off = await evaluateWitnessConditionsAsync(c, { solver: mk(), consultOnFeasible: false });
  assert.equal(off.status, 'feasible-model');
  assert.equal(off.solverConsulted, false);
  const on = await evaluateWitnessConditionsAsync(c, { solver: mk(), consultOnFeasible: true });
  assert.equal(on.status, 'infeasible-under-model');
  assert.equal(on.abstractStatus, 'feasible-model');
  // The feasible twin stays exactly what the abstract domain said.
  const ok = await evaluateWitnessConditionsAsync(conditionsOf(SAT_PLAIN), { solver: mk(), consultOnFeasible: true });
  assert.equal(ok.status, 'feasible-model');
  assert.equal(ok.solverStatus, 'feasible-model');
});

test('fixture: an infeasible guarded path earns the all-paths-protected exclusion, a feasible one does not', real, async () => {
  for (const [src, infeasible] of [[CYCLE, true], [SAT, false], [CYCLE_PLAIN, true], [SAT_PLAIN, false]]) {
    const a = analyse(src);
    const x = a.found[0];
    const z3 = mk();
    const ev = await evaluatePathEvidenceAsync({ ...argsOf(a, x), solverOpts: { solver: z3, consultOnFeasible: true } });
    assert.equal(ev.feasibility.status === 'infeasible-under-model', infeasible, src);
    assert.equal(ev.controlState, 'unprotected', 'no sanitizer on the path in either fixture');
    const sum = summarizeFlowEvidence({ result: x.result, paths: [x.path], evidences: [ev] });
    if (infeasible) {
      assert.equal(sum.allPathsProtected.excludedInfeasible.length, 1, 'the infeasible path is listed, not silently dropped');
      assert.equal(sum.allPathsProtected.relevantPathCount, 0);
      assert.notEqual(sum.allPathsProtected.holds, false, 'the infeasible unprotected path no longer refutes the claim');
    } else {
      assert.equal(sum.allPathsProtected.holds, false, 'a feasible unprotected path refutes the claim');
      assert.equal(sum.allPathsProtected.relevantPathCount, 1);
    }
  }
});

test('mutation: semantics-preserving rewrites keep the verdict, near-misses move it', real, async () => {
  const verdict = async (src) => (await evaluateWitnessConditionsAsync(conditionsOf(src), { solver: mk(), consultOnFeasible: true })).status;
  const rename = CYCLE_PLAIN.replace(/\ba\b/g, 'p').replace(/\bb\b/g, 'q').replace(/\bc\b/g, 'r');
  const flipped = 'function h(req, res, a, b, c) { const id = req.body.id; if (b > a) { if (c > b) { if (a > c) { db.query(id); } } } }';
  const conjoined = 'function h(req, res, a, b, c) { const id = req.body.id; if (a < b && b < c && c < a) { db.query(id); } }';
  const withDead = 'function h(req, res, a, b, c) { const id = req.body.id; log(1); if (a < b) { if (b < c) { if (c < a) { db.query(id); } } } }';
  for (const src of [CYCLE_PLAIN, rename, flipped, conjoined, withDead]) assert.equal(await verdict(src), 'infeasible-under-model', src);
  // Near-misses (one comparison weakened or reversed) must not be called infeasible.
  const weaker = 'function h(req, res, a, b, c) { const id = req.body.id; if (a < b) { if (b < c) { if (c >= a) { db.query(id); } } } }';
  const nonStrictAll = 'function h(req, res, a, b, c) { const id = req.body.id; if (a <= b) { if (b <= c) { if (c <= a) { db.query(id); } } } }';
  for (const src of [SAT_PLAIN, weaker, nonStrictAll]) assert.equal(await verdict(src), 'feasible-model', src);
});

// ---- never a crash, never a false unsat ----------------------------------------------------------------

function fakeModule({ verdict = 'unknown', why = '', hang = false, onInterrupt } = {}) {
  return {
    init: async () => ({
      Z3: { global_param_set() {}, interrupt() { onInterrupt?.(); } },
      getVersionString: () => 'fake-1',
      Context: () => ({
        ptr: 1,
        Solver: class { set() {} fromString() {} check() { return hang ? new Promise(() => {}) : Promise.resolve(verdict); } reasonUnknown() { return why; } },
      }),
    }),
  };
}

test('z3 missing: an import failure is unsupported, the abstract answer survives, nothing is reduced', async () => {
  const gone = createZ3Solver({ loader: async () => { throw Object.assign(new Error('Cannot find package z3-solver'), { code: 'ERR_MODULE_NOT_FOUND' }); } });
  assert.equal(gone.available, true, 'unknown until the first attempt');
  const c = conditionsOf(CYCLE);
  const r = await evaluateWitnessConditionsAsync(c, { solver: gone });
  assert.equal(gone.available, false);
  assert.equal(gone.loadFailure, 'ERR_MODULE_NOT_FOUND');
  assert.equal(r.status, 'unknown');
  assert.equal(r.solverStatus, 'unsupported');
  assert.equal(r.solverConsulted, false);
  assert.notEqual(r.status, 'infeasible-under-model');
  const direct = await gone.check(toSolverProblem(c));
  assert.equal(direct.result, 'unsupported');
  // The feasible-refinement route is equally inert.
  const f = await evaluateWitnessConditionsAsync(conditionsOf(CYCLE_PLAIN), { solver: gone, consultOnFeasible: true });
  assert.equal(f.status, 'feasible-model');
  // A module with no init() is a load failure too.
  const bad = createZ3Solver({ loader: async () => ({}) });
  assert.equal((await bad.check(toSolverProblem(c))).result, 'unsupported');
});

test('z3 timeout and memory: an unknown from the solver is a timeout or unknown, never unsat', async () => {
  const c = conditionsOf(CYCLE_PLAIN);
  const cases = [['timeout', 'timeout', 'timeout'], ['memout', 'unknown', 'unknown'], ['canceled', 'unknown', 'unknown'], ['', 'unknown', 'feasible-model']];
  for (const [why, backendResult, status] of cases) {
    const b = createZ3Solver({ loader: async () => fakeModule({ why }) });
    const direct = await b.check(toSolverProblem(c));
    assert.equal(direct.result, backendResult, why);
    const r = await evaluateWitnessConditionsAsync(c, { solver: b, consultOnFeasible: false });
    assert.equal(r.status, 'feasible-model', 'consultOnFeasible off: nothing is asked');
    const r2 = await evaluateWitnessConditionsAsync(c, { solver: createZ3Solver({ loader: async () => fakeModule({ why }) }), consultOnFeasible: true });
    assert.equal(r2.status, status === 'timeout' ? 'feasible-model' : 'feasible-model', `${why}: a feasible answer is never reduced by a non-unsat`);
    assert.notEqual(r2.status, 'infeasible-under-model');
  }
  // On an unknown abstract answer a solver timeout is reported as timeout and the abstract answer is kept.
  const b = createZ3Solver({ loader: async () => fakeModule({ why: 'timeout' }) });
  const t = await evaluateWitnessConditionsAsync(conditionsOf(CYCLE), { solver: b });
  assert.equal(t.status, 'timeout');
  assert.equal(t.abstractStatus, 'unknown');
});

test('z3 hang: the orchestrator deadline releases the caller, aborts the solver, and a wedged context stops being used', async () => {
  let interrupted = 0;
  const b = createZ3Solver({ timeoutMs: 30, loader: async () => fakeModule({ hang: true, onInterrupt: () => { interrupted += 1; } }) });
  const t0 = Date.now();
  const r = await evaluateWitnessConditionsAsync(conditionsOf(CYCLE), { solver: b, timeoutMs: 60 });
  assert.equal(r.status, 'timeout');
  assert.ok(Date.now() - t0 < 400, 'released near the deadline');
  assert.ok(interrupted >= 1, 'the solver was told to stop');
  await new Promise((res) => setTimeout(res, 700));
  assert.equal(b.available, false, 'a context that ignored its own timeout is retired');
  const again = await evaluateWitnessConditionsAsync(conditionsOf(CYCLE), { solver: b });
  assert.equal(again.solverStatus, 'unsupported');
});

test('unsat inside a loop is not trusted: the solver cannot see iterations', async () => {
  const fake = { name: 'fake', check: async () => ({ result: 'unsat' }) };
  const loopSrc = 'function h(req, res, ok) { const id = req.body.id; while (ok) { ok = g(); if (ok) { db.query(id); } else { db.query(id); } } }';
  const a = analyse(loopSrc);
  // Build the two-arm witness by hand, exactly as the interval-domain loop test does.
  const fn = [...buildProjectIR({ 'a.js': 'function h(req, res, ok) { while (ok) { ok = g(); if (ok) { log(1); } else { log(2); } } }' }).callGraph.functions.values()][0];
  const call = (n) => Object.entries(fn.cfg.nodes).find(([, x]) => x.kind === 'call' && x.args?.[0]?.value === n)[0];
  const hop = (id, nodeId) => ({ edgeId: id, scope: fn.qid, siteNodeId: nodeId, context: null });
  const c = collectWitnessConditions([hop('e1', call(1)), hop('e2', call(2))], { fnOf: () => fn });
  assert.ok(a);
  const r = await evaluateWitnessConditionsAsync(c, { solver: fake });
  assert.equal(r.status, 'unknown');
  assert.ok(r.reasons.includes('solver-unsat-not-trusted-in-loop'));
});

// ---- default scans are untouched -----------------------------------------------------------------------

test('default: no environment switch means no solver is chosen and z3 is never loaded', async () => {
  assert.equal(smtBackendEnabled({}), false);
  assert.equal(resolveSolver(undefined, {}), noSolver);
  const explicit = { name: 'x', check: async () => ({ result: 'sat' }) };
  assert.equal(resolveSolver(explicit, { AGENTIC_SECURITY_LINEAGE_SMT: 'z3' }), explicit, 'an explicit solver wins');
  assert.equal(resolveSolver(undefined, { AGENTIC_SECURITY_LINEAGE_SMT: 'z3' }), sharedZ3Solver());
  assert.equal(smtBackendEnabled({ AGENTIC_SECURITY_LINEAGE_SMT: '1' }), false, 'only the exact value z3 enables it');
  const before = sharedZ3Solver().stats().loads;
  const a = analyse(CYCLE);
  const sync = evaluatePathEvidence(argsOf(a, a.found[0]));
  const asyn = await evaluatePathEvidenceAsync(argsOf(a, a.found[0]));
  assert.deepEqual(asyn.feasibility.status, sync.feasibility.status);
  assert.equal(asyn.feasibility.solverStatus, 'unsupported');
  assert.equal(sharedZ3Solver().stats().loads, before, 'nothing loaded z3');
  assert.equal((await checkWithSolver(conditionsOf(CYCLE))).status, 'unsupported');
});
