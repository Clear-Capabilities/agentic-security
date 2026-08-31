// Sub-project C, increment C6 — FR-306 edge grading (`flow-grade.js`).
//
// Absorbed from the design task's own PoC (flow-grade-poc.test.js, deleted
// in the same commit that lands this file — §16.8 item 11 / C3's item 15 /
// C4's item 11 / C5's item 12 precedent). Every assertion below was
// originally proven against a LOCAL prototype in DESIGN_PATH_PROVENANCE.md
// §16's own design task; this file re-points them at the SHIPPED
// `src/lineage/flow-grade.js` module instead, with the local prototype
// block deleted.
//
// The fixture harness below is `path-query.test.js`'s own, verbatim in
// shape: real parsed JS/TS through the real `parser-js.js`, hand-seeded
// entry states, the real interprocedural resolver, the real `PathStore`,
// and the real `reconstructPaths`. Nothing about grading is tested against
// a hand-invented hop except the two cases that CANNOT be produced by
// today's engine and are documented as such (§16.3's reserved `implicit`
// tier, and `aggregateFlowGrades`' own error contract).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';
import {
  FieldIdentitySummaryCache,
  createCallSummaryResolver,
} from '../../src/lineage/summaries.js';
import { PathStore } from '../../src/lineage/path-store.js';
import { reconstructPaths, sinkCandidates } from '../../src/lineage/path-query.js';
import { EVIDENCE_GRADES } from '../../src/lineage/protection.js';
import {
  FLOW_EVIDENCE_GRADES,
  IMPLICIT_FLOW_REASONS,
  DEGRADED_LOSS_REASONS,
  flowGradeRank,
  aggregateFlowGrades,
  gradeHop,
  gradePath,
} from '../../src/lineage/flow-grade.js';

// =====================================================================
// §16.8 item 1: the isolation boundary is enforced by a test, not just
// documented. `flow-grade.js` must import NOTHING at all — one step
// stricter than `path-query.js`'s own `['./ids.js']` boundary.
// =====================================================================

test('boundary: flow-grade.js imports NOTHING — its specifier list is EXACTLY [] (§16.1)', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/flow-grade.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  // Same order/line-layout-independent scan `path-store.test.js`'s and
  // `path-query.test.js`'s own boundary tests use: match every module
  // specifier string that follows `from`/`import(`/`export ... from`
  // ANYWHERE in the source, not just a line-anchored `/^import\s.*$/gm`
  // (which a multi-line specifier list, a re-export, or a dynamic import
  // can hide from).
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, [], 'flow-grade.js must import nothing — a pure function library over the fields it is handed');
});

// =====================================================================
// Shared fixture harness — `path-query.test.js`'s, unchanged.
// =====================================================================

function parseFns(src, file) {
  const ir = parseJsFile(file, src);
  assert.ok(ir, 'real parser must parse this fixture source');
  const byName = {};
  for (const fn of ir.functions) byName[fn.name] = fn;
  return byName;
}

function lookupCalleeFor(byName) {
  return (calleeExpr) => {
    if (!calleeExpr || calleeExpr.kind !== 'ident') return null;
    const fn = byName[calleeExpr.name];
    return fn ? { qid: fn.qid, fn } : null;
  };
}

function record(fn, entryState, { byName, cache } = {}) {
  const raw = [];
  const ctx = { recordHop: (h) => raw.push(h) };
  if (byName) {
    ctx.resolveCallSummary = createCallSummaryResolver(
      cache ?? new FieldIdentitySummaryCache(), lookupCalleeFor(byName));
  }
  const result = analyzeFunctionFieldIdentity(fn, entryState, ctx);
  const store = new PathStore();
  store.addHops(raw);
  return { raw, store, result };
}

/** Every path reachable from every structural sink candidate. */
function allPaths(store) {
  const out = [];
  for (const sink of sinkCandidates(store)) out.push(...reconstructPaths(store, sink.id).paths);
  return out;
}

/** Test-side convenience: the per-hop grade strings of a `PathGrade`. */
const hopGradeNames = (pathGrade) => pathGrade.hops.map((h) => h.grade);

/**
 * The NAIVE grader §14.9's own corrected note warns a C6 implementer
 * would write: identical precedence, but reading ONLY the edge's
 * top-level reason arrays. Executed rather than described, so the
 * contrast in C6/5 and C6/6 is measured.
 */
function naiveTopLevelOnlyGrade(hop) {
  if (hop.ambiguousCorrelation === true) return 'ambiguous';
  if (hop.lossReasons.length > 0) return 'severed';
  if (hop.widenReasons.length > 0) return 'widened';
  return 'explicit';
}

// =====================================================================
// C6/0 — the vocabulary itself.
// =====================================================================

test('C6/0: the flow-evidence vocabulary is a NEW, separate enum — it shares no value with protection.js\'s EVIDENCE_GRADES, which grades a different thing', () => {
  const overlap = FLOW_EVIDENCE_GRADES.filter((g) => EVIDENCE_GRADES.includes(g));
  assert.deepEqual(overlap, [],
    'a flow-explicitness grade must never be mistakable for a protection-evidence grade');
  // Every grade has a unique, total rank, and `explicit` is the top.
  const ranks = FLOW_EVIDENCE_GRADES.map(flowGradeRank);
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
  assert.equal(new Set(ranks).size, ranks.length);
  assert.equal(FLOW_EVIDENCE_GRADES[0], 'explicit');
  // The aggregation table is a permutation of the value list — a value
  // missing from either side would silently throw or silently win. The
  // table itself is private (`_PRECEDENCE`), so the parity check is run
  // indirectly: every grade must aggregate against every other without
  // throwing, and the worst-wins result must always be one of the two.
  for (const a of FLOW_EVIDENCE_GRADES) {
    for (const b of FLOW_EVIDENCE_GRADES) {
      const result = aggregateFlowGrades([a, b]);
      assert.ok(result === a || result === b || (a === 'unassessed' && b === 'unassessed'),
        `aggregateFlowGrades([${a}, ${b}]) must resolve to one of its inputs`);
    }
  }
});

// =====================================================================
// C6/1 — a pure explicit path grades at the highest tier.
// =====================================================================

test('C6/1: a plain, unwidened, unambiguous, intraprocedural assignment chain grades `explicit` at every hop AND at the path', () => {
  const src = 'function f(user) { const b = user.email; return b; }';
  const byName = parseFns(src, '/x/c6-explicit.js');
  const { store } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  const paths = allPaths(store);
  assert.equal(paths.length, 1);
  const g = gradePath(paths[0]);
  assert.deepEqual(hopGradeNames(g), ['explicit', 'explicit']);
  assert.equal(g.grade, 'explicit');
  assert.equal(g.rank, 0, 'the top of the confidence order');
  assert.deepEqual(g.factors, [], 'nothing to disclose about a clean flow');
  assert.equal(g.incomplete, false);
  assert.equal(g.degraded, false);
  assert.equal(g.truncated, false);
});

// =====================================================================
// C6/2 — a genuinely widened hop grades strictly lower, never equal.
// =====================================================================

test('C6/2: a real `widenReason` grades `widened` — strictly lower-ranked than `explicit`, and NEVER the same grade (FR-306\'s literal wording)', () => {
  const cases = [
    ['unresolved-call', 'function f(user) { const b = mystery(user.email); return b; }'],
    ['dynamic-property-key', 'function f(user, k) { const bag = {}; bag[k] = user.email; return bag; }'],
  ];
  const explicitSrc = 'function f(user) { const b = user.email; return b; }';
  const explicitByName = parseFns(explicitSrc, '/x/c6-2-base.js');
  const { store: explicitStore } = record(explicitByName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  const explicitGrade = gradePath(allPaths(explicitStore)[0]);

  for (const [reason, src] of cases) {
    const byName = parseFns(src, `/x/c6-2-${reason}.js`);
    const { store } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
    const paths = allPaths(store);
    assert.equal(paths.length, 1, `${reason}: one path`);
    const g = gradePath(paths[0]);
    assert.equal(g.grade, 'widened', `${reason}: the path grade is widened`);
    assert.ok(g.factors.includes(`widen:${reason}`), `${reason}: the actual cause is named, not just the tier`);
    assert.notEqual(g.grade, explicitGrade.grade,
      `${reason}: FR-306 — a widened flow may NOT share an explicit assignment's evidence grade`);
    assert.ok(g.rank > explicitGrade.rank, `${reason}: and it is strictly lower-confidence, not merely different`);
    // "visually distinct" is a per-HOP claim: exactly one hop is widened,
    // and the grade says which.
    assert.equal(g.widenedHopCount, 1);
    assert.equal(hopGradeNames(g).filter((x) => x === 'widened').length, 1);
    assert.equal(g.hops[g.worstHopIndex].grade, 'widened');
    // The per-hop CAUSE is on the path answer itself — no second
    // `gradeHop` call needed to render FR-306's "visually distinct" half.
    assert.ok(g.hops[g.worstHopIndex].factors.includes(`widen:${reason}`));
  }
});

test('C6/2b: a hop can carry TWO widen reasons at once, and both are named in the factors', () => {
  const src = 'function f(user, k) { const v = user[k]; return v; }';
  const byName = parseFns(src, '/x/c6-2b.js');
  const { store } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  const g = gradePath(allPaths(store)[0]);
  assert.equal(g.grade, 'widened');
  assert.deepEqual(
    g.factors.filter((f) => f.startsWith('widen:')),
    ['widen:dynamic-property-key', 'widen:unresolved-call'],
    'a widened dynamic read carries both reasons; the grade is one tier but the disclosure is not lossy',
  );
});

// =====================================================================
// C6/3 — `ambiguousCorrelation` alone is graded, and graded DIFFERENTLY
// from a genuine widening.
// =====================================================================

test('C6/3: an `ambiguousCorrelation` hop with no widenReason/lossReason grades `ambiguous` — a distinct, strictly lower tier than `widened`', () => {
  const src = 'function f(p, q) { const x = { a: p.email, b: q.email }; return x; }';
  const byName = parseFns(src, '/x/c6-3.js');
  let entryState = addIdentity(emptyState(), 'p.email', 'data:email');
  entryState = addIdentity(entryState, 'q.email', 'data:email');
  const { store } = record(byName.f, entryState);
  const paths = allPaths(store);
  assert.equal(paths.length, 4, '§9.1\'s cross-join: four routes, none collapsed');

  for (const p of paths) {
    const g = gradePath(p);
    assert.equal(g.grade, 'ambiguous');
    assert.equal(g.widenedHopCount, 0, 'nothing here is widened — the engine lost no precision');
    assert.equal(g.lossHopCount, 0);
    assert.ok(g.factors.includes('ambiguous-correlation'));
    // Strictly worse than a widening: a widened hop certainly happened and
    // is merely imprecise; an ambiguous pairing may never have happened.
    assert.ok(flowGradeRank('ambiguous') > flowGradeRank('widened'));
    assert.ok(flowGradeRank('ambiguous') > flowGradeRank('explicit'));
  }
});

// =====================================================================
// C6/4 — crossing a function boundary does NOT lower the grade.
// =====================================================================

test('C6/4: a sound interprocedural stitch grades IDENTICALLY to the same flow inlined — crossing a boundary is a factor, never a demotion', () => {
  const inlined = 'function f(user) { const b = user.email; return b; }';
  const split = 'function helper(u) { return u.email; } function caller(a) { const out = helper(a); return out; }';

  const byInlined = parseFns(inlined, '/x/c6-4-inlined.js');
  const { store: inlinedStore } = record(byInlined.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  const inlinedGrade = gradePath(allPaths(inlinedStore)[0]);

  const bySplit = parseFns(split, '/x/c6-4-split.js');
  const { store: splitStore } = record(bySplit.caller, addIdentity(emptyState(), 'a.email', 'data:email'), { byName: bySplit });
  const calleeExit = sinkCandidates(splitStore).find((n) => n.scope === bySplit.helper.qid);
  const stitched = reconstructPaths(splitStore, calleeExit.id).paths;
  assert.equal(stitched.length, 1);
  const stitchedGrade = gradePath(stitched[0]);

  assert.equal(stitchedGrade.hops.length, 2, 'arg -> param, then param -> callee exit');
  assert.deepEqual(hopGradeNames(stitchedGrade), ['explicit', 'explicit'],
    'C3/C4 PROVED the stitch lands on the node the callee independently created (§14.3 Q1) — there is no imprecision to grade');
  assert.equal(stitchedGrade.grade, inlinedGrade.grade,
    'the same flow, factored into two functions, grades the same — a grade must report evidence quality, not code structure');
  assert.ok(stitchedGrade.factors.includes('cross-scope'),
    'the boundary crossing IS disclosed — as a factor, so a consumer can still render it distinctly');
  assert.equal(stitchedGrade.rank, 0);
});

test('C6/4b: penalising cross-scope would INVERT the ranking — the real through-the-callee chain grades higher than §14.7\'s bypass, and only because cross-scope is not a demotion', () => {
  const src = 'function helper(u) { return u.email; } function caller(a) { const out = helper(a); return out; }';
  const byName = parseFns(src, '/x/c6-4b.js');
  const { store } = record(byName.caller, addIdentity(emptyState(), 'a.email', 'data:email'), { byName });
  const callerExit = sinkCandidates(store).find((n) => n.scope === byName.caller.qid);
  const r = reconstructPaths(store, callerExit.id);
  assert.equal(r.paths.length, 2);

  const through = r.paths.find((p) => p.crossScopeCount === 2);
  const bypass = r.paths.find((p) => p.crossScopeCount === 0);
  assert.ok(through && bypass);

  const gThrough = gradePath(through);
  const gBypass = gradePath(bypass);
  assert.equal(gThrough.grade, 'explicit', 'the route the program actually takes');
  assert.equal(gBypass.grade, 'ambiguous', '§14.7\'s disclosed bypass, which skips the callee');
  assert.ok(gThrough.rank < gBypass.rank,
    'the CORRECT path outranks the artefact — a cross-scope demotion would have penalised exactly the path that crosses the boundary twice');
  // And this agrees with `comparePaths`, which already ranks MORE
  // crossScope as BETTER (§15.7 key 4). A cross-scope demotion would have
  // put C6's grade in direct contradiction with C5's shipped ordering.
  assert.equal(r.paths[0].id, through.id);
});

// =====================================================================
// C6/5 — THE trap: an annotation-only widenReason. Bigger than §13.6.
// =====================================================================

test('C6/5: a genuine widening can live ONLY in `annotations[]`, with the edge\'s own widenReasons EMPTY — a top-level-only grader calls it `explicit`, violating FR-306', () => {
  // Three real, separately-parsed shapes, all measured. In each, the
  // widening is produced by an expression-internal construct whose hop
  // §2.2 classifies as an ANNOTATION (null fromPath, null peerScope), so
  // `path-store.js` never folds its reason into `edge.widenReasons`.
  const cases = [
    ['bare-call argument', 'function f(user) { sink(mystery(user.email)); }'],
    ['object-literal property', 'function f(user) { const o = { a: mystery(user.email) }; return o; }'],
    ['ternary branch', 'function f(user, c) { const o = c ? mystery(user.email) : user.email; return o; }'],
  ];

  let provenCases = 0;
  for (const [label, src] of cases) {
    const byName = parseFns(src, `/x/c6-5-${provenCases}.js`);
    const { store } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
    const hops = allPaths(store).flatMap((p) => p.hops);
    const trap = hops.find((h) => h.widenReasons.length === 0
      && h.annotations.some((a) => a.widenReason === 'unresolved-call'));
    assert.ok(trap, `${label}: the annotation-only widening reproduces`);

    assert.equal(naiveTopLevelOnlyGrade(trap), 'explicit',
      `${label}: the naive top-level-only grader reports the HIGHEST grade for a widened flow`);
    const g = gradeHop(trap);
    assert.equal(g.grade, 'widened', `${label}: reading annotations[] too gets it right`);
    assert.deepEqual(g.annotationOnly, ['widen:unresolved-call'],
      `${label}: and it names exactly which input would have been invisible`);
    assert.ok(g.factors.includes('widen:unresolved-call'));
    provenCases += 1;
  }
  assert.equal(provenCases, 3, 'all three shapes reproduce it — this is not one exotic corner');
});

test('C6/5b: `path-query.js`\'s `materialize()` fix (§16.8 item 7) — the Path\'s OWN `widenedHopCount`/`shape` report `1`/`widened` on the fixture the pre-fix code scored as explicit', () => {
  const src = 'function f(user) { sink(mystery(user.email)); }';
  const byName = parseFns(src, '/x/c6-5b.js');
  const { store } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  // Two `escape` sinks here (one per bare-call argument site), so pick the
  // path whose single hop is the one carrying the annotation-only widening.
  const paths = allPaths(store);
  assert.equal(paths.length, 2);
  const p = paths.find((x) => x.hops.some((h) => h.annotations.some((a) => a.widenReason === 'unresolved-call')));
  assert.ok(p, 'the annotation-carrying path exists');

  // THE REGRESSION ASSERTION — `materialize()`'s own fields, now
  // annotation-aware, no local prototype helper needed.
  assert.equal(p.widenedHopCount, 1,
    'the widening is real and the count must see it');
  assert.equal(p.shape.split('/')[2], 'widened',
    "§15.7's diversity `shape` signature must see it too — it is derived from the same filter");
  assert.equal(p.lossHopCount, 0, 'and the loss half is untouched by a widen-only fixture');
  assert.equal(p.shape.split('/')[3], 'intact');

  // And the grade agrees with the corrected count, which is the whole point
  // of §16.7 Finding 1: `gradePath` never depended on the buggy field — it
  // computes its own union regardless.
  const g = gradePath(p);
  assert.equal(g.widenedHopCount, p.widenedHopCount);
  assert.equal(g.grade, 'widened');
});

test('C6/5c: the SAME `materialize()` fix closes the loss half — a §13.6-degraded path\'s `lossHopCount`/`shape` are correct, not annotation-blind', () => {
  const src = `
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `;
  const byName = parseFns(src, '/x/c6-5c.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');
  const { store } = record(byName.outer, entryState, { byName, cache: new FieldIdentitySummaryCache(1) });

  // The degraded binding edge is only reachable from its own target node —
  // that is Finding 2, and it is why this fixture needs a direct start node
  // rather than a sink candidate.
  const e = store.edges().find((x) => x.annotations.some((a) => a.lossReason === 'context-cap-degraded'));
  assert.ok(e);
  const r = reconstructPaths(store, e.toNodeId);
  assert.equal(r.paths.length, 1);
  const p = r.paths[0];

  assert.equal(p.lossHopCount, 1,
    "the honestly-degraded hop must count as lossy — anything else is §18.4's failure mode inside a display count");
  assert.equal(p.shape.split('/')[3], 'lossy');
  assert.equal(gradePath(p).grade, 'severed');
  assert.equal(gradePath(p).degraded, true);
});

// =====================================================================
// C6/6 — §13.6's context-cap-degraded annotation-only loss marker.
// =====================================================================

test('C6/6: a §13.6 context-cap-degraded marker lives ONLY in annotations[] — it grades `severed`, AND raises a separate `degraded` flag, and can never be invisible to a grade reader', () => {
  const src = `
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `;
  const byName = parseFns(src, '/x/c6-6.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');
  const { store } = record(byName.outer, entryState, { byName, cache: new FieldIdentitySummaryCache(1) });

  const degradedEdges = store.edges().filter((e) => e.annotations.some((a) => a.lossReason === 'context-cap-degraded'));
  assert.equal(degradedEdges.length, 1, 'the cap-1 cache degrades exactly one resolution');
  const e = degradedEdges[0];

  // The trap, measured: the marker is in NEITHER top-level array.
  assert.deepEqual(e.lossReasons, [], '§14.4 classifies it as an annotation, so it never reaches edge.lossReasons');
  assert.deepEqual(e.widenReasons, []);
  assert.equal(naiveTopLevelOnlyGrade(e), 'explicit',
    'a top-level-only grader reports the argument -> parameter binding as a fully explicit assignment');

  const g = gradeHop(e);
  assert.equal(g.grade, 'severed', 'folded into the grade: the trail genuinely stops here');
  assert.equal(g.degraded, true, 'AND raised separately, because the CAUSE is what §18.4 requires be visible');
  assert.deepEqual(g.annotationOnly, ['loss:context-cap-degraded']);
  assert.ok(g.factors.includes('loss:context-cap-degraded'));
  assert.equal(g.incomplete, true);
  // `gradeHop` returns an OBJECT, so a consumer cannot read the grade
  // without also receiving `degraded`/`factors` — the marker is not
  // "surfaced if you remember to look", it is structurally unavoidable.
  assert.ok('degraded' in g && 'factors' in g && 'annotationOnly' in g);
});

test('C6/6b: FINDING — the degraded binding edge is unreachable from every structural sink candidate, so a sink-rooted reconstruction never surfaces it at all (not fixed here; §16.7 Finding 2)', () => {
  const src = `
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `;
  const byName = parseFns(src, '/x/c6-6b.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');
  const { store } = record(byName.outer, entryState, { byName, cache: new FieldIdentitySummaryCache(1) });
  const e = store.edges().find((x) => x.annotations.some((a) => a.lossReason === 'context-cap-degraded'));

  // Its target is an ordinary `path` node (the callee's parameter) with no
  // outgoing edges — because the callee's body was degraded away. It is
  // therefore neither a sink candidate (return/escape/loss) nor on any
  // path leading to one.
  const target = store.getNode(e.toNodeId);
  assert.equal(target.kind, 'path');
  assert.equal(store.edgesFrom(target.id).length, 0);
  assert.equal(sinkCandidates(store).some((n) => n.id === target.id), false);

  const fromSinks = allPaths(store);
  assert.equal(fromSinks.filter((p) => gradePath(p).degraded).length, 0,
    'MEASURED: no sink-rooted path carries the marker — the honest degradation is invisible to the sink-first query');

  // It IS reachable, and correctly graded, when the walk starts at that node.
  const direct = reconstructPaths(store, target.id);
  assert.equal(direct.paths.length, 1);
  assert.equal(gradePath(direct.paths[0]).degraded, true);
  assert.equal(gradePath(direct.paths[0]).grade, 'severed');
});

// =====================================================================
// C6/7 — the aggregation rule.
// =====================================================================

test('C6/7: a path mixing clean and widened hops grades WORST-WINS — per-hop grades stay distinct so the UI knows WHICH hop to mark', () => {
  const src = 'function f(user) { const a = user.email; const b = mystery(a); return b; }';
  const byName = parseFns(src, '/x/c6-7.js');
  const { store } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  const paths = allPaths(store);
  assert.equal(paths.length, 1);
  const p = paths[0];
  assert.equal(p.hopCount, 3);

  const g = gradePath(p);
  assert.deepEqual(hopGradeNames(g), ['explicit', 'widened', 'explicit'],
    'FR-306\'s "visually distinct" half: the widened hop is identifiable, the clean ones are not dragged down');
  assert.equal(g.grade, 'widened',
    'FR-306\'s "may not be displayed as the same evidence grade" half: the PATH cannot claim explicit');
  assert.equal(g.worstHopIndex, 1, 'and it names which hop is responsible');

  // The alternatives, executed rather than argued: every other reduction
  // lets the widened hop hide behind two clean ones.
  const names = hopGradeNames(g);
  assert.equal(names[0], 'explicit', 'first-wins would report explicit');
  assert.equal(names[names.length - 1], 'explicit', 'last-wins would report explicit');
  const best = names.map(flowGradeRank).sort((a, b) => a - b)[0];
  assert.equal(FLOW_EVIDENCE_GRADES[best], 'explicit', 'best-wins would report explicit');
  const majority = names.filter((x) => x === 'explicit').length > names.length / 2;
  assert.equal(majority, true, 'majority-wins would report explicit');
});

test('C6/7b: worst-wins across ALL five tiers, on a real store — the lowest-graded hop on a path always sets the path grade', () => {
  // Assembled from real hops of the fixtures above plus the one reserved
  // tier no engine emits (§16.3), so the aggregation is exercised over the
  // full vocabulary rather than the two tiers real code happens to produce
  // on one path.
  const orderedWorstFirst = ['ambiguous', 'severed', 'implicit', 'widened', 'explicit'];
  for (let i = 0; i < orderedWorstFirst.length; i++) {
    for (let j = 0; j < orderedWorstFirst.length; j++) {
      const expected = orderedWorstFirst[Math.min(i, j)];
      assert.equal(aggregateFlowGrades([orderedWorstFirst[i], orderedWorstFirst[j]]), expected);
      assert.equal(aggregateFlowGrades([orderedWorstFirst[j], orderedWorstFirst[i]]), expected,
        'order-independent — an aggregation that depended on hop order would be the representative-picking bug class again');
    }
  }
});

test('C6/7c: `aggregateFlowGrades` mirrors `aggregateVerdicts`\' contract exactly — empty is `unassessed`, an unrecognized value THROWS rather than quietly ranking as safest', () => {
  assert.equal(aggregateFlowGrades([]), 'unassessed');
  assert.equal(aggregateFlowGrades(undefined), 'unassessed');
  assert.equal(aggregateFlowGrades(['explicit', 'unassessed']), 'explicit',
    "'unassessed' never wins over a real grade");
  assert.throws(() => aggregateFlowGrades(['expliict']), /unrecognized flow evidence grade/);
  assert.throws(() => flowGradeRank('code'), /unrecognized flow evidence grade/,
    "a protection EVIDENCE_GRADES value is not a flow grade, and is rejected rather than coerced");
});

// =====================================================================
// C6/8 — loss, truncation, and the reserved `implicit` tier.
// =====================================================================

test('C6/8: a real `lossReason` write-out grades `severed` and is flagged incomplete', () => {
  const src = 'function f(user, obj) { ({a: obj.z} = user); return obj; }';
  const byName = parseFns(src, '/x/c6-8.js');
  const { store } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  const lossPaths = allPaths(store).filter((p) => p.lossHopCount > 0);
  assert.ok(lossPaths.length > 0, '§10.2\'s unsupported-target loss site fires on real parsed source');
  const g = gradePath(lossPaths[0]);
  assert.equal(g.grade, 'severed');
  assert.ok(g.factors.includes('loss:unsupported-target'));
  assert.equal(g.incomplete, true);
  assert.equal(g.degraded, false, 'a representation loss is not a BUDGET degradation — the two causes stay apart');
});

test('C6/9: §14.8\'s `markTruncated` reaches the grade as a FLAG, never as a demotion — an honestly-truncated analysis does not make a clean hop look widened', () => {
  const src = 'function f(user) { const b = user.email; return b; }';
  const byName = parseFns(src, '/x/c6-9.js');
  const { store, raw } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  const before = gradePath(allPaths(store)[0]);
  assert.equal(before.grade, 'explicit');
  assert.equal(before.truncated, false);

  store.markTruncated(byName.f.qid, raw[0].context, 'iter-budget');
  const after = gradePath(allPaths(store)[0]);
  assert.equal(after.grade, 'explicit', 'the hops are exactly as explicit as they were');
  assert.equal(after.truncated, true, 'but the analysis-level truncation is carried');
  assert.equal(after.incomplete, true);
  assert.ok(after.factors.includes('analysis-truncated'));
});

test('C6/10: `implicit` is RESERVED — nothing the engine emits today produces it, and a hand-built control-dependence hop does', () => {
  // (a) No real fixture in this file produces it.
  const fixtures = [
    ['function f(user) { const b = user.email; return b; }', 'user.email'],
    ['function f(user) { const b = mystery(user.email); return b; }', 'user.email'],
    ['function f(user, k) { const bag = {}; bag[k] = user.email; return bag; }', 'user.email'],
    ['function f(user) { sink(mystery(user.email)); }', 'user.email'],
    ['function f(user, obj) { ({a: obj.z} = user); return obj; }', 'user.email'],
  ];
  let graded = 0;
  for (const [src, seed] of fixtures) {
    const byName = parseFns(src, '/x/c6-10.js');
    const { store } = record(byName.f, addIdentity(emptyState(), seed, 'data:email'));
    for (const p of allPaths(store)) {
      for (const h of p.hops) {
        assert.notEqual(gradeHop(h).grade, 'implicit', 'the engine models no implicit flow (§10.2)');
        graded += 1;
      }
    }
  }
  assert.ok(graded > 0, 'sanity: hops really were graded');

  // (b) The reserved tier is not a dead branch — §14.2's `origin` node
  // precedent: kept, hand-tested, and disclosed as the exact shape a later
  // increment will produce.
  assert.deepEqual(IMPLICIT_FLOW_REASONS, ['control-dependence']);
  const implicitHop = {
    widenReasons: ['control-dependence'], lossReasons: [], annotations: [],
    ambiguousCorrelation: false, crossScope: false, truncated: false,
  };
  const g = gradeHop(implicitHop);
  assert.equal(g.grade, 'implicit');
  assert.deepEqual(g.implicitReasons, ['control-dependence']);
  assert.deepEqual(g.widenReasons, [], 'a control-dependence reason selects its own tier and never double-counts as a widening');
  assert.ok(flowGradeRank('implicit') > flowGradeRank('widened'));
  assert.ok(flowGradeRank('implicit') < flowGradeRank('severed'));
});

test('C6/10b: `DEGRADED_LOSS_REASONS` names exactly the reason §13.6 emits', () => {
  assert.deepEqual(DEGRADED_LOSS_REASONS, ['context-cap-degraded']);
});

// =====================================================================
// C6/11 — grading needs no path and no store: it is not a query concern.
// =====================================================================

test('C6/11: `gradeHop` returns byte-identical results for a raw PathStore EDGE and for the `Hop` denormalized from it — which is why grading belongs in its own module, not in path-query.js', () => {
  const src = 'function helper(u) { return u.email; } function caller(a) { const out = helper(a); return out; }';
  const byName = parseFns(src, '/x/c6-11.js');
  const { store } = record(byName.caller, addIdentity(emptyState(), 'a.email', 'data:email'), { byName });
  const hops = allPaths(store).flatMap((p) => p.hops);
  assert.ok(hops.length > 0);
  let compared = 0;
  for (const h of hops) {
    const e = store.getEdge(h.edgeId);
    assert.deepEqual(gradeHop(e), gradeHop(h), 'an edge grades the same as its denormalized hop');
    compared += 1;
  }
  assert.ok(compared >= 5, `compared ${compared} edge/hop pairs`);
});

// =====================================================================
// C6/12 — the closed-set property FR-306 literally demands.
// =====================================================================

test('C6/12: across every fixture in this file, no hop carrying ANY widen/loss/ambiguity signal — top-level OR annotation-only — ever shares `explicit`\'s grade', () => {
  const fixtures = [
    ['function f(user) { const b = user.email; return b; }', ['user.email']],
    ['function f(user) { const b = mystery(user.email); return b; }', ['user.email']],
    ['function f(user, k) { const bag = {}; bag[k] = user.email; return bag; }', ['user.email']],
    ['function f(user, k) { const v = user[k]; return v; }', ['user.email']],
    ['function f(user) { sink(mystery(user.email)); }', ['user.email']],
    ['function f(user) { const o = { a: mystery(user.email) }; return o; }', ['user.email']],
    ['function f(user, c) { const o = c ? mystery(user.email) : user.email; return o; }', ['user.email']],
    ['function f(user, obj) { ({a: obj.z} = user); return obj; }', ['user.email']],
    ['function f(p, q) { const x = { a: p.email, b: q.email }; return x; }', ['p.email', 'q.email']],
    ['function f(user) { const a = user.email; const b = mystery(a); return b; }', ['user.email']],
  ];
  let explicitHops = 0;
  let gradedHops = 0;
  for (const [src, seeds] of fixtures) {
    const byName = parseFns(src, '/x/c6-12.js');
    let es = emptyState();
    for (const s of seeds) es = addIdentity(es, s, 'data:email');
    const { store } = record(byName.f, es);
    for (const p of allPaths(store)) {
      for (const h of p.hops) {
        const g = gradeHop(h);
        gradedHops += 1;
        const anySignal = g.widenReasons.length > 0 || g.lossReasons.length > 0
          || g.implicitReasons.length > 0 || g.ambiguousCorrelation;
        if (g.grade === 'explicit') {
          explicitHops += 1;
          assert.equal(anySignal, false,
            'FR-306: a hop with any imprecision/ambiguity signal must never be graded explicit');
        } else {
          assert.equal(anySignal, true, 'and a hop with none must never be graded lower than explicit');
        }
      }
    }
  }
  // Pinned, not bounded — §16.9's published count. The same trade-off
  // §15.10 item 14 states for C5's own measured table: an unrelated IR or
  // engine change CAN move this number, and the correct response is to
  // re-measure and update §16.9, never to relax the assertion.
  assert.equal(gradedHops, 28, `graded ${gradedHops} real hops across 10 fixtures`);
  assert.ok(explicitHops > 0, 'sanity: some hops really are explicit, so the check is not vacuous');
});
