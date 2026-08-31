// Sub-project C, increment C6 — FR-306 edge grading: DESIGN-TASK PROOF OF
// CONCEPT.
//
// Throwaway-named on purpose, exactly as C1's/C3's/C4's/C5's own design
// tasks were (`engine-provenance-interprocedural-poc.test.js`,
// `path-store-poc.test.js`, `path-query-poc.test.js` — each absorbed into
// the permanent suite and deleted by its follow-up implementation task).
// This file prototypes the proposed `flow-grade.js` LOCALLY; shipped source
// under `src/lineage/` is unmodified by this task. Every number and every
// behavioural claim in DESIGN_PATH_PROVENANCE.md §16 was produced by
// running this file.
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

// =====================================================================
// LOCAL PROTOTYPE of the proposed `scanner/src/lineage/flow-grade.js`.
// The follow-up implementation task lifts this block into that file
// verbatim, deletes it here, and re-points the imports (§16.8 item 1).
//
// It imports NOTHING — one step stricter than `path-query.js`'s own
// `['./ids.js']` boundary. Grading is a pure function of the fields a
// `PathStore` EDGE already carries, so it needs neither `ids.js` nor the
// store nor a reconstructed path (proven by C6/10).
// =====================================================================

/**
 * §16.2. The flow-evidence vocabulary, in CONFIDENCE order, most
 * confident first. Deliberately NOT `protection.js`'s `EVIDENCE_GRADES`
 * — see §16.2's rejection note (that enum grades the SOURCE of a
 * protection verdict; this one grades how explicit a recorded data
 * movement is, and every value here comes from the same evidence source).
 *
 * `implicit` is RESERVED: nothing in the engine emits a control-dependence
 * reason today (§10.2 — "the engine models no implicit flow today; do not
 * invent one"). It is present because FR-306 names it first and because
 * §14.2's `origin` node kind set the precedent for keeping, and hand-
 * testing, the exact shape a later increment will produce.
 *
 * `unassessed` is the empty-input answer only, mirroring
 * `protection.js`'s `aggregateVerdicts` returning `'not_assessed'` for an
 * empty array. Nothing ever grades a real hop `unassessed`.
 */
const FLOW_EVIDENCE_GRADES = Object.freeze([
  'explicit', 'widened', 'implicit', 'severed', 'ambiguous', 'unassessed',
]);

/**
 * §16.4. Risk precedence for aggregation — lower index wins, exactly like
 * `protection.js`'s own private `_PRECEDENCE`. This is the reverse of the
 * confidence order above for the five real grades, with `unassessed` kept
 * last so it survives an aggregation only when there is nothing else in it.
 */
const _PRECEDENCE = Object.freeze([
  'ambiguous', 'severed', 'implicit', 'widened', 'explicit', 'unassessed',
]);

/**
 * §16.3. Reason strings that mean "this hop is control-dependent, not a
 * data assignment". Empty of anything the engine emits today, by design.
 */
const IMPLICIT_FLOW_REASONS = Object.freeze(['control-dependence']);

/** §16.5. Loss reasons that mean "an engine budget degraded this away". */
const DEGRADED_LOSS_REASONS = Object.freeze(['context-cap-degraded']);

function flowGradeRank(grade) {
  const i = FLOW_EVIDENCE_GRADES.indexOf(grade);
  if (i === -1) throw new Error(`flowGradeRank: unrecognized flow evidence grade "${grade}"`);
  return i;
}

/**
 * §16.4. Reduce hop grades to one path grade: the WORST wins. Never
 * guesses — an empty array is `'unassessed'`, and an unrecognized grade
 * throws rather than silently sorting last, verbatim `aggregateVerdicts`'
 * own contract ("a typo here must not quietly rank as safest").
 */
function aggregateFlowGrades(grades) {
  if (!Array.isArray(grades) || grades.length === 0) return 'unassessed';
  let worst = null;
  let worstRank = Infinity;
  for (const g of grades) {
    const rank = _PRECEDENCE.indexOf(g);
    if (rank === -1) throw new Error(`aggregateFlowGrades: unrecognized flow evidence grade "${g}"`);
    if (rank < worstRank) { worstRank = rank; worst = g; }
  }
  return worst;
}

function _sortedUnion(...arrays) {
  const s = new Set();
  for (const a of arrays) for (const v of a ?? []) if (v != null) s.add(v);
  return [...s].sort();
}

/**
 * §16.3. Grade ONE hop. Accepts either a `path-query.js` `Hop` or a raw
 * `path-store.js` EDGE — they carry the same grading fields, a hop being a
 * denormalized copy of its edge (proven by C6/10).
 *
 * **The annotation rule (§16.5), and it is load-bearing:** `widenReasons`
 * and `lossReasons` are read as the UNION of the hop's own top-level
 * arrays AND every `annotations[].widenReason` / `.lossReason`. §2.2
 * classifies a null-`fromPath`, null-`peerScope` in-half as an annotation
 * on the edges its siblings form, so a genuine widening recorded at an
 * expression-internal construct lands ONLY in `annotations[]` — measured
 * on three real fixtures (C6/5). A grader reading only the top-level
 * arrays grades those flows `explicit`, which is FR-306's own literal
 * prohibition.
 *
 * `crossScope` is carried as a FACTOR and never affects `grade` (§16.6).
 */
function gradeHop(hop) {
  const annotations = Array.isArray(hop.annotations) ? hop.annotations : [];
  const topWiden = Array.isArray(hop.widenReasons) ? hop.widenReasons : [];
  const topLoss = Array.isArray(hop.lossReasons) ? hop.lossReasons : [];
  const widenAll = _sortedUnion(topWiden, annotations.map((a) => a.widenReason));
  const lossAll = _sortedUnion(topLoss, annotations.map((a) => a.lossReason));

  // A control-dependence reason is not a widening — it selects the
  // `implicit` tier and is removed from `widenReasons` so it never
  // double-counts.
  //
  // §16.3: the subtraction is applied to the WIDEN side ONLY, deliberately
  // (fix round 1, nitpick 8). Applying it to `lossAll` too would let a
  // future `lossReason: 'control-dependence'` be silently UPGRADED from
  // `severed` to the more-confident `implicit` tier — a grade moving in
  // the optimistic direction because a new reason string was added
  // elsewhere. Unreachable today (no loss reason is in the set), and kept
  // unreachable by construction rather than by luck.
  const isImplicit = (r) => IMPLICIT_FLOW_REASONS.includes(r);
  const implicitReasons = widenAll.filter(isImplicit).sort();
  const widenReasons = widenAll.filter((r) => !isImplicit(r));
  const lossReasons = [...lossAll];

  // Exactly which reasons would have been invisible to a top-level-only
  // reader. Named, not merely folded — §18.4's transparency requirement
  // applied to the grade's own inputs.
  const annotationOnly = [
    ...widenAll.filter((r) => !topWiden.includes(r)).map((r) => `widen:${r}`),
    ...lossAll.filter((r) => !topLoss.includes(r)).map((r) => `loss:${r}`),
  ].sort();

  const ambiguousCorrelation = hop.ambiguousCorrelation === true;
  const truncated = hop.truncated === true;
  const crossScope = hop.crossScope === true;

  const grade = ambiguousCorrelation ? 'ambiguous'
    : lossReasons.length > 0 ? 'severed'
      : implicitReasons.length > 0 ? 'implicit'
        : widenReasons.length > 0 ? 'widened'
          : 'explicit';

  const factors = [
    ...widenReasons.map((r) => `widen:${r}`),
    ...lossReasons.map((r) => `loss:${r}`),
    ...implicitReasons.map((r) => `implicit:${r}`),
    ...(ambiguousCorrelation ? ['ambiguous-correlation'] : []),
    ...(truncated ? ['analysis-truncated'] : []),
    ...(crossScope ? ['cross-scope'] : []),
  ].sort();

  const degraded = lossAll.some((r) => DEGRADED_LOSS_REASONS.includes(r));
  return {
    grade,
    rank: flowGradeRank(grade),
    factors,
    widenReasons,
    lossReasons,
    implicitReasons,
    annotationOnly,
    ambiguousCorrelation,
    degraded,
    truncated,
    crossScope,
    incomplete: grade === 'severed' || degraded || truncated,
  };
}

/**
 * §16.4. Grade one reconstructed `Path`. The path's grade is the WORST of
 * its hops' — `protection.js`'s `aggregateVerdicts` risk-precedence
 * reduction, applied to the one axis FR-306 governs.
 *
 * Counts are recomputed from `gradeHop`, deliberately NOT read off the
 * Path's own `widenedHopCount`/`lossHopCount` — those are computed in
 * `path-query.js`'s `materialize()` from the edge's TOP-LEVEL arrays only
 * and therefore under-report annotation-carried reasons (§16.7, Finding 1).
 */
function gradePath(path) {
  const hops = Array.isArray(path.hops) ? path.hops : [];
  const hopGrades = hops.map((h) => gradeHop(h));
  const grade = aggregateFlowGrades(hopGrades.map((g) => g.grade));
  const complete = path.complete === true;
  const analysisTruncated = path.analysisTruncated === true;
  const factors = _sortedUnion(
    hopGrades.flatMap((g) => g.factors),
    complete ? [] : ['partial-path'],
    analysisTruncated ? ['analysis-truncated'] : [],
  );
  return {
    grade,
    rank: flowGradeRank(grade),
    // §16.4 (fix round 1, finding 3): the FULL `HopGrade` objects, in path
    // order — not a parallel array of bare grade strings. A bare-string
    // array loses per-hop CAUSE, forcing every caller that wants to render
    // FR-306's "visually distinct" half to re-invoke `gradeHop` per hop and
    // re-derive what this function already computed.
    hops: hopGrades,
    worstHopIndex: hopGrades.findIndex((g) => g.grade === grade),
    factors,
    widenedHopCount: hopGrades.filter((g) => g.widenReasons.length > 0).length,
    lossHopCount: hopGrades.filter((g) => g.lossReasons.length > 0).length,
    implicitHopCount: hopGrades.filter((g) => g.implicitReasons.length > 0).length,
    ambiguousHopCount: hopGrades.filter((g) => g.ambiguousCorrelation).length,
    degradedHopCount: hopGrades.filter((g) => g.degraded).length,
    truncatedHopCount: hopGrades.filter((g) => g.truncated).length,
    degraded: hopGrades.some((g) => g.degraded),
    truncated: analysisTruncated || hopGrades.some((g) => g.truncated),
    complete,
    incomplete: !complete || analysisTruncated || hopGrades.some((g) => g.incomplete),
  };
}

// ===================== end of local prototype =====================

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
 * §16.7 Finding 1 / §16.8's `path-query.js` remediation item, prototyped
 * LOCALLY exactly as the grading functions above are.
 *
 * This is the whole fix: `path-query.js`'s `materialize()` currently
 * computes `widenedHopCount` / `lossHopCount` — and, from them, §15.7's
 * `shape` signature — with `hops.filter((h) => h.widenReasons.length > 0)`,
 * i.e. from the two EDGE-FORMING halves only. It is exactly the consumer
 * §14.9's own correction and §15.8 tell to "read `annotations[]` too, not
 * only the edge's top-level reason arrays", and it does not.
 *
 * The fix belongs in `materialize()` and NOWHERE ELSE. It must NOT be
 * pushed down into `path-store.js`'s `edge.widenReasons`/`edge.lossReasons`:
 * those two arrays are part of `provenanceEdgeId`'s discriminator (§14.5),
 * so changing them would move every edge id, and with it every `ppath:` id
 * (§15.6) — a re-hash of the whole DAG to fix a display count.
 */
function withAnnotationAwareCounts(path) {
  const annWiden = (h) => h.widenReasons.length > 0 || (h.annotations ?? []).some((a) => a.widenReason != null);
  const annLoss = (h) => h.lossReasons.length > 0 || (h.annotations ?? []).some((a) => a.lossReason != null);
  const widenedHopCount = path.hops.filter(annWiden).length;
  const lossHopCount = path.hops.filter(annLoss).length;
  return {
    ...path,
    widenedHopCount,
    lossHopCount,
    // `shape` is rebuilt from the corrected counts — it is derived from the
    // same two filters in `materialize()`, so a fix that left it alone
    // would leave §15.7's diversity bucketing reading the stale answer.
    shape: [
      path.complete ? 'complete' : 'partial',
      path.crossScopeCount > 0 ? 'boundary' : 'local',
      widenedHopCount > 0 ? 'widened' : 'explicit',
      lossHopCount > 0 ? 'lossy' : 'intact',
      path.ambiguousHopCount > 0 ? 'ambiguous' : 'correlated',
    ].join('/'),
  };
}

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
  // missing from either side would silently throw or silently win.
  assert.deepEqual([...FLOW_EVIDENCE_GRADES].sort(), [..._PRECEDENCE].sort());
  assert.equal(_PRECEDENCE[_PRECEDENCE.length - 1], 'unassessed',
    "'unassessed' loses every aggregation it is not alone in — aggregateVerdicts' own 'not_assessed' precedent");
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

test('C6/5b: §16.8\'s `materialize()` remediation, prototyped — the annotation-aware counts report `widenedHopCount: 1` and a `widened` shape on the fixture C5 currently scores as explicit', () => {
  const src = 'function f(user) { sink(mystery(user.email)); }';
  const byName = parseFns(src, '/x/c6-5b.js');
  const { store } = record(byName.f, addIdentity(emptyState(), 'user.email', 'data:email'));
  // Two `escape` sinks here (one per bare-call argument site), so pick the
  // path whose single hop is the one carrying the annotation-only widening.
  const paths = allPaths(store);
  assert.equal(paths.length, 2);
  const p = paths.find((x) => x.hops.some((h) => h.annotations.some((a) => a.widenReason === 'unresolved-call')));
  assert.ok(p, 'the annotation-carrying path exists');

  // THE REGRESSION ASSERTION — the behaviour §16.8's `path-query.js` item
  // must ship. Written against the local prototype so it states the target
  // rather than the defect, and so it keeps passing unchanged once the fix
  // lands in `materialize()` itself.
  const fixed = withAnnotationAwareCounts(p);
  assert.equal(fixed.widenedHopCount, 1,
    'the widening is real and the count must see it');
  assert.equal(fixed.shape.split('/')[2], 'widened',
    "§15.7's diversity `shape` signature must see it too — it is derived from the same filter");
  assert.equal(fixed.lossHopCount, 0, 'and the loss half is untouched by a widen-only fixture');
  assert.equal(fixed.shape.split('/')[3], 'intact');

  // Forward-compatible: the SHIPPED count may be either the design-time
  // measured value (0) or the fixed one (1), and this test must not be the
  // thing that blocks the fix. Deliberately not `assert.equal(p.widenedHopCount, 0)`
  // (fix round 1, finding 1 — that assertion pinned the DEFECT).
  assert.ok(p.widenedHopCount <= fixed.widenedHopCount,
    'shipped `materialize()` measured 0 here at design time; it becomes 1 once §16.8\'s item lands, and never exceeds the corrected count');

  // And the grade agrees with the corrected count, which is the whole point
  // of §16.7 Finding 1: `gradePath` never depended on the buggy field.
  const g = gradePath(p);
  assert.equal(g.widenedHopCount, fixed.widenedHopCount);
  assert.equal(g.grade, 'widened');
});

test('C6/5c: the SAME remediation fixes the loss half — a §13.6-degraded path\'s `lossHopCount`/`shape` are annotation-blind today and correct under the prototype', () => {
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

  const fixed = withAnnotationAwareCounts(p);
  assert.equal(fixed.lossHopCount, 1,
    "the honestly-degraded hop must count as lossy — anything else is §18.4's failure mode inside a display count");
  assert.equal(fixed.shape.split('/')[3], 'lossy');
  assert.ok(p.lossHopCount <= fixed.lossHopCount,
    'shipped `materialize()` measured 0 here at design time; it becomes 1 once §16.8\'s item lands');
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
