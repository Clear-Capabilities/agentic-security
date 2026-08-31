//
// flow-grade.js — FR-306 edge grading (Sub-project C, increment 6).
//
// Binding spec: DESIGN_PATH_PROVENANCE.md §16 (§16.1-§16.10; design + PoC
// landed as Task 1, this is Task 2, the mechanical implementation). A
// PURE grading function library: it consumes ONLY the fields a
// `path-query.js` `Hop`/`Path` or a raw `path-store.js` edge already
// carries. **Zero imports** — one step stricter than `path-query.js`'s own
// `['./ids.js']` boundary (§16.1). Never `engine.js`/`summaries.js`/
// `driver.js`, and never `path-store.js`/`path-query.js` either: grading
// needs neither a path nor the store, since a hop is a denormalized copy
// of its edge (proven by `C6/11`, over every edge of the 2-function
// resolved-call fixture — grading a raw `PathStore` edge and grading the
// `Hop` denormalized from it are byte-identical).
//

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
export const FLOW_EVIDENCE_GRADES = Object.freeze([
  'explicit', 'widened', 'implicit', 'severed', 'ambiguous', 'unassessed',
]);

/**
 * §16.4. Risk precedence for aggregation — lower index wins, exactly like
 * `protection.js`'s own private `_PRECEDENCE`. This is the reverse of the
 * confidence order above for the five real grades, with `unassessed` kept
 * last so it survives an aggregation only when there is nothing else in it.
 * Kept private, exactly as `protection.js` keeps its own — `C6/0` is the
 * parity check that stops it drifting from `FLOW_EVIDENCE_GRADES`.
 */
const _PRECEDENCE = Object.freeze([
  'ambiguous', 'severed', 'implicit', 'widened', 'explicit', 'unassessed',
]);

/**
 * §16.3. Reason strings that mean "this hop is control-dependent, not a
 * data assignment". Empty of anything the engine emits today, by design.
 */
export const IMPLICIT_FLOW_REASONS = Object.freeze(['control-dependence']);

/** §16.5. Loss reasons that mean "an engine budget degraded this away". */
export const DEGRADED_LOSS_REASONS = Object.freeze(['context-cap-degraded']);

export function flowGradeRank(grade) {
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
export function aggregateFlowGrades(grades) {
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
 * denormalized copy of its edge (proven by C6/11).
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
export function gradeHop(hop) {
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
 * Path's own `widenedHopCount`/`lossHopCount`. `path-query.js`'s own
 * `materialize()` now computes those fields annotation-aware too (§16.7
 * Finding 1 / §16.8 item 7), so as of this module the two sources agree —
 * but `gradePath` still computes its own union rather than re-coupling
 * itself to `Path`'s fields: grading is what OWNS this union by design
 * (§16.5), and a caller that can grade a raw `PathStore` edge with no
 * `Path` at all (`C6/11`) must not depend on a `Path`-shaped count that
 * doesn't exist for that input.
 */
export function gradePath(path) {
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
