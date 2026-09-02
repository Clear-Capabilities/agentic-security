// obligation-predicates.js — Milestone 4 sub-project 6b: the graph-fact
// predicate evaluator + ObligationMapping record builder (FR-504 §7.12).
//
// A `graph-flow` predicate spec is a small declarative match object,
// mirroring dataflow/catalog.js's own established `match`-object +
// hand-written-matcher pattern (this codebase's convention for "a small
// declarative query, evaluated by a hand-written function," rather than a
// general query language) — {type:'graph-flow', dataClass, sinkKind,
// dimension, requiredVerdict}. No pre-joined "enriched flow" view exists
// on a shipped DataFlowGraph v1 document, so evaluateGraphFlowPredicate
// builds its own id->entity Maps and joins flow.dataElementIds/.sink
// against dataElements[]/nodes[], exactly as graph-builder.js's own
// internal loops already do.
//
// buildObligationMappingFromGraphPredicate mints a real ObligationMapping
// record (sub-project 6a) from an evaluation result. State derivation
// (scoping doc ruling 4, REVISED — see the "worst case wins" note below,
// found by the final whole-branch review): graph absent -> unknown;
// predicate matches zero relevant flows -> not_applicable; at least one
// relevant flow is genuinely, ASSESSED-and-failing -> gap_detected; no
// genuine failure but at least one relevant flow was never assessed ->
// unknown; every relevant flow was assessed and cleared ->
// evidence_supported. applicabilityInputs stays all-null (ruling 5 — no
// operator-config source for it exists anywhere in this codebase yet, a
// deliberately deferred, separate increment).
//
// WORST-CASE-WINS STATE DERIVATION (found by the final whole-branch
// review, reproduced live against this repo's own real
// bench/data-lineage/ corpus): the original version collapsed an
// UNASSESSED protection verdict (`not_assessed`/`unknown` — e.g. every
// external category other than external-api, which is the only one
// transit-protection.js actually evaluates) into "failed the requirement"
// exactly the same as a genuine `unprotected` verdict. On the real
// corpus this produced a false `gap_detected` — a HIPAA transmission-
// security gap asserted with zero real evidence — for the ONE non-
// not_applicable case the predicate reached, and did so silently (no
// warning, `evidence: []`). This directly violated the same "missing
// evidence must read as unknown/not_assessed, never a verdict" rule
// this codebase already leans on for AC-06 (`at-rest-protection.test.js`)
// and `docs/OSCAL.md`'s own "an unassessed control gets no finding" rule.
// Fixed by tracking assessed-vs-unassessed per flow and prioritizing a
// genuine failure > genuine unassessment > genuine success — mirroring
// `protection.js`'s own `aggregateVerdicts()` risk-precedence
// convention (the pessimistic answer wins), the established precedent
// this package already follows elsewhere (`flow-grade.js`'s `gradePath`,
// `graph-builder.js`'s `flow.protectionSummary` computation).
//
// KIND-VS-UNRESOLVED MATCHING (found by the same review, reproduced live
// against this repo's own AC-07 flagship fixture — PHI reaching an AI
// model provider): FR-203 (`coverage.js#resolveSiteDecision`) rewrites a
// sink node's `kind` to `'unresolved'` when its destination can't be
// statically resolved, retaining `subtype`/`category` — the highest-risk
// shape (a dynamic destination) was therefore silently excluded from
// this predicate's own sink-kind filter, reporting `not_applicable`
// ("this requirement does not apply") for exactly the case that most
// needs it to apply. Fixed by also matching `kind === 'unresolved'` —
// once matched, the worst-case-wins state derivation above correctly
// resolves it to `unknown` (an unresolved destination has no real
// transit verdict either), never a false `not_applicable` or a false
// `gap_detected`.
//
// EVIDENCE GAP, DISCLOSED (found by the same review): `evidence` is
// sourced from `edge.evidenceRefs`, but `graph-builder.js` hardcodes
// every real edge's `evidenceRefs` to `[]` and nothing downstream ever
// populates it — confirmed by grep, zero write sites beyond that one
// literal. So `record.evidence` is structurally always empty on any
// graph the real pipeline produces, including a genuine
// `evidence_supported` record. This is a real, upstream gap in
// `graph-builder.js` (no edge-level evidence producer exists for
// protection verdicts today), not something this module can close on
// its own — named here rather than silently shipped as if it worked.
//
// KNOWN LIMITATION: evaluateGraphFlowPredicate reads only
// flow.edgeIds[0] — a flow with multiple edges is evaluated using its
// first edge only, silently ignoring the rest. Not currently reachable:
// graph-builder.js (the only real producer of flows) always mints a
// single-element edgeIds array. This is a latent gap for any future
// multi-edge-flow producer, or a hand-built graph conforming to the
// schema (which places no length constraint on flow.edgeIds) — worth
// revisiting (e.g. worst-verdict-wins across all edges, mirroring
// aggregateVerdicts()'s own precedent) if that assumption ever changes.
//
// NEVER THROWS, defensively, not just by convention (found by the same
// review: 7 of 11 malformed-graph shapes tried threw a raw TypeError
// that propagated all the way out of auditor-walkthrough.js's
// evaluateFramework, losing every control's evaluation for the whole
// framework — a total compliance-report outage from one degraded
// graph). Every array field is defensively coerced via Array.isArray
// before use; a non-object entry inside an array is filtered out rather
// than dereferenced.

import { computeGraphDigest } from './export-json.js';
import { obligationId } from './ids.js';

function _asArray(v) {
  return Array.isArray(v) ? v : [];
}

export function evaluateGraphFlowPredicate(spec, graph) {
  const dataElementsById = new Map(_asArray(graph?.dataElements).filter(Boolean).map((d) => [d.id, d]));
  const nodesById = new Map(_asArray(graph?.nodes).filter(Boolean).map((n) => [n.id, n]));
  const edgesById = new Map(_asArray(graph?.edges).filter(Boolean).map((e) => [e.id, e]));

  const relevantFlows = _asArray(graph?.flows).filter((f) => {
    if (!f || typeof f !== 'object') return false;
    const des = _asArray(f.dataElementIds).map((id) => dataElementsById.get(id)).filter(Boolean);
    const hasClass = des.some((d) => _asArray(d.dataClasses).includes(spec.dataClass));
    if (!hasClass) return false;
    const sinkNode = nodesById.get(f.sink);
    if (!sinkNode) return false;
    // Also match 'unresolved' — see the KIND-VS-UNRESOLVED MATCHING note
    // above; excluding it silently drops the highest-risk (dynamic-
    // destination) sinks from this predicate's own applicability.
    return sinkNode.kind === spec.sinkKind || sinkNode.kind === 'unresolved';
  });

  if (relevantFlows.length === 0) {
    return {
      applicable: false, matched: null, hasFailure: false, hasUnassessed: false,
      contributingGraphIds: [], evidence: [], resultsCount: 0, failedCount: 0, notAssessedCount: 0,
    };
  }

  // A verdict of 'not_assessed'/'unknown' means "never checked," never
  // "checked and failed" — see the WORST-CASE-WINS STATE DERIVATION note
  // above for why this distinction is load-bearing.
  const UNASSESSED_VERDICTS = new Set(['not_assessed', 'unknown']);
  const results = relevantFlows.map((f) => {
    const edge = edgesById.get(_asArray(f.edgeIds)[0]);
    const verdict = edge?.protection?.[spec.dimension]?.verdict ?? 'not_assessed';
    const assessed = !UNASSESSED_VERDICTS.has(verdict);
    return { flow: f, edge, verdict, assessed, cleared: verdict === spec.requiredVerdict };
  });

  const hasFailure = results.some((r) => r.assessed && !r.cleared);
  const hasUnassessed = results.some((r) => !r.assessed);

  return {
    applicable: true,
    // Kept for backward compatibility with any caller reading the
    // simple boolean — true only in the unambiguous "every relevant
    // flow was assessed and cleared" case; buildObligationMappingFromGraphPredicate
    // itself reads hasFailure/hasUnassessed directly for the real,
    // worst-case-wins state derivation.
    matched: !hasFailure && !hasUnassessed,
    hasFailure,
    hasUnassessed,
    contributingGraphIds: results.map((r) => r.flow.id).filter((id) => typeof id === 'string'),
    evidence: results.flatMap((r) => _asArray(r.edge?.evidenceRefs)),
    resultsCount: results.length,
    failedCount: results.filter((r) => r.assessed && !r.cleared).length,
    notAssessedCount: results.filter((r) => !r.assessed).length,
  };
}

const _NULL_APPLICABILITY_INPUTS = Object.freeze({
  entityRole: null, jurisdiction: null, dataSubject: null, businessProcess: null,
  merchantLevel: null, systemScope: null, aiSystemRole: null,
});

export function buildObligationMappingFromGraphPredicate({
  framework, frameworkVersion, requirementId, requirementSource, predicateLabel, graph, evaluation,
}) {
  const graphId = graph?.graphId ?? null;
  const graphDigest = graph ? computeGraphDigest(graph) : null;

  // Found by this task's own review: a caller-contract violation (a
  // truthy graph paired with a missing/null evaluation — i.e. forgetting
  // to call evaluateGraphFlowPredicate first) used to throw here,
  // inconsistent with this package's "public API never throws on
  // malformed input" convention (obligation-mapping.js's own JSDoc,
  // path-query.js, flow-grade.js). Not reachable through this sub-
  // project's own documented calling convention (Task 2's wiring always
  // pairs graph/evaluation correctly), but degrading to 'unknown' here
  // — the same answer a genuinely absent graph gets — is honest and
  // matches every sibling module's own never-throw contract.
  //
  // Worst-case-wins (found by the final whole-branch review — see the
  // WORST-CASE-WINS STATE DERIVATION note at the top of this file): a
  // genuine assessed failure always outranks a genuine unassessment,
  // which always outranks a genuine clean pass.
  let state;
  if (!graph || !evaluation) state = 'unknown';
  else if (!evaluation.applicable) state = 'not_applicable';
  else if (evaluation.hasFailure) state = 'gap_detected';
  else if (evaluation.hasUnassessed) state = 'unknown';
  else state = 'evidence_supported';

  return {
    id: obligationId({ framework, frameworkVersion, requirementId, graphId: graphId ?? '', graphDigest: graphDigest ?? '' }),
    graphId: graphId ?? '(no graph)',
    graphDigest: graphDigest ?? '(no graph)',
    framework,
    frameworkVersion,
    requirementId,
    requirementSource: requirementSource ?? null,
    applicabilityInputs: { ..._NULL_APPLICABILITY_INPUTS },
    state,
    predicate: predicateLabel,
    factType: 'code_inferred',
    contributingGraphIds: evaluation?.contributingGraphIds ?? [],
    evidence: evaluation?.evidence ?? [],
    conflicts: [],
    missingManualArtifacts: [],
    reviewer: null,
    reviewedAt: null,
    expiresAt: null,
  };
}
