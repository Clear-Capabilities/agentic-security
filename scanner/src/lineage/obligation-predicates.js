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
// (scoping doc ruling 4): graph absent -> unknown; predicate matches zero
// relevant flows -> not_applicable; every relevant flow clears ->
// evidence_supported; at least one relevant flow fails -> gap_detected.
// applicabilityInputs stays all-null (ruling 5 — no operator-config
// source for it exists anywhere in this codebase yet, a deliberately
// deferred, separate increment).

import { computeGraphDigest } from './export-json.js';
import { obligationId } from './ids.js';

export function evaluateGraphFlowPredicate(spec, graph) {
  const dataElementsById = new Map((graph?.dataElements ?? []).map((d) => [d.id, d]));
  const nodesById = new Map((graph?.nodes ?? []).map((n) => [n.id, n]));
  const edgesById = new Map((graph?.edges ?? []).map((e) => [e.id, e]));

  const relevantFlows = (graph?.flows ?? []).filter((f) => {
    const des = (f.dataElementIds ?? []).map((id) => dataElementsById.get(id)).filter(Boolean);
    const hasClass = des.some((d) => (d.dataClasses ?? []).includes(spec.dataClass));
    if (!hasClass) return false;
    const sinkNode = nodesById.get(f.sink);
    return !!sinkNode && sinkNode.kind === spec.sinkKind;
  });

  if (relevantFlows.length === 0) {
    return { applicable: false, matched: null, contributingGraphIds: [], evidence: [], resultsCount: 0, failedCount: 0 };
  }

  const results = relevantFlows.map((f) => {
    const edge = edgesById.get((f.edgeIds ?? [])[0]);
    const verdict = edge?.protection?.[spec.dimension]?.verdict ?? 'not_assessed';
    return { flow: f, edge, verdict, cleared: verdict === spec.requiredVerdict };
  });

  return {
    applicable: true,
    matched: results.every((r) => r.cleared),
    contributingGraphIds: results.map((r) => r.flow.id),
    evidence: results.flatMap((r) => r.edge?.evidenceRefs ?? []),
    resultsCount: results.length,
    failedCount: results.filter((r) => !r.cleared).length,
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

  let state;
  if (!graph) state = 'unknown';
  else if (!evaluation.applicable) state = 'not_applicable';
  else if (evaluation.matched) state = 'evidence_supported';
  else state = 'gap_detected';

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
