//
// path-evidence.js: the DAG-04 evidence for witnesses, assembled (R04.1 to R04.6).
//
// One entry point per use:
//   * evaluatePathEvidence       one reconstructed path: conditions + feasibility + control state.
//   * summarizeFlowEvidence      a group of paths that share one graph flow: alternatives stay distinct,
//                                infeasible-under-model paths are listed (never silently dropped), and the
//                                all-paths claim goes through assessAllPathsProtectedWithControls.
//   * buildControlEvidence       the `controlEvidence` slot of a witness bundle (posture/witness-bundle.js).
//
// Everything here is opt-in. Nothing runs, and no field is added to any output, unless a caller (or the
// graph builder with `pathEvidence: true` / AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES=1) asks for it.

import crypto from 'node:crypto';
import { collectWitnessConditions, evaluateWitnessConditions, PATH_PREDICATE_VERSION, SATISFIABILITY_NOTE } from './path-predicates.js';
import { evaluateWitnessConditionsAsync } from './smt-orchestrator.js';
import { creditPath, assessAllPathsProtectedWithControls, CONTROL_CREDIT_VERSION } from './control-credit.js';

export const PATH_EVIDENCE_VERSION = 'path-evidence/1';

export function pathEvidenceEnabled(opts) {
  if (opts && opts.pathEvidence !== undefined) return Boolean(opts.pathEvidence);
  return process.env.AGENTIC_SECURITY_LINEAGE_PATH_PREDICATES === '1';
}

const sha12 = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);

function assemble(path, conditions, feasibility, credit) {
  const refsByEdge = conditions.edgeGuards;
  return {
    version: PATH_EVIDENCE_VERSION,
    pathId: path.id ?? null,
    conditions, feasibility, credit,
    controlState: credit.controlState,
    edgeGuards: refsByEdge,
    controlRefs: credit.credits.map((c) => ({ edgeId: c.edgeId, ref: `ctl:${sha12(`${c.scope}|${c.nodeId}|${c.callee}|${c.sinkFamily}`)}` })),
  };
}

/** Synchronous evidence for one reconstructed path (abstract domains only). */
export function evaluatePathEvidence({ path, nodeOf, fnOf, sinkFamily = null, predicateOpts } = {}) {
  const hops = path?.hops ?? [];
  const conditions = collectWitnessConditions(hops, { fnOf });
  const feasibility = evaluateWitnessConditions(conditions, predicateOpts);
  const credit = creditPath({ hops, nodeOf, fnOf, sinkFamily, truncated: path?.complete === false || path?.analysisTruncated === true });
  return assemble(path ?? {}, conditions, feasibility, credit);
}

/** As above, but an `unknown` abstract answer may be sent to an optional solver (awaited, time-bounded, cancellable). */
export async function evaluatePathEvidenceAsync({ path, nodeOf, fnOf, sinkFamily = null, predicateOpts, solverOpts } = {}) {
  const hops = path?.hops ?? [];
  const conditions = collectWitnessConditions(hops, { fnOf });
  const feasibility = await evaluateWitnessConditionsAsync(conditions, { ...(predicateOpts ?? {}), ...(solverOpts ?? {}) });
  const credit = creditPath({ hops, nodeOf, fnOf, sinkFamily, truncated: path?.complete === false || path?.analysisTruncated === true });
  return assemble(path ?? {}, conditions, feasibility, credit);
}

const STATE_RANK = { unprotected: 0, unknown: 1, protected: 2 };

/**
 * Summarize every path of one flow group. `evidences` is the per-path output of evaluatePathEvidence.
 * The aggregate control state is the WORST over relevant paths, never the best, and alternatives are
 * listed one by one with their own conjunction of conditions.
 */
export function summarizeFlowEvidence({ result, paths, evidences, proof = null }) {
  const byId = new Map(evidences.map((e, i) => [paths[i].id, e]));
  const assessed = assessAllPathsProtectedWithControls({ result, enumerated: paths, evidenceOf: (p) => byId.get(p.id), proof });
  const relevant = evidences.filter((e) => e.feasibility.status !== 'infeasible-under-model');
  let worst = null;
  for (const e of relevant) if (worst === null || STATE_RANK[e.controlState] < STATE_RANK[worst]) worst = e.controlState;
  const feasCounts = {};
  for (const e of evidences) feasCounts[e.feasibility.status] = (feasCounts[e.feasibility.status] ?? 0) + 1;
  return {
    version: PATH_EVIDENCE_VERSION,
    semanticsVersion: PATH_PREDICATE_VERSION,
    controlSemanticsVersion: CONTROL_CREDIT_VERSION,
    pathCount: paths.length,
    feasibility: feasCounts,
    controlState: worst ?? 'unknown',
    allPathsProtected: assessed,
    alternatives: evidences.map((e, i) => ({
      pathId: paths[i].id,
      feasibility: e.feasibility.status,
      feasibilityReasons: e.feasibility.reasons,
      controlState: e.controlState,
      predicateRefs: e.conditions.clauses.map((c) => ({ ref: c.ref, polarity: c.polarity, branchNodeId: c.branchNodeId, scope: c.scope, text: c.text, versions: c.versions })),
    })),
    note: SATISFIABILITY_NOTE,
  };
}

/**
 * The `controlEvidence` slot of a witness bundle (posture/witness-bundle.js validates its shape).
 * Maps the five-valued feasibility result onto the slot's three statuses and keeps the precise result in
 * `detail`, so `timeout` and `unsupported` stay visible as `unknown` rather than becoming a clean bill.
 */
export function buildControlEvidence(evidence, { pathEdgeIds }) {
  const f = evidence.feasibility;
  const status = f.status === 'feasible-model' ? 'feasible' : f.status === 'infeasible-under-model' ? 'infeasible' : 'unknown';
  const onPath = new Set(pathEdgeIds);
  const predicateRefs = [];
  for (const c of evidence.conditions.clauses) for (const edgeId of c.atEdgeIds) if (onPath.has(edgeId)) predicateRefs.push({ edgeId, ref: c.ref });
  const controlRefs = evidence.controlRefs.filter((r) => onPath.has(r.edgeId));
  return {
    status,
    predicateRefs: predicateRefs.sort((a, b) => (a.edgeId + a.ref < b.edgeId + b.ref ? -1 : 1)),
    controlRefs,
    detail: {
      semanticsVersion: PATH_PREDICATE_VERSION,
      feasibility: f.status,
      reasons: f.reasons,
      contradiction: f.contradiction ?? null,
      unmodeledPredicates: f.unmodeledPredicates ?? [],
      solver: f.solver ?? null,
      limitations: f.limitations,
      doesNotImply: SATISFIABILITY_NOTE,
      controlState: evidence.controlState,
      controlSemanticsVersion: CONTROL_CREDIT_VERSION,
      controlsRejected: evidence.credit.rejected.map((r) => ({ edgeId: r.edgeId, callee: r.callee, reason: r.reason })),
      controlLimitations: evidence.credit.limitations,
    },
  };
}
