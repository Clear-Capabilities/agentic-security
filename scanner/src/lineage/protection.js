//
// Protection verdict model (Data Flow Explorer PRD section 14.1 + 8.4).
// Every protection dimension carries two INDEPENDENT fields: a verdict
// and an evidence grade — "declared protected" must never render
// identically to code-and-configuration-proven protection (PRD 14.1).
//
// This module defines the model only (enums, the empty/default shape,
// and the pure aggregation function). The analyzers that actually DECIDE
// a verdict per edge (transit/at-rest/handling — PRD FR-401 through
// FR-403) are Milestone 2 (DFG-010), not this module.

export const PROTECTION_VERDICTS = Object.freeze(['protected', 'unprotected', 'unknown', 'not_applicable', 'not_assessed']);

export const EVIDENCE_GRADES = Object.freeze(['runtime', 'code_and_config', 'code', 'config', 'declared', 'manual', 'none']);

export const PROTECTION_DIMENSIONS = Object.freeze(['transit', 'atRest', 'handling']);

export function emptyProtection() {
  const dim = () => ({ verdict: 'not_assessed', evidenceGrade: 'none' });
  return { transit: dim(), atRest: dim(), handling: dim() };
}

export function isValidProtectionDimension(d) {
  if (!d || typeof d !== 'object') return false;
  return PROTECTION_VERDICTS.includes(d.verdict) && EVIDENCE_GRADES.includes(d.evidenceGrade);
}

// PRD section 8.4: "For an aggregated path, visible risk precedence is
// unprotected/prohibited -> mixed -> unknown/manual_required ->
// protected/permitted -> not_assessed." Lower index = higher precedence
// (wins the aggregation). 'mixed' is not itself in PROTECTION_VERDICTS —
// it is a caller-supplied aggregate state from an upstream step (e.g. "one
// branch protected, one branch unprotected") that this function's own
// ranking table must still place correctly among the five base verdicts.
const _PRECEDENCE = ['unprotected', 'mixed', 'unknown', 'protected', 'not_applicable', 'not_assessed'];

/**
 * Reduce a set of verdicts (protection verdicts, or 'mixed') to the single
 * highest-precedence one. Never guesses: an empty array is 'not_assessed',
 * and an unrecognized verdict throws rather than silently sorting last —
 * a typo here must not quietly rank as "safest".
 */
export function aggregateVerdicts(verdicts) {
  if (!Array.isArray(verdicts) || verdicts.length === 0) return 'not_assessed';
  let best = null;
  let bestRank = Infinity;
  for (const v of verdicts) {
    const rank = _PRECEDENCE.indexOf(v);
    if (rank === -1) throw new Error(`aggregateVerdicts: unrecognized verdict "${v}"`);
    if (rank < bestRank) { bestRank = rank; best = v; }
  }
  return best;
}
