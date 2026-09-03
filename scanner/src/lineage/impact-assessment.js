// impact-assessment.js — M5 deliverable #4 (FR-507 §10.10): the
// ImpactAssessment extension contract — the result of asking "what is
// reachable from this compromised node/edge/flow/data element, per the
// graph's own already-scanned evidence." NOT a DataFlowGraph v1 entity,
// mirrors recipient-profile.js's/scenario.js's own contract shape
// exactly (structural-only {valid, errors} validator, zero graph
// access at construction time).
//
// See docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-blast-radius-impact-scoping.md
// for the full design reasoning, including why there is no
// affectedObligationIds field (ObligationMapping records are built on
// demand per compliance framework, not stored on the graph) and why
// `scope` is always 'possible' today (no runtime-corroboration layer
// exists yet).

export const IMPACT_VERSION = '1.0.0';

export const IMPACT_TARGET_KINDS = Object.freeze(['node', 'edge', 'flow', 'dataElement']);

// 'possible' is the only value any producer emits today — 'observed'
// is reserved for a future Digital Twin (M5 #7) increment with a real
// runtime-corroboration signal. Both are valid schema values now so
// that increment needs no breaking change to this contract later.
export const IMPACT_SCOPE_VALUES = Object.freeze(['possible', 'observed']);

// Discloses WHICH of the two genuinely different traversal semantics
// produced this record (final-review I2 fix) — `scope` alone cannot
// distinguish them, since both families emit `scope: 'possible'`.
// 'topology_reachable': a `node` target's topology-wide showAllPaths
// BFS — "everything this compromised node could push to." 'flow_
// restricted': an `edge`/`flow`/`dataElement` target's direct trace
// over the flows that actually carry it — never the topology-wide BFS.
// Without this field a JSON consumer cannot tell "exact carrier trace"
// from "topological presumption" apart, the exact silent-conflation
// this codebase's own disclosure discipline exists to prevent.
export const IMPACT_TRACE_KINDS = Object.freeze(['topology_reachable', 'flow_restricted']);

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isStringArray(v) { return Array.isArray(v) && v.every((x) => typeof x === 'string'); }

/**
 * Structural validation only — mirrors validateRecipientProfile's/
 * validateScenario's own {valid, errors} shape and "never throws"
 * contract.
 */
export function validateImpactAssessment(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'ImpactAssessment record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('impact:')) {
    err('$.id', 'id is required and must start with "impact:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.graphId)) err('$.graphId', 'graphId is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');
  if (!_isNonEmptyString(record.targetId)) err('$.targetId', 'targetId is required');
  if (!IMPACT_TARGET_KINDS.includes(record.targetKind)) {
    err('$.targetKind', `targetKind must be one of ${IMPACT_TARGET_KINDS.join('|')}`);
  }
  if (!IMPACT_SCOPE_VALUES.includes(record.scope)) {
    err('$.scope', `scope must be one of ${IMPACT_SCOPE_VALUES.join('|')}`);
  }
  if (!IMPACT_TRACE_KINDS.includes(record.traceKind)) {
    err('$.traceKind', `traceKind must be one of ${IMPACT_TRACE_KINDS.join('|')}`);
  }
  if (!_isStringArray(record.affectedNodeIds ?? [])) err('$.affectedNodeIds', 'affectedNodeIds must be an array of strings');
  if (!_isStringArray(record.affectedEdgeIds ?? [])) err('$.affectedEdgeIds', 'affectedEdgeIds must be an array of strings');
  if (!_isStringArray(record.affectedDataClasses ?? [])) err('$.affectedDataClasses', 'affectedDataClasses must be an array of strings');
  if (!_isStringArray(record.affectedRecipientProfileIds ?? [])) err('$.affectedRecipientProfileIds', 'affectedRecipientProfileIds must be an array of strings');
  if (!_isStringArray(record.coverageLimitations ?? [])) err('$.coverageLimitations', 'coverageLimitations must be an array of strings');
  if (!_isNonEmptyString(record.generatedAt)) err('$.generatedAt', 'generatedAt is required');
  return { valid: errors.length === 0, errors };
}
