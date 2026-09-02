// obligation-mapping.js — Milestone 4 sub-project 6a: the ObligationMapping
// extension contract (FR-504 §7.12, PRD §10.10's own field list).
//
// A PURE schema/validation module for ObligationMapping records. Zero
// imports, matching flow-grade.js's own "pure function library" precedent
// — this file has even less reason to import anything, since a record's
// shape check needs no graph traversal.
//
// ObligationMapping records are explicitly NOT DataFlowGraph v1 entities
// (PRD §10.10: extension records are "associated with, but not required
// inside" the immutable base graph) — never added to
// dataflow-graph.schema.json, never routed through validate.js's
// validateGraph(), never given a node:/edge:/flow:/data: canonical ID.
// See ids.js's obligationId() for the id scheme and its own header
// comment for why (mirrors provenanceNodeId/provenanceEdgeId's own
// precedent for "a real, stable-ID'd entity that deliberately is not a
// base-graph entity").
//
// The predicate/mapping ENGINE that actually produces real records from a
// real graph is a separate, later sub-project — this file only defines
// what a valid record looks like.

// PRD line 503-508's own six states.
export const OBLIGATION_STATES = Object.freeze([
  'evidence_supported', 'gap_detected', 'unknown',
  'manual_required', 'not_applicable', 'accepted_exception',
]);

// PRD §10.10's cross-cutting fact-typing rule, applied to every extension
// contract, not just this one.
export const OBLIGATION_FACT_TYPES = Object.freeze([
  'code_inferred', 'config_correlated', 'runtime_observed',
  'declared', 'manual', 'hypothetical',
]);

// FR-504's own applicability-inputs list (line 512): "entity role,
// jurisdiction, data subject, business process, merchant level, system
// scope, AI-system role... must be explicitly configured or marked
// unknown — never guessed from a field name." Every key defaults to
// null (== "not configured") rather than being omitted, so a record can
// never silently lack an input the PRD requires be shown.
export const APPLICABILITY_INPUT_KEYS = Object.freeze([
  'entityRole', 'jurisdiction', 'dataSubject', 'businessProcess',
  'merchantLevel', 'systemScope', 'aiSystemRole',
]);

function _isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function _isStringOrNull(v) {
  return v === null || v === undefined || typeof v === 'string';
}

function _isStringArray(v) {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

/**
 * Structural validation only — no cross-reference into any real graph
 * (this module has zero graph access by design). Returns {valid, errors}
 * — errors is an array of {path, message}, mirroring validate.js's own
 * shape. Never throws.
 */
export function validateObligationMapping(record) {
  const errors = [];
  const err = (path, message) => errors.push({ path, message });

  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'obligation mapping record must be an object');
    return { valid: false, errors };
  }

  if (!_isNonEmptyString(record.id) || !record.id.startsWith('obligation:')) {
    err('$.id', 'id is required and must start with "obligation:"');
  }
  if (!_isNonEmptyString(record.graphId)) err('$.graphId', 'graphId is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');
  if (!_isNonEmptyString(record.framework)) err('$.framework', 'framework is required');
  if (!_isNonEmptyString(record.frameworkVersion)) err('$.frameworkVersion', 'frameworkVersion is required');
  if (!_isNonEmptyString(record.requirementId)) err('$.requirementId', 'requirementId is required');
  if (!_isStringOrNull(record.requirementSource)) err('$.requirementSource', 'requirementSource must be a string or null');

  if (!record.applicabilityInputs || typeof record.applicabilityInputs !== 'object' || Array.isArray(record.applicabilityInputs)) {
    err('$.applicabilityInputs', 'applicabilityInputs is required and must be an object');
  } else {
    for (const key of APPLICABILITY_INPUT_KEYS) {
      if (!_isStringOrNull(record.applicabilityInputs[key])) {
        err(`$.applicabilityInputs.${key}`, `applicabilityInputs.${key} must be a string or null`);
      }
    }
  }

  if (!OBLIGATION_STATES.includes(record.state)) {
    err('$.state', `unrecognized state "${record.state}" — must be one of ${OBLIGATION_STATES.join('|')}`);
  }
  if (!_isNonEmptyString(record.predicate)) err('$.predicate', 'predicate is required');
  if (!OBLIGATION_FACT_TYPES.includes(record.factType)) {
    err('$.factType', `unrecognized factType "${record.factType}" — must be one of ${OBLIGATION_FACT_TYPES.join('|')}`);
  }

  if (!_isStringArray(record.contributingGraphIds ?? [])) err('$.contributingGraphIds', 'contributingGraphIds must be an array of strings');
  if (!_isStringArray(record.evidence ?? [])) err('$.evidence', 'evidence must be an array of strings');
  if (!_isStringArray(record.conflicts ?? [])) err('$.conflicts', 'conflicts must be an array of strings');
  if (!_isStringArray(record.missingManualArtifacts ?? [])) err('$.missingManualArtifacts', 'missingManualArtifacts must be an array of strings');

  if (!_isStringOrNull(record.reviewer)) err('$.reviewer', 'reviewer must be a string or null');
  if (!_isStringOrNull(record.reviewedAt)) err('$.reviewedAt', 'reviewedAt must be a string or null');
  if (!_isStringOrNull(record.expiresAt)) err('$.expiresAt', 'expiresAt must be a string or null');

  // AC-28's own binding rule: PRD line 514 is explicit that
  // evidence_supported means only "this predicate's evidence is
  // supported," never organizational compliance — this module does NOT
  // reject a record for having some null applicability inputs alongside
  // evidence_supported (an input can be genuinely inapplicable to a
  // given predicate). What IS enforced structurally: accepted_exception
  // requires a real reviewer and expiresAt — an exception with no owner
  // or no expiry is exactly the silent-permanent-waiver failure mode
  // this state exists to prevent from being invisible.
  if (record.state === 'accepted_exception') {
    if (!_isNonEmptyString(record.reviewer)) err('$.reviewer', 'accepted_exception requires a reviewer');
    if (!_isNonEmptyString(record.expiresAt)) err('$.expiresAt', 'accepted_exception requires an expiresAt');
  }

  return { valid: errors.length === 0, errors };
}
