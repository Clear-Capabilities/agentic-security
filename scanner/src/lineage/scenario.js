// scenario.js — M5 deliverable #3a (FR-502 §10.10, DFG-0xx): the
// Scenario extension contract — a hypothetical set of graph overrides,
// NOT a DataFlowGraph v1 entity, mirrors recipient-profile.js's own
// contract shape exactly (structural-only {valid, errors} validator,
// zero graph access, per-field evidence typing for the fields a
// Scenario actually overrides).
//
// See docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-whatif-simulator-scoping.md
// for the full design reasoning, including why EVIDENCE_GRADES gained
// 'assumed' instead of reusing 'declared', and why this module's own
// operations catalog excludes synthetic node/edge insertion (deferred).

export const SCENARIO_VERSION = '1.0.0';

// The 6 in-scope hypothetical-change kinds (FR-502's own 7, minus the
// deferred synthetic-insertion category). Each operation names its
// target canonical id(s) plus the override value(s); scenario-engine.js
// is the only consumer that interprets `kind`.
export const SCENARIO_OPERATION_KINDS = Object.freeze([
  'require_transit_protection',
  'apply_handling',
  'remove_entity',
  'replace_recipient_fact',
  'change_storage_fact',
  'change_governance_fact',
]);

// Per-operation-kind required fields, beyond the universal `kind`. Kept
// as data (not inline in validateScenario) for the same reason
// SCENARIO_OPERATION_KINDS above is — a single source of truth a table
// can be checked against — though scenario-engine.js does not currently
// import this table itself; it only mentions it in a prose comment on
// its own _applyReplaceRecipientFact.
export const SCENARIO_OPERATION_REQUIRED_FIELDS = Object.freeze({
  require_transit_protection: ['targetEdgeId'],
  apply_handling: ['targetEdgeId', 'handling'],
  remove_entity: ['targetNodeId'],
  replace_recipient_fact: ['targetNodeId', 'field', 'value'],
  change_storage_fact: ['targetNodeId', 'field', 'value'],
  change_governance_fact: ['targetFlowId', 'field', 'value'],
});

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function _isStringArray(v) { return Array.isArray(v) && v.every((x) => typeof x === 'string'); }

/**
 * Structural validation only — mirrors validateRecipientProfile's own
 * {valid, errors} shape and "never throws" contract. Does not check
 * that targetEdgeId/targetNodeId/targetFlowId actually exist in any
 * real graph — that is scenario-engine.js's job at apply time, since
 * this module has zero graph access by design.
 */
export function validateScenario(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'Scenario record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('scenario:')) {
    err('$.id', 'id is required and must start with "scenario:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.baseGraphId)) err('$.baseGraphId', 'baseGraphId is required');
  if (!_isNonEmptyString(record.baseGraphDigest)) err('$.baseGraphDigest', 'baseGraphDigest is required');
  if (!_isNonEmptyString(record.author)) err('$.author', 'author is required');
  if (!_isNonEmptyString(record.createdAt)) err('$.createdAt', 'createdAt is required');
  if (record.expiration !== null && record.expiration !== undefined && !_isNonEmptyString(record.expiration)) {
    err('$.expiration', 'expiration must be a string or null');
  }
  if (!_isStringArray(record.assumptions ?? [])) err('$.assumptions', 'assumptions must be an array of strings');
  if (!_isStringArray(record.verificationRequirements ?? [])) {
    err('$.verificationRequirements', 'verificationRequirements must be an array of strings');
  }
  if (!Array.isArray(record.operations) || record.operations.length === 0) {
    err('$.operations', 'operations is required and must be a non-empty array');
  } else {
    record.operations.forEach((op, i) => {
      const p = `$.operations[${i}]`;
      if (!_isPlainObject(op)) { err(p, 'each operation must be an object'); return; }
      if (!SCENARIO_OPERATION_KINDS.includes(op.kind)) {
        err(`${p}.kind`, `unrecognized operation kind "${op.kind}" — must be one of ${SCENARIO_OPERATION_KINDS.join('|')}`);
        return;
      }
      for (const field of SCENARIO_OPERATION_REQUIRED_FIELDS[op.kind]) {
        if (op[field] === undefined || op[field] === null || op[field] === '') {
          err(`${p}.${field}`, `operation of kind "${op.kind}" requires "${field}"`);
        }
      }
    });
  }
  // simulatedDelta is populated by scenario-engine.js after apply, never
  // by a caller constructing the pre-apply record — null is the only
  // valid pre-apply value, an object (scenario-diff.js's own shape) the
  // only valid post-apply value.
  if (record.simulatedDelta !== null && record.simulatedDelta !== undefined && !_isPlainObject(record.simulatedDelta)) {
    err('$.simulatedDelta', 'simulatedDelta must be null (before apply) or an object (after apply)');
  }
  return { valid: errors.length === 0, errors };
}
