// cross-repo-link.js — M5 deliverable #8 (FR-304's "declared" half only,
// per the M5 top-level scoping doc's own DFG-025 row and this
// deliverable's own scoping doc, 2026-09-02). The CrossRepoLink
// extension contract — a graph-attached array (mirrors
// `graph.recipientProfiles[]`'s own precedent, `recipient-profile.js`),
// NEVER a DataFlowGraph v1 core-schema edge: `validate.js`'s
// `_validateEdge` requires both endpoints of an edge to resolve against
// the ONE graph's own `nodeIds` set, so a foreign node id from a
// different repo's build can never pass `validateGraph()` — settling,
// not merely motivating, the decision that a cross-repo link must be a
// separate extension record.
//
// Mirrors `recipient-profile.js`'s own file shape exactly (pure module,
// `{valid, errors}` validator, zero graph access at construction time),
// with the one real, disclosed departure that module's own header also
// discloses for itself: no per-field `fieldEvidence` map, since every
// field on a CrossRepoLink is uniformly operator-declared (no
// code-derived half) — closer to `ObligationMapping`'s single
// record-level `factType` shape (here, `provenance`) than to
// `RecipientProfile`'s per-field one.
//
// `provenance` reuses `schema.js`'s own `EDGE_PROVENANCE_VALUES` — this
// deliverable's CLI is the FIRST real producer of `'manual'` anywhere in
// this codebase (confirmed by the scoping investigation: every shipped
// edge is `provenance: 'code'`, unconditionally, per Milestone 2
// Sub-project F increment 1). `'schema'` stays reserved on the SAME
// field for a future "imported"/auto-correlated producer (FR-304's
// second flavor — destination/schema-based automatic cross-repo edge
// correlation) — explicitly out of scope for this deliverable, per the
// scoping doc's own "The real correction" section.

import { EDGE_PROVENANCE_VALUES } from './schema.js';

export const CROSS_REPO_LINK_VERSION = '1.0.0';

// The operator-config filename this deliverable's CLI reads/writes,
// resolved via `posture/state-dir.js`'s `statePath()` — mirrors
// `recipient-registry.js`'s own `RECIPIENT_CONFIG_FILENAME` precedent.
export const CROSS_REPO_LINKS_FILENAME = 'cross-repo-links.json';

// Fixed, single legal value — mirrors `edge.relationship`'s own single
// legal value ('data_flow', validate.js's `_validateEdge`). No new
// taxonomy is introduced for this deliverable.
export const CROSS_REPO_LINK_RELATIONSHIP = 'data_flow';

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isStringOrNull(v) { return v === null || v === undefined || typeof v === 'string'; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

// Shared endpoint-shape check for `local`/`remote` — `local` always
// checks {graphId, graphDigest, nodeId}; `remote` additionally checks
// {repository, sourceFile} via `extraFields`.
function _validateEndpoint(endpoint, label, err, extraFields = []) {
  if (!_isPlainObject(endpoint)) {
    err(`$.${label}`, `${label} is required and must be an object`);
    return;
  }
  if (!_isNonEmptyString(endpoint.graphId)) err(`$.${label}.graphId`, `${label}.graphId is required`);
  if (!_isNonEmptyString(endpoint.graphDigest)) err(`$.${label}.graphDigest`, `${label}.graphDigest is required`);
  if (!_isNonEmptyString(endpoint.nodeId)) err(`$.${label}.nodeId`, `${label}.nodeId is required`);
  for (const field of extraFields) {
    if (!_isNonEmptyString(endpoint[field])) err(`$.${label}.${field}`, `${label}.${field} is required`);
  }
}

/**
 * Structural validation only — mirrors `validateRecipientProfile`'s/
 * `validateScenario`'s own `{valid, errors}` shape and "never throws"
 * contract. Never confirms `local.nodeId`/`remote.nodeId` actually exist
 * in any real graph — that needs real graph content, which this pure
 * module deliberately has no access to (mirrors `scenario.js`'s own
 * "structural-only, zero graph access" boundary exactly). That check is
 * `federation-loader.js`'s (for the remote side) and the CLI's own
 * `loadSignedGraph` call (for the local side) job, at declare time.
 *
 * @param {object} record
 * @returns {{valid: boolean, errors: Array<{path: string, message: string}>}}
 */
export function validateCrossRepoLink(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });

  if (!_isPlainObject(record)) {
    err('$', 'CrossRepoLink record must be an object');
    return { valid: false, errors };
  }

  if (!_isNonEmptyString(record.id) || !record.id.startsWith('crosslink:')) {
    err('$.id', 'id is required and must start with "crosslink:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!EDGE_PROVENANCE_VALUES.includes(record.provenance)) {
    err('$.provenance', `unrecognized provenance "${record.provenance}" — must be one of ${EDGE_PROVENANCE_VALUES.join('|')}`);
  }
  if (record.relationship !== CROSS_REPO_LINK_RELATIONSHIP) {
    err('$.relationship', `relationship must be "${CROSS_REPO_LINK_RELATIONSHIP}" (got "${record.relationship}")`);
  }

  _validateEndpoint(record.local, 'local', err);
  _validateEndpoint(record.remote, 'remote', err, ['repository', 'sourceFile']);

  if (!_isStringOrNull(record.rationale)) err('$.rationale', 'rationale must be a string or null');
  if (!_isNonEmptyString(record.declaredBy)) err('$.declaredBy', 'declaredBy is required');
  if (!_isNonEmptyString(record.declaredAt)) err('$.declaredAt', 'declaredAt is required');

  return { valid: errors.length === 0, errors };
}
