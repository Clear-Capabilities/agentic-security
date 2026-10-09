// Deterministic identities for the assurance evidence contracts (CORE-002).
//
// Reuses, does not duplicate:
//   - canonicalJson (posture/evidence-bundle.js): sorted keys at every depth, so
//     two records that differ only in key order serialize to the same bytes.
//   - computeStableId (posture/stable-id.js): the refactor-stable finding id.
//     A hypothesis id is that same id; this module never invents a second way to
//     identify a finding.
//
// An identity is a hash over an ALLOWLIST of semantic fields, never over the
// whole record. That is what keeps clocks, nonces and migration bookkeeping out
// of an id: a field that is not named in the allowlist cannot reach the hash,
// however it is added later. The lineage package (scanner/src/lineage) has its
// own id namespace for graph entities; vulnerability evidence ids use distinct
// prefixes (vrec/obind/capd/rlab/rev) so the two can never be confused, and this
// module imports nothing from lineage.

import * as crypto from 'node:crypto';
import { canonicalJson } from '../evidence-bundle.js';
import { computeStableId } from '../stable-id.js';

export const ID_HEX_LEN = 16;

export const ID_PREFIXES = Object.freeze({
  verification: 'vrec',
  observationBinding: 'obind',
  capabilityDecision: 'capd',
  routingLabel: 'rlab',
  releaseEvidence: 'rev',
});

/** Canonical bytes of a value: key-order independent, no clock, no randomness. */
export function canonicalize(value) {
  return canonicalJson(value);
}

/** `sha256:<64 hex>` digest of the canonical form of a value. */
export function digestOf(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

export function digestOfBytes(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * Prefixed id over an allowlisted projection of a record.
 * `fields` is the allowlist; a missing field projects to null so an absent field
 * and an explicit null produce the same id (canonicalJson already treats them so).
 */
export function semanticId(prefix, record, fields) {
  const material = {};
  for (const f of fields) material[f] = record?.[f] === undefined ? null : record[f];
  const hex = crypto.createHash('sha256').update(canonicalJson({ kind: prefix, material })).digest('hex');
  return `${prefix}:${hex.slice(0, ID_HEX_LEN)}`;
}

/** The hypothesis id of a finding: its refactor-stable id, reused unchanged. */
export function hypothesisIdFromFinding(finding) {
  if (!finding || typeof finding !== 'object') return null;
  return finding.stableId || computeStableId(finding);
}
