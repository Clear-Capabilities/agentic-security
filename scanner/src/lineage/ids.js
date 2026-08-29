//
// Stable-ID spec for DataFlowGraph v1 (PRD 10.1: "Stable within the
// repository/commit; independent of visual layout"). Mirrors the shape
// scanner/src/posture/stable-id.js already established for findings:
// sha256 over a canonicalized, pipe-joined material string, truncated to
// a fixed hex length, prefixed by the entity kind. Same rationale — a
// content hash survives reordering and re-emission, unlike an
// incrementing counter.

import * as crypto from 'node:crypto';

const ID_HEX_LEN = 12;

function _hash(material, len = ID_HEX_LEN) {
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, len);
}

function _canon(parts) {
  return parts.map((p) => (p === undefined || p === null ? '' : String(p))).join('|');
}

/** PRD 10.2's literal example shape: `dfg:<repository>:<commit>:<configuration-hash>`. */
export function graphId({ repository, commit, configHash } = {}) {
  const repo = repository || 'unknown-repo';
  const c = commit || 'uncommitted';
  const cfg = configHash || 'default';
  return `dfg:${repo}:${c}:${cfg}`;
}

/** discriminatorParts should include enough of {system, location, destination} to be unique within the graph. */
export function nodeId(kind, discriminatorParts = []) {
  return `node:${kind}:${_hash(_canon([kind, ...discriminatorParts]))}`;
}

/** discriminatorParts should include the owning service/schema so the same field name in two services never collides (PRD 10.4). */
export function dataElementId(canonicalName, discriminatorParts = []) {
  return `data:${_hash(_canon([canonicalName, ...discriminatorParts]))}`;
}

export function edgeId(fromId, toId, relationship, discriminatorParts = []) {
  return `edge:${_hash(_canon([fromId, toId, relationship, ...discriminatorParts]))}`;
}

/**
 * dataElementIds is treated as a SET (sorted before hashing) — a flow
 * carrying {card_number, cvv} has one identity regardless of the order the
 * builder discovered them in. `discriminatorParts` is the escape hatch for
 * two flows sharing source/sink/fields that must still be distinct paths
 * (e.g. a masked branch vs. a raw branch to the same log sink).
 */
export function flowId(sourceNodeId, sinkNodeId, dataElementIds = [], discriminatorParts = []) {
  const sorted = [...dataElementIds].sort();
  return `flow:${_hash(_canon([sourceNodeId, sinkNodeId, ...sorted, ...discriminatorParts]))}`;
}

export function transformationId(anchorId, calleeName, discriminatorParts = []) {
  return `transform:${_hash(_canon([anchorId, calleeName, ...discriminatorParts]))}`;
}

export function evidenceId(claim, location, discriminatorParts = []) {
  return `evidence:${_hash(_canon([claim, location, ...discriminatorParts]))}`;
}
