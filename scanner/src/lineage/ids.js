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
 * A node in `path-store.js`'s provenance DAG (Sub-project C, increment 4;
 * DESIGN_PATH_PROVENANCE.md §14.2/§14.5). `pnode:`/`pedge:` are deliberately
 * distinct prefixes from `node:`/`edge:` above: a provenance node is NOT a
 * `DataFlowGraph v1` node, and `validate.js`'s id-prefix regexes must never
 * be able to confuse the two namespaces.
 *
 * Object-argument, not this file's usual positional-plus-discriminatorParts
 * form (a deliberate, narrow divergence — `graphId` is the in-file
 * precedent) — the discriminator is wide enough that a positional array is
 * exactly the shape a future field addition would silently omit from.
 */
export function provenanceNodeId(
  { kind, scope, context, path, siteNodeId, dataElementId },
  discriminatorParts = [],
) {
  return `pnode:${kind}:${_hash(_canon([kind, scope, context, path, siteNodeId, dataElementId, ...discriminatorParts]))}`;
}

/**
 * An edge in `path-store.js`'s provenance DAG: one (in-half, out-half) pair
 * at one join group (§14.5). The discriminator carries the SITE (`scope`,
 * `context`, `siteNodeId`) as well as both endpoint ids — two structurally
 * identical hops at two different program points are two materially
 * different edges (FR-305), each needing its own `line` for display and
 * §9.2's hop-ordering lever; omitting `siteNodeId` would silently collide
 * them into one edge carrying one arbitrary line. It also carries both
 * halves' `kind`/`subKind` and their reason strings — the
 * `flagship-fixture.mjs` lesson (see this package's own CLAUDE.md row)
 * applied deliberately: under-specifying a content-hash discriminator is a
 * silent merge. NOT in the discriminator: `syntacticPath` and `line`
 * (display material), edge `annotations[]`, and `ambiguousCorrelation`
 * (both are functions of the group and the endpoints already in the id).
 */
export function provenanceEdgeId(
  {
    fromNodeId, toNodeId, dataElementId,
    scope, context, siteNodeId,
    inKind, inSubKind, outKind, outSubKind,
    widenReasons = [], lossReasons = [],
  },
  discriminatorParts = [],
) {
  return `pedge:${_hash(_canon([
    fromNodeId, toNodeId, dataElementId,
    scope, context, siteNodeId,
    inKind, inSubKind, outKind, outSubKind,
    [...widenReasons].sort().join(','), [...lossReasons].sort().join(','),
    ...discriminatorParts,
  ]))}`;
}

/**
 * A reconstructed path (Sub-project C, increment 5;
 * DESIGN_PATH_PROVENANCE.md §15.6). `pnode:`/`pedge:`'s own header left this
 * name deliberately unclaimed (§14.5: "the thing C5 reconstructs *is* a
 * path, and it will plausibly want that name") — increment 5 claims it,
 * with a `ppath:` prefix joining the same family. A reconstructed path is
 * not a `DataFlowGraph v1` entity either, so `validate.js` needs no change.
 *
 * The discriminator is the EDGE id SEQUENCE, never the node id sequence
 * (§15.6/FR-305 — two paths can share a node sequence while differing in
 * the edges that join it, e.g. two assignments at two different program
 * points, and that difference must not be hidden by dedup) — order matters
 * for a path, unlike a node/edge discriminator's set-like fields, so
 * `edgeIds` is NOT sorted before hashing. `startNodeId` is strictly
 * redundant today (a path always has at least one hop, so the last edge id
 * already determines it) but is kept per §14.5's own lesson: over-specifying
 * a content hash costs nothing, under-specifying one is a silent merge.
 */
export function pathId({ startNodeId, edgeIds }, discriminatorParts = []) {
  return `ppath:${_hash(_canon([startNodeId, ...edgeIds, ...discriminatorParts]))}`;
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

/**
 * An ObligationMapping record's id (FR-504 §7.12, sub-project 6a) — NOT a
 * DataFlowGraph v1 entity, so validate.js's id-prefix regexes and
 * json-schema-parity.test.js's $defs audit need zero change, mirroring
 * why provenanceNodeId/provenanceEdgeId are prefixed outside the
 * node:/edge:/flow: family. Discriminated by
 * (framework, frameworkVersion, requirementId, graphId) — the same
 * (framework, requirement) pair evaluated against two different base
 * graphs, or two different snapshots of the same repository, must never
 * collide into one id.
 */
export function obligationId(
  { framework, frameworkVersion, requirementId, graphId },
  discriminatorParts = [],
) {
  return `obligation:${_hash(_canon([framework, frameworkVersion, requirementId, graphId, ...discriminatorParts]))}`;
}
