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
 * node:/edge:/flow: family. Discriminated by (framework, frameworkVersion,
 * requirementId, graphId, graphDigest) — graphId ALONE is not enough:
 * real callers never supply graphId's own configHash component (only
 * `graph-builder.js` reads it, via `opts.configHash ?? 'default'`, and
 * nothing calls it with one), so every real scan at one commit produces
 * the identical graphId regardless of the graph's actual CONTENT — found
 * by this sub-project's own final whole-branch review, reproduced live:
 * two records against genuinely different base graphs (same repo/commit,
 * different analyzer output) collided onto one id without graphDigest in
 * the material. graphDigest is the field §10.10 already requires every
 * extension record to carry precisely so it can be distinguished from a
 * same-graphId, different-content graph — this discriminator is what
 * makes that requirement actually load-bearing for uniqueness, not just
 * a payload field alongside an otherwise-collidable id.
 */
export function obligationId(
  { framework, frameworkVersion, requirementId, graphId, graphDigest },
  discriminatorParts = [],
) {
  return `obligation:${_hash(_canon([framework, frameworkVersion, requirementId, graphId, graphDigest, ...discriminatorParts]))}`;
}

/**
 * A DecisionStory record's id (M4 deliverable #7, FR-501 §14, DFG-035) —
 * NOT a DataFlowGraph v1 entity, mirrors obligationId's own precedent
 * exactly (a real, stable-ID'd extension record that is deliberately not
 * a base-graph entity). Discriminated by (graphDigest, audienceMode,
 * scopeQuery) rather than graphId alone, for the identical reason
 * obligationId's own comment gives: two stories over the same graphId but
 * genuinely different graph CONTENT (or a different filter/audience
 * scope) must not collide onto one id. `scopeQuery` is passed pre-
 * serialized by the caller (a plain object is not itself hashable
 * material) so this function stays a thin, generic hasher rather than
 * embedding export-briefing.js's own scopeQuery shape.
 */
export function storyId(
  { graphDigest, audienceMode, scopeQuery },
  discriminatorParts = [],
) {
  const scope = typeof scopeQuery === 'string' ? scopeQuery : JSON.stringify(scopeQuery ?? null);
  return `story:${_hash(_canon([graphDigest, audienceMode, scope, ...discriminatorParts]))}`;
}

/**
 * A GraphSnapshot record's id (M4 deliverable #8, FR-503 §14, DFG-022,
 * sub-project 8a) — NOT a DataFlowGraph v1 entity, mirrors obligationId's/
 * storyId's own precedent exactly (a real, stable-ID'd extension record
 * that is deliberately not a base-graph entity). Discriminated by
 * (graphId, commit, capturedAt) — `commit` is the REAL git HEAD resolved
 * by graph-snapshot.js's own persistence layer, never `graphId`'s own
 * embedded commit component (which is the literal string 'uncommitted' on
 * every real scan today — see graph-snapshot.js's own header comment).
 */
export function snapshotId(
  { graphId, commit, capturedAt },
  discriminatorParts = [],
) {
  return `snapshot:${_hash(_canon([graphId, commit, capturedAt, ...discriminatorParts]))}`;
}

/**
 * A GraphDiff record's id (M4 deliverable #9, FR-503 §14, DFG-022,
 * sub-project 8b) — NOT a DataFlowGraph v1 entity, mirrors snapshotId's
 * own precedent exactly (a real, stable-ID'd extension record that is
 * deliberately not a base-graph entity). Discriminated by
 * (beforeSnapshotId, afterSnapshotId) — unlike snapshotId, no separate
 * timestamp component is needed: each snapshot id is itself
 * content-derived (its own graphId/commit/capturedAt), so the pair alone
 * already makes a diff between two SPECIFIC snapshots deterministic, and
 * a diff is not itself a new capture event the way a snapshot is.
 */
export function diffId(
  { beforeSnapshotId, afterSnapshotId },
  discriminatorParts = [],
) {
  return `diff:${_hash(_canon([beforeSnapshotId, afterSnapshotId, ...discriminatorParts]))}`;
}
