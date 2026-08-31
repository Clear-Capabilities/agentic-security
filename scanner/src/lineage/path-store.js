//
// path-store.js — the compact provenance DAG (Sub-project C, increment 4).
//
// Binding spec: DESIGN_PATH_PROVENANCE.md §14 (§14.1-§14.11). This module
// is a PURE CONSUMER of a hop-record stream — the 14-field shape §3/§13.0
// define, exactly as C1-C3 ship it. It does not run analysis, and it must
// NEVER import `engine.js`, `summaries.js`, or `driver.js` (§14.1): its
// only dependency is `ids.js`. This is a stronger, additional isolation
// boundary on top of the pre-existing "`src/lineage/` may import pure
// utilities from `src/dataflow/`, never that package's `engine.js`/
// `summaries.js`" rule, and it is what makes the store testable against a
// hand-built hop array with zero dependency on a real analysis run — a
// real project-wide driver run still emits ZERO hops today (no source
// registry, Sub-project D/E).
//
// Construction is cycle-safe BY CONSTRUCTION, not by discipline (§9.3,
// §14.6): one linear pass over the offered hops plus a per-group cross
// product, never a graph walk. There is no recursion anywhere in this
// file. The read API is deliberately traversal-free — every method below
// is an O(1)/O(degree) index lookup. Bounded backward reconstruction is
// C5's job and C5's alone.
//

import { provenanceNodeId, provenanceEdgeId } from './ids.js';

// §3 + §13.0's exact 14-field hop shape, in a FIXED order. Never derive a
// dedupe/discriminator key via `Object.keys(h)` — that is order-dependent,
// and would let two differently-key-ordered-but-identical hop objects hash
// to different keys. Listed explicitly so a hop with an ABSENT key (§3
// warns this is reachable for any emission path that bypasses
// `analyzeFunctionFieldIdentity`'s progressive stamping) is DETECTED here
// (`diagnostics().malformed`) instead of silently hashing to a different
// dedupe key than its fully-stamped twin — this is where §3's completeness
// guarantee becomes checkable rather than merely asserted (§14.6).
export const HOP_FIELDS = [
  'kind', 'subKind', 'scope', 'dataElementId', 'fromPath', 'toPath',
  'syntacticPath', 'nodeId', 'line', 'widenReason', 'lossReason',
  'context', 'peerScope', 'peerContext',
];

const IN_KINDS = new Set(['production', 'selection']);

function hopDedupeKey(h) {
  return HOP_FIELDS.map((f) => JSON.stringify(h[f] ?? null)).join('|');
}

function joinKeyOf(h) {
  // §13.3's four-part join key, superseding §2.2's original three-part form.
  return [h.scope, h.nodeId, h.dataElementId, h.context]
    .map((p) => JSON.stringify(p ?? null)).join('|');
}

function scopeKeyOf(scope, context) {
  return `${JSON.stringify(scope ?? null)}|${JSON.stringify(context ?? null)}`;
}

/**
 * §14.3: which node does an inbound half (`production`/`selection`) start
 * at?
 *
 * Rules, in order:
 *   1. `fromPath !== null` -> sourced, at `(scope, context, path, id)`.
 *   2. `fromPath === null && peerScope !== null && lossReason === null` ->
 *      peer-sourced, at `(peerScope, peerContext, <return>, id)`. See §14.4
 *      — this is the single most load-bearing rule in the whole module.
 *   3. otherwise -> annotation.
 */
export function classifyIn(h) {
  if (h.fromPath !== null && h.fromPath !== undefined) {
    return {
      role: 'source',
      crossScope: false,
      node: {
        kind: 'path', scope: h.scope, context: h.context,
        path: h.fromPath, siteNodeId: null, dataElementId: h.dataElementId,
      },
    };
  }
  // §14.4, THE CORRECTION TO §2.2: a null `fromPath` with a non-null
  // `peerScope` is NOT source-less. It is PEER-ADDRESSED — its source is
  // the callee's own function-exit node. `lossReason === null` is the
  // discriminator that keeps a §13.6 context-cap-degraded hop out of this
  // branch: that hop names a callee whose body was never analyzed, so an
  // edge from its (non-existent) exit node would be a fabricated origin —
  // it falls through to annotation instead, exactly what §13.6 asked for.
  if (h.peerScope !== null && h.peerScope !== undefined && h.lossReason == null) {
    return {
      role: 'source',
      crossScope: true,
      node: {
        kind: 'return', scope: h.peerScope, context: h.peerContext,
        path: null, siteNodeId: null, dataElementId: h.dataElementId,
      },
    };
  }
  return { role: 'annotation', crossScope: false, node: null };
}

/**
 * §14.3: which node does an outbound half (`write-out`) land at?
 *
 * Rules, in order:
 *   1. `toPath !== null && peerScope !== null` -> peer-targeted, at
 *      `(peerScope, peerContext, toPath, id)` — Q1's answer.
 *   2. `toPath !== null` -> targeted, at `(scope, context, toPath, id)`.
 *   3. `subKind === 'return'` -> the `return` terminal (per function-context).
 *   4. `subKind === 'call-arg'` -> the `escape` terminal (per CFG node).
 *   5. `lossReason !== null` -> the `loss` terminal (per CFG node).
 *   6. otherwise -> unclassified, recorded and never silently dropped.
 */
export function classifyOut(h) {
  if (h.toPath !== null && h.toPath !== undefined) {
    const cross = h.peerScope !== null && h.peerScope !== undefined;
    return {
      role: 'target',
      crossScope: cross,
      node: {
        kind: 'path',
        scope: cross ? h.peerScope : h.scope,
        context: cross ? h.peerContext : h.context,
        path: h.toPath, siteNodeId: null, dataElementId: h.dataElementId,
      },
    };
  }
  // Terminal out-halves. `return` is per-(scope, context) — it must be,
  // because a `call-resolved` hop addresses it with only
  // (peerScope, peerContext) and no node id, so every return site of a
  // context must aggregate into one exit node. `escape`/`loss` are
  // per-CFG-node, since nothing addresses them from elsewhere and the
  // extra precision tells a reader WHICH call/assignment ended the path.
  if (h.subKind === 'return') {
    return {
      role: 'target', crossScope: false,
      node: { kind: 'return', scope: h.scope, context: h.context, path: null, siteNodeId: null, dataElementId: h.dataElementId },
    };
  }
  if (h.subKind === 'call-arg') {
    return {
      role: 'target', crossScope: false,
      node: { kind: 'escape', scope: h.scope, context: h.context, path: null, siteNodeId: h.nodeId, dataElementId: h.dataElementId },
    };
  }
  if (h.lossReason != null) {
    return {
      role: 'target', crossScope: false,
      node: { kind: 'loss', scope: h.scope, context: h.context, path: null, siteNodeId: h.nodeId, dataElementId: h.dataElementId },
    };
  }
  return { role: 'unclassified', crossScope: false, node: null };
}

export class PathStore {
  constructor() {
    this._groups = new Map();
    this._seen = new Set();
    this._truncations = new Map();
    this._malformed = [];
    this._unclassified = [];
    // Every peer-sourced in-half accepted so far (crossScope === true from
    // classifyIn), tracked so diagnostics() can report §14.4's disclosed
    // stream-completeness gap (`orphanedPeerSources`) at build-finalize
    // time without a second pass over the raw hops.
    this._peerSourced = [];
    this._stats = { hopsOffered: 0, hopsAccepted: 0 };
    this._built = null;
  }

  /**
   * Accepts one hop record. Returns `true` if it was newly accepted
   * (added to a group), `false` if it was an exact repeat of an
   * already-accepted hop (Decision 8's worklist re-emission, collapsed
   * here — §14.6 dedup boundary 1). A malformed hop (missing a required
   * field) is still recorded in `diagnostics().malformed`, never thrown.
   */
  addHop(hop) {
    this._stats.hopsOffered += 1;
    const missing = HOP_FIELDS.filter((f) => !Object.prototype.hasOwnProperty.call(hop, f));
    if (missing.length > 0) {
      this._malformed.push({ hop, missing });
    }
    const k = hopDedupeKey(hop);
    if (this._seen.has(k)) return false;
    this._seen.add(k);
    this._stats.hopsAccepted += 1;

    const jk = joinKeyOf(hop);
    let g = this._groups.get(jk);
    if (!g) {
      g = {
        scope: hop.scope, nodeId: hop.nodeId, dataElementId: hop.dataElementId,
        context: hop.context, line: hop.line ?? null,
        in: [], out: [], annotations: [],
      };
      this._groups.set(jk, g);
    }
    if (IN_KINDS.has(hop.kind)) {
      const c = classifyIn(hop);
      if (c.role === 'source') {
        g.in.push({ hop, ...c });
        if (c.crossScope) this._peerSourced.push({ hop, node: c.node });
      } else {
        g.annotations.push(hop);
      }
    } else if (hop.kind === 'write-out') {
      const c = classifyOut(hop);
      if (c.role === 'target') g.out.push({ hop, ...c });
      else this._unclassified.push(hop);
    } else {
      this._unclassified.push(hop);
    }
    this._built = null;
    return true;
  }

  /** Bulk `addHop`. Returns the count newly accepted. */
  addHops(hops) {
    let n = 0;
    for (const h of hops) if (this.addHop(h)) n += 1;
    return n;
  }

  /**
   * §9.5's reserved out-of-band channel. Analysis-level (not per-hop)
   * truncation — an `ITER_BUDGET` break in `analyzeFunctionFieldIdentity`
   * — has no hop representation and deliberately must not get one (§2.2's
   * three-kind taxonomy is closed, per §14.8). Marks every node and edge
   * in `(scope, context)` as `truncated: true`.
   */
  markTruncated(scope, context, reason) {
    this._truncations.set(scopeKeyOf(scope, context), reason);
    this._built = null;
  }

  _build() {
    if (this._built) return this._built;
    const nodes = new Map();
    const edges = new Map();
    const outIndex = new Map();
    const inIndex = new Map();

    const intern = (desc) => {
      const id = provenanceNodeId(desc);
      let n = nodes.get(id);
      if (!n) {
        n = {
          id, ...desc,
          truncated: this._truncations.has(scopeKeyOf(desc.scope, desc.context)),
        };
        nodes.set(id, n);
      }
      return n;
    };

    for (const g of this._groups.values()) {
      let sources = g.in;
      let originated = false;
      if (sources.length === 0 && g.annotations.length > 0) {
        // §2.2's annotation rule, in the ONE direction it is still right:
        // with no non-null in-half anywhere at this key, the annotation is
        // itself the origin of the value ("no prior aliasing source").
        originated = true;
        sources = [{
          hop: g.annotations[0], role: 'source', crossScope: false,
          node: { kind: 'origin', scope: g.scope, context: g.context, path: null, siteNodeId: g.nodeId, dataElementId: g.dataElementId },
        }];
      }
      // §9.1's correlation ambiguity, extended to the call boundary by
      // §13.2's own disclosure — measured PER PAIRING, not per group
      // (§14.7's correction to §9.1's original group-level measure, which
      // over-marks: it fires on every edge at a resolved call site,
      // including the two that are exactly right, because the argument's
      // in-half and the return's in-half share one join key). Counting
      // only the pairings the store would ACTUALLY form (after the peer x
      // peer exclusion) recovers the distinction at zero cost.
      const pairable = (s, o) => !(s.crossScope && o.crossScope);
      const sourcesFor = (o) => new Set(sources.filter((s) => pairable(s, o)).map((s) => provenanceNodeId(s.node)));
      const targetsFor = (s) => new Set(g.out.filter((o) => pairable(s, o)).map((o) => provenanceNodeId(o.node)));

      const annotations = g.annotations.map((a) => ({
        kind: a.kind, subKind: a.subKind,
        widenReason: a.widenReason ?? null, lossReason: a.lossReason ?? null,
        peerScope: a.peerScope ?? null, peerContext: a.peerContext ?? null,
      }));

      for (const s of sources) {
        for (const o of g.out) {
          // §14.3: an edge with BOTH endpoints in the peer's namespace is
          // never a caller-side fact — it is a transition entirely inside
          // the callee, which the callee's own hops already record, and
          // materializing it manufactures a callee-return -> callee-param
          // cycle that no program ever executed.
          if (!pairable(s, o)) continue;
          const from = intern(s.node);
          const to = intern(o.node);
          const widenReasons = [...new Set([s.hop.widenReason, o.hop.widenReason].filter((r) => r != null))].sort();
          const lossReasons = [...new Set([s.hop.lossReason, o.hop.lossReason].filter((r) => r != null))].sort();
          const desc = {
            fromNodeId: from.id, toNodeId: to.id, dataElementId: g.dataElementId,
            scope: g.scope, context: g.context, siteNodeId: g.nodeId,
            inKind: s.hop.kind, inSubKind: s.hop.subKind,
            outKind: o.hop.kind, outSubKind: o.hop.subKind,
            widenReasons, lossReasons,
          };
          const id = provenanceEdgeId(desc);
          if (!edges.has(id)) {
            edges.set(id, {
              id, ...desc, line: g.line,
              crossScope: s.crossScope || o.crossScope,
              originated,
              ambiguousCorrelation: sourcesFor(o).size >= 2 && targetsFor(s).size >= 2,
              annotations,
              truncated: this._truncations.has(scopeKeyOf(g.scope, g.context)),
            });
            if (!outIndex.has(from.id)) outIndex.set(from.id, new Set());
            if (!inIndex.has(to.id)) inIndex.set(to.id, new Set());
            outIndex.get(from.id).add(id);
            inIndex.get(to.id).add(id);
          }
        }
      }
    }

    // §14.4's disclosed stream-completeness gap / §14.10 item 10: a
    // peer-sourced hop (lossReason: null, non-null peerScope) whose named
    // (peerScope, peerContext, <return>, dataElementId) node has ZERO real
    // in-edges once the whole stream has been ingested — reachable via a
    // cache warmed by a no-recorder run and reused by a later
    // recorder-attached run (driver.js's own returned cache). Detected here
    // via the store's own inIndex at build-finalize time. Recorded, never
    // fabricated into an origin, never dropped.
    const orphanedPeerSources = [];
    for (const { hop, node } of this._peerSourced) {
      const id = provenanceNodeId(node);
      const inEdges = inIndex.get(id);
      if (!inEdges || inEdges.size === 0) {
        orphanedPeerSources.push({ hop, nodeId: id });
      }
    }

    this._built = { nodes, edges, outIndex, inIndex, orphanedPeerSources };
    return this._built;
  }

  // ---- minimal read API (§14.6/§14.9). C4 ships NO traversal: every
  // method below is an O(1)/O(degree) index lookup, so no code in this
  // increment can recurse into a cycle. Bounded backward reconstruction is
  // C5's job and C5's alone.
  nodes() { return [...this._build().nodes.values()]; }
  edges() { return [...this._build().edges.values()]; }
  getNode(id) { return this._build().nodes.get(id) ?? null; }
  getEdge(id) { return this._build().edges.get(id) ?? null; }
  nodeIdFor(desc) { return provenanceNodeId(desc); }
  edgesFrom(nodeId) { return [...(this._build().outIndex.get(nodeId) ?? [])].map((e) => this._build().edges.get(e)); }
  edgesTo(nodeId) { return [...(this._build().inIndex.get(nodeId) ?? [])].map((e) => this._build().edges.get(e)); }
  hasEdge(fromId, toId) { return this.edgesFrom(fromId).some((e) => e.toNodeId === toId); }
  stats() { return { ...this._stats, groups: this._groups.size, nodes: this._build().nodes.size, edges: this._build().edges.size }; }

  /**
   * Four buckets, all "recorded, never thrown, never silently dropped"
   * (§14.9/§14.10 item 10):
   *   - `malformed`: hops missing a required field.
   *   - `unclassified`: out-halves matching none of §14.3's rules.
   *   - `truncations`: `(scope, context)` pairs marked via `markTruncated`.
   *   - `orphanedPeerSources`: §14.4's disclosed stream-completeness gap.
   */
  diagnostics() {
    return {
      malformed: this._malformed,
      unclassified: this._unclassified,
      truncations: [...this._truncations.entries()],
      orphanedPeerSources: this._build().orphanedPeerSources,
    };
  }
}
