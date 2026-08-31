// Sub-project C, increment C4 — DESIGN-TASK proof-of-concept for
// `path-store.js` (the compact provenance DAG) and `ids.js`'s two new
// stable-ID functions.
//
// THIS FILE IS DELIBERATELY THROWAWAY-NAMED, exactly like increment C3's
// own `engine-provenance-interprocedural-poc.test.js` was (since deleted).
// Every behavioural claim in `DESIGN_PATH_PROVENANCE.md` §14 was produced
// by running this file. The prototypes below (`provenanceNodeId`,
// `provenanceEdgeId`, `PathStore`) are LOCAL — shipped source is unmodified
// by this design task, so the design can be reviewed before any of it is
// wired in. §14.10 is the follow-up implementation task's checklist for
// extracting them into `scanner/src/lineage/ids.js` and
// `scanner/src/lineage/path-store.js` and re-pointing this file at them.
//
// The three prototype symbols are `export`ed purely so §14.11's measured
// numbers could be reproduced from a throwaway script against the exact
// same code the assertions below run against, rather than a hand-copied
// second version of it. The follow-up task drops the exports along with
// the prototypes themselves.
//
// The two questions this file exists to ANSWER (both were open when the
// task was scoped, and neither is answerable on paper — see §14.3/§14.4):
//
//   Q1  Cross-function node addressing: is a `write-out/call-arg-bind`
//       hop's DESTINATION node `(peerScope, peerContext, toPath, id)`,
//       rather than `(scope, context, toPath, id)`?
//   Q2  Does the `call-resolved` hop's `fromPath: null` ever form a real
//       edge — i.e. what actually connects a callee's return value to the
//       caller's variable — or is the hop stream insufficient?
//
// ANSWERS, both proven below by running the real engine over real parsed
// JS/TS: Q1 yes (test "Q1"); Q2 yes, it forms a real CROSS-SCOPE edge from
// the callee's own function-exit node — but ONLY once §2.2's annotation
// rule is corrected, because as literally written it demotes exactly this
// hop to an annotation and silently drops the stitch (test "Q2b").
//
// Note on hand-seeding: `runFieldIdentityAnalysis` (driver.js) analyzes
// every function from `emptyState()` and there is still no source registry
// (Sub-project D/E), so a real project-wide driver run emits ZERO hops
// today. Every fixture here therefore seeds an entry state by hand and
// drives `analyzeFunctionFieldIdentity` / the real
// `FieldIdentitySummaryCache` + `createCallSummaryResolver` machinery
// directly — the identical technique
// `engine-provenance-interprocedural.test.js` already uses.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';
import {
  FieldIdentitySummaryCache,
  createCallSummaryResolver,
} from '../../src/lineage/summaries.js';

// =====================================================================
// PROTOTYPE 1 — `ids.js`'s two new functions (§14.5).
//
// Copied convention, byte-for-byte, from `src/lineage/ids.js`: sha256 over
// a canonicalized, pipe-joined material string, truncated to ID_HEX_LEN,
// prefixed by the entity kind. Never a counter.
// =====================================================================

const ID_HEX_LEN = 12;

function _hash(material, len = ID_HEX_LEN) {
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, len);
}

function _canon(parts) {
  return parts.map((p) => (p === undefined || p === null ? '' : String(p))).join('|');
}

/**
 * A node in the provenance DAG. See §14.2 for why `context` is part of the
 * identity and why terminal nodes live in their own `kind` namespace
 * rather than behind a fabricated path token like '@return' (Decision 5's
 * bug class).
 *
 * Object-argument rather than ids.js's usual positional-plus-
 * discriminatorParts form, deliberately — see §14.5's note on the
 * flagship-fixture collision precedent.
 */
export function provenanceNodeId(
  { kind, scope, context, path, siteNodeId, dataElementId },
  discriminatorParts = [],
) {
  return `pnode:${kind}:${_hash(_canon([kind, scope, context, path, siteNodeId, dataElementId, ...discriminatorParts]))}`;
}

/**
 * An edge in the provenance DAG: one (in-half, out-half) pair at one join
 * group. The discriminator carries the SITE (`scope`/`context`/
 * `siteNodeId`) as well as the endpoints, because two structurally
 * identical hops at two different program points are two materially
 * different edges (FR-305) that must keep their own `line` for display and
 * for §9.2's hop-ordering lever.
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

// =====================================================================
// PROTOTYPE 2 — `path-store.js`.
//
// PURE CONSUMER: this block imports nothing from engine.js/summaries.js/
// driver.js and knows nothing about how a hop was produced. That is the
// isolation boundary §14.1 introduces on top of the pre-existing
// lineage/dataflow one, and it is what makes the store testable against a
// hand-built hop array with zero dependency on a real analysis run.
// =====================================================================

// §3 + §13.0's exact 14-field shape. Listed explicitly rather than derived
// from `Object.keys(h)` so a hop with an ABSENT key (§3 warns this is
// reachable for any emission path that bypasses
// `analyzeFunctionFieldIdentity`'s progressive stamping) is DETECTED here
// instead of silently hashing to a different dedupe key than its
// fully-stamped twin.
const HOP_FIELDS = [
  'kind', 'subKind', 'scope', 'dataElementId', 'fromPath', 'toPath',
  'syntacticPath', 'nodeId', 'line', 'widenReason', 'lossReason',
  'context', 'peerScope', 'peerContext',
];

const IN_KINDS = new Set(['production', 'selection']);

function hopDedupeKey(h) {
  return HOP_FIELDS.map((f) => JSON.stringify(h[f] ?? null)).join('|');
}

function joinKeyOf(h) {
  // §13.3's four-part join key, superseding §2.2's three-part form.
  return [h.scope, h.nodeId, h.dataElementId, h.context]
    .map((p) => JSON.stringify(p ?? null)).join('|');
}

function scopeKeyOf(scope, context) {
  return `${JSON.stringify(scope ?? null)}|${JSON.stringify(context ?? null)}`;
}

/** §14.3: which node does an inbound half start at? */
function classifyIn(h) {
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
  // edge from its (non-existent) exit node would be a fabricated origin.
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

/** §14.3: which node does an outbound half land at? */
function classifyOut(h) {
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
  // (peerScope, peerContext) and no node id. `escape`/`loss` are
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
    this._stats = { hopsOffered: 0, hopsAccepted: 0 };
    this._built = null;
  }

  addHop(hop) {
    this._stats.hopsOffered += 1;
    const missing = HOP_FIELDS.filter((f) => !Object.prototype.hasOwnProperty.call(hop, f));
    if (missing.length > 0) {
      // §3's completeness guarantee, made checkable at the consumer rather
      // than merely asserted at the producer. Recorded, never thrown — a
      // store that dies on one malformed record would lose the whole run.
      this._malformed.push({ hop, missing });
    }
    const k = hopDedupeKey(hop);
    if (this._seen.has(k)) return false;   // Decision 8's worklist re-emission
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
      if (c.role === 'source') g.in.push({ hop, ...c });
      else g.annotations.push(hop);
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

  addHops(hops) { let n = 0; for (const h of hops) if (this.addHop(h)) n += 1; return n; }

  /**
   * §9.5's reserved channel. Analysis-level (not per-hop) truncation — an
   * `ITER_BUDGET` break in `analyzeFunctionFieldIdentity` — has no hop
   * representation and deliberately must not get one (§2.2's three-kind
   * taxonomy is closed). It arrives out of band, and every node and edge
   * in that (scope, context) is then marked `truncated: true`.
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
      // §13.2's own disclosure — but measured PER PAIRING, not per group
      // (§14.7). §9.1's original group-level test
      // (`distinctInPaths >= 2 && distinctOutPaths >= 2`) marks every edge
      // at a resolved call site, including the two that are exactly right,
      // because the argument's in-half and the return's in-half share one
      // join key. Counting only the pairings the store would ACTUALLY form
      // (i.e. after the peer x peer exclusion) recovers the distinction at
      // zero cost and with no new hop field.
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
          // materializing it manufactures a callee return -> callee param
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
    this._built = { nodes, edges, outIndex, inIndex };
    return this._built;
  }

  // ---- minimal read API. C4 ships NO traversal (§14.6): every method
  // below is an O(1)/O(degree) index lookup, so no code in this increment
  // can recurse into a cycle. Bounded backward reconstruction is C5's.
  nodes() { return [...this._build().nodes.values()]; }
  edges() { return [...this._build().edges.values()]; }
  getNode(id) { return this._build().nodes.get(id) ?? null; }
  getEdge(id) { return this._build().edges.get(id) ?? null; }
  nodeIdFor(desc) { return provenanceNodeId(desc); }
  edgesFrom(nodeId) { return [...(this._build().outIndex.get(nodeId) ?? [])].map((e) => this._build().edges.get(e)); }
  edgesTo(nodeId) { return [...(this._build().inIndex.get(nodeId) ?? [])].map((e) => this._build().edges.get(e)); }
  hasEdge(fromId, toId) { return this.edgesFrom(fromId).some((e) => e.toNodeId === toId); }
  stats() { return { ...this._stats, groups: this._groups.size, nodes: this._build().nodes.size, edges: this._build().edges.size }; }
  diagnostics() {
    return {
      malformed: this._malformed,
      unclassified: this._unclassified,
      truncations: [...this._truncations.entries()],
    };
  }
}

// =====================================================================
// Shared harness (the hand-seeding technique from
// engine-provenance-interprocedural.test.js).
// =====================================================================

function parseFns(src, file) {
  const ir = parseJsFile(file, src);
  assert.ok(ir, 'real parser must parse this fixture source');
  const byName = {};
  for (const fn of ir.functions) byName[fn.name] = fn;
  return byName;
}

function lookupCalleeFor(byName) {
  return (calleeExpr) => {
    if (!calleeExpr || calleeExpr.kind !== 'ident') return null;
    const fn = byName[calleeExpr.name];
    return fn ? { qid: fn.qid, fn } : null;
  };
}

/** Runs one function with a recorder and returns {raw, store, result}. */
function record(fn, entryState, { byName, cache } = {}) {
  const raw = [];
  const ctx = { recordHop: (h) => raw.push(h) };
  if (byName) {
    ctx.resolveCallSummary = createCallSummaryResolver(cache ?? new FieldIdentitySummaryCache(), lookupCalleeFor(byName));
  }
  const result = analyzeFunctionFieldIdentity(fn, entryState, ctx);
  const store = new PathStore();
  store.addHops(raw);
  return { raw, store, result };
}

const pathNode = (scope, context, path, dataElementId) => ({
  kind: 'path', scope, context, path, siteNodeId: null, dataElementId,
});
const returnNode = (scope, context, dataElementId) => ({
  kind: 'return', scope, context, path: null, siteNodeId: null, dataElementId,
});

// =====================================================================
// 1. The simple intraprocedural chain (plan Step 2, item 1).
// =====================================================================

test('C4/1: `const b = a.email; return b;` builds exactly 3 nodes and 2 edges — no more, no fewer', () => {
  const byName = parseFns('function f(a) { const b = a.email; return b; }', '/x/c4-chain.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);

  const ctx = raw[0].context;
  const scope = byName.f.qid;
  assert.ok(typeof ctx === 'string' && ctx.length > 0);

  const nAEmail = store.nodeIdFor(pathNode(scope, ctx, 'a.email', 'data:email'));
  const nB = store.nodeIdFor(pathNode(scope, ctx, 'b', 'data:email'));
  const nExit = store.nodeIdFor(returnNode(scope, ctx, 'data:email'));

  assert.deepEqual(
    store.nodes().map((n) => n.id).sort(),
    [nAEmail, nB, nExit].sort(),
    `expected exactly the 3 nodes a.email / b / <exit>; got ${JSON.stringify(store.nodes().map((n) => `${n.kind}:${n.path}`))}`,
  );
  assert.equal(store.edges().length, 2, 'exactly two edges: a.email -> b, b -> <exit>');
  assert.ok(store.hasEdge(nAEmail, nB), 'a.email -> b');
  assert.ok(store.hasEdge(nB, nExit), 'b -> <exit>');
  assert.equal(store.edgesTo(nAEmail).length, 0, 'a.email is the origin of this path — nothing flows into it');
  assert.equal(store.edgesFrom(nExit).length, 0, 'the exit node is terminal');

  // Every edge is field-precise and carries its site for FR-305/§9.2.
  for (const e of store.edges()) {
    assert.equal(e.dataElementId, 'data:email');
    assert.equal(e.scope, scope);
    assert.equal(e.context, ctx);
    assert.equal(typeof e.siteNodeId, 'string');
    assert.equal(typeof e.line, 'number');
    assert.equal(e.ambiguousCorrelation, false);
    assert.equal(e.crossScope, false);
  }
  assert.deepEqual(store.diagnostics().unclassified, [], 'every hop shape in this fixture is classified');
  assert.deepEqual(store.diagnostics().malformed, [], 'every hop carries all 14 fields');
});

test('C4/1b: two identities through one construct stay field-distinct end to end (FR-301 carried into FR-303\'s structure)', () => {
  const src = `
    function f(user) {
      const u = user;
      const o = { email: u.email, ssn: u.ssn };
      return o;
    }
  `;
  const byName = parseFns(src, '/x/c4-six.js');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const { store, raw } = record(byName.f, entryState);
  const ctx = raw[0].context;
  const scope = byName.f.qid;

  // §6's own worked example: two ordered paths that never touch.
  for (const [field, id] of [['email', 'data:email'], ['ssn', 'data:ssn']]) {
    const chain = [
      pathNode(scope, ctx, `user.${field}`, id),
      pathNode(scope, ctx, `u.${field}`, id),
      pathNode(scope, ctx, `o.${field}`, id),
      returnNode(scope, ctx, id),
    ].map((d) => store.nodeIdFor(d));
    for (let i = 0; i < chain.length - 1; i++) {
      assert.ok(store.hasEdge(chain[i], chain[i + 1]), `${id}: hop ${i} -> ${i + 1} missing`);
    }
  }
  // The two elements never share a node.
  const byId = new Map();
  for (const n of store.nodes()) {
    assert.ok(!byId.has(n.id) || byId.get(n.id) === n.dataElementId);
    byId.set(n.id, n.dataElementId);
  }
  // The object literal is an EDGE annotation, never a node (§2.1).
  assert.ok(store.nodes().every((n) => n.kind !== 'origin'), 'the object literal produced no node of its own');
  const objAnnotated = store.edges().filter((e) => e.annotations.some((a) => a.subKind === 'object'));
  assert.ok(objAnnotated.length > 0, 'the production/object hop survives as an edge annotation');
});

test('C4/1c: worklist re-emission (Decision 8) is collapsed at ingest — a loop fixture offers far more hops than it accepts, and the DAG is identical either way', () => {
  const src = `
    function f(user) {
      let a = user.email;
      let b = 0;
      while (b) { const t = a; a = t; }
      return a;
    }
  `;
  const byName = parseFns(src, '/x/c4-loop.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);

  const s = store.stats();
  assert.ok(s.hopsOffered > s.hopsAccepted, `the worklist must re-emit on this loop fixture (offered ${s.hopsOffered}, accepted ${s.hopsAccepted})`);

  // Feeding the SAME stream twice must not change anything — the store is
  // idempotent under duplicate delivery, which is the property Decision 8
  // pushes onto the consumer.
  const before = { nodes: store.nodes().length, edges: store.edges().length };
  store.addHops(raw);
  store.addHops(raw);
  assert.deepEqual({ nodes: store.nodes().length, edges: store.edges().length }, before);
});

test('C4/1d: the two dedup boundaries are NOT equivalent — raw-hop dedup alone leaves duplicate edges that only node/edge-id dedup collapses', () => {
  // Two DIFFERENT hop records (different `syntacticPath`) describing the
  // SAME logical edge. Raw-hop content dedup keeps both; the edge-id map
  // collapses them, because `syntacticPath` is display material and is
  // deliberately not part of the edge discriminator.
  const base = {
    scope: 'S', nodeId: 'n1', context: 'C', dataElementId: 'data:e', line: 1,
    peerScope: null, peerContext: null, widenReason: null, lossReason: null,
  };
  const store = new PathStore();
  assert.equal(store.addHop({ ...base, kind: 'production', subKind: 'ident', fromPath: 'a.email', toPath: null, syntacticPath: 'a' }), true);
  assert.equal(store.addHop({ ...base, kind: 'production', subKind: 'ident', fromPath: 'a.email', toPath: null, syntacticPath: null }), true);
  store.addHop({ ...base, kind: 'write-out', subKind: 'assign', fromPath: null, toPath: 'b', syntacticPath: null });

  assert.equal(store.stats().hopsAccepted, 3, 'raw-hop dedup keeps both in-halves: they are not byte-identical');
  assert.equal(store.edges().length, 1, 'edge-id dedup collapses them into ONE edge — this is the correctness-bearing dedup');
});

// =====================================================================
// 2. Q1 — cross-function node addressing (plan Step 2, item 2).
// =====================================================================

test('C4/Q1: a call-arg-bind hop\'s DESTINATION node is (peerScope, peerContext, toPath, id) — proven by it being byte-identical to the node the CALLEE\'s own hops independently create', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-q1.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.caller, entryState, { byName });

  const bind = raw.find((h) => h.subKind === 'call-arg-bind');
  assert.ok(bind, 'the shipped resolver emits the binding hop');
  assert.equal(bind.scope, byName.caller.qid, 'stamped with the CALLER\'s scope (§13.2)');
  assert.equal(bind.peerScope, byName.helper.qid);
  assert.equal(bind.toPath, 'u.email');

  // The callee's OWN in-half for the same location, recorded independently
  // inside helper's own analysis run.
  const calleeRead = raw.find((h) => h.scope === byName.helper.qid && h.fromPath === 'u.email');
  assert.ok(calleeRead, 'helper\'s own selection/member from u.email is in the stream');

  const peerAddressed = store.nodeIdFor(pathNode(bind.peerScope, bind.peerContext, bind.toPath, bind.dataElementId));
  const calleeOwn = store.nodeIdFor(pathNode(calleeRead.scope, calleeRead.context, calleeRead.fromPath, calleeRead.dataElementId));
  assert.equal(peerAddressed, calleeOwn, 'ANSWER TO Q1: peer addressing lands on exactly the node the callee itself created');

  // And the naive alternative (the hop's own stamped scope/context) does not.
  const naive = store.nodeIdFor(pathNode(bind.scope, bind.context, bind.toPath, bind.dataElementId));
  assert.notEqual(naive, calleeOwn, 'naive (own-scope) addressing would create a DIFFERENT node');
  assert.equal(store.getNode(naive), null, 'and that node exists nowhere in the built store — it would be an orphan no hop can reach');

  // The store, built with peer addressing, really connects them.
  assert.ok(store.hasEdge(
    store.nodeIdFor(pathNode(bind.scope, bind.context, 'a.email', 'data:email')),
    calleeOwn,
  ), 'a.email (caller) -> u.email (callee) is a real cross-scope edge');
  const crossEdge = store.edgesTo(calleeOwn).find((e) => e.outSubKind === 'call-arg-bind');
  assert.ok(crossEdge.crossScope, 'and it is marked cross-scope');
});

test('C4/Q1b: naive own-scope addressing COLLIDES with a caller-local variable of the same name — Decision 5\'s bug class, avoided only by peerScope', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const u = a.email; const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-q1b.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.caller, entryState, { byName });

  const bind = raw.find((h) => h.subKind === 'call-arg-bind');
  assert.equal(bind.toPath, 'u.email', 'the callee\'s parameter is also named `u`');
  const callerLocalU = raw.find((h) => h.scope === byName.caller.qid && h.kind === 'write-out' && h.toPath === 'u');
  assert.ok(callerLocalU, 'the caller has its OWN local `u`');

  const naive = store.nodeIdFor(pathNode(bind.scope, bind.context, 'u', bind.dataElementId));
  const callerU = store.nodeIdFor(pathNode(callerLocalU.scope, callerLocalU.context, 'u', callerLocalU.dataElementId));
  assert.equal(naive, callerU, 'PROOF OF THE HAZARD: own-scope addressing of the callee parameter `u` is the SAME id as the caller\'s local `u`');

  const correct = store.nodeIdFor(pathNode(bind.peerScope, bind.peerContext, 'u.email', bind.dataElementId));
  assert.notEqual(correct, callerU, 'peer addressing keeps the two namespaces apart');
  assert.ok(store.getNode(correct), 'and the peer-addressed node is real');
  // The caller's own `u` must not have acquired the callee's binding edge.
  assert.ok(!store.edgesTo(callerU).some((e) => e.outSubKind === 'call-arg-bind'),
    'no binding edge lands on the caller-local `u`');
});

// =====================================================================
// 3. Q2 — does `call-resolved`'s null fromPath stitch the return value?
//    (plan Step 2, item 3.)
// =====================================================================

test('C4/Q2: the callee\'s return value reaches the caller\'s variable — via a CROSS-SCOPE edge from the callee\'s own function-exit node, addressed by the call-resolved hop\'s peerScope/peerContext', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-q2.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw, result } = record(byName.caller, entryState, { byName });
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'the analysis really does carry the identity across the call');

  const callerCtx = raw.find((h) => h.scope === byName.caller.qid).context;
  const calleeCtx = raw.find((h) => h.scope === byName.helper.qid).context;
  const cr = raw.find((h) => h.subKind === 'call-resolved');
  assert.equal(cr.fromPath, null, 'the call-resolved hop carries NO fromPath — this is the whole question');
  assert.equal(cr.peerScope, byName.helper.qid);
  assert.equal(cr.peerContext, calleeCtx, 'and its peerContext is byte-equal to the context the callee\'s own body was recorded under');

  const nArg = store.nodeIdFor(pathNode(byName.caller.qid, callerCtx, 'a.email', 'data:email'));
  const nParam = store.nodeIdFor(pathNode(byName.helper.qid, calleeCtx, 'u.email', 'data:email'));
  const nCalleeExit = store.nodeIdFor(returnNode(byName.helper.qid, calleeCtx, 'data:email'));
  const nOut = store.nodeIdFor(pathNode(byName.caller.qid, callerCtx, 'out', 'data:email'));
  const nCallerExit = store.nodeIdFor(returnNode(byName.caller.qid, callerCtx, 'data:email'));

  // ANSWER TO Q2: the full four-hop chain exists, and it goes THROUGH the
  // callee rather than around it.
  const chain = [nArg, nParam, nCalleeExit, nOut, nCallerExit];
  for (let i = 0; i < chain.length - 1; i++) {
    assert.ok(store.hasEdge(chain[i], chain[i + 1]),
      `missing hop ${i} -> ${i + 1} of the cross-function chain`);
  }
  const stitch = store.edgesFrom(nCalleeExit).find((e) => e.toNodeId === nOut);
  assert.equal(stitch.inSubKind, 'call-resolved', 'the stitch\'s in-half IS the call-resolved hop');
  assert.equal(stitch.crossScope, true);

  // The one remaining, honestly-disclosed artefact (§14.7): the argument's
  // in-half and the caller-local landing out-half are at the same join key,
  // so the cross product also contains a BYPASS edge a.email -> out that
  // skips the callee. It is kept (dropping it would need leg-based pruning,
  // which §14.7 shows drops REAL edges in a mixed group) and marked.
  const bypass = store.edgesFrom(nArg).find((e) => e.toNodeId === nOut);
  assert.ok(bypass, 'the bypass edge exists');
  assert.equal(bypass.ambiguousCorrelation, true, 'and is the ONLY edge here marked ambiguous');
  assert.equal(store.edges().filter((e) => e.ambiguousCorrelation).length, 1,
    'the per-pairing ambiguity measure (§14.7) leaves the four real chain edges unmarked — §9.1\'s group-level test marked three of five here');
  for (const e of [store.edgesFrom(nArg).find((x) => x.toNodeId === nParam), stitch]) {
    assert.equal(e.ambiguousCorrelation, false, 'the two genuine call-boundary edges are NOT devalued by the marker');
  }
});

test('C4/Q2b: §2.2\'s annotation rule, applied LITERALLY, silently deletes that stitch — this is the correction §14.4 makes', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-q2b.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { raw } = record(byName.caller, entryState, { byName });

  // Reproduce §2.2 verbatim: "a null-fromPath in-half is an ANNOTATION on
  // the edges formed by any non-null in-half at the same key ... It forms
  // a real edge only when NO non-null in-half exists at that key."
  const callNodeHops = raw.filter((h) => h.subKind === 'call-resolved');
  const cr = callNodeHops[0];
  const sameKey = raw.filter((h) => h.scope === cr.scope && h.nodeId === cr.nodeId
    && h.dataElementId === cr.dataElementId && h.context === cr.context);
  const nonNullInHalves = sameKey.filter((h) => (h.kind === 'production' || h.kind === 'selection') && h.fromPath !== null);
  assert.ok(nonNullInHalves.length > 0,
    'THE DEFECT: the argument expression\'s own in-half sits at the SAME join key as the call-resolved hop, so §2.2 demotes call-resolved to an annotation');
  assert.deepEqual(nonNullInHalves.map((h) => h.fromPath), ['a.email']);

  // Under the literal rule the callee's exit node has no outgoing edge at
  // all: reconstruction from `out` would report the argument as its
  // immediate predecessor and the callee body would be unreachable.
  const strict = new PathStore();
  strict.addHops(raw.map((h) => (h.subKind === 'call-resolved' ? { ...h, peerScope: null, peerContext: null } : h)));
  const calleeCtx = raw.find((h) => h.scope === byName.helper.qid).context;
  const nCalleeExit = strict.nodeIdFor(returnNode(byName.helper.qid, calleeCtx, 'data:email'));
  assert.equal(strict.edgesFrom(nCalleeExit).length, 0,
    'under the literal §2.2 reading the callee\'s exit is a dead end — the return value never reaches the caller');
});

test('C4/Q2c: the peer-addressed rule does NOT fire for a §13.6 context-cap-degraded call-resolved hop — that one really is an annotation, because its callee has no recorded body', () => {
  const src = `
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `;
  const byName = parseFns(src, '/x/c4-q2c.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');
  // Cap of 1 distinct entry context per function — the shipped B6
  // degradation path (`FieldIdentitySummaryCache(1)`, positional).
  const cache = new FieldIdentitySummaryCache(1);
  const { store, raw } = record(byName.outer, entryState, { byName, cache });

  const degraded = raw.find((h) => h.lossReason === 'context-cap-degraded');
  assert.ok(degraded, 'the shipped resolver emits the §13.6 loss hop under a cap-1 cache');
  assert.equal(degraded.fromPath, null);
  assert.equal(degraded.toPath, null);
  assert.ok(degraded.peerScope, 'it still names the callee');

  // It must NOT create an edge out of a fabricated callee exit node.
  const phantomExit = store.nodeIdFor(returnNode(degraded.peerScope, degraded.peerContext, degraded.dataElementId));
  assert.equal(store.getNode(phantomExit), null,
    'no exit node is fabricated for a callee whose body was never analyzed — that would be a path that begins in the middle of nothing');

  // But it is NEVER dropped: it survives as an annotation on the real
  // argument -> parameter edge at the same join key (§13.6's own
  // "C4 must surface it under both readings; what it must never do is
  // drop it").
  const annotated = store.edges().filter((e) => e.annotations.some((a) => a.lossReason === 'context-cap-degraded'));
  assert.ok(annotated.length > 0, 'the degradation is visible on a real edge');
  assert.ok(annotated.some((e) => e.outSubKind === 'call-arg-bind'),
    'specifically on the argument -> parameter binding edge, which is where the data actually went');
});

// =====================================================================
// 4. Cycles (plan Step 2, item 4).
// =====================================================================

test('C4/4: a mutually-recursive call graph builds without recursing, stack-overflowing, or looping — and the store honestly contains a cycle', () => {
  const src = `
    function ping(u) { const r = pong(u); return { a: u.email, b: r }; }
    function pong(u) { const r = ping(u); return { c: u.email, d: r }; }
    function top(user) { return ping(user); }
  `;
  const byName = parseFns(src, '/x/c4-cycle.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store, raw } = record(byName.top, entryState, { byName });
  assert.ok(raw.length > 0);
  assert.deepEqual(store.diagnostics().unclassified, []);

  const s = store.stats();
  assert.ok(s.nodes > 0 && s.edges > 0, `built ${s.nodes} nodes / ${s.edges} edges without recursing`);

  // The store's own construction never walks the graph, so it cannot spin.
  // Prove a cycle nonetheless EXISTS, with an explicitly bounded walk in
  // the TEST (never in path-store.js itself — §14.6/§9.3).
  const adjacency = new Map();
  for (const e of store.edges()) {
    if (!adjacency.has(e.fromNodeId)) adjacency.set(e.fromNodeId, []);
    adjacency.get(e.fromNodeId).push(e.toNodeId);
  }
  let cyclic = false;
  const BUDGET = 20000;
  let steps = 0;
  for (const start of adjacency.keys()) {
    const stack = [[start, new Set([start])]];
    while (stack.length && steps < BUDGET) {
      steps += 1;
      const [cur, seen] = stack.pop();
      for (const nxt of adjacency.get(cur) ?? []) {
        if (nxt === start) { cyclic = true; break; }
        if (!seen.has(nxt)) stack.push([nxt, new Set([...seen, nxt])]);
      }
      if (cyclic) break;
    }
    if (cyclic) break;
  }
  assert.ok(cyclic, 'a real cycle exists in this DAG — §9.3 is not hypothetical, and C5 must be cycle-safe by construction');
});

test('C4/4b: the peer x peer exclusion is load-bearing — without it, EVERY resolved call manufactures a callee-exit -> callee-parameter cycle that no program executed', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c4-peerpeer.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.caller, entryState, { byName });

  const calleeCtx = raw.find((h) => h.scope === byName.helper.qid).context;
  const nParam = store.nodeIdFor(pathNode(byName.helper.qid, calleeCtx, 'u.email', 'data:email'));
  const nExit = store.nodeIdFor(returnNode(byName.helper.qid, calleeCtx, 'data:email'));

  assert.ok(store.hasEdge(nParam, nExit), 'the callee\'s own body edge is present (recorded by the callee\'s own hops)');
  assert.equal(store.hasEdge(nExit, nParam), false,
    'and the reverse edge — which a naive full cross product of the call group WOULD create — is excluded');

  // Show the naive product really would create it.
  const cr = raw.find((h) => h.subKind === 'call-resolved');
  const bind = raw.find((h) => h.subKind === 'call-arg-bind');
  assert.equal(joinKeyOf(cr), joinKeyOf(bind),
    'the call-resolved in-half and the call-arg-bind out-half share a join key, so a naive cross product pairs them');
  assert.equal(classifyIn(cr).crossScope, true);
  assert.equal(classifyOut(bind).crossScope, true);
});

// =====================================================================
// 5. Stable-ID behaviour (plan Step 2, item 5).
// =====================================================================

test('C4/5: provenanceEdgeId is idempotent for the same logical edge and never collides for a structurally different one', () => {
  const src = 'function f(a) { const b = a.email; return b; }';
  const byName = parseFns(src, '/x/c4-ids.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { raw } = record(byName.f, entryState);

  // Idempotence across two independent runs and across re-delivery.
  const s1 = new PathStore(); s1.addHops(raw);
  const s2 = new PathStore(); s2.addHops(raw); s2.addHops(raw);
  const { raw: raw2 } = record(byName.f, entryState);
  const s3 = new PathStore(); s3.addHops(raw2);
  const ids = (s) => s.edges().map((e) => e.id).sort();
  assert.deepEqual(ids(s1), ids(s2), 're-delivering the same stream yields identical edge ids');
  assert.deepEqual(ids(s1), ids(s3), 'a second independent analysis run yields identical edge ids (content hash, not a counter)');

  // Non-collision: every field of the discriminator must move the id.
  const base = {
    fromNodeId: 'pnode:path:aaa', toNodeId: 'pnode:path:bbb', dataElementId: 'data:e',
    scope: 'S', context: 'C', siteNodeId: 'n1',
    inKind: 'production', inSubKind: 'ident', outKind: 'write-out', outSubKind: 'assign',
    widenReasons: [], lossReasons: [],
  };
  const seen = new Map([[provenanceEdgeId(base), 'base']]);
  const variants = {
    fromNodeId: 'pnode:path:zzz', toNodeId: 'pnode:path:zzz', dataElementId: 'data:x',
    scope: 'S2', context: 'C2', siteNodeId: 'n2',
    inKind: 'selection', inSubKind: 'member', outKind: 'write-out-x', outSubKind: 'return',
  };
  for (const [field, value] of Object.entries(variants)) {
    const id = provenanceEdgeId({ ...base, [field]: value });
    assert.ok(!seen.has(id), `changing ${field} must change the edge id (collided with ${seen.get(id)})`);
    seen.set(id, field);
  }
  for (const [field, value] of [['widenReasons', ['unresolved-call']], ['lossReasons', ['unsupported-target']]]) {
    const id = provenanceEdgeId({ ...base, [field]: value });
    assert.ok(!seen.has(id), `changing ${field} must change the edge id`);
    seen.set(id, field);
  }
  // Reason arrays are SETS — order must not matter.
  assert.equal(
    provenanceEdgeId({ ...base, widenReasons: ['a', 'b'] }),
    provenanceEdgeId({ ...base, widenReasons: ['b', 'a'] }),
  );
  assert.match(provenanceEdgeId(base), /^pedge:[0-9a-f]{12}$/);
  assert.match(provenanceNodeId({ kind: 'path', scope: 'S', context: 'C', path: 'a', siteNodeId: null, dataElementId: 'data:e' }), /^pnode:path:[0-9a-f]{12}$/);
});

test('C4/5b: provenanceNodeId separates every discriminator, and 5000 distinct nodes never collide', () => {
  const base = { kind: 'path', scope: 'S', context: 'C', path: 'a.b', siteNodeId: null, dataElementId: 'data:e' };
  const seen = new Set([provenanceNodeId(base)]);
  for (const [field, value] of Object.entries({ kind: 'return', scope: 'S2', context: 'C2', path: 'a.c', siteNodeId: 'n1', dataElementId: 'data:f' })) {
    const id = provenanceNodeId({ ...base, [field]: value });
    assert.ok(!seen.has(id), `changing ${field} must change the node id`);
    seen.add(id);
  }
  // The §9.4 case that motivates `context` being part of node identity.
  assert.notEqual(
    provenanceNodeId({ ...base, context: 'x.email=data:email' }),
    provenanceNodeId({ ...base, context: 'x=data:email' }),
    'two entry contexts of one function must not share a node',
  );
  const bulk = new Set();
  for (let i = 0; i < 5000; i++) {
    const id = provenanceNodeId({ kind: 'path', scope: `svc-${i % 41}`, context: `ctx-${i % 7}`, path: `p.${i}`, siteNodeId: null, dataElementId: `data:${i % 13}` });
    assert.ok(!bulk.has(id), `collision at i=${i}`);
    bulk.add(id);
  }
});

// =====================================================================
// 6. Terminal nodes, §9.1 marking, §9.5 truncation, malformed hops.
// =====================================================================

test('C4/6: escape and loss terminals are real nodes, so a path that ends at one is reportable as ENDING there rather than as absent (§18.4)', () => {
  const src = `
    function f(user, k) {
      logEvent(user.email);
      ({ z } = user);
      return 1;
    }
  `;
  const byName = parseFns(src, '/x/c4-terminal.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);

  const escapeHop = raw.find((h) => h.subKind === 'call-arg');
  assert.ok(escapeHop, 'the bare call statement emits a write-out/call-arg escape');
  const nEscape = store.nodeIdFor({ kind: 'escape', scope: escapeHop.scope, context: escapeHop.context, path: null, siteNodeId: escapeHop.nodeId, dataElementId: escapeHop.dataElementId });
  assert.ok(store.getNode(nEscape), 'the escape is a real terminal node');
  assert.ok(store.edgesTo(nEscape).length > 0, 'and something flows into it');

  const lossHop = raw.find((h) => h.lossReason === 'unsupported-target');
  assert.ok(lossHop, 'the assignment-expression destructuring is a loss site');
  const nLoss = store.nodeIdFor({ kind: 'loss', scope: lossHop.scope, context: lossHop.context, path: null, siteNodeId: lossHop.nodeId, dataElementId: lossHop.dataElementId });
  assert.ok(store.getNode(nLoss), 'the loss is a real terminal node, never a silently dropped hop');
  const lossEdge = store.edgesTo(nLoss)[0];
  assert.ok(lossEdge.lossReasons.includes('unsupported-target'), 'and the edge carries WHY it is a dead end');
  assert.deepEqual(store.diagnostics().unclassified, []);
});

test('C4/6b: §9.1 cross-join edges are marked, not prevented — at an object literal and, per §13.2, at a multi-argument call site', () => {
  const objSrc = 'function f(p, q) { const x = { a: p.email, b: q.email }; return x; }';
  const objFns = parseFns(objSrc, '/x/c4-xjoin.js');
  let es = addIdentity(emptyState(), 'p.email', 'data:email');
  es = addIdentity(es, 'q.email', 'data:email');
  const { store: objStore } = record(objFns.f, es);
  const marked = objStore.edges().filter((e) => e.ambiguousCorrelation);
  assert.ok(marked.length >= 4, `expected the 2x2 cross product to be marked, got ${marked.length}`);

  const callSrc = `
    function two(p, q) { return { p, q }; }
    function caller(m, n) { const r = two(m, n); return r; }
  `;
  const callFns = parseFns(callSrc, '/x/c4-xjoin2.js');
  let es2 = addIdentity(emptyState(), 'm.email', 'data:email');
  es2 = addIdentity(es2, 'n.email', 'data:email');
  const { store: callStore } = record(callFns.caller, es2, { byName: callFns });
  const callMarked = callStore.edges().filter((e) => e.ambiguousCorrelation && e.outSubKind === 'call-arg-bind');
  assert.ok(callMarked.length >= 4,
    `§13.2's disclosed multi-argument cross-join must be marked, got ${callMarked.length}`);
});

test('C4/6c: §9.5\'s analysis-level truncation has a reserved, out-of-band channel — no new hop `kind` is invented', () => {
  const byName = parseFns('function f(a) { const b = a.email; return b; }', '/x/c4-trunc.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);
  assert.ok(store.nodes().every((n) => !n.truncated));
  assert.ok(store.edges().every((e) => !e.truncated));

  store.markTruncated(byName.f.qid, raw[0].context, 'iter-budget');
  assert.ok(store.nodes().every((n) => n.truncated), 'every node in the truncated (scope, context) is marked');
  assert.ok(store.edges().every((e) => e.truncated), 'and every edge — the whole result set, per §9.5');
  assert.deepEqual(store.diagnostics().truncations.map(([, r]) => r), ['iter-budget']);
});

test('C4/6d: a hop with an ABSENT required key is recorded as malformed rather than silently dedup-splitting (§3\'s completeness guarantee, checked at the consumer)', () => {
  const store = new PathStore();
  const good = {
    kind: 'production', subKind: 'ident', scope: 'S', dataElementId: 'data:e',
    fromPath: 'a', toPath: null, syntacticPath: null, nodeId: 'n1', line: 1,
    widenReason: null, lossReason: null, context: 'C', peerScope: null, peerContext: null,
  };
  const { scope, ...missingScope } = good;
  store.addHop(good);
  store.addHop(missingScope);
  assert.equal(store.diagnostics().malformed.length, 1);
  assert.deepEqual(store.diagnostics().malformed[0].missing, ['scope']);
});

test('C4/6e: an annotation-only group (no non-null in-half anywhere at the key) IS edge-forming, per §2.2\'s surviving half', () => {
  // Hand-built, and disclosed as such in §14.4: no real-parser fixture
  // found during this task produces a group whose ONLY in-half has a null
  // fromPath and a null peerScope, because every construct that carries an
  // identity at all inherits a contributing key from somewhere upstream.
  const base = {
    scope: 'S', nodeId: 'n1', context: 'C', dataElementId: 'data:e', line: 3,
    peerScope: null, peerContext: null, syntacticPath: null, lossReason: null,
  };
  const store = new PathStore();
  store.addHop({ ...base, kind: 'production', subKind: 'call', fromPath: null, toPath: null, widenReason: 'unresolved-call' });
  store.addHop({ ...base, kind: 'write-out', subKind: 'assign', fromPath: null, toPath: 'x', widenReason: 'unresolved-call' });

  assert.equal(store.edges().length, 1);
  const e = store.edges()[0];
  assert.equal(e.originated, true, 'the value originates at this construct — it has no prior aliasing source');
  const origin = store.getNode(e.fromNodeId);
  assert.equal(origin.kind, 'origin');
  assert.equal(origin.siteNodeId, 'n1');
  assert.equal(store.edgesTo(origin.id).length, 0);
});
