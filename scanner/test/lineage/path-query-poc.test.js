// Sub-project C, increment C5 — DESIGN TASK proof-of-concept for the
// bounded backward-reconstruction query (`path-query.js`, working name).
//
// Deliberately throwaway-named (`-poc`), mirroring C1's / C3 Task 1's /
// C4 Task 1's own precedent: this file PROTOTYPES the module locally and
// ships NO change to any `src/lineage/*.js` file. Every claim in
// DESIGN_PATH_PROVENANCE.md §15 was produced by running this file. The
// follow-up implementation task re-points these assertions at the shipped
// `src/lineage/path-query.js` and renames the file (§15.10 item 11).
//
// The prototype consumes `PathStore` ONLY through its public read API
// (`nodes`/`edges`/`getNode`/`getEdge`/`edgesFrom`/`edgesTo`/`hasEdge`/
// `nodeIdFor`/`stats`/`diagnostics`) — never a `_`-prefixed field — and,
// like `path-store.js` itself, never imports `engine.js`/`summaries.js`/
// `driver.js`. (The FIXTURES below do import those, exactly as
// `path-store.test.js`'s own fixtures do; the module under design does
// not.)

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
import { PathStore } from '../../src/lineage/path-store.js';

// =====================================================================
// LOCAL PROTOTYPE of the module §15 designs. Shipped source is unmodified
// by this design task.
// =====================================================================

const ID_HEX_LEN = 12;

/**
 * §14.5 deliberately left `pathId` unclaimed ("The thing C5 reconstructs
 * *is* a path, and it will plausibly want that name for its own entity").
 * C5 claims it. `ppath:` joins the `pnode:`/`pedge:` family — a
 * reconstructed path is not a `DataFlowGraph v1` entity either, so
 * `validate.js` stays untouched.
 *
 * The discriminator is the EDGE id sequence plus the start node id. It is
 * deliberately NOT the node id sequence — see §15.6 (FR-305): the edges
 * are what carry the transformation/control evidence, and two paths over
 * the same nodes through different edges are two materially different
 * paths.
 */
function pathId({ startNodeId, edgeIds }) {
  const material = [startNodeId, ...edgeIds].map((p) => (p == null ? '' : String(p))).join('|');
  return `ppath:${crypto.createHash('sha256').update(material).digest('hex').slice(0, ID_HEX_LEN)}`;
}

const DEFAULTS = {
  maxPaths: 32,
  maxPathsPerTerminal: 8,
  maxCandidatePaths: 256,
  maxExpansions: 10000,
  maxDepth: 64,
};

/** Terminal reasons. Only `origin` means "this really is where the recorded flow starts". */
const TERMINAL_ORIGIN = 'origin';
const TERMINAL_INCOMPLETE = 'incomplete-record';
const TERMINAL_CYCLE = 'cycle';
const TERMINAL_DEPTH = 'depth-limit';

/**
 * §15.9's stand-in for Sub-project D's source/sink registry, which does
 * not exist. NOT a registry: it returns every structurally terminal node
 * kind, with no notion of whether any of them is a security-relevant sink.
 */
function sinkCandidates(store) {
  return store.nodes().filter((n) => n.kind === 'return' || n.kind === 'escape' || n.kind === 'loss');
}

function hopOf(edge) {
  return {
    edgeId: edge.id,
    fromNodeId: edge.fromNodeId,
    toNodeId: edge.toNodeId,
    line: edge.line,
    scope: edge.scope,
    context: edge.context,
    siteNodeId: edge.siteNodeId,
    dataElementId: edge.dataElementId,
    inKind: edge.inKind,
    inSubKind: edge.inSubKind,
    outKind: edge.outKind,
    outSubKind: edge.outSubKind,
    crossScope: edge.crossScope,
    widenReasons: edge.widenReasons,
    lossReasons: edge.lossReasons,
    ambiguousCorrelation: edge.ambiguousCorrelation,
    annotations: edge.annotations,
    originated: edge.originated,
    truncated: edge.truncated,
  };
}

/** Source-first materialization of one enumerated DFS branch. */
function materialize(store, nodesRev, edgesRev, terminalReason) {
  const nodeIds = [...nodesRev].reverse();
  const edges = [...edgesRev].reverse();
  const hops = edges.map((e) => hopOf(e));
  const edgeIds = hops.map((h) => h.edgeId);
  const nodes = nodeIds.map((id) => store.getNode(id));
  const crossScopeCount = hops.filter((h) => h.crossScope).length;
  const widenedHopCount = hops.filter((h) => h.widenReasons.length > 0).length;
  const lossHopCount = hops.filter((h) => h.lossReasons.length > 0).length;
  const ambiguousHopCount = hops.filter((h) => h.ambiguousCorrelation).length;
  const analysisTruncated = nodes.some((n) => n && n.truncated) || hops.some((h) => h.truncated);
  return {
    id: pathId({ startNodeId: nodeIds[nodeIds.length - 1], edgeIds }),
    nodeIds,
    edgeIds,
    hops,
    hopCount: hops.length,
    dataElementId: hops[0]?.dataElementId ?? null,
    sourceNodeId: nodeIds[0],
    sinkNodeId: nodeIds[nodeIds.length - 1],
    terminal: { nodeId: nodeIds[0], reason: terminalReason, kind: nodes[0]?.kind ?? null },
    complete: terminalReason === TERMINAL_ORIGIN,
    crossScopeCount,
    widenedHopCount,
    lossHopCount,
    ambiguousHopCount,
    analysisTruncated,
    // §15.7's diversity signature. `transformation` and `protection` are
    // DELIBERATELY absent — Sub-project D / Milestone 2 own them.
    shape: [
      terminalReason === TERMINAL_ORIGIN ? 'complete' : 'partial',
      crossScopeCount > 0 ? 'boundary' : 'local',
      widenedHopCount > 0 ? 'widened' : 'explicit',
      lossHopCount > 0 ? 'lossy' : 'intact',
      ambiguousHopCount > 0 ? 'ambiguous' : 'correlated',
    ].join('/'),
  };
}

/** §15.7's total order. Deterministic: the final key is the content-hash id. */
function comparePaths(a, b) {
  if (a.complete !== b.complete) return a.complete ? -1 : 1;
  if (a.ambiguousHopCount !== b.ambiguousHopCount) return a.ambiguousHopCount - b.ambiguousHopCount;
  if (a.lossHopCount !== b.lossHopCount) return a.lossHopCount - b.lossHopCount;
  if (a.widenedHopCount !== b.widenedHopCount) return a.widenedHopCount - b.widenedHopCount;
  if (a.crossScopeCount !== b.crossScopeCount) return b.crossScopeCount - a.crossScopeCount;
  if (a.hopCount !== b.hopCount) return a.hopCount - b.hopCount;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * §15.3's bounded backward walk. Iterative (an explicit stack, never
 * recursion), cycle-safe by an explicit PER-PATH visited set, and bounded
 * by four independent budgets. `path-store.js`'s own construction is a
 * single linear pass and never needed any of this — §9.3/§14.6 hand the
 * whole problem here.
 */
function reconstructPaths(store, startNodeId, opts = {}) {
  const budget = { ...DEFAULTS, ...opts };
  const startNode = store.getNode(startNodeId);
  const truncationReasons = new Set();

  const result = {
    startNodeId,
    startNodeKind: startNode ? startNode.kind : null,
    unknownStartNode: !startNode,
    paths: [],
    truncated: false,
    truncationReasons: [],
    noPathReason: null,
    enumeratedPathCount: 0,
    returnedPathCount: 0,
    droppedPathCount: 0,
    completePathCount: 0,
    cyclesClipped: 0,
    terminals: [],
    analysisTruncated: false,
    budget: { ...budget, expansionsUsed: 0 },
  };
  // An id that names no node is NOT "no path exists" — it is "you asked
  // about something that is not in this store". §15.4 keeps the two
  // apart, because collapsing them is §18.4's failure mode wearing a
  // different hat.
  if (!startNode) return result;

  const orphaned = new Set(store.diagnostics().orphanedPeerSources.map((o) => o.nodeId));

  const candidates = [];
  let expansions = 0;
  const stack = [{
    nodeId: startNodeId,
    nodesRev: [startNodeId],
    edgesRev: [],
    onPath: new Set([startNodeId]),
  }];

  while (stack.length > 0) {
    if (candidates.length >= budget.maxCandidatePaths) { truncationReasons.add('candidate-cap'); break; }
    if (expansions >= budget.maxExpansions) { truncationReasons.add('expansion-budget'); break; }
    const frame = stack.pop();
    const hops = frame.edgesRev.length;
    // `edgesTo` is the traversal primitive; sorted for determinism, since
    // it is backed by a Set and carries no inherent order.
    const incoming = [...store.edgesTo(frame.nodeId)].sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));

    if (incoming.length === 0) {
      if (hops > 0) {
        candidates.push(materialize(store, frame.nodesRev, frame.edgesRev,
          orphaned.has(frame.nodeId) ? TERMINAL_INCOMPLETE : TERMINAL_ORIGIN));
      }
      continue;
    }
    if (hops >= budget.maxDepth) {
      truncationReasons.add('depth-limit');
      candidates.push(materialize(store, frame.nodesRev, frame.edgesRev, TERMINAL_DEPTH));
      continue;
    }

    let extended = 0;
    let clipped = 0;
    for (const e of incoming) {
      expansions += 1;
      if (frame.onPath.has(e.fromNodeId)) { clipped += 1; continue; }
      extended += 1;
      stack.push({
        nodeId: e.fromNodeId,
        nodesRev: [...frame.nodesRev, e.fromNodeId],
        edgesRev: [...frame.edgesRev, e],
        onPath: new Set([...frame.onPath, e.fromNodeId]),
      });
    }
    result.cyclesClipped += clipped;
    if (extended === 0 && hops > 0) {
      // Every continuation would revisit a node already on this path. The
      // branch ends HERE, and it ends because of a cycle — never silently
      // as if this node were the flow's origin.
      candidates.push(materialize(store, frame.nodesRev, frame.edgesRev, TERMINAL_CYCLE));
    }
  }

  result.budget.expansionsUsed = expansions;
  result.enumeratedPathCount = candidates.length;
  result.completePathCount = candidates.filter((p) => p.complete).length;

  // §15.5's cap, applied PER TERMINAL first. The terminal node is the
  // closest thing to a "source" this increment has; a purely global cap
  // lets one prolific terminal crowd another out entirely, which would
  // report a real source as having zero paths.
  const byTerminal = new Map();
  for (const p of candidates) {
    if (!byTerminal.has(p.terminal.nodeId)) byTerminal.set(p.terminal.nodeId, []);
    byTerminal.get(p.terminal.nodeId).push(p);
  }
  const kept = [];
  const terminals = [];
  for (const [nodeId, group] of [...byTerminal.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const ordered = [...group].sort(comparePaths);
    const take = ordered.slice(0, budget.maxPathsPerTerminal);
    if (ordered.length > take.length) truncationReasons.add('per-terminal-cap');
    kept.push(...take);
    terminals.push({
      nodeId,
      terminalReason: group[0].terminal.reason,
      enumeratedPathCount: group.length,
      keptPathCount: take.length,
      truncated: ordered.length > take.length,
    });
  }

  // §15.7: the global cap is applied DIVERSITY-FIRST, round-robin across
  // (terminal, shape) buckets, so §18.4's "prioritize paths that differ in
  // boundary/transformation/protection state" is honoured as written — it
  // asks for a DIVERSE retained set, not a top-N by any single scalar.
  let returned = kept;
  if (kept.length > budget.maxPaths) {
    truncationReasons.add('path-cap');
    const buckets = new Map();
    for (const p of [...kept].sort(comparePaths)) {
      const key = `${p.terminal.nodeId}|${p.shape}`;
      if (!buckets.has(key)) buckets.set(key, []);
      buckets.get(key).push(p);
    }
    const order = [...buckets.keys()].sort();
    returned = [];
    let progress = true;
    while (returned.length < budget.maxPaths && progress) {
      progress = false;
      for (const k of order) {
        if (returned.length >= budget.maxPaths) break;
        const b = buckets.get(k);
        if (b.length > 0) { returned.push(b.shift()); progress = true; }
      }
    }
  }

  returned = [...returned].sort(comparePaths);
  result.paths = returned;
  result.returnedPathCount = returned.length;
  result.droppedPathCount = candidates.length - returned.length;
  result.analysisTruncated = returned.some((p) => p.analysisTruncated);
  for (const t of terminals) t.returnedPathCount = returned.filter((p) => p.terminal.nodeId === t.nodeId).length;
  result.terminals = terminals;

  result.truncated = truncationReasons.size > 0 || result.droppedPathCount > 0;
  result.truncationReasons = [...truncationReasons].sort();

  if (result.paths.length === 0 && !result.truncated) {
    // The one place a genuinely empty answer is produced — and it says
    // WHICH kind of empty it is. §18.4's load-bearing constraint.
    result.noPathReason = orphaned.has(startNodeId) ? TERMINAL_INCOMPLETE : 'no-incoming-edges';
  }
  return result;
}

/** AC-10's banner predicate, derived from the result — never re-derived by a caller. */
function isIncompleteAnswer(r) {
  return r.truncated || r.unknownStartNode || r.analysisTruncated
    || r.noPathReason === TERMINAL_INCOMPLETE
    || r.paths.some((p) => !p.complete);
}

// =====================================================================
// Shared fixture harness — identical to `path-store.test.js`'s, so every
// DAG below is a REAL one built from real parsed JS/TS through the real
// engine + the real interprocedural resolver.
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
// 1. The simple reconstruction round-trip (§15.2).
// =====================================================================

test('C5/1: §6\'s worked example reconstructs into exactly the two field-distinct three-hop paths §14.11 predicts — source-first, edge-carrying, zero truncation', () => {
  const src = `
    function f(user) {
      const u = user;
      const o = { email: u.email, ssn: u.ssn };
      return o;
    }
  `;
  const byName = parseFns(src, '/x/c5-six.js');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const { store, raw } = record(byName.f, entryState);
  const scope = byName.f.qid;
  const ctx = raw[0].context;

  for (const [field, id] of [['email', 'data:email'], ['ssn', 'data:ssn']]) {
    const sink = store.nodeIdFor(returnNode(scope, ctx, id));
    const r = reconstructPaths(store, sink);

    assert.equal(r.unknownStartNode, false);
    assert.equal(r.truncated, false, 'a 3-hop chain is nowhere near any budget');
    assert.deepEqual(r.truncationReasons, []);
    assert.equal(r.noPathReason, null);
    assert.equal(r.paths.length, 1, `${id}: exactly one path`);
    assert.equal(r.enumeratedPathCount, 1);
    assert.equal(r.droppedPathCount, 0);
    assert.equal(r.completePathCount, 1);
    assert.equal(isIncompleteAnswer(r), false, 'AC-10: nothing about this answer is partial');

    const p = r.paths[0];
    // SOURCE-FIRST: a human reads a path source -> sink even though the
    // walk that produced it ran sink -> source.
    assert.deepEqual(p.nodeIds, [
      store.nodeIdFor(pathNode(scope, ctx, `user.${field}`, id)),
      store.nodeIdFor(pathNode(scope, ctx, `u.${field}`, id)),
      store.nodeIdFor(pathNode(scope, ctx, `o.${field}`, id)),
      sink,
    ], `${id}: the exact node sequence §6 predicts, source-first`);
    assert.equal(p.hopCount, 3);
    assert.equal(p.complete, true);
    assert.equal(p.terminal.reason, 'origin');
    assert.equal(p.terminal.kind, 'path');

    // The path CARRIES its edges, not just node ids — FR-306 needs to
    // grade each hop, and the grading material lives on the edges.
    assert.equal(p.edgeIds.length, 3);
    for (let i = 0; i < 3; i++) {
      assert.equal(p.hops[i].fromNodeId, p.nodeIds[i], `hop ${i} starts where node ${i} is`);
      assert.equal(p.hops[i].toNodeId, p.nodeIds[i + 1], `hop ${i} ends where node ${i + 1} is`);
      const e = store.getEdge(p.edgeIds[i]);
      assert.ok(e, 'every edge id on a path round-trips through the store');
      assert.equal(e.id, p.hops[i].edgeId);
      // FR-306's grading material, present on every hop.
      assert.ok(Array.isArray(p.hops[i].widenReasons));
      assert.ok(Array.isArray(p.hops[i].lossReasons));
      assert.ok(Array.isArray(p.hops[i].annotations));
      assert.equal(typeof p.hops[i].ambiguousCorrelation, 'boolean');
      assert.equal(typeof p.hops[i].crossScope, 'boolean');
      assert.equal(typeof p.hops[i].line, 'number');
    }
    // FR-301 carried into FR-303: a reconstructed path is field-precise
    // for free — see C5/1b for why this needs no filtering.
    assert.equal(p.dataElementId, id);
    assert.ok(p.hops.every((h) => h.dataElementId === id));
  }
});

test('C5/1b: every edge in the store joins two nodes of the SAME dataElementId, so a backward walk can never wander between data elements — field precision is structural, not filtered', () => {
  const src = `
    function f(user) {
      const u = user;
      const o = { email: u.email, ssn: u.ssn };
      return o;
    }
  `;
  const byName = parseFns(src, '/x/c5-fieldprec.js');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const { store } = record(byName.f, entryState);
  assert.ok(store.edges().length > 0);
  for (const e of store.edges()) {
    const from = store.getNode(e.fromNodeId);
    const to = store.getNode(e.toNodeId);
    assert.equal(from.dataElementId, e.dataElementId);
    assert.equal(to.dataElementId, e.dataElementId);
  }
});

test('C5/1c: the annotation-carrying object-literal hop survives onto the reconstructed path — FR-306 grading material is not discarded while assembling a path', () => {
  const src = `
    function f(user) {
      const o = { email: user.email };
      return o;
    }
  `;
  const byName = parseFns(src, '/x/c5-ann.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);
  const sink = store.nodeIdFor(returnNode(byName.f.qid, raw[0].context, 'data:email'));
  const r = reconstructPaths(store, sink);
  assert.equal(r.paths.length, 1);
  const annotated = r.paths[0].hops.filter((h) => h.annotations.some((a) => a.subKind === 'object'));
  assert.ok(annotated.length > 0, 'the production/object annotation reaches the path output');
});

// =====================================================================
// 2. Cross-function reconstruction (§15.3) — the walk must cross scope.
// =====================================================================

test('C5/2: reconstruction from the CALLER\'s exit node walks through the cross-scope stitch, into the callee\'s exit, out to the callee\'s parameter and back to the caller\'s argument', () => {
  const src = `
    function helper(u) { return u.email; }
    function caller(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c5-cross.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.caller, entryState, { byName });

  const callerCtx = raw.find((h) => h.scope === byName.caller.qid).context;
  const calleeCtx = raw.find((h) => h.scope === byName.helper.qid).context;
  const nArg = store.nodeIdFor(pathNode(byName.caller.qid, callerCtx, 'a.email', 'data:email'));
  const nParam = store.nodeIdFor(pathNode(byName.helper.qid, calleeCtx, 'u.email', 'data:email'));
  const nCalleeExit = store.nodeIdFor(returnNode(byName.helper.qid, calleeCtx, 'data:email'));
  const nOut = store.nodeIdFor(pathNode(byName.caller.qid, callerCtx, 'out', 'data:email'));
  const nCallerExit = store.nodeIdFor(returnNode(byName.caller.qid, callerCtx, 'data:email'));

  const r = reconstructPaths(store, nCallerExit);
  assert.equal(r.truncated, false);
  assert.equal(r.enumeratedPathCount, 2, 'the real through-the-callee chain AND §14.7\'s disclosed bypass');
  assert.equal(r.paths.length, 2);

  const through = r.paths.find((p) => p.nodeIds.includes(nCalleeExit));
  const bypass = r.paths.find((p) => !p.nodeIds.includes(nCalleeExit));
  assert.ok(through && bypass);

  assert.deepEqual(through.nodeIds, [nArg, nParam, nCalleeExit, nOut, nCallerExit],
    'the walk crossed the function boundary in BOTH directions (arg -> param, callee exit -> caller local)');
  assert.equal(through.crossScopeCount, 2, 'two boundary-crossing hops');
  assert.equal(through.ambiguousHopCount, 0);
  assert.equal(through.complete, true);

  assert.deepEqual(bypass.nodeIds, [nArg, nOut, nCallerExit]);
  assert.equal(bypass.crossScopeCount, 0);
  assert.equal(bypass.ambiguousHopCount, 1, '§14.7\'s bypass is the one ambiguous edge, and it lands on this path');

  // §15.7's ordering rule, doing real work: the trustworthy
  // through-the-callee path outranks the shorter bypass even though the
  // bypass is half the length.
  assert.equal(r.paths[0].id, through.id, 'the non-ambiguous, boundary-crossing path is ranked FIRST');
  assert.equal(r.paths[1].id, bypass.id);
  if (process.env.C5_PRINT_TABLE) console.log(`5/2: through hops=${through.hopCount} crossScope=${through.crossScopeCount} amb=${through.ambiguousHopCount}; bypass hops=${bypass.hopCount} crossScope=${bypass.crossScopeCount} amb=${bypass.ambiguousHopCount}`); // eslint-disable-line no-console
  assert.ok(bypass.hopCount < through.hopCount, 'and it wins despite being the LONGER path — length is the last content key, not the first');
});

test('C5/2b: an `escape` node is reachable as a start node but never as an intermediate — nothing in the store ever points OUT of a terminal kind', () => {
  const src = `
    function f(user) {
      logEvent(user.email);
      return 1;
    }
  `;
  const byName = parseFns(src, '/x/c5-escape.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store } = record(byName.f, entryState);

  const escapes = store.nodes().filter((n) => n.kind === 'escape');
  assert.equal(escapes.length, 1);
  for (const n of store.nodes()) {
    if (n.kind === 'escape' || n.kind === 'loss') {
      assert.equal(store.edgesFrom(n.id).length, 0, `${n.kind} nodes are structurally terminal — nothing flows out of one`);
    }
  }
  const r = reconstructPaths(store, escapes[0].id);
  assert.equal(r.truncated, false);
  assert.ok(r.paths.length >= 1, 'but reconstruction FROM one works, and that is the point (§14.2: D\'s sink-attachment point)');
  assert.equal(r.paths[0].complete, true);
  assert.equal(r.startNodeKind, 'escape');

  // §15.9's registry stand-in.
  assert.ok(sinkCandidates(store).some((n) => n.id === escapes[0].id));
});

// =====================================================================
// 3. Bounded, honest truncation on a REAL cycle (§15.3/§15.4).
// =====================================================================

test('C5/3: the C4/4 mutual-recursion fixture (a proven cycle) reconstructs under a small explicit budget — it TERMINATES, and it reports truncation rather than a silently short list', () => {
  const src = `
    function ping(u) { const r = pong(u); return { a: u.email, b: r }; }
    function pong(u) { const r = ping(u); return { c: u.email, d: r }; }
    function top(user) { return ping(user); }
  `;
  const byName = parseFns(src, '/x/c5-cycle.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store } = record(byName.top, entryState, { byName });
  assert.equal(store.stats().nodes, 8, 'the same 8-node / 11-edge cyclic DAG C4/4 pins');
  assert.equal(store.stats().edges, 11);

  const sinks = sinkCandidates(store);
  assert.ok(sinks.length > 0);

  // (a) A generous budget: the walk still terminates, because the
  // per-path visited set makes every enumerated path SIMPLE. This is the
  // termination guarantee that does NOT depend on any budget being small.
  let anyCycleClipped = false;
  let expansions = 0;
  let clips = 0;
  for (const s of sinks) {
    const r = reconstructPaths(store, s.id, { maxExpansions: 1e6, maxCandidatePaths: 1e6, maxPaths: 1e6, maxPathsPerTerminal: 1e6 });
    assert.equal(r.truncated, false, 'with every budget at 10^6 nothing is truncated — the walk genuinely exhausted the graph');
    expansions += r.budget.expansionsUsed;
    clips += r.cyclesClipped;
    if (r.cyclesClipped > 0) anyCycleClipped = true;
  }
  assert.ok(anyCycleClipped, 'a real cycle really was clipped — §9.3 is not hypothetical here either');
  // §15.11's last row, re-measured with every budget at 10^6: identical.
  // The visited set, not a budget, is what stopped the walk.
  assert.equal(expansions, 35, '§15.11: 35 expansions summed across all four sink candidates');
  assert.equal(clips, 7, '§15.11: 7 per-path visited-set clips');
  assert.ok(expansions < 1e6);

  // (b) A deliberately tiny budget on the richest sink. The result must
  // be BOTH terminated and honestly labelled.
  const richest = sinks
    .map((s) => ({ s, n: reconstructPaths(store, s.id, { maxPaths: 1e6, maxPathsPerTerminal: 1e6 }).enumeratedPathCount }))
    .sort((a, b) => b.n - a.n)[0];
  assert.ok(richest.n >= 2, `the cyclic fixture yields ${richest.n} simple paths at its richest sink`);

  const tight = reconstructPaths(store, richest.s.id, { maxPaths: 1, maxPathsPerTerminal: 1 });
  assert.equal(tight.paths.length, 1, 'the cap is honoured exactly');
  assert.equal(tight.truncated, true, '§18.4: and the caller is TOLD the list is not everything');
  assert.ok(tight.droppedPathCount > 0, 'with an explicit truncation COUNT, per §18.4\'s own wording');
  assert.equal(tight.enumeratedPathCount, tight.paths.length + tight.droppedPathCount);
  assert.ok(tight.truncationReasons.length > 0);
  assert.equal(isIncompleteAnswer(tight), true, 'AC-10\'s banner fires');

  // (c) An expansion budget so small the walk cannot even finish one
  // branch. Still terminates; still says so.
  const starved = reconstructPaths(store, richest.s.id, { maxExpansions: 1 });
  assert.equal(starved.truncated, true);
  assert.ok(starved.truncationReasons.includes('expansion-budget'));
  assert.equal(starved.unknownStartNode, false);
  assert.equal(starved.noPathReason, null,
    'CRITICAL (§18.4): a budget-starved result must never acquire a "no path" explanation');
  assert.equal(isIncompleteAnswer(starved), true);

  // (d) The fourth budget — `maxCandidatePaths` — fires too, and like
  // `expansion-budget` it is a RESULT-level reason only: the branches in
  // flight when it trips are abandoned, never emitted as partial paths.
  const capped = reconstructPaths(store, richest.s.id, { maxCandidatePaths: 1, maxPaths: 1e6, maxPathsPerTerminal: 1e6 });
  assert.ok(capped.truncationReasons.includes('candidate-cap'));
  assert.equal(capped.truncated, true);
  assert.equal(capped.noPathReason, null);
  assert.ok(capped.enumeratedPathCount <= 2,
    'enumeration really did stop at the candidate cap rather than running to completion');
});

test('C5/3b: a depth-limited branch is emitted as a PARTIAL path whose terminal says `depth-limit` — never as a path that appears to reach an origin', () => {
  const src = `
    function ping(u) { const r = pong(u); return { a: u.email, b: r }; }
    function pong(u) { const r = ping(u); return { c: u.email, d: r }; }
    function top(user) { return ping(user); }
  `;
  const byName = parseFns(src, '/x/c5-depth.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store } = record(byName.top, entryState, { byName });
  const richest = sinkCandidates(store)
    .map((s) => ({ s, n: reconstructPaths(store, s.id, { maxPaths: 1e6, maxPathsPerTerminal: 1e6 }) }))
    .sort((a, b) => b.n.enumeratedPathCount - a.n.enumeratedPathCount)[0];
  const deepest = Math.max(...richest.n.paths.map((p) => p.hopCount));
  assert.ok(deepest >= 2);

  const clipped = reconstructPaths(store, richest.s.id, { maxDepth: 1, maxPaths: 1e6, maxPathsPerTerminal: 1e6 });
  assert.ok(clipped.truncationReasons.includes('depth-limit'));
  assert.equal(clipped.truncated, true);
  const partials = clipped.paths.filter((p) => p.terminal.reason === 'depth-limit');
  assert.ok(partials.length > 0, 'the clipped branch is REPORTED, not dropped — a dead end recorded as a dead end (§14.2)');
  for (const p of partials) {
    assert.equal(p.complete, false, 'and it is explicitly not a complete source-to-sink path');
    assert.equal(p.hopCount, 1);
  }
  // The depth check runs AFTER the zero-in-edges check, deliberately: a
  // node with no predecessors is a genuine origin no matter how deep the
  // walk is, so a 1-hop path onto a real origin is still `complete: true`.
  // Only a branch the LIMIT stopped is marked partial.
  for (const p of clipped.paths) {
    assert.equal(p.complete, p.terminal.reason === 'origin',
      'completeness is exactly "terminated at a real origin", never "the walk stopped"');
  }
  assert.ok(clipped.paths.some((p) => p.complete),
    'a 1-hop path onto a node with genuinely zero predecessors is still complete');
});

test('C5/3c: a path that ends only because every continuation would revisit a node reports terminal `cycle`, not `origin`', () => {
  const src = `
    function ping(u) { const r = pong(u); return { a: u.email, b: r }; }
    function pong(u) { const r = ping(u); return { c: u.email, d: r }; }
    function top(user) { return ping(user); }
  `;
  const byName = parseFns(src, '/x/c5-cyclterm.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store } = record(byName.top, entryState, { byName });

  const seen = new Set();
  for (const s of sinkCandidates(store)) {
    const r = reconstructPaths(store, s.id, { maxPaths: 1e6, maxPathsPerTerminal: 1e6, maxCandidatePaths: 1e6 });
    for (const p of r.paths) seen.add(p.terminal.reason);
  }
  assert.ok(seen.has('cycle'),
    `a cyclic DAG must produce at least one cycle-terminated path; saw ${JSON.stringify([...seen])}`);
  assert.ok(seen.has('origin'), 'and at least one genuinely complete one, so the two are demonstrably different labels');
});

// =====================================================================
// 4. "Genuinely no path" vs "truncated" — two DIFFERENT empty results
//    (§15.4). This is §18.4's single most load-bearing constraint.
// =====================================================================

test('C5/4: a node with genuinely ZERO incoming paths returns NOT-truncated, zero paths, and an explicit `no-incoming-edges` reason', () => {
  const byName = parseFns('function f(a) { const b = a.email; return b; }', '/x/c5-nopath.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);
  const origin = store.nodeIdFor(pathNode(byName.f.qid, raw[0].context, 'a.email', 'data:email'));
  assert.equal(store.edgesTo(origin).length, 0, 'this node really has no in-edges');

  const r = reconstructPaths(store, origin);
  assert.deepEqual(r.paths, []);
  assert.equal(r.truncated, false, 'NOT truncated — we looked, exhaustively, and there is genuinely nothing');
  assert.deepEqual(r.truncationReasons, []);
  assert.equal(r.noPathReason, 'no-incoming-edges');
  assert.equal(r.unknownStartNode, false);
  assert.equal(r.enumeratedPathCount, 0);
  assert.equal(r.droppedPathCount, 0);
  assert.equal(isIncompleteAnswer(r), false, 'AC-10: no banner — this answer is complete');
});

test('C5/4b: the three empty-looking results are pairwise distinguishable in the DATA, not by convention', () => {
  const byName = parseFns('function f(a) { const b = a.email; return b; }', '/x/c5-three-empties.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);
  const scope = byName.f.qid;
  const ctx = raw[0].context;

  const genuinelyEmpty = reconstructPaths(store, store.nodeIdFor(pathNode(scope, ctx, 'a.email', 'data:email')));
  const unknown = reconstructPaths(store, 'pnode:path:ffffffffffff');
  const starved = reconstructPaths(store, store.nodeIdFor(returnNode(scope, ctx, 'data:email')), { maxExpansions: 0 });

  for (const r of [genuinelyEmpty, unknown, starved]) assert.deepEqual(r.paths, [], 'all three LOOK empty');

  const shape = (r) => JSON.stringify([r.truncated, r.unknownStartNode, r.noPathReason, r.truncationReasons]);
  assert.notEqual(shape(genuinelyEmpty), shape(unknown));
  assert.notEqual(shape(genuinelyEmpty), shape(starved));
  assert.notEqual(shape(unknown), shape(starved));

  assert.deepEqual(shape(genuinelyEmpty), JSON.stringify([false, false, 'no-incoming-edges', []]));
  assert.deepEqual(shape(unknown), JSON.stringify([false, true, null, []]));
  assert.deepEqual(shape(starved), JSON.stringify([true, false, null, ['expansion-budget']]));

  assert.equal(isIncompleteAnswer(genuinelyEmpty), false);
  assert.equal(isIncompleteAnswer(unknown), true);
  assert.equal(isIncompleteAnswer(starved), true);
});

test('C5/4c: a node whose zero in-edges are a RECORDING GAP (§14.4\'s orphanedPeerSources) says `incomplete-record`, never `no-incoming-edges`', () => {
  const src = `
    function helper(u) { return u.email; }
    function callerA(a) { const out = helper(a); return out; }
    function callerB(a) { const out = helper(a); return out; }
  `;
  const byName = parseFns(src, '/x/c5-orphan.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const cache = new FieldIdentitySummaryCache();

  // Warm the cache with NO recorder (helper's own body hops never fire)…
  analyzeFunctionFieldIdentity(byName.callerA, entryState, {
    resolveCallSummary: createCallSummaryResolver(cache, lookupCalleeFor(byName)),
  });
  // …then analyze callerB against the SAME cache WITH a recorder.
  const raw = [];
  analyzeFunctionFieldIdentity(byName.callerB, entryState, {
    recordHop: (h) => raw.push(h),
    resolveCallSummary: createCallSummaryResolver(cache, lookupCalleeFor(byName)),
  });
  const store = new PathStore();
  store.addHops(raw);

  const cr = raw.find((h) => h.subKind === 'call-resolved');
  const orphanId = store.nodeIdFor(returnNode(cr.peerScope, cr.peerContext, cr.dataElementId));
  assert.ok(store.diagnostics().orphanedPeerSources.some((o) => o.nodeId === orphanId), 'the store flags it');
  assert.equal(store.edgesTo(orphanId).length, 0);

  const r = reconstructPaths(store, orphanId);
  assert.deepEqual(r.paths, []);
  assert.equal(r.truncated, false, 'no budget was hit — this is not a truncation');
  assert.equal(r.noPathReason, 'incomplete-record',
    'but it is NOT proof of absence either: the store itself knows the recording is incomplete here');
  assert.equal(isIncompleteAnswer(r), true, 'AC-10: the banner fires — the scope really is incomplete');

  // And a path that WALKS INTO that node terminates as `incomplete-record`,
  // never as a complete path that appears to reach a real origin.
  const callerCtx = raw.find((h) => h.scope === byName.callerB.qid).context;
  const sink = store.nodeIdFor(returnNode(byName.callerB.qid, callerCtx, 'data:email'));
  const r2 = reconstructPaths(store, sink);
  const viaOrphan = r2.paths.filter((p) => p.terminal.nodeId === orphanId);
  assert.ok(viaOrphan.length > 0, 'a real path does reach it');
  for (const p of viaOrphan) {
    assert.equal(p.terminal.reason, 'incomplete-record');
    assert.equal(p.complete, false, 'so it is never presented as a complete source-to-sink path');
  }
  assert.equal(isIncompleteAnswer(r2), true);
});

test('C5/4d: §14.8\'s markTruncated channel reaches the reconstruction result — an analysis that was itself cut short can never yield a path that claims to be complete evidence', () => {
  const byName = parseFns('function f(a) { const b = a.email; return b; }', '/x/c5-analysis-trunc.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);
  const sink = store.nodeIdFor(returnNode(byName.f.qid, raw[0].context, 'data:email'));

  const before = reconstructPaths(store, sink);
  assert.equal(before.analysisTruncated, false);
  assert.equal(isIncompleteAnswer(before), false);

  store.markTruncated(byName.f.qid, raw[0].context, 'iter-budget');
  const after = reconstructPaths(store, sink);
  assert.equal(after.paths.length, 1, 'the path is still returned — never withheld');
  assert.equal(after.analysisTruncated, true, 'but it is labelled: the analysis behind it hit ITER_BUDGET');
  assert.equal(after.paths[0].analysisTruncated, true);
  assert.equal(isIncompleteAnswer(after), true, 'AC-10\'s banner fires on §9.5\'s truncation too, not only on C5\'s own budgets');
  assert.equal(after.truncated, false, 'and it is a DIFFERENT flag from C5\'s own path-budget truncation — the two causes stay distinguishable');
});

// =====================================================================
// 5. Deduplication (§15.6, FR-305) and prioritization (§15.7, §18.4).
// =====================================================================

test('C5/5: two paths with an IDENTICAL node sequence but different EDGES are two paths, not one — collapsing them would hide the differing program point FR-305 forbids hiding', () => {
  const src = `
    function f(user) {
      let a = user.email;
      let b = a;
      b = a;
      return b;
    }
  `;
  const byName = parseFns(src, '/x/c5-dedup.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);
  const scope = byName.f.qid;
  const ctx = raw[0].context;
  const nA = store.nodeIdFor(pathNode(scope, ctx, 'a', 'data:email'));
  const nB = store.nodeIdFor(pathNode(scope, ctx, 'b', 'data:email'));

  const parallel = store.edgesFrom(nA).filter((e) => e.toNodeId === nB);
  assert.equal(parallel.length, 2,
    'the SAME node pair really is joined by two distinct edges — two assignments at two CFG nodes (§14.5: siteNodeId is in the edge discriminator precisely so these do not collide)');
  assert.notEqual(parallel[0].line, parallel[1].line, 'and they differ in the one thing a reader would notice: the line');

  const sink = store.nodeIdFor(returnNode(scope, ctx, 'data:email'));
  const r = reconstructPaths(store, sink);
  const viaAB = r.paths.filter((p) => p.nodeIds.includes(nA) && p.nodeIds.includes(nB));
  assert.ok(viaAB.length >= 2, 'both are reconstructed as SEPARATE paths');
  const nodeSeqs = new Set(viaAB.map((p) => p.nodeIds.join('>')));
  assert.ok(nodeSeqs.size < viaAB.length,
    'PROOF: at least two of them share a node sequence — a node-keyed dedup would have collapsed them');
  const ids = new Set(viaAB.map((p) => p.id));
  assert.equal(ids.size, viaAB.length, 'but the edge-keyed pathId keeps them apart');
  // The lines a UI would show differ, which is exactly the "materially
  // different" content FR-305 says dedup may not hide.
  const lineSets = new Set(viaAB.map((p) => p.hops.map((h) => h.line).join(',')));
  assert.ok(lineSets.size >= 2, 'and the difference is user-visible');
});

test('C5/5b: within one call the DFS cannot emit the same edge sequence twice, so pathId dedup is an identity definition and a safety net — never a volume control (measured, not assumed)', () => {
  const src = `
    function ping(u) { const r = pong(u); return { a: u.email, b: r }; }
    function pong(u) { const r = ping(u); return { c: u.email, d: r }; }
    function top(user) { return ping(user); }
  `;
  const byName = parseFns(src, '/x/c5-dupcheck.js');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const { store } = record(byName.top, entryState, { byName });
  let checked = 0;
  for (const s of store.nodes()) {
    const r = reconstructPaths(store, s.id, { maxPaths: 1e6, maxPathsPerTerminal: 1e6, maxCandidatePaths: 1e6 });
    const ids = r.paths.map((p) => p.id);
    assert.equal(new Set(ids).size, ids.length, 'no duplicate pathId within one call');
    checked += r.paths.length;
  }
  assert.ok(checked > 0, `checked ${checked} reconstructed paths across every node in a cyclic fixture`);
});

test('C5/5c: pathId is a content hash — the same logical path from two independent analysis runs gets the same id', () => {
  const src = 'function f(a) { const b = a.email; return b; }';
  const byName = parseFns(src, '/x/c5-pathid.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const one = record(byName.f, entryState);
  const two = record(byName.f, entryState);
  const sinkOf = (s) => s.nodeIdFor(returnNode(byName.f.qid, one.raw[0].context, 'data:email'));
  const a = reconstructPaths(one.store, sinkOf(one.store));
  const b = reconstructPaths(two.store, sinkOf(two.store));
  assert.equal(a.paths.length, 1);
  assert.deepEqual(a.paths.map((p) => p.id), b.paths.map((p) => p.id));
  assert.match(a.paths[0].id, /^ppath:[0-9a-f]{12}$/);
});

test('C5/5d: §9.1\'s cross-join keeps its phantom alternates as SEPARATE paths and de-prioritizes them by their ambiguity marker — detect-and-mark carried all the way to the ordered output', () => {
  const src = 'function f(p, q) { const x = { a: p.email, b: q.email }; return x; }';
  const byName = parseFns(src, '/x/c5-xjoin.js');
  let es = addIdentity(emptyState(), 'p.email', 'data:email');
  es = addIdentity(es, 'q.email', 'data:email');
  const { store, raw } = record(byName.f, es);
  const scope = byName.f.qid;
  const ctx = raw[0].context;
  const sink = store.nodeIdFor(returnNode(scope, ctx, 'data:email'));

  const r = reconstructPaths(store, sink);
  assert.ok(r.paths.length >= 4, `the 2x2 cross product yields ${r.paths.length} distinct paths, all kept`);
  assert.equal(r.truncated, false, 'nothing was capped away at the default budget');

  // Every path is distinct by node sequence here — the cross-join produces
  // genuinely different routes, so nothing is collapsed.
  const seqs = new Set(r.paths.map((p) => p.nodeIds.join('>')));
  assert.equal(seqs.size, r.paths.length);

  // Ordering: any unambiguous path sorts ahead of every ambiguous one.
  const firstAmbiguousIdx = r.paths.findIndex((p) => p.ambiguousHopCount > 0);
  const lastCleanIdx = r.paths.map((p) => p.ambiguousHopCount).lastIndexOf(0);
  if (firstAmbiguousIdx !== -1 && lastCleanIdx !== -1) {
    assert.ok(lastCleanIdx < firstAmbiguousIdx, 'ambiguity-free paths come first');
  }
  // Non-decreasing ambiguity across the whole ordered list.
  for (let i = 1; i < r.paths.length; i++) {
    assert.ok(r.paths[i].ambiguousHopCount >= r.paths[i - 1].ambiguousHopCount,
      'the ordered list never puts a more-ambiguous path ahead of a less-ambiguous one');
  }
});

test('C5/5e: the cap is applied PER TERMINAL first, so one prolific source can never crowd another out of the result entirely (§15.5)', () => {
  const src = 'function f(p, q) { const x = { a: p.email, b: q.email }; return x; }';
  const byName = parseFns(src, '/x/c5-percap.js');
  let es = addIdentity(emptyState(), 'p.email', 'data:email');
  es = addIdentity(es, 'q.email', 'data:email');
  const { store, raw } = record(byName.f, es);
  const sink = store.nodeIdFor(returnNode(byName.f.qid, raw[0].context, 'data:email'));

  const full = reconstructPaths(store, sink);
  const terminals = new Set(full.paths.map((p) => p.terminal.nodeId));
  assert.ok(terminals.size >= 2, `this fixture has ${terminals.size} distinct terminals (p.email and q.email)`);

  const capped = reconstructPaths(store, sink, { maxPathsPerTerminal: 1 });
  assert.equal(capped.truncated, true);
  assert.ok(capped.truncationReasons.includes('per-terminal-cap'));
  const cappedTerminals = new Set(capped.paths.map((p) => p.terminal.nodeId));
  assert.deepEqual([...cappedTerminals].sort(), [...terminals].sort(),
    'EVERY terminal still appears — none is reported as having zero paths just because another terminal was prolific');
  // FR-305's "the UI must show a path count", per source/sink pair.
  assert.equal(capped.terminals.length, terminals.size);
  for (const t of capped.terminals) {
    assert.equal(t.returnedPathCount, 1);
    assert.ok(t.enumeratedPathCount >= t.returnedPathCount);
    assert.equal(t.truncated, t.enumeratedPathCount > t.keptPathCount);
  }
});

test('C5/5f: a purely GLOBAL cap would crowd a terminal out entirely — this is the measurement that motivated the per-terminal cap, not an assumption', () => {
  const src = 'function f(p, q) { const x = { a: p.email, b: q.email }; return x; }';
  const byName = parseFns(src, '/x/c5-globalcap.js');
  let es = addIdentity(emptyState(), 'p.email', 'data:email');
  es = addIdentity(es, 'q.email', 'data:email');
  const { store, raw } = record(byName.f, es);
  const sink = store.nodeIdFor(returnNode(byName.f.qid, raw[0].context, 'data:email'));

  const full = reconstructPaths(store, sink);
  const terminals = [...new Set(full.paths.map((p) => p.terminal.nodeId))];
  assert.ok(terminals.length >= 2);

  // Naive global-only cap: rank everything, keep the top N.
  const naive = [...full.paths].sort(comparePaths).slice(0, 2);
  const naiveTerminals = new Set(naive.map((p) => p.terminal.nodeId));

  // The shipped design's cap, at the same total size.
  const designed = reconstructPaths(store, sink, { maxPathsPerTerminal: 1, maxPaths: 2 });
  const designedTerminals = new Set(designed.paths.map((p) => p.terminal.nodeId));

  assert.equal(designedTerminals.size, terminals.length,
    'the designed cap keeps every terminal represented at N=2');
  if (process.env.C5_PRINT_TABLE) console.log(`5f: terminals=${terminals.length} naiveCovers=${naiveTerminals.size} designedCovers=${designedTerminals.size} totalPaths=${full.paths.length}`); // eslint-disable-line no-console
  assert.equal(naiveTerminals.size, 1,
    'MEASURED: a naive global-only top-N cap at N=2 returns two paths that both terminate at the SAME source, reporting the other source as having zero paths');
  assert.ok(naiveTerminals.size < designedTerminals.size,
    `naive global-only ranking covers ${naiveTerminals.size} terminal(s) at N=2 vs the designed cap's ${designedTerminals.size}`);
});

test('C5/5g: the global cap is DIVERSITY-first — at a cap smaller than the bucket count it spans distinct path SHAPES rather than filling up from one bucket (§18.4: "prioritize paths that DIFFER in boundary…")', () => {
  const src = `
    function helper(u) { return u.email; }
    function f(a, b) { const o = { r: helper(a), s: b.email }; return o; }
  `;
  const byName = parseFns(src, '/x/c5-diverse.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.email', 'data:email');
  const { store, raw } = record(byName.f, entryState, { byName });
  const scope = byName.f.qid;
  const ctx = raw.find((h) => h.subKind === 'call-resolved').context;
  const sink = store.nodeIdFor(returnNode(scope, ctx, 'data:email'));

  const full = reconstructPaths(store, sink, { maxPaths: 1e6, maxPathsPerTerminal: 1e6 });
  const shapes = new Set(full.paths.map((p) => p.shape));
  assert.ok(full.paths.length > 2, `the fixture yields ${full.paths.length} paths`);
  assert.ok(shapes.size >= 2, `spanning ${shapes.size} distinct shapes: ${JSON.stringify([...shapes])}`);
  assert.ok(full.paths.some((p) => p.crossScopeCount > 0), 'at least one path crosses a function boundary');
  assert.ok(full.paths.some((p) => p.crossScopeCount === 0), 'and at least one stays local — a genuine boundary difference');

  if (process.env.C5_PRINT_TABLE) console.log(`5g: paths=${full.paths.length} shapes=${shapes.size} ${JSON.stringify([...shapes])}`); // eslint-disable-line no-console
  const n = shapes.size;
  const capped = reconstructPaths(store, sink, { maxPaths: n, maxPathsPerTerminal: 1e6 });
  assert.equal(capped.paths.length, n);
  assert.equal(capped.truncated, true, 'and the caller is told the list was capped');
  assert.ok(capped.truncationReasons.includes('path-cap'));
  assert.equal(new Set(capped.paths.map((p) => p.shape)).size, n,
    'the retained set spans EVERY shape — a plain top-N by rank does not guarantee this');
});

// =====================================================================
// 6. The read-API sufficiency question (§15.9) and the isolation boundary.
// =====================================================================

test('C5/6: the whole design needs nothing from PathStore that PathStore does not already export — no `_`-prefixed access anywhere in the prototype', () => {
  // Every read the prototype performs, exercised explicitly against the
  // public API. If any of these needed a private field, `path-store.js`
  // would have to change; none does.
  const byName = parseFns('function f(a) { const b = a.email; return b; }', '/x/c5-api.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const { store, raw } = record(byName.f, entryState);
  const sink = store.nodeIdFor(returnNode(byName.f.qid, raw[0].context, 'data:email'));

  assert.ok(store.getNode(sink), 'getNode — start-node existence');
  assert.ok(Array.isArray(store.edgesTo(sink)), 'edgesTo — the traversal primitive');
  assert.ok(Array.isArray(store.nodes()), 'nodes — the sinkCandidates stand-in');
  assert.ok(store.getEdge(store.edges()[0].id), 'getEdge — hop round-trip');
  assert.ok(Array.isArray(store.diagnostics().orphanedPeerSources), 'diagnostics — the incomplete-record signal');
  assert.equal(typeof store.stats().nodes, 'number');

  const srcText = reconstructPaths.toString() + materialize.toString() + sinkCandidates.toString() + hopOf.toString();
  assert.equal(/store\._/.test(srcText), false, 'the prototype never touches a private PathStore field');
});

// =====================================================================
// 7. §15.11's measured-numbers table. Every row of the published table is
//    produced HERE, by running this test, and asserted so a future
//    refactor that changes a published number fails rather than silently
//    leaving the design doc stale (C4's `C4/1b`/`C4/4` precedent).
// =====================================================================

const MEASURE = [
  {
    name: 'simple chain: `const b = a.email; return b;`',
    src: 'function f(a) { const b = a.email; return b; }',
    fn: 'f', seed: [['a.email', 'data:email']], interproc: false,
    expect: { sinks: 1, enumerated: 1, complete: 1, maxHops: 2, expansions: 2, clipped: 0 },
  },
  {
    name: "§6's worked example (2 fields, object literal)",
    src: 'function f(user) { const u = user; const o = { email: u.email, ssn: u.ssn }; return o; }',
    fn: 'f', seed: [['user.email', 'data:email'], ['user.ssn', 'data:ssn']], interproc: false,
    expect: { sinks: 2, enumerated: 2, complete: 2, maxHops: 3, expansions: 6, clipped: 0 },
  },
  {
    name: '2-function resolved call',
    src: 'function helper(u) { return u.email; } function caller(a) { const out = helper(a); return out; }',
    fn: 'caller', seed: [['a.email', 'data:email']], interproc: true,
    expect: { sinks: 2, enumerated: 3, complete: 3, maxHops: 4, expansions: 7, clipped: 0 },
  },
  {
    name: "§9.1's cross-join (`{a: p.email, b: q.email}`)",
    src: 'function f(p, q) { const x = { a: p.email, b: q.email }; return x; }',
    fn: 'f', seed: [['p.email', 'data:email'], ['q.email', 'data:email']], interproc: false,
    expect: { sinks: 1, enumerated: 4, complete: 4, maxHops: 2, expansions: 6, clipped: 0 },
  },
  {
    name: "§14.7's leg counter-example (`{r: helper(a), s: b.email}`)",
    src: 'function helper(u) { return u.email; } function f(a, b) { const o = { r: helper(a), s: b.email }; return o; }',
    fn: 'f', seed: [['a.email', 'data:email'], ['b.email', 'data:email']], interproc: true,
    expect: { sinks: 3, enumerated: 11, complete: 11, maxHops: 4, expansions: 18, clipped: 0 },
  },
  {
    name: 'mutual recursion (`ping`/`pong`/`top`) — the cyclic DAG',
    src: 'function ping(u) { const r = pong(u); return { a: u.email, b: r }; } function pong(u) { const r = ping(u); return { c: u.email, d: r }; } function top(user) { return ping(user); }',
    fn: 'top', seed: [['user.email', 'data:email']], interproc: true,
    expect: { sinks: 4, enumerated: 13, complete: 9, maxHops: 6, expansions: 35, clipped: 7 },
  },
];

test('C5/M: §15.11\'s measured-numbers table, produced by running every fixture rather than estimated', () => {
  const rows = [];
  for (const m of MEASURE) {
    const byName = parseFns(m.src, `/x/c5-measure-${m.fn}.js`);
    let es = emptyState();
    for (const [p, id] of m.seed) es = addIdentity(es, p, id);
    const { store } = record(byName[m.fn], es, m.interproc ? { byName } : {});

    const sinks = sinkCandidates(store);
    let enumerated = 0; let complete = 0; let maxHops = 0; let expansions = 0; let clipped = 0;
    for (const s of sinks) {
      const r = reconstructPaths(store, s.id, { maxPaths: 1e6, maxPathsPerTerminal: 1e6, maxCandidatePaths: 1e6 });
      assert.equal(r.truncated, false, `${m.name}: an unbounded run must not report truncation`);
      enumerated += r.enumeratedPathCount;
      complete += r.completePathCount;
      expansions += r.budget.expansionsUsed;
      clipped += r.cyclesClipped;
      for (const p of r.paths) maxHops = Math.max(maxHops, p.hopCount);
    }
    const got = { sinks: sinks.length, enumerated, complete, maxHops, expansions, clipped };
    rows.push([m.name, got]);
    if (process.env.C5_PRINT_TABLE) console.log(`RAW ${m.name} -> ${JSON.stringify(got)}`); // eslint-disable-line no-console
    else assert.deepEqual(got, m.expect, `${m.name}: §15.11's published row`);
  }
  if (process.env.C5_PRINT_TABLE) {
    for (const [name, got] of rows) {
      // eslint-disable-next-line no-console
      console.log(`| ${name} | ${got.sinks} | ${got.enumerated} | ${got.complete} | ${got.enumerated - got.complete} | ${got.maxHops} | ${got.expansions} | ${got.clipped} |`);
    }
  }
});
