//
// path-query.js — bounded backward-reconstruction query (Sub-project C,
// increment 5).
//
// Binding spec: DESIGN_PATH_PROVENANCE.md §15 (§15.1-§15.11; design + PoC
// landed as Task 1, this is Task 2, the mechanical implementation). This
// module is a PURE CONSUMER of a built `PathStore` (Sub-project C,
// increment 4) — it never sees a hop record, C4 already turned those into a
// DAG. It must NEVER import `engine.js`, `summaries.js`, or `driver.js`
// (§15.1, the same boundary §14.1 established for `path-store.js`), and it
// consumes `PathStore` ONLY through its public read API — never a
// `_`-prefixed field. Its only import is `ids.js`, for `pathId`.
//
// The backward walk is an ITERATIVE DFS over an explicit stack — never
// recursion (§15.3): the DAG can genuinely be cyclic (§9.3, proven by
// `path-store.test.js`'s own mutual-recursion fixture), and this module's
// whole job is graph TRAVERSAL, unlike `path-store.js`'s own single linear
// pass. Cycle safety comes from an explicit PER-PATH visited set (never a
// global one — the SAME node can legitimately appear on two different
// candidate paths), not from any budget; the budgets exist to bound WORK
// and OUTPUT size, not to be the thing that makes the walk terminate.
//

import { pathId } from './ids.js';

/**
 * All `opts`-overridable. Two-plus orders of magnitude above what every
 * fixture measured in the design task's PoC needs (§15.11's largest row
 * uses 35 expansions) — deliberately UNCALIBRATED (§15.3): nothing bigger
 * than a hand-built fixture is measurable until a driver run emits real
 * hops (Sub-projects D/E). A starting point to re-measure then, not a
 * tuned result.
 */
export const DEFAULTS = {
  maxPaths: 32,
  maxPathsPerTerminal: 8,
  maxCandidatePaths: 256,
  maxExpansions: 10000,
  maxDepth: 64,
};

// §15.4's terminal-reason vocabulary. Only 'origin' means "this really is
// where the recorded flow starts" (`complete: true`). 'expansion-budget'
// and 'candidate-cap' are deliberately NOT terminal reasons — see the loop
// below; those two branches are abandoned, never emitted as a marked
// partial path.
const TERMINAL_ORIGIN = 'origin';
const TERMINAL_INCOMPLETE = 'incomplete-record';
const TERMINAL_CYCLE = 'cycle';
const TERMINAL_DEPTH = 'depth-limit';

/**
 * §15.9's stand-in for Sub-project D's source/sink registry, which does not
 * exist yet. NOT a registry: it returns every structurally terminal node
 * kind (`return`/`escape`/`loss`), with no notion of whether any of them is
 * a security-relevant sink — that judgment belongs to Sub-project D's
 * eventual registry. Named `sinkCandidates`, not `sinks`, for the same
 * reason `reconstructPaths`' own parameter is `startNodeId` rather than
 * `sinkNodeId`: it is a structural filter with no security opinion.
 */
export function sinkCandidates(store) {
  return store.nodes().filter((n) => n.kind === 'return' || n.kind === 'escape' || n.kind === 'loss');
}

/**
 * Denormalizes one edge into a path hop — §15.2's grading material carried
 * INLINE, not just the edge id. A path that cannot be graded without also
 * carrying the store is a poor hand-off to C6, Sub-project E's graph
 * builder, and Milestone 3's API.
 */
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

/**
 * Source-first materialization of one enumerated DFS branch (§15.2). The
 * walk itself runs sink-first (backward from `startNodeId`); a human reads
 * a flow source -> sink, so the arrays are reversed here, once, at the
 * point a candidate is emitted.
 */
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
    // §15.2: a connected walk is field-precise BY CONSTRUCTION — every edge
    // `path-store.js` builds joins two nodes whose descriptors both take
    // `dataElementId` from the same hop (§14.3) — so this needs no
    // filtering, only reading off the first hop.
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
    // DELIBERATELY absent — Sub-project D / Milestone 2 own them; using
    // today's widen/loss reasons as a stand-in for either would be
    // inventing vocabulary that isn't backed by data.
    shape: [
      terminalReason === TERMINAL_ORIGIN ? 'complete' : 'partial',
      crossScopeCount > 0 ? 'boundary' : 'local',
      widenedHopCount > 0 ? 'widened' : 'explicit',
      lossHopCount > 0 ? 'lossy' : 'intact',
      ambiguousHopCount > 0 ? 'ambiguous' : 'correlated',
    ].join('/'),
  };
}

/**
 * §15.7's total order over reconstructed paths. Deterministic: the final
 * key is the content-hash id, so no tie is ever left to insertion order.
 * Exported, not merely internal (§15.10 item 11b, fix round 1's own
 * correction to the original design's export list) — the shipped tests
 * call it directly to build the naive-global-cap contrast fixture.
 */
export function comparePaths(a, b) {
  if (a.complete !== b.complete) return a.complete ? -1 : 1;
  if (a.ambiguousHopCount !== b.ambiguousHopCount) return a.ambiguousHopCount - b.ambiguousHopCount;
  if (a.lossHopCount !== b.lossHopCount) return a.lossHopCount - b.lossHopCount;
  if (a.widenedHopCount !== b.widenedHopCount) return a.widenedHopCount - b.widenedHopCount;
  if (a.crossScopeCount !== b.crossScopeCount) return b.crossScopeCount - a.crossScopeCount;
  if (a.hopCount !== b.hopCount) return a.hopCount - b.hopCount;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * §15.3's bounded backward walk from `startNodeId`, deliberately not named
 * `sinkNodeId` (there is no sink registry — see `sinkCandidates` above;
 * once Sub-project D lands, the caller supplies a registered sink here and
 * nothing about the signature changes). Iterative — an explicit stack,
 * never recursion — cycle-safe by a PER-PATH visited set, and bounded by
 * four independent budgets plus the two post-hoc caps below.
 *
 * Returns a `ReconstructionResult`: §15.4's five pairwise-distinguishable
 * answers, so a truncated result can NEVER be mistaken for "no path exists"
 * (§18.4's single most load-bearing constraint).
 */
export function reconstructPaths(store, startNodeId, opts = {}) {
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
  // about something that is not in this store". §15.4 keeps the two apart,
  // because collapsing them is §18.4's failure mode wearing a different hat.
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
    // §15.3's exact ordering constraint: the zero-in-edges check above MUST
    // run BEFORE this depth check. A node with no predecessors is a genuine
    // origin no matter how deep the walk is, so a path that reaches one is
    // `complete: true` even at `maxDepth: 1`. Only a branch the LIMIT
    // stopped is marked partial.
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
      // §15.5's own corrected rule: a sorted UNION over the terminal's own
      // paths, never a positional pick — a terminal can genuinely carry
      // MIXED reasons (e.g. one sink reached by both a `cycle` clip and a
      // `depth-limit` stop), and picking `group[0]`'s reason would make the
      // answer depend on DFS enumeration order.
      terminalReasons: [...new Set(group.map((p) => p.terminal.reason))].sort(),
      enumeratedPathCount: group.length,
      keptPathCount: take.length,
      // Filled in AFTER the global cap runs, below. Computing `truncated`
      // here — from the per-terminal cap alone — would report `false` for a
      // terminal the GLOBAL cap later starves to zero returned paths. This
      // is §15.5's fix round 1, finding 1 (BLOCKING): the single most
      // load-bearing correctness property in this module.
      returnedPathCount: 0,
      droppedPathCount: 0,
      truncated: false,
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
  // §15.5's corrected formula, computed AFTER the global round-robin above,
  // never from the per-terminal cap alone: `enumerated > returned` is the
  // only definition that covers both caps. `droppedPathCount` makes the
  // count explicit per pair the way `result.droppedPathCount` does per
  // call, and the two always sum consistently — a consumer can never be
  // told two different stories.
  for (const t of terminals) {
    t.returnedPathCount = returned.filter((p) => p.terminal.nodeId === t.nodeId).length;
    t.droppedPathCount = t.enumeratedPathCount - t.returnedPathCount;
    t.truncated = t.droppedPathCount > 0;
  }
  result.terminals = terminals;

  result.truncated = truncationReasons.size > 0 || result.droppedPathCount > 0;
  result.truncationReasons = [...truncationReasons].sort();

  if (result.paths.length === 0 && !result.truncated) {
    // The one place a genuinely empty answer is produced — and it says
    // WHICH kind of empty it is. This ordering IS §18.4's own load-bearing
    // constraint expressed as a code path: `noPathReason` is computed ONLY
    // when `truncated === false`, so a truncated result can never acquire a
    // `noPathReason` — never a stylistic choice.
    result.noPathReason = orphaned.has(startNodeId) ? TERMINAL_INCOMPLETE : 'no-incoming-edges';
  }
  return result;
}

/**
 * AC-10's persistent partial-coverage banner predicate — §15.4's five-term
 * disjunction, exported so no caller re-derives it (and no caller forgets a
 * term).
 */
export function isIncompleteAnswer(result) {
  return result.truncated || result.unknownStartNode || result.analysisTruncated
    || result.noPathReason === TERMINAL_INCOMPLETE
    || result.paths.some((p) => !p.complete);
}
