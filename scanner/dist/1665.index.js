export const id = 1665;
export const ids = [1665,4547];
export const modules = {

/***/ 61665:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   planCuts: () => (/* binding */ planCuts)
/* harmony export */ });
/* unused harmony exports UNCUTTABLE, CONTROL_SEMANTICS, maxFlowMinCut, screenCandidates, buildCutNetwork, candidatesToOperations, validateCutSet, planSharedControls */
/* harmony import */ var _scenario_engine_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(24547);
// cut-planner.js — DAG-09: graph cuts and control-placement planning.
//
// Pure module. Given a DataFlowGraph v1 and a set of CANDIDATE control
// locations (each with semantics, owner, estimated cost and feasibility),
// it builds a query-specific source-to-sink flow network, computes a
// minimum-cost cut with iterative Dinic max-flow (no recursion; cycles are
// fine), and validates the proposed set by applying it as a hypothetical
// scenario through scenario-engine.js's `applyScenario` and searching the
// RESULT graph for remaining bypasses.
//
// What this module is and is not:
//   - Every placement it returns is HYPOTHETICAL. Nothing here reads or
//     writes remediation state, and this module deliberately does not
//     import remediation.js: only a real rescan feeding the existing
//     verification gate (scan_verification / manual_attestation) can ever
//     move a remediation item to `verified`. Results carry `verified:false`.
//   - The cut is exact only for the finite, fixed-capacity network it
//     builds from the MODELED edge set. Multi-query shared-control planning
//     (`planSharedControls`) is a greedy weighted set cover and is labelled
//     approximate; it makes no optimality claim.
//   - A cut certificate is derived from the full modeled edge set
//     (graph.edges), never from a capped display-path list. When the graph
//     is not known to be complete (coverage.analysisCompletion absent or
//     not complete, or non-modeled nodes inside the network) the result is
//     scoped to the modeled subgraph and `totalCoverage` is 'unknown'.
//   - Controls are modelled only as the scenario engine can express them:
//     transit protection or handling on an edge, or removal of an entity.
//     A node control is vertex-split: it guards every path through the node.



/** Capacity standing in for "no feasible control here" (cannot be cut). */
const UNCUTTABLE = 1e12;
const MAX_COST = 1e6;
const EPS = 1e-9;

const CONTROL_SEMANTICS = Object.freeze([
  'transit_protection', 'handling', 'remove_entity',
]);

// ── Max-flow / min-cut (Dinic, iterative) ─────────────────────────────────

/**
 * Max-flow on `n` vertices (0..n-1) with directed `arcs` of
 * `{from, to, cap}`. Returns `{maxFlow, reachable, cutArcs}` where
 * `cutArcs` are indices into `arcs` crossing the source-side residual
 * reachable set (a minimum cut). Iterative; handles cycles and parallel arcs.
 */
function maxFlowMinCut(n, arcs, s, t) {
  const head = new Array(n).fill(-1);
  const to = []; const cap = []; const next = [];
  const arcEdge = [];
  const addEdge = (u, v, c) => {
    to.push(v); cap.push(c); next.push(head[u]); head[u] = to.length - 1;
    to.push(u); cap.push(0); next.push(head[v]); head[v] = to.length - 1;
  };
  arcs.forEach((a, i) => { arcEdge[i] = to.length; addEdge(a.from, a.to, a.cap); });

  let flow = 0;
  if (s === t) return { maxFlow: 0, reachable: new Array(n).fill(false), cutArcs: [] };
  const level = new Array(n);
  for (;;) {
    level.fill(-1);
    level[s] = 0;
    const queue = [s];
    for (let qi = 0; qi < queue.length; qi++) {
      const u = queue[qi];
      for (let e = head[u]; e !== -1; e = next[e]) {
        if (cap[e] > EPS && level[to[e]] < 0) { level[to[e]] = level[u] + 1; queue.push(to[e]); }
      }
    }
    if (level[t] < 0) break;
    const it = head.slice();
    const stack = [];
    let u = s;
    blocking: for (;;) {
      while (u !== t) {
        let advanced = false;
        for (; it[u] !== -1; it[u] = next[it[u]]) {
          const e = it[u];
          if (cap[e] > EPS && level[to[e]] === level[u] + 1) { stack.push(e); u = to[e]; advanced = true; break; }
        }
        if (!advanced) {
          if (u === s) break blocking;
          level[u] = -1; // dead end
          const e = stack.pop();
          u = to[e ^ 1];
          it[u] = next[it[u]];
        }
      }
      let b = Infinity;
      for (const e of stack) if (cap[e] < b) b = cap[e];
      for (const e of stack) { cap[e] -= b; cap[e ^ 1] += b; }
      flow += b;
      stack.length = 0;
      u = s;
    }
  }
  const reachable = new Array(n).fill(false);
  reachable[s] = true;
  const q = [s];
  for (let qi = 0; qi < q.length; qi++) {
    const u = q[qi];
    for (let e = head[u]; e !== -1; e = next[e]) {
      if (cap[e] > EPS && !reachable[to[e]]) { reachable[to[e]] = true; q.push(to[e]); }
    }
  }
  const cutArcs = [];
  arcs.forEach((a, i) => {
    if (a.cap > 0 && reachable[a.from] && !reachable[a.to]) cutArcs.push(i);
  });
  return { maxFlow: flow, reachable, cutArcs };
}

// ── Candidates ────────────────────────────────────────────────────────────

function _locKey(loc) { return `${loc.type}:${loc.id}`; }

/**
 * Normalizes and screens candidate interventions. A candidate:
 *   { id?, location: {type:'edge'|'node', id}, semantics, owner, cost,
 *     feasible?, disallowed?, families?, handling? }
 * Returns {eligible: Map<locKey, candidate>, excluded: [{candidate, reason}]}.
 * Eligible = valid shape, feasible, not disallowed, family-compatible.
 */
function screenCandidates(candidates, query = {}) {
  const excluded = [];
  const best = new Map();
  for (const raw of candidates ?? []) {
    const c = raw && typeof raw === 'object' ? raw : {};
    const loc = c.location;
    const reject = (reason) => excluded.push({ candidate: raw, reason });
    if (!loc || (loc.type !== 'edge' && loc.type !== 'node') || typeof loc.id !== 'string' || !loc.id) {
      reject('location must be {type: edge|node, id}'); continue;
    }
    if (!CONTROL_SEMANTICS.includes(c.semantics)) { reject(`semantics must be one of ${CONTROL_SEMANTICS.join('|')}`); continue; }
    if (c.semantics === 'remove_entity' && loc.type !== 'node') { reject('remove_entity applies to a node location'); continue; }
    if (typeof c.owner !== 'string' || !c.owner) { reject('owner is required'); continue; }
    if (typeof c.cost !== 'number' || !Number.isFinite(c.cost) || c.cost <= 0 || c.cost > MAX_COST) {
      reject(`cost must be a finite number in (0, ${MAX_COST}]`); continue;
    }
    if (c.disallowed === true) { reject('intervention site is disallowed'); continue; }
    if (c.feasible === false) { reject('intervention is marked infeasible'); continue; }
    if (query.family && Array.isArray(c.families) && c.families.length > 0 && !c.families.includes(query.family)) {
      reject(`control does not support rule family "${query.family}"`); continue;
    }
    const cand = { ...c, id: c.id ?? `cand:${_locKey(loc)}:${c.semantics}` };
    const key = _locKey(loc);
    const cur = best.get(key);
    if (!cur || cand.cost < cur.cost || (cand.cost === cur.cost && cand.id < cur.id)) best.set(key, cand);
  }
  return { eligible: best, excluded };
}

// ── Network construction ──────────────────────────────────────────────────

function _edgePreProtected(e) {
  const p = e.protection;
  if (!p) return false;
  return ['transit', 'atRest', 'handling'].some((d) => p[d]?.verdict === 'protected');
}

function _assessCompleteness(graph, usedNodeIds) {
  const reasons = [];
  const ac = graph.coverage?.analysisCompletion ?? graph.scanHealth?.analysisCompletion;
  if (ac === undefined || ac === null) reasons.push('graph carries no analysisCompletion field, so completeness is unknown');
  else if (!(ac === 'complete' || ac === 'full' || ac === true || ac === 1)) reasons.push(`analysisCompletion is ${JSON.stringify(ac)}`);
  const unresolved = graph.coverage?.unresolvedDestinations;
  if (typeof unresolved === 'number' && unresolved > 0) reasons.push(`${unresolved} unresolved destination(s)`);
  let nonModeled = 0;
  for (const n of graph.nodes ?? []) {
    if (usedNodeIds.has(n.id) && n.coverageStatus !== undefined && n.coverageStatus !== 'modeled') nonModeled++;
  }
  if (nonModeled > 0) reasons.push(`${nonModeled} network node(s) are not fully modeled`);
  const complete = reasons.length === 0;
  return {
    complete,
    totalCoverage: complete ? 'modeled-complete' : 'unknown',
    reasons,
  };
}

/**
 * Builds the query-specific network. Query (all optional):
 *   dataElementIds | dataElementNames  restrict SOURCES/SINKS to flows that carry them
 *   sources / sinks                    explicit node ids
 *   trustBoundary {from, to}           node.trustZone values for sources / sinks
 *   nodeIds                            restrict the network to these nodes
 *   family                             rule family (filters candidates)
 * Edges always come from the full graph.edges set, never a capped path list.
 */
function buildCutNetwork(graph, query = {}, candidates = []) {
  const limitations = [];
  const nodes = graph.nodes ?? [];
  const allowed = query.nodeIds ? new Set(query.nodeIds) : null;
  const nodeIds = nodes.map((n) => n.id).filter((id) => !allowed || allowed.has(id));
  const idx = new Map(nodeIds.map((id, i) => [id, i]));
  const N = nodeIds.length;
  const IN = (i) => 2 * i; const OUT = (i) => 2 * i + 1;
  const S = 2 * N; const T = 2 * N + 1;

  const { eligible, excluded } = screenCandidates(candidates, query);

  // Sources and sinks.
  let deIds = null;
  if (query.dataElementIds || query.dataElementNames) {
    deIds = new Set(query.dataElementIds ?? []);
    for (const de of graph.dataElements ?? []) {
      if (query.dataElementNames?.includes(de.name)) deIds.add(de.id);
    }
  }
  const carrying = (graph.flows ?? []).filter((f) => !deIds || (f.dataElementIds ?? []).some((d) => deIds.has(d)));
  if (deIds && carrying.some((f) => (f.alternatePathCount ?? 0) > 0)) {
    limitations.push('data-element restriction narrows sources and sinks only; edges come from the full modeled edge set because flow path lists may hide alternates');
  }
  let sourceIds = query.sources ?? [...new Set(carrying.map((f) => f.source))];
  let sinkIds = query.sinks ?? [...new Set(carrying.map((f) => f.sink))];
  if (query.trustBoundary) {
    const { from, to } = query.trustBoundary;
    const zone = new Map(nodes.map((n) => [n.id, n.trustZone]));
    if (from) sourceIds = nodeIds.filter((id) => zone.get(id) === from);
    if (to) sinkIds = nodeIds.filter((id) => zone.get(id) === to);
    if (nodes.every((n) => n.trustZone === undefined)) limitations.push('trust boundary requested but no node carries trustZone; no sources or sinks matched');
  }
  sourceIds = sourceIds.filter((id) => idx.has(id)).sort();
  sinkIds = sinkIds.filter((id) => idx.has(id)).sort();

  const arcs = [];
  const arcLoc = []; // parallel to arcs: {type,id} or null for structural arcs
  const addArc = (from, to, cap, loc) => { arcs.push({ from, to, cap }); arcLoc.push(loc); };

  nodeIds.forEach((id, i) => {
    const cand = eligible.get(`node:${id}`);
    addArc(IN(i), OUT(i), cand ? cand.cost : UNCUTTABLE, { type: 'node', id });
  });

  const existingControls = [];
  let skippedEdges = 0;
  for (const e of [...(graph.edges ?? [])].sort((a, b) => (a.id < b.id ? -1 : 1))) {
    if (!idx.has(e.from) || !idx.has(e.to)) { if (!allowed) skippedEdges++; continue; }
    if (_edgePreProtected(e)) { existingControls.push(e.id); continue; }
    const cand = eligible.get(`edge:${e.id}`);
    addArc(OUT(idx.get(e.from)), IN(idx.get(e.to)), cand ? cand.cost : UNCUTTABLE, { type: 'edge', id: e.id });
  }
  if (skippedEdges > 0) limitations.push(`${skippedEdges} edge(s) reference nodes missing from the graph and were not modeled`);
  for (const id of sourceIds) addArc(S, IN(idx.get(id)), UNCUTTABLE, null);
  for (const id of sinkIds) addArc(OUT(idx.get(id)), T, UNCUTTABLE, null);

  const usedNodeIds = new Set(nodeIds);
  return {
    nodeIds, idx, arcs, arcLoc, S, T, sourceIds, sinkIds,
    eligible, excludedCandidates: excluded, existingControls, limitations,
    completeness: _assessCompleteness(graph, usedNodeIds),
    edgeCount: arcs.filter((_, i) => arcLoc[i]?.type === 'edge').length,
  };
}

// Reachability (BFS) in the network with `removed` locations cut. Returns
// parent map for witness paths. Iterative.
function _reach(net, removedLocKeys, onlySink = null) {
  const adj = new Map();
  net.arcs.forEach((a, i) => {
    const loc = net.arcLoc[i];
    if (loc && removedLocKeys.has(_locKey(loc))) return;
    if (!adj.has(a.from)) adj.set(a.from, []);
    adj.get(a.from).push({ to: a.to, loc });
  });
  const parent = new Map([[net.S, null]]);
  const queue = [net.S];
  for (let qi = 0; qi < queue.length; qi++) {
    const u = queue[qi];
    for (const nx of adj.get(u) ?? []) {
      if (!parent.has(nx.to)) { parent.set(nx.to, { prev: u, loc: nx.loc }); queue.push(nx.to); }
    }
  }
  const sinkReach = net.sinkIds.filter((id) => parent.has(2 * net.idx.get(id) + 1));
  return { parent, reachableSinks: onlySink ? sinkReach.filter((s) => s === onlySink) : sinkReach };
}

function _witness(net, parent, sinkId) {
  const nodePath = []; const edgePath = [];
  let cur = 2 * net.idx.get(sinkId) + 1;
  while (cur !== net.S && cur !== undefined) {
    const p = parent.get(cur);
    if (!p) break;
    if (p.loc?.type === 'edge') edgePath.push(p.loc.id);
    const v = cur >> 1;
    if (cur < 2 * net.nodeIds.length && (nodePath.length === 0 || nodePath[nodePath.length - 1] !== net.nodeIds[v])) nodePath.push(net.nodeIds[v]);
    cur = p.prev;
  }
  return { nodes: nodePath.reverse(), edges: edgePath.reverse() };
}

// ── Scenario mapping ──────────────────────────────────────────────────────

/** Translate chosen candidates into scenario-engine operations. */
function candidatesToOperations(graph, candidates) {
  const ops = [];
  for (const c of candidates) {
    const { type, id } = c.location;
    if (type === 'edge') {
      if (c.semantics === 'transit_protection') ops.push({ kind: 'require_transit_protection', targetEdgeId: id });
      else if (c.semantics === 'handling') ops.push({ kind: 'apply_handling', targetEdgeId: id, handling: c.handling ?? 'sanitized' });
      continue;
    }
    if (c.semantics === 'remove_entity') { ops.push({ kind: 'remove_entity', targetNodeId: id }); continue; }
    // Node control: guards every path through the node, so apply it to the
    // edges a path must use to pass the node (out-edges of a source node,
    // in-edges otherwise).
    const node = (graph.nodes ?? []).find((n) => n.id === id);
    const isSource = node?.kind === 'source';
    for (const e of graph.edges ?? []) {
      if (isSource ? e.from !== id : e.to !== id) continue;
      if (c.semantics === 'transit_protection') ops.push({ kind: 'require_transit_protection', targetEdgeId: e.id });
      else ops.push({ kind: 'apply_handling', targetEdgeId: e.id, handling: c.handling ?? 'sanitized' });
    }
  }
  return ops;
}

// ── Validation through the scenario engine ────────────────────────────────

/**
 * Validates a proposed set of candidates by applying it as a hypothetical
 * scenario and searching the RESULT graph for remaining source-to-sink
 * paths over the full modeled edge set. Returns residual witness paths
 * (display-capped, with the exact reachable-sink count alongside), the
 * certificate, limitations and modeled coverage. Never changes remediation
 * state; `verified` is always false.
 */
function validateCutSet(graph, query, chosen, opts = {}) {
  const maxPaths = opts.maxResidualPaths ?? 10;
  const limitations = [];
  const ops = candidatesToOperations(graph, chosen);
  let scenarioGraph = graph;
  let skippedOperations = [];
  if (ops.length > 0) {
    try {
      const r = (0,_scenario_engine_js__WEBPACK_IMPORTED_MODULE_0__.applyScenario)(graph, { operations: ops }, opts.scenarioOpts ?? {});
      scenarioGraph = r.graph; skippedOperations = r.skippedOperations;
    } catch (e) {
      limitations.push(`scenario engine could not apply the proposed controls: ${e.message}`);
    }
  }
  for (const s of skippedOperations) limitations.push(`scenario operation skipped: ${s.reason}`);

  // Rebuild the network on the scenario graph with NO candidates: any edge
  // the scenario protected is dropped as a pre-existing control, any removed
  // entity is gone, so what remains is exactly the bypass surface.
  const net = buildCutNetwork(scenarioGraph, query, []);
  const { parent, reachableSinks } = _reach(net, new Set());
  const residualPaths = reachableSinks.slice(0, maxPaths).map((s) => ({ sink: s, ..._witness(net, parent, s) }));
  const bypassFound = reachableSinks.length > 0;

  return {
    hypothetical: true,
    verified: false,
    bypassFound,
    residualSinkCount: reachableSinks.length,
    residualPaths,
    residualPathsTruncated: reachableSinks.length > maxPaths,
    appliedOperationCount: ops.length - skippedOperations.length,
    skippedOperations,
    certificate: {
      kind: 'all-modeled-paths',
      basis: 'full modeled edge set of the scenario graph',
      usedDisplayPathList: false,
      modeledEdgeCount: (scenarioGraph.edges ?? []).length,
      allModeledPathsCut: !bypassFound,
      totalCoverage: net.completeness.totalCoverage,
      scope: net.completeness.complete ? 'complete-modeled-graph' : 'modeled-subgraph-only',
    },
    completeness: net.completeness,
    limitations: [...limitations, ...net.limitations],
  };
}

// ── Planner ───────────────────────────────────────────────────────────────

function _locationsFromCut(net, cutArcs) {
  const chosen = [];
  const infinite = [];
  for (const i of cutArcs) {
    const loc = net.arcLoc[i];
    if (!loc) { infinite.push({ type: 'structural' }); continue; }
    const cand = net.eligible.get(_locKey(loc));
    if (cand && net.arcs[i].cap < UNCUTTABLE) chosen.push(cand);
    else infinite.push(loc);
  }
  chosen.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { chosen, uncuttable: infinite };
}

/**
 * Plan a minimum-cost control placement for one query.
 * status: 'complete-cut' | 'partial' | 'no-flow' | 'no-feasible-cut'.
 * 'partial' means some paths cannot be cut by any eligible control; the
 * returned set is the best finite portion and the residual bypass is
 * reported explicitly. A graph that is not known complete downgrades the
 * certificate to modeled-subgraph scope with unknown total coverage.
 */
function planCuts(graph, query = {}, candidates = [], opts = {}) {
  const net = buildCutNetwork(graph, query, candidates);
  const base = {
    hypothetical: true,
    verified: false,
    query,
    network: {
      nodeCount: net.nodeIds.length, edgeCount: net.edgeCount,
      sources: net.sourceIds, sinks: net.sinkIds,
      preExistingProtectedEdges: net.existingControls,
    },
    completeness: net.completeness,
    excludedCandidates: net.excludedCandidates,
    limitations: [...net.limitations],
    note: 'Proposed control placement is hypothetical. Only a real rescan through the remediation verification gate can verify a fix.',
  };
  if (net.sourceIds.length === 0 || net.sinkIds.length === 0) {
    return { ...base, status: 'no-flow', cut: { cost: 0, controls: [] }, validation: null,
      limitations: [...base.limitations, 'query selected no sources or no sinks'] };
  }
  const { maxFlow, cutArcs } = maxFlowMinCut(net.arcs.length ? 2 * net.nodeIds.length + 2 : 2, net.arcs, net.S, net.T);
  if (maxFlow <= EPS) {
    return { ...base, status: 'no-flow', cut: { cost: 0, controls: [] },
      validation: validateCutSet(graph, query, [], opts) };
  }
  const { chosen, uncuttable } = _locationsFromCut(net, cutArcs);
  const finiteCost = chosen.reduce((a, c) => a + c.cost, 0);
  const hasUncuttable = maxFlow >= UNCUTTABLE / 2;
  const validation = validateCutSet(graph, query, chosen, opts);

  // Per-sink minimum cut cost (informational; the joint cut above is what
  // separates every sink at once).
  const perSink = net.sinkIds.map((sid) => {
    const arcs = net.arcs.filter((a) => a.to !== net.T || a.from === 2 * net.idx.get(sid) + 1);
    const r = maxFlowMinCut(2 * net.nodeIds.length + 2, arcs, net.S, net.T);
    return { sink: sid, minCutCost: r.maxFlow >= UNCUTTABLE / 2 ? null : r.maxFlow, cuttable: r.maxFlow < UNCUTTABLE / 2 };
  });

  let status;
  const limitations = [...base.limitations, ...validation.limitations];
  if (hasUncuttable || validation.bypassFound) {
    status = chosen.length ? 'partial' : 'no-feasible-cut';
    limitations.push('no complete cut exists using eligible controls; residual bypass paths are listed');
  } else {
    status = 'complete-cut';
  }
  if (!net.completeness.complete) {
    limitations.push('graph is not known complete: suggestions are scoped to the modeled subgraph and total coverage is unknown');
  }
  return {
    ...base,
    status,
    cut: { cost: finiteCost, flowValue: hasUncuttable ? null : maxFlow, controls: chosen, optimal: !hasUncuttable,
      optimality: hasUncuttable ? 'not applicable: no complete finite cut exists' : 'minimum cost for this single-query network under the declared capacities' },
    uncuttableLocations: uncuttable,
    perSink,
    validation,
    limitations,
  };
}

// ── Shared / multi-family planning (approximate) ──────────────────────────

/**
 * Greedy weighted set cover over per-query minimum cuts. Queries are
 * `{id, ...query}`. Elements are (query, sink) pairs; a set of locations
 * covers an element when removing it disconnects that sink in that query's
 * network (a control only counts in a query where it is eligible, so
 * incompatible families do not leak coverage). APPROXIMATE: no optimality
 * claim. Each selected set is then validated per query.
 */
function planSharedControls(graph, queries, candidates, opts = {}) {
  const nets = queries.map((q) => ({ q, net: buildCutNetwork(graph, q, candidates) }));
  const elements = [];
  for (const { q, net } of nets) {
    const { reachableSinks } = _reach(net, new Set());
    for (const s of reachableSinks) elements.push({ query: q.id, sink: s });
  }
  const covers = (net, locKeys, sink) => !_reach(net, locKeys, sink).reachableSinks.includes(sink);
  const eligibleKeyIn = (net, key) => net.eligible.has(key);

  // Candidate sets: per-query joint cut and per-(query,sink) cuts.
  const sets = [];
  for (const { q, net } of nets) {
    const { maxFlow, cutArcs } = maxFlowMinCut(2 * net.nodeIds.length + 2, net.arcs, net.S, net.T);
    if (maxFlow > EPS && maxFlow < UNCUTTABLE / 2) sets.push(_locationsFromCut(net, cutArcs).chosen);
    for (const sid of net.sinkIds) {
      const arcs = net.arcs.filter((a) => a.to !== net.T || a.from === 2 * net.idx.get(sid) + 1);
      const r = maxFlowMinCut(2 * net.nodeIds.length + 2, arcs, net.S, net.T);
      if (r.maxFlow > EPS && r.maxFlow < UNCUTTABLE / 2) {
        const subnet = { ...net, arcs };
        sets.push(_locationsFromCut(subnet, r.cutArcs).chosen);
      }
    }
  }
  const costOf = new Map();
  for (const s of sets) for (const c of s) costOf.set(_locKey(c.location), c);

  const coveredBy = (chosenKeys) => {
    const keys = new Set(chosenKeys);
    return elements.filter((el) => {
      const { net } = nets.find((n) => n.q.id === el.query);
      const effective = new Set([...keys].filter((k) => eligibleKeyIn(net, k)));
      return covers(net, effective, el.sink);
    });
  };

  const chosenKeys = new Set();
  let covered = [];
  for (;;) {
    let bestSet = null; let bestScore = 0; let bestCovered = covered;
    for (const s of sets) {
      const newKeys = s.map((c) => _locKey(c.location)).filter((k) => !chosenKeys.has(k));
      if (newKeys.length === 0) continue;
      const cov = coveredBy([...chosenKeys, ...newKeys]);
      const gain = cov.length - covered.length;
      if (gain <= 0) continue;
      const cost = newKeys.reduce((a, k) => a + costOf.get(k).cost, 0);
      const score = gain / cost;
      if (score > bestScore + 1e-12) { bestScore = score; bestSet = newKeys; bestCovered = cov; }
    }
    if (!bestSet) break;
    for (const k of bestSet) chosenKeys.add(k);
    covered = bestCovered;
  }

  const controls = [...chosenKeys].sort().map((k) => costOf.get(k));
  const coveredIds = new Set(covered.map((e) => `${e.query}|${e.sink}`));
  const uncovered = elements.filter((e) => !coveredIds.has(`${e.query}|${e.sink}`));
  const perQueryValidation = queries.map((q) => {
    const eligibleHere = controls.filter((c) => nets.find((n) => n.q.id === q.id).net.eligible.has(_locKey(c.location)));
    return { query: q.id, validation: validateCutSet(graph, q, eligibleHere, opts) };
  });
  return {
    hypothetical: true,
    verified: false,
    method: 'greedy weighted set cover over per-query minimum cuts',
    approximate: true,
    optimalityClaim: 'none: the result is not claimed to be globally optimal',
    controls,
    totalCost: controls.reduce((a, c) => a + c.cost, 0),
    coveredElements: covered,
    uncoveredElements: uncovered,
    perQueryValidation,
    limitations: ['approximate shared-control selection; compare against per-query plans before relying on the total'],
  };
}


/***/ }),

/***/ 24547:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   applyScenario: () => (/* binding */ applyScenario)
/* harmony export */ });
/* harmony import */ var _protection_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(80965);
/* harmony import */ var _dataflow_privacy_sink_policy_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3138);
// scenario-engine.js — M5 deliverable #3a (FR-502): the clone-and-
// override engine. Deep-clones the base graph, applies each declared
// Scenario operation, then re-runs the SAME two pure aggregators
// graph-builder.js's own real pipeline uses (aggregateVerdicts,
// isSinkPermitted) over only the flows an operation actually touched —
// never re-running the taint/path pipeline, per this sub-project's own
// scoping doc.
//
// The exact recomputation this module mirrors, confirmed by direct
// read of graph-builder.js's own real edge/flow minting pass:
//   flow.protectionSummary = aggregateVerdicts([
//     edge.protection.transit.verdict,
//     edge.protection.atRest.verdict,
//     edge.protection.handling.verdict,
//   ])
//   flow.policyVerdict = isSinkPermitted(dataElement.dataClasses, sinkNode.subtype,
//     opts.privacySinkPolicy, { environment: opts.environment, destination: sinkNode.destination?.literalValue ?? null })
//     ? 'permitted' : 'prohibited'  (or 'not_evaluated' if no policy/classes/sinkKind)




function _deepClone(v) { return JSON.parse(JSON.stringify(v)); }

function _byId(arr) { return new Map((arr ?? []).map((x) => [x.id, x])); }

// Aggregates protectionSummary across EVERY edge belonging to `flow`, not
// just one of them — a flow's `edgeIds` can in principle name more than
// one edge (graph-builder.js's own real flows are always single-edge
// today, but the schema and this module both accept a multi-edge array
// with no restriction), and aggregateVerdicts's own documented purpose is
// exactly this cross-branch/cross-edge reduction (PRD §8.4). Picking a
// single arbitrary edge here would silently go stale the moment a
// scenario is built against a genuinely multi-hop flow.
function _recomputeProtectionSummaryForFlow(flow, graph) {
  const edges = graph.edges.filter((e) => flow.edgeIds.includes(e.id));
  const verdicts = edges.flatMap((e) => [
    e.protection.transit.verdict,
    e.protection.atRest.verdict,
    e.protection.handling.verdict,
  ]);
  return (0,_protection_js__WEBPACK_IMPORTED_MODULE_0__/* .aggregateVerdicts */ .SX)(verdicts);
}

function _recomputePolicyVerdict(flow, graph, opts) {
  if (opts.privacySinkPolicy == null) return null; // signal: leave flow.policyVerdict untouched
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
  const classes = de?.dataClasses ?? [];
  const sinkKind = sinkNode?.subtype ?? null;
  if (!classes.length || !sinkKind) return 'not_evaluated';
  const ctx = {
    environment: opts.environment ?? process.env.AGENTIC_SECURITY_ENVIRONMENT ?? null,
    destination: sinkNode?.destination?.literalValue ?? null,
  };
  return (0,_dataflow_privacy_sink_policy_js__WEBPACK_IMPORTED_MODULE_1__/* .isSinkPermitted */ .i$)(classes, sinkKind, opts.privacySinkPolicy, ctx) ? 'permitted' : 'prohibited';
}

// Every flow using this edge (by edgeIds membership) gets protectionSummary
// recomputed; policyVerdict only for flows whose sink node's destination
// or the flow's own dataClasses could plausibly have changed — but since
// applyScenario always calls this after ANY node/edge touch to be safe
// (recomputation is cheap and idempotent), scope is simply "every flow
// touching this edge or this node".
function _touchedFlows(graph, { edgeId, nodeId }) {
  return graph.flows.filter((f) =>
    (edgeId && f.edgeIds.includes(edgeId)) ||
    (nodeId && (f.source === nodeId || f.sink === nodeId)));
}

function _recomputeTouchedFlows(graph, touch, opts) {
  for (const flow of _touchedFlows(graph, touch)) {
    flow.protectionSummary = _recomputeProtectionSummaryForFlow(flow, graph);
    const newPolicyVerdict = _recomputePolicyVerdict(flow, graph, opts);
    if (newPolicyVerdict !== null) flow.policyVerdict = newPolicyVerdict;
  }
}

function _applyRequireTransitProtection(graph, op) {
  const edge = _byId(graph.edges).get(op.targetEdgeId);
  if (!edge) return { ok: false, reason: `targetEdgeId "${op.targetEdgeId}" not found in graph.edges` };
  edge.protection.transit = { verdict: 'protected', evidenceGrade: 'assumed' };
  _recomputeTouchedFlows(graph, { edgeId: edge.id }, op._opts);
  return { ok: true };
}

function _applyHandling(graph, op) {
  const edge = _byId(graph.edges).get(op.targetEdgeId);
  if (!edge) return { ok: false, reason: `targetEdgeId "${op.targetEdgeId}" not found in graph.edges` };
  // Mirrors graph-builder.js's own gate (~line 757): 'encrypted' handling
  // only earns the atRest 'protected' verdict when the edge's sink node
  // is store-kind (database/file/object-storage/cache/client-storage/
  // backup/export). For any other sink kind (e.g. 'external-api',
  // 'queue') "at rest" isn't even a meaningful concept — falls through to
  // the same 'handling' dimension the non-encrypted case already sets.
  const sinkNode = graph.nodes.find((n) => n.id === edge.to);
  if (op.handling === 'encrypted' && sinkNode?.kind === 'store') {
    edge.protection.atRest = { verdict: 'protected', evidenceGrade: 'assumed' };
  } else {
    edge.protection.handling = { verdict: 'protected', evidenceGrade: 'assumed' };
  }
  _recomputeTouchedFlows(graph, { edgeId: edge.id }, op._opts);
  return { ok: true };
}

function _applyRemoveEntity(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  const removedEdgeIds = new Set(graph.edges.filter((e) => e.from === node.id || e.to === node.id).map((e) => e.id));
  graph.edges = graph.edges.filter((e) => !removedEdgeIds.has(e.id));
  graph.flows = graph.flows.filter((f) => f.source !== node.id && f.sink !== node.id
    && !f.edgeIds.some((id) => removedEdgeIds.has(id)));
  graph.nodes = graph.nodes.filter((n) => n.id !== node.id);
  // Cascade-prune graph.recipientProfiles[] too — a RecipientProfile whose
  // contributingGraphIds referenced ONLY this now-removed node must not
  // survive dangling (a downstream `dataflow export --format recipients`
  // consumer filters by exactly contributingGraphIds against surviving
  // node ids); a profile with OTHER surviving contributing ids just loses
  // this one id, never the whole record. Guarded on the array existing —
  // the base graph shape used throughout this sub-project's own tests
  // doesn't always include it. A profile with NO contributingGraphIds at
  // all (null/undefined — real graph-builder.js output always mints a
  // non-empty array, so this is defensive against a hand-built/external
  // graph only) is left untouched rather than normalized to `[]` and
  // dropped, since a missing array is not evidence the profile referenced
  // this node.
  // NOTE (final-review re-review N2, disclosed not fixed): this cascade
  // is real graph mutation, but scenario-diff.js's WATCHED_SCENARIO_FIELDS
  // has no `recipientProfile` kind, so diffScenarioGraph's own delta
  // report stays silent about a recipient record that disappeared or lost
  // a contributing id here — a future increment's fuller fix, not scope
  // creep for this pass.
  if (graph.recipientProfiles?.length) {
    graph.recipientProfiles = graph.recipientProfiles
      .map((rp) => (rp.contributingGraphIds == null ? rp
        : { ...rp, contributingGraphIds: rp.contributingGraphIds.filter((id) => id !== node.id) }))
      .filter((rp) => rp.contributingGraphIds == null || rp.contributingGraphIds.length > 0);
  }
  return { ok: true };
}

// Scoped, at the applier level, to exactly `node.destination` — this
// sub-project's own scoping doc maps "replace a provider or move region"
// onto node.destination, the graph-level equivalent of a recipient's
// technical endpoint, and nothing else. scenario.js's own
// SCENARIO_OPERATION_REQUIRED_FIELDS only requires `field` be a non-empty
// string, never restricts its value — a real applied write to any other
// top-level node field (e.g. 'subtype') would land on the node but be
// completely invisible to scenario-diff.js's WATCHED_SCENARIO_FIELDS.node
// (which only watches 'destination'/'storeDetail'), since that list can
// only stay exhaustive if this applier never writes outside it. Rejecting
// any other field here — never widening the watch list — is what keeps
// that list exhaustive by construction. Mirrors the existing "skip a
// target id it can't find" pattern: reported in skippedOperations, never
// thrown.
function _applyReplaceRecipientFact(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  if (op.field !== 'destination') {
    return { ok: false, reason: `replace_recipient_fact only supports field "destination" (got "${op.field}") — this operation is scoped to a node's recipient/destination fact only` };
  }
  node[op.field] = _deepClone(op.value);
  // The destination just changed — any edge.protection.transit verdict INTO
  // this node was derived from the OLD destination (transit-protection.js's
  // resolveTransitProtectionForSite is keyed on the sink's own destination)
  // and is now stale. Never let a stale verdict survive with a real (non-
  // 'assumed') evidence grade — reset to the honest "we don't know anymore"
  // state rather than re-derive (re-deriving needs transitEvidenceByFile,
  // IR-level data unavailable post-build) or silently keep the old verdict.
  // NOTE (final-review re-review N1, disclosed not fixed): this demotion is
  // per-EDGE and is always honest at that level (and always visible in
  // diffScenarioGraph's own delta, since edge.protection.transit is a
  // WATCHED_SCENARIO_FIELDS.edge entry) — but flow.protectionSummary
  // aggregates transit/atRest/handling via aggregateVerdicts, whose
  // precedence ranks not_assessed LAST, so a scenario that ALSO sets this
  // edge's own handling dimension to 'protected' (via apply_handling) in
  // the SAME operations list can mask the demotion at the flow-summary
  // level, even though the masking verdict itself is honestly graded
  // 'assumed'. graph-builder.js's own cross-dimension aggregation is
  // documented safe only because transit/atRest are mutually exclusive by
  // construction and handling is "never written" by any real analyzer —
  // this module (scenario-engine.js) is the one exception to that last
  // clause, which is exactly what makes the masking reachable here.
  for (const edge of graph.edges) {
    if (edge.to === node.id) {
      edge.protection.transit = { verdict: 'not_assessed', evidenceGrade: 'none' };
    }
  }
  _recomputeTouchedFlows(graph, { nodeId: node.id }, op._opts);
  return { ok: true };
}

function _applyChangeStorageFact(graph, op) {
  const node = _byId(graph.nodes).get(op.targetNodeId);
  if (!node) return { ok: false, reason: `targetNodeId "${op.targetNodeId}" not found in graph.nodes` };
  node.storeDetail = { ...(node.storeDetail ?? {}), [op.field]: _deepClone(op.value) };
  return { ok: true };
}

function _applyChangeGovernanceFact(graph, op) {
  const flow = _byId(graph.flows).get(op.targetFlowId);
  if (!flow) return { ok: false, reason: `targetFlowId "${op.targetFlowId}" not found in graph.flows` };
  flow.governanceRefs = { ...(flow.governanceRefs ?? {}), [op.field]: _deepClone(op.value) };
  return { ok: true };
}

const _APPLIERS = {
  require_transit_protection: _applyRequireTransitProtection,
  apply_handling: _applyHandling,
  remove_entity: _applyRemoveEntity,
  replace_recipient_fact: _applyReplaceRecipientFact,
  change_storage_fact: _applyChangeStorageFact,
  change_governance_fact: _applyChangeGovernanceFact,
};

/**
 * Apply `scenario.operations` to a deep clone of `baseGraph`. Never
 * mutates `baseGraph`. An operation whose target id does not exist in
 * the graph is skipped (reported in `skippedOperations`), never thrown —
 * a Scenario written against an older snapshot must degrade honestly.
 * `opts.privacySinkPolicy`/`opts.environment` mirror graph-builder.js's
 * own opts; omitting privacySinkPolicy means policyVerdict
 * recomputation is skipped entirely (base value kept on every touched
 * flow) rather than guessed.
 *
 * Scenario-shape validation (`validateScenario`, `scenario.js`) is the
 * CALLER's responsibility, not this module's — this function does no
 * upfront shape checking beyond each operation's own per-target `_byId`
 * lookup. An unrecognized `op.kind` is skipped via the `_APPLIERS` map
 * lookup below rather than validated against `SCENARIO_OPERATION_KINDS`
 * ahead of time. This mirrors `recipient-profile.js`'s own precedent,
 * where `validateRecipientProfile` is never called internally by any
 * producer either — the CLI layer (Task 4) calls `validateScenario`
 * before `applyScenario`, by design.
 */
function applyScenario(baseGraph, scenario, opts = {}) {
  const graph = _deepClone(baseGraph);
  const appliedOperations = [];
  const skippedOperations = [];
  for (const op of scenario.operations ?? []) {
    const applier = _APPLIERS[op.kind];
    if (!applier) {
      skippedOperations.push({ operation: op, reason: `unrecognized operation kind "${op.kind}"` });
      continue;
    }
    const result = applier(graph, { ...op, _opts: opts });
    if (result.ok) appliedOperations.push({ operation: op });
    else skippedOperations.push({ operation: op, reason: result.reason });
  }
  return { graph, appliedOperations, skippedOperations };
}


/***/ })

};
