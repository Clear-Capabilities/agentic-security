// Static Single Assignment transform (P2.4).
//
// Renames every variable in the IR so each definition gets a unique name
// (`x_0`, `x_1`, `x_2`, ...). At control-flow joins, places a φ-node that
// merges the incoming definitions.
//
// Why this matters for taint:
//   let x = req.body;     // x_0 := tainted
//   x = sanitize(x);      // x_1 := clean
//   doSink(x);            // sink reads x_1 → clean
//
// Without SSA, the engine sees one variable `x`. The sanitize-then-use
// pattern looks like a "still tainted" finding because the same name was
// tainted earlier in the function. SSA turns this into two separate
// variables, eliminating the conflation.
//
// Algorithm (Cytron-Ferrante 1991):
//
//   1. Compute the dominator tree of the CFG.
//   2. Compute dominance frontiers for each node.
//   3. For each variable `v` defined in node `n`, place a φ(v) at every
//      node in DF(n) — these are the join points where v's def reaches.
//   4. Rename each definition `v` to `v_<count>` (increment per def).
//      Each use of `v` is rewritten to the most-recent dominating def.
//
// v1 in this module: we expose the SSA transform as a standalone pass that
// the engine can opt into via AGENTIC_SECURITY_SSA=1. Default-off because
// it changes IR shape and the existing engine must consume the new shape.
//
// Public API:
//   computeSSA(cfg)   → mutates cfg in place; each variable is now suffixed
//                       _0/_1/_2..., φ-nodes inserted at join points.
//   isSSAEnabled()    → bool from env

import { accessPathOf } from '../dataflow/access-paths.js';

export function isSSAEnabled() {
  return process.env.AGENTIC_SECURITY_SSA === '1';
}

/**
 * Compute dominators for a CFG using the iterative algorithm.
 *
 * Returns Map<nodeId, Set<nodeId>>  — dom[n] = set of nodes that dominate n.
 */
// Exported (Stage 6 correctness audit) so dataflow/implicit-flow.js can
// reuse this tested algorithm to correctly scope "is node N genuinely
// inside branch B" (N is inside iff B dominates N — every path to N passes
// through B) instead of a path-dependent DFS depth counter that had no way
// to detect a branch's join point.
export function computeDominators(cfg) {
  const nodes = Object.keys(cfg.nodes || {});
  const entry = cfg.entry;
  const dom = new Map();
  for (const n of nodes) dom.set(n, new Set(nodes));
  dom.set(entry, new Set([entry]));
  // Reverse adjacency for predecessor lookup.
  const preds = new Map();
  for (const n of nodes) preds.set(n, []);
  for (const n of nodes) {
    for (const s of (cfg.nodes[n]?.succ || [])) {
      if (preds.has(s)) preds.get(s).push(n);
    }
  }
  let changed = true;
  let safety = 1000;
  while (changed && safety-- > 0) {
    changed = false;
    for (const n of nodes) {
      if (n === entry) continue;
      const ps = preds.get(n) || [];
      if (!ps.length) continue;
      let newDom = null;
      for (const p of ps) {
        const pDom = dom.get(p);
        if (!pDom) continue;
        if (newDom === null) newDom = new Set(pDom);
        else {
          // Intersect
          for (const x of [...newDom]) if (!pDom.has(x)) newDom.delete(x);
        }
      }
      if (!newDom) newDom = new Set();
      newDom.add(n);
      const cur = dom.get(n);
      if (!cur || cur.size !== newDom.size || [...newDom].some(x => !cur.has(x))) {
        dom.set(n, newDom);
        changed = true;
      }
    }
  }
  return dom;
}

/**
 * Compute the immediate dominator of each node.
 *
 *   idom[n] = the unique x in (dom[n] - {n}) that doesn't dominate any
 *   other node in (dom[n] - {n}).
 *
 * Returns Map<nodeId, nodeId | null>.
 */
function computeImmediateDominators(dom) {
  const idom = new Map();
  for (const [n, ds] of dom) {
    const candidates = [...ds].filter(x => x !== n);
    if (candidates.length === 0) { idom.set(n, null); continue; }
    // pick the one with the largest |dom| (closest to n).
    let best = null;
    let bestSize = -1;
    for (const c of candidates) {
      const cs = (dom.get(c) || new Set()).size;
      if (cs > bestSize) { best = c; bestSize = cs; }
    }
    idom.set(n, best);
  }
  return idom;
}

/**
 * Compute dominance frontiers using the standard algorithm:
 *
 *   for each join node j (≥2 predecessors):
 *     for each predecessor p of j:
 *       runner = p
 *       while runner !== idom(j):
 *         DF[runner].add(j)
 *         runner = idom(runner)
 *
 * Returns Map<nodeId, Set<nodeId>>.
 */
function computeDominanceFrontiers(cfg, idom) {
  const DF = new Map();
  const nodes = Object.keys(cfg.nodes || {});
  for (const n of nodes) DF.set(n, new Set());
  const preds = new Map();
  for (const n of nodes) preds.set(n, []);
  for (const n of nodes) {
    for (const s of (cfg.nodes[n]?.succ || [])) {
      if (preds.has(s)) preds.get(s).push(n);
    }
  }
  for (const j of nodes) {
    const ps = preds.get(j) || [];
    if (ps.length < 2) continue;
    const idomJ = idom.get(j);
    for (const p of ps) {
      let runner = p;
      let safety = nodes.length + 5;
      while (runner && runner !== idomJ && safety-- > 0) {
        DF.get(runner).add(j);
        runner = idom.get(runner) || null;
      }
    }
  }
  return DF;
}

/**
 * Collect, per CFG node, the set of variables defined at that node.
 */
function defsPerNode(cfg) {
  const defs = new Map();
  for (const id of Object.keys(cfg.nodes || {})) {
    const n = cfg.nodes[id];
    const set = new Set();
    if (n && n.kind === 'assign' && typeof n.target === 'string') {
      // Use the access path's root (the LHS top-level identifier).
      const ap = n.target;
      const root = ap.split('.')[0];
      set.add(root);
    }
    defs.set(id, set);
  }
  return defs;
}

/**
 * Place φ-nodes for variables. Returns Map<nodeId, Set<varName>> — the
 * variables that need a φ at each node.
 */
function placePhis(cfg, defs, DF) {
  // For each variable v, collect nodes where v is defined.
  const allVars = new Set();
  const defNodesByVar = new Map();
  for (const [nid, vars] of defs) {
    for (const v of vars) {
      allVars.add(v);
      if (!defNodesByVar.has(v)) defNodesByVar.set(v, new Set());
      defNodesByVar.get(v).add(nid);
    }
  }
  const phis = new Map();
  for (const id of Object.keys(cfg.nodes || {})) phis.set(id, new Set());
  for (const v of allVars) {
    const work = [...(defNodesByVar.get(v) || [])];
    const visited = new Set(work);
    while (work.length) {
      const n = work.shift();
      const df = DF.get(n) || new Set();
      for (const j of df) {
        if (phis.get(j).has(v)) continue;
        phis.get(j).add(v);
        if (!visited.has(j)) { work.push(j); visited.add(j); }
      }
    }
  }
  return phis;
}

/**
 * Apply Cytron-Ferrante SSA renaming to a CFG. Mutates the CFG in place:
 *   - Every `assign` target gets renamed with `_N` suffix.
 *   - Every read of a variable gets rewritten to the dominating def's name.
 *   - φ-nodes are inserted at join points and carry the incoming defs.
 *
 * v1: we record the SSA names on a side map (`cfg.ssa.versions: Map<nid, Map<var, newName>>`)
 * instead of rewriting the existing exprDesc structures — keeps the IR
 * backward-compatible for engines that don't consume SSA.
 */
export function computeSSA(cfg) {
  if (!cfg || !cfg.nodes || !cfg.entry) return cfg;
  const dom = computeDominators(cfg);
  const idom = computeImmediateDominators(dom);
  const DF = computeDominanceFrontiers(cfg, idom);
  const defs = defsPerNode(cfg);
  const phis = placePhis(cfg, defs, DF);

  // Renaming pass: walk dominator tree in pre-order; for each variable
  // maintain a stack of versions. On entry to a node, push a new version
  // for each definition; on exit, pop.
  const ssaInfo = {
    versions: new Map(),    // nid -> Map<var, current ssa name>
    phis: new Map(),        // nid -> [{ var, ssaName, incoming: [{predNid, ssaName}] }]
    nextVersion: new Map(), // var -> next index
  };
  // Build children-of-idom map.
  const idomChildren = new Map();
  for (const [n, p] of idom) {
    if (!p) continue;
    if (!idomChildren.has(p)) idomChildren.set(p, []);
    idomChildren.get(p).push(n);
  }

  const counter = ssaInfo.nextVersion;
  const stacks = new Map();

  function freshName(v) {
    const i = counter.get(v) || 0;
    counter.set(v, i + 1);
    return `${v}_${i}`;
  }
  function topOf(v) {
    const s = stacks.get(v);
    if (!s || !s.length) return null;
    return s[s.length - 1];
  }
  function rename(nid) {
    const n = cfg.nodes[nid];
    if (!n) return;
    // Materialize φ-functions at this node: each phi-var gets a fresh name.
    const phisHere = phis.get(nid) || new Set();
    const phiList = [];
    for (const v of phisHere) {
      const name = freshName(v);
      const pushed = stacks.get(v) || [];
      pushed.push(name);
      stacks.set(v, pushed);
      phiList.push({ var: v, ssaName: name, incoming: [] });
    }
    if (phiList.length) ssaInfo.phis.set(nid, phiList);

    // Record per-node versions (read-visible).
    const vmap = new Map();
    for (const [v, s] of stacks) {
      if (s.length) vmap.set(v, s[s.length - 1]);
    }

    // Handle this node's def — if `assign`, fresh-name the LHS.
    const myDefs = defs.get(nid) || new Set();
    for (const v of myDefs) {
      const name = freshName(v);
      const pushed = stacks.get(v) || [];
      pushed.push(name);
      stacks.set(v, pushed);
      vmap.set(v, name);
    }
    ssaInfo.versions.set(nid, vmap);

    // Recurse into idom children.
    for (const child of (idomChildren.get(nid) || [])) {
      rename(child);
    }

    // Pop the stacks we pushed.
    for (const v of myDefs) {
      const s = stacks.get(v);
      if (s) s.pop();
    }
    for (const { var: v } of phiList) {
      const s = stacks.get(v);
      if (s) s.pop();
    }
  }
  rename(cfg.entry);

  cfg.ssa = ssaInfo;
  return cfg;
}

/**
 * Public helper: given a CFG with `cfg.ssa` populated, return the SSA name
 * of `varName` as seen on entry to `nodeId`.
 */
export function ssaNameAt(cfg, nodeId, varName) {
  if (!cfg || !cfg.ssa) return null;
  const v = cfg.ssa.versions.get(nodeId);
  if (!v) return null;
  return v.get(varName) || null;
}
