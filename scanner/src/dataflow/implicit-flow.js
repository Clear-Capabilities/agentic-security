// Implicit-flow detection (P1.5).
//
// Today the engine tracks EXPLICIT taint — values flow into sinks. Implicit
// flow tracks CONTROL-DEPENDENCE: when a branch's condition is tainted, any
// variable assigned in that branch carries a SECONDARY taint at lower
// confidence (0.5 by default).
//
// Canonical motivating pattern:
//
//   if (req.body.role === 'admin') {
//     isAdmin = true;
//   }
//   if (isAdmin) callDangerous();
//
// The explicit-flow engine never sees taint flow into `isAdmin` — the
// dependence is control-only. Implicit-flow analysis adds `isAdmin` to a
// SHADOW state with confidence 0.5 whenever it's mutated inside a
// tainted-conditional branch.
//
// Over-approximation: implicit flow is famously noisy (sneaks into pure
// branches that don't actually leak info). So this analysis is OPT-IN
// only — gated by AGENTIC_SECURITY_IMPLICIT_FLOW=1 — and findings emitted
// carry an explicit `implicit:true` flag + capped confidence at 0.55.
//
// Public API:
//   isImplicitFlowEnabled()           → bool from env
//   buildImplicitContext(cfg, taintState)
//     → Map<nodeId, { tainted: bool, conditionLabel: string }>
//   mutationsInTaintedBranch(node, ctx)
//     → array of variable names that get assigned in a tainted branch
//   applyImplicitFlow(state, mutatedVars, conditionLabel)
//     → new state with the implicit-tainted vars added at confidence 0.5

import { addPath } from './access-paths.js';
import { computeDominators } from '../ir/ssa.js';

export function isImplicitFlowEnabled() {
  // OPT-IN (default OFF): implicit/control-dependence flow is famously noisy, so
  // it must be explicitly requested. Findings carry implicit:true + capped
  // confidence so the standard pipeline ranks them below explicit flows.
  return process.env.AGENTIC_SECURITY_IMPLICIT_FLOW === '1';
}

/**
 * Compute, for each CFG node, whether it's "inside" a tainted-condition
 * branch and what condition tainted it. Returns Map<nodeId, ctx>.
 *
 *   cfg:           the function CFG
 *   exprTaint:     callback (expr) -> bool, using the current taint state
 *
 * Correctness (Stage 6 audit): this used to be a path-dependent DFS that
 * incremented a "depth" counter on entering a tainted `if`'s successors and
 * only ever decremented it at a loop-header — there was no mechanism to
 * detect a branch's natural JOIN point, so once a path entered depth 1,
 * every node reachable afterward (including everything textually AFTER the
 * if/else closes, for the rest of the function) stayed marked
 * `tainted: true` forever. A first fix attempt (reset depth at the join)
 * was reverted because it broke the equally-real, intentional pattern
 * `if (tainted) { p = x; } eval(p)`: `p`'s taint must survive past the
 * branch on the VARIABLE (via markImplicitTaint → the normal forward-taint
 * state, entirely independent of this map), even though `eval(p)` itself is
 * not lexically inside the branch.
 *
 * The actual invariant this map must encode is narrower than "reachable
 * after a tainted if": a node N is genuinely INSIDE the branch rooted at
 * successor B if and only if B DOMINATES N — every path from the function
 * entry to N passes through B. A join point (reachable via the other
 * branch, or via any path that bypasses the if) is by definition NOT
 * dominated by B. This is exactly what `computeDominators` (shared with
 * ir/ssa.js's SSA φ-node placement) computes, so reuse it instead of a
 * path-dependent walk that structurally cannot distinguish "inside" from
 * "after".
 *
 * One more wrinkle the CFG shape forces on us: parser-js.js's IfStatement
 * lowering models a missing `else` as a DIRECT edge from the `if` node to
 * the post-if join node (`if (!path.node.alternate) linkCfg(fn, condId,
 * joinId)`), so `n.succ` for an else-less `if` is `[branchEntry, joinId]`
 * — the join node is literally one of the "successors" too. Naively
 * dominance-checking every successor as if it were a branch root treats
 * `joinId` itself as something to dominate through, and `joinId` trivially
 * dominates everything after it (there's no other way to reach that code),
 * which resurrects the exact over-attribution this fix exists to close.
 * Distinguish a genuine branch entry from a join/skip target structurally:
 * a real branch entry has EXACTLY ONE predecessor — this `if` node itself.
 * A join node always has a second predecessor (the branch's own tail, or —
 * for the else-less case — this same direct skip edge), so it never
 * qualifies.
 */
export function buildImplicitContext(cfg, exprTaint) {
  const ctxByNid = new Map();
  if (!cfg || !cfg.nodes) return ctxByNid;
  const dom = computeDominators(cfg);
  const predCount = new Map();
  const soleParent = new Map();
  for (const [pid, p] of Object.entries(cfg.nodes)) {
    for (const s of (p?.succ || [])) {
      predCount.set(s, (predCount.get(s) || 0) + 1);
      if (!soleParent.has(s)) soleParent.set(s, pid);
    }
  }
  for (const [nid, n] of Object.entries(cfg.nodes)) {
    if (!n || n.kind !== 'if' || !n.cond || !exprTaint(n.cond)) continue;
    // Config-constant filter: if condition is `ident === literal` where
    // ident is NOT tainted, skip (it's a config check, not a taint branch).
    if (n.cond.kind === 'binary' && (n.cond.op === '===' || n.cond.op === '==' || n.cond.op === 'Eq') &&
        n.cond.right && n.cond.right.kind === 'literal' &&
        n.cond.left && n.cond.left.kind === 'ident' &&
        !exprTaint(n.cond.left)) {
      continue;
    }
    const label = _formatCondLabel(n.cond);
    for (const branchRoot of (n.succ || [])) {
      if (branchRoot === nid) continue; // guard against a malformed self-loop
      // Not a genuine branch entry — it's a join/skip target reachable
      // some other way too (see header). Marking it (or anything only
      // reachable through it) would leak taint past the branch's real scope.
      if ((predCount.get(branchRoot) || 0) !== 1 || soleParent.get(branchRoot) !== nid) continue;
      for (const [candidate, domSet] of dom) {
        if (candidate === nid) continue;
        if (domSet && domSet.has(branchRoot) && !ctxByNid.has(candidate)) {
          ctxByNid.set(candidate, { tainted: true, conditionLabel: label });
        }
      }
    }
  }
  return ctxByNid;
}

function _formatCondLabel(cond) {
  if (!cond) return '?';
  if (cond.kind === 'ident') return cond.name;
  if (cond.kind === 'member') return `${_formatCondLabel(cond.object)}.${cond.prop}`;
  if (cond.kind === 'binary') return `${_formatCondLabel(cond.left)} ${cond.op} ${_formatCondLabel(cond.right)}`;
  if (cond.kind === 'literal') return JSON.stringify(cond.value);
  return cond.kind || '?';
}

/**
 * Given an `assign` node, return the target name if the assignment happens
 * inside a tainted branch.
 */
export function implicitAssignTarget(node, ctx) {
  if (!node || node.kind !== 'assign') return null;
  if (!ctx || !ctx.tainted) return null;
  if (typeof node.target !== 'string') return null;
  // Literal-assignment filter: assigning a constant in a tainted branch
  // is not an implicit information leak.
  if (node.source && node.source.kind === 'literal') return null;
  return node.target;
}

/**
 * Add `varName` to `state` with an `implicit-` marker prefix so consumers
 * can distinguish primary taint from implicit (lower-confidence) taint.
 *
 * Convention: implicit taint markers look like `implicit:<varName>` in the
 * state set. Engine sink-checks consult both the primary path AND any
 * `implicit:<...>` paths when emitting findings.
 */
export function markImplicitTaint(state, varName) {
  if (!varName || typeof varName !== 'string') return state;
  return addPath(state, `implicit:${varName}`);
}

/**
 * Helper: produce an implicit-flow finding from an assign-in-tainted-branch
 * event. Used by the engine when a sink later consumes an implicit-tainted
 * variable.
 */
export function createImplicitFinding(node, conditionLabel) {
  return {
    kind: 'taint',
    implicit: true,
    confidence: 0.40,
    vuln: `Implicit flow — variable mutated inside tainted-conditional branch (condition: ${conditionLabel || '?'})`,
    severity: 'medium',
    cwe: 'CWE-200',
    line: node?.line || 0,
    remediation: 'Verify that the conditional branch does not let user-controlled state escape into privileged paths. Implicit-flow findings are noisier than explicit-flow; review with elevated scrutiny.',
  };
}
