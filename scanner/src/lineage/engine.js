import { accessPathOf, pathIsCoveredByPrefix } from '../dataflow/access-paths.js';
import { identitiesAt, emptyState, removeIdentitiesAt, addIdentity, joinStates, statesEqual } from './field-identity.js';

function noIdentity() {
  return { flat: new Set(), byPath: new Map(), widened: false };
}

function unionOfByPath(byPath) {
  const union = new Set();
  for (const ids of byPath.values()) for (const id of ids) union.add(id);
  return union;
}

// Whatever in `flat` is NOT already captured by `byPath` — this is the part
// of a value's identity set that has no more specific field-level home, and
// is safe to write coarsely (it was never distinguished field-by-field to
// begin with, so writing it coarsely does not merge two ALREADY-DISTINGUISHED
// facts the way writing the full `flat` at a root would). See
// DESIGN_INTRAPROCEDURAL.md §3 for the full reasoning and the bug this
// closes (a plain-variable alias, e.g. `const copy = user;`, surviving one
// level of aliasing past round 1's object-literal-only fix).
function residualFlat(flat, byPath) {
  const covered = unionOfByPath(byPath);
  const residual = new Set();
  for (const id of flat) if (!covered.has(id)) residual.add(id);
  return residual;
}

export function resolveExprIdentities(state, expr) {
  if (!expr) return noIdentity();

  switch (expr.kind) {
    case 'ident':
    case 'member': {
      const path = accessPathOf(expr);
      if (!path) return noIdentity();
      const flat = identitiesAt(state, path);
      const byPath = new Map();
      for (const [candidatePath, ids] of state) {
        if (candidatePath !== path && pathIsCoveredByPrefix(candidatePath, path)) {
          const subPath = candidatePath.slice(path.length + 1);
          const existing = byPath.get(subPath) ?? new Set();
          byPath.set(subPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'literal':
    case 'unknown':
      return noIdentity();

    case 'object': {
      const flat = new Set();
      const byPath = new Map();
      for (const prop of expr.props) {
        const r = resolveExprIdentities(state, prop.value);
        for (const id of r.flat) flat.add(id);
        // Use the RESIDUAL, not the full r.flat: if prop.value is itself an
        // aliased/structured reference (now possible via the ident/member
        // case above returning a populated byPath), writing the full flat
        // here would duplicate what the nested subPath entries below already
        // separate — the same coarse-merge bug one level deeper. See
        // DESIGN_INTRAPROCEDURAL.md §3.
        const propResidual = residualFlat(r.flat, r.byPath);
        if (propResidual.size > 0) {
          const existing = byPath.get(prop.key) ?? new Set();
          byPath.set(prop.key, new Set([...existing, ...propResidual]));
        }
        for (const [subPath, ids] of r.byPath) {
          const fullPath = `${prop.key}.${subPath}`;
          const existing = byPath.get(fullPath) ?? new Set();
          byPath.set(fullPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'array': {
      const flat = new Set();
      for (const el of expr.elements) {
        const r = resolveExprIdentities(state, el);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'tpl': {
      const flat = new Set();
      for (const part of expr.parts) {
        const r = resolveExprIdentities(state, part);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'binary': {
      // Arithmetic/comparison operators always PRODUCE A NEW PRIMITIVE —
      // structure-flattening by design, not a gap. See
      // DESIGN_INTRAPROCEDURAL.md §4's "structure-preserving vs.
      // structure-flattening" invariant.
      const left = resolveExprIdentities(state, expr.left);
      const right = resolveExprIdentities(state, expr.right);
      return { flat: new Set([...left.flat, ...right.flat]), byPath: new Map(), widened: false };
    }

    case 'logical': {
      // Unlike `binary`, `||`/`&&`/`??` can return one operand VERBATIM, BY
      // REFERENCE, via short-circuit evaluation — structurally identical to
      // `union` below (select/pass through an existing value). Must forward
      // byPath, merged per sub-path across both operands, the same way
      // `union` merges per sub-path across branches. See
      // DESIGN_INTRAPROCEDURAL.md §4.
      const left = resolveExprIdentities(state, expr.left);
      const right = resolveExprIdentities(state, expr.right);
      const flat = new Set([...left.flat, ...right.flat]);
      const byPath = new Map();
      for (const r of [left, right]) {
        for (const [subPath, ids] of r.byPath) {
          const existing = byPath.get(subPath) ?? new Set();
          byPath.set(subPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'union': {
      // A ternary selects one branch's value VERBATIM at runtime — this is
      // the expression-level equivalent of the CFG's own branch join
      // (joinStates), which unions PER PATH rather than flattening. Must do
      // the same here: merge each branch's byPath per sub-path, never
      // collapse into one coarse flat blob. See DESIGN_INTRAPROCEDURAL.md §4.
      const flat = new Set();
      const byPath = new Map();
      for (const branch of expr.branches) {
        const r = resolveExprIdentities(state, branch);
        for (const id of r.flat) flat.add(id);
        for (const [subPath, ids] of r.byPath) {
          const existing = byPath.get(subPath) ?? new Set();
          byPath.set(subPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'call': {
      const flat = new Set();
      for (const arg of expr.args ?? []) {
        const r = resolveExprIdentities(state, arg);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: flat.size > 0 };
    }

    case 'assign-expr': {
      // Nested assignment-as-expression (e.g. `if ((x = getUser()).isAdmin)`)
      // is read-only here: resolves what the expression VALUE carries but
      // does NOT write into `x` in `state` — see
      // scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md §4 for why this is a
      // deliberate, documented limitation, not an oversight.
      // A simple pass-through of whatever the assignment's source resolves
      // to (structure-preserving), so its byPath is forwarded directly, not
      // dropped. See DESIGN_INTRAPROCEDURAL.md §4.
      const r = resolveExprIdentities(state, expr.source);
      return { flat: r.flat, byPath: r.byPath, widened: r.flat.size > 0 };
    }

    default:
      return noIdentity();
  }
}

function step(node, stateIn, widenings) {
  switch (node.kind) {
    case 'assign': {
      const resolved = resolveExprIdentities(stateIn, node.source);
      let state = removeIdentitiesAt(stateIn, node.target);
      // Write every byPath entry at its own sub-path, and write only the
      // RESIDUAL (whatever in `flat` isn't already captured by byPath's
      // union) coarsely at the target's own root — never the full `flat`
      // when byPath has structure, since that recreates the coarse-merge
      // bug (FR-301). This single rule subsumes round 1's explicit
      // byPath-empty-vs-nonempty branching: an empty residual is a no-op, so
      // a plain value (byPath empty, e.g. `user.email`) still writes its
      // full `flat` at `target` exactly as before, and an object-literal or
      // aliased-reference RHS (byPath populated) writes only its per-field
      // entries. See DESIGN_INTRAPROCEDURAL.md §3 for the full reasoning,
      // including the aliasing gap (`const copy = user;`) this closes.
      const residual = residualFlat(resolved.flat, resolved.byPath);
      for (const id of residual) state = addIdentity(state, node.target, id);
      for (const [subPath, ids] of resolved.byPath) {
        for (const id of ids) state = addIdentity(state, `${node.target}.${subPath}`, id);
      }
      if (resolved.widened && resolved.flat.size > 0) {
        widenings.push({ atPath: node.target, dataElementIds: [...resolved.flat], reason: 'unresolved-call', line: node.line });
      }
      return { state, returnFact: null };
    }

    case 'call': {
      for (const arg of node.args ?? []) {
        const r = resolveExprIdentities(stateIn, arg);
        if (r.flat.size > 0) {
          widenings.push({ atPath: null, dataElementIds: [...r.flat], reason: 'unresolved-call-arg', line: node.line });
        }
      }
      return { state: stateIn, returnFact: null };
    }

    case 'return': {
      const resolved = node.value ? resolveExprIdentities(stateIn, node.value) : { flat: new Set(), widened: false };
      if (resolved.widened && resolved.flat.size > 0) {
        widenings.push({ atPath: null, dataElementIds: [...resolved.flat], reason: 'unresolved-call', line: node.line });
      }
      return { state: stateIn, returnFact: resolved.flat };
    }

    case 'entry':
    case 'exit':
    case 'noop':
    case 'loop-header':
    case 'if':
    case 'throw':
    case 'unknown':
    default:
      return { state: stateIn, returnFact: null };
  }
}

// Mirrors scanner/src/dataflow/engine.js's analyzeFunction ITER_BUDGET
// (Premortem 2R4.4 / 2R-9): the join-then-changed-check below is already
// sound and terminating for any well-formed CFG (state only grows via
// monotonic union over a finite universe of paths/ids per function, so the
// fixed point is reached in finitely many steps — verified by hand-tracing
// the loop-back-edge test below, which converges in 6 iterations with no
// re-visits needed). This cap is purely a defensive backstop against a
// malformed/generated CFG, matching the real engine's documented posture,
// not a load-bearing part of the termination proof.
const ITER_BUDGET = 5000;

export function analyzeFunctionFieldIdentity(fn, entryState) {
  const nodes = fn.cfg.nodes;
  const work = [fn.cfg.entry];
  const inStates = new Map([[fn.cfg.entry, entryState]]);
  const outStates = new Map();
  const widenings = [];
  const returnFactsByNode = new Map();
  let iterations = 0;

  while (work.length) {
    if (++iterations > ITER_BUDGET) break;
    const nid = work.shift();
    const node = nodes[nid];
    if (!node) continue;
    const incoming = inStates.get(nid) ?? emptyState();
    const { state: out, returnFact } = step(node, incoming, widenings);
    if (returnFact && returnFact.size > 0) {
      // Union onto any existing fact for this node rather than pushing a
      // new array entry every visit — see Fix 2 in the final whole-branch
      // review: a `return` node revisited by the worklist (its incoming
      // join hadn't settled on an earlier visit) used to produce a second,
      // stale, strictly-weaker entry for the same nodeId/line. A consumer
      // doing `returnFacts.find(f => f.nodeId === X)` would silently get
      // the wrong, under-approximating answer. Mirrors how outStates/
      // inStates already union via joinStates below.
      const existing = returnFactsByNode.get(nid);
      const identities = existing ? new Set([...existing.identities, ...returnFact]) : new Set(returnFact);
      returnFactsByNode.set(nid, { line: node.line, identities });
    }

    const prevOut = outStates.get(nid);
    const merged = prevOut ? joinStates(prevOut, out) : out;
    if (!prevOut || !statesEqual(prevOut, merged)) {
      outStates.set(nid, merged);
      for (const succ of node.succ ?? []) {
        const prevIn = inStates.get(succ);
        const newIn = prevIn ? joinStates(prevIn, merged) : merged;
        if (!prevIn || !statesEqual(prevIn, newIn)) {
          inStates.set(succ, newIn);
          work.push(succ);
        }
      }
    }
  }

  const returnFacts = [...returnFactsByNode.entries()]
    .map(([nodeId, fact]) => ({ nodeId, line: fact.line, identities: fact.identities }));

  const exitState = outStates.get(fn.cfg.exit) ?? emptyState();
  const mutatedParams = new Map();
  for (const param of fn.params) {
    // identitiesAt now aggregates both ancestor coverage AND descendant
    // coverage (see field-identity.js), so this correctly reports every
    // identity recorded on the param's own path or any field under it —
    // e.g. `target.copiedEmail = user.email` is attributed to `target`.
    //
    // NOTE — this is sound but NOT "write-only": if the param's entry-state
    // facts were never touched at all (a purely read-only param), those
    // original facts still survive unchanged into exitState and are
    // reported here too. `mutatedParams` means "what this param carries at
    // function exit" (a safe over-approximation a caller can rely on never
    // under-reporting), not "was this param's value replaced by an
    // assignment." Do not rename this without checking every consumer's
    // expectations first — Sub-project B is the intended reader of this
    // exact contract.
    const ids = identitiesAt(exitState, param);
    if (ids.size > 0) mutatedParams.set(param, ids);
  }

  return { exitState, returnFacts, mutatedParams, widenings };
}
