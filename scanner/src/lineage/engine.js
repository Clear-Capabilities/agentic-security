import { accessPathOf } from '../dataflow/access-paths.js';
import { identitiesAt, emptyState, removeIdentitiesAt, addIdentity, joinStates, statesEqual } from './field-identity.js';

function noIdentity() {
  return { flat: new Set(), byPath: new Map(), widened: false };
}

export function resolveExprIdentities(state, expr) {
  if (!expr) return noIdentity();

  switch (expr.kind) {
    case 'ident':
    case 'member': {
      const path = accessPathOf(expr);
      return { flat: path ? identitiesAt(state, path) : new Set(), byPath: new Map(), widened: false };
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
        if (r.flat.size > 0) {
          const existing = byPath.get(prop.key) ?? new Set();
          byPath.set(prop.key, new Set([...existing, ...r.flat]));
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

    case 'binary':
    case 'logical': {
      const left = resolveExprIdentities(state, expr.left);
      const right = resolveExprIdentities(state, expr.right);
      return { flat: new Set([...left.flat, ...right.flat]), byPath: new Map(), widened: false };
    }

    case 'union': {
      const flat = new Set();
      for (const branch of expr.branches) {
        const r = resolveExprIdentities(state, branch);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
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
      const r = resolveExprIdentities(state, expr.source);
      return { flat: r.flat, byPath: new Map(), widened: r.flat.size > 0 };
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
      // A source with a byPath breakdown (an object-literal RHS) writes ONLY
      // the per-field entries — see DESIGN_INTRAPROCEDURAL.md §3's "Corrected
      // design" note. Writing the flat union at the container's own path too
      // would re-merge distinct fields (FR-301's violation), and is no longer
      // needed: identitiesAt now aggregates descendants when the container is
      // queried as a whole (e.g. `return rec`), so per-field writes alone
      // answer both "give me this exact field" and "give me the whole object".
      // A source with no byPath breakdown (a plain value, e.g. `user.email`)
      // is unaffected and still writes `flat` at `target` exactly as before.
      if (resolved.byPath.size > 0) {
        for (const [subPath, ids] of resolved.byPath) {
          for (const id of ids) state = addIdentity(state, `${node.target}.${subPath}`, id);
        }
      } else {
        for (const id of resolved.flat) state = addIdentity(state, node.target, id);
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
