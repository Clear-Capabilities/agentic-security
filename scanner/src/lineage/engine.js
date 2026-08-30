import { accessPathOf, pathIsCoveredByPrefix } from '../dataflow/access-paths.js';
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
      for (const id of resolved.flat) state = addIdentity(state, node.target, id);
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
  const returnFacts = [];
  let iterations = 0;

  while (work.length) {
    if (++iterations > ITER_BUDGET) break;
    const nid = work.shift();
    const node = nodes[nid];
    if (!node) continue;
    const incoming = inStates.get(nid) ?? emptyState();
    const { state: out, returnFact } = step(node, incoming, widenings);
    if (returnFact && returnFact.size > 0) {
      returnFacts.push({ nodeId: nid, line: node.line, identities: returnFact });
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

  const exitState = outStates.get(fn.cfg.exit) ?? emptyState();
  const mutatedParams = new Map();
  for (const param of fn.params) {
    // NOT identitiesAt(exitState, param): identitiesAt(state, path) answers
    // "what identity covers THIS path" by looking at path itself plus any
    // ANCESTOR entry in state (a shorter prefix that covers it) — e.g. if
    // the whole `user` object were tainted, identitiesAt(state, 'user.email')
    // would correctly inherit it. That is the wrong direction here: a param
    // is "mutated" when the function body wrote an identity onto the
    // param's OWN path or any DESCENDANT of it (`target.copiedEmail = ...`
    // must be attributed to `target`), which is the reverse traversal.
    // identitiesAt(exitState, 'target') would miss `target.copiedEmail`
    // entirely — confirmed empirically: running the brief's literal code
    // against the "mutatedParams" test below threw immediately
    // (`mutatedParams.get('target')` was undefined, not an iterable Set)
    // because identitiesAt never looked downward from 'target' into
    // 'target.copiedEmail'.
    const ids = new Set();
    for (const [candidatePath, candidateIds] of exitState) {
      if (candidatePath === param || pathIsCoveredByPrefix(candidatePath, param)) {
        for (const id of candidateIds) ids.add(id);
      }
    }
    if (ids.size > 0) mutatedParams.set(param, ids);
  }

  return { exitState, returnFacts, mutatedParams, widenings };
}
