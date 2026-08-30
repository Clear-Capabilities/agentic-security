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
export function residualFlat(flat, byPath) {
  const covered = unionOfByPath(byPath);
  const residual = new Set();
  for (const id of flat) if (!covered.has(id)) residual.add(id);
  return residual;
}

// Round 6 finding: round 5's wildcard guards (`path === '*' ||
// path.endsWith('.*')`) only recognized a TRAILING wildcard segment. A
// wildcard segment can also appear in the MIDDLE of a path — `store[k].name`
// lowers to the access path `store.*.name` (accessPathOf's own, pre-existing
// convention for a statically-unknown computed key), which is neither
// exactly '*' nor ending in '.*', so it fell through to the OLD, unfixed
// strong-update/silent-drop behavior — round 5's own bug recurring one path
// segment deeper. These two helpers generalize both the selection-side
// (`member`) and write-out-side (`assign`) guards to be position-
// independent: any '*' segment anywhere in the path, not just a trailing
// one.
//
// Finds the longest DEFINITE (wildcard-free) prefix of `path` before its
// first '*' segment — e.g. 'store.*.name' -> 'store', 'bag.*' -> 'bag',
// '*' -> null (no definite prefix at all), 'a.b.c' -> null (no wildcard
// present, caller should not treat this as a wildcard path in the first
// place). This subsumes round 5's trailing-only `endsWith('.*')` handling
// as a special case ('bag.*' through this function gives the same 'bag'
// round 5's `slice(0, -2)` gave) while also correctly handling an INTERIOR
// wildcard, which round 5 missed.
function definitePrefixBeforeWildcard(path) {
  const segments = path.split('.');
  const idx = segments.indexOf('*');
  if (idx <= 0) return null; // no wildcard present, or '*' is the very first segment (no definite prefix)
  return segments.slice(0, idx).join('.');
}

function pathHasWildcard(path) {
  return path.split('.').includes('*');
}

export function resolveExprIdentities(state, expr, ctx) {
  if (!expr) return noIdentity();

  switch (expr.kind) {
    case 'ident': {
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

    case 'member': {
      const path = accessPathOf(expr);
      if (path) {
        if (pathHasWildcard(path)) {
          // A computed member access with a statically-unknown key (`obj[k]`) —
          // we don't know WHICH field is being read, so conservatively resolve
          // the definite prefix's aggregate identity (identitiesAt's existing
          // descendant aggregation, from round 2, already does exactly this
          // when queried at that prefix path) and flag it widened, per
          // DESIGN_INTRAPROCEDURAL.md §4's dynamic-property-key example. Never
          // silently drop it (FR-306's "never launder identity into a clean
          // value" principle) — see the round-5 re-review that found this gap,
          // and round 6's generalization to an INTERIOR wildcard (e.g.
          // 'store.*.name' from `store[k].name`), which round 5's
          // trailing-only check missed.
          const basePath = definitePrefixBeforeWildcard(path);
          const flat = basePath ? identitiesAt(state, basePath) : new Set();
          return { flat, byPath: new Map(), widened: flat.size > 0 };
        }
        // Pure ident/member chain — resolve directly against state, same
        // logic as the `ident` case above.
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

      // The base isn't a pure path (e.g. `(user ?? other).email`,
      // `(flag ? a : b).email`, `({a: user}).a.email`) — resolve the base
      // recursively and SELECT `prop` out of its `byPath`, mirroring how the
      // `object` case's construction attributes a property to its own key.
      // This is the read-side mirror of that write-side logic — without it,
      // a value round 3 correctly taught to carry structure via `byPath`
      // silently loses that structure the moment a field is read off it
      // directly, rather than through an intermediate variable. Also inherit
      // the base's RESIDUAL (via the existing `residualFlat` helper, same one
      // `assign`/`object` already use) — a coarse/ancestor-level fact on the
      // base conservatively applies to every field read off it, same
      // reasoning as `identitiesAt`'s ancestor coverage for state-backed reads.
      const base = resolveExprIdentities(state, expr.object, ctx);
      if (expr.prop === '*') {
        // Same reasoning as the path-succeeds branch above: unknown key on a
        // non-path base — conservatively use everything the base carries
        // (base.flat is already that full aggregate), flagged widened.
        return { flat: new Set(base.flat), byPath: new Map(), widened: base.flat.size > 0 };
      }
      const baseResidual = residualFlat(base.flat, base.byPath);
      const flat = new Set(baseResidual);
      const byPath = new Map();
      for (const [subPath, ids] of base.byPath) {
        if (subPath === expr.prop) {
          for (const id of ids) flat.add(id);
        } else if (subPath.startsWith(`${expr.prop}.`)) {
          const rebased = subPath.slice(expr.prop.length + 1);
          const existing = byPath.get(rebased) ?? new Set();
          byPath.set(rebased, new Set([...existing, ...ids]));
          for (const id of ids) flat.add(id);
        }
      }
      return { flat, byPath, widened: base.widened };
    }

    case 'literal':
    case 'unknown':
      return noIdentity();

    case 'object': {
      const flat = new Set();
      const byPath = new Map();
      for (const prop of expr.props) {
        const r = resolveExprIdentities(state, prop.value, ctx);
        for (const id of r.flat) flat.add(id);
        if (prop.spread) {
          // Object spread ({...src}) copies ALL of src's own properties onto
          // this object as TOP-LEVEL siblings — merge the spread source's
          // byPath structure directly into this object's own byPath,
          // preserving field-level distinctness (a spread's contents are
          // fully known, unlike a computed-unknown-key property, which is
          // why this is a different branch from the `prop.key === '*'` case
          // below, not the same one).
          for (const [subPath, ids] of r.byPath) {
            const existing = byPath.get(subPath) ?? new Set();
            byPath.set(subPath, new Set([...existing, ...ids]));
          }
          continue;
        }
        if (prop.key === '*') {
          // Unknown computed key (`{[k]: v}`, round 5 — see
          // scanner/src/ir/parser-js.js's ObjectExpression case, which now
          // emits the literal key '*' for a non-literal computed key,
          // mirroring computed-member-access's existing convention) —
          // fold into the coarse residual for this object rather than a
          // specific byPath entry, which would just be a differently-
          // shaped version of the same fabricated-key collision bug (only
          // with '*' as the fabricated key instead of the key expression's
          // own variable name). Nothing to do here beyond adding to `flat`
          // above — leaving it OUT of `byPath` is exactly what makes it
          // residual when this object is later written via `assign`.
          continue;
        }
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
        const r = resolveExprIdentities(state, el, ctx);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'tpl': {
      const flat = new Set();
      for (const part of expr.parts) {
        const r = resolveExprIdentities(state, part, ctx);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'binary': {
      // Arithmetic/comparison operators always PRODUCE A NEW PRIMITIVE —
      // structure-flattening by design, not a gap. See
      // DESIGN_INTRAPROCEDURAL.md §4's "structure-preserving vs.
      // structure-flattening" invariant.
      const left = resolveExprIdentities(state, expr.left, ctx);
      const right = resolveExprIdentities(state, expr.right, ctx);
      return { flat: new Set([...left.flat, ...right.flat]), byPath: new Map(), widened: false };
    }

    case 'logical': {
      // Unlike `binary`, `||`/`&&`/`??` can return one operand VERBATIM, BY
      // REFERENCE, via short-circuit evaluation — structurally identical to
      // `union` below (select/pass through an existing value). Must forward
      // byPath, merged per sub-path across both operands, the same way
      // `union` merges per sub-path across branches. See
      // DESIGN_INTRAPROCEDURAL.md §4.
      const left = resolveExprIdentities(state, expr.left, ctx);
      const right = resolveExprIdentities(state, expr.right, ctx);
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
        const r = resolveExprIdentities(state, branch, ctx);
        for (const id of r.flat) flat.add(id);
        for (const [subPath, ids] of r.byPath) {
          const existing = byPath.get(subPath) ?? new Set();
          byPath.set(subPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'call': {
      // NEW (Sub-project B, increment 2): if the caller supplied a resolver
      // and it recognizes this specific call, use the resolved callee's REAL
      // return facts (both flat and byPath, so a caller selecting one field
      // off a resolved call's structured return value gets the same
      // field-level precision as any other structure-preserving construct)
      // instead of the generic unresolved-call fallback below. This is what
      // makes the structure-preserving/structure-flattening invariant (see
      // DESIGN_INTRAPROCEDURAL.md §3) genuinely true for a call now: a
      // RESOLVED call is structure-preserving (forwards byPath); an
      // UNRESOLVED one remains structure-flattening (flat + widened),
      // exactly as before this increment. `ctx` is optional and
      // backward-compatible — no `ctx` (or no `ctx.resolveCallSummary`)
      // falls straight through to the pre-existing behavior below,
      // unchanged.
      if (ctx?.resolveCallSummary) {
        const summary = ctx.resolveCallSummary(expr.callee, expr.args ?? [], state);
        if (summary) {
          return { flat: new Set(summary.returnFlat), byPath: new Map(summary.returnByPath), widened: false };
        }
      }
      const flat = new Set();
      for (const arg of expr.args ?? []) {
        const r = resolveExprIdentities(state, arg, ctx);
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
      const r = resolveExprIdentities(state, expr.source, ctx);
      return { flat: r.flat, byPath: r.byPath, widened: r.widened };
    }

    default:
      return noIdentity();
  }
}

function step(node, stateIn, widenings, ctx) {
  switch (node.kind) {
    case 'assign': {
      if (typeof node.target !== 'string') {
        // Assignment-expression-form destructuring (`({a} = obj)`, as opposed
        // to `const {a} = obj`) is lowered by the real parser into a single
        // `assign` node whose `target` is the raw pattern object, not a
        // string path — scanner/src/dataflow/engine.js (the sibling taint
        // engine) already guards this exact shape, a bug it once hit; this
        // package inherited the same gap until a final review found it.
        // Writing to a stringified pattern object as a fabricated path key
        // would silently collide across every unrelated destructuring
        // assignment in the function, merging their fields together.
        // Correctly tracking this form would require walking the pattern the
        // same way the parser already does for declaration-form destructuring
        // — deferred (matching the sibling engine's own precedent of skipping
        // rather than guessing) rather than attempted here.
        return { state: stateIn, returnFact: null };
      }
      const resolved = resolveExprIdentities(stateIn, node.source, ctx);
      if (pathHasWildcard(node.target)) {
        // A computed-key write (`obj[k] = ...`) must be a WEAK update (add to
        // whatever the container already carries, never clear it first) — a
        // strong update here would treat two genuinely different (but
        // statically indistinguishable) write locations as the same location,
        // silently deleting an earlier write. scanner/src/dataflow/engine.js's
        // `_addPathAliasAware` already established this exact precedent for
        // the sibling taint engine; this mirrors it. Round 6: generalized to
        // an INTERIOR wildcard too (e.g. 'store.*.name' from
        // `store[k].name = ...`) — round 5's trailing-only check
        // (`endsWith('.*')`) let this fall through to a strong update one
        // path segment deeper, recreating round 5's own bug.
        const containerPath = definitePrefixBeforeWildcard(node.target);
        let wState = stateIn;
        if (containerPath) {
          const allIds = new Set([...residualFlat(resolved.flat, resolved.byPath), ...[...resolved.byPath.values()].flatMap((s) => [...s])]);
          for (const id of allIds) wState = addIdentity(wState, containerPath, id);
          if (allIds.size > 0) {
            widenings.push({ atPath: containerPath, dataElementIds: [...allIds], reason: 'dynamic-property-key', line: node.line });
          }
        }
        return { state: wState, returnFact: null };
      }
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
      // This CFG node kind is a bare call-statement (its return value is
      // discarded, e.g. `logEvent(user);`), evaluated here purely to flag
      // widening on its ARGUMENT expressions. `ctx` is threaded through
      // for consistency with every other resolveExprIdentities call site
      // in this file — an argument can itself be a nested, RESOLVED call
      // expression (e.g. `logEvent(copyEmail(user))`), and without `ctx`
      // that nested call would spuriously widen on the resolved callee's
      // full argument set instead of using its real (possibly narrower)
      // return facts, exactly the same imprecision increment B2 closes for
      // the `assign`/`return` cases. This does not change what this case
      // itself does with the result (still only checks `r.flat` for a
      // widening event) — it only lets a nested `call` sub-expression
      // resolve precisely when `ctx` makes that possible.
      for (const arg of node.args ?? []) {
        const r = resolveExprIdentities(stateIn, arg, ctx);
        if (r.flat.size > 0) {
          widenings.push({ atPath: null, dataElementIds: [...r.flat], reason: 'unresolved-call-arg', line: node.line });
        }
      }
      return { state: stateIn, returnFact: null };
    }

    case 'return': {
      const resolved = node.value ? resolveExprIdentities(stateIn, node.value, ctx) : { flat: new Set(), widened: false };
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

export function analyzeFunctionFieldIdentity(fn, entryState, ctx) {
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
    const { state: out, returnFact } = step(node, incoming, widenings, ctx);
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
