import { accessPathOf, pathIsCoveredByPrefix } from '../dataflow/access-paths.js';
import { identitiesAt, emptyState, removeIdentitiesAt, addIdentity, joinStates, statesEqual, hashState } from './field-identity.js';

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

// --- Path provenance hop recording (Sub-project C, increment 1) ---------
// See DESIGN_PATH_PROVENANCE.md for the full design. Only two helpers below
// are new; everything else in this file is unchanged in shape, and the
// accumulator (`ctx.recordHop`) is threaded exactly the way `ctx` already
// flows everywhere (Decision 7) — no new plumbing, no new parameters.

// Which state keys jointly contributed each id to identitiesAt(state, path)?
// Mirrors identitiesAt's own bidirectional prefix-coverage test (field-
// identity.js) EXACTLY — if that test ever changes, this must change with
// it or the provenance DAG silently disconnects (Decision 6). Single pass
// over `state`: O(|state|) total for every id at `path`, not O(|state| x
// |ids|) — the naive per-id-loop cost the design doc's initial draft
// understated and a review corrected (Decision 6, "Cost, corrected"). Used
// internally by the engine's own hop-recording sites; never called on the
// hot path when no recorder is present (guarded by `ctx?.recordHop` at each
// call site, matching Decision 1's "extra, discarded computation" allowance).
function contributingKeysAllIds(state, path) {
  const byId = new Map();
  for (const [candidatePath, ids] of state) {
    if (!(pathIsCoveredByPrefix(path, candidatePath) || pathIsCoveredByPrefix(candidatePath, path))) continue;
    for (const id of ids) {
      const set = byId.get(id) ?? new Set();
      set.add(candidatePath);
      byId.set(id, set);
    }
  }
  return byId;
}

// Per-id form of the above, exported for DESIGN_PATH_PROVENANCE.md's
// structural test guard (a design review recommendation, folded into Task
// 2 of the Sub-project C increment-1 plan): a test asserts that
// unioning `contributingKeys(state, path, id)` over every id in
// `identitiesAt(state, path)` reconstructs that same set exactly, so a
// future change to identitiesAt's coverage test that isn't mirrored here
// fails loudly instead of silently disconnecting the DAG. Not on the
// engine's own hot path (see contributingKeysAllIds above) — this is a
// thin per-id wrapper for test/debugging use, where re-scanning `state`
// once per call is fine.
export function contributingKeys(state, path, id) {
  return contributingKeysAllIds(state, path).get(id) ?? new Set();
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
      // Path provenance (Sub-project C, increment 1, Task 2 instrumented
      // site 1 of 4): one production/ident in-half per (contributing state
      // key, dataElementId) pair — Decision 6, NOT one per queried `path`.
      // Extra computation whose result is entirely discarded when no
      // recorder is present (Decision 1).
      if (ctx?.recordHop) {
        const contrib = contributingKeysAllIds(state, path);
        for (const id of flat) {
          const keys = contrib.get(id);
          if (!keys) continue;
          for (const key of keys) {
            ctx.recordHop({
              kind: 'production', subKind: 'ident',
              fromPath: key, toPath: null, dataElementId: id,
              syntacticPath: key === path ? null : path,
              widenReason: null, lossReason: null,
            });
          }
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
          // Path provenance (Sub-project C, increment 2, Task 1, §10.1
          // `member` path-branch/wildcard row): fromPath is the DEFINITE
          // PREFIX before the wildcard, never the raw '*'-containing path
          // (Decision 5) — recording the wildcard form would create a DAG
          // node no read hop could ever reach.
          if (ctx?.recordHop) {
            for (const id of flat) {
              ctx.recordHop({
                kind: 'selection', subKind: 'member',
                fromPath: basePath, toPath: null, dataElementId: id,
                syntacticPath: path, widenReason: 'dynamic-property-key', lossReason: null,
              });
            }
          }
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
        // Path provenance (§10.1 `member` path-branch/no-wildcard row): one
        // selection in-half per (contributing state key, dataElementId)
        // pair — Decision 6, exactly the same pattern as `ident` above
        // (this branch IS structurally identical to ident's own
        // resolution, just against a dotted path instead of a bare name).
        if (ctx?.recordHop) {
          const contrib = contributingKeysAllIds(state, path);
          for (const id of flat) {
            const keys = contrib.get(id);
            if (!keys) continue;
            for (const key of keys) {
              ctx.recordHop({
                kind: 'selection', subKind: 'member',
                fromPath: key, toPath: null, dataElementId: id,
                syntacticPath: key === path ? null : path,
                widenReason: null, lossReason: null,
              });
            }
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
        const flat = new Set(base.flat);
        // Path provenance (§10.1 `member` non-path-base/`prop==='*'` row):
        // fromPath null — the base is an in-flight value, not itself a
        // state key; the base's own recursion already emitted whatever
        // state-backed in-halves it carries. This hop only annotates the
        // (widened) selection.
        if (ctx?.recordHop) {
          for (const id of flat) {
            ctx.recordHop({
              kind: 'selection', subKind: 'member',
              fromPath: null, toPath: null, dataElementId: id,
              syntacticPath: null, widenReason: 'dynamic-property-key', lossReason: null,
            });
          }
        }
        return { flat, byPath: new Map(), widened: base.flat.size > 0 };
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
      // Path provenance (§10.1 `member` non-path-base/`prop !== '*'` row):
      // fromPath null, same reasoning as the `prop === '*'` branch above —
      // this hop only annotates the selection, per id in the resulting
      // (post-selection) flat set.
      if (ctx?.recordHop) {
        for (const id of flat) {
          ctx.recordHop({
            kind: 'selection', subKind: 'member',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: null, lossReason: null,
          });
        }
      }
      return { flat, byPath, widened: base.widened };
    }

    // Path provenance (§10.1): `literal` emits nothing, because no identity
    // exists to have provenance. `unknown` also emits nothing — nothing was
    // resolved, so nothing is being dropped; a `lossReason` here would be
    // speculative, and §10.1 is explicit that this is a decide-with-
    // evidence call, not something to add on spec alone.
    case 'literal':
    case 'unknown':
      return noIdentity();

    case 'object': {
      const flat = new Set();
      const byPath = new Map();
      for (const prop of expr.props) {
        const r = resolveExprIdentities(state, prop.value, ctx);
        for (const id of r.flat) flat.add(id);
        // Path provenance (Sub-project C, increment 1, Task 2 instrumented
        // site 2 of 4): one production/object in-half per id this property
        // contributes, fromPath null — a fresh structural annotation, not a
        // prior aliasing source (Decision 5/§10.1). All three rows of
        // §10.1's `object` table (plain, spread, `*`-keyed) agree on
        // kind/fromPath/toPath, so this is emitted once here rather than
        // duplicated in each of the three branches below — but they do NOT
        // agree on widenReason: the `*`-keyed row is explicitly
        // `'dynamic-property-key'` (a computed key we cannot statically
        // resolve), while a plain or spread property is an explicit,
        // non-widened flow. A fix-round review caught this file's own
        // earlier comment overstating the agreement to cover widenReason
        // too, which had silently left `{[k]: v}` graded as an explicit
        // flow.
        if (ctx?.recordHop) {
          const objWidenReason = prop.key === '*' ? 'dynamic-property-key' : null;
          for (const id of r.flat) {
            ctx.recordHop({
              kind: 'production', subKind: 'object',
              fromPath: null, toPath: null, dataElementId: id,
              syntacticPath: null, widenReason: objWidenReason, lossReason: null,
            });
          }
        }
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
      // Path provenance (§10.1 `array` row): structure-flattening by
      // design (spread ambiguity, ADR §4) — identity propagates FULLY;
      // only per-index distinction is lost, which is a precision fact, not
      // an identity loss, so no widenReason/lossReason here.
      if (ctx?.recordHop) {
        for (const id of flat) {
          ctx.recordHop({
            kind: 'production', subKind: 'array',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: null, lossReason: null,
          });
        }
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'tpl': {
      const flat = new Set();
      for (const part of expr.parts) {
        const r = resolveExprIdentities(state, part, ctx);
        for (const id of r.flat) flat.add(id);
      }
      // Path provenance (§10.1 `tpl` row): transformation-bearing — the
      // identity is embedded in a new string. This is an EXPLICIT flow, not
      // a widened one (ADR §4), so no widenReason.
      if (ctx?.recordHop) {
        for (const id of flat) {
          ctx.recordHop({
            kind: 'production', subKind: 'tpl',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: null, lossReason: null,
          });
        }
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
      const flat = new Set([...left.flat, ...right.flat]);
      // Path provenance (§10.1 `binary` row): same as `tpl` — deliberately
      // a separate case (not shared) per ADR §4, but the hop shape agrees.
      if (ctx?.recordHop) {
        for (const id of flat) {
          ctx.recordHop({
            kind: 'production', subKind: 'binary',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: null, lossReason: null,
          });
        }
      }
      return { flat, byPath: new Map(), widened: false };
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
      // Path provenance (§10.1 `logical` row): structure-preserving
      // (short-circuit evaluation can return an operand verbatim) — no
      // widenReason.
      if (ctx?.recordHop) {
        for (const id of flat) {
          ctx.recordHop({
            kind: 'production', subKind: 'logical',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: null, lossReason: null,
          });
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
      // Path provenance (§10.1 `union` row): structure-preserving — both
      // branches emitted their own in-halves during recursion above; this
      // hop annotates the resulting selection. Both branches' ids landing
      // here is FR-305's genuine multiple-path case, not §9.1's phantom
      // cross-join.
      if (ctx?.recordHop) {
        for (const id of flat) {
          ctx.recordHop({
            kind: 'production', subKind: 'union',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: null, lossReason: null,
          });
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
        // Path provenance (Sub-project C, increment 3, §13.1): pass the
        // whole stamped ctx as a 4th argument — this is the ONLY place the
        // full ctx crosses from engine.js into summaries.js. `ctx` here is
        // already the stamped `stepCtx` (§7.2), so this hands
        // resolveCallSummary both the caller's recorder AND the caller's
        // scope/nodeId/line/context stamping in one object.
        const summary = ctx.resolveCallSummary(expr.callee, expr.args ?? [], state, ctx);
        if (summary) {
          const flat = new Set(summary.returnFlat);
          const byPath = new Map(summary.returnByPath);
          // Path provenance (§10.1 `call` resolved row): records only that
          // a RESOLVED call contributed — the actual cross-function stitch
          // is C3's job, not C2's.
          //
          // §13.2(c): peerScope/peerContext name the callee this call
          // resolved to, so C4 can connect this hop to the callee's own
          // write-out/return hops. `?? null`, never a bare reference — a
          // 3-argument resolveCallSummary stub (an older/hand-built test
          // fixture that doesn't return resolvedQid/resolvedContext) must
          // not throw or stamp `undefined`.
          if (ctx?.recordHop) {
            for (const id of flat) {
              ctx.recordHop({
                kind: 'production', subKind: 'call-resolved',
                fromPath: null, toPath: null, dataElementId: id,
                syntacticPath: null, widenReason: null, lossReason: null,
                peerScope: summary.resolvedQid ?? null, peerContext: summary.resolvedContext ?? null,
              });
            }
          }
          return { flat, byPath, widened: false };
        }
      }
      const flat = new Set();
      for (const arg of expr.args ?? []) {
        const r = resolveExprIdentities(state, arg, ctx);
        for (const id of r.flat) flat.add(id);
      }
      // Path provenance (§10.1 `call` unresolved row): an unresolved call's
      // return is genuinely unknown structure — flat + widened, never
      // laundered into a clean value.
      if (ctx?.recordHop) {
        for (const id of flat) {
          ctx.recordHop({
            kind: 'production', subKind: 'call',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: 'unresolved-call', lossReason: null,
          });
        }
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
      // Path provenance (§10.1 `assign-expr` row): pure pass-through — the
      // source's own recursion already emitted its own in-halves; this hop
      // forwards the source's `widened` flag, so it forwards an approximate
      // widenReason too, matching the SAME documented-approximate
      // 'unresolved-call' convention step()'s `assign`/`return` hops
      // already use (resolveExprIdentities's return shape has no real
      // reason string to forward — see Decision 3's deviation note; a full
      // fix needs a broader threading change, out of this task's scope).
      // Note the known limitation this case already documents: it does not
      // write to state, so there is no write-out hop here — an in-half with
      // no out-half that is NOT a loss.
      if (ctx?.recordHop) {
        const assignExprWidenReason = r.widened && r.flat.size > 0 ? 'unresolved-call' : null;
        for (const id of r.flat) {
          ctx.recordHop({
            kind: 'production', subKind: 'assign-expr',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: assignExprWidenReason, lossReason: null,
          });
        }
      }
      return { flat: r.flat, byPath: r.byPath, widened: r.widened };
    }

    // Path provenance (§10.1): the switch's own `default` — no known case
    // matched, nothing was resolved, so (same reasoning as `unknown` above)
    // nothing is being dropped and there is nothing to record.
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
        //
        // Path provenance (Sub-project C, increment 2, Task 2, §10.2
        // `assign`/target-not-a-string row): a genuine LOSS site —
        // `lossReason: 'unsupported-target'`. The design doc's own dated
        // correction to this row is explicit that resolving `node.source`
        // is NOT merely discarded computation once a recorder IS present:
        // running the full resolveExprIdentities tree on node.source
        // genuinely EMITS real production/selection in-half hops for
        // whatever it reads — these correctly join with this row's own
        // loss marker to show "this data was read here, then lost, because
        // the target couldn't be represented" (arguably necessary for
        // §18.4's transparency requirement, not incidental). If
        // node.source resolves no identity at all, none of that fires and
        // there is nothing to lose.
        //
        // CORRECTION (final whole-branch review): this resolve must run
        // UNCONDITIONALLY, not gated on `ctx?.recordHop` — an earlier
        // version gated it, reasoning it was "extra, discarded computation"
        // per Decision 1. That reasoning is wrong for THIS call specifically:
        // resolveExprIdentities is not side-effect-free when
        // ctx.resolveCallSummary is present (interprocedural mode) — its
        // `call` case can trigger FieldIdentitySummaryCache.compute() for a
        // callee, which registers a context against that function's
        // distinct-context cap (summaries.js). Gating the resolve on
        // ctx?.recordHop therefore meant a recorder's mere PRESENCE could
        // consume cap budget a non-recorder run never would, silently
        // changing a LATER, unrelated call site's own resolution once the
        // cap is hit — a real, reproduced violation of this whole
        // increment's own "byte-identical with no recorder" acceptance bar,
        // in the unsound direction (attaching a recorder made the analysis
        // LOSE an identity a no-recorder run kept). The fix: resolve
        // unconditionally (matching the sibling `assign` branches below,
        // which already do this), and gate ONLY the hop emission on
        // `ctx?.recordHop` — mirroring Decision 1's own "extra computation
        // is fine to skip, but only when it is genuinely side-effect-free"
        // intent, which this call never actually satisfied.
        const resolved = resolveExprIdentities(stateIn, node.source, ctx);
        if (ctx?.recordHop) {
          const allIds = new Set([...residualFlat(resolved.flat, resolved.byPath), ...[...resolved.byPath.values()].flatMap((s) => [...s])]);
          for (const id of allIds) {
            ctx.recordHop({
              kind: 'write-out', subKind: 'assign',
              fromPath: null, toPath: null, dataElementId: id,
              syntacticPath: null, widenReason: null, lossReason: 'unsupported-target',
            });
          }
        }
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
          // Path provenance (§10.2 `assign`/wildcard-target row): one
          // write-out/assign-weak record per (containerPath, id) — toPath
          // is the DEFINITE PREFIX before the wildcard (Decision 5, same
          // discipline as `member`'s wildcard-read branch), never the raw
          // '*'-containing `node.target`, which is carried instead on
          // `syntacticPath`. This is a WEAK update (no kill), so
          // `widenReason: 'dynamic-property-key'` — mirrors the widenings
          // ledger push below, not a new/better reason.
          for (const id of allIds) {
            wState = addIdentity(wState, containerPath, id);
            if (ctx?.recordHop) {
              ctx.recordHop({
                kind: 'write-out', subKind: 'assign-weak',
                fromPath: null, toPath: containerPath, dataElementId: id,
                syntacticPath: node.target, widenReason: 'dynamic-property-key', lossReason: null,
              });
            }
          }
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
      //
      // Path provenance (Sub-project C, increment 1, Task 2 instrumented
      // site 3 of 4): one write-out/assign out-half per `addIdentity` call,
      // at the EXACT path just written (never `node.target` alone for a
      // byPath entry — DESIGN_PATH_PROVENANCE.md §10.1 flags recording the
      // coarser `node.target` here as "the most likely C2 mistake", since it
      // would mismatch the granularity every read hop uses and disconnect
      // the DAG). `widenReason` mirrors the SAME (documented-approximate)
      // 'unresolved-call' label the widenings ledger below already uses in
      // this exact branch — not a new/better reason, just the one this
      // task's scope has evidence for; see the CLAUDE.md note on that
      // ledger's own known mislabeling, which this hop record inherits
      // rather than fixes (fixing it needs resolveExprIdentities's return
      // shape to thread a real reason string, out of Task 2's scope).
      const residual = residualFlat(resolved.flat, resolved.byPath);
      const assignWidenReason = resolved.widened && resolved.flat.size > 0 ? 'unresolved-call' : null;
      for (const id of residual) {
        state = addIdentity(state, node.target, id);
        if (ctx?.recordHop) {
          ctx.recordHop({
            kind: 'write-out', subKind: 'assign',
            fromPath: null, toPath: node.target, dataElementId: id,
            syntacticPath: null, widenReason: assignWidenReason, lossReason: null,
          });
        }
      }
      for (const [subPath, ids] of resolved.byPath) {
        for (const id of ids) {
          const toPath = `${node.target}.${subPath}`;
          state = addIdentity(state, toPath, id);
          if (ctx?.recordHop) {
            ctx.recordHop({
              kind: 'write-out', subKind: 'assign',
              fromPath: null, toPath, dataElementId: id,
              syntacticPath: null, widenReason: assignWidenReason, lossReason: null,
            });
          }
        }
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
        // Path provenance (§10.2 `call` bare-statement row): one
        // write-out/call-arg record per id in the argument's resolved
        // identity set — the value LEAVES the analysis via an argument.
        // This is an ESCAPE, not a loss (the natural sink-attachment point
        // for Sub-project D), so no lossReason/widenReason here — mirrors
        // `return`'s own write-out hop shape (toPath deliberately null).
        if (ctx?.recordHop) {
          for (const id of r.flat) {
            ctx.recordHop({
              kind: 'write-out', subKind: 'call-arg',
              fromPath: null, toPath: null, dataElementId: id,
              syntacticPath: null, widenReason: null, lossReason: null,
            });
          }
        }
      }
      return { state: stateIn, returnFact: null };
    }

    case 'return': {
      const resolved = node.value ? resolveExprIdentities(stateIn, node.value, ctx) : { flat: new Set(), widened: false };
      if (resolved.widened && resolved.flat.size > 0) {
        widenings.push({ atPath: null, dataElementIds: [...resolved.flat], reason: 'unresolved-call', line: node.line });
      }
      // Path provenance (Sub-project C, increment 1, Task 2 instrumented
      // site 4 of 4): one write-out/return out-half per id, toPath
      // deliberately null (a return exits the function, it doesn't land at
      // a path) — never a fabricated pseudo-path like '@return'
      // (DESIGN_PATH_PROVENANCE.md §3/§10.1: mixing a fabricated token into
      // the endpoint namespace is exactly Decision 5's forbidden bug class).
      // C3/C4 identify a function exit by
      // `kind === 'write-out' && subKind === 'return' && toPath === null`.
      if (ctx?.recordHop) {
        const returnWidenReason = resolved.widened && resolved.flat.size > 0 ? 'unresolved-call' : null;
        for (const id of resolved.flat) {
          ctx.recordHop({
            kind: 'write-out', subKind: 'return',
            fromPath: null, toPath: null, dataElementId: id,
            syntacticPath: null, widenReason: returnWidenReason, lossReason: null,
          });
        }
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
  // Path provenance (Sub-project C, increment 1, Decision 7.2): stamped
  // once for the whole analysis, since resolveExprIdentities never sees the
  // enclosing function.
  const scope = fn.qid ?? null;
  // Path provenance (Sub-project C, increment 3, §13.3): computed once per
  // analysis run, alongside `scope` — never per hop. `null` when no
  // recorder is present, matching every other conditional field this file
  // stamps. `hashState(entryState)` is the exact primitive
  // FieldIdentitySummaryCache already keys on (summaries.js's `_key`), so
  // two hops share a `context` iff the cache would consider them the same
  // context.
  const context = ctx?.recordHop ? hashState(entryState) : null;

  while (work.length) {
    if (++iterations > ITER_BUDGET) break;
    const nid = work.shift();
    const node = nodes[nid];
    if (!node) continue;
    const incoming = inStates.get(nid) ?? emptyState();
    // Path provenance (Decision 7.2): `nodeId`/`line` are stamped here, once
    // per node visit, from the worklist's own map key `nid` — NEVER from
    // `node.id` (hand-built CFG fixtures, e.g. test/lineage/engine-walker
    // .test.js, set no `id` field on their nodes at all; the real parser
    // does set `node.id`, equal to the map key, so `nid` is correct for
    // both). With no recorder present, `stepCtx` is the SAME `ctx` reference
    // — no allocation, nothing for a backward-compatibility test to catch
    // (Decision 7.2's "true by construction" point).
    const stepCtx = ctx?.recordHop
      ? { ...ctx, recordHop: (h) => ctx.recordHop({
          scope, nodeId: nid, line: node.line ?? null,
          context, peerScope: null, peerContext: null,
          ...h,
        }) }
      : ctx;
    const { state: out, returnFact } = step(node, incoming, widenings, stepCtx);
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
