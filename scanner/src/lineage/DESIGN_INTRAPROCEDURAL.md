# Intraprocedural Field-Identity Engine — Design Record

Scope: Sub-project A of Milestone 1 (see
`docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`).
Single-function analysis only. No interprocedural resolution, no path DAG,
no registry integration.

## 1. State shape

`Map<accessPath: string, Set<dataElementId: string>>` — for each access path
reachable in a function, the set of data-element IDs it carries. This is the
direct fix for FR-301: the existing taint engine's state
(`scanner/src/dataflow/access-paths.js`'s `Set<accessPath>`, boolean per
path) cannot distinguish "this path carries data element X" from "this path
carries data element Y" — only "this path is tainted." The existing
interprocedural summary cache (`scanner/src/dataflow/summaries.js`) is
explicitly documented as parameter-granularity only ("`f(obj)` with obj.foo
tainted is treated the same as obj.bar tainted") — reusing that state shape
would silently violate FR-301 the first time a benchmark case exercised two
distinct fields on the same object parameter. This is a hard fork, decided
here, not left to a later task to discover partway through implementation.

## 2. Reuse boundary (binding on every later task and sub-project)

**Reused directly, as pure utilities, unmodified:**
- `scanner/src/dataflow/access-paths.js`'s `accessPathOf`,
  `pathIsCoveredByPrefix`, `isCoveredBy` — all operate purely on path
  strings, no taint state involved. Confirmed by reading the file: none of
  its exports take or return taint-specific state.
- The real JS/TS IR shape from `scanner/src/ir/parser-js.js` — consumed
  as-is, never reimplemented.

**Structurally mirrored (same algorithm, new state type), never imported:**
- `scanner/src/dataflow/engine.js`'s `analyzeFunction` worklist loop (forward
  dataflow analysis, explicit worklist, join-via-repeated-merge at CFG
  branch-rejoin points, no separate "join node" concept — a rejoin is just
  a point that receives more than one predecessor's merged state over the
  worklist's lifetime). This package's own `analyzeFunctionFieldIdentity`
  (Task 4) copies this ALGORITHM, not this file's code or state.

**Never reused, must be reimplemented for field-identity semantics:**
- `access-paths.js`'s `addPath`/`removePathAndDescendants`/`joinSets` — these
  operate on `Set<string>` (presence/absence). Field identity needs
  Map-shaped equivalents that union *label sets* per path on join, not just
  path presence. See `field-identity.js` (Task 2).
- `scanner/src/dataflow/summaries.js`'s `SummaryCache` — out of scope for
  this plan (interprocedural is Sub-project B), but its `_hashState`
  approach (canonicalize then hash) is worth mirroring conceptually once
  Sub-project B needs a cache key over field-identity state; `field-identity.js`
  ships a `hashState` now specifically so Sub-project B doesn't have to
  retrofit one onto an already-shipped state shape.

**Forbidden absolutely:** importing `scanner/src/dataflow/engine.js` or
touching its live taint `Set<accessPath>` state. Per
`scanner/src/lineage/CLAUDE.md` and PRD §3.1/§18.1.

## 3. Ancestor/descendant semantics (bidirectional — corrected from the original one-directional design)

`identitiesAt(state, path)` aggregates in BOTH directions:

- **Ancestor coverage** (original): a coarser recorded fact about a
  container implies the same fact about anything under it, when nothing
  more specific overrides it — `identitiesAt(state, 'obj.email')` includes
  any identity recorded at `'obj'` itself. Mirrors `access-paths.js`'s
  `isCoveredBy`.
- **Descendant coverage** (added by the corrected design below): asking
  about a container AS A WHOLE aggregates everything recorded under it —
  `identitiesAt(state, 'obj')` includes an identity recorded only at
  `'obj.email'`. The object legitimately carries every field's identity
  when read as a whole (`return obj` after `obj = {email: X, ssn: Y}` must
  see both).

This does NOT reintroduce cross-field leakage: querying `obj.email` never
picks up a sibling path like `obj.ssn` — neither is a prefix of the other,
so descendant coverage only ever aggregates when the query path is an
actual ancestor of the recorded path, never across siblings.

### Corrected design

The original design (above, before this note) was one-directional:
ancestor-visible-from-descendant only, with the reverse deliberately
excluded ("asking about the whole object doesn't imply you learn a fact
that was only ever established about one of its fields"). This was wrong,
and the final whole-branch review (composing pieces no single task review
had reason to combine) found why: `assign`'s object-literal handling
combined with the one-directional `identitiesAt` forced a choice between
two broken options —

(a) write the object literal's resolved identities BOTH at each field's
    own sub-path (`rec.email`, `rec.ssn`) AND as a flat union at the
    container's own path (`rec`) — needed so a later whole-object read
    (`return rec`) could see every field, since one-directional
    `identitiesAt` couldn't look downward. But this write is exactly
    FR-301's violation: `identitiesAt(state, 'rec.email')` then
    ancestor-inherits from the coarse `rec` entry and returns
    `{email, ssn}` — both fields, merged, for a query that asked about
    only one. This was the actual bug (see `engine.js`'s pre-fix `assign`
    case), and it was a plan-authoring bug, not an implementer error — the
    flat-union-at-root write was specified verbatim in this project's own
    original brief.

(b) drop the flat-union-at-root write and keep only the per-field
    sub-path writes — this fixes (a) but breaks `return rec`: with the
    old one-directional `identitiesAt`, querying `rec` finds nothing,
    since no identity was ever recorded at `rec` itself.

The bidirectional design resolves both without a redundant coarse write:
per-field writes alone are sufficient (`assign`'s object-literal case now
writes ONLY `rec.email`/`rec.ssn`, never `rec`), `identitiesAt(state,
'rec.email')` correctly returns only `{email}` (no ancestor entry exists
to leak from), and `identitiesAt(state, 'rec')` correctly returns
`{email, ssn}` via descendant aggregation. Sibling paths remain correctly
isolated from each other throughout, since aggregation only ever follows
an actual prefix relationship.

Unlike boolean taint (where recording a fact at a coarser path makes any
existing finer-path fact redundant and `access-paths.js`'s `addPath` prunes
it away), field-identity state does **not** prune a descendant entry when an
ancestor gains a *different* identity — `obj` carrying data element X and
`obj.email` carrying data element Y are both real, independently meaningful
facts that must coexist (this coexistence IS FR-301's core requirement).
Pruning is deliberately NOT implemented as an optimization in this first
slice — `field-identity.js`'s state can carry redundant entries (an
ancestor and descendant both recording the same identity); this affects
efficiency, never correctness, since `identitiesAt`'s union already handles
it. Left as a documented, deferred optimization, not built now, per this
project's "don't design for hypothetical future requirements" convention.

### The residual principle (round 2 — closes an aliasing gap round 1 left open)

The bidirectional `identitiesAt` fix above (round 1) was necessary but not
sufficient. A final re-review of round 1 found the exact same coarse-merge
bug survives through one level of variable aliasing, because round 1 only
applied the "write per-field, not a coarse root value" rule at the object-
literal call site — `resolveExprIdentities`'s `ident`/`member` case still
unconditionally returned an empty `byPath`, even when the state genuinely
had per-field structure recorded under the resolved path. Concretely:

```js
function combine(user) {
  const copy = user;       // copy = user is a plain alias, not an object
                            // literal, so round 1's `assign` fix never
                            // triggers: resolveExprIdentities(state, user)
                            // returned byPath: Map() (always empty for
                            // ident/member), so `assign` fell into the
                            // byPath-empty branch and wrote the FULL flat
                            // union ({email, ssn}) at `copy`'s own path —
                            // exactly the coarse-root-write bug round 1
                            // fixed for object literals, recreated here.
  const e = copy.email;    // identitiesAt('copy.email') then ancestor-
                            // inherits from that coarse `copy` entry and
                            // returns {email, ssn} — both fields.
  return e;                 // WRONG: should be {email} only.
}
```

This was measurably *worse* than the pre-round-1 code for this exact shape:
before round 1, a one-directional `identitiesAt` silently dropped this flow
entirely (safe but useless); round 1's bidirectional `identitiesAt` can now
correctly resolve `user`'s full field set on read, but `assign` had nowhere
to put that structured information except a coarse merge — going from
"silently drops the flow" to "silently merges distinct fields", the more
serious of FR-301's two failure modes.

The fix generalizes round 1's rule into one helper, `residualFlat(flat,
byPath)` (`engine.js`), applied consistently at three sites rather than
being special-cased at `assign` alone:

1. `resolveExprIdentities`'s `ident`/`member` case now populates `byPath`
   from the state's recorded descendants of the resolved path — an alias
   like `user` (with `user.email`/`user.ssn` recorded) is now structurally
   indistinguishable from a fresh object literal `{email: ..., ssn: ...}`
   for every downstream consumer of `byPath`.
2. `resolveExprIdentities`'s `object` case writes `residualFlat(r.flat,
   r.byPath)` — not the full `r.flat` — coarsely at a property's own key.
   This closes a *deeper, compounding* version of the same bug that (1)
   alone would reintroduce: `{ a: someAliasedObject }`, where
   `someAliasedObject` is itself an alias with `byPath` structure (per (1)).
   Without this, the coarse write at key `a` would duplicate what the
   nested `a.x`/`a.y` entries already separate, one level deeper than round
   1 ever checked.
3. `step()`'s `assign` case collapses round 1's explicit
   byPath-empty-vs-nonempty branching into one rule: write every `byPath`
   entry at its own sub-path, and write `residualFlat(resolved.flat,
   resolved.byPath)` — whatever isn't already captured by that
   structure — coarsely at the target's own root. An empty residual is a
   no-op, so this naturally subsumes both of round 1's cases without
   branching on them explicitly.

`identitiesAt`'s read-side logic (the bidirectional aggregation from round
1) is untouched by this round — only the *write* side (what gets recorded
by `assign`, and how `resolveExprIdentities` reports structure to it)
changed. A whole-object read through an alias (`const copy = user; return
copy;`) still correctly aggregates every field, exactly as round 1's fix
already guaranteed, because that guarantee never depended on `assign`
writing a coarse value — it depended on `identitiesAt`'s descendant
aggregation, which this round doesn't touch.

## 4. Per-construct handling (JS/TS, this plan's scope)

- **Assignment** (`target: string`, `source: exprDesc`): resolve `source`'s
  identities, clear stale facts at `target` and its descendants
  (reassignment invalidates whatever was there), write the resolved
  identities at `target`.
- **Object literals**: each property's value is resolved recursively and
  attributed to `target.<key>` (dotted, nested objects produce dotted
  sub-paths like `target.a.b`) — this is the concrete mechanism that proves
  FR-301: two properties on one object literal, from two different data
  elements, land at two different access paths in the state, never merged.
  `assign`'s handling of this case writes ONLY these per-field `byPath`
  entries — never a coarse value at the container's own path (`target`
  itself) — because for a plain object literal the residual is always
  empty (see §3's "Corrected design" and "The residual principle"
  notes for why a coarse root write was tried and rejected, and for the
  general rule this is a special case of). This is the documented,
  correct behavior, not an oversight: `identitiesAt`'s descendant
  aggregation (§3) already answers a whole-object read like `return
  target` correctly from the per-field entries alone. The same residual
  rule applies identically to a plain variable/property alias
  (`target = someOtherRef`) — see §3's "The residual principle" note —
  since round 2 made `resolveExprIdentities` report `byPath` structure
  for those references too, not just for object literals.
- **Array literals**: flattened, no index sensitivity — matches
  `access-paths.js`'s own documented limitation (no `[i]`/`[*]` support;
  "index sensitivity is a follow-on"). An array carrying two different
  fields at two different indices is not distinguishable in this slice;
  this is an accepted, documented limitation, not silently wrong (every
  element's identities are still recorded, just flattened into one bag
  rather than per-index).
- **Member access** (property read): resolves via `accessPathOf` +
  `identitiesAt` — no new logic needed, this is what those functions exist
  for.
- **Template literals and string concatenation (`binary`/`logical` with
  string operators, `tpl` interpolation)**: DO propagate identity normally
  (not flagged as widened/implicit). Rationale: the underlying value is
  genuinely and traceably present in the result — this is different in kind
  from FR-306's "implicit and widened" category, which is about flows whose
  connection to the original field is inferred/approximate (an unresolved
  call, a dynamic property key), not flows where the field's actual value is
  verbatim embedded in a larger string. This is a real design call, stated
  explicitly here so it isn't silently assumed by whichever task implements
  the resolver.
- **Unresolved function calls** (every call in this plan's scope, since no
  registry/summary integration exists yet): the call's result is treated as
  conservatively carrying the union of its arguments' resolved identities,
  but flagged as a **widening event** (`{atPath, dataElementIds, reason,
  line}`) — a side list the engine returns alongside its main state, never
  silently dropped. This satisfies the project's "never launder identity
  into a clean value" principle (mirrors PRD §18.4's "never translate 'path
  budget exhausted' into 'no path'" spirit) without requiring this plan to
  build the registry integration that would let some calls resolve
  precisely (that's Sub-project D's job).
- **Destructuring**: resolved (Task 5 read the real IR lowering directly,
  closing the open question this ADR originally left unanswered).
  `const {email, ssn} = user;` lowers to one plain `assign` CFG node per
  bound name — a string `target` (e.g. `'email'`) and a `member`-kind
  `source` (e.g. `{kind: 'member', object: {kind: 'ident', name: 'user'},
  prop: 'email'}`) — see `scanner/src/ir/parser-js.js`'s
  `VariableDeclarator` visitor, the `id.kind === 'object-pattern'` branch,
  around lines 453-463. This is byte-identical to the shape `step()`'s
  `'assign'` case already handles for a plain `member`-sourced assignment,
  so destructuring required zero special-case code in `engine.js` —
  confirmed end to end against the real parser in
  `test/lineage/engine-integration.test.js`.
- **Ternary/conditional expressions** (`union` kind, both branches kept by
  the parser — never resolved to one): both branches' identities are
  unioned, matching the conservative "either could execute" semantics the
  worklist's branch-join already uses at the CFG level.
- **`unknown`-kind expressions** (JSX, anything the parser doesn't handle):
  resolve to "carries no identity" — fails open, matching the general IR
  contract's own `unknown` CFG-node-kind treatment. Not flagged as a
  coverage gap by this plan (that accounting is AC-11/coverage-ledger
  territory — Sub-project E's job, not this one's).

## 5. What this plan explicitly does NOT build (so later sub-projects don't assume it's here)

Interprocedural call resolution and summaries (Sub-project B); the path DAG
(Sub-project C); any connection to the source/sink registry or
transformation-kind catalog (Sub-project D); any `DataFlowGraph v1` output
(Sub-project E); any wiring into `runScan`/the CLI. This plan's output is
consumed directly by tests with hand-supplied entry facts, nothing else,
by design.
