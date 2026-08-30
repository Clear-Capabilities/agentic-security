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

## 3. Ancestor/descendant semantics (deliberately asymmetric, mirrors access-paths.js)

An ancestor path's recorded identity IS visible when querying a descendant
path (`identitiesAt(state, 'obj.email')` includes any identity recorded at
`'obj'` itself) — mirrors `access-paths.js`'s `isCoveredBy`: a coarser fact
is sound information about everything under it. The reverse does NOT hold:
a descendant's identity is never visible when querying its ancestor
(`identitiesAt(state, 'obj')` does NOT include an identity recorded only at
`'obj.email'`) — asking about the whole object doesn't imply you learn a
fact that was only ever established about one of its fields.

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
- **Destructuring**: NOT resolved in this design record — the real IR
  lowering for `const {a, b} = x` was not read during this plan's research
  pass (parser-js.js's destructuring-to-CFG lowering lives before the
  section that was read). Task 4/5 must read that code directly before
  implementing destructuring handling; see those tasks' explicit
  verification steps. This ADR intentionally does not assert a shape it
  cannot back with a real code citation.
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
