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
byPath)` (`engine.js`), applied consistently everywhere a `flat`+`byPath`
pair is written to a target/key — not special-cased at `assign` alone.
Two concrete applications from round 2:

- `resolveExprIdentities`'s `ident`/`member` case now populates `byPath`
  from the state's recorded descendants of the resolved path — an alias
  like `user` (with `user.email`/`user.ssn` recorded) is now structurally
  indistinguishable from a fresh object literal `{email: ..., ssn: ...}`
  for every downstream consumer of `byPath`.
- `resolveExprIdentities`'s `object` case writes `residualFlat(r.flat,
  r.byPath)` — not the full `r.flat` — coarsely at a property's own key.
  This closes a *deeper, compounding* version of the same bug that the
  point above alone would reintroduce: `{ a: someAliasedObject }`, where
  `someAliasedObject` is itself an alias with `byPath` structure. Without
  this, the coarse write at key `a` would duplicate what the nested
  `a.x`/`a.y` entries already separate, one level deeper than round 1 ever
  checked.
- `step()`'s `assign` case collapses round 1's explicit
  byPath-empty-vs-nonempty branching into one rule: write every `byPath`
  entry at its own sub-path, and write `residualFlat(resolved.flat,
  resolved.byPath)` — whatever isn't already captured by that
  structure — coarsely at the target's own root. An empty residual is a
  no-op, so this naturally subsumes both of round 1's cases without
  branching on them explicitly.

**This was originally written up as "applied consistently at exactly three
sites."** That was a mistake independent of whether the three were
correctly identified: a hand-counted enumeration reads as a closed,
completed list, and a fixed-count claim is exactly what let a fourth,
fifth, and sixth site (`union`, `logical`, `assign-expr` — see round 3
below) go unexamined through two further rounds of scrutiny. The durable
statement is the general invariant in "The structure-preserving vs.
structure-flattening invariant (round 3)" below, not a count. Treat any
future "N sites" phrasing in this document as a bug in the document.

`identitiesAt`'s read-side logic (the bidirectional aggregation from round
1) is untouched by round 2 or round 3 — only the *write* side (what gets
recorded by `assign`, and how `resolveExprIdentities` reports structure to
it) has changed. A whole-object read through an alias (`const copy = user;
return copy;`) still correctly aggregates every field, exactly as round 1's
fix already guaranteed, because that guarantee never depended on `assign`
writing a coarse value — it depended on `identitiesAt`'s descendant
aggregation, which neither round 2 nor round 3 touches.

### The structure-preserving vs. structure-flattening invariant (round 3 — closes the bug CLASS, not just individual sites)

A third re-review found the SAME coarse-merge bug survived, untouched by
rounds 1-2, in three more `resolveExprIdentities` cases: `union` (ternary),
`logical` (`||`/`&&`/`??`), and `assign-expr`. All three unconditionally
returned `byPath: new Map()` regardless of what their operands' `byPath`
contained — the same class of bug round 2 closed for `ident`/`member` and
`object`, just not yet applied here.

Confirmed via the real parser:

```js
const c = flag ? user : other;  return c.email;  // → [email, ssn, name] instead of [email]
const c = user ?? {};           return c.email;  // → [email, ssn]      instead of [email]
const c = flag ? user : user;   return c.email;  // → [email, ssn]      instead of [email]
```

The third example is the sharpest proof this is a bug rather than a
legitimate approximation: both ternary branches ARE the same object, so
there is no real alternative to justify merging `user`'s own fields
together — yet the pre-fix code did exactly that, purely because the
ternary *syntax* was present.

**Why this is the SAME bug, not the (legitimately different, already-
accepted) branch-alternatives approximation**: the CFG's own branch join
(`joinStates`) already handles the equivalent
`if (flag) { c = user; } else { c = other; } return c.email;` correctly —
it unions PER PATH, so `c.email`/`c.ssn`/`c.name` stay separated even
though the join conservatively doesn't know which branch ran. The
ternary/logical form of the exact same program gave a strictly WORSE
(wrong) answer for identical semantics — that asymmetry between two
syntactic forms of the same semantics is the tell. The correct
approximation is "union per sub-path across alternatives" (exactly what
`joinStates` already does at the CFG level) — NOT "flatten everything into
one coarse blob."

Rather than enumerate a fixed site count again (see the note above on why
that failed twice), the durable rule is: every `resolveExprIdentities` case
falls into one of two categories, and every case in the switch must be
checked against this invariant whenever the switch changes.

- **Structure-preserving** — its result could genuinely BE an existing
  structured value from `state`, by reference/selection, not by computing
  something new. Must forward `byPath`: `ident` (round 2), `member`
  (round 2 for the case where its base is a pure ident/member chain
  resolvable via `accessPathOf`; round 4 added a second path — see below —
  for when the base is NOT a pure chain, e.g. `(user ?? other).email`),
  `object` (constructs new structure directly; round 1/2), `union`
  (selects one branch verbatim; round 3), `logical` (short-circuit
  evaluation can return an operand verbatim; round 3), `assign-expr`
  (simple pass-through of its resolved source; round 3).
- **Structure-flattening, correctly and by design** — nothing to forward,
  or forwarding would be actively wrong. Stays flat-only, deliberately:
  `literal` (no state involved), `tpl` (template literals always produce a
  new string, primitivizing whatever's interpolated), `binary` (arithmetic/
  comparison operators always produce a new primitive — this is why
  `binary` and `logical` are split into separate cases as of round 3, not
  shared), `array` (this IR's parser transparently unwraps `SpreadElement`
  — see `scanner/src/ir/parser-js.js`'s `exprOf`'s `SpreadElement` case —
  so `[...xs, user]` and `[xs, user]` are byte-identical in the IR; naive
  per-index attribution would actively MISATTRIBUTE a spread source's
  contents to a literal index, which is worse than staying uniformly flat.
  This is corrected from an earlier, factually false version of this
  rationale — "no index-sensitive access paths" — which round 4's review
  found untrue: `accessPathOf`/the parser's `exprOf`/`lhsPath` DO extract
  literal computed keys and can build paths like `arr.0`. The spread
  ambiguity, not a missing capability, is the real reason to stay flat.
  Fixing this properly would require the parser to distinguish spread
  elements from literal elements first — out of scope for this plan),
  `call` (an unresolved call's return value is genuinely UNKNOWN structure
  — correctly flat + `widened: true`, honestly modeling "we don't know,"
  not laundering an identity), `unknown`/default (nothing to preserve).

### The three hop types the invariant covers (round 4 — broadens the invariant beyond `resolveExprIdentities`'s own switch)

A fourth re-review found the invariant as stated through round 3 was
itself scoped too narrowly: it only asked "which `resolveExprIdentities`
switch cases PRODUCE `byPath`," which is exactly the round-1-through-3
bug class, but misses two other places structure is lost that are not
about which case *produces* `byPath` at all.

- **Production** — a switch case building a value's structure. This is
  rounds 1-3's fixes, and the category the "structure-preserving vs.
  structure-flattening" list above documents.
- **Selection** — reading a field off an already-produced structured
  value. Round 3 taught `union`/`logical`/`object`/`assign-expr` to
  correctly report their structure via `byPath` when RESOLVED AS A WHOLE
  (e.g. `const c = user ?? other; return c.email;` correctly resolves to
  `[email]`), but the pre-round-3 `member` case resolved its base only via
  `accessPathOf`, which returns `null` for anything that isn't a pure
  ident/member chain — so `member` fell into `noIdentity()` and silently
  DROPPED the identity the moment the exact same value was read directly,
  with no intermediate variable: `return (user ?? other).email;` returned
  `[]`. Same semantics, two syntactic forms, two different (and one
  wrong) answers — the same tell every prior round used to find its bug.
  Fixed by giving `member` a second resolution path, alongside its
  existing `accessPathOf`-based one, that resolves the base recursively
  and selects `prop` out of the base's `byPath` — the read-side mirror of
  how `object`'s construction attributes a property to its own key.
- **Write-out** — writing a resolved value to a target path that must
  itself be a valid, non-fabricated path. `step()`'s `assign` case passed
  `node.target` straight through to `removeIdentitiesAt`/`addIdentity`
  with no guard that it was actually a string path. Assignment-expression-
  form destructuring (`({a} = obj)`, lowered by the real parser into one
  `assign` CFG node whose `target` is the raw pattern object, not a
  string) implicitly stringified to the literal string `"[object Object]"`
  — every such destructuring anywhere in a function collided onto this
  one fabricated key, silently merging fields from unrelated statements.
  Fixed by guarding `node.target` to be a string before writing anything
  (skip rather than fabricate a key), matching a precedent already
  established in the sibling taint engine (`scanner/src/dataflow/
  engine.js`'s own `assign` case) that this package had not inherited.

**The general rule going forward:** a structured value's `byPath` must
survive every hop it passes through — anywhere structure is built,
selected out of, or written to a target — losing it (via an empty
fallback, a fabricated key, or a coarse merge) at ANY of these three hop
types is this bug class, regardless of which specific construct triggers
it. Checking only "does this switch case forward `byPath`" (round 3's own
framing) is necessary but not sufficient — selection sites outside the
switch's own recursive calls, and write-out sites in `step()`, must be
checked too.

### Statically-unknown path components (round 5 — the three hop types were right, but assumed every PATH COMPONENT flowing through them was a real property name)

A fifth re-review found that round 4's three-hop-types invariant, while
correctly identifying *where* structure can be lost, never questioned
whether the path components flowing through those hops (`node.target`,
`expr.prop`, `prop.key`) are always real, distinct property names. They
are not: `scanner/src/dataflow/access-paths.js`'s `accessPathOf` — reused
directly by this package per §2's reuse boundary — already maps a
computed member access with a statically-unknown key (`user[k]`, where `k`
is a variable, not a literal) to a path ending in the literal segment `*`
(e.g. `"user.*"`). This is an existing, already-established convention in
the shared IR/access-path layer (`scanner/src/ir/parser-js.js`'s
`MemberExpression` case and `lhsPath`'s computed-write handling both
already emit it), not something round 5 invented — but this package had
never interpreted it specially, and it broke all three hop types at once:

- **Selection**: `member`'s path-succeeds branch queried
  `identitiesAt(state, 'user.*')` for `user[k]`, which never matches real
  entries like `'user.email'` — silently returning `[]` instead of
  propagating a widened flow. This directly contradicted this document's
  own §4 "Unresolved function calls" entry, which already named a dynamic
  property key as an example that must propagate as a widened flow, never
  silently vanish (FR-306's "never launder identity into a clean value"
  principle).
- **Write-out**: every computed-key write on the SAME container lowers to
  the SAME literal target string (`'bag.*'`), since the actual runtime key
  is statically unknown — `bag[k1] = user.email; bag[k2] = user.ssn;`
  produces two `assign` nodes with the identical target `'bag.*'`.
  `step()`'s `assign` case's STRONG update (`removeIdentitiesAt` before
  writing) treated these as the same location a later write legitimately
  overwrites, silently deleting the first write's identity —
  `scanner/src/dataflow/engine.js`'s `_addPathAliasAware` had already
  solved exactly this for the sibling taint engine (a trailing `.*` write
  must be a WEAK update — add to the container, never clear it first) but
  this package had not inherited that precedent, the same pattern as round
  4's Finding 5 (write-out sites need their own scrutiny, not just
  production/selection).
- **Production**: `scanner/src/ir/parser-js.js`'s `ObjectExpression`
  handling built each property's `key` as `p.key.name || ...` with no
  check of Babel's own `p.computed` flag — so a computed property with a
  non-literal key expression (`{[k]: v}`) resolved to the key
  EXPRESSION's own variable name (`'k'`), colliding with an explicit,
  non-computed property literally named `k` on the same object:
  `{ k: user.ssn, [k]: user.email }` produced two properties both keyed
  `'k'`, which `resolveExprIdentities`'s `object` case then merged into
  ONE byPath entry — FR-301's core violation, via a more innocuous-looking
  fabricated key than any prior round's finding.

**The fix**, entirely at the engine layer for selection/write-out
(wildcard handling is a policy decision about how to interpret a path
component, not something baked into `field-identity.js`'s pure state
primitives) plus a minimal, convention-following change to the shared
parser for production: a `'*'`-ending (or bare `'*'`) path component is
now recognized wherever it can appear —

- `member`'s path-succeeds branch and its non-path fallback both check for
  a `'*'` key/trailing-`.*` path and resolve the CONTAINER's full
  aggregate (via `identitiesAt`'s existing descendant aggregation, or the
  base's own `flat`), flagged `widened: true`.
- `step()`'s `assign` case checks for a `'*'`-ending target and performs a
  WEAK update (`addIdentity` onto whatever the container already carries,
  never `removeIdentitiesAt` first), flagged as a `dynamic-property-key`
  widening event.
- `parser-js.js`'s `ObjectExpression` handling now checks `p.computed`: a
  computed key that is itself a resolvable literal (`{[42]: v}`,
  `{['literal']: v}` — Babel still marks these `computed: true`) still
  resolves to that literal's string form, exactly as before; a computed
  key that is NOT a literal resolves to the literal string `'*'` —
  mirroring the EXISTING computed-member-access convention this same file
  already uses for `obj[k]` reads and writes, not a new one.
  `resolveExprIdentities`'s `object` case folds a `key === '*'` property
  into the object's coarse residual (never a byPath entry keyed `'*'`,
  which would just be a differently-shaped version of the same collision
  bug).

**The durable framing, restated once more per this round's own finding
(subsumes round 4's "three hop types" note and this round's finding
without needing to re-enumerate constructs again):** every path component
the IR supplies must be either a real property name or an explicitly
modeled unknown (`'*'`), and every kill (`removeIdentitiesAt`) must be
justified as a strong update on a definite, uniquely-identified location —
a write to an unknown/aliased location must be a weak update instead.

### Two under-enforcements of the round-5 invariant (round 6 — the invariant itself was correct, its application wasn't complete)

A sixth re-review found the round-5 invariant CORRECT but under-enforced in
two places, both fixed together.

**Finding 1 — destructuring keys had the same computed-key bug round 5
fixed for object literals.** Round 5 fixed `parser-js.js`'s
`ObjectExpression` handling (production, for `{[k]: v}`) but never touched
`lhsPath`'s `ObjectPattern` branch — the DESTRUCTURING-pattern lowering, a
different code path in the same file, used for `const {[field]: value} =
user`. It had the identical bug: a non-literal computed key resolved to the
key EXPRESSION's own variable name instead of `'*'`, so `const { [field]:
value } = user; return value;` silently dropped `value`'s identity
entirely (`returnFacts: []`) — the equivalent `return user[field]` already
widened correctly per round 5's fix.

Fixed by extracting the shared `resolveObjectKey(p)` helper from
`ObjectExpression`'s already-fixed logic and calling it from both sites, so
a third instance of this exact bug class can't appear in some future
object-key-reading code path in this file.

**Finding 2 — the round-5 wildcard guards only handled a TRAILING `'*'`,
not an INTERIOR one.** Round 5's guards in `engine.js` (`path === '*' ||
path.endsWith('.*')` on the selection side; `node.target === '*' ||
node.target.endsWith('.*')` on the write-out side) only recognized a
wildcard segment at the very end of a path. A wildcard can appear in the
MIDDLE too: `store[k1].name`/`store[k2].name` both lower to the identical
access path `'store.*.name'` (the `'*'` is interior, not trailing) —
`endsWith('.*')` is false for this string, so it fell through to the OLD,
unfixed strong-update/silent-drop behavior. This is round 5's own bug (b)
recurring one path segment deeper: the second assign's
`removeIdentitiesAt(state, 'store.*.name')` deleted the first write's
identity, and the read-side equivalent (`store[k].name = user.ssn; return
store.a.name;`) silently returned `[]` instead of conservatively resolving
via the definite prefix.

Fixed by replacing both position-dependent checks with two new shared
helpers in `engine.js`, `definitePrefixBeforeWildcard(path)` and
`pathHasWildcard(path)` — the former finds the longest wildcard-free prefix
of a path before its FIRST `'*'` segment, at any position, subsuming round
5's trailing-only handling as a special case (`'bag.*'` still resolves to
`'bag'`, exactly as before) while also correctly handling an interior one
(`'store.*.name'` now resolves to `'store'`, not falling through
unguarded).

`member`'s non-path fallback branch (round 4, for when `accessPathOf`
returns `null` because the base isn't a pure ident/member chain) needed no
change: it never constructs or parses a dotted path string in the first
place — it resolves the base recursively via the expression tree, and each
recursive call independently checks its own single-segment `expr.prop ===
'*'`. An "interior" wildcard in this branch's terms is just an outer
`member` node whose base (a nested `member`) itself has `prop === '*'` —
already handled by that same check firing one recursion level in, with no
path-string parsing involved at any level.

**Deferred, not fixed this round (Finding 3 from the same re-review):** a
widening event recorded by `assign`/`return`'s widening-push always uses
the hardcoded reason string `'unresolved-call'`, even when the actual
cause was a dynamic property key (`'dynamic-property-key'` is used
correctly at the `assign` case's own `'*'`-target weak-update branch, but
NOT at the general `resolved.widened` push a few lines below it, which
covers e.g. a `return`-side dynamic-key read). This is Minor and
soundness-unaffected — the identity SETS themselves are correct either
way, only the stated cause in the widening ledger can be wrong — and is
left as a documented follow-up: a real fix would require threading a
reason string through `resolveExprIdentities`'s return shape more broadly
than this round's scope covers.

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
- **Array literals**: flattened, no index sensitivity. **Not** because this
  IR lacks index-sensitive access paths — round 4's review found that
  claim false: `accessPathOf`/the parser's `exprOf`/`lhsPath` DO extract
  literal computed keys for both reads and writes, and paths like `arr.0`
  are buildable. The real reason: the parser transparently unwraps
  `SpreadElement` (`scanner/src/ir/parser-js.js`'s `exprOf`'s
  `SpreadElement` case), so `[...xs, user]` and `[xs, user]` are
  byte-identical in the IR — naive per-index attribution would actively
  MISATTRIBUTE a spread source's contents to a literal index, which is
  worse than staying uniformly flat. An array carrying two different
  fields at two different indices is not distinguishable in this slice;
  this is an accepted, documented limitation, not silently wrong (every
  element's identities are still recorded, just flattened into one bag
  rather than per-index). Fixing this properly would require the parser
  to distinguish spread elements from literal elements first — out of
  scope for this plan.
- **Object spread/rest — KNOWN, UNFIXED LIMITATION, not covered by the array
  reassurance above.** `{...user}` (object spread in a literal) and
  `const {...rest} = user` (object rest in a destructuring pattern) are
  **silently dropped entirely** by the parser today — `scanner/src/ir/parser-js.js`'s
  `ObjectExpression` handling filters out `SpreadElement` properties
  *before* building the `props` array, and its destructuring lowering does
  the analogous drop for a rest binding, so `{...user}` and `{}` are
  byte-identical in the emitted IR. This is **not** "flattened into one
  bag" the way array spread is (that reassurance, immediately above, does
  NOT extend to objects) — the identity vanishes completely, a false
  negative (`return {...user};` currently resolves to nothing, not to a
  coarse aggregate). Confirmed pre-existing since the parser's first
  commit, not introduced or missed by any round of this plan's own fix
  chain — every fix in this document (the residual principle, the
  production/selection/write-out invariant, the wildcard/fabricated-key
  closure) provably never reaches this code path, since the `SpreadElement`
  node is filtered out before any of those mechanisms would see it.
  Possible wider blast radius into `scanner/src/dataflow/`'s own taint
  engine (which shares this parser) is flagged but not confirmed. Fixing
  this is real, scoped, follow-up work for a later sub-project — not
  attempted here, and not silently glossed over either.
- **Member access** (property read): when the whole `object.prop...` chain
  is a pure ident/member chain, resolves via `accessPathOf` + `identitiesAt`
  — no new logic needed, this is what those functions exist for. When the
  base is NOT a pure chain (a ternary, a logical expression, an object
  literal, an assign-expr, a call — anything `accessPathOf` returns `null`
  for), round 4 added a fallback: resolve the base recursively and SELECT
  `prop` out of the base's `byPath` (plus its residual), so reading a field
  directly off one of these constructs gives the same answer as going
  through an intermediate variable first. See the "three hop types" note
  above (the "selection" hop) for the full story.
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
  the parser — never resolved to one) and **logical expressions**
  (`logical` kind, `||`/`&&`/`??`): both/all alternatives' identities are
  unioned PER SUB-PATH — the exact same per-path union `joinStates`
  already performs at the CFG branch-join level, not a coarse flat merge.
  (A previous revision of this bullet claimed this parity while the code
  underneath still flattened `union`/`logical` into one flat blob, entirely
  dropping `byPath` — see round 3's "The structure-preserving vs.
  structure-flattening invariant" note below for the fix and why the false
  claim is believed to be why the gap survived two rounds of review: it read
  as an already-accepted approximation rather than a bug.) `binary`
  (arithmetic/comparison operators) is deliberately NOT part of this
  group — see the invariant below for why.
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
