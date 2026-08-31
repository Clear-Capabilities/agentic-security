# Path Provenance Recording — Design Record

Scope: Sub-project C of Milestone 1, increment C1 (see
`docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md`).
This document decides **how provenance is recorded** as data flows through
the field-identity engine. It does **not** decide the storage structure
(`path-store.js`, C4), the reconstruction query (C5), or the FR-306 edge
grading (C6) — those consume what is decided here.

Binding on every later Sub-project C increment, the same way
`DESIGN_INTRAPROCEDURAL.md` is binding on `field-identity.js` / `engine.js`.
If an implementation increment finds a decision here to be wrong or
incomplete once real code is attempted, **fix this document with a dated
note explaining what changed and why** — do not silently diverge code from
doc. That is exactly what Sub-project A's own six-round history shows is
the expensive failure mode.

---

## 0. The requirements this must satisfy

Verbatim from `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` (repo root,
untracked per this repo's convention):

- **FR-303:** *"The engine must retain a compact predecessor/provenance DAG
  from which ordered paths can be reconstructed. It must not eagerly
  materialize every possible path during scanning because that creates path
  explosion."*
- **FR-305:** *"When several paths connect the same source and sink, the UI
  must show a path count and allow the user to inspect each path.
  Deduplication may collapse identical internal segments but cannot hide
  materially different transformations or controls."*
- **FR-306:** *"Implicit/control-dependent and unknown-field widened flows
  must be visually distinct and lower-confidence."*
- **§18.4**, the load-bearing constraint: *"Never translate 'path budget
  exhausted' into 'no path.'"*

And two hard local constraints, inherited:

- **`field-identity.js` is read-only.** Its `Map<accessPath,
  Set<dataElementId>>` shape and all seven exports stay byte-for-byte
  unmodified. Provenance may not become part of that Map's value type.
  Re-opening FR-301's correctness surface under a richer shape is a bad
  trade against six rounds of adversarial review.
- **Backward compatibility is the acceptance bar.** With no recorder
  supplied, every observable output of `resolveExprIdentities` /
  `analyzeFunctionFieldIdentity` / `summaries.js` / `driver.js` must be
  byte-identical to today's.

---

## 1. Decision 1 — provenance is an emitted RECORD STREAM, not analysis state

**Decided:** the engine emits *hop records* through an optional, write-only
callback supplied on the existing `ctx` object. It does not accumulate,
store, join, or read back any provenance structure of its own.

Three alternatives were considered and rejected:

- **(a) Provenance in the state value type** (`Map<path, Map<id,
  Set<ProvenanceEdge>>>`). Rejected: forbidden by the constraint above, and
  for good reason — every `identitiesAt` / `joinStates` / `removeIdentitiesAt`
  / `statesEqual` / `hashState` invariant would need re-deriving under a new
  shape, and `hashState` (the summary cache key, Sub-project B) would start
  discriminating contexts by *provenance* rather than by *facts*, silently
  exploding B6's per-function context cap.
- **(b) A second, parallel dataflow state** ("last writer per path"), joined
  at CFG merge points alongside `state`. Rejected: it would have to
  participate in the worklist's fixed point, which means real changes to
  `analyzeFunctionFieldIdentity`'s convergence logic, a second `statesEqual`,
  and a second termination argument. That is a rewrite of A's core in
  everything but name.
- **(c) Enriching `resolveExprIdentities`'s return shape** with an `origins`
  map, so write-out sites emit complete, self-contained edges. Rejected —
  though it is the closest call. It would force every switch case to build a
  nested origin structure, which is a provenance DAG re-implemented *inside*
  the resolver, one increment early and without the deduplication C4 exists
  to provide. It also cannot represent a hop that has a source but no
  destination (a bare `call` argument; a return) without inventing a second
  channel anyway.

**Why a callback rather than an array on `ctx`.** The consumer chooses
storage: an array for a test, a deduplicating set for C4, a budget-capped
sink for C5. It also mirrors `ctx.resolveCallSummary`, the precedent
Sub-project B's increment 2 already established for extending this engine
additively.

**The write-only invariant** (this is what makes "zero behavior change"
provable rather than merely hoped for):

> The engine must never read from the recorder, never branch on anything it
> returns, and never let a recorder's presence change `state`, `returnFacts`,
> `mutatedParams`, `widenings`, or `exitState`. The single permitted
> `ctx.recordHop`-conditional behavior is **extra computation whose result is
> discarded** (e.g. resolving a source expression purely to learn which
> identities a skipped write would have carried). `recordHop`'s return value
> is ignored.

A corollary worth stating because it is easy to get wrong: a recorder may be
**lossy** (drop records past a budget) without affecting analysis results at
all. That is what lets C5's path budget live entirely in the consumer.

**`recordHop` must not throw.** Deliberately un-guarded, matching
`resolveCallSummary`'s existing precedent — swallowing a consumer's exception
would hide a real bug in exchange for nothing. A throwing recorder aborts the
analysis; that is a consumer defect.

---

## 2. Decision 2 — the DAG's node granularity is `(scope, accessPath, dataElementId)`; hop records are HALF-EDGES

This is the decision the rest of the shape follows from, so it is stated
before the shape.

### 2.1 What a DAG node is

A reconstructed path that a human can read is a sequence of **state
locations**: `user.email` → `u.email` → `o.email` → *(returned)*. Every step
in that sequence is a place the engine actually recorded an identity. The
things that happen *between* two such locations — an object literal, a
template literal, a ternary, a resolved call — are **not additional nodes**.
They are properties of the edge.

**Decided:** the DAG's node is `(scope, accessPath, dataElementId)`.
Expression-internal constructs annotate edges; they never create nodes.

This is what makes the structure *compact* in FR-303's sense: `user.email`
read in forty places is one node, and the forty reads are forty edges out of
it. A node-per-expression design would be a materialized-path structure in
disguise.

### 2.2 Why records are half-edges, and how they join

A complete edge needs both endpoints. The engine never has both at once:

- `resolveExprIdentities` knows the **source** path (it reads `state`) but
  has no idea where the value will eventually land — it is deep inside an
  expression tree and its caller may be an `assign`, a `return`, a call
  argument, or nothing at all.
- `step()`'s `assign` knows the **destination** path but receives only
  `{flat, byPath, widened}` from the resolver — no source-path information
  whatsoever.

So a record is a half-edge, and its `kind` says which half:

| Hop type | Half | `fromPath` | `toPath` | Emitted by |
|---|---|---|---|---|
| `production` | inbound | the contributing state key, or `null` for a construct that reads no state | `null` | `resolveExprIdentities` cases |
| `selection` | inbound | the contributing state key, or `null` | `null` | `member`'s two resolution branches |
| `write-out` | outbound | `null` | the exact path passed to `addIdentity`, or `null` for a hop with no landing path | `step()` cases |

**The join rule (binding on C4):** in-half and out-half records join into an
edge when they share `(scope, nodeId, dataElementId)`.
**Superseded by §13.3 (increment C3): the key is now the four-part
`(scope, nodeId, dataElementId, context)`** — see §13.0/§13.3. Every use of
the three-part form in this document predates C3 and should be read with
`context` appended.
Either form is sound only because
of an invariant that must be re-checked, not assumed:

> **Every CFG node kind, in one `step()` invocation, has at most one *write
> destination expression* — one `target`, one `return value`, one argument
> list with no destination at all.** A future CFG node kind with two
> independent destinations (e.g. a lowered swap, or a multi-assignment node)
> breaks the join rule and needs an explicit correlation token before it can
> be instrumented.

That is an *enumeration principle*, deliberately not a count of today's node
kinds — see §10.

**A gap a design review found in this rule as originally written, closed
here:** the rule above says WHEN two records join; it did not say what a
`null`-`fromPath` in-half means when it joins alongside a non-null one at
the same key. This matters concretely: `const o = {email: u.email}` at one
CFG node produces, for `data:email`, TWO in-halves (a `selection` hop from
`u.email`, AND a `production/object` hop with `fromPath: null`) and ONE
out-half (`write-out` to `o.email`). Read literally, the join rule would
emit a spurious extra edge with no real source. The intended semantics,
already implicit in §2.1's worked examples but not stated as a rule: **a
`null`-`fromPath` in-half is an ANNOTATION on the edges formed by any
non-null in-half at the same key, not an edge-forming half-edge of its
own.** It forms a real edge only when NO non-null in-half exists at that
key — which is precisely the "value with no prior aliasing source" case
(a literal, or — the one case that matters for interprocedural stitching —
a resolved call's return value, which is C3's join point, not C1/C2's).

> **CORRECTED 2026-08-30 by increment C4 — see §14.4.** The parenthesis
> above names the resolved-call return value, and the rule then EXCLUDES
> it: in the real C3 stream the argument expression's own non-null in-half
> sits at the *same* join key as the `production/call-resolved` hop, so
> "only when NO non-null in-half exists" demotes the return stitch to an
> annotation and silently deletes it (measured — a store built that way
> leaves the callee's exit node with zero outgoing edges). **The
> discriminator is `peerScope`, not `fromPath`:** a null `fromPath` with a
> non-null `peerScope` is PEER-ADDRESSED — its source is the callee's own
> function-exit node — and is always edge-forming, except when it also
> carries a `lossReason` (§13.6's context-cap marker, whose callee has no
> recorded body, so an edge from it would fabricate an origin). The rule as
> written above remains correct, unchanged, for the genuinely source-less
> case: `peerScope === null`.

The three hop types are exactly `DESIGN_INTRAPROCEDURAL.md`'s already-hardened
production / selection / write-out taxonomy. That is not a coincidence to be
grateful for; it is the point. Every place structure can be *lost* is a place
provenance must be *emitted*, because they are the same set of places. A
provenance site that is not one of those three is a sign the taxonomy is
being extended without the review the taxonomy earned.

---

## 3. Decision 3 — the hop record shape

```js
/**
 * One hop record = one half-edge for ONE data element at ONE CFG node.
 * Every field is always present; nullable fields carry `null`, never
 * `undefined` and never an omitted key (a stable shape is what lets C4
 * hash a record for deduplication without a canonicalization step).
 *
 * Increment C3 adds three more always-present fields to this shape —
 * `context`, `peerScope`, `peerContext` — and moves the join key to
 * `(scope, nodeId, dataElementId, context)`. See §13.0 and §13.3; this
 * block is otherwise unchanged.
 *
 * This completeness guarantee is delivered by `analyzeFunctionFieldIdentity`'s
 * OWN worklist wrapper (§7.2's "progressive stamping"), not by
 * `resolveExprIdentities`/`step()` individually — those only ever emit the
 * SEMANTIC fields (kind/subKind/fromPath/toPath/dataElementId/
 * syntacticPath/widenReason/lossReason). `scope`/`nodeId`/`line` are
 * stamped onto every record by the wrapper as it flows through `ctx`,
 * BEFORE any site ever sees it. A whole-branch review confirmed this
 * empirically: calling `resolveExprIdentities` directly with a bare
 * `{recordHop}` (bypassing `analyzeFunctionFieldIdentity`) emits records
 * missing `scope`/`nodeId`/`line` entirely — not `null`, ABSENT. Unreachable
 * in shipped code today (the sole caller, `summaries.js`'s `resolveCallSummary`,
 * passes no `ctx` at all — see §7.4's ctx holes), but §7.4 tells C3 to wire a
 * recorder in at exactly that site. **Binding on C3:** any new emission path
 * that does not route through `analyzeFunctionFieldIdentity`'s own wrapper
 * must independently stamp all three progressive fields itself, or this
 * completeness guarantee — and the no-canonicalization contract C4 is being
 * designed around — silently breaks.
 */
{
  kind: 'production' | 'selection' | 'write-out',
  subKind: string,          // the specific case: 'ident' | 'member' | 'object' |
                            // 'array' | 'tpl' | 'binary' | 'logical' | 'union' |
                            // 'call' | 'call-resolved' | 'assign-expr' |
                            // 'assign' | 'assign-weak' | 'return' | 'call-arg'
  scope: string | null,     // the analyzed function's qid; null when unknown
  dataElementId: string,    // ALWAYS a non-null id — see Decision 4
  fromPath: string | null,  // a REAL state key — see Decision 5 and 6
  toPath: string | null,    // the exact path handed to addIdentity — see Decision 5
  syntacticPath: string | null, // the path the IR supplied / the analysis queried,
                            // when it differs from the endpoint actually used;
                            // null when they are the same
  nodeId: string,           // the CFG node id (the worklist key — see Decision 7)
  line: number | null,      // node.line, for display
  widenReason: string | null,  // null = explicit flow; otherwise the reason
                            // ('unresolved-call' | 'dynamic-property-key' | …)
  lossReason: string | null,   // null = the identity propagated; otherwise
                            // WHY this hop is a dead end ('unsupported-target' | …)
}
```

### Deviations from the plan's suggested starting shape, and why

- **`widened: boolean` → `widenReason: string | null`.** The boolean and a
  reason string side by side are redundant, and redundant fields drift — the
  exact failure this codebase punishes elsewhere. `widened` is recoverable as
  `widenReason !== null`. The upgrade also **closes, at the hop layer,
  `DESIGN_INTRAPROCEDURAL.md`'s explicitly-deferred Finding 3** (round 6):
  the `widenings` ledger mislabels a dynamic-property-key widening as
  `'unresolved-call'` because the reason is stamped at `assign`/`return`,
  far from where the cause is known. A hop is recorded *at the site that knows
  its own cause*, so it can label correctly for free. C6 should read
  `widenReason` from hops, not from `widenings`. (The `widenings` ledger's own
  mislabel is untouched and remains open; this does not fix it, it routes
  around it.)
- **`lossReason` added.** §18.4's most load-bearing constraint is that a
  truncated or unfollowable path must never look like the absence of a path.
  A dead end that is *recorded as a dead end* is the data-layer form of that
  guarantee; an unrecorded drop is invisible and indistinguishable from "no
  flow exists." Without this field, C5 physically cannot satisfy AC-10 from
  the data alone.
- **`scope` added.** C3 stitches across functions; a hop with no owner cannot
  be stitched. Adding it now costs one field; adding it in C3 means
  re-instrumenting everything C2 wrote.
- **`syntacticPath` added.** Decision 5 forces endpoints to be real state
  paths, which discards the IR's own framing (`store.*.name` becomes `store`).
  That framing is the only human-readable trace of *why* a hop widened; it
  belongs somewhere, and it must not be in the endpoint.
- **`nodeId` kept, but sourced differently.** See Decision 7 — hand-built test
  fixtures do not set `node.id`, so it must come from the worklist key.

---

## 4. Decision 4 — one record per `dataElementId`, never a Set-valued record

**Confirmed** (the plan's own proposal), with stronger reasoning than the
plan gave, plus one argument the plan did not have.

The plan's argument was that per-identity records let a later query
distinguish "two elements took the same route" from "one route carries N
elements." True, but weak on its own — a Set could be exploded at query time.

The two decisive arguments:

**(1) The half-edge join is only well-defined per identity.** With
`(scope, nodeId, dataElementId)` as the join key, a Set-valued half-edge
would have to be exploded before joining anyway, so the Set buys nothing and
costs a normalization step. Worse, a Set-valued in-half `{ids: {A, B}}`
paired with a Set-valued out-half `{ids: {A}}` makes B's fate **ambiguous**:
was B read and deliberately not written (folded into a residual, dropped at
an unsupported target), or is the out-half merely under-reporting? Per
identity, "B has an in-half and no out-half at this node" is an unambiguous,
readable fact — and it is exactly the fact `lossReason` exists to explain.

**(2) A worked example where a Set-valued record is outright wrong.** With
state `{ user: {data:blob}, user.email: {data:email} }` (an ancestor and a
descendant both carrying identity — a shape §3 of
`DESIGN_INTRAPROCEDURAL.md` explicitly says must be allowed to coexist),
`const u = user;` resolves `flat = {data:blob, data:email}` and
`byPath = {email: {data:email}}`, residual `{data:blob}`. The `assign` then
writes **two different paths**: `u` ← `data:blob` and `u.email` ←
`data:email`. Per identity, the records come out exactly right:

```
in:  production/ident  from 'user'        id data:blob   syntacticPath 'user'
in:  production/ident  from 'user.email'  id data:email  syntacticPath 'user'
out: write-out/assign  to   'u'           id data:blob
out: write-out/assign  to   'u.email'     id data:email
→ edges: user → u (data:blob), user.email → u.email (data:email)
```

A Set-valued record — one in-half `{from: 'user', ids: {blob, email}}`, one
out-half `{to: 'u', ids: {blob, email}}` — would report `user → u` carrying
both, losing `user.email → u.email` entirely. That is FR-301's own merge bug,
recreated one layer up in the provenance representation, in exactly the
ancestor/descendant shape Sub-project A's round 1 was fixed to handle.

**The cost, disclosed:** record volume is O(identities × hops), and the
worklist re-emits on every revisit (Decision 8). Mitigations: the recorder is
opt-in, so a scan that does not want provenance pays literally nothing; and
C4 deduplicates by record content, which collapses the revisit multiplicity
and all repeated reads of the same location.

---

## 5. Decision 5 — endpoints are paths the engine actually read from or wrote to; never a syntactic path

> **Invariant (the Sub-project C analogue of round 5's own):** every non-null
> `fromPath` / `toPath` on a hop record must be a path the engine actually
> **queried against** or **passed to `addIdentity`**. A wildcard-bearing
> syntactic path is never an endpoint. The wildcard is an *attribute* of the
> hop (`widenReason: 'dynamic-property-key'`, `syntacticPath` carrying the
> raw form), never part of its endpoint.

### This answers the plan's Step 5 question, and the answer is "no"

The plan asked whether `toPath` "naturally carries the `'*'`-suffixed path
already, same as the existing write-out logic." **It does not, and it must
not.** Reading the actual code settles it: `step()`'s wildcard branch does
not write to `node.target` at all —

```js
const containerPath = definitePrefixBeforeWildcard(node.target);   // 'store.*.name' → 'store'
for (const id of allIds) wState = addIdentity(wState, containerPath, id);
```

— it writes at the **definite prefix**. So the only correct `toPath` for
`store[k].name = user.ssn` is `'store'`, with `syntacticPath: 'store.*.name'`
and `widenReason: 'dynamic-property-key'`. The read side is symmetric:
`member`'s wildcard branch queries `identitiesAt(state, basePath)` where
`basePath` is the same definite prefix, so `fromPath` is `'store'`, not
`'store.*.name'`.

### Why getting this wrong would be expensive

If C2 recorded `toPath: 'store.*.name'`, the DAG would grow a node
`(store.*.name, id)` that **no read hop anywhere can ever match** — because
no read hop ever names that path either, for the same reason. Backward
reconstruction from a sink would hit that node and find zero predecessors,
and would report *no path* for every flow that passed through a dynamic
property key. That is §18.4's single most load-bearing constraint —
"never translate 'path budget exhausted' into 'no path'" — violated in a
new disguise: not budget exhaustion, but a fabricated endpoint, producing
the same silent, confident, wrong "there is no flow here."

This is the same bug class as round 4's `"[object Object]"` target and round
5's `'*'` object key: **a path component that is not a real, resolved
location, used as an identity key.** The rule above is the general form.

### Two sub-cases the rule already covers

- **`typeof node.target !== 'string'`** (assignment-expression destructuring,
  `({a} = obj)`): the engine deliberately skips rather than fabricating a key.
  Provenance must not fabricate one either. This is a **loss** site — see the
  checklist in §10.2 for how to record it.
- **`prop.key === '*'`** in an `object` literal: the engine folds it into the
  coarse residual and writes it at the container root. So the eventual
  `toPath` is the container, from the residual write — already correct under
  this rule, with `widenReason: 'dynamic-property-key'` carried on the
  production hop.

---

## 6. Decision 6 — `fromPath` is the CONTRIBUTING state key, not the queried path

This decision does not appear in the plan at all, and it is the one most
likely to have been discovered late and expensively.

`identitiesAt(state, path)` aggregates **bidirectionally** (round 1 of
Sub-project A): querying `u.email` sees an identity recorded at the ancestor
`u`, and querying `u` sees identities recorded at descendants `u.email` /
`u.ssn`. So the path a read hop *queried* is very often **not** a key in
`state` at all.

If `fromPath` were the queried path, the DAG would contain nodes with no
incoming edges that nonetheless are not sources — e.g. a node `(u.email, id)`
created by a read, when the identity actually lives at `(u, id)`. Backward
reconstruction would terminate there and report a path that begins in the
middle of the program. Every flow that passes through ancestor or descendant
coverage — which is most of them, because that is how object structure is
modeled here — would silently truncate.

**Decided:** at a state-backed read, emit **one record per (contributing
state key, dataElementId)** pair, where a contributing key is a key of
`state` that (a) contains that id and (b) stands in a prefix-coverage
relation to the queried path, in either direction — i.e. exactly the keys
`identitiesAt` unioned to produce the answer. The queried path goes in
`syntacticPath`.

Mechanically this needs one new pure helper in `engine.js` (not in
`field-identity.js` — no change there), roughly:

```js
// Which state keys actually contributed `id` to identitiesAt(state, path)?
// Mirrors identitiesAt's own bidirectional coverage test exactly; if that
// test ever changes, this must change with it or the DAG silently
// disconnects. Pure, allocation-only-when-recording.
function contributingKeys(state, path, id) { /* … */ }
```

**Cost, corrected — a design review caught this understated:** naively
calling `contributingKeys(state, path, id)` once per id (as the signature
above suggests) is O(|state| × |ids at path|), not O(|state|) — the state
scan repeats per id. The fix is a single pass: scan `state` once against
`path` (the same prefix-coverage test `identitiesAt` already does), and for
each covered key partition ITS ids by contributing key in one step, rather
than re-scanning per id. That is O(|state|) total for all ids at a path, the
cost this section originally claimed. C2's implementer should build the
single-pass version, not the naive per-id loop the signature above implies
— and it must be called **only when `ctx?.recordHop` is present**, squarely
within Decision 1's "extra discarded computation" allowance.

### Worked example — the plan's own Task 2 fixture, traced end to end

```js
function f(user) {
  const u = user;                                    // n1
  const o = { email: u.email, ssn: u.ssn };          // n2
  return o;                                          // n3
}
// entry state: user.email → data:email, user.ssn → data:ssn
```

| node | records emitted |
|---|---|
| n1 | `production/ident from 'user.email' id data:email syntacticPath 'user'`<br>`production/ident from 'user.ssn' id data:ssn syntacticPath 'user'`<br>`write-out/assign to 'u.email' id data:email`<br>`write-out/assign to 'u.ssn' id data:ssn` |
| n2 | `selection/member from 'u.email' id data:email`<br>`selection/member from 'u.ssn' id data:ssn`<br>`production/object from null id data:email`<br>`production/object from null id data:ssn`<br>`write-out/assign to 'o.email' id data:email`<br>`write-out/assign to 'o.ssn' id data:ssn` |
| n3 | `production/ident from 'o.email' id data:email syntacticPath 'o'`<br>`production/ident from 'o.ssn' id data:ssn syntacticPath 'o'`<br>`write-out/return to null id data:email`<br>`write-out/return to null id data:ssn` |

Joining by `(scope, nodeId, dataElementId)` yields exactly:

```
data:email :  user.email → u.email → o.email → ⟨return⟩   (via: object at n2)
data:ssn   :  user.ssn   → u.ssn   → o.ssn   → ⟨return⟩   (via: object at n2)
```

Two ordered paths, field-distinct end to end, from a structure containing
fourteen deduplicated records (the table above: 4 at n1 + 6 at n2 + 4 at n3)
and zero materialized paths. Note that the two elements never touch, at any
hop — which is FR-301's requirement carried into FR-303's structure.

**Correction found during Task 2's real implementation (this document
previously said "twelve" here, which was simply a miscount of the table
two paragraphs above — a genuine defect, not a deliberate simplification):**
fourteen is the count once EVERY hop type in the table is instrumented,
which requires `member`'s selection case (the two `selection/member` rows
at n2) — that is increment C2's job, not C1's. Task 2's own four-site POC
(§11 — `ident`, `object`, `assign`, `return`; deliberately NOT `member`)
was run against this exact fixture and produces exactly **twelve**
deduplicated records for it (4 at n1 + 4 at n2, since the two
`selection/member` rows never fire + 4 at n3) — confirmed by
`scanner/test/lineage/engine-provenance.test.js`, which pins this count.
So "twelve" was a real number, just attached to the wrong scope (it
describes Task 2's own POC output, not this section's full-coverage
worked example) — both twelve and fourteen are now stated explicitly,
against the scope each actually belongs to, so a future reader doesn't
have to re-derive which is which by hand.

Had `fromPath` been the queried path, n1 would have emitted
`from 'user'` for both ids and n3 `from 'o'` for both, and the reconstruction
would have been `user → u.email` / `user → u.ssn` — two paths that begin at a
container the engine never recorded anything at, merging the two elements'
first hop. The plan's own POC fixture is therefore already sufficient to
expose this; Task 2 should assert the *contributing-key* form explicitly.

---

## 7. Decision 7 — the injection mechanism, and the exact threading audit

### 7.1 The parameter

`ctx.recordHop(record)` — an optional callback on the **existing** `ctx`
object, mirroring `ctx.resolveCallSummary` exactly (Sub-project B, increment
2). No signature change to `resolveExprIdentities`,
`analyzeFunctionFieldIdentity`, `step()`, or any exported function.

### 7.2 Progressive stamping — call sites supply only semantic fields

`resolveExprIdentities` does **not** know `nodeId`, `line`, or `scope`. It is
called from `step(node, …)` and never receives the node. Rather than thread
three more arguments through fifteen call sites (and rely on nobody ever
forgetting one), the recorder is **enriched as it descends**:

- `analyzeFunctionFieldIdentity` stamps `scope` (from `fn.qid ?? null`) once,
  for the whole analysis.
- `step` stamps `nodeId` and `line` once per node visit.

```js
// in analyzeFunctionFieldIdentity, before the worklist:
const scope = fn.qid ?? null;
// in the worklist, per node (nid is the map KEY — see the warning below):
const stepCtx = ctx?.recordHop
  ? { ...ctx, recordHop: (h) => ctx.recordHop({ scope, nodeId: nid, line: node.line ?? null, ...h }) }
  : ctx;
```

Two properties this buys:

- **A call site cannot forget or mis-supply `nodeId`/`line`/`scope`.** That
  entire bug class is structurally impossible.
- **With no recorder, `ctx` is passed through byte-identically** — no
  allocation, no new object, nothing for a backward-compatibility test to
  catch. The `? :` above is not an optimization; it is the mechanism by
  which "zero behavior change when absent" is true by construction.

Spread order (`{scope, nodeId, line, ...h}`) puts the stamped fields first so
a record may deliberately override them — needed in C3, where a hop written
into a *callee's* entry state must carry the callee's `scope`, not the
caller's.

> **`nodeId` must come from the worklist's map key (`nid`), not `node.id`.**
> Verified by reading `test/lineage/engine-walker.test.js`: hand-built CFG
> fixtures set no `id` field on their nodes at all, only the map key. The
> real parser (`parser-js.js`) does set `node.id`, and sets it equal to the
> key — so `nid` is correct for both and `node.id` is correct for only one.
> A hop stamped `nodeId: undefined` would collapse every node in a
> hand-built-fixture function onto one join key, merging unrelated hops.

### 7.3 Threading audit — inside `engine.js`, nothing further is needed

Verified by enumerating every call site rather than counting them:

```
$ grep -n "resolveExprIdentities(" src/lineage/engine.js
```

**Every call site in `engine.js` already passes `ctx` unconditionally** —
`member`'s recursive base, `object`, `array`, `tpl`, `binary` (×2), `logical`
(×2), `union`, `call`'s args, `assign-expr`, and `step()`'s three call sites
(`assign`, `call`, `return`). The enumeration principle, not the count:
*every* `resolveExprIdentities` call in this file threads `ctx`, and any new
one must. So instrumenting one case is sufficient to prove the mechanism; no
new plumbing exists anywhere in `engine.js`.

### 7.4 Threading audit — `summaries.js` and `driver.js` have three real holes

The same audit run across the package finds **three places where `ctx` is
dropped or reconstructed**, all outside `engine.js`. None blocks C2; all
three block C3, and they are named here so C3 does not rediscover them the
expensive way:

| Site | Problem |
|---|---|
| `summaries.js:291`, in `entryStateFromCall` | `resolveExprIdentities(callerState, callArgs[i])` is called with **no `ctx` at all**. Argument→parameter binding is the single most important interprocedural hop, and it is currently unrecordable. `entryStateFromCall`'s signature must gain a way to receive one. |
| `summaries.js:357`, in `createCallSummaryResolver` | Constructs a **fresh** `{ resolveCallSummary }` ctx for the callee's `analyzeFunctionFieldIdentity`, discarding any `recordHop` the caller had. A resolved call chain therefore records the caller's hops and none of the callee's. |
| `driver.js:65` | Same fresh-`{ resolveCallSummary }` construction for every top-level function. The project-wide entry point cannot pass a recorder in at all today. |

There is also a **missing call-site identity** problem C3 must solve:
`resolveCallSummary(calleeExpr, callArgs, callerState)` has no access to the
calling CFG node, so a cross-function hop cannot be stamped with the call
site it crossed at. Recommended fix, consistent with §7.2: `step`'s derived
ctx already carries the stamped `recordHop`; extend the same derived ctx with
the plain values (`ctx.hopSite = {scope, nodeId, line}`) so `summaries.js` can
read them without any signature change. Decide this in C3, not now — but do
not design C3's hop shape as though the call site were available for free.

This entire subsection exists because of Sub-project A's round-4 lesson,
generalized: *the check must not stop at the file you are editing.* Round 4's
gap survived three reviews because everyone checked
`resolveExprIdentities`'s switch and nobody checked `step()`. The Sub-project
C version of that mistake is checking `engine.js` and not checking
`summaries.js` / `driver.js`.

---

## 8. Decision 8 — the worklist re-emits; deduplicate at the consumer

`analyzeFunctionFieldIdentity` is a fixed-point worklist: a node is
re-`step()`ed whenever an incoming state changes. So **every hop is emitted
once per node visit**, not once per program point.

**Decided:** the engine does *not* suppress duplicates. Doing so would
require a second per-node memo — i.e. Decision 1's rejected option (b) in
miniature. C4 deduplicates by record content.

**Why duplicates are harmless and no early-iteration hop is ever wrong:**
the state visible at a node is **monotone** across worklist iterations.
`inStates`/`outStates` are only ever updated through `joinStates`, which
unions; `step` is monotone in its input (each case only unions more into what
it produces, and `assign`'s kill removes a *fixed*, content-independent set of
paths). Therefore the identities resolvable at a node on iteration *k+1* are a
superset of those on iteration *k*, so the hops emitted on iteration *k* are a
**subset** of those emitted on the final iteration. Duplicates are exact
repeats; nothing recorded early is later invalidated. Content-deduplication
is therefore both safe and complete.

**Inherited imprecision, disclosed:** because `outStates.set(nid, joinStates(prevOut, out))`
joins a node's *own* successive outputs, a strong update inside a loop is
weakened across iterations — a pre-existing property of Sub-project A's
worklist, not something provenance introduces. Hop records inherit it exactly:
inside a loop, a re-assigned variable may retain in-halves from a prior
iteration's source. Recording it faithfully is correct; "fixing" it here would
mean disagreeing with the analysis the hops are supposed to explain.

---

## 9. Known imprecisions of this design, disclosed up front

None of these is a soundness hole — each over-approximates *paths*, never
under-reports *identities*. They are listed so a later increment measures
them rather than rediscovering them.

### 9.1 The half-edge cross-join can invent a path

Within one CFG node, all in-halves for an id join with all out-halves for
that id. When the **same** `dataElementId` is read from ≥2 distinct paths
**and** written to ≥2 distinct paths at the same node, the cross product
contains edges that never really happened:

```js
const x = { a: p.email, b: q.email };   // both p.email and q.email carry data:email
// in-halves : p.email, q.email     out-halves: x.a, x.b
// joined    : 4 edges — of which p.email→x.b and q.email→x.a are phantom
```

**Decided: detect and mark, do not prevent.** C4 can identify this exactly —
at a `(scope, nodeId, dataElementId)` group, `distinctInPaths ≥ 2 &&
distinctOutPaths ≥ 2` — and mark the resulting edges
`ambiguousCorrelation: true`. FR-306 already requires a lower-confidence
grade for less-certain hops; this feeds it directly, and FR-305's constraint
is about not *hiding* differences, which marking satisfies and silence would
not.

> **CORRECTED by increment C4 — see §14.7.** The group-level measure above
> (`distinctInPaths ≥ 2 && distinctOutPaths ≥ 2` on the WHOLE group) is too
> coarse: applied to a plain resolved call, it marks every edge in the
> group — including both edges of the correct call-boundary chain — because
> the annotation-only `call-resolved` in-half (`fromPath: null`) counts as
> a second "distinct" in-path even though it never forms its own edge
> (§2.2's correction). §14.7 replaces this with a per-*pairing* measure
> (ambiguous only when the SPECIFIC in-half/out-half pair being joined has
> a same-key sibling on both sides), verified against a real resolved-call
> fixture where the group-level form over-marks 3 of 5 edges and the
> per-pairing form marks exactly the 1 genuinely ambiguous one. The
> `slot`-field discussion below is unaffected by this correction.

**The known fix, if C4 measures this as a real problem:** add a `slot` field
— the sub-path *within the value under construction* that a hop contributes
to — and join on `(scope, nodeId, dataElementId, slot)`. It is deferred, not
overlooked, because it requires threading a slot prefix down through
`resolveExprIdentities`'s recursion for the **in-expression** case (the
resolver does not know its own position in its parent). The cost is lower
than that framing suggests for a real, non-exotic shape a design review
confirmed by execution: a plain alias of a multi-field object —
`const u = user;` where `state` already has `user.a: X, user.b: X` — trips
this exact condition (`distinctInPaths=2, distinctOutPaths=2` for the same
id) with **neither** half needing anything threaded through, since both
in-halves (`user.a`, `user.b`) and both out-halves (`u.a`, `u.b`) already
carry their own sub-path as their own `fromPath`/`toPath`. A `slot` for
THIS shape is a same-node string transform, not a signature change — only
the in-expression case (`{a: p.email, b: q.email}`, where the resolver
itself must know it's building the `a` vs `b` slot) needs the recursion
change. Do not adopt either half speculatively; measure first — but do not
assume both halves cost the same when deciding whether to.

**Frequency, corrected:** the paragraph above previously called this "a
narrow case that has not yet been shown to occur." A design review
reproduced it with the plain-alias shape by running the real walker — it is
not exotic, and any object carrying the same identity at two fields, then
aliased or passed through untouched, hits it. This does not change the
decision (detect-and-mark is still correct, and still sound — nothing is
silently wrong), but `ambiguousCorrelation: true` should be expected to
appear on a real, non-trivial share of ordinary aliasing edges, not treated
as a rare corner case when C4 is scoping how much weight to give it in
FR-306's confidence grading.

### 9.2 The DAG is flow-insensitive at reconstruction time

The forward analysis is flow-sensitive; the DAG is not. `a = user.email; a = other.email;`
— where both carry `data:email` — leaves two predecessors for `(a, data:email)`,
and reconstruction will report both, though only the second reaches a later
sink.

Note the narrowness: this needs the **same** id written to the **same** path
from **different** sources. When the ids differ, the killed identity simply
has no outgoing hop past the kill point and backward reconstruction never
visits it — the dead branch is naturally unreachable, at no cost.

**Lever available to C5, not mandated here:** every edge carries `nodeId` and
`line`, so a reconstruction can require hop ordering to be non-decreasing
along a path, or de-prioritize paths that are not. Whether that is worth its
false-negative risk on loops and back-edges is C5's call, made against real
measurements.

### 9.3 Cyclic DAGs are possible

`x = y; y = x;` produces a two-cycle for a shared id. Reconstruction (C5) must
be cycle-safe by construction — a visited set per path, plus the hop budget —
and a path truncated by cycle-breaking must be reported as truncated, per
§18.4. Stated here so C5 does not treat acyclicity as an inherited guarantee:
**the "DAG" in FR-303 names the intent, not a property this recording
mechanism enforces.**

### 9.4 The join key does not distinguish entry contexts — a real gap for C3, named now

> **CLOSED by increment C3 — see §13.3**, which adds the `context` field
> proposed at the end of this section and moves the join key to
> `(scope, nodeId, dataElementId, context)`. The worked example below was
> reproduced, and both phantoms shown excluded, in this design's own
> now-deleted PoC file at design time, and again in the permanent suite
> (`test/lineage/engine-provenance-interprocedural.test.js`) once shipped.
> The section is kept as written because it is the reasoning §13.3 rests on.

`(scope, nodeId, dataElementId)` is the join key throughout this document
(§2.2). It is sufficient for ONE analysis run of ONE function under ONE
entry state. It is NOT sufficient once `FieldIdentitySummaryCache` (Sub-
project B, B1/B6) computes up to 16 distinct entry contexts for the SAME
qid — which `driver.js` already triggers today, independent of anything
Sub-project C adds. Two contexts of the same function emit hops that share
`(scope, nodeId, dataElementId)` but describe DIFFERENT endpoints:

```js
function g(x) { const y = x; return y; }
// context A (entry: x.email → data:email): in-half from 'x.email', out-half to 'y.email'
// context B (entry: x        → data:email): in-half from 'x',       out-half to 'y'
// joined at n1 for data:email: 2 in-halves × 2 out-halves = 4 edges,
// 2 of which (x.email→y, x→y.email) never actually happened in either context
```

§8's monotonicity argument does not cover this — it is scoped to worklist
revisits WITHIN one analysis run, and neither context's hop set is a subset
of the other's. This is a different failure from §9.1's cross-join (that one
is real ambiguity within a single, real execution; this one mixes hops from
executions that never coexisted).

**Not this increment's or C2's problem to fix** — C1/C2 only ever run one
entry state at a time, so it cannot manifest yet. **Named here, now,
specifically so C3 (which is what actually turns on multi-context analysis
for provenance) does not rediscover it expensively**, matching this
document's own stated purpose. The fix is additive and cheap when C3 gets
there: add a `context` field (e.g. `hashState(entryState)`, reusing the
exact primitive `FieldIdentitySummaryCache` already keys on) to the record
and fold it into the join key — no change to the half-edge model, the node
granularity, or anything C1/C2 build.

### 9.5 The worklist's own iteration budget is an unrepresented truncation

`analyzeFunctionFieldIdentity`'s `ITER_BUDGET` (5000) is a defensive backstop
against a malformed/generated CFG — on a real, well-formed CFG the fixed
point is reached in finitely many steps and the budget is never hit (see
`engine.js`'s own comment on `ITER_BUDGET`). But if it ever IS hit, the
worklist `break`s and returns a silently partial fixed point — exactly the
"path budget exhausted" class §18.4 requires never be presented as "no
path." This design has no `lossReason` value for it today (`§3`'s value set
covers per-hop losses like `unsupported-target`/`dynamic-property-key`, not
a whole-analysis-run truncation). Defensive-only, not expected to fire on
real code — but §18.4 treats exactly this constraint as load-bearing, so it
should not be the one gap this document leaves unnamed. **For whichever
increment first surfaces analysis-level (not per-hop) truncation to a
consumer** (plausibly C5's reconstruction-result shape, per the scoping
doc's own §3): a function whose `analyzeFunctionFieldIdentity` run hit
`ITER_BUDGET` should mark its ENTIRE result set as budget-truncated, not
leave individual hops looking complete.

### 9.6 A callee's body is recorded once per ENTRY CONTEXT, not once per call site

**Added by increment C3, from a measurement, not a prediction** — see §13.4
for the run that produced it.

`FieldIdentitySummaryCache.compute(qid, entryState, analyzeFn)` memoizes:
`analyzeFn` — the thing that transitively emits the callee's own hops —
runs only on a cache MISS. So when two call sites bind the *same*
`(qid, entryState)`, the callee's internal hops are emitted **once**, for
whichever call site missed first. The later, cache-hitting call site emits
its own `call-arg-bind` and `call-resolved` hops (neither goes through the
cache) and nothing else.

**Accepted as a disclosed property, and it is not a loss** — *provided*
`peerContext` is recorded (§13.2). Both call sites' `call-arg-bind` hops
carry the same `peerContext`, which is exactly the `context` stamped on the
single recorded copy of the callee's body, so a consumer walking forward
from either call site reaches that body. The body is **shared, not
orphaned**; sharing one recorded body across N call sites that produce the
same callee behaviour *is* FR-303's compactness requirement, not a gap in
it. Proven by execution, not argued: the PoC asserts, for the two-call-site
fixture, that every bind hop's `peerContext` is a context whose body is
present in the record stream.

Two caveats, stated so a later increment does not rediscover them:

- **Without `peerContext` this WOULD be a silent loss**, and the naive
  wiring is precisely the one that omits it. That is what makes
  `peerContext` load-bearing rather than decorative, and it is why §13.4
  does not need the much larger "cache stores and replays a per-summary hop
  list" fix that was the alternative on the table.
- **The one genuinely orphaned case is a B6 cap degradation**, where the
  bound context's body was never computed at all. That is a real §18.4
  violation, it is separate from this section, and §13.6 handles it.

---

## 10. Full instrumentation checklist for increment C2

**Not to be implemented by this increment.** Increment C1's proof-of-concept
covers four sites only (§11). This table is C2's work order, written now while
the design is fresh, matching `DESIGN_INTRAPROCEDURAL.md`'s own precedent of
naming what is deferred rather than being silent about it.

**The enumeration principle, not a count:** *every* `case` in
`resolveExprIdentities`'s switch and *every* `case` in `step()`'s switch — plus
the `default` of each — must be visited and given a verdict, including a
verdict of "emits nothing, because …". A hand-counted "these N sites" claim is
precisely what let Sub-project A's rounds 3, 4 and 5 each ship an unexamined
site (see `DESIGN_INTRAPROCEDURAL.md`'s own note that "any future 'N sites'
phrasing in this document is a bug in the document"). If the switch grows a
case, this table is stale until it grows a row.

### 10.1 `resolveExprIdentities` — every case

| case | hop type(s) | `fromPath` | `toPath` | notes |
|---|---|---|---|---|
| `ident` | production | contributing state key per id (Decision 6) | `null` | `syntacticPath` = the resolved path. `byPath` construction reads the same keys — do not double-emit. |
| `member` (path branch, no wildcard) | selection | contributing state key per id | `null` | `syntacticPath` = the resolved dotted path. |
| `member` (path branch, wildcard) | selection | `definitePrefixBeforeWildcard(path)` — **never** the `'*'` path | `null` | `widenReason: 'dynamic-property-key'`, `syntacticPath` = the raw `'…*…'` path. Decision 5. |
| `member` (non-path base, `prop !== '*'`) | selection | `null` (base is an in-flight value, not a state key) | `null` | The base's own recursion already emitted the state-backed in-halves; this hop only annotates the selection. |
| `member` (non-path base, `prop === '*'`) | selection | `null` | `null` | `widenReason: 'dynamic-property-key'`. |
| `literal` | — | — | — | Emits nothing: no identity exists to have provenance. |
| `unknown` / `default` | — | — | — | Emits nothing. **Consider** a `lossReason: 'unmodelled-expression'` marker for the coverage ledger — but only when an identity is demonstrably being dropped, which for these cases it is not (nothing was resolved). Decide in C2 with evidence, do not add speculatively. |
| `object` (plain property) | production | `null` | `null` | Per id in the property's contribution. Edge annotation (`via: 'object'`). Structure is *preserved* here — no `lossReason`. |
| `object` (spread property) | production | `null` | `null` | `subKind: 'object'`, but distinguish spread in a note if C4 needs it — the byPath merge is structurally different (top-level siblings). |
| `object` (`prop.key === '*'`) | production | `null` | `null` | `widenReason: 'dynamic-property-key'`. Folds into the residual, so the eventual `toPath` is the container root — already correct under Decision 5. |
| `array` | production | `null` | `null` | Structure-flattening **by design** (spread ambiguity, ADR §4). **No `lossReason`** — identity propagates fully; only per-index distinction is lost, which is a precision fact, not an identity loss. Getting this wrong would flood the coverage ledger with false gaps. |
| `tpl` | production | `null` | `null` | Transformation-bearing: the identity is embedded in a new string. Prime FR-307 / Sub-project D raw material. No `widenReason` — ADR §4 is explicit that this is an *explicit* flow, not a widened one. |
| `binary` | production | `null` | `null` | Same as `tpl`. Deliberately separate from `logical`. |
| `logical` | production | `null` | `null` | Structure-preserving (short-circuit returns an operand verbatim). |
| `union` (ternary) | production | `null` | `null` | Structure-preserving. Both branches emit; the resulting multiple in-halves are *correct* — this is FR-305's genuine multiple-path case, not §9.1's phantom. |
| `call` (unresolved) | production | `null` | `null` | `widenReason: 'unresolved-call'`. |
| `call` (resolved via `ctx.resolveCallSummary`) | production | `null` | `null` | `subKind: 'call-resolved'`, `widenReason: null`. The cross-function stitching itself is **C3**, not C2 — C2 records only that a resolved call contributed. |
| `assign-expr` | production | `null` | `null` | Pure pass-through; forwards the source's `widened`, so forward its `widenReason` too. Note the known limitation: it does **not** write to state, so there is no write-out hop — an in-half with no out-half that is *not* a loss. |

**2026-08-30 implementation note (C2, Task 1):** the `assign-expr` row's
"forward its `widenReason` too" instruction assumed a real reason string was
available to forward. It isn't — `resolveExprIdentities`'s return shape is
`{flat, byPath, widened}`, a boolean, not a reason string (that's exactly
Decision 3's own already-disclosed gap: only a *hop*, not the general
return value, carries `widenReason`). Resolved by applying the SAME
documented-approximate `'unresolved-call'` convention `step()`'s
`assign`/`return` cases already use when forwarding a bare `widened` flag
(`r.widened && r.flat.size > 0 ? 'unresolved-call' : null`) — not a new
mechanism, just the existing one, applied consistently. This inherits
those cases' already-disclosed mislabeling risk (a widening actually
caused by a dynamic property key can read as `'unresolved-call'`); it does
not worsen it. A real fix still needs `resolveExprIdentities` to thread an
actual reason string through its return value, out of C2's scope.

### 10.2 `step()` — every CFG node kind

| case | hop type | `fromPath` | `toPath` | notes |
|---|---|---|---|---|
| `assign`, target not a string | write-out | `null` | `null` | **Loss site.** `lossReason: 'unsupported-target'`. Requires resolving `node.source` purely to learn the ids. **Not merely discarded computation, a design review flagged this understated:** resolving `node.source` recursively runs the FULL `resolveExprIdentities` tree for that expression, which — when `ctx?.recordHop` is present — genuinely EMITS real in-half (`production`/`selection`) hops for whatever `node.source` reads, exactly as it would for any other resolved expression. These are not spurious: they correctly join with THIS row's `lossReason` write-out to show "this data was read here, then lost, because the target couldn't be represented" — arguably necessary for §18.4's transparency requirement, not incidental. If no identity resolves from `node.source`, none of that fires and there is nothing to lose. **CORRECTION (a later final whole-branch review, increment C2): "permitted (Decision 1) but must be guarded on `ctx?.recordHop`" — this document's own earlier wording — is WRONG, and describes a real bug increment C2 shipped and then fixed.** `resolveExprIdentities` is not side-effect-free when `ctx.resolveCallSummary` is present: its `call` case can trigger `FieldIdentitySummaryCache.compute()` for a callee, which registers a context against that function's distinct-context cap (`summaries.js`). Gating the resolve itself (not just the hop emission) on `ctx?.recordHop` meant a recorder's mere PRESENCE could consume cap budget a no-recorder run never would, silently changing a LATER, unrelated call site's own resolution once the cap was hit — reproduced with real parsed source, in the unsound direction (attaching a recorder made the analysis LOSE an identity a no-recorder run kept). Decision 1's "extra, discarded computation" allowance covers computation that is genuinely inert to skip; this resolve never qualified, because it can mutate cache state a sibling call site later reads. **The resolve itself must always run unconditionally; only the HOP EMISSION may be gated on `ctx?.recordHop`** — exactly the pattern the sibling `assign` (normal) branch already used, which is why that branch never exhibited this bug. Regression-tested with a real `FieldIdentitySummaryCache` at a low cap in `test/lineage/engine-provenance.test.js`. |
| `assign`, wildcard target | write-out | `null` | `definitePrefixBeforeWildcard(node.target)` | `subKind: 'assign-weak'`, `widenReason: 'dynamic-property-key'`, `syntacticPath` = raw target. **Weak update** — no kill. One record per `(containerPath, id)`. |
| `assign`, normal — residual write | write-out | `null` | `node.target` | One record per id in the residual. |
| `assign`, normal — `byPath` writes | write-out | `null` | `` `${node.target}.${subPath}` `` | **One record per `addIdentity` call**, at the exact sub-path written. Recording `node.target` here instead is the most likely C2 mistake: it would claim `o` where the identity is really at `o.email`, mismatching the granularity every read hop uses and disconnecting the DAG. |
| `assign`, normal — the kill (`removeIdentitiesAt(stateIn, node.target)`) | — | — | — | **No row of its own, and that is the correct answer, not an oversight** (§10's own rule requires every case get a verdict, including "emits nothing, because…" — this is that verdict, made explicit per a design review's request). §9.2 already covers this from the reconstruction side: a killed identity simply has no outgoing hop past the kill point, so backward reconstruction never visits the dead branch — at no representation cost. Nothing to emit here beyond what the surrounding residual/byPath writes above already record. |
| `call` (bare call statement) | write-out | `null` | `null` | `subKind: 'call-arg'`. The value leaves the analysis via an argument — not a loss, an escape. This is the natural sink-attachment point for Sub-project D. |
| `return` | write-out | `null` | `null` | `subKind: 'return'`. Deliberately **not** a pseudo-path like `'@return'` — mixing a fabricated token into the endpoint namespace is the bug class of Decision 5. C3/C4 identify a function exit by `kind === 'write-out' && subKind === 'return' && toPath === null`, scoped by `scope`. |
| `throw` | — | — | — | Currently a no-op in `step()`. Emits nothing. Revisit only if `throw` ever becomes a real transfer function. |
| `entry` / `exit` / `noop` / `loop-header` / `if` / `unknown` / `default` | — | — | — | No transfer, nothing to record. `if` is where **implicit/control-dependent** flow would eventually be recorded for FR-306's first half — the engine models no implicit flow today, so there is nothing to emit; do not invent one in C2. |

### 10.3 Cross-file sites C3 must add (not C2)

`summaries.js`'s `entryStateFromCall` (argument→parameter write-outs, in the
**callee's** scope), `applyAtCallSite` (callee mutation→caller write-outs), and
`summaryFromAnalysisResult`'s return-fact union (the callee-exit→caller-value
hop). Plus the three ctx holes and the missing call-site identity in §7.4. C3
must also mark hops recorded during a B5 bottom-stub round and hops from a
B6 context-capped, degraded summary — §3 of the scoping doc names both, and
neither is representable in today's shape without a new `subKind` or
`lossReason` value. That is C3's call to make, and it is additive.

> **2026-08-30 correction (increment C3, per this document's own
> fix-rather-than-diverge policy).** Three of this paragraph's instructions
> were wrong once real code was attempted, and §13 supersedes them:
>
> - *"argument→parameter write-outs, in the **callee's** scope"* — **no.**
>   The binding out-half must be stamped with the **caller's**
>   `scope`/`nodeId`/`context`, because that is the only way it joins with
>   the in-halves the argument expression's own resolution emits (which run
>   under the caller's `stepCtx`). The callee's identity is carried on the
>   new `peerScope`/`peerContext` fields instead. See §13.2.
> - *"C3 must also mark hops recorded during a B5 bottom-stub round"* —
>   there is **nothing to mark**: a bottom stub's `returnFlat` is empty, so
>   `case 'call'` emits no `call-resolved` hop at all on that round. See
>   §13.6, which measured this.
> - *"`applyAtCallSite` (callee mutation→caller write-outs)"* — **deferred,
>   not done.** `applyAtCallSite` is exported and unit-tested but is wired
>   into nothing: `engine.js` never calls it (a fact `test/lineage/driver
>   .test.js` already records). Instrumenting a mechanism that never runs
>   would ship untested-by-construction hop code. See §13.7's exclusions.

**Also C3's, and load-bearing, not optional:** §9.4's `context` field. C3 is
what actually exercises multiple entry contexts for the same qid through
this recording mechanism — closing §9.4 is a precondition for C3's own hops
being correct, not a nice-to-have alongside them.

---

## 11. What increment C1's proof-of-concept (Task 2) covers

Four sites only: `resolveExprIdentities`'s `ident` and `object`, and
`step()`'s `assign` (non-wildcard branch) and `return`. Enough to prove one
in-half, one annotation-only hop, one out-half, and one exit marker join into
a real, ordered path against real parsed JS/TS — and nothing more. Everything
in §10 beyond those four is C2's.

Task 2 should assert, specifically:

1. **Opt-out is genuinely zero-cost.** An existing scenario, run with no
   `recordHop`, produces byte-identical output.
2. **Contributing-key semantics** (Decision 6), not queried-path semantics —
   the §6 worked example distinguishes them and is the natural fixture.
3. **Per-identity records** (Decision 4) — two ids through one construct give
   two records, never one carrying a Set.
4. **`nodeId` comes from the worklist key** (Decision 7) — assert distinct
   `nodeId`s on a hand-built fixture whose nodes set no `id` field.

---

## 12. What this document deliberately does NOT decide

The storage structure and its stable ID (`path-store.js`, `ids.js`'s `pathId`
— C4); the backward-walk query, the alternate-path cap, the prioritization
rule, and the truncation-is-never-silent result shape (C5); how `widenReason`
maps onto FR-306's evidence grades (C6); any `DataFlowGraph v1` output
(Sub-project E); source/sink registries and transformation-kind recognition
(Sub-project D); collapsing repeated library/framework nodes into typed
summary hops (§18.4 — home undecided, plausibly D or C4).

**Updated 2026-08-30 by increment C3.** Nothing needed removing from this
list — the questions §13 closes were open in §7.4 / §9.4 / §10.3, never in
this section's own prose. For the record, §13 now decides: the `context` field and the join-key extension (§9.4 →
§13.3); the `resolveCallSummary` / `entryStateFromCall` signature changes
and the three §7.4 ctx holes (§13.1); the argument→parameter binding hop's
shape (§13.2); whether call-site identity needs its own `hopSite` field
(§13.5 — it does not); and how a B5/B6-degraded resolution is represented
(§13.6). Added to this list by §13, i.e. deliberately punted further:

- **How C4 materializes a cross-scope half-edge.** §13.2 records the peer
  endpoint's `(scope, context)`; it does not decide whether C4 renders the
  caller→callee transition as one edge, two, or a typed "call" segment.
- **Instrumenting `applyAtCallSite`** — deferred until it is actually wired
  into `engine.js` (see §10.3's correction and §13.7).
- **Interprocedural provenance for the hand-rolled-parser languages.**
  `createCallGraphLookup` resolves nothing for Python/Ruby/PHP/Go/Java/C#/
  Kotlin IR (their `callee` is a flat dotted string, deliberately not
  resolved — see `summaries.js`'s `_resolvableCalleeName`), and no
  member-expression callee resolves anywhere without CHA. Every such call
  takes the unresolved fallback, so it gets `production/call` and no
  cross-function hops at all. C3 does not change that boundary; it inherits
  it from B3, and it is a coverage fact a consumer must not read as "no
  flow crosses this call."

Two levers are named but **not** adopted here, with their trigger conditions,
so a later increment adopts them on evidence rather than on taste: the `slot`
correlation field (§9.1) and hop-order filtering during reconstruction (§9.2).

**Updated 2026-08-30 by increment C4.** The first item on this list — "the
storage structure and its stable ID (`path-store.js`, `ids.js`'s `pathId` —
C4)" — is now **decided in §14**, including the two things this section
could not have anticipated: cross-function node addressing (§14.3) and the
correction §2.2's annotation rule needed before the resolved-call return
value could be stitched at all (§14.4). §14 also settles the "one edge, two,
or a typed call segment" question this section punted (two cross-scope
edges — §14.3/§14.4), declines the library/framework-collapse item as
Sub-project D's rather than C4's (§14.9), and supplies part of the evidence
§9.1's `slot` lever was waiting on (§14.7). Everything else on this list is
still open, and `pathId` itself is now deliberately left unclaimed for C5
(§14.5).

**Updated 2026-08-30 by increment C6.** This list's third item — "how
`widenReason` maps onto FR-306's evidence grades (C6)" — is now **decided
in §16**, and the answer is wider than the item's own wording: `widenReason`
is one of *four* grading inputs (`ambiguousCorrelation`, `lossReason`,
`widenReason`, and — the one §14.9's own correction warned about, measured
larger than that warning states — reasons carried in `annotations[]`
rather than on the edge's top-level arrays, §16.5). §16 also declines to
reuse `protection.js`'s `EVIDENCE_GRADES` for it, with the reason stated
(§16.2), and keeps the `implicit` half of FR-306 as a **reserved,
unreachable** tier rather than inventing an implicit-flow analysis §10.2
explicitly forbids (§16.3). Everything else on this list — the backward-walk
question aside, which §15 closed — is still open.

---

## 13. Interprocedural hop recording (Sub-project C, increment 3)

**Implemented.** Design landed as `a2d42695` (fix round `fa27354e`, correction
`a8846463`); shipped by Task 2 (`5ee9143d`) and Task 3 (`119cff02`), whole-branch
reviewed clean at `ac6ed4c2`. The section below is kept in its original,
design-time voice (future tense, "the follow-up task must…") as the historical
record of what was decided and why — read `summaries.js`/`engine.js`/`driver.js`
themselves, or `scanner/src/lineage/CLAUDE.md`'s own module-table rows, for the
current, as-shipped description. The design-time PoC file this section
originally shipped alongside it (`engine-provenance-interprocedural-poc.test.js`)
no longer exists — Task 3 absorbed everything it proved into the permanent
suite (`engine-provenance-interprocedural.test.js`, `engine-provenance.test.js`,
`driver.test.js`) and deleted it, per item 15 below.

Added 2026-08-30. Everything in this section is **decided**, not proposed,
and every behavioural claim in it was produced by running code in
`scanner/test/lineage/engine-provenance-interprocedural-poc.test.js` — a
throwaway-named PoC committed alongside this section, which the follow-up
implementation task should re-point at the shipped functions and then fold
into `engine-provenance.test.js`.

> **Fix round 1 (2026-08-30), from this increment's own task review.** One
> BLOCKING defect and three disclosure gaps were found in §13's first
> draft and are corrected in place, each marked where it applies: §13.2a
> now forwards a RECORDER-ONLY ctx at the hole-2 site (the original
> full-ctx forwarding changed analysis results with no recorder attached,
> in the unsound direction under a tight cap); §13.2 discloses the
> multi-argument cross-join; §13.6 is now prototyped rather than only
> designed, and pins how C4 must read its loss hop under §2.2's annotation
> rule. Recorded here rather than silently rewritten, per this document's
> own policy.

**What C3 does NOT touch:** `field-identity.js` (unchanged, byte-for-byte,
as in every prior increment), and the isolation rule (`src/lineage/` may
import pure utilities from `src/dataflow/`, never `dataflow/engine.js` or
`dataflow/summaries.js`). Every change below is additive and inert when
`ctx.recordHop` is absent, matching Decision 1.

### 13.0 The record shape gains exactly three fields

Extending §3's shape. Same contract as every existing field: **always
present, `null` when inapplicable, never `undefined`, never an omitted
key**, so C4 can still hash a record without a canonicalization step.

```js
  context:     string | null,  // hashState(entryState) of the analysis run
                               // this hop was emitted in. null only when a
                               // hop is emitted outside analyzeFunctionFieldIdentity.
  peerScope:   string | null,  // the OTHER function's qid, on a cross-function hop
  peerContext: string | null,  // that function's entry-context hash
```

`peerScope`/`peerContext` name the function on the far side of a
cross-function hop. **The direction is read off the existing `kind` field,
not off a fourth new field** — §2.2 already defines `kind` as "which half
this is", so a `write-out` hop's peer is its *destination* and a
`production` hop's peer is its *source*. That is why this is two fields and
not four (`fromScope`/`fromContext`/`toScope`/`toContext`): the direction is
already in the record.

Only two hop shapes ever set them: `write-out/call-arg-bind` (§13.2) and
`production/call-resolved` (§13.2's return half). Every other hop carries
`null` for both, stamped by the wrapper in §13.3.

**Additivity, verified rather than assumed.** No test in
`engine-provenance.test.js` compares a hop object by `deepEqual` or asserts
a closed set of keys. Its two shape guards (lines ~595 and ~1383) are
`hasOwnProperty` + `!== undefined` over a REQUIRED list, and its
count assertions (`hops.length === 14`, and the per-shape counts) run on
`dedupeHops`, whose key is `JSON.stringify(h, Object.keys(h).sort())`.
`context` is constant within a single analysis run, so it cannot split a
dedupe group. The PoC re-runs the §6 fixture with all three fields stamped
on and still gets exactly 14 deduplicated records. **No existing assertion
needs updating.**

### 13.1 `resolveCallSummary` gains a 4th parameter; `case 'call'` is its one call site

**Decided:**

```js
resolveCallSummary(calleeExpr, callArgs, callerState, ctx)   // ctx: NEW, 4th, optional
```

and `engine.js`'s `case 'call'` (today engine.js:505) becomes

```js
const summary = ctx.resolveCallSummary(expr.callee, expr.args ?? [], state, ctx);
```

That is the whole of hole 1. `ctx` there is already the *stamped* `stepCtx`
(§7.2), threaded down unchanged through every recursive
`resolveExprIdentities` call (§7.3), so passing it hands `summaries.js`
both the caller's recorder **and** the caller's `scope`/`nodeId`/`line`/
`context` stamping in one object. Fourth position keeps every existing
3-parameter resolver stub — including the hand-built ones in
`engine-provenance.test.js` and `engine-integration.test.js` — working
untouched.

**Why an explicit parameter and not `this`.** Today `case 'call'` invokes
the resolver as a *method* (`ctx.resolveCallSummary(...)`), so `this` is
already the stamped `stepCtx`. The PoC exploits exactly that to prove
reachability without modifying `engine.js`, and pins it with an assertion.
It is **not** the shipped fix: `createCallSummaryResolver` passes the
resolver down as `{ resolveCallSummary }` and `driver.js` builds a fresh
ctx object per function, so any caller that destructures
(`const { resolveCallSummary } = ctx`) silently gets `this === undefined`
and the recorder vanishes with no error. A load-bearing channel must not
depend on call syntax.

**Measured, before the change:** the resolver receives `arguments.length
=== 3` and `arguments[3] === undefined`.

### 13.2 The argument→parameter binding hop

Two changes, one at each end of a resolved call.

**(a) `entryStateFromCall` gains `ctx` as an optional 4th parameter — and
forwards a RECORDER-ONLY derivation of it, never the ctx itself:**

```js
entryStateFromCall(paramNames, callArgs, callerState, ctx)   // ctx: NEW, 4th, optional
  // inside, once, before the loop:
  const argCtx = ctx?.recordHop ? { recordHop: ctx.recordHop } : undefined;
  // ... then, per argument:
  const resolved = resolveExprIdentities(callerState, callArgs[i], argCtx);
```

Return shape unchanged (`summaries.test.js`'s existing calls keep working).
It has exactly **one** call site, `summaries.js:338` inside
`createCallSummaryResolver`; `driver.js` does not call it at all.

That forwarding is what makes the argument's **in-halves** exist: ordinary
`production`/`selection` hops with correct contributing-key `fromPath`s
(Decision 6), stamped with the caller's `scope`/`nodeId`/`context` because
`ctx.recordHop` is the caller's already-stamped recorder (§7.2).

> **Why `resolveCallSummary` MUST be stripped here (2026-08-30, fix round 1
> — this section's first draft forwarded the full `ctx` and was wrong).**
> `resolveExprIdentities` branches on `ctx?.resolveCallSummary`. Handing it
> a live one at *this* site makes an argument that is itself a resolvable
> call — `sink(scrub(user))` — start resolving interprocedurally, where the
> shipped engine takes the unresolved-call fallback. That changes the
> ANALYSIS RESULT with **no recorder attached anywhere**, breaking this
> sub-project's flat "byte-identical without a recorder" bar. Reproduced
> two ways, both recorder-free, both in the PoC:
>
> - `function scrub(u){return {safe:1}} function sink(p){return p}
>   function caller(user){const out = sink(scrub(user)); return out;}`
>   seeded `user.email → data:email`: shipped keeps `data:email` in `out`;
>   full-ctx forwarding **drops** it.
> - Two call sites sharing a cap-1 cache: the extra nested resolve consumes
>   the callee's only context slot, so a later, unrelated call degrades to
>   an empty summary — an identity the shipped engine KEEPS is **lost**.
>   That is the unsound direction, and it is the same class of bug C2
>   already shipped once and fixed (§10.2's `assign`/unsupported-target
>   correction: a recorder's mere presence must never consume cap budget).
>
> The recorder-only derivation adds hop RECORDING without adding
> RESOLUTION. With a recorder attached, the argument's in-half is then
> recorded **honestly against the path the analysis actually took** —
> `production/call` with `widenReason: 'unresolved-call'`, not a
> `call-resolved` that never happened — which §8 requires anyway ("fixing"
> it here would mean disagreeing with the analysis the hops exist to
> explain).
>
> **Note for whoever writes the guard:** §13.7 item 16's own
> with-recorder/without-recorder comparison is structurally BLIND to this,
> because the divergence moves both arms identically. The guard that
> catches it must compare against a **hardcoded pre-C3 golden literal**
> (§13.7 item 15b), never "the shipped resolver" by name — once this task's
> own wiring lands, the shipped resolver IS that wiring, so a live
> comparison degenerates into `assert.deepEqual(result, result)`. The PoC's
> two regression tests (three arms: shipped / fixed / the hazard, the last
> pinned so the test cannot go vacuous) prove this NOW, while "shipped"
> still means something distinct — the golden values they hardcode are
> what item 15b's follow-up test must carry forward.

**(b) The binding out-half is emitted in `createCallSummaryResolver`,
not in `entryStateFromCall`:**

```js
{
  kind: 'write-out', subKind: 'call-arg-bind',
  fromPath: null,
  toPath: <paramName> | `${paramName}.${subPath}`,
  dataElementId: <id>,
  syntacticPath: null, widenReason: null, lossReason: null,
  peerScope: <callee qid>, peerContext: hashState(<callee entryState>),
}
```

emitted once per `(path, id)` entry of the freshly built `entryState`, and
guarded on `ctx?.recordHop`.

Four decisions, each with its reason:

- **`kind: 'write-out'`, not `'production'`.** §2.2's taxonomy is
  directional: `production`/`selection` are *inbound* halves carrying a
  `fromPath`; `write-out` is the *outbound* half carrying a `toPath`. The
  binding has a real destination path and joins with the argument
  expression's inbound halves at the caller's node — it is structurally the
  same event as `assign`, which is exactly how `summaries.js` already
  describes `entryStateFromCall` in its own header. `production/call-resolved`
  is `kind: 'production'` for the opposite reason: it is the call's *output*
  side, an inbound half at the caller.
- **`fromPath: null`**, not `contributingKeys(...)` against the argument's
  `accessPathOf`. Every write-out in §10.2 carries `fromPath: null` and
  relies on the resolver's own in-halves for the source; because (a)
  already forwards `ctx`, those in-halves are emitted with correct
  contributing keys for free. Computing them a second time here would
  emit a duplicate, differently-shaped source for the same edge. The PoC
  asserts the argument's `production/ident from 'a.email'` in-half and the
  bind out-half share `(scope, nodeId, dataElementId, context)` — i.e. the
  edge joins under §2.2's existing rule with no special case.
- **`toPath` is the exact path written**, `u` or `u.email`, never the
  coarse `u` when a sub-path was written — the same granularity rule §10.2
  flags as "the most likely C2 mistake".
- **`peerScope`/`peerContext` are mandatory here, not decorative.**
  `toPath: 'u'` is a path in the *callee's* namespace, recorded on a hop
  stamped with the *caller's* scope. Without `peerScope`, C4 would create
  the DAG node `(callerScope, 'u', id)` — colliding with any caller-local
  variable named `u`. That is Decision 5's bug class (an endpoint that is
  not the location it names) in a new disguise. `peerContext` is what makes
  the binding land in the *right* context of the callee, i.e. §9.4's own
  failure one level up, and it is also what makes §9.6 a sharing property
  rather than a loss.

**Arguments that are not path-shaped.** A literal argument resolves to no
identity, so no entry appears in `entryState` and **no hop is emitted at
all** — the same verdict §10.1 gives `literal`. An argument that is itself
an unresolved call *does* carry ids: it emits a bind hop with
`fromPath: null` and `widenReason: null`, because the widening is already
carried on its own `production/call` in-half (`widenReason: 'unresolved-call'`)
which joins with this out-half at the same key. Duplicating it would
double-grade the edge. Both cases are pinned in the PoC.

**Disclosed consequence of `fromPath: null` at a MULTI-ARGUMENT call site
(2026-08-30, fix round 1).** When two arguments at the same call site carry
the **same** `dataElementId`, the 4-part join key does **not** separate them
— both in-halves and both bind out-halves share
`(scope, nodeId, dataElementId, context)`, so the cross product names the
wrong parameter half the time:

```js
function two(p, q) { … }
two(m, n);   // m.email and n.email both carry data:email
// in-halves : m.email, n.email     out-halves: p.email, q.email
// joined    : 4 edges — m.email→q.email and n.email→p.email are phantom
```

This is **§9.1's already-disclosed cross-join, not a new bug class** — the
same shape at a call boundary instead of inside an object literal — and it
is handled the same way: C4 detects it exactly
(`distinctInPaths ≥ 2 && distinctOutPaths ≥ 2` at a group) and marks
`ambiguousCorrelation: true`. Reproduced in the PoC, so it is a measured
property rather than a hypothetical. Two notes for whoever revisits it:

- The bind hop is the **cheapest possible instance of §9.1's own `slot`
  lever**. §9.1 defers `slot` because the in-expression case needs a slot
  prefix threaded down through `resolveExprIdentities`'s recursion — but
  here the **parameter index is known for free** at the emission site
  (`fn.params[i]`), on both halves, with nothing to thread. If §9.1's
  evidence threshold for adopting `slot` is ever met, this case closes for
  the price of one field.
- Do **not** try to close it by putting the argument's path in `fromPath`
  instead: that reintroduces the double-emission this section rejects, and
  it still would not correlate the halves — it would only make the phantom
  edges harder to detect.

**(c) The return direction.** `case 'call'`'s existing
`production/call-resolved` hop (engine.js:512-520) gains
`peerScope`/`peerContext`, so C4 can connect it to the callee's own
`write-out/return` hops (`kind === 'write-out' && subKind === 'return' &&
toPath === null`, scoped by `scope` **and now `context`**). The information
comes from `createCallSummaryResolver` returning a **fresh wrapper**:

```js
return summary ? { ...summary, resolvedQid: qid, resolvedContext: calleeContext } : summary;
```

A fresh object every call — the cached summary is never mutated, so
`fieldSummaryEq` and the B5 refinement loop are untouched. `engine.js`
reads only `returnFlat`/`returnByPath`, so a resolver that does *not*
supply these (every existing hand-built test stub) must yield
`peerScope: null`, not `undefined` — read them as `summary.resolvedQid ?? null`.
The PoC proves both halves: the identity is available at the site, and the
augmented return leaves the analysis result identical to the shipped
resolver's.

### 13.3 The `context` field and the join-key extension

**Decided:** `context = hashState(entryState)` — the exact primitive
`FieldIdentitySummaryCache` already keys on (`summaries.js`'s `_key`), so
two hops share a `context` iff the cache would consider them the same
context. Reusing it rather than inventing a second notion is what keeps
"which body does this call site's `peerContext` point at" answerable by
string equality.

**Stamped in exactly one place:** `analyzeFunctionFieldIdentity`'s existing
per-node `stepCtx` wrapper (engine.js:864-866), computed once per analysis
alongside `scope`:

```js
const scope = fn.qid ?? null;
const context = ctx?.recordHop ? hashState(entryState) : null;   // only when recording
...
const stepCtx = ctx?.recordHop
  ? { ...ctx, recordHop: (h) => ctx.recordHop({
        scope, nodeId: nid, line: node.line ?? null,
        context, peerScope: null, peerContext: null,
        ...h,
      }) }
  : ctx;
```

`hashState` is added to `engine.js`'s existing `./field-identity.js` import
— no new dependency, no isolation-rule concern. Cost is one O(|state|) hash
per analysis, and only when a recorder is attached.

Two properties this buys, both already relied on by §7.2 and now
load-bearing for C3:

- **Zero change at the 15 existing `recordHop` call sites.** The three new
  fields are stamped by the wrapper, before `...h`, so a site that supplies
  none gets the correct nulls and a site that supplies `peerScope`/
  `peerContext` overrides them — §7.2's spread-order rule, used for the
  purpose it was written for.
- **A nested analysis's stamps win.** When a callee's hops flow out through
  the caller's already-stamped `recordHop` (§13.4's wiring), the callee's
  own wrapper has already put `scope`/`nodeId`/`line`/`context` into `h`,
  so the caller's outer stamp cannot overwrite them. Proven in the PoC: a
  hop recorded two resolved hops deep carries `inner`'s qid and `inner`'s
  own context, not `outer`'s.

**The join key becomes `(scope, nodeId, dataElementId, context)`**,
superseding §2.2's three-part key everywhere in this document. §9.4's
worked example, reconstructed by running the real cache over
`function g(x) { const y = x; return y; }` under two contexts:

| join key | joinable pairs | phantoms |
|---|---|---|
| `(scope, nodeId, dataElementId)` | `x→y`, `x→y.email`, `x.email→y`, `x.email→y.email` | 2 |
| `(scope, nodeId, dataElementId, context)` | `x→y`, `x.email→y.email` | 0 |

Exactly the failure §9.4 predicted, and exactly the fix it proposed.

**Existing tests broken by this: none** — see §13.0 for the evidence.

### 13.4 The cache-hit finding, and why it does NOT need the big fix

The question was whether `FieldIdentitySummaryCache.compute`'s memoization
silently suppresses a callee's own internal hops on a cache HIT, and
whether that forces the cache to store and replay a per-summary hop list.

**Measured** (two call sites to the same callee, deliberately seeded so
both produce the identical entry state and `hashState` collides):

- The callee's internal hops appear for **one** entry context, not two —
  the second call site is a cache hit and `analyzeFn` never runs again.
  Transitively true for its own callee too (`inner`, two hops deep).
- Both call sites *do* emit their own `call-arg-bind` and
  `production/call-resolved` hops — those are emitted outside `compute`.
- Control run, two *distinct* entry contexts: two distinct sets of
  callee-internal hops, at both depths. So the suppression is genuinely the
  cache key doing its job, not a wiring bug.

**Decided: (a), accept and disclose — recorded as §9.6.** The big fix (the
cache storing a hop list per summary and replaying it on every hit) is
**rejected**, for a reason the measurement makes concrete rather than for
cost: because both call sites' bind hops carry the same `peerContext`, and
that `peerContext` equals the `context` stamped on the one recorded body,
**nothing is orphaned** — a consumer walking forward from either call site
reaches the same, correctly-contexted body. Replaying would emit N
byte-identical copies of a body that C4 deduplicates by content anyway
(Decision 8's mechanism), i.e. cost with no information gained, and it
would make record volume O(call sites × callee size) — the opposite of
FR-303.

**Sizing, since the plan asked for it honestly:** were it ever needed, the
replay fix is roughly *(i)* a `Map<cacheKey, hopRecord[]>` alongside
`_cache`, *(ii)* wrapping `analyzeFn`'s recorder to tee into that list,
*(iii)* replaying on the hit path in `compute` — but *(iv)* the replayed
records would need the *hitting* call site's identity re-stamped onto them
to be worth anything, which is a per-record rewrite, and *(v)* it interacts
with B5's refinement loop, which re-invokes `analyzeFn` and would need the
list reset per round. Non-trivial, and unnecessary. Do not do it without
evidence from C4/C5 that shared bodies are actually a reconstruction
problem.

### 13.5 Call-site identity: no `hopSite` field — §7.4's recommendation is superseded

§7.4 proposed `ctx.hopSite = {scope, nodeId, line}` as plain values on the
derived ctx, so `summaries.js` could stamp a cross-function hop with the
call site it crossed at.

**Decided: not needed, and not added.** §13.1 threads the entire stamped
`stepCtx` into `resolveCallSummary`, and that ctx's `recordHop` *already*
applies `{scope, nodeId, line, context}` to everything emitted through it.
The `call-arg-bind` hop therefore carries the call site's full identity
with no new field, no new plumbing, and — decisively — **the same values
the argument's own in-halves carry**, which is the property that makes the
edge join at all. A separate `hopSite` field would be a second, parallel
copy of information the stamping mechanism already delivers, i.e. exactly
the redundant-fields-drift failure mode §3 rejected `widened` for.

C4/C5 get call-site identity as: the caller-side `(scope, nodeId, line,
context)` on a `call-arg-bind` / `call-resolved` hop, plus
`(peerScope, peerContext)` for the function on the other side. That is
strictly more than `hopSite` would have carried.

### 13.6 B5/B6 degradation marking: the mechanism is decided here, the emission ships with §13.7

Three things were measured before deciding.

**Finding 1 — a B6 cap degradation is, today, completely silent.** With
`maxContextsPerFn: 1` and two call sites requesting genuinely different
contexts of the same callee, the second resolution degrades to the
empty-entry fallback. Its `returnFlat` is empty, so `case 'call'`'s
`for (const id of flat)` loop emits **nothing** — there is not even a hop
present to carry a marker. The call site's `call-arg-bind` hop points at a
`peerContext` that has no body anywhere in the record stream, and nothing
says why. That is §18.4's constraint violated in the interprocedural
dimension: "context budget exhausted" is indistinguishable from "no flow
crosses this call."

**Finding 2 — the fallback is the *same object* as the empty-entry
summary.** `compute`'s cap branch returns
`this._cache.get(this._key(qid, emptyState())) ?? emptyFieldSummary()`;
object identity, not a copy (asserted in the PoC). Setting a flag on it in
place would retroactively mark the **precise** empty-entry summary as
degraded for every later reader — a real bug, avoided only by knowing
about it in advance.

**Finding 3 — B5's bottom stub needs no marking.** The stub is
`{...emptyFieldSummary(), _recursive: true}`; empty `returnFlat`, so no
`call-resolved` hop is emitted on that round either. And B5's refinement
re-invokes `analyzeFn`, re-emitting the callee's hops with the *better*
summary; per Decision 8's monotonicity argument the stub round's output is
a subset of the refined round's, so the duplicate-tolerant record stream
absorbs it. Nothing to mark, nothing to strip.

**Decided — B6 marking is IN SCOPE for C3, B5 marking is not (there is
nothing to mark).** Not deferred to C4/C6: C4 grades edges that exist, and
this is about an edge that does *not* exist. Only the site that performed
the degradation knows it happened; by C4 the information is gone. The shape:

1. `FieldIdentitySummaryCache.compute`'s cap-degradation branch returns a
   **shallow copy** — `const degraded = { ...fallback, degradedReason: 'context-cap' };`
   — and caches the copy. Never mutates `fallback` (Finding 2).
   `degradedReason` is a **permanent, documented, externally-visible
   field**, deliberately unlike `_recursive`: `_recursive` is stripped
   because it is a transient recursion-in-progress marker, whereas a
   degraded summary stays degraded for the life of the cache entry. A
   string, not a boolean, so a later increment can add reasons without a
   shape change. `fieldSummaryEq` deliberately does **not** compare it —
   it is diagnostic, exactly like `widenings`.
2. `createCallSummaryResolver`, when `summary.degradedReason` is set and
   `ctx?.recordHop` is present, emits **one loss hop per id that entered
   the callee** (i.e. per `(path, id)` of the entry state it just built):

   ```js
   {
     kind: 'production', subKind: 'call-resolved',
     fromPath: null, toPath: null, dataElementId: <id>,
     syntacticPath: null, widenReason: null,
     lossReason: 'context-cap-degraded',
     peerScope: <callee qid>, peerContext: <callee context>,
   }
   ```

   Emitted at the resolver, not in `engine.js`, precisely because
   `engine.js`'s loop over an empty `returnFlat` cannot fire. The ids come
   from the *argument* side because those are exactly the identities whose
   downstream fate is now unrepresented — Decision 4's "always a real,
   non-null `dataElementId`" is satisfied without inventing one.
   `lossReason`, not `widenReason`, because §3 defines `lossReason` as "why
   this hop is a dead end", which is precisely what it is.

**How C4 must read this hop, pinned so §2.2 cannot silently swallow it
(2026-08-30, fix round 1).** The loss hop has `fromPath: null` *and*
`toPath: null`, so under §2.2's annotation rule it is an **annotation on
whatever edges the non-null in-halves form at the same join key**, not an
edge-forming half of its own — and once (a) records the argument's own
in-half, that is the common case at a degraded call site with a
path-shaped argument. **That is the intended reading, deliberately**: the
marker belongs *on* the real `argument → parameter` edge, saying "this
data was bound into a callee whose summary the engine honestly degraded;
its downstream is unrepresented." It is the same relationship
§10.2's `unsupported-target` write-out already has with the in-halves it
joins. When there is no non-null in-half (a literal or otherwise
path-less argument), §2.2's rule makes it edge-forming instead, which is
also correct — the "value with no prior aliasing source" case. **C4 must
surface it under both readings; what it must never do is drop it**,
because dropping it restores exactly the §18.4 silence Finding 1 measured.

**Prototyped, not just designed (2026-08-30, fix round 1).** Round 0 left
this the one mechanism in §13 that was specified without being run, which
contradicted this section's own opening claim. It is now executed in the
PoC via a `MarkingSummaryCache` subclass that overrides the cap branch
exactly as item 1 above specifies. Confirmed by running: the degraded call
site's hop carries `lossReason: 'context-cap-degraded'` and a
`peerContext` that provably has no recorded body; the precisely-resolved
call site's `call-resolved` hop carries no marker; the shallow copy leaves
the precise empty-entry summary unmarked (Finding 2, in both directions);
and a recorder-free run is unaffected by marking, which is what makes
`degradedReason` diagnostic rather than a fact.

Wiring the emission into shipped `summaries.js` is the follow-up task's job
(§13.7), like every other site here.

### 13.7 What the follow-up implementation task must do

Written the way §10.1/§10.2 were written for C2, so the next brief needs no
re-derivation. Files, in dependency order.

**`scanner/src/lineage/engine.js`**

| # | Site | Change |
|---|---|---|
| 1 | imports (line 2) | add `hashState` to the existing `./field-identity.js` import |
| 2 | `analyzeFunctionFieldIdentity`, ~line 848 | `const context = ctx?.recordHop ? hashState(entryState) : null;` beside the existing `scope` |
| 3 | `stepCtx` wrapper, ~line 864-866 | stamp `context, peerScope: null, peerContext: null` before `...h` (§13.3's snippet, verbatim) |
| 4 | `case 'call'`, line 505 | pass `ctx` as the 4th argument to `ctx.resolveCallSummary`. **This is the ONLY place the full ctx crosses into `summaries.js`** — items 6/7 below must not let `resolveCallSummary` reach `resolveExprIdentities` from there (§13.2a's boxed warning). |
| 5 | `case 'call'` resolved branch, ~line 512-520 | add `peerScope: summary.resolvedQid ?? null, peerContext: summary.resolvedContext ?? null` to the `call-resolved` hop (`?? null`, never bare — a 3-arg test stub supplies neither) |

**`scanner/src/lineage/summaries.js`**

| # | Site | Change |
|---|---|---|
| 6 | `entryStateFromCall`, line 286 | add optional 4th param `ctx`, then derive `const argCtx = ctx?.recordHop ? { recordHop: ctx.recordHop } : undefined;` ONCE before the loop and pass **`argCtx`, never `ctx`**, to `resolveExprIdentities` (line 291). Stripping `resolveCallSummary` is load-bearing, not tidiness — forwarding the full ctx changes the analysis result with no recorder attached, in the unsound direction under a tight cap. See §13.2a. Return shape unchanged. |
| 7 | `createCallSummaryResolver`'s closure, line 334 | add optional 4th param `ctx`; pass it to `entryStateFromCall` (which does the stripping in item 6 — keep the derivation inside `entryStateFromCall`, so the hazard cannot reappear via a future second caller) |
| 8 | same, after `entryStateFromCall` | compute `const calleeContext = hashState(entryState);` and, when `ctx?.recordHop`, emit one `write-out/call-arg-bind` per `(path, id)` of `entryState` (§13.2b's exact shape) |
| 9 | same, inside `cache.compute`'s callback, line 357 | build the callee ctx as `ctx?.recordHop ? { resolveCallSummary, recordHop: ctx.recordHop } : { resolveCallSummary }` — **hole 3**. Do not re-stamp `context` here; the callee's own `analyzeFunctionFieldIdentity` (change #2/#3) does it, and its stamps win by spread order. |
| 10 | same, at return | wrap: `{ ...summary, resolvedQid: qid, resolvedContext: calleeContext }` — a fresh object, never a mutation |
| 11 | `FieldIdentitySummaryCache.compute`, cap branch, lines 115-123 | return/cache a **shallow copy** carrying `degradedReason: 'context-cap'` (§13.6, Finding 2). Prototyped in the PoC as `MarkingSummaryCache` — but that subclass re-derives `willDegrade` by re-testing the cap (`!seen.has(hash) && seen.size >= this._maxContextsPerFn`) *outside* `compute`, purely because a subclass cannot see which branch `super.compute` took. Do NOT carry that re-derivation inline: mark `fallback` at its one real call site, inside the existing cap-branch `if` (lines 115-123), right where the branch is already decided — `const fallback = { ...base, degradedReason: 'context-cap' };` before `this.set(...)`/`return fallback;`, never a mutation of the shared object in place (the same fallback can be cached under multiple keys, e.g. the function's own empty-entry summary — mutating it in place would leak the marking there too), and never a second cap test. |
| 12 | `createCallSummaryResolver` | when `summary.degradedReason` and `ctx?.recordHop`, emit the §13.6 loss hop per entry-state id |
| 13 | `fieldSummaryEq` comment | note that `degradedReason` is deliberately not compared (diagnostic, like `widenings`) |

**`scanner/src/lineage/driver.js`**

| # | Site | Change |
|---|---|---|
| 14 | `runFieldIdentityAnalysis`, line 65 | accept `opts.recordHop` and spread it into the per-function ctx **conditionally** (`...(opts.recordHop ? { recordHop: opts.recordHop } : {})`), so a caller that supplies none gets a byte-identical `{ resolveCallSummary }` — Decision 7.2's "true by construction" |

**Tests**

| # | Change |
|---|---|
| 15 | Re-point `engine-provenance-interprocedural-poc.test.js`'s local prototypes at the shipped functions, delete the `this`-binding stand-in and the "hole is real" tests (they will correctly start failing), and fold what remains into `engine-provenance.test.js`. Drop the PoC file and its `package.json` `test:lineage` entry in the same commit. |
| 15b | Add the **golden-baseline** regression the PoC now carries: for a fixture whose call ARGUMENT is itself a resolvable call, and again for a two-call-site cap-1 cache, assert the new wiring's recorder-free result equals a **hardcoded pre-C3 golden literal** (`['data:email']` and `['data:other-email']` respectively — the exact values the PoC pins), comparing the full canonicalized `{exitState, returnFacts, mutatedParams, widenings}` shape (matching item 16's own canonicalization), not just `returnFacts`' identities. **Do NOT compare against "the shipped resolver"** — after this task lands, the shipped resolver IS the new wiring, so a live comparison degenerates into `assert.deepEqual(result, result)`, a vacuous, always-passing test. Only a value fixed independently of whichever implementation is live stays meaningful. Item 16's with/without-recorder comparison cannot catch this class either way (the divergence moves both arms identically) — the guard must be a fixed golden, not a relative comparison. |
| 16 | Extend the existing **write-only invariant** test (`engine-provenance.test.js`, ~line 245) with at least one multi-function fixture driven through a real `FieldIdentitySummaryCache`, run with and without a recorder. This is the guard that catches the C2-era class of bug where a recorder's presence perturbed cache-cap accounting; C3 adds three new recorder-conditional branches inside `summaries.js`, so it must cover them. |
| 17 | Add a `driver.js` test proving `opts.recordHop` reaches every function in a multi-file project AND that omitting it leaves `runFieldIdentityAnalysis`'s `results`/`cache` unchanged. |

**Deliberately NOT in the follow-up's scope:** instrumenting
`applyAtCallSite` (not wired into `engine.js`; see §10.3's correction), the
cache hop-replay fix (§13.4), a `hopSite` field (§13.5), and any change to
`field-identity.js` (never).

---

## 14. `path-store.js`: the compact DAG (Sub-project C, increment 4)

Added 2026-08-30 by increment C4's design task. Everything in this section
is **decided**, not proposed, and every behavioural claim and every number
in it was produced by running code in
`scanner/test/lineage/path-store-poc.test.js` — a throwaway-named PoC
committed alongside this section, which prototypes `path-store.js` and the
two new `ids.js` functions LOCALLY (shipped source is unmodified by this
design task, exactly as C3's own design task did). §14.10 is the follow-up
implementation task's file/line checklist.

Two questions were open when this increment was scoped, and neither is
answerable on paper. Both are now answered by execution:

- **Q1 — cross-function node addressing.** A `write-out/call-arg-bind`
  hop's destination is `(peerScope, peerContext, toPath, dataElementId)`,
  **not** `(scope, context, …)`. §14.3.
- **Q2 — does `call-resolved`'s `fromPath: null` ever form a real edge?**
  **Yes** — it is the caller-side half of the return stitch, and its source
  is the callee's own function-exit node. But §2.2's annotation rule, read
  literally, demotes exactly this hop to an annotation and silently deletes
  the stitch. §14.4 corrects §2.2 in place.

### 14.1 What `path-store.js` is, and the isolation boundary it introduces

`path-store.js` is a **pure consumer of a hop-record stream**. It takes
hop records — the exact 14-field shape §3 + §13.0 define — and builds a
deduplicated DAG. It does not run analysis, and:

> **`path-store.js` must NEVER import `engine.js`, `summaries.js`, or
> `driver.js`.** It consumes their OUTPUT, never their internals. This is a
> stronger, additional boundary on top of the existing "`src/lineage/` may
> import pure utilities from `src/dataflow/`, never that package's
> `engine.js`/`summaries.js`" rule.

This is not tidiness. It is what makes the store testable at all right now:
there is still no source registry (Sub-projects D/E), so
`runFieldIdentityAnalysis` analyzes every function from `emptyState()` and a
real project-wide driver run emits **zero** hops today. A store that could
only be exercised through the driver would be untestable by construction. A
store fed a hand-built or hand-seeded array is testable immediately, and
every fixture below does exactly that.

It also means `path-store.js`'s only dependency is `ids.js`.

### 14.2 The node: `(scope, context, kind, path | siteNodeId, dataElementId)`

§2.1 decided the node is `(scope, accessPath, dataElementId)`. C4 makes two
additions, both forced by evidence rather than taste.

**(a) `context` is part of node identity.** §13.3 already moved the *join
key* to four parts. The node must follow, for a reason §13.2 states
directly: `peerContext` "is what makes the binding land in the *right*
context of the callee." If node identity ignored `context`, `peerContext`
would be decorative and §9.4's phantom would return one level up — two entry
contexts of one function would share a node, and a backward walk in
context B could leave through an edge that only ever existed in context A.
Cost, measured: the two-context `function g(x) { const y = x; return y; }`
fixture builds 6 nodes with `context` in the identity and would collapse to
5 without it. The blow-up is bounded by the B6 per-function context cap
(default 16), and correctness wins.

**(b) Terminal endpoints get their own node `kind`, never a fabricated
path.** §10.2 is explicit that a `return` must not be given a pseudo-path
like `'@return'`, and that C3/C4 identify a function exit structurally
(`kind === 'write-out' && subKind === 'return' && toPath === null`). C4 needs
those endpoints to *be* nodes, so it keeps them in a separate namespace
rather than inventing a path string that could collide with a real one:

| node `kind` | created by | keyed on | why |
|---|---|---|---|
| `path` | any half with a non-null `fromPath`/`toPath` | `(scope, context, path, id)` | the ordinary state location |
| `return` | `write-out/return`; also *addressed* by `production/call-resolved` via `(peerScope, peerContext)` | `(scope, context, id)` — **per function-context, not per CFG node** | forced: a `call-resolved` hop names only `(peerScope, peerContext)`, with no node id, so every return site of a context must aggregate into one exit node |
| `escape` | `write-out/call-arg` (a bare call statement) | `(scope, context, siteNodeId, id)` | the value leaves the analysis; §10.2 calls this the natural sink-attachment point for Sub-project D. Nothing addresses it from elsewhere, so per-CFG-node precision is free |
| `loss` | any `write-out` with `toPath === null` and a non-null `lossReason` (today: `assign`/`unsupported-target`) | `(scope, context, siteNodeId, id)` | §18.4: a dead end that is *recorded as a dead end* is the data-layer form of "never present a truncation as an absence" |
| `origin` | §2.2's surviving half — a group whose ONLY in-halves are annotations | `(scope, context, siteNodeId, id)` | "a value with no prior aliasing source" |

`origin` is exercised only by a hand-built hop pair in this task's PoC — no
real-parser fixture in C1-C3's own instrumentation reaches it today, since
every construct that carries a `dataElementId` currently inherits it from
somewhere already in `state` (a contributing key `production`/`selection`
hop always accompanies it). This is a real, honestly-disclosed gap, but not
a dead branch: it is the exact shape a Sub-project D source registry will
produce the first time it seeds an identity at a source site with no prior
state to point to (a null-`fromPath`, null-`peerScope` in-half is precisely
"this value originates here, not upstream"). Kept, tested with the hand-built
pair, and left for D's own real-parser coverage rather than removed.

Expression-internal constructs still create **no** nodes (§2.1). An object
literal, a ternary, a template literal survive as `annotations[]` on the
edges they helped form — pinned by a test asserting the `production/object`
hop is present as an annotation and that no node was created for it.

### 14.3 Half-edge classification — the exact rules, and the answer to Q1

Grouped by §13.3's four-part join key `(scope, nodeId, dataElementId,
context)`. Within a group:

**In-halves** (`kind` is `production` or `selection`):

1. `fromPath !== null` → **sourced**, at `(scope, context, path, id)`.
2. `fromPath === null && peerScope !== null && lossReason === null` →
   **peer-sourced**, at `(peerScope, peerContext, ⟨return⟩, id)`. See §14.4.
3. otherwise → **annotation**.

**Out-halves** (`kind === 'write-out'`), in this order:

1. `toPath !== null && peerScope !== null` → **peer-targeted**, at
   `(peerScope, peerContext, toPath, id)`. **This is Q1's answer.**
2. `toPath !== null` → **targeted**, at `(scope, context, toPath, id)`.
3. `subKind === 'return'` → the `return` terminal.
4. `subKind === 'call-arg'` → the `escape` terminal.
5. `lossReason !== null` → the `loss` terminal.
6. otherwise → **unclassified**, recorded in `diagnostics().unclassified`
   and never silently dropped. Empty for every fixture in the PoC — which
   is the closed-set proof that rules 1-5 cover today's whole out-half
   vocabulary (`assign`, `assign-weak`, `call-arg`, `call-arg-bind`,
   `return`, and `assign`-with-`unsupported-target`).

**Q1, proven rather than argued.** For
`function helper(u) { return u.email; } function caller(a) { const out = helper(a); return out; }`
seeded `a.email → data:email`, the bind hop is stamped `scope: caller`,
`peerScope: helper`, `toPath: 'u.email'`. The PoC asserts that the node id
computed from `(peerScope, peerContext, 'u.email', id)` is **byte-identical**
to the node id computed from the callee's OWN
`selection/member from 'u.email'` hop (`scope: helper`, its own `context`) —
i.e. peer addressing lands exactly on a node the callee independently
created. The naive alternative computes a different id, and
`store.getNode(thatId)` is `null`: it is an orphan no hop anywhere can reach.

And the hazard is not hypothetical. With a caller that also has a local
variable named `u`, the PoC shows own-scope addressing of the callee's
parameter produces the **same id** as the caller's own local `u` — Decision
5's bug class ("an endpoint that is not the location it names") in a new
disguise, exactly as §13.2 predicted. Peer addressing keeps them apart, and
no binding edge lands on the caller-local `u`.

**A pair whose BOTH endpoints are peer-addressed is excluded.** At any
resolved call, the `call-resolved` in-half and the `call-arg-bind` out-half
share a join key (asserted in the PoC), so a naive full cross product pairs
them and manufactures a `callee ⟨return⟩ → callee parameter` edge that no
program ever executed — a fabricated cycle, created by C4 rather than by the
code. Such a pair always describes a transition *entirely inside* the
callee, which the callee's own hops already record, so excluding it can
never drop a real caller-side fact. Nothing else is pruned; see §14.7.

### 14.4 Q2 — the return stitch, and a correction to §2.2

Running the two-function fixture above with a recorder produces, at the
caller's `const out = helper(a)` CFG node, **four** hops sharing one join
key:

```
production/ident      fromPath 'a.email'  (the argument's own in-half)
write-out/call-arg-bind  toPath 'u.email'  peer=(helper, Ch)
production/call-resolved fromPath null     peer=(helper, Ch)
write-out/assign      toPath 'out'
```

and, inside `helper` under context `Ch`, `selection/member from 'u.email'`
plus `write-out/return toPath null`.

**The stitch exists, and it goes through the callee.** The
`production/call-resolved` hop is `kind: 'production'`, so per §13.0 its
peer is its *source* — and that source is the callee's function-exit node
`(helper, Ch, ⟨return⟩, id)`, which the callee's own `write-out/return` hop
independently creates. `peerContext` is byte-equal to the `context` the
callee's body was recorded under (asserted). The PoC walks the whole chain:

```
(caller, Ca, a.email) → (helper, Ch, u.email) → (helper, Ch, ⟨return⟩)
                      → (caller, Ca, out)     → (caller, Ca, ⟨return⟩)
```

Four edges, two of them cross-scope, and no step is asserted rather than
built.

> **Correction to §2.2, per this document's own fix-rather-than-diverge
> policy.** §2.2 says a `null`-`fromPath` in-half "forms a real edge only
> when NO non-null in-half exists at that key — which is precisely the
> 'value with no prior aliasing source' case (a literal, or — the one case
> that matters for interprocedural stitching — a resolved call's return
> value, which is C3's join point…)". That parenthesis names the right case
> and the rule then **excludes** it: in the real C3 stream the argument
> expression's own `production/ident from 'a.email'` in-half sits at the
> *same* join key as the `call-resolved` hop (measured — the PoC asserts
> it), so the literal rule demotes `call-resolved` to an annotation. A
> `PathStore` built that way leaves the callee's exit node with **zero**
> outgoing edges: reconstruction from `out` reports the argument as its
> immediate predecessor and the callee body is unreachable. The PoC builds
> exactly that store and asserts the dead end, so the defect cannot be
> re-argued away.
>
> **The corrected discriminator is `peerScope`, not `fromPath`.** A null
> `fromPath` with a non-null `peerScope` is not source-less; it is
> **peer-addressed**. §2.2's annotation rule survives unchanged for the
> genuinely source-less case (`peerScope === null`), which is what the
> `origin` node kind covers.

**The one exception, and it is `lossReason`.** §13.6's context-cap
degradation hop is also `production/call-resolved` with `fromPath: null`
and a non-null `peerScope` — but it names a callee whose body was **never
analyzed**, so `(peerScope, peerContext, ⟨return⟩, id)` does not exist in
the stream. Treating it as peer-sourced would fabricate an origin node with
no predecessors and report a path that begins in the middle of nothing —
Decision 5's bug class again. `lossReason === null` is therefore part of
rule 2, and a degraded hop falls through to *annotation*, which is exactly
the reading §13.6 asked for ("the marker belongs *on* the real
`argument → parameter` edge"). Verified against the shipped resolver under
`new FieldIdentitySummaryCache(1)`: no exit node is fabricated for the
degraded callee, and the `lossReason: 'context-cap-degraded'` marker is
present on the real `call-arg-bind` edge. It is never dropped — which is
the half §13.6 says matters most.

> **Disclosed precondition, found by task review, not closed this
> increment.** The `lossReason === null` guard correctly distinguishes "the
> callee's body was analyzed" from "it was degraded away" WITHIN one fully
> recorded analysis run. It does not, on its own, guarantee the callee's
> exit hops are actually PRESENT in the stream `path-store.js` was fed —
> that additionally requires the stream to be complete for
> `(peerScope, peerContext)`. A reachable counter-shape: analyze `callerA`
> against a shared `FieldIdentitySummaryCache` with NO recorder attached
> (warming the cache with `helper`'s summary), then analyze `callerB`
> against that SAME cache with a recorder attached. `helper` is now a cache
> HIT for `callerB` — `resolveCallSummary`'s `cache.compute()` never
> re-invokes `analyzeFn`, so `helper`'s own body hops never fire a second
> time — yet the resolved summary still carries `lossReason: null` (it was
> genuinely, precisely resolved; it just wasn't resolved *this run*). Fed
> into `path-store.js`, `callerB`'s `call-resolved` hop is peer-sourced at
> `(helper, Ch, ⟨return⟩)`, a node the store never otherwise creates —
> exactly the fabricated-origin failure mode the `lossReason` guard exists
> to prevent, reached by a different door. Not reachable within a SINGLE
> fully-recorded run (checked across 6 fixtures: 2-fn, 3-fn/2-site, mutual
> recursion, self recursion, mutated-param return, §9.6's own same-context
> cache hit — zero orphaned exit nodes in any of them), but directly
> reachable through `driver.js`'s own returned-and-reused `cache`, which
> `driver.test.js` already exercises in this exact shape. **Left for the
> follow-up implementation task (§14.10 item 10):** `path-store.js` must
> treat this as a build-time DIAGNOSTIC, not a silent fabrication — a
> `return` node with zero in-edges that nonetheless sources a real
> cross-scope edge is detectable with the same `inIndex`/`outIndex` the
> store already builds, and must be recorded via `diagnostics()`, never
> thrown and never dropped, per this document's own established §9 culture
> and §14.9's "recorded, never silent" framing.

### 14.5 The two new `ids.js` functions

`DESIGN_PATH_PROVENANCE.md` §12 and the C-scoping doc both anticipated a
single `pathId`. Two functions are needed, and neither is called `pathId`:

```js
provenanceNodeId({ kind, scope, context, path, siteNodeId, dataElementId },
                 discriminatorParts = [])      // -> `pnode:<kind>:<12 hex>`
provenanceEdgeId({ fromNodeId, toNodeId, dataElementId,
                   scope, context, siteNodeId,
                   inKind, inSubKind, outKind, outSubKind,
                   widenReasons = [], lossReasons = [] },
                 discriminatorParts = [])      // -> `pedge:<12 hex>`
```

Both use `ids.js`'s existing `_hash`/`_canon` helpers unchanged: sha256 over
a canonicalized, pipe-joined material string, truncated to `ID_HEX_LEN`,
prefixed by the entity kind. Never a counter.

- **Distinct `pnode:`/`pedge:` prefixes, not `node:`/`edge:`.** A provenance
  node is not a `DataFlowGraph v1` node; `validate.js` regex-checks the
  `node:`/`edge:` prefixes for graph entities, and making the two
  indistinguishable would be a latent contract bug. Sub-project E maps
  between the two namespaces; it must not confuse them.
- **`pathId` is deliberately left unused.** The thing C5 reconstructs *is* a
  path, and it will plausibly want that name for its own entity. Calling an
  edge a path now would cost C5 the obvious name.
- **The edge discriminator carries the SITE** (`scope`, `context`,
  `siteNodeId`) as well as both endpoint ids. `fromNodeId`/`toNodeId` already
  embed each side's own scope/context, but not the CFG node the pair was
  observed at — and two structurally identical hops at two different program
  points are two materially different edges (FR-305), each needing its own
  `line` for display and for §9.2's hop-ordering lever. Omit `siteNodeId` and
  they silently collide into one edge carrying one arbitrary line.
- **It also carries both halves' `kind`/`subKind` and their reason strings.**
  This is the `flagship-fixture.mjs` lesson applied deliberately: that
  module's edge ids once collided because `dataElementIds` was left out of
  the discriminator (see this package's own CLAUDE.md row). Over-specifying a
  content hash costs nothing; under-specifying it is a silent merge.
- **Object arguments, not `ids.js`'s usual positional form.** A deliberate,
  narrow divergence (`graphId` is the in-file precedent). `provenanceEdgeId`'s
  discriminator is twelve fields wide, `provenanceNodeId`'s is six, and a
  positional `discriminatorParts` array is exactly the shape from which a
  field gets omitted.

  > **Corrected by the final whole-branch review (finding 2).** The
  > sentence above originally said "`path-store.js` calls each of these
  > from ONE place" as the justification. `provenanceEdgeId` genuinely has
  > one call site; `provenanceNodeId` has FIVE (`intern`, `sourcesFor`,
  > `targetsFor`, the `orphanedPeerSources` check, and `nodeIdFor`). The
  > object-argument choice is still correct — arguably more so at five call
  > sites than at one, since a positional array is exactly as easy to get
  > wrong the second, third, fourth, and fifth time as the first — but the
  > stated reason was wrong. `scanner/src/lineage/CLAUDE.md`'s own
  > `path-store.js` row repeated the same error and has been corrected too.
- **Not in the discriminator:** `syntacticPath` and `line` (display
  material — pinned by a test where two hop records differing only in
  `syntacticPath` collapse to one edge), edge `annotations[]`, and
  `ambiguousCorrelation` (both are functions of the group and of the
  endpoints already in the id, so they cannot distinguish two edges).

The PoC pins idempotence (two independent analysis runs of the same fixture
produce identical edge ids; re-delivering a stream changes nothing) and
non-collision (every discriminator field, changed alone, moves the id;
reason arrays are order-independent sets; 5000 distinct node descriptors
produce 5000 distinct ids).

### 14.6 Deduplication — two boundaries, and they are not interchangeable

§8 pushes worklist re-emission onto the consumer. The consumer needs **both**
of these, and the plan's own framing of them as alternatives is wrong:

1. **Raw-hop dedup, at ingest.** A `Set` keyed on the 14 fields in a fixed
   order. This is the volume control: it collapses the re-visit
   multiplicity §8 describes. Measured on a `while`-loop fixture: 12 records
   offered, 8 accepted. It is safe precisely because of §8's monotonicity
   argument — duplicates are exact repeats, never stale facts.
   The key is built from an **explicit field list**, not `Object.keys(h)`,
   so a hop with an ABSENT key (§3 warns this is reachable for any emission
   path bypassing `analyzeFunctionFieldIdentity`'s progressive stamping)
   is recorded in `diagnostics().malformed` instead of silently hashing to a
   different key than its fully-stamped twin. C4 is where §3's completeness
   guarantee becomes checkable rather than merely asserted.
2. **Node/edge dedup, at materialization.** Content-hash ids are Map keys,
   so two structurally identical edges collapse. This is the
   **correctness-bearing** one: two hop records that are NOT byte-identical
   can still describe the same logical edge (the PoC pins a pair differing
   only in `syntacticPath`), and (1) keeps both. (2) collapses them to one.

Dedup (1) alone leaves duplicate edges. Dedup (2) alone would be correct but
would let group membership grow unboundedly on a hot loop, and the per-group
cross product is quadratic in group size. Ship both.

**Where `context`'s memory cost actually lands, unmeasured but named.**
`context` (§13.3's `hashState(entryState)`) is `hashState`'s full canonical
string — bounded by the entry state's size, not the function's — computed
once per analysis run and held by reference on every node/edge record
sharing it, so the per-record field cost is one pointer, not N copies of the
string. The real, unmeasured cost is in the DERIVED key strings this
increment builds from it: dedup (1)'s ingest key and (2)'s node/edge id
discriminator each concatenate the full `context` text once per hop/group,
and those concatenated strings are retained for the store's lifetime in
`_seen`/the group index. This is what C5/Sub-project E should profile at
real project scale, not the record fields themselves.

**Construction is two-phase**: `addHop`/`addHops` accumulate into groups;
nodes and edges are materialized lazily on the first read and cached until
the next `addHop`. This is what lets an edge's annotation set be complete
before its id is computed, and it makes the store order-insensitive — the
same hops delivered in any order produce the same DAG.

**Cycle safety (§9.3).** Construction is one linear pass over the hop stream
plus a per-group cross product; it never walks the graph, so it cannot
recurse into a cycle. The read API is deliberately **traversal-free** —
`nodes()`, `edges()`, `getNode`, `getEdge`, `edgesFrom`, `edgesTo`,
`hasEdge`, `nodeIdFor`, `stats`, `diagnostics` are all O(1) or O(degree)
index lookups. There is no recursion anywhere in this increment's code, by
construction rather than by discipline. Bounded backward reconstruction is
C5's job and C5's alone. Proven on a mutual-recursion fixture
(`ping`/`pong`/`top`): the store builds 8 nodes and 11 edges from 34 raw
records without recursing, and an explicitly budgeted walk *in the test*
confirms a genuine cycle really is present — §9.3 is not hypothetical.

### 14.7 Correlation ambiguity is measured per pairing, not per group

§9.1 marks an edge `ambiguousCorrelation: true` when, at a group,
`distinctInPaths ≥ 2 && distinctOutPaths ≥ 2`. Applied verbatim to a C3
stream this is far too coarse, and the measurement is the argument: at the
two-function resolved-call fixture it marks **3 of 5** edges — including
both genuinely correct call-boundary edges — because the argument's in-half
and the return's in-half share one join key by construction (§14.4). A
marker that fires on the right answers is not usable input to FR-306's
confidence grading.

**Decided: count only the pairings the store would actually form.** For an
edge `(s, o)`, ambiguity is `|{s' : pairable(s', o)}| ≥ 2 && |{o' :
pairable(s, o')}| ≥ 2`, where `pairable` is §14.3's peer×peer exclusion.
Measured effect, same fixtures: the resolved-call fixture drops from 3
marked edges to **1**; a 3-function/2-call-site fixture from 6 to 2; the
mutual-recursion fixture from 6 to 2. §9.1's own genuine intraprocedural
case (`const x = { a: p.email, b: q.email }`, both carrying the same id) is
**unchanged at 4** — the refinement removes only the marks that the call
boundary's own structure introduced, not §9.1's real ambiguity. No new hop
field, no threading, no `slot`.

**The one artefact that survives, disclosed rather than pruned.** The
remaining marked edge at a resolved call is the **bypass**: `a.email → out`,
which skips the callee. It is real data flow (the identity genuinely reaches
`out`) but it is not the route the program takes, and it lets a
reconstruction report a path that never enters the callee. Pruning it would
require a leg-based rule ("in a group containing a peer half, a non-peer ×
non-peer pair is not an edge") and that rule was tried and **rejected on a
counter-example**: at `const o = { r: helper(a), s: b.email }` the group also
contains a legitimate non-peer × non-peer pair (`b.email → o.s`), which the
rule deletes. Losing a real edge is a worse failure than keeping a marked
extra one — §9.1's own "detect and mark, do not prevent" verdict, reached
here for the second time on independent evidence.

**The cheap closure remains on the table, unchanged from §13.2's own note:**
the parameter index is known for free at the bind emission site, so a `slot`
field would separate the legs exactly. §9.1's evidence-first policy still
applies; this section now supplies part of that evidence.

### 14.8 §9.5's analysis-level truncation: a reserved out-of-band channel

**Decided: reserve it in C4, do not invent a hop for it.** An `ITER_BUDGET`
break in `analyzeFunctionFieldIdentity` is a whole-analysis-run truncation,
and §9.5 says the entire result set for that function must be marked, not
individual hops. Representing it as a hop would mean a fourth hop `kind` —
which §2.2 explicitly guards against ("a provenance site that is not one of
those three is a sign the taxonomy is being extended without the review the
taxonomy earned"). So it arrives out of band:

```js
store.markTruncated(scope, context, reason)   // e.g. reason: 'iter-budget'
```

Every node and edge in that `(scope, context)` then carries
`truncated: true`, and `diagnostics().truncations` lists them. Prototyped
and pinned: before the call nothing is marked, after it everything in that
scope-context is. **Reserving costs one method and one Map now; retrofitting
it in C5 would mean revisiting the node and edge shape after C5 has been
built on them.** The *producer* side — engine or driver actually calling it
when the budget breaks — is deliberately NOT in C4's scope: it is an
`engine.js` change, and C4 changes no existing file.

### 14.9 What C4 deliberately does not do

- **No backward walk, no reconstruction, no path budget, no prioritization.**
  C5's, entirely. C4 ships the structure and the minimum read API needed to
  prove that structure correct.
- **No `DataFlowGraph v1` output.** Sub-project E.
- **No FR-306 grade computation.** C6 reads `widenReasons`/`lossReasons`/
  `ambiguousCorrelation`/`truncated`/**`annotations[]`** off the edges; C4
  only carries them.

  > **Corrected by the final whole-branch review (finding 5): `annotations[]`
  > was missing from this list, and its absence would reintroduce exactly
  > the silence §13.6 exists to prevent.** A §13.6 context-cap-degraded
  > marker (`lossReason: 'context-cap-degraded'`) is classified as an
  > ANNOTATION, not a source (correctly, per §14.4's `lossReason` exception
  > — the peer was never analyzed, so it cannot be peer-sourced) — it
  > therefore never reaches `edge.lossReasons`, only `edge.annotations[]`.
  > `C4/Q2c` proves this is exactly where it lives (it finds the marker via
  > `e.annotations.some(a => a.lossReason === 'context-cap-degraded')`, not
  > via `e.lossReasons`). A C6 implementer reading only "reads
  > `widenReasons`/`lossReasons`/…" off the edges would drop the marker
  > silently — the precise §18.4 failure mode §13.6 was written to close.
  > C6 must read `annotations[]` too, not only the edge's own top-level
  > reason arrays.
- **No collapsing of repeated library/framework nodes into typed summary
  hops.** §12 and the C-scoping doc both left this "plausibly D or C4". It is
  **not** C4: deciding that a node is a library node needs a registry that
  does not exist yet (Sub-project D). C4 has no way to tell a framework
  function from an application one, and guessing would be the same class of
  error as a fabricated endpoint.
- **No wiring into `runFieldIdentityAnalysis`.** A driver run emits zero hops
  today (§14.1). Wiring is a follow-up task's item, and it is a `driver.js`
  change, not a `path-store.js` one.
- **No change to `field-identity.js`** (never), and no change to any existing
  `src/lineage/*.js` file in the design task itself.

### 14.10 What the follow-up implementation task must do

Written the way §10.1/§10.2/§13.7 were, so the next brief needs no
re-derivation.

**`scanner/src/lineage/ids.js`**

| # | Site | Change |
|---|---|---|
| 1 | after `edgeId` | add `provenanceNodeId` with §14.5's exact object signature; prefix `pnode:<kind>:`, via the existing `_hash`/`_canon` |
| 2 | after it | add `provenanceEdgeId` with §14.5's exact object signature; prefix `pedge:` |
| 3 | `test/lineage/ids.test.js` | extend with the discriminator-separation and bulk-non-collision cases the PoC carries (`C4/5`, `C4/5b`) |
| 4 | `validate.js` | **no change.** `pnode:`/`pedge:` are not `DataFlowGraph v1` entity kinds and must not be added to its id-prefix regexes. Confirm by running `npm run test:lineage` — the json-schema-parity test must stay green untouched |

**`scanner/src/lineage/path-store.js` (new)**

| # | Item | Detail |
|---|---|---|
| 5 | imports | `ids.js` ONLY. Never `engine.js`/`summaries.js`/`driver.js` (§14.1). Add a test that asserts this by reading the file's own import list, so the boundary is enforced rather than documented |
| 6 | `HOP_FIELDS` | the explicit 14-field list from §3 + §13.0, in a fixed order — never `Object.keys(h)` (§14.6) |
| 7 | `classifyIn` / `classifyOut` | §14.3's rules verbatim, including `lossReason === null` in the peer-sourced branch (§14.4) and the `unclassified` fallthrough |
| 8 | `PathStore` | `addHop(hop) -> boolean`, `addHops(hops) -> number`, `markTruncated(scope, context, reason)`; two-phase build; the traversal-free read API listed in §14.6 |
| 9 | edge construction | per-group cross product with the peer×peer exclusion (§14.3) and the per-pairing ambiguity measure (§14.7) |
| 10 | `diagnostics()` | `{ malformed, unclassified, truncations, orphanedPeerSources }` — all four are "recorded, never thrown, never dropped". `orphanedPeerSources` is §14.4's disclosed stream-completeness gap: a peer-sourced `call-resolved` hop (`lossReason: null`, non-null `peerScope`) whose named `(peerScope, peerContext, ⟨return⟩, dataElementId)` node has zero real in-edges once the whole stream has been ingested — detectable via the store's own `inIndex`/`outIndex` at build-finalize time, no new input needed. Reachable today via a cache warmed by a no-recorder run and reused by a later recorder-attached run (`driver.js`'s own returned cache, exactly as `driver.test.js` reuses it) — record it, do not fabricate an origin for it and do not drop the edge. |

**Tests**

| # | Change |
|---|---|
| 11 | Re-point `path-store-poc.test.js` at the shipped `path-store.js`/`ids.js`, delete its two local prototype blocks, rename it to `path-store.test.js`, and update the `test:lineage` script in `scanner/package.json` in the SAME commit — C3's item 15 precedent |
| 12 | Keep every assertion, and especially keep `C4/Q2b` (the literal-§2.2 store with a dead-end callee exit) — it is the only guard that stops the §14.4 correction being silently undone by a future refactor of `classifyIn` |
| 13 | Add a driver-level test only once a hop-emitting driver run is possible (Sub-project D/E). Until then a driver test would assert on an empty stream and be vacuous — see the note at the top of `engine-provenance-interprocedural.test.js`'s own driver test for the same reasoning |

**Deliberately NOT in the follow-up's scope:** everything in §14.9, plus any
change to `engine.js`/`summaries.js` (C4 consumes the C3 stream exactly as
shipped — no hop shape change is needed to answer Q1 or Q2).

### 14.11 Measured numbers

Every row produced by running the PoC's own fixtures through the prototype
store on 2026-08-30. "raw" is records offered, "dedup" is records accepted
after §14.6's ingest dedup.

| fixture | raw | dedup | groups | nodes | edges | cross-scope | ambiguous |
|---|---|---|---|---|---|---|---|
| `const b = a.email; return b;` | 4 | 4 | 2 | 3 | 2 | 0 | 0 |
| §6's own worked example (2 fields, object literal) | 14 | 14 | 6 | 8 | 6 | 0 | 0 |
| `while` loop with a re-assigned variable | 12 | 8 | 4 | 4 | 4 | 0 | 0 |
| 2-function resolved call | 8 | 8 | 3 | 5 | 5 | 2 | 1 |
| 3-function chain, 2 call sites | 20 | 20 | 7 | 11 | 11 | 6 | 2 |
| mutual recursion (`ping`/`pong`/`top`) | 34 | 19 | 6 | 8 | 11 | 5 | 2 |
| §9.1's cross-join (`{a: p.email, b: q.email}`) | 9 | 8 | 2 | 5 | 6 | 0 | 4 |

§6's fixture is the one to read closely: its 14 deduplicated records become
**8 nodes and 6 edges** — the two field-distinct three-hop paths §6 predicts
(`user.email → u.email → o.email → ⟨return⟩` and the same for `.ssn`), with
**zero** materialized paths. That is FR-303's compactness requirement,
measured rather than claimed.

---

## 15. Bounded path reconstruction (Sub-project C, increment 5)

Added 2026-08-30 by increment C5's design task. Everything in this section
is **decided**, not proposed, and every behavioural claim and every number
in it was produced by running code in
`scanner/test/lineage/path-query-poc.test.js` — a throwaway-named PoC
committed alongside this section, which prototypes `path-query.js` and the
one new `ids.js` function LOCALLY (shipped source is unmodified by this
design task, exactly as C1's, C3's and C4's own design tasks did). §15.10
is the follow-up implementation task's file/line checklist.

§14.9 drew the boundary this section crosses: *"No backward walk, no
reconstruction, no path budget, no prioritization. C5's, entirely."* Five
questions were open when this increment was scoped, and none is answerable
on paper. All five are now answered by execution:

- **Q3 — what IS a path in the output?** A node id sequence *and* the edge
  sequence that joins it, with the grading-bearing edge fields carried
  inline. A bare node sequence is provably insufficient. §15.2.
- **Q4 — what stops a backward walk on a genuinely cyclic DAG?** An
  explicit **per-path** visited set (never a global one), plus three
  in-walk budgets (`maxExpansions`, `maxDepth`, `maxCandidatePaths`) — see
  §15.10's own corrected count (Task 2 review finding 5; an earlier draft
  here said "four," double-counting or mis-scoping against the two
  post-hoc caps §15.5 adds separately). Proven terminating on `C4/4`'s real
  mutual-recursion cycle. §15.3.
- **Q5 — what does §18.4's "cap alternate paths per source/sink pair" bound
  when there is no source/sink registry?** The **(terminal node, start
  node) pair** — the terminal node is the closest thing to a "source" this
  increment has, and a purely global cap is measurably worse. §15.5.
- **Q6 — what is FR-305's "materially different" with today's signals?**
  The **edge** id sequence, never the node id sequence. Proven against a
  real fixture where the two disagree. §15.6.
- **Q7 — what does §18.4's "prioritize paths that differ in boundary,
  transformation, or protection state" mean when two of those three do not
  exist yet?** It asks for a **diverse retained set**, not a top-N by any
  scalar — so the cap is diversity-first over the signals that do exist,
  and the two absent dimensions are named, not faked. §15.7.

### 15.1 `path-query.js`: what it is, and the boundary it inherits

`path-query.js` is a **pure consumer of a built `PathStore`**. It takes a
store and one node id and returns a bounded, ordered, honestly-labelled
list of reconstructed paths. It never sees a hop record — C4 already turned
those into a DAG — and it inherits §14.1's isolation rule unchanged:

> **`path-query.js` must NEVER import `engine.js`, `summaries.js`, or
> `driver.js`**, and must consume `PathStore` ONLY through its public read
> API — never `_groups`/`_build()`/`_peerSourced`/any other `_`-prefixed
> field. Its only import is `ids.js`, for `pathId`.

Same reason as C4's: a real project-wide driver run still emits **zero**
hops today (no source registry — Sub-projects D/E), so a query module that
could only be exercised through the driver would be untestable by
construction. The PoC pins the private-field half of this by string-matching
the prototype's own source for `store._`.

**One entry point, plus two small helpers:**

```js
reconstructPaths(store, startNodeId, opts = {})  // -> ReconstructionResult
sinkCandidates(store)                            // -> node[]  (§15.9)
isIncompleteAnswer(result)                       // -> boolean (AC-10)
```

`startNodeId`, deliberately **not** named `sinkNodeId`. There is no sink
registry, so calling the parameter a sink would import vocabulary the
codebase does not have and would read as a promise this increment cannot
keep. Once Sub-project D lands, the caller supplies a registered sink node
here and nothing about the signature changes.

### 15.2 Q3 — what a path IS: nodes AND edges, with the grading material inline

FR-306 requires that a path's output carry enough to grade each hop
(implicit/widened vs. explicit). A bare node-id sequence cannot: every
grading signal C4 records — `widenReasons`, `lossReasons`,
`ambiguousCorrelation`, `annotations[]`, `crossScope`, `line`, and the four
`inKind`/`inSubKind`/`outKind`/`outSubKind` fields — lives on the **edge**,
not on either endpoint. And the node sequence is not even a unique key
(§15.6). So:

```js
Path = {
  id,                 // `ppath:<12 hex>` — see §15.6
  nodeIds: [...],     // SOURCE-FIRST; length = hopCount + 1
  edgeIds: [...],     // SOURCE-FIRST; edgeIds[i] joins nodeIds[i] -> nodeIds[i+1]
  hops:    [...],     // one per edge, denormalized (below)
  hopCount,
  dataElementId,      // singular — see the note below
  sourceNodeId, sinkNodeId,
  terminal: { nodeId, reason, kind },   // reason ∈ §15.4's terminal vocabulary
  complete,                             // === (terminal.reason === 'origin')
  crossScopeCount, widenedHopCount, lossHopCount, ambiguousHopCount,
  analysisTruncated,                    // §14.8's markTruncated, reaching a consumer at last
  shape,                                // §15.7's diversity signature
}
```

**Source-first, even though the walk runs sink-first.** A human reads a
flow source → sink; the walk is an implementation detail. The PoC asserts
the exact node sequence §6 predicts, in that order, and asserts
`hops[i].fromNodeId === nodeIds[i] && hops[i].toNodeId === nodeIds[i+1]`
for every hop.

**A hop is a denormalized copy of the edge, not the edge id alone.** Ids
alone would be smaller and would still round-trip through `store.getEdge`
(the PoC checks that every `edgeIds[i]` does), but a path that cannot be
graded without also carrying the store is a poor hand-off to C6, to
Sub-project E's graph builder, and to Milestone 3's API. FR-303's
compactness constraint governs the **store**, not an on-demand query
result — §18.4's own wording is "store a provenance DAG, not a list of
every expanded path", and the cap plus the budgets are what keep the
materialized list bounded.

**A path never changes data element, and this needs no filtering.** Every
edge `path-store.js` builds joins two nodes whose descriptors both take
`dataElementId` from the same hop (§14.3), so a connected walk is
field-precise by construction — FR-301's distinctness carried into
FR-303's structure for free. Pinned directly (`C5/1b`: every edge in a real
two-identity store has `from.dataElementId === e.dataElementId ===
to.dataElementId`). A future change that broke this would silently let a
reconstruction wander between data elements, so it is asserted rather than
assumed.

### 15.3 Q4 — the backward walk, and how it terminates on a real cycle

`edgesTo(nodeId)` is the traversal primitive. The walk is an **iterative
DFS over an explicit stack — never recursion**, matching this package's own
established discipline (`path-store.js` has no recursion at all; C5 has a
graph walk and still has none).

**Termination discipline, in order of what actually does the work:**

1. **A per-path visited set** — the set of nodes already on the current
   partial path. An in-edge whose source is already on the path is
   *clipped* and counted (`cyclesClipped`). This is what makes the walk
   terminate on a cyclic DAG regardless of budget: every enumerated path is
   a **simple** path, and a finite graph has finitely many. Measured on
   `C4/4`'s real 8-node/11-edge mutual-recursion cycle (§15.11's last row):
   the walk finishes having used **35 expansions** summed across all four
   sink candidates, with **7 clips**. `C5/3` re-runs it with every budget
   raised to 10^6 and asserts the expansion count is unchanged and far
   below the ceiling — the visited set, not a budget, is what stopped it.
   > **A GLOBAL visited set would be wrong, not merely conservative.** It
   > would make every node reachable on at most one path, which
   > deletes exactly the alternate paths FR-305 exists to show.
2. **`maxExpansions`** (default 10000) — total in-edges examined. This is
   the hard, shape-independent termination guarantee, and the only one that
   bounds *work* rather than *output*. It is the budget the brief's "a cap
   on total paths explored, not just total nodes visited" asks for.
3. **`maxDepth`** (default 64) — hops on a single path.
   > **Corrected by fix round 1 (finding 5): this is the SECOND most
   > load-bearing knob, not the most droppable one.** A DFS frame carries a
   > copy of the path so far, so extending a k-hop path costs O(k) and one
   > path of depth D costs **O(D²)** — a cost `maxExpansions` cannot see,
   > because it counts edges examined, not elements copied. Measured
   > (`C5/3d`) on a hand-built straight 3000-hop chain: the whole walk is
   > 3000 expansions — 30% of the default expansion budget (10000, corrected
   > from an earlier "0.03%" here that was wrong by 1000x), comfortably
   > under that budget so it would never fire — yet it takes ~150 ms unbounded against
   > ~0 ms at `maxDepth: 8`. It is also the **only** budget whose limit
   > produces an EMITTED, marked partial rather than an abandoned branch
   > (§15.4), proven by contrast on the same store.
4. **`maxCandidatePaths`** (default 256) — stop enumerating once this many
   complete-or-partial branches have been collected.
   > **Corrected by fix round 1 (finding 5). This knob is a TIGHTENING
   > constant, not an independent safety guarantee, and the earlier text
   > here ("bounds memory") was wrong as written.** The DFS emits at most
   > one candidate per *popped* frame, and a frame is only ever pushed by
   > an expansion, so `enumeratedPathCount ≤ expansionsUsed + 1` holds
   > **unconditionally** — `maxExpansions` already bounds the candidate
   > array on its own. `C5/3e` measures that bound across every start node
   > of three fixtures with this knob raised out of the way. What the knob
   > genuinely buys is a much tighter *default* (256, against the ~10001
   > `maxExpansions` alone would permit) and an early exit for a caller who
   > wants a few paths fast. It is kept for that, stated as that. Dropping
   > it, and its `'candidate-cap'` truncation reason with it, would also
   > have been defensible.

**The depth check runs AFTER the zero-in-edges check, deliberately.** A
node with no predecessors is a genuine origin no matter how deep the walk
is, so a path that reaches one is `complete: true` even at `maxDepth: 1`
(`C5/3b` pins exactly this). Only a branch the *limit* stopped is marked
partial.

**`edgesTo` is sorted by edge id before traversal.** `path-store.js` backs
its indexes with `Set`s and the read API carries no inherent order, so an
unsorted walk would be insertion-order-dependent. Sorting makes the
enumeration order, and therefore every tie-broken output order, stable.

**Defaults are honestly uncalibrated.** They are two-plus orders of
magnitude above what every fixture in the PoC needs (§15.11's largest row
uses 35 expansions), but no fixture here is a real project, and no real
project can be measured until a driver run emits hops (Sub-projects D/E).
They are a starting point to re-measure then, not a tuned result.

### 15.4 §18.4's load-bearing constraint: five distinguishable answers

> *"Never translate 'path budget exhausted' into 'no path.'"*

The result shape makes **five** answers pairwise distinguishable **in the
data**, not by convention or by a caller's discipline:

Every result also carries `startNodeId` and `startNodeKind` (the started-from
node's `kind`, or `null` when it is unknown), so a consumer can tell what it
asked about without a second `getNode` call.

| answer | `truncated` | `unknownStartNode` | `noPathReason` | `truncationReasons` | means |
|---|---|---|---|---|---|
| complete, with paths | `false` | `false` | `null` | `[]` | this really is everything |
| genuinely empty | `false` | `false` | `'no-incoming-edges'` | `[]` | we looked exhaustively; nothing flows in |
| **recording gap** | `false` | `false` | `'incomplete-record'` | `[]` | nothing flows in *in the recorded stream*, and the store itself knows the stream is incomplete here — **not proof of absence** |
| unknown node | `false` | `true` | `null` | `[]` | you asked about a node that is not in this store |
| budget-truncated | `true` | `false` | **`null`** | non-empty | the list is short because a limit stopped us |

`C5/4b` asserts three of these — genuinely-empty, unknown-node and
budget-truncated — are pairwise different as **literal JSON**, not merely
different in spirit; `C5/4c` adds the recording-gap row against a real
cache-warming fixture, and `C5/1` the first. The single most important cell is
the bold `null`: **a truncated result can never acquire a `noPathReason`**,
because `noPathReason` is only ever computed when `truncated === false`.
That is the §18.4 constraint expressed as a code path, not as a comment.

**Truncation reasons** (result-level, sorted, non-empty iff `truncated`):
`'expansion-budget'`, `'candidate-cap'`, `'depth-limit'`,
`'per-terminal-cap'`, `'path-cap'`. `truncated` is *also* set whenever
`droppedPathCount > 0`, so a cap that silently discarded a path is
impossible.

**Terminal reasons** (per path): `'origin'` (the only one that sets
`complete: true`), `'incomplete-record'`, `'cycle'`, `'depth-limit'`.

- A branch that ends because **every** continuation would revisit a node
  reports `'cycle'` — never `'origin'`. Presenting a cycle-clip as an
  origin would be §18.4's failure mode at path granularity. `C5/3c` proves
  a real cyclic fixture produces both labels, so they are demonstrably
  different rather than nominally so.
- A branch that ends at a node in `diagnostics().orphanedPeerSources`
  reports `'incomplete-record'`. This is §14.4's disclosed
  stream-completeness gap reaching a consumer for the first time: C4
  records it, C5 is the first thing that must not lie about it. `C5/4c`
  builds the real cache-warmed-without-a-recorder scenario and proves both
  the zero-path form and the walked-into form.
- **`'expansion-budget'` and `'candidate-cap'` are deliberately NOT
  terminal reasons.** When those trip, in-flight branches are **abandoned,
  not emitted**: a branch cut at an arbitrary global point has a
  meaningless prefix, and emitting it would manufacture a "path" the graph
  does not contain. `'depth-limit'` is different — that branch genuinely
  reached a stated ceiling — so it *is* emitted, marked partial. `C5/3b`
  pins that; `C5/3`'s two starved runs pin both of the others
  (`maxExpansions: 1` and `maxCandidatePaths: 1`), each producing
  `truncated: true` with `noPathReason: null` and no fabricated partial.

**Two further incompleteness signals, both distinct from `truncated`:**

- `analysisTruncated` — true when any node or edge on a returned path
  carries §14.8's `truncated: true` from `markTruncated(scope, context,
  reason)`. §14.8 reserved that channel and named no consumer; **C5 is its
  consumer.** `C5/4d` proves the path is still *returned* (never withheld)
  and still *labelled*, and that the flag stays separate from C5's own
  `truncated` so the two causes never merge.
- `paths.some(p => !p.complete)` — a returned list every one of whose paths
  is partial is a very different answer from a list of complete ones.

`isIncompleteAnswer(result)` is the single derived predicate AC-10's
persistent partial-coverage banner should drive off, so no caller
re-derives it (and no caller forgets a term):

```js
result.truncated || result.unknownStartNode || result.analysisTruncated
  || result.noPathReason === 'incomplete-record'
  || result.paths.some((p) => !p.complete)
```

AC-10's *"a zero-flow filter result must say that the scope is
incomplete"* then falls straight out: an empty `paths` with
`isIncompleteAnswer() === true` is exactly that case, and an empty `paths`
with `isIncompleteAnswer() === false` is honestly a real zero.

### 15.5 Q5 — the alternate-path cap: per (terminal, start) pair, today

§18.4 says *"cap alternate paths per source/sink pair with an explicit
truncation count."* `path-store.js` has no notion of a source or a sink.
The naive reading — cap the paths returned by one call, i.e. per *start
node* — is strictly coarser than "per pair", and the difference is not
academic:

> **MEASURED (`C5/5f`), on the mutual-recursion fixture.** At the first
> sink with two terminals the walk finds **6 paths across 2 distinct
> terminals** — 4 complete, 2 cycle-terminated — and the two terminals are
> separated by a real, deterministic ranking reason rather than by chance:
> every *complete* path terminates at one of them, every
> *cycle-terminated* path at the other, and `complete` is `comparePaths`'
> **first** key. So a naive global top-N cap at **N = 4** fills entirely
> from the complete terminal and covers **1 of 2**; the other terminal is
> reported as having *zero* paths. That is §18.4's own failure
> mode ("budget exhausted" presented as "no path") reached through the cap
> rather than through the walk.
>
> **Re-anchored by fix round 1 (finding 3).** This measurement was
> originally taken on the §9.1 cross-join fixture. The claim was true
> there, but it proved nothing: all four of that fixture's paths share an
> **identical** `comparePaths` content tuple (`C5/5d` now pins the flat
> `[1,1,1,1]` ambiguity vector), so which two survived a naive cap was
> decided purely by `pathId`'s hash. A measurement that holds by hash
> coincidence is exactly the "prose stronger than the proof" failure this
> document exists to prevent.

**Decided: the cap is applied per TERMINAL first, then globally.**

- `maxPathsPerTerminal` (default 8) — candidates are grouped by
  `terminal.nodeId`, ordered within the group (§15.7), and truncated there.
  Because every call already fixes one start node, "(terminal, start)" *is*
  a pair, and the terminal node is the closest thing to a source this
  increment has. This is a genuine per-pair cap today, not a stand-in.
- `maxPaths` (default 32) — a global ceiling on the returned list,
  applied diversity-first (§15.7).
- `result.terminals[]` reports, per terminal:
  `{nodeId, terminalReasons, enumeratedPathCount, keptPathCount,
  returnedPathCount, droppedPathCount, truncated}`. This is also what
  FR-305's *"the UI must show a path count"* needs — a count **per
  source/sink pair**, not one aggregate.

  Two properties of that row are load-bearing, and fix round 1 found both
  of them wrong in the first draft:

  > **`truncated` is `enumeratedPathCount > returnedPathCount` — measured
  > AFTER the global cap, never from the per-terminal cap alone (finding 1,
  > blocking).** The first draft computed it from `maxPathsPerTerminal`
  > only, *before* the diversity round-robin ran, so a terminal that the
  > **global** cap starved to zero returned paths still reported
  > `truncated: false`. Reproduced concretely on the §9.1 cross-join
  > fixture at `{maxPaths: 1, maxPathsPerTerminal: 8}`: the `p.email`
  > terminal showed `enumerated=2 kept=2 returned=0 truncated=false` — a
  > terminal with ZERO returned paths claiming it was not truncated. (That
  > exact row now reads `enumerated=2 kept=2 returned=0 droppedPathCount=2
  > truncated=true`, pinned verbatim by `C5/5e`.) That
  > is §18.4's exact failure mode reproduced at *pair* granularity, inside
  > the very field this section introduces to satisfy it at *call*
  > granularity, and it would have been read by precisely the consumers
  > (C6, Milestone 3's UI) that the field exists for. `droppedPathCount`
  > makes the count explicit per pair the way `result.droppedPathCount`
  > does per call, and `C5/5e` now pins BOTH cases — the per-terminal cap
  > (where the bug structurally cannot fire) and the global cap alone
  > (where it did) — plus the arithmetic that the per-terminal rows sum to
  > the per-call totals, so a consumer can never be told two different
  > stories.
  >
  > **`terminalReasons` is a sorted UNION over the terminal's own paths,
  > never a positional pick (finding 2).** A terminal can genuinely carry
  > MIXED reasons: on the mutual-recursion fixture at `maxDepth: 3`, one
  > sink has a terminal reached by both a `'cycle'` clip and a
  > `'depth-limit'` stop. The first draft's `group[0].terminal.reason`
  > therefore reported whichever the DFS happened to enumerate first —
  > the SAME representative-picking bug class C4's own final whole-branch
  > review found in `path-store.js`'s `origin` branch (`g.annotations[0]`)
  > and fixed the same way. The singular field is **removed**, not
  > supplemented, so no consumer can keep reading the order-dependent one;
  > `C5/5h` asserts its absence as well as the union's correctness.

**What changes when Sub-project D's registry lands.** Very little, and that
is the point. D relabels *which* terminals are registered sources; the
grouping key does not change, and neither does the cap's meaning. The one
thing D adds is the ability to say "this terminal is not a registered
source" — at which point a caller may want to *drop* rather than cap such
paths, which is a filter, not a cap, and belongs in D's own increment. The
per-call framing is therefore already correct: today's cap does not need to
be revisited, only supplemented.

### 15.6 Q6 — deduplication, and what FR-305 forbids hiding

> FR-305: *"Deduplication may collapse identical internal segments but
> cannot hide materially different transformations or controls."*

**Decided: a path's identity is its EDGE id sequence, never its node id
sequence.**

```js
pathId({ startNodeId, edgeIds })   // -> `ppath:<12 hex>`
```

§14.5 left `pathId` deliberately unclaimed for exactly this entity
("`pathId` is deliberately left unused. The thing C5 reconstructs *is* a
path, and it will plausibly want that name"). C5 claims it, with a
`ppath:` prefix joining the `pnode:`/`pedge:` family — a reconstructed path
is not a `DataFlowGraph v1` entity either, so `validate.js` stays untouched
(§15.10 item 4). `startNodeId` is in the discriminator even though it is
strictly **redundant today** — a path always has at least one hop (a start
node with no in-edges yields zero paths, never one empty path, §15.4), so
the last edge id already determines it. It is kept because over-specifying
a content hash costs nothing while under-specifying one is a silent merge —
§14.5's own lesson, applied rather than re-learned — and because it keeps
the id well-defined if a later increment ever admits a zero-hop or
otherwise edge-less path entity.

**Why node-keyed dedup would violate FR-305, proven on a real fixture.**
`C5/5` builds

```js
function f(user) { let a = user.email; let b = a; b = a; return b; }
```

and measures that the node pair `(a, data:email) -> (b, data:email)` is
joined by **two distinct edges** — two assignments at two CFG nodes, which
`provenanceEdgeId` keeps apart precisely because §14.5 put `siteNodeId` in
the discriminator ("two structurally identical hops at two different
program points are two materially different edges (FR-305)"). Reconstruction
returns them as two paths with an **identical node sequence** and different
`line`s. Collapsing on nodes would hide the differing program point — the
one thing a reader would notice, and squarely inside "materially
different". Collapsing on edge ids cannot hide anything, because an edge id
is a content hash over every grading-bearing field (§14.5): two paths with
the same edge sequence are identical hop-for-hop, in kind, sub-kind,
reasons, and site.

**Honest scope, measured not assumed.** Within one `reconstructPaths` call
a DFS with a per-path visited set **cannot** emit the same edge sequence
twice, so dedup is *not* a volume control here — it is an identity
definition (stable across runs and across calls: `C5/5c` proves two
independent analysis runs of the same fixture produce the same `ppath:`
id) and a safety net. `C5/5b` measures the no-duplicates property across
every node of the cyclic fixture rather than asserting it.

**What is NOT collapsed, and why.** §9.1's cross-join phantoms
(`p.email → x.b` where the value came from `q.email`) are genuinely
different node sequences and are **kept**, marked
`ambiguousCorrelation: true` on the offending hop, and de-prioritized by
§15.7's order. That is §9.1's own "detect and mark, do not prevent"
verdict carried to the output — and §14.7 reached the same verdict a second
time on independent evidence. Silently collapsing them would be exactly the
hiding FR-305 forbids; the `ambiguousHopCount` on the path is how a
consumer tells them apart. `C5/5d` pins the *keeping* half on §9.1's own
fixture (4 distinct routes, none collapsed).

> **Where the DE-PRIORITIZING half is actually proven, corrected by fix
> round 1 (finding 4).** Not on §9.1's fixture: its ambiguity vector is a
> flat `[1,1,1,1]`, so every ordering assertion made on it is **vacuous** —
> a guarded "unambiguous before ambiguous" check never executes and a
> monotonicity loop only ever compares `1 >= 1`. `C5/5d` now pins that
> flatness explicitly, so the fixture can never again be mistaken for
> ordering evidence, and proves the ordering on §14.7's leg fixture
> instead, whose ambiguity genuinely varies (`1` vs `2`) — and where the
> more-ambiguous paths are ALSO the boundary-crossing ones, so key 2
> (ambiguity) is shown to *override* key 4 (cross-scope) rather than merely
> agree with it. `C5/2` is the other genuine reorder (§15.7).

### 15.7 Q7 — prioritization: diversity first, and what is honestly deferred

> §18.4: *"Prioritize paths that differ in boundary, transformation, or
> protection state."*

Read carefully, that sentence asks for a **diverse retained set** — show
the user paths that differ from each other — not a ranking by any single
scalar. Both halves are implemented, and they are different mechanisms.

**(a) The cap is diversity-first.** Each path carries a `shape` signature
built ONLY from signals that exist today:

```
<complete|partial> / <boundary|local> / <widened|explicit> / <lossy|intact> / <ambiguous|correlated>
```

from `terminal.reason`, `crossScopeCount`, `widenReasons`, `lossReasons`
and `ambiguousCorrelation` respectively. When `maxPaths` binds, candidates
are bucketed by `(terminal.nodeId, shape)` and taken **round-robin** across
buckets, so no bucket is crowded out. `C5/5g` proves this on a real
fixture (`{ r: helper(a), s: b.email }` — 8 paths from its `⟨return⟩` sink
alone, spanning 2 shapes: `complete/boundary/…` and `complete/local/…`, a
genuine boundary difference). Capped to exactly the bucket count, the
retained set spans **every** shape — which a plain top-N by rank does not
guarantee.

**(b) Within that, a deterministic total order** (`comparePaths`), keys in
order:

1. `complete` first — an incomplete path is not evidence of a full flow.
2. fewer `ambiguousHopCount` — §9.1/§14.7's marker, lower confidence.
3. fewer `lossHopCount`, then fewer `widenedHopCount` — FR-306's
   lower-confidence grades, in the order a reader would rank them.
4. **more** `crossScopeCount` — §18.4's "boundary" dimension, and this
   document's own repeated emphasis on interprocedural stitching being the
   hard, load-bearing case.
5. fewer hops — a shorter explanation, all else equal.
6. `id` lexicographic — stability, never a tie left to insertion order.

`C5/2` proves this order does real work rather than being decorative: at
the plain 2-function resolved call, the **4-hop through-the-callee chain**
(`crossScope 2`, `ambiguous 0`) is ranked **ahead of** the 2-hop bypass
(`crossScope 0`, `ambiguous 1`) — the correct answer wins despite being
twice as long, because length is the last content key rather than the
first.

**Honestly deferred, and named:**

- **Transformation kind** — there is no transformation-kind recognition in
  this codebase at all. **Sub-project D.** Today's nearest signals
  (`widenReasons`/`lossReasons`) describe *analysis imprecision*, not a
  transformation the program performs, and using them as a stand-in would
  be inventing vocabulary that isn't backed by data.
- **Protection state** — `protection.js` defines the verdict *model*; no
  analyzer produces a verdict. **Milestone 2.**

When either lands, it adds a component to `shape` and a key to
`comparePaths`. Neither changes the mechanism, and neither is faked in the
meantime.

### 15.8 What C5 deliberately does not do

- **No source/sink registry.** `sinkCandidates()` (§15.9) is a structural
  stand-in and says so. **Sub-project D.**
- **No FR-306 grade computation.** C5's path output *carries* every
  grading input (`widenReasons`, `lossReasons`, `ambiguousCorrelation`,
  `annotations[]`, `crossScope`, plus the four kind/sub-kind fields) and
  computes only counts. Turning counts into a grade is **C6**. Note
  §14.9's own correction: a consumer must read `annotations[]` too, not
  only the edge's top-level reason arrays — `hops[].annotations` is
  therefore carried verbatim.
- **No `DataFlowGraph v1` output.** Sub-project E.
- **No flow-sensitivity filter.** §9.2 offered C5 a lever (require
  non-decreasing `line`/`nodeId` along a path, or de-prioritize paths that
  violate it) and explicitly left the call to C5 "made against real
  measurements". **Declined for now, with the reason stated:** the
  measurement that would justify it does not exist — no fixture here has a
  real kill-then-reuse shape at scale, and §9.2's own note that the lever
  carries "false-negative risk on loops and back-edges" is not something to
  accept against zero evidence. The material is on the path (`hops[].line`,
  `hops[].siteNodeId`) for whichever increment does measure it.
- **No change to `path-store.js`, and none to `field-identity.js`
  (never).** §15.9.
- **No driver wiring.** A driver run emits zero hops today (§14.1); wiring
  is Sub-project D/E's, and it is a `driver.js` change, not a
  `path-query.js` one.

### 15.9 `path-store.js`'s read API is sufficient — no change, and why

Checked by building the whole prototype against it. The query itself needs
exactly **four** of the ten exported reads:

| read | used for |
|---|---|
| `getNode(id)` | start-node existence (the `unknownStartNode` answer), terminal `kind`, and each node's `truncated` flag |
| `edgesTo(id)` | **the** traversal primitive — the only walk call, and the only read inside the loop |
| `nodes()` | `sinkCandidates()`'s O(N) filter (§15.9's registry stand-in) |
| `diagnostics()` | `orphanedPeerSources` → the `'incomplete-record'` signal, read once per call |

A hop is denormalized straight off the edge objects `edgesTo` already
returns, so **`getEdge` is never called by the query** — it is used only by
the tests, to prove every emitted `edgeIds[i]` round-trips. `nodeIdFor` is
likewise fixtures-only. `edges`, `edgesFrom`, `hasEdge` and `stats` are
unused entirely.

**The one question the brief raised explicitly — is there a cheap way to
find every sink-shaped node without a registry? — is answered YES with no
API addition.** `store.nodes()` already returns every node with its `kind`,
so:

```js
function sinkCandidates(store) {
  return store.nodes().filter((n) =>
    n.kind === 'return' || n.kind === 'escape' || n.kind === 'loss');
}
```

is an O(N) filter over the public API. It belongs in `path-query.js`, not
in `path-store.js`: deciding what counts as a sink is a *query* concern,
and the moment D ships a registry this helper is superseded rather than
extended. It is named `sinkCandidates`, not `sinks`, for the same reason
the entry point's parameter is `startNodeId` — it is a structural filter
with no security opinion, and its doc comment says so.

`escape` and `loss` cannot appear as intermediates: `classifyIn` never
produces them as a source, so nothing in the store ever points *out* of
one. `C5/2b` asserts `edgesFrom(n).length === 0` for every such node in a
real fixture, which is what makes them safe start nodes and impossible
mid-path nodes.

**One observation, deliberately NOT a change request.** `edgesFrom`/
`edgesTo` each call `this._build()` twice per invocation, and `nodes()`/
`edges()` copy the whole map on every call. At `maxExpansions` scale
(10^4 `edgesTo` calls, each an O(1) cached `_build()` plus an O(degree)
map) this is immaterial, and §14.6 already names the real profiling target
(the derived `context` key strings) for Sub-project E. Recorded so a later
reader knows it was looked at and judged, not missed.

### 15.10 What the follow-up implementation task must do

Written the way §10.1/§13.7/§14.10 were, so the next brief needs no
re-derivation.

**`scanner/src/lineage/ids.js`**

| # | Site | Change |
|---|---|---|
| 1 | after `provenanceEdgeId` | add `pathId({ startNodeId, edgeIds }, discriminatorParts = [])` → `ppath:<12 hex>`, via the existing `_hash`/`_canon`. Object argument, matching the `provenanceNodeId`/`provenanceEdgeId` precedent (§14.5) |
| 2 | `test/lineage/ids.test.js` | extend with `pathId` idempotence + non-collision (a changed edge id anywhere in the sequence, and a reordered sequence, must both move the id) |
| 3 | — | **no change to `validate.js`.** `ppath:` is not a `DataFlowGraph v1` entity kind. Confirm by running `npm run test:lineage`; `json-schema-parity.test.js` must stay green untouched |

**`scanner/src/lineage/path-query.js` (new)**

| # | Item | Detail |
|---|---|---|
| 4 | imports | `ids.js` ONLY. Never `engine.js`/`summaries.js`/`driver.js`, and never a `_`-prefixed `PathStore` field. Add the same import-list self-check test `path-store.test.js`'s boundary test uses (§14.10 item 5), plus the `store\._` source scan the PoC's `C5/6` already carries |
| 5 | `DEFAULTS` | `{ maxPaths: 32, maxPathsPerTerminal: 8, maxCandidatePaths: 256, maxExpansions: 10000, maxDepth: 64 }`, all `opts`-overridable. Document them as uncalibrated (§15.3) |
| 6 | `reconstructPaths(store, startNodeId, opts)` | iterative DFS over an explicit stack — **no recursion**. Per-path visited set. `edgesTo` sorted by edge id. Zero-in-edges check BEFORE the depth check (§15.3) |
| 7 | terminal classification | `'origin'` / `'incomplete-record'` (node in `diagnostics().orphanedPeerSources`) / `'cycle'` (every continuation clipped) / `'depth-limit'`. `'expansion-budget'`/`'candidate-cap'` are result-level only — those branches are abandoned, never emitted (§15.4) |
| 8 | the cap | per `terminal.nodeId` first (`maxPathsPerTerminal`), then a diversity-first round-robin over `(terminal.nodeId, shape)` buckets for `maxPaths` (§15.5/§15.7). `result.terminals[]` per §15.5 |
| 9 | the result shape | exactly §15.4's table, plus `startNodeId`/`startNodeKind`/`enumeratedPathCount`/`returnedPathCount`/`droppedPathCount`/`completePathCount`/`cyclesClipped`/`analysisTruncated`/`terminals[]`/`budget.expansionsUsed`. `noPathReason` must be computed ONLY when `truncated === false` — that ordering IS §18.4's constraint, and `terminals[].truncated`/`droppedPathCount` must be computed AFTER the global cap, never from the per-terminal cap alone (§15.5). **`completePathCount` is scoped to the full ENUMERATION (every complete path found before any cap is applied), same as `enumeratedPathCount`/`droppedPathCount` — NOT to `result.paths` after capping.** Final whole-branch review finding 5: it can therefore legitimately exceed `result.paths.length`; a caller wanting "how many complete paths are actually IN this response" must compute `result.paths.filter(p => p.complete).length` itself, never read `completePathCount` for that. |
| 10 | `sinkCandidates(store)` | §15.9's filter, with the "not a registry" doc comment |
| 11 | `isIncompleteAnswer(result)` | §15.4's five-term predicate, exported so AC-10's banner has one owner |
| 11b | `comparePaths(a, b)` | §15.7's total order, **also exported**. It is not merely internal: the tests call it directly to build the naive-global-cap contrast (`C5/5f`), so items 12/13 below are unsatisfiable without it. Added by fix round 1 (finding 6) |

**Tests**

| # | Change |
|---|---|
| 12 | Re-point `path-query-poc.test.js` at the shipped `path-query.js`/`ids.js`, delete its local prototype block, rename it to `path-query.test.js`, and update the `test:lineage` script in `scanner/package.json` in the SAME commit — C3's item 15 / C4's item 11 precedent |
| 13 | Keep every assertion, and especially keep `C5/4b` (the three empty-looking results as literal JSON) and `C5/4c` (`incomplete-record`) — together they are the only guard that stops §18.4's constraint being silently undone |
| 14 | Keep `C5/M`'s measured-numbers table asserted against §15.11's published rows, so a refactor that changes a published number fails a test rather than leaving this document stale (C4's `C4/1b`/`C4/4` precedent). **The trade-off, stated rather than discovered later:** these numbers are a property of the current parser/IR/engine as much as of `path-query.js`, so an unrelated IR or engine change CAN fail this test without anything being wrong with reconstruction. That is the intended cost — the same one §14.11's own pinned counts carry — and the correct response is to re-measure and update §15.11's table in the same commit, never to relax the assertion. The `C5_PRINT_TABLE` env var prints the freshly measured rows to make that re-measurement one command; it must never be allowed to SKIP the assertion (fix round 1, finding 7) |
| 15 | Add a driver-level test only once a hop-emitting driver run is possible (Sub-projects D/E) — until then it would assert on an empty store and be vacuous, same reasoning as §14.10 item 13 |

**Deliberately NOT in the follow-up's scope:** everything in §15.8, plus
any change to `path-store.js`, `engine.js`, `summaries.js` or `driver.js`
(C5 consumes the C4 DAG exactly as shipped — no store change is needed to
answer Q3-Q7).

### 15.11 Measured numbers

Every row produced by running the PoC's own fixtures through the prototype
on 2026-08-30 (`C5/M`), with the three OUTPUT caps (`maxPaths`,
`maxPathsPerTerminal`, `maxCandidatePaths`) raised to 10^6 and the work
budgets left at their defaults, so the numbers describe the graph rather
than a cap. Every row asserts `truncated: false`, which is what proves no
budget bound it. "sinks" is `sinkCandidates()`'s count; the walk is run once
per sink candidate and the remaining columns are summed across them.
"expansions" is in-edges examined; "clipped" is per-path visited-set
rejections (i.e. cycle encounters).

| fixture | sinks | paths | complete | partial | max hops | expansions | clipped |
|---|---|---|---|---|---|---|---|
| `const b = a.email; return b;` | 1 | 1 | 1 | 0 | 2 | 2 | 0 |
| §6's worked example (2 fields, object literal) | 2 | 2 | 2 | 0 | 3 | 6 | 0 |
| 2-function resolved call | 2 | 3 | 3 | 0 | 4 | 7 | 0 |
| §9.1's cross-join (`{a: p.email, b: q.email}`) | 1 | 4 | 4 | 0 | 2 | 6 | 0 |
| §14.7's leg counter-example (`{r: helper(a), s: b.email}`) | 3 | 11 | 11 | 0 | 4 | 18 | 0 |
| mutual recursion (`ping`/`pong`/`top`) — cyclic | 4 | 13 | 9 | 4 | 6 | 35 | 7 |

Three rows to read closely:

- **§6's worked example** reconstructs into exactly the **two field-distinct
  three-hop paths** §14.11 predicted from its 8 nodes / 6 edges —
  `user.email → u.email → o.email → ⟨return⟩` and the same for `.ssn`, with
  zero truncation and zero cross-contamination. §14.11 proved the structure
  was there; this row is the structure actually being read back out. That
  is FR-303's *"ordered paths can be reconstructed"* half, measured.
- **The 2-function resolved call**'s 3 paths split 1 + 2 across its two
  sink candidates: `helper`'s own exit node yields the single path
  `u.email → ⟨return helper⟩`, and `caller`'s exit node yields **two** —
  the real 4-hop through-the-callee chain
  (`a.email → u.email → ⟨return helper⟩ → out → ⟨return caller⟩`) and
  §14.7's disclosed 2-hop **bypass** (`a.email → out → ⟨return caller⟩`),
  which skips the callee. The bypass is kept, marked
  `ambiguousCorrelation`, and ranked **last** (`C5/2`) — the shipped design
  neither deletes it nor lets it outrank the real chain.
- **Mutual recursion** is the only row with partial paths: 4 of its 13 are
  `'cycle'`-terminated. They are labelled, not dropped, and not disguised
  as origins. 35 expansions and 7 clips on an 8-node/11-edge cyclic graph
  is the whole termination story, and no budget was involved in it.

---

## 16. FR-306 edge grading (Sub-project C, increment 6)

Added 2026-08-30 by increment C6's design task. Everything in this section
is **decided**, not proposed, and every behavioural claim and every number
in it was produced by running code in
`scanner/test/lineage/flow-grade-poc.test.js` — a throwaway-named PoC
committed alongside this section, which prototypes `flow-grade.js` LOCALLY
(shipped source under `src/lineage/` is unmodified by this design task,
exactly as C1's, C3's, C4's and C5's own design tasks were). §16.8 is the
follow-up implementation task's file/line checklist.

**FR-306, verbatim:** *"Implicit/control-dependent and unknown-field
widened flows must be visually distinct and lower-confidence. They may not
be displayed as the same evidence grade as an explicit field assignment."*

§15.8 drew the boundary this section crosses: *"No FR-306 grade
computation. C5's path output CARRIES every grading input … and computes
only counts. Turning counts into a grade is C6."* Five questions were open
when this increment was scoped, and none is answerable on paper. All five
are now answered by execution:

- **Q8 — how many tiers, and separated by what?** Five, plus an
  empty-input answer: `explicit` > `widened` > `implicit` (reserved) >
  `severed` > `ambiguous`. §16.2/§16.3.
- **Q9 — does crossing a function boundary lower a hop's grade?** **No.**
  A sound interprocedural stitch grades identically to the same flow
  inlined, and a cross-scope demotion would have *inverted* the ranking
  C5's own `comparePaths` already ships. §16.6.
- **Q10 — does `annotations[]` factor into the grade?** **Yes, and this is
  the single most load-bearing decision in the section.** A genuine
  widening lives ONLY in `annotations[]` on three real, separately-parsed
  fixtures — not just §13.6's context-cap marker. A grader reading only
  the edge's top-level arrays grades those flows `explicit`, which is
  FR-306's own literal prohibition. §16.5.
- **Q11 — is a per-path aggregate needed, or is per-hop grading enough?**
  **Both are needed**, and FR-306's two clauses are why. §16.4.
- **Q12 — reuse `protection.js`'s `EVIDENCE_GRADES`?** **No**, and the
  reason is a correctness hazard rather than taste. §16.2.

### 16.1 `flow-grade.js`: a new module, not new exports on `path-query.js`

**Decided:** a new file, `scanner/src/lineage/flow-grade.js`, with **zero
imports** — one step stricter than `path-query.js`'s own `['./ids.js']`
boundary, and it inherits §14.1/§15.1's rule unchanged (never
`engine.js`/`summaries.js`/`driver.js`).

The obvious alternative — `gradeHop`/`gradePath` exported from
`path-query.js` itself, since they consume nothing it does not already
produce — was evaluated and rejected on three grounds, one of which is
measured:

- **Grading needs neither a path nor the store.** `gradeHop` returns
  **byte-identical** results for a raw `PathStore` **edge** and for the
  `Hop` denormalized from it (`C6/11`, over every edge of the 2-function
  resolved-call fixture) — because a hop *is* a denormalized copy of its
  edge (§15.2). So Sub-project E's graph builder and Milestone 3's API can
  grade an edge without running a DFS, and Milestone 4 can grade a stored
  edge with no reconstruction at all. Putting the function inside the
  reconstruction module would make every such consumer import the walk.
- **`path-query.js`'s shipped boundary test asserts its import list is
  EXACTLY `['./ids.js']`.** A separate grading module could not be
  imported by it without weakening that test, and this increment
  deliberately does not weaken it.
- **C6's implementation then touches zero existing `src/lineage/*.js`
  files** — the same property C4's and C5's design tasks preserved.

**Exports** (the exact signatures the follow-up task must ship):

```js
export const FLOW_EVIDENCE_GRADES;                 // frozen, confidence order
export const IMPLICIT_FLOW_REASONS;                // frozen, ['control-dependence']
export const DEGRADED_LOSS_REASONS;                // frozen, ['context-cap-degraded']
export function flowGradeRank(grade);              // -> 0..5, throws on unrecognized
export function aggregateFlowGrades(grades);       // -> grade, mirrors aggregateVerdicts
export function gradeHop(hop);                     // -> HopGrade  (§16.3)
export function gradePath(path);                   // -> PathGrade (§16.4)
```

`gradeHop` accepts a `path-query.js` `Hop` **or** a `path-store.js` edge;
`gradePath` accepts a `path-query.js` `Path`. Neither mutates its input,
and neither reads a `_`-prefixed field of anything.

### 16.2 Q12 — a NEW vocabulary, and why `EVIDENCE_GRADES` is the wrong one

```js
export const FLOW_EVIDENCE_GRADES = Object.freeze([
  'explicit', 'widened', 'implicit', 'severed', 'ambiguous', 'unassessed',
]);   // CONFIDENCE order: index 0 is the most confident
```

**`protection.js`'s `EVIDENCE_GRADES` (`['runtime', 'code_and_config',
'code', 'config', 'declared', 'manual', 'none']`) is deliberately NOT
reused or extended.** It was read in full before this was decided, and the
rejection is on substance, not on convenience:

- **It grades a different axis.** Those values name *where a protection
  verdict's evidence came from* — observed at runtime, read out of code,
  read out of configuration, merely declared. Every flow grade in this
  section comes from **the same** evidence source (static field-identity
  analysis of code); what varies is how *explicit* the recorded data
  movement is. Mapping `widened` onto `declared`, or `explicit` onto
  `code`, would be a category error that silently changes what
  `protection.js` means.
- **Extending it would be a live correctness hazard, not just churn.**
  `EVIDENCE_GRADES` is consumed by `protection.js`'s own
  `isValidProtectionDimension` and, through this package's stated "every
  enum here is a single source of truth" convention, by
  `dataflow-graph.schema.json` and `validate.js`. Adding `widened` to it
  would make a flow grade **validate cleanly as a protection evidence
  grade** on a `DataFlowGraph v1` entity. That is exactly the
  indistinguishable-namespace bug §14.5 rejected `node:`/`edge:` prefixes
  for.
- **A separate vocabulary touches none of those files this increment**,
  which is a factor in its favour rather than an afterthought — see
  §16.10 for what Sub-project E must do when a grade *does* reach a
  `DataFlowGraph v1` entity.

`C6/0` asserts the two enums share **no** value, that the ranks are a
total order, and — the check that actually stops a future edit going
wrong — that the aggregation table (§16.4) is a permutation of the value
list, so no grade can be silently missing from either side.

**What each value means:**

| grade | meaning | produced by |
|---|---|---|
| `explicit` | the engine resolved a real, field-precise data movement exactly | a hop with no widen/loss/implicit reason and `ambiguousCorrelation: false` |
| `widened` | the movement is real but over-approximated — FR-306's "unknown-field widened" | any `widenReason` (`dynamic-property-key`, `unresolved-call`), top-level **or** annotation-carried |
| `implicit` | control-dependent, not a data assignment — FR-306's "implicit/control-dependent" | **RESERVED. Nothing emits it today** (§16.3) |
| `severed` | the trail is honestly recorded as stopping here | any `lossReason` (`unsupported-target`, `context-cap-degraded`), top-level **or** annotation-carried |
| `ambiguous` | the engine cannot confirm this specific pairing happened at all | `ambiguousCorrelation: true` (§9.1/§14.7) |
| `unassessed` | there was nothing to grade | `aggregateFlowGrades([])` only — never a real hop |

**Why `ambiguous` is the lowest tier**, below both `widened` and
`severed`: a widened hop *certainly happened* and is merely imprecise; a
severed hop *certainly happened* and its continuation is unrepresented; an
ambiguous hop **may never have happened at all** — §14.7's own resolved-call
bypass is exactly such an edge, real data flow that is not the route the
program takes. This is also the order C5 already shipped: §15.7's
`comparePaths` keys are `ambiguousHopCount`, then `lossHopCount`, then
`widenedHopCount`, and §15.7's own prose calls the latter two "FR-306's
lower-confidence grades, in the order a reader would rank them". C6 adopts
that order rather than inventing a competing one.

**Why `implicit` sits between `widened` and `severed`:** it is FR-306's
other named category, so it belongs adjacent to `widened`; and it is
weaker evidence than a widened data assignment, because no data movement
was observed at all — only an inference from control.

### 16.3 The per-hop rule

`gradeHop(hop)` returns an **object**, never a bare string — see §16.5 for
why that is structural rather than stylistic:

```js
{
  grade,                  // one of FLOW_EVIDENCE_GRADES, never 'unassessed'
  rank,                   // flowGradeRank(grade); 0 = most confident
  factors,                // sorted, deduped: 'widen:<r>' | 'loss:<r>' |
                          // 'implicit:<r>' | 'ambiguous-correlation' |
                          // 'analysis-truncated' | 'cross-scope'
  widenReasons,           // sorted UNION of top-level + annotations[]
  lossReasons,            // sorted UNION of top-level + annotations[]
  implicitReasons,        // the IMPLICIT_FLOW_REASONS subset, removed from the two above
  annotationOnly,         // the reasons that would have been INVISIBLE to a
                          // top-level-only reader — see §16.5
  ambiguousCorrelation, degraded, truncated, crossScope,
  incomplete,             // grade === 'severed' || degraded || truncated
}
```

**Precedence, worst wins within one hop** (a hop can carry several
signals at once — `C6/2b` measures a real hop with two widen reasons):

1. `ambiguousCorrelation === true` → `ambiguous`
2. any non-implicit `lossReason` → `severed`
3. any `IMPLICIT_FLOW_REASONS` reason → `implicit`
4. any non-implicit `widenReason` → `widened`
5. otherwise → `explicit`

**`implicit` is reserved and currently unreachable, deliberately.**
§10.2's own verdict for `if` is explicit: *"the engine models no implicit
flow today, so there is nothing to emit; do not invent one."* The tier
exists because FR-306 names it first, and it is kept-but-hand-tested on
exactly §14.2's `origin`-node-kind precedent (*"a real, honestly-disclosed
gap, but not a dead branch: it is the exact shape a Sub-project D … will
produce"*). Its trigger is a reason string in the exported
`IMPLICIT_FLOW_REASONS` set (today `['control-dependence']`), which is
also **removed** from `widenReasons`/`lossReasons` so it can never
double-count. `C6/10` proves both halves: no hop of five real fixtures
grades `implicit`, and a hand-built control-dependence hop does.

**`crossScope`, `originated` and `truncated` are never grade inputs.**
`crossScope` is §16.6; `truncated` (§14.8's `markTruncated`) is an
analysis-run fact, not a statement about this hop's explicitness, so it is
a flag and a factor only — `C6/9` marks a clean fixture truncated and
asserts the grade stays `explicit` while `truncated`/`incomplete` flip to
`true`.

### 16.4 Q11 — the per-path aggregate is worst-wins, and per-hop alone is NOT enough

**Decided: both, and FR-306's two clauses are the reason.** The sentence
has two halves and they are different requirements:

- *"must be visually distinct"* — a **per-hop** claim. A UI marks the
  widened hop, not the whole path; if the whole path were graded down
  uniformly, the reader could not see which step is the weak one.
  `gradePath` therefore returns `hopGrades[]` and `worstHopIndex`.
- *"may not be displayed as the same evidence grade as an explicit field
  assignment"* — a claim about **the evidence grade a flow is displayed
  at**, i.e. one scalar per path. With per-hop grading alone there is no
  such scalar, so nothing prevents a UI from displaying a path containing
  a widened hop as an explicit flow.

**The aggregate is the WORST grade among the hops**, mirroring
`protection.js`'s `aggregateVerdicts()` risk-precedence reduction — the
established precedent in this exact package — via a private precedence
table that is the reverse of the confidence order, with `unassessed` last
so it survives only when it is alone:

```js
const _PRECEDENCE = ['ambiguous', 'severed', 'implicit', 'widened', 'explicit', 'unassessed'];
```

`aggregateFlowGrades` copies `aggregateVerdicts`' contract verbatim,
including its refusals: an empty array is `'unassessed'`, and an
**unrecognized grade throws** rather than silently sorting last (`C6/7c`
— a typo, or a `protection.js` value handed in by mistake, must not
quietly rank as safest).

**Every other reduction was executed, not argued** (`C6/7`, on
`const a = user.email; const b = mystery(a); return b;` — hop grades
`['explicit', 'widened', 'explicit']`): first-wins, last-wins, best-wins
and majority-wins all report `explicit` for a path that provably contains
a widened hop. Only worst-wins satisfies FR-306. `C6/7b` additionally
proves the reduction is **order-independent** across all 5×5 tier pairs —
an order-dependent aggregate would be the representative-picking bug class
C4 found in `path-store.js`'s `origin` branch and C5 found in
`terminals[].terminalReasons`, for the third time.

`gradePath` also **recomputes** its counts from `gradeHop` and
deliberately does **not** read the Path's own
`widenedHopCount`/`lossHopCount`/`ambiguousHopCount` — see §16.7 Finding 1.

### 16.5 Q10 — `annotations[]` is folded into the grade AND flagged separately

§14.9's own corrected note warned that a C6 implementer reading only
`widenReasons`/`lossReasons` off the edges would silently drop §13.6's
context-cap-degraded marker. **Measured, the problem is larger than that
warning states**, and it is what forced this decision:

> **`C6/5` — a genuine `widenReason: 'unresolved-call'` lives ONLY in
> `annotations[]`, with the edge's own `widenReasons` EMPTY, on three
> real, separately-parsed fixtures:**
>
> ```js
> function f(user) { sink(mystery(user.email)); }                        // member -> call-arg
> function f(user) { const o = { a: mystery(user.email) }; return o; }   // member -> assign
> function f(user, c) { const o = c ? mystery(user.email) : user.email; return o; }
> ```
>
> In each, the widening is produced by an expression-internal construct
> whose hop §2.2 classifies as an **annotation** (null `fromPath`, null
> `peerScope`), so `path-store.js` never folds its reason into
> `edge.widenReasons` — that array is built from the *edge-forming* halves
> only (`s.hop.widenReason`, `o.hop.widenReason`). The PoC runs the naive
> top-level-only grader against these hops and measures it returning
> **`explicit`** — FR-306's literal prohibition, reached by reading the
> field the requirement's own material appears to live in. This is not
> §13.6's one exotic marker; it is an ordinary shape of ordinary code.

**Decided, and the two halves are not alternatives:**

1. **Fold annotation-carried reasons into the grade.** `widenReasons` and
   `lossReasons` on a `HopGrade` are the sorted UNION of the hop's own
   top-level arrays and every `annotations[].widenReason` / `.lossReason`.
   An annotation's reason is the same *kind of fact* as a top-level one —
   it is on a different field only because §2.2 classified that half as an
   annotation, which is a statement about edge formation, not about
   evidence quality.
2. **AND surface it separately, by cause.** `degraded: true` is raised
   whenever a `DEGRADED_LOSS_REASONS` value is present, the specific
   reason is named in `factors`, and `annotationOnly[]` names exactly
   which inputs a top-level-only reader would have missed. §18.4 requires
   the *cause* be visible, not merely a tier: "context budget exhausted"
   must stay distinguishable from "the target was unrepresentable", and
   both must stay distinguishable from "no flow".

For §13.6's marker specifically (`C6/6`): the degraded `call-arg-bind`
edge has `lossReasons: []` and `widenReasons: []` at top level, the naive
grader calls it `explicit`, and `gradeHop` returns
`grade: 'severed', degraded: true, annotationOnly: ['loss:context-cap-degraded']`.
Grading it `severed` is the reading §13.6 itself asked for — the marker
belongs *on* the real argument→parameter edge, saying the data was bound
into a callee whose downstream is unrepresented.

**Why `gradeHop` returns an object rather than a string.** The brief for
this increment asked that an annotation-only marker never be "silently
invisible to a consumer reading only the grade". The structural answer is
that **there is no way to read only the grade**: the return value is an
object whose `grade` is one field among `factors`, `annotationOnly`,
`degraded`, `truncated` and `incomplete`. A consumer that wants the
scalar must reach through an object that already handed it the
disclosure.

### 16.6 Q9 — crossing a function boundary does NOT lower the grade

**Decided: `crossScope` is a factor, never a demotion.** Three
independent reasons, two of them measured:

- **FR-306 names two lower-confidence categories, and this is neither.**
  Implicit/control-dependent, and unknown-field widened. A function
  boundary is not an imprecision.
- **The stitch is proven sound, not merely plausible.** §14.3's Q1 proof:
  the node id computed from `(peerScope, peerContext, toPath, id)` is
  **byte-identical** to the node id the callee independently created from
  its own hop. There is no over-approximation to grade down.
- **A cross-scope demotion would report code structure, not evidence
  quality.** `C6/4` grades the same flow twice — inlined
  (`const b = user.email; return b;`) and factored into two functions
  (`helper(u){return u.email}` / `caller(a){const out = helper(a); …}`) —
  and measures **the same grade** (`explicit`, rank 0, hop grades
  `['explicit','explicit']`). Under a demotion, well-factored code would
  systematically grade below the identical inlined flow.
- **And it would invert C5's own ranking.** `C6/4b`: at the 2-function
  resolved call, the real through-the-callee chain (`crossScopeCount: 2`)
  grades `explicit` while §14.7's disclosed bypass (`crossScopeCount: 0`)
  grades `ambiguous` — the correct path outranks the artefact. §15.7's
  `comparePaths` already ranks **more** `crossScopeCount` as **better**
  (key 4); a cross-scope demotion would have put C6's grade in direct
  contradiction with C5's shipped order.

The boundary crossing is still disclosed — `crossScope: true` on the
`HopGrade` and `'cross-scope'` in `factors` — so a UI can render it
distinctly without it being a confidence claim.

### 16.7 Findings this increment does NOT fix, named rather than patched

**Finding 1 (Minor, soundness-unaffected) — `path-query.js`'s
`Path.widenedHopCount` / `lossHopCount` / `shape` under-report
annotation-carried reasons.** `materialize()` computes them as
`hops.filter((h) => h.widenReasons.length > 0).length` etc., i.e. from the
edge's top-level arrays only — the exact blind spot §16.5 measures.
`C6/5b` pins it: on `sink(mystery(user.email))` the annotation-carrying
path reports `widenedHopCount: 0` and a `shape` whose third component is
`explicit`, while `gradePath` reports `widenedHopCount: 1` and
`grade: 'widened'`. **Deliberately not fixed here**, for the same reason
§3 gives for routing around the `widenings` ledger's own mislabel rather
than fixing it: changing those counts changes `comparePaths`' ordering,
§15.7's `shape` bucketing for the diversity cap, and §15.11's published
measured table — a C5 change, with its own re-measurement, not a
side effect of C6's design task. C6 routes around it by recomputing from
`gradeHop`. **A follow-up increment should decide whether to close it in
`materialize()`**, at which point §15.11's table must be re-measured in the
same commit.

**Finding 2 (Minor) — a §13.6-degraded binding edge is unreachable from
every structural sink candidate.** `C6/6b` measures it: the degraded
`call-arg-bind` edge's target is an ordinary `path` node (the callee's
parameter) with **zero** outgoing edges, because the callee's body was
never analyzed. It is therefore not a `sinkCandidates()` result
(`return`/`escape`/`loss` only) and not on any path leading to one, so a
sink-rooted reconstruction surfaces **no** path carrying the marker — the
§16.9 table's last row shows the whole degraded fixture yielding only
`explicit`/`ambiguous` path grades. It *is* reachable and correctly graded
when the walk starts at that node directly (proven in the same test).
**Not C6's to fix:** the fix is either a `sinkCandidates()` change (a
*query* concern, §15.9) or Sub-project D's registry deciding that a
degraded dead end is a reportable endpoint. Named here so it is not
rediscovered as "C6's grading dropped the marker" — grading does not drop
it; nothing asks grading about it.

**Finding 3 (Minor, tier-unaffected) — `factors` inherits
`DESIGN_INTRAPROCEDURAL.md`'s round-6 Finding 3 mislabel.** `step()`'s
`assign`/`return` sites stamp a hardcoded `'unresolved-call'` whenever
they forward a bare `widened` flag (§10.1's own 2026-08-30 note), so a
widening actually caused by a dynamic property key can be *named*
`widen:unresolved-call` in a grade's `factors`. The **grade** is
unaffected — both are widenings and both select the `widened` tier — and
`C6/2b` shows the read side does carry both reasons where it knows them.
Closing it needs `resolveExprIdentities` to thread a real reason string
through its return value, which has been out of scope since C2.

### 16.8 What the follow-up implementation task must do

Written the way §10.1/§13.7/§14.10/§15.10 were, so the next brief needs no
re-derivation.

**`scanner/src/lineage/flow-grade.js` (new)**

| # | Item | Detail |
|---|---|---|
| 1 | the whole module | Lift the local prototype block at the top of `test/lineage/flow-grade-poc.test.js` verbatim (it is written to be lifted: no test-only code inside it). **Zero imports** — add the same import-list self-check test `path-store.test.js`/`path-query.test.js` already carry, asserting the specifier list is EXACTLY `[]` |
| 2 | `FLOW_EVIDENCE_GRADES` | §16.2's frozen array, in CONFIDENCE order. Export `IMPLICIT_FLOW_REASONS` and `DEGRADED_LOSS_REASONS` too — a consumer must be able to test membership without re-typing a literal |
| 3 | `_PRECEDENCE` | §16.4's private table. Keep it private, exactly as `protection.js` keeps its own; the parity check in `C6/0` is what stops it drifting from the value list |
| 4 | `flowGradeRank` / `aggregateFlowGrades` | throw on an unrecognized grade, `'unassessed'` for empty — `aggregateVerdicts`' contract verbatim |
| 5 | `gradeHop` | §16.3's precedence and §16.5's UNION. It must accept a raw `PathStore` edge as well as a `Hop`; `C6/11` is the guard |
| 6 | `gradePath` | §16.4's worst-wins, `hopGrades[]`, `worstHopIndex`, and counts **recomputed from `gradeHop`** — never read off the Path (§16.7 Finding 1) |

**No change to any other file.**

| # | File | Change |
|---|---|---|
| 7 | `path-query.js` | **none.** Do not attach a `grade` to `Path` this increment — it would change the shape `C5/4b`'s literal-JSON guard and §15.11's table are pinned against, and it would force `path-query.js` to import a second module in violation of its own boundary test. A consumer calls `gradePath(path)` |
| 8 | `path-store.js`, `engine.js`, `summaries.js`, `driver.js`, `field-identity.js` | **none** (`field-identity.js`: never) |
| 9 | `schema.js` / `dataflow-graph.schema.json` / `validate.js` | **none this increment.** A flow grade is not a `DataFlowGraph v1` entity field yet. Confirm by running `npm run test:lineage` — `json-schema-parity.test.js` must stay green untouched. **Binding on Sub-project E:** the moment a flow grade is written onto a `DataFlowGraph v1` edge, this package's "every enum here is a single source of truth" convention applies and all three files must gain it in the same commit |
| 10 | `protection.js` | **none.** §16.2 |

**Tests**

| # | Change |
|---|---|
| 11 | Re-point `flow-grade-poc.test.js` at the shipped `flow-grade.js`, delete its local prototype block, rename it to `flow-grade.test.js`, and update the `test:lineage` script in `scanner/package.json` in the SAME commit — C3's item 15 / C4's item 11 / C5's item 12 precedent |
| 12 | Keep every assertion, and especially keep **`C6/5`** (the three annotation-only widening fixtures with the naive grader executed alongside) and **`C6/6`** (§13.6's marker) — together they are the only guard that stops §16.5's union being silently narrowed back to the top-level arrays, which would restore the exact FR-306 violation this increment exists to close |
| 13 | Keep `C6/12`'s pinned hop count and §16.9's table asserted, per §15.10 item 14's stated trade-off: an unrelated IR/engine change CAN move these numbers, and the correct response is to re-measure and update §16.9 in the same commit, never to relax the assertion |
| 14 | Add a driver-level test only once a hop-emitting driver run is possible (Sub-projects D/E) — until then it would grade an empty store and be vacuous, same reasoning as §14.10 item 13 / §15.10 item 15 |

### 16.9 Measured numbers

Every row produced by running the PoC's own fixtures on 2026-08-30, with
the reconstruction budgets left at their `DEFAULTS`. "paths" is summed
across every `sinkCandidates()` start node; "hops" is the total hop count
across those paths.

| fixture | paths | hops | hop grades | path grades | annotation-only reasons |
|---|---|---|---|---|---|
| `const b = user.email; return b;` | 1 | 2 | explicit:2 | explicit:1 | — |
| unresolved call `mystery(user.email)` | 1 | 2 | widened:1 explicit:1 | widened:1 | — |
| dynamic-key write `bag[k] = user.email` | 1 | 2 | widened:1 explicit:1 | widened:1 | — |
| dynamic-key read `user[k]` | 1 | 2 | widened:1 explicit:1 | widened:1 | — |
| §9.1 cross-join `{a: p.email, b: q.email}` | 4 | 8 | ambiguous:4 explicit:4 | ambiguous:4 | — |
| 2-function resolved call | 3 | 8 | explicit:7 ambiguous:1 | explicit:2 ambiguous:1 | — |
| bare-call arg `sink(mystery(user.email))` | 2 | 2 | widened:1 explicit:1 | widened:1 explicit:1 | `widen:unresolved-call` |
| object prop `{a: mystery(user.email)}` | 2 | 3 | explicit:2 widened:1 | explicit:1 widened:1 | `widen:unresolved-call` |
| ternary `c ? mystery(user.email) : user.email` | 2 | 3 | explicit:2 widened:1 | explicit:1 widened:1 | `widen:unresolved-call` |
| unsupported target `({a: obj.z} = user)` | 1 | 1 | severed:1 | severed:1 | — |
| mixed clean + widened | 1 | 3 | explicit:2 widened:1 | widened:1 | — |
| §13.6 context-cap degraded (cap 1) | 6 | 25 | explicit:22 ambiguous:3 | explicit:3 ambiguous:3 | — |

Three rows to read closely:

- **The three annotation-only rows** are §16.5's whole argument. Each has
  a hop the naive top-level-only grader calls `explicit` and this design
  calls `widened`, and the `annotationOnly` column names the input that
  made the difference. `bare-call arg` is the sharpest: two `escape`
  sinks, two one-hop paths, and only one of them is widened — so the
  distinction is not an artefact of the fixture having one path.
- **The 2-function resolved call** is §16.6's: 7 of its 8 hops grade
  `explicit` despite three of them crossing a function boundary, and the
  single `ambiguous` hop is §14.7's disclosed bypass, not the stitch.
- **§13.6's degraded fixture** shows **no** `severed` and **no** degraded
  path grade — that is §16.7 Finding 2, measured. The marker is graded
  correctly (`C6/6`); it is simply not reachable from any sink candidate.

`C6/12` additionally sweeps **28 real hops across 10 fixtures** and asserts
the closed-set property FR-306 literally demands, in both directions: a
hop carrying any widen/loss/implicit/ambiguity signal — top-level **or**
annotation-only — is never graded `explicit`, and a hop carrying none is
never graded lower.

### 16.10 What C6 deliberately does not do

- **No transformation-kind or protection component in the grade.**
  §15.7's honest deferral stands: transformation-kind recognition does not
  exist (Sub-project D) and no analyzer produces a protection verdict
  (Milestone 2). When either lands it adds a *separate* dimension
  alongside this one, not a value inside `FLOW_EVIDENCE_GRADES` — a flow's
  explicitness and its protection state are orthogonal, exactly as
  `protection.js` keeps verdict and evidence grade orthogonal.
- **No implicit/control-dependence ANALYSIS.** The `implicit` tier is
  reserved (§16.3). Producing the reason that fills it is an `engine.js`
  change at §10.2's `if` row and is not in Sub-project C's scope.
- **No grade attached to `Path` or to a `DataFlowGraph v1` edge.**
  §16.8 items 7 and 9.
- **No UI or visual grammar.** FR-306's "visually distinct" half is
  satisfied here by making the distinction *available and unmissable* per
  hop; rendering it is Milestone 3's.
- **No change to `path-query.js`'s counts.** §16.7 Finding 1.
- **No change to `field-identity.js`** (never), and no change to any
  existing `src/lineage/*.js` file in the design task itself.
