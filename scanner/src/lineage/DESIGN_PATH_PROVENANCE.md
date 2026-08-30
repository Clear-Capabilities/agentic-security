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
edge when they share `(scope, nodeId, dataElementId)`. This is sound because
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
| `assign`, target not a string | write-out | `null` | `null` | **Loss site.** `lossReason: 'unsupported-target'`. Requires resolving `node.source` purely to learn the ids — permitted (Decision 1) but must be guarded on `ctx?.recordHop`. **Not merely discarded computation, a design review flagged this understated:** resolving `node.source` recursively runs the FULL `resolveExprIdentities` tree for that expression, which — when `ctx?.recordHop` is present — genuinely EMITS real in-half (`production`/`selection`) hops for whatever `node.source` reads, exactly as it would for any other resolved expression. These are not spurious: they correctly join with THIS row's `lossReason` write-out to show "this data was read here, then lost, because the target couldn't be represented" — arguably necessary for §18.4's transparency requirement, not incidental. Just don't write it up as if nothing gets emitted before this row's own loss marker. If no identity resolves from `node.source`, none of that fires and there is nothing to lose. |
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

Two levers are named but **not** adopted here, with their trigger conditions,
so a later increment adopts them on evidence rather than on taste: the `slot`
correlation field (§9.1) and hop-order filtering during reconstruction (§9.2).
