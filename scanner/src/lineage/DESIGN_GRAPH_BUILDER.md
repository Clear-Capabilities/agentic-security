# DESIGN_GRAPH_BUILDER.md — Sub-project E's binding design record

**Status:** landed as Sub-project E, increment **E1** (design spike). Binding
on E2, E3, E4 and E5, the same way `DESIGN_INTRAPROCEDURAL.md` binds
Sub-projects A/B, `DESIGN_PATH_PROVENANCE.md` binds C, and
`DESIGN_REGISTRIES.md` binds D.

Every number in this document was produced by running real code against the
live tree in the increment that wrote it — never quoted from an upstream
scoping document. The proofs live in `test/lineage/graph-builder-poc.test.js`
(deliberately throwaway; see §9.1) and `test/lineage/driver.test.js`'s three
`E1/driver-*` tests. Where this document and that PoC disagree, the PoC is
right and this document is stale — fix it here, do not fork it.

---

## 1. What this sub-project actually is

A-D built machinery. **Nothing calls it.** `grep -rn "lineage/" src bin` from
`scanner/`, excluding `src/lineage/` itself, returns exactly one hit and it is
a comment. Every one of the fifteen shipped modules is reachable only from
`test/lineage/*`.

Sub-project E is the first increment family whose deliverable is an
**artifact** rather than a capability: a `DataFlowGraph v1` document, produced
from a real repository, that `validateGraph()` accepts and that a human can
read without being lied to.

Two mechanisms had to be settled before any of E2-E5 could be written, and
both are settled here:

1. **Seeding** (§3) — how a real call site becomes a field-identity entry
   state. Today the shipped driver hardcodes `emptyState()` and produces
   **exactly zero hops** on real code. Measured, twice, in `E1/1`.
2. **Projection** (§6) — how a provenance DAG that is *variable*-granular
   (494 pnodes for a 33-file project) becomes a `DataFlowGraph v1` document
   that is *system*-granular (14 nodes for a whole synthetic platform).

---

## 2. Ground truth, re-measured in this increment

### 2.1 The shipped driver, unchanged, on real code

| Project | files | functions | **hops** | pnodes / pedges | `sinkCandidates()` |
|---|---|---|---|---|---|
| `test/fixtures/vulnerable-js` | 1 | 8 | **0** | 0 / 0 | 0 |
| `frontend/` | 33 | 441 | **0** | 0 / 0 | 0 |

Reproduced exactly. `E1/1` pins it as a shipped test so the gap cannot close
by accident.

### 2.2 The registry matchers, at real call sites in `vulnerable-js`

- `matchSource` — **9 call-site matches, 3 distinct entries**
  (`js-req-body`, `js-req-params`, `js-req-query`). Reproduced exactly.
- `matchSinkOrSanitizer` (sink-kind hits only) — **12 matches, 6 distinct
  entries**, *when counted once per CFG `call` statement node*. Counting every
  call sub-expression instead gives **13**, because `res.send(eval(x))` and
  the separate CFG node for `eval(x)` are the same call twice. The scoping
  doc's 12 is the per-CFG-node count, and **the per-CFG-node count is the one
  the design uses** (§4.1) — not for agreement's sake, but because a CFG
  `call` statement node is the only shape that produces an `escape`
  provenance node to reconstruct from.

### 2.3 The synthetic-seed comparison, and one honest non-reproduction

`vulnerable-js` reproduces the scoping doc's synthetic-seed table **in every
column**: 7 functions seeded, 21/21 hops offered/accepted, 9 join groups,
16 pnodes / 9 pedges, 9 sink candidates (all `escape`), 9 paths, all complete.

`frontend/` does **not** reproduce (doc: 1253/1048 hops, 369 groups, 494/418,
234 candidates). The IR is provably identical — 33 files, 441 functions, both
runs — so the divergence is entirely in the scoping doc's own unspecified
seeding harness. Six variants were tried (per-parameter vs. one shared
identity × `cache.set` keyed on the seeded state / on `emptyState()` / not at
all); the closest was per-parameter + seeded key at **1305/1133**. This is
recorded rather than chased: the synthetic seed is exactly what §3 replaces,
and the fixture the design is actually proven against reproduces to the digit.

**One variant pair is a real finding, not harness noise:** on `frontend/`,
keying `cache.set` on `emptyState()` (the shipped line) rather than on the
state actually analyzed changes accepted hops from **1133 to 1448** and sink
candidates from **247 to 348** — a 27% swing. §3.4 is why.

---

## 3. Seeding

### 3.1 Where the expressions come from

Walk `fn.cfg.nodes` and, per node, the **same expression roots
`engine.js`'s own `step()` switch reads**: `assign` → `source`, `call` →
`callee` + `args`, `return` → `value`. Then recurse into every
sub-expression.

Deliberately **not** `fn.reads` / `fn.calls`: D5 already measured that a call
used as an assignment RHS never reaches `fn.calls[]` at all. Those
side-channels are incomplete for this purpose and using them would silently
lose sources. `fn.cfg.nodes` is a plain `Object` at runtime, not a `Map`
(also D5's finding — `ir/CLAUDE.md`'s header is wrong about this).

### 3.2 The seed-path rule — seed the FIELD, not the container

`matchSource` matches `req.body`. The thing that has a field identity is
`req.body.card_number`. **Extend the matched expression outward through every
enclosing pure-member access, then take `accessPathOf` of the outermost
node.** Fall back to the matched expression's own path when it is not the
object of a member access (`User.create(req.body)`) — that container-level
seed is the honest answer for that shape.

This is not cosmetic. On `vulnerable-js` it is the difference between six
data elements named `body`/`params`/`query` and six named
`id`/`password`/`name`/`expr`/`body`/`host` — and
`classifyDataElementName('password')` returns `['CREDENTIALS']` while
`classifyDataElementName('body')` returns `[]`. **Classification is
impossible without this rule.** `E1/2` pins both halves.

Seeding at the deeper path is sound: `identitiesAt` aggregates
bidirectionally, so a later read of `req.body` as a whole still sees every
field seeded under it, while a read of an *unmatched* sibling correctly sees
nothing.

### 3.3 The seed record

One record per matched call site:

```
{ file, qid, nodeId, line, entryId, seedPath, canonicalName,
  category, coverageStatus, externality, reason,   // <- reclassifySource(entry)
  dataElementId, dataClasses }                     // <- ids.js + classification.js
```

A matched expression with **no** access path (`accessPathOf` → `null`) is
recorded in an `unseedable[]` list and counted in the coverage ledger — never
dropped. Measured on `vulnerable-js`: zero unseedable.

### 3.4 `dataElementId` minting (E1 item **(b)**)

```
dataElementId(canonicalName, [repository, file, seedPath, category ?? ''])
```

- `canonicalName` is the **last segment of the seed path** (`card_number`),
  which is what `classifyDataElementName` needs.
- PRD §10.4 forbids an identifier based only on the field name. The
  discriminator carries a **system proxy** (`repository` + `file`), the
  **access path**, and the **category**.
- `file` is Milestone 1's only available proxy for §10.4's "service or
  schema". When a real service/module boundary signal exists (Milestone 2's
  system attribution), it belongs in the discriminator *ahead of* `file`, not
  instead of it.
- **Function scope (`qid`) is deliberately NOT in the discriminator.** Two
  handlers in one file reading `req.body.email` are one logical field far more
  often than two; §10.4's rule is about not merging across *services*, and it
  is already satisfied. Over-splitting is not free — it fragments the graph
  without evidence in either direction.

`E1/3` pins all four directions: same name in two files → two ids; two fields
in one file → two ids; the same field read twice in one file → one id; and
`dataElementId(name, [])` never equals the real id.

### 3.5 Where seeding lives (E1 item **(a)**) — `driver.js` gets an additive hook

**Decision: `opts.seedEntryState(fn) -> state | falsy`, on
`runFieldIdentityAnalysis`. Implemented in this increment.**

The alternative — a wrapper that calls `driver.js`'s lower-level pieces —
was rejected for three measured reasons:

1. The wrapper would have to duplicate the per-function
   `createCallGraphLookup` / `createCallSummaryResolver` construction
   verbatim. That is a fork that will drift. B4 extracted
   `summaryFromAnalysisResult` precisely to avoid a second, drifting copy of
   a smaller piece of logic than this.
2. **The cache-overwrite hazard is inside `driver.js` and a wrapper cannot
   fix it** — it would have to reimplement the loop anyway, i.e. become the
   fork in point 1.
3. `opts.recordHop` already established exactly this additive-hook contract
   for exactly this file.

**Backward compatibility is proven, not asserted.** With the hook omitted,
`entryState` *is* `emptyState()`, so both the `analyzeFunctionFieldIdentity`
call and the `cache.set` below it are byte-identical to the pre-hook line.
`E1/driver-1` pins the results and the cache keys against a **hardcoded
golden literal captured from the pre-hook `driver.js`** — never against the
shipped implementation, which is C3 §13.2a's vacuous-test trap.

### 3.6 The cache-overwrite hazard, and the half nobody had named

`driver.js`'s own comment disclosed that `cache.set(fn.qid, emptyState(), …)`
can overwrite a lazily-computed entry with a *different* value, and that this
"becomes load-bearing the moment entry states carry real identities."

It named the wrong half. The worse half is the **KEY**. Writing a summary
under `emptyState()` claims "this is what `fn` does when nothing flows in."
Once a seed puts real identities into `fn`'s entry state that claim is
**false**, and a later call site resolving `fn` with clean arguments builds an
empty callee entry state, hits that key, and is handed return facts that exist
only because the driver seeded them.

Measured on a two-function real-parser fixture (`E1/driver-3`):

| keying | `caller`'s local `v` after `const v = helper(o)` |
|---|---|
| `cache.set(qid, emptyState(), …)` — pre-fix | `['data:SEEDED']` — **fabricated** |
| `cache.set(qid, entryState, …)` — shipped | `[]` — correct |

The fix is one identifier, and it is a no-op when no hook is supplied. It also
improves `FieldIdentitySummaryCache.compute`'s cap-degradation fallback
(`this._cache.get(_key(qid, emptyState())) ?? emptyFieldSummary()`), which
previously degraded to a *seeded* summary and now degrades to an honestly
empty one.

`E1/driver-3` proves **both** directions: a local replica of the pre-fix loop
(the mutant) fabricates; the shipped driver does not.

### 3.7 What real seeding measures

| Project | seeds | hops | pnodes / pedges | node kinds reached |
|---|---|---|---|---|
| `vulnerable-js` | 9 | **23** | 15 / 9 | `path`, `escape` |
| `frontend/` | **0** | 0 | 0 / 0 | — |

(Re-measured after the `lineage-engine-receiver-identity-hotfix` — task
review MF-2. The receiver-identity fix adds real intraprocedural hops that
were previously silently dropped, so these numbers moved from the design
task's own original measurement: **19** hops / 14 pnodes / 8 pedges. See
§11 item 1's RESOLVED note.)

Two things follow, and E2/F must not be surprised by either:

- **A real seed's `pnodes` count is narrower than the synthetic
  per-parameter seed's, though `hops` and `pedges` are not** (task review
  MF-3 corrected this claim's original overreach): post-fix, `pnodes` is
  15 vs the synthetic seed's 16 (narrower, by 1); `hops` is 23 vs 21
  (WIDER, since the receiver fix surfaces real hops the synthetic seed's
  own per-parameter approach never modeled); `pedges` is 9 vs 9 (tied). The
  real seed still seeds only what a registry matched — that property
  holds — but "strictly narrower on every dimension" no longer does, and
  this table states the true per-dimension comparison rather than the
  original, now-false blanket claim.
- **`frontend/` produces zero seeds and therefore zero hops** — not a bug. It
  is a browser prototype with no HTTP-request-shaped source in the catalog.
  Every non-zero number the scoping doc measured for `frontend/` came from the
  synthetic seed. **`frontend/` is not a usable Sub-project E benchmark
  target**; F must pick corpora that contain real sources.
- Still **zero `loss`, zero `origin`, zero `return`** node kinds on real code,
  matching §2.1's own finding. A "complete" path terminates at an ordinary
  `path` node; §6.3 is how the projection knows which of those is a source.

---

## 4. Registry-backed sink enumeration

### 4.1 The enumeration unit is a CFG `call` STATEMENT node

`engine.js`'s `step()` emits `write-out`/`call-arg` — the hop that becomes an
`escape` provenance node — **only** for a bare `call` CFG node. So that is the
only shape a sink-rooted `reconstructPaths` can start from.

Every other call expression (an assignment RHS, a return value, a nested
argument) that matches a sink entry is **counted into
`coverage.sinks.nonStatementSitesNotEnumerable`, never silently dropped**.
Measured on `vulnerable-js`: 11 statement sites, 1 non-statement site. This is
a real, named gap for E2/E3 (§11, item 3), not a design choice.

Locating a site's escape nodes needs no scan of the store's internals:
`escape` nodes carry `(scope, siteNodeId)` and are keyed by `(fn.qid,
cfgNodeId)`. Multiple contexts of one function simply yield multiple escapes
at the same key, which is correct.

### 4.2 Both catalogs, and one precision cost

The enumerator consults `matchSinkOrSanitizer` **and** `matchPrivacySink`.
Dropping the privacy catalog would drop `logger.info`, i.e. AC-02's own worked
example.

The cost is real and must be in the ledger: `matchPrivacySink` supports no
receiver constraint at all, so `privacy-js-axios-post` matches
`app.post('/ping', handler)` on the bare callee name. **3 of `vulnerable-js`'s
11 sink sites are that false match**, and they surface as a disconnected
`external`/`external-api` node with zero data elements. That is honest
behaviour (a matched sink nothing reached), but E4 must count it and Sub-project
F must not treat it as recall.

### 4.3 Multi-candidate resolution (E1 item **(d)**) — represent, never pick

Three steps, in order:

1. **Promote via the receiver that actually matched.** Keep the candidates
   whose entry declares `match.receiver` or `match.receiverBase` — the
   matcher already verified those textually. If exactly one survives, use it,
   **coverageStatus unchanged**.
   - `match.receiverTypeIn` deliberately does **not** count: it gates on a
     CHA-resolved class type and is vacuously allowed whenever no
     `receiverType` is supplied, which is always here. D5 already measured
     this exact trap; treating it as specificity would promote on evidence
     that was never checked.
   - This reads a returned candidate's own declared constraint. It does not
     re-run any matching, so the Global Constraint against re-deriving
     `catalog.js`'s work holds.
2. **Unanimous category** among the survivors → use it.
3. **Plurality**, otherwise: one node at the plurality category,
   `coverageStatus: 'partial'`, and a `reason` naming every alternative
   category *and* every candidate entry id — `sink-registry.js`'s own
   `thirdPartySdk` convention, reused rather than a second convention
   invented.

Measured (`E1/9`):

| call site | candidates | resolution |
|---|---|---|
| `res.send(x)` | `js-express-res-send`, `js-koa-send`, `privacy-js-res-send` | **receiver** → `http-response`, `modeled` |
| `ctx.send(x)` | `js-koa-send`, `privacy-js-res-send` — task review MF-3: `js-express-res-send` is filtered out here by `matchSinkOrSanitizer`'s own `_receiverAllowed`, since the receiver isn't `res`; only TWO candidates, not three | **plurality** → `file`, `partial`, alternatives named |
| bare `send(x)` | same two as `ctx.send(x)` | **plurality** → `file`, `partial`, alternatives named |

**Disclosed weakness:** step 3's "plurality" is frequently a 1-1 tie, and the
tie is broken by lexicographic category order. That is deterministic but
arbitrary. It is mitigated, not solved, by the mandatory demotion to `partial`
and by naming every alternative in the reason — a reader is never shown a
confident wrong answer. A real fix needs per-call-site type information the
lineage package does not have.

---

## 5. §16.7 Finding 2's enumerator (E1 item **(e)**) — RESOLVED, `diagnostics()`-union

`DESIGN_PATH_PROVENANCE.md` §16.7 offers two mechanisms. **E uses the union
mechanism**, and the question it left open — "is this genuinely computable
from `path-store.js`'s public read API alone?" — is answered **yes**,
measured, not argued:

```js
store.nodes()
  .filter((n) => store.edgesFrom(n.id).length === 0)
  .filter((n) => store.edgesTo(n.id).length > 0)
  .filter((n) => store.edgesTo(n.id).some((e) =>
    e.lossReasons.some((r) => DEGRADED_LOSS_REASONS.includes(r))
    || e.annotations.some((a) => DEGRADED_LOSS_REASONS.includes(a.lossReason))))
```

Three public methods, one exported constant from `flow-grade.js`. **No change
to `path-store.js`, and no sixth node kind** (which would have moved every
`pnode:`/`pedge:`/`ppath:` id in the tree).

The `annotations[]` half of the check is not optional: §16.5 measured that a
genuine degradation reason can live *only* there, with the edge's own
`lossReasons` empty.

Proven live in `E1/10` on real parsed code, in both directions: at
`maxContextsPerFn: 16` there is no degradation and the enumerator finds
**zero** terminals (it does not over-fire); at `maxContextsPerFn: 2` a real
`context-cap-degraded` hop appears and the enumerator finds **exactly one**
`path` node with zero out-edges — a node `sinkCandidates()` cannot return,
because its kind is not `return`/`escape`/`loss`. That is §16.7 Finding 2
exactly, closed.

The node minted for it uses **the vocabulary already fixed by
`DESIGN_REGISTRIES.md`'s closing section**, re-derived nowhere:
`kind: 'unresolved'`, `coverageStatus: 'partial'`, `externality: 'unknown'`,
with a `reason` naming the context-cap degradation.

**Keep it structurally distinct from FR-203's `unresolved`.** FR-203 (E4's
other closure) is `reclassifySink(entry, {destinationUnresolved,
blockingExpression})`: classification *succeeded*, only the destination is
dynamic, so `coverageStatus` carries over **unchanged**. §16.7's is
`partial` **unconditionally**, because the analysis itself is incomplete.
`sink-registry.js`'s header warns about conflating them at length; do not.

---

## 6. The projection (E1 item **(c)**)

### 6.1 The rule, in one sentence

**A `DataFlowGraph v1` node is a REGISTRY DECISION. An edge and a flow are a
PATH.**

Node identity is
`nodeId(kind, [repository, subtypeKey, coverageStatus, externality, destination])`
where `subtypeKey` is the registry `category`, or — for a null-category
decision — `unsupported-sink:<CWE>` / `unsupported-source:<entryId>` so
`js-exec` (CWE-78) and `js-eval` (CWE-95) stay two nodes rather than
collapsing into one anonymous `process`.

`destination` is in the discriminator and is **always `''` in Milestone 1**.
It is there so that when FR-202 resolves destinations in Milestone 2,
"PostgreSQL prod" and "PostgreSQL analytics" split into two nodes without a
discriminator change — the same way the flagship fixture already distinguishes
Payment API from Analytics API.

### 6.2 Why not per-provenance-node, and why not per-call-site

- **Per-pnode** is what §2.1 already rejected: 494 nodes for one 33-file
  project.
- **Per-call-site** was measured and rejected here: `vulnerable-js` alone
  would produce ~14 nodes — the *same count as the entire flagship platform*,
  for a 42-line file.
- **Per-registry-decision** gives a node count bounded by the **taxonomy**,
  not by the repository: at most `|SOURCE_CATEGORIES| + |SINK_CATEGORIES| +
  (distinct unsupported CWEs) + 1`, i.e. under ~60 for any repository of any
  size.

Measured (`E1/7`), replicating `vulnerable-js` 1× / 10× / 50×:

| copies | functions | **nodes** | edges | flows | dataElements |
|---|---|---|---|---|---|
| 1 | 8 | **9** | 6 | 6 | 6 |
| 10 | 80 | **9** | 60 | 60 | 60 |
| 50 | 400 | **9** | 300 | 300 | 300 |
| 200 | 1600 | **9** | 1200 | 1200 | 1200 |

(the 200× row was measured during the spike at 104 ms; the shipped test stops
at 50× to keep `test:lineage` fast.)

Nodes are invariant; everything field- or path-granular scales linearly. That
invariance **is** the projection rule.

### 6.3 Source attachment

A reconstructed `Path` carries a `dataElementId`, and every data element id in
the store came from exactly one seed. So `seedByDataElementId.get(p.dataElementId)`
is the source join — an O(1) map lookup, no path-shape heuristics. A path
whose `dataElementId` has no seed is skipped and would be a diagnostic (none
observed).

This is what §2.1's "on real code every complete path terminates at an
ordinary `path` node, and nothing in the store says which of those is a
source" needed: the store never needs to know. The seed ledger knows.

### 6.4 Edges and flows, and FR-305

**One graph edge per `(sourceNode, sinkNode, fromPath, toPath, dataElementId,
mappingType, transformationIds)`.** `toPath` is `null` — a call argument is
not an access path, and fabricating one is Decision 5's forbidden bug class.

**One flow per `(sourceNode, sinkNode, dataElementId, Path.shape,
gradePath().grade, ordered transformation ids)`**, with
`alternatePathCount = collapsedPaths - 1`.

That key is FR-305 (*"deduplication may collapse identical internal segments
but cannot hide materially different transformations or controls"*) expressed
as data. Two paths differing in transformation, in evidence grade, or in
`shape` (complete/partial × boundary/local × widened/explicit × lossy/intact ×
ambiguous/correlated) are two flows. Everything else collapses.

**The `context` dimension collapses for free.** `hashState(entryState)` appears
nowhere in the flow key, and data element ids are context-independent by
construction (§3.4), so two entry contexts of one function producing the same
projection are one flow with a higher `alternatePathCount` — never two nodes,
never two flows.

A worked example this actually produces (`E1/14`): one masked-log flow yields
**two** flows, graded `explicit` (the real cross-scope path through
`maskCard`) and `ambiguous` (the caller-side bypass §14.7 marks
`ambiguousCorrelation`). Collapsing them would hide exactly what FR-305/FR-306
forbid hiding. This is the rule working, not a defect.

Since only source and sink nodes exist, a flow's `edgeIds` has length 1. That
is honest: the projection does not invent intermediate system nodes it has not
identified. Cross-scope hops are disclosed in `flow.limitations` via
`gradePath().factors` (`evidence: cross-scope`), never silently dropped.

### 6.5 AC-11, and a flagged unresolved question for E4/H

- **Coarse half, satisfied here:** a matched source or sink is a `nodes[]`
  entry whether or not any flow touches it, carrying its registry
  `coverageStatus` and a non-empty `coverageReason`. Measured on
  `vulnerable-js`: 6 of 11 sink sites connected, and the 5 disconnected ones
  are still nodes (`E1/13`).
- **Fine half, NOT satisfied by `nodes[]`:** because nodes are
  category-granular, a category with 9 connected and 1 disconnected call site
  reads as connected. The disconnected *call site* is visible only in
  `graph.coverage` (§10).

**Flagged for E4 and H, honestly unresolved here:** whether AC-11's acceptance
test (*"the user opens the corresponding inventory … it is visible with a
coverage reason"*) is satisfied by a coverage-ledger row rather than a
`nodes[]` row is a product judgment E1 cannot settle from the code. Two
options were considered and one was **rejected outright**: minting a per-site
node *only when it is disconnected* makes node identity depend on
connectivity, so a node would appear and disappear as the analysis improves,
breaking id stability across runs. Do not do that. If a per-site inventory row
is required, it must be an additional, always-present entity (a ledger row, or
an `evidence` entity), never a conditional node.

### 6.6 `node.subtype: null` — an escalated schema divergence — RESOLVED

**RESOLVED** by the `2026-08-31-lineage-schema-subtype-nullability-hotfix`
Milestone-0 hotfix — this file is committed in the same commit as the fix
itself, so it cannot self-reference its own hash; find the exact commit via
`git log --grep='relax node.subtype schema nullability'` (the commit message
starts `fix(lineage): relax node.subtype schema nullability`).

Decision 1 (inherited, `DESIGN_REGISTRIES.md` §9.0) says a `null` category
becomes a `null`/absent `subtype`. `validate.js` accepted that already — it
never looked at `subtype` at all, which was itself half the bug: it was also
silently accepting genuinely wrong values (e.g. a bare number) with no check.

**`dataflow-graph.schema.json` did not.** Its node definition had `subtype` in
`required` with `"type": "string"`, so a null-category node was invalid
against the JSON-Schema twin while being valid against the runtime validator,
and `json-schema-parity.test.js` could not see the difference (it only ever
compared enum arrays and the top-level envelope's `required` keys, never a
per-entity `$defs.<entity>.required` array).

**The fix, applied outside Sub-project E** (this file's own node contract
description above is unaffected — E still emits `subtype: null` per Decision
1, exactly as originally written): `dataflow-graph.schema.json`'s `$defs.node`
now declares `"subtype": { "type": ["string", "null"] }` and no longer lists
`subtype` in `required` (both `null` and a fully absent field are legal, per
`DESIGN_REGISTRIES.md` §9.0's own "null/absent" phrasing, which never
committed to one representation over the other); `validate.js` gained an
active check — present-and-non-null-and-non-string (a number, object, array,
etc.) is now a validation error, present-and-null or absent are not;
`json-schema-parity.test.js` gained a new block comparing every
`$defs.<entity>.required` array against the fields `validate.js` actually
enforces as required, per entity, closing the exact blind spot that let this
divergence go undetected. The two validators no longer disagree on any of
`vulnerable-js`'s 9 nodes (nor on the flagship fixture's 14, which all already
carried string subtypes and needed no change).

---

## 7. Transformations

### 7.1 Attribution

For each hop on a projected path, resolve the CFG node at
`(hop.scope, hop.siteNodeId)` and build a `recognizeTransformation`
descriptor from its callee (`{type:'member-call', object, method}` for a
member callee, `{type:'call', callee}` for an identifier).

`inputPath`/`outputPath` come from the hop's `fromPath`/`toPath`;
`location` from the CFG node's file and the hop's line; `kind`,
`reversibility`, `algorithm`, `confidence`, `evidence` from D4's recognizer
verbatim.

### 7.2 `null` from the recognizer → `kind: 'unknown'`, and only when attributable

`NEVER_EMITTED_KINDS = ['custom', 'unknown']` forces a choice. **It is
`'unknown'`.** `'custom'` asserts "this is a real transform we simply cannot
name", which is a stronger claim than a `null` supports.

An `unknown` entity is emitted only when **the hop's edge carries
`widenReason: 'unresolved-call'`** (the hop record itself says a call
transformed this value) **and the CFG node carries exactly one call
expression**, so the callee attribution cannot be a guess. Otherwise a
`flow.limitations` string records the site and says why attribution was
refused.

That scoping was added because the naive rule got it wrong on real code:
`res.send(eval(req.body.expr))` has two call expressions at one CFG node, and
the naive rule attributed the widening to `res.send` when `eval` caused it.

Both cases are proven reachable on real parsed code in `E1/11`: `maskCard` →
`kind: 'mask'`, `reversibility: 'irreversible'`, `confidence: 'medium'`;
`reshapeForVendor` → `kind: 'unknown'`, `reversibility: 'unknown'`,
`algorithm: null`, evidence naming the `unresolved-call` hop.

### 7.3 The two §10.6 fields with no honest source

- **`appliesToAllPaths: null`** — never `true`/`false`. That is FR-307's
  all-path proof and nothing in `src/lineage/` does path-feasibility
  reasoning.
- **No control-credit field of any kind — not even `false`.** `false` reads as
  "credit was considered and denied", a claim E has no basis for. Decision 2
  reserves awarding credit for Milestone 2's FR-401-405. `E1/11` sweeps every
  transformation's key set against `/credit|granted|denied|verdict|protected/i`
  — the same structural enforcement D4 already uses on its own decisions.

---

## 8. Flow and edge defaults

- `flow.protectionSummary: 'not_assessed'` on every flow.
- `flow.policyVerdict: 'not_evaluated'` on every flow.
- `edge.protection: emptyProtection()` on every edge — all three dimensions
  `{verdict: 'not_assessed', evidenceGrade: 'none'}`.
- `edge.protocol.destinationResolution: 'unknown'` on every edge (FR-202 is
  Milestone 2; `'dynamic'` would be a claim that resolution was attempted and
  failed).

§10.7's *"the end-to-end summary must be derived from the individual edge
verdicts, never stored as an unsupported independent claim"* is satisfied
**trivially and correctly**: every edge verdict is `not_assessed`, so the only
derivable summary is `not_assessed`. E3 must keep it derived, not hardcoded —
the moment Milestone 2 gives an edge a real verdict, the flow summary must
follow it.

`flow.limitations[]` is where the honesty budget goes, and it is **sourced
from `gradePath().factors`**, never re-derived: widening reasons, loss
reasons, ambiguous correlation, analysis truncation, cross-scope, plus
reconstruction truncation reasons and the multi-candidate ambiguity note.

---

## 9. Checklist for E2-E5

### 9.0 What already shipped in E1

- `src/lineage/driver.js`: `opts.seedEntryState` + the `cache.set` key fix.
  **Nothing else.** No graph-builder.js, no source-seeding.js, no
  lineage/index.js, no `runFullScan` wiring (none of the three exists in the
  tree, so none is backtick-quoted here).
- `test/lineage/driver.test.js`: `E1/driver-1` … `E1/driver-3`, permanent.
- `test/lineage/graph-builder-poc.test.js`: throwaway, §9.1.

### 9.1 The PoC absorption protocol — stated, not implicit

D1 left D2/D3's protocol implicit until §9.1 had to spell it out. Stating it
up front here:

- **E2 absorbs the seeding half** — `E1/1` … `E1/5` — into
  test/lineage/source-seeding.test.js (not backtick-quoted: it does not exist in the tree yet, and this repo's doc-drift checker flags a dangling backtick-quoted path), re-pointed at the shipped
  source-seeding.js. It also inherits `E1/14`, the escalated engine
  limitation (§11 item 1), because that test is about seeding reaching a sink.
- **E3 absorbs the projection half** — `E1/6` … `E1/13` — into
  test/lineage/graph-builder.test.js (same reason — not yet in the tree), re-pointed at the shipped
  graph-builder.js.
- **Whichever of E2/E3 lands SECOND deletes
  `test/lineage/graph-builder-poc.test.js`**, removes it from
  `package.json`'s `test:lineage` script, and removes its row from
  `src/lineage/CLAUDE.md` — after confirming the other's absorption is
  complete. Neither may delete it unilaterally. (D1 §9.1's two-lander rule.)
- `E1/driver-1` … `E1/driver-3` are **permanent** and are absorbed by nobody.
  They guard `driver.js`, which is shipped code.

### 9.2 E2 — src/lineage/source-seeding.js (not yet in the tree)

1. Export `planSeeds(callGraph, {repository})` and
   `seedEntryStateFactory(seeds)` exactly as §3.1-§3.5 specify.
2. Import list must be exactly
   `['../dataflow/catalog.js', '../dataflow/access-paths.js', './source-registry.js', './classification.js', './ids.js', './field-identity.js']`
   — pin it with the self-checking boundary test `path-query.js` established.
3. Ship the `unseedable[]` accounting from day one; an unseedable match that
   is merely absent is the failure mode this whole PRD exists to prevent.
4. Re-measure `path-query.js`'s five uncalibrated `DEFAULTS` against real
   seeded stores — that is E2's own deliverable per the scoping doc, and §2.3
   above shows how easily an unspecified harness makes such numbers
   irreproducible. Record the harness, not just the number.
5. Do **not** pick `frontend/` as a measurement target (§3.7).

### 9.3 E3 — src/lineage/graph-builder.js — SHIPPED, see src/lineage/CLAUDE.md

1. `buildDataFlowGraph(callGraph, opts)` — **corrected by E3, per this
   file's own §9.1 policy** ("where this document and that PoC disagree,
   the PoC is right and this document is stale — fix it here, do not fork
   it"): this item originally stated the signature as
   `buildDataFlowGraph(perFileIR, callGraph, opts)` (three arguments), but
   the PoC's own shipped, tested implementation was always the
   two-argument form above — it reads everything E3 itself needs from
   `callGraph.functions[*].cfg` and never used a separate `perFileIR`
   parameter. E3 shipped the PoC's real two-argument signature rather than
   forking it to match this document's stale prose. **This is scoped to
   E3, not a claim that `perFileIR` is never needed anywhere in this
   sub-project (task review, E3's own follow-up review)**: §10's ledger —
   E4's job — requires `languages: [{language, filesExpected,
   filesAnalyzed}]` and `parseFailures: []`, and a parse failure is
   structurally invisible to a `callGraph`-only builder (a file that fails
   to parse contributes zero functions, so nothing in `callGraph` records
   its absence). E4 will need a per-file input of its own — either
   `opts.perFile` or an equivalent — to populate those two fields
   honestly; it should not assume E3's two-argument precedent means it can
   do the same. Still mirror `dataflow/index.js`'s `runDeepAnalysis`
   **shape** and import nothing from it.
2. Node minting per §6.1; edge/flow keys per §6.4; `subtype` per §6.6, with
   the schema divergence escalated in the PR, not silently emitted.
3. Ship the four assertions `validate.js` cannot make (`E1/8`): every
   `subtype` in the registry vocabulary or null; every `node.dataElementIds`
   entry referentially sound; no two *different* registry decisions collided
   onto one node id; no `pedge:`/`ppath:` id in `flow.edgeIds`.
4. Determinism: sort every entity array by id before emit, and take
   `generatedAt` from `opts` — `emptyGraphEnvelope()` defaults it to
   `new Date().toISOString()`, which breaks `--deterministic`. E5 settles the
   policy (§9.5); E3 must at minimum make it injectable.

### 9.4 E4 — src/lineage/coverage.js (not yet in the tree)

1. Finish §10's ledger sketch.
2. Close **FR-203**: call `reclassifySink(entry, {destinationUnresolved,
   blockingExpression})` at real call sites whose destination expression is
   not statically resolvable. Keep it structurally distinct from §5's case.
3. Ship §5's enumerator union as a real module function.
4. Prove it the way D5 was proven: an empty-but-valid graph must **fail**
   these tests.
5. **Two things E3's own review confirmed E4 needs, named here so neither
   is rediscovered mid-implementation.** (a) FR-203 needs no new export
   from `graph-builder.js` — `enumerateSinkSites` already returns, per
   site, `{file, qid, nodeId, line, calleeExpr, entry, decision,
   ambiguity}`, and the raw `entry` is exactly what `reclassifySink(entry,
   {destinationUnresolved, blockingExpression})` (item 2 above) needs;
   confirmed live, this signature composes cleanly with no change to E3's
   shipped module. (b) `buildDataFlowGraph` currently mints sink nodes
   from `site.decision` internally with no hook to substitute an
   FR-203-adjusted decision, and hardcodes `coverage.languages`/
   `parseFailures` to `[]` with no per-file input to populate them
   honestly (a parse failure is structurally invisible to a
   `callGraph`-only builder — see §9.3 item 1's own note above). E4 will
   need either an `opts` hook on `buildDataFlowGraph` (e.g.
   `opts.resolveSiteDecision`, `opts.perFile`) or a post-processing pass
   over the built graph — decide which explicitly, don't default to
   whichever is easiest to hack in.

### 9.5 E5 — src/lineage/index.js (not yet in the tree) + `runFullScan`

1. Copy the `AGENTIC_SECURITY_PRIVACY_DEEP` block's shape in
   `dataflow/index.js`: opt-in, best-effort, failure **recorded** in
   `scanHealth`, never swallowed, never able to fail a scan.
   **Correction (final whole-branch review, N-6): this item's own wording
   is wrong about which block's failure-handling to copy, and was never
   amended when item 5 below and `src/lineage/index.js`'s own header
   comment already corrected it.** The `AGENTIC_SECURITY_PRIVACY_DEEP`
   block's actual failure-handling is a bare `catch {}` that silently
   swallows — the opposite of "recorded in scanHealth, never swallowed"
   this item asks for in the same sentence. What E5 actually shipped
   copies `_deepEnabled`'s own failure-handling instead (status
   `'complete'`/`'failed'`/`'not_available'`, `failure` folded into
   `scanHealth.lineageAnalysis`, never a bare `catch {}`) — see item 5's
   own "Disclosed, deliberate difference" note for the full reasoning and
   `src/lineage/index.js`'s header for where this is stated at the
   implementation site.
2. Consume `runScan`'s existing `_sharedIR` `{perFile, callGraph}` memo. No
   new IR pass.
3. Settle `generatedAt` under `--deterministic` (§2.7 of the scoping doc) and
   where the artifact is written.
4. `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` becomes genuinely operator-facing
   here for the first time — and per §5 it now has an observable effect on
   output (degraded terminals), so document it.
5. **Disclosed, deliberate difference from `_deepEnabled`: no CI auto-disable.**
   `_deepEnabled`'s own gate additionally checks `inCi`/`ciOverrideAllowed`
   (deep mode defaults OFF in CI unless `AGENTIC_SECURITY_DEEP_IN_CI=1` is
   also set) — the lineage gate has no equivalent. `AGENTIC_SECURITY_LINEAGE_DEEP=1`
   runs unconditionally in CI once an operator sets it, with no separate
   "and also allow it in CI" flag. This is deliberate, not an omission:
   deep mode's CI caution exists because it is sometimes enabled implicitly
   by other default-on machinery, where an operator might not have
   consciously chosen "run this in CI"; lineage is reachable only via this
   one explicit opt-in env var, so setting it already IS the operator's own
   CI decision — there is nothing implicit to guard against.

---

## 10. The coverage ledger, sketched (E1 item **(f)**)

E4 owns the finished contract. This is the shape E1 proved out, grounded in
the flagship fixture's own four keys plus what AC-11, FR-203 and §16.7
require:

```js
graph.coverage = {
  // --- the flagship fixture's own four keys, kept ---
  languages: [{ language, filesExpected, filesAnalyzed }],
  parseFailures: [],
  destinationResolutionStatus: 'not-attempted',   // FR-202 is Milestone 2
  pathBudgetTruncation: <bool>,

  // --- AC-11's fine half ---
  sources: { matched, unseedable, dataElements,
             byCategory: { <category>: { sites, coverageStatus } } },
  sinks:   { callStatementSites, connected, disconnected,
             nonStatementSitesNotEnumerable,        // §4.1's named gap
             byCategory: { <category>: { sites, connected, coverageStatus } } },

  // --- the two "must never disappear" obligations ---
  degradedTerminals: <count>,                      // §16.7 Finding 2
  unresolvedDestinations: <count>,                 // FR-203

  // --- §18.4: budget exhaustion is never "no path" ---
  paths: { enumerated, projected, truncatedQueries },
  budgets: { ...path-query.js DEFAULTS actually used },

  // --- provenance scale, for G's comparison report ---
  provenance: { hops, pnodes, pedges },
};
```

**The one rule to design against explicitly:** a node E *dropped* and a node
with *no path* must be distinguishable in the output, and neither may look
like the other. `byCategory` is what makes "this category was never matched"
distinguishable from "this category matched and connected nothing".

Measured on `vulnerable-js`, the sketch reports: 9 sources matched, 0
unseedable, 6 data elements; 11 sink statement sites, 6 connected, 5
disconnected, 1 non-statement site not enumerable; 0 degraded terminals; 23
hops / 15 pnodes / 9 pedges (re-measured by E3, task review N-2 — the
`lineage-engine-receiver-identity-hotfix` moved this from the pre-hotfix
19/14/8 §3.7 already corrected; this section had not been).

---

## 11. Escalations — things E cannot fix, named here rather than discovered later

1. **`lineage/engine.js` drops RECEIVER-borne identity through a method
   call. RESOLVED**, by a dedicated hotfix task (2026-08-31, "Lineage Engine
   Hotfix: Unresolved-Call Receiver Identity" — see this file's git history
   for the exact commit that landed this change). `case 'call'`'s unresolved
   branch used to union only `expr.args`, never `expr.callee.object`.
   Measured: `pan + 'x'` and `String(pan)` always kept the identity;
   **`pan.slice(0, 4)` lost it**. `dataflow/engine.js` had already solved
   exactly this with `_calleeReceiverTainted`; this package had not
   inherited it, and no lineage design document disclosed the gap until this
   escalation entry.

   **The fix's exact mechanism, BOTH callee shapes (task review MF-1: the
   first cut of this fix ported only half of `_calleeReceiverTainted`'s own
   precedent and was found to still lose the identity for every non-JS
   parser's callee shape — closed in the same hotfix, not left as a second
   escalation):**
   - `parser-js.js`'s structured `{kind:'member', object, prop}` callee:
     `expr.callee.object` (the receiver) is recursively resolved via
     `resolveExprIdentities` and its `flat` identities are unioned into the
     branch's own `flat` result, the same way each argument's `flat`
     identities already were.
   - Every OTHER language parser's flat, dot-joined STRING callee
     (`"pan.slice"`, not an exprDesc — `parser-py.js`/`parser-java.js`/
     `parser-go.js`/`parser-php.js`/`parser-rb.js`/`parser-cs.js`/
     `parser-kt.js`/`parser-cpp.js` all emit this shape): the receiver is
     recovered by slicing the string after its LAST `.` and querying that
     prefix directly via `identitiesAt`, mirroring
     `_calleeReceiverTainted`'s own string branch (`isCoveredBy`) — this
     one needs the actual identity SET, not a boolean.
   - Both match `DESIGN_INTRAPROCEDURAL.md`'s structure-flattening rule for
     `call` (an unresolved call's return is genuinely unknown structure, so
     only `flat` participates, never `byPath`). Proven permanently in
     `test/lineage/engine-receiver-identity.test.js` against both real
     JS/TS (`parser-js.js`) and real Python (`parser-py.js`) parsed IR —
     not reachable from any shipped caller today (this package's only real
     caller, Sub-project E, is wired against `parser-js.js`'s JS/TS output
     only), but `resolveExprIdentities` has no JS-only gate of its own, and
     shipping the fix for one callee shape while leaving the other
     half-inherited would have reproduced this exact bug class one
     language over.

   **The consequence was not theoretical:** it produced **zero flows** for
   `bench/data-lineage/fixtures/js-api-to-log-masked` — the mask-then-log
   fixture that is AC-02's own worked example and one of only three entries in
   the lineage accuracy corpus. `E1/14` (now updated to assert the FIX, not
   the bug) pins both halves: the real fixture now yields 2 flows (the real
   cross-scope path through `maskCard`, graded `widened` because the call
   itself stays unresolved, plus the caller-side bypass FR-305/§14.7 marks
   `ambiguousCorrelation`); the same structure with a receiver-free transform
   already yielded 2 flows (graded `explicit`/`ambiguous`) and still does.

   Sub-project E's own E1 PoC tests that pinned the pre-fix (buggy) numbers —
   `E1/4`, `E1/6`, `E1/13`'s hop counts (19 -> 23 on `vulnerable-js`; node
   count 14 -> 15, edge count 8 -> 9) and `E1/14` itself — were updated as a
   direct, disclosed consequence of this fix, per that PoC file's own
   comments at each changed assertion, not silently left stale.

2. **RESOLVED.** ~~`node.subtype: null` is invalid against
   `dataflow-graph.schema.json` while valid against `validate.js`~~ — §6.6.
   Fixed by the `2026-08-31-lineage-schema-subtype-nullability-hotfix`
   Milestone-0 hotfix: the schema now declares `subtype`'s type as
   `["string", "null"]` and drops it from `required`; `validate.js` gained an
   active check accepting `string | null | absent` and rejecting anything
   else (a bare number, previously silently accepted); the parity test now
   compares `$defs.<entity>.required` arrays, not just enums. Find the exact
   commit via `git log --grep='relax node.subtype schema nullability'`.

3. **A sink in an assignment RHS, a return value, or a nested argument has no
   `escape` provenance node**, so no sink-rooted reconstruction can start
   there — §4.1. Counted in the ledger; closing it needs either a new hop kind
   (a `path-store.js`/`engine.js` change, out of E's scope) or a
   forward-from-source query `path-query.js` does not have.

4. **`matchPrivacySink` has no receiver constraint**, so bare-name over-match
   is structural — §4.2. 3 of 11 sink sites in a 42-line fixture. Out of E's
   scope (`privacy-catalog.js` is on the must-not-modify list); F must not
   count these as recall.

5. **The plurality tie-break is arbitrary** — §4.3. Mitigated by `partial` +
   named alternatives, not solved.

6. **`validate.js` does not enforce every field `dataflow-graph.schema.json`
   declares `required`** — found and escalated by the
   `2026-08-31-lineage-schema-subtype-nullability-hotfix` while closing
   item 2. `test/lineage/json-schema-parity.test.js` now derives, live
   against the flagship fixture, exactly which schema-required fields
   `validate.js` actually enforces, and pins the rest as a documented
   `KNOWN_REQUIRED_GAPS` allowlist so a NEW gap of this shape fails loudly.
   Two of these are **risk-bearing, not merely opaque object bags**:
   `edge.coverageStatus` and `flow.coverageStatus` are the SAME enum
   `node.coverageStatus` is already checked for — AC-11's "a discovered
   sink stays visible with a reason" rests on this field, and `validate.js`
   checks it on a node but not on the edge or flow carrying that node's own
   flow — and `evidence.claim` (the evidence contract's own free-text
   assertion) is never checked at all. The full current set: `node` —
   `system`/`externality`/`lifecycleStages`/`governanceRefs`/`confidence`;
   `fieldMapping` — `fromPath`/`toPath`/`dataElementIds`/
   `transformationIds`; `edge` — `protocol`/`boundaryCrossings`/
   `evidenceRefs`/`coverageStatus`; `dataElement` —
   `aliases`/`sourceLocations`/`classificationEvidence`/`manualOverride`;
   `flow` — `dataElementIds`/`edgeIds`/`evidenceRefs`/`coverageStatus`;
   `evidence` — `claim`. Out of scope for that hotfix (its own Global
   Constraints forbade tightening any validation beyond `subtype`) and out
   of Sub-project E's scope too (`validate.js` is Milestone-0 frozen
   contract code) — named here so a future Milestone-0 hardening pass finds
   it named, not rediscovered. Whoever closes this should prioritize
   `edge.coverageStatus`/`flow.coverageStatus` first, given AC-11's own
   stake in the property.

---

## 12. The reuse boundary (E1 item **(g)**) — confirmed against the source

`src/lineage/` may import **`matchSource`** and **`matchSinkOrSanitizer`**
from `../dataflow/catalog.js`, **`matchPrivacySink`** from
`../dataflow/privacy-catalog.js`, and **`accessPathOf`** from
`../dataflow/access-paths.js`.

Confirmed by reading `catalog.js`'s own module boundary, not by citing the
scoping doc's paraphrase:

- All four are **top-level `export function` declarations**, reachable
  directly from the module. None is reached through `dataflow/engine.js`, and
  none needs it.
- All four are **pure with respect to lineage state**. `catalog.js` holds
  index maps and a provenance-filter memo built at module load from a frozen
  catalog; nothing a caller passes mutates them, and nothing they return is a
  live taint object. `accessPathOf` is a pure recursive function over an
  exprDesc — `field-identity.js` already imports its sibling
  `pathIsCoveredByPrefix` from the same file, which is the in-package
  precedent.
- `DESIGN_REGISTRIES.md` §1's argument holds and is the reason this is the
  right call rather than merely a permitted one: *"they never re-derive what a
  call site matches … duplicating it would fork a matcher the corpus proves
  against one that nothing proves."*

Still forbidden, unchanged (PRD §18.1): `dataflow/engine.js`'s live taint
state, `dataflow/summaries.js`'s `SummaryCache`, and `dataflow/index.js`'s
`runDeepAnalysis` (E **mirrors** its shape; E imports nothing from it).

`E1/12` enforces this mechanically — it reads the PoC's own source, extracts
every module specifier, and asserts the `dataflow/` subset is exactly those
three files, in the shape `path-query.js`'s own `['./ids.js']` boundary test
established.
