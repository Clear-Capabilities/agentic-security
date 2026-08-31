# DESIGN_HANDLING_ANALYZER.md — Sub-project D's binding design record (Milestone 2, increments 1-2)

**Status:** landed as Milestone 2, Sub-project D, increments **1** (FR-403's
taxonomy label, §1-§4) and **2** (FR-307's multi-path control-credit rule,
§5) — two slices of a "Large" sub-project, per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-d1-plan.md`
and
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-d2-plan.md`.
Binding on later Sub-project D increments the same way `DESIGN_
DESTINATION_RESOLVER.md` binds Sub-project A — MUCH shorter than
`DESIGN_GRAPH_BUILDER.md`/`DESIGN_PATH_PROVENANCE.md`/`DESIGN_REGISTRIES.md`
on purpose: this is two slices of a larger sub-project, not the whole thing.

---

## 1. What this increment actually is

FR-403 asks: for a field reaching a sink, what HANDLING was applied to it
along the way — raw, masked, hashed, tokenized, encrypted, etc.? Increment 1
produces that TAXONOMY LABEL for one already-reconstructed path (the caller
picks which path — increment 1 does not iterate multiple paths to one
sink). Increment 1 deliberately did NOT implement FR-307's multi-path
control-credit rule (AC-12: "a transform on one branch cannot make the full
flow green") — that needed comparing MULTIPLE paths to the same sink, named
here at the time as a distinct, larger follow-up (D2) rather than silently
attempted. **D2 is now done** — see §5 below.

No new detection. This increment is entirely a RECLASSIFICATION of
`transform-catalog.js`'s already-shipped `recognizeTransformation` output
(Sub-project D, increment 4) onto a new, narrower vocabulary, applied to a
single reconstructed path's hops (Sub-project C's already-shipped
`path-query.js#reconstructPaths`).

---

## 2. The `handling` verdict shape and the kind → HANDLING_VALUES mapping

`classifyHandling(path, callGraph)` (`handling-analyzer.js`) returns:

```
{
  handling: HandlingValue,               // schema.js's HANDLING_VALUES
  recognizedTransform: TransformDecision | null,  // transform-catalog.js's
                                                     // own recognizeTransformation()
                                                     // return shape, unmodified
  hopIndex: number | null,               // index into path.hops where the
                                           // transform was found, else null
}
```

`schema.js`'s `HANDLING_VALUES` is FR-403's own 8-value taxonomy: `raw`,
`masked`, `redacted`, `hashed`, `tokenized`, `encrypted`, `aggregated`,
`unknown`.

The `transform-catalog.js` `kind` → `HANDLING_VALUES` mapping:

| `kind` | `handling` | Why |
|---|---|---|
| `mask` | `masked` | direct |
| `redact` | `redacted` | direct |
| `hash` | `hashed` | direct |
| `tokenize` | `tokenized` | direct |
| `encrypt` | `encrypted` | direct |
| `decrypt` | `unknown` | a decrypt immediately before a sink is actively the OPPOSITE of protection — never mapped to a protective label |
| `encode` | `unknown` | encoding is reversible obfuscation, not itself a protective handling state |
| `decode` | `unknown` | the direct counterpart of `encode` |
| `truncate` | `unknown` | general-purpose shortening, not necessarily a privacy control (`transform-catalog.js`'s own disclosed low-confidence note) |
| `normalize` | `unknown` | reversibility itself is `unknown` at the catalog level; no protective claim is possible |
| `aggregate` | `unknown` | **disclosed, not a drive-by decision**: `HANDLING_VALUES` carries its own `aggregated` value, but awarding it needs shape-level reasoning about a WHOLE collection (is EVERY record aggregated, or just this one hop's local variable?) that a single-hop, single-path classifier cannot do soundly. Deferred beyond D2, still open (§6) — `classifyHandling` never emits `'aggregated'`, the same way `transform-catalog.js` itself never emits `custom`/`unknown` as a recognized kind: an honest gap, not a guess. |

`custom`/`unknown` never reach this table because `recognizeTransformation`
never emits them (`transform-catalog.js`'s own documented contract) — a
`null` `recognizeTransformation` result (no match at that hop) is simply
skipped, not routed through this table at all.

A path with NO recognized transform on ANY hop, and a literal/direct field
reaching the sink, is `raw` — `classifyHandling`'s own fallback when the
walk exhausts every hop with no match:
`{handling: 'raw', recognizedTransform: null, hopIndex: null}`.

### A load-bearing naming note

`protection.js`'s `PROTECTION_DIMENSIONS` already includes a dimension
literally named `'handling'` — a per-EDGE `{verdict, evidenceGrade}` object
scored from `PROTECTION_VERDICTS` (`protected`/`unprotected`/`unknown`/
`not_applicable`/`not_assessed`). That is a DIFFERENT field
(`edge.protection.handling`), a DIFFERENT vocabulary, and a DIFFERENT
question ("is this dimension protected?" vs. "what taxonomy label applies
to this hop?"). The two share a name because this taxonomy is precisely
what a later Milestone 2 analyzer will read to DECIDE that verdict — see
`transform-catalog.js`'s own header: recognizing that a transform happened
is Sub-project D's job; deciding whether it earns "protected" is a later
FR-401-405 analyzer reading this output. This increment sets only
`flow.handling` (the taxonomy string). It never writes
`edge.protection.handling` and never reads it either.

---

## 3. `classifyHandling(path, callGraph)` — the walk

Walks `path.hops` in the order `path-query.js` already materializes them
(source → sink — see that module's own header: "a human reads a flow
source -> sink, so the arrays are reversed here, once, at the point a
candidate is emitted"). For each hop:

1. Resolve `callGraph.functions.get(hop.scope)?.cfg?.nodes?.[hop.siteNodeId]`
   defensively — `callGraph.functions` is a real `Map` (`ir/callgraph.js`'s
   own shape), never a plain object; a missing/malformed lookup at any step
   is `undefined`, not a throw, and the hop is skipped.
2. When that CFG node resolves, collect every `{kind: 'call'}` expression
   reachable from it — mirroring `graph-builder.js`'s own per-hop
   transformation-extraction loop (§7 of `DESIGN_GRAPH_BUILDER.md`)
   exactly: `exprRoots`/`walkExpr` over the node (`source-seeding.js`,
   already shipped) plus the node's OWN call when the node itself is
   `kind: 'call'` (a bare call statement — `exprRoots` only ever yields a
   call node's `callee`/`args`, never a `{kind:'call'}` shape for the node
   itself, so `graph-builder.js` unshifts that case explicitly and this
   module mirrors it). This is NOT the narrower "only literal `call`-kind
   CFG nodes" reading a first pass at this plan's own wording might
   suggest — the AC-02 fixture this increment must pass
   (`maskCard(cardNumber)` as an assignment RHS) proves why: the hop
   carrying the `call-resolved`/`call-arg-bind` production for that call is
   stamped with the CALLER's `assign`-kind CFG node id (`engine.js`'s
   `stepCtx` wrapper stamps every hop with the CURRENT worklist node,
   whatever its kind), never a literal `call`-kind node. Restricting the
   walk to `node.kind === 'call'` alone would silently never find
   `maskCard` here at all — verified live before settling on this reading.
3. For each collected call, in expression order, build a
   `transform-catalog.js` descriptor and call `recognizeTransformation`.
   The FIRST recognized transform found — across the whole path, hop by
   hop, call by call — wins; nothing later is consulted.

### Callee-descriptor construction: a disclosed third copy, not a cycle

`graph-builder.js` already has a private (unexported) `calleeDescriptor`
helper for this exact shape, and `registry-real-code.test.js` has its own
independent copy for a structural cross-check. This increment needs a
THIRD. Two ways to avoid tripling it were considered and rejected:

- **Export `calleeDescriptor` from `graph-builder.js` and import it here.**
  Rejected: this increment ALSO wires `classifyHandling` INTO
  `graph-builder.js`'s own flow-construction loop (§4 below) — so
  `graph-builder.js` must import `handling-analyzer.js`. Importing
  `calleeDescriptor` the other way would make the two files mutually
  dependent, the exact shape `coverage.js`/`resolve-destination.js` already
  carry and justify carefully (their header comments explain why it's safe
  there). Introducing a SECOND such cycle for a ~10-line helper is not
  worth the added reasoning burden.
- **Move `calleeDescriptor` into `source-seeding.js`**, which already hosts
  the shared `exprRoots`/`walkExpr` primitives both `graph-builder.js` and
  this module import. Rejected as out of this increment's stated scope —
  `source-seeding.js` is not on the plan's file list, and widening its
  reuse boundary is a real, separate decision this increment should not
  make as a side effect.

`handling-analyzer.js` therefore carries its own small, private
`calleeDescriptorOf`, byte-for-byte the same logic as `graph-builder.js`'s
own — a disclosed, judgment-call duplicate, not an oversight.

---

## 4. Wiring — inside `graph-builder.js`'s flow-construction loop

`flow.handling` is set once, at FLOW-MINT time, inside
`buildDataFlowGraph`'s `groupsByFlowKey` loop — the same place
`protection.js`'s `emptyProtection()` is attached to an EDGE object
one loop up. `classifyHandling(p, callGraph)` is called on `group[0].p`
(the flow's own representative reconstructed `Path`, already in scope in
that loop) and its `.handling` string is written to `flow.handling`.

Per this increment's own simplification: EVERY flow gets a real
`flow.handling` value — never `null` — since every sink category
plausibly has SOME handling answer (even `'raw'` for a field that reached
it untransformed). A future increment MAY special-case a sink category
with no natural "handling" concept to `null` instead of a fabricated
`'raw'`; this increment does not attempt that distinction.

`classifyHandling` is computed ONCE, at graph-build time, from the flow's
OWN reconstructed path — consistent with how every other flow field is
computed today (per this plan's own "Explicitly deferred" list: no
re-derivation if a flow's underlying path later changes).

---

## 5. FR-307 multi-path control-credit (increment 2)

**Status:** landed as Milestone 2, Sub-project D, increment **2**, per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-d2-plan.md`.
Computes `transformation.appliesToAllPaths` — the field `graph-builder.js`
had stubbed at `null` on every transformation entity since increment 1 (§4's
"honest absences" note) — and nothing else.

### Scope boundary

This increment does **NOT** compute `flow.protectionSummary` as
`mixed`/`unprotected` (AC-12's own literal end-to-end verdict wording) —
that field stays `'not_assessed'`, exactly as before. Populating it for real
needs a real protection-verdict analyzer (Sub-project B/C's transit/at-rest
analyzers, or Sub-project G's policy verdict), none of which exist yet.
`appliesToAllPaths` is the load-bearing SIGNAL those future analyzers will
consume, not the verdict itself.

### The rule

For every **coarse key** `[src.id, snk.id, de.id].join('|')` — deliberately
coarser than `groupsByFlowKey`'s own key, since it drops `shape`/`grade`/
`sortedT`, so every flow group reaching the same sink for the same field
from the same source, regardless of which transforms were found on it,
collapses into one coarse group:

1. Collect every DISTINCT flow group (post-dedup — `groupsByFlowKey`'s own
   entries, not raw reconstructed paths) sharing that coarse key, and each
   one's `sortedT` (its ordered transformation-id array).
2. For every transformation id `tid` appearing in ANY flow group's
   `sortedT` within that coarse group: `tid` "applies to all paths" for
   THIS coarse group iff `sortedT.includes(tid)` is true for **every** flow
   group in the coarse group — not just the ones where it appears.
3. Write the result onto `transformsById.get(tid).appliesToAllPaths`.

Note that `groupsByFlowKey`'s own key already includes the transformation-id
set (`sortedT.join(',')`), which was Milestone 1's own flow-key design, not
something this increment needed to build — two paths to the same
`(source, sink, dataElement)` that apply DIFFERENT transforms already landed
in DIFFERENT flow groups before this increment, each with its own
`flow.handling`. This increment adds the cross-group AGGREGATION on top:
comparing every flow group in a coarse key against every other one, which
`groupsByFlowKey`'s own per-group key cannot do by itself.

### Conjunction across coarse groups (a disclosed rare-collision case)

A transformation's own id (`ids.transformationId(anchor, ...)`) is keyed on
the SINK node id, not the data-element id — a `transformsById` entry can in
principle (rare, not observed in any shipped fixture) be referenced by flows
for more than one data element, if two different fields happen to produce
byte-identical `(file, line, fromPath, toPath)` at the same sink. If the
SAME `tid` is relevant to more than one coarse group, the final
`appliesToAllPaths` is the AND of every coarse group's own answer for that
`tid` — `true` only if every coarse group where it is relevant judges it
`true`. This is the conservative (never-overclaim) direction, consistent
with FR-307's own "insufficient" framing and with Milestone 2's own
"false-protected" exit-gate concern: a release must never assert credit it
cannot prove. This case is disclosed but not separately fixture-tested — see
§5's own "Explicitly deferred" entry below.

### Why a truncated/incomplete path needs no special-case code

If one path to a sink was cut short by `path-query.js`'s own budget/depth
limits before reaching a transform call site, that path's own flow-group
`sortedT` simply won't contain that transform's id — the hop was never
walked, so `recognizeTransformation` never ran on it. Under the rule above,
that flow group's absence of `tid` in its own `sortedT` already forces
`appliesToAllPaths` to `false` for any `tid` present in a SIBLING flow group
in the same coarse key — the conservative answer falls out of the existing
conjunction, with no additional "is this path incomplete" branch needed.
`test/lineage/graph-builder.test.js`'s truncated-path test proves this is
real, not just argued in prose, by forcing a real `path-query.js` depth
truncation (via `buildDataFlowGraph`'s existing `opts.budget` passthrough)
on one branch while a sibling branch's transform completes.

### Implementation

`graph-builder.js` only — a second pass over data the existing
flow-construction loop already builds (`groupsByFlowKey`/`transformsById`),
not new detection. Runs strictly after the flow-construction loop finishes
populating those maps and before `graph.transformations`/`graph.flows` are
assigned from them. See that file's own inline comment at the aggregation
block for the exact code.

## 6. Explicitly deferred (named, not silently skipped)

- **`aggregate`'s own `'aggregated'` verdict** — needs shape-level
  reasoning about a WHOLE collection, not a single hop. See §2's table.
  Deferred, not scheduled.
- **Any UI/display of the handling taxonomy.**
- **Re-deriving `handling` for a flow whose reconstructed path changes**
  after a later Sub-project A/E change — this increment computes it once,
  at graph-build time, same as every other flow field.
- **Populating `edge.protection.handling`'s own verdict** from this
  taxonomy — a later Milestone 2 analyzer's job, not this increment's
  (§2's naming note).
- **`flow.protectionSummary` computation** (`mixed`/`unprotected`/
  `protected`) — AC-12's own literal end-to-end verdict wording — stays
  `'not_assessed'`. Needs a real protection-verdict analyzer consuming
  `appliesToAllPaths` as one of its inputs (Sub-project B/C/G, none built
  yet); increment 2 produces the SIGNAL, not the verdict.
- **The rare same-call-site-different-data-element `t.id` collision** (see
  §5's "Conjunction across coarse groups") — handled conservatively (AND
  across groups) but not separately tested with a dedicated collision
  fixture, since no real catalog/parser shape produces it today.
