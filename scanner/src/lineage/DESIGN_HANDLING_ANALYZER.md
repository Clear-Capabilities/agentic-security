# DESIGN_HANDLING_ANALYZER.md — Sub-project D's binding design record (Milestone 2, increment 1)

**Status:** landed as Milestone 2, Sub-project D, increment **1** — a first
slice of a "Large" sub-project (FR-403's own taxonomy label only), per
`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-d1-plan.md`.
Binding on later Sub-project D increments the same way `DESIGN_
DESTINATION_RESOLVER.md` binds Sub-project A — MUCH shorter than
`DESIGN_GRAPH_BUILDER.md`/`DESIGN_PATH_PROVENANCE.md`/`DESIGN_REGISTRIES.md`
on purpose: this is one slice of a larger sub-project, not the whole thing.

---

## 1. What this increment actually is

FR-403 asks: for a field reaching a sink, what HANDLING was applied to it
along the way — raw, masked, hashed, tokenized, encrypted, etc.? This
increment produces that TAXONOMY LABEL for one already-reconstructed path
(the caller picks which path — this increment does not iterate multiple
paths to one sink). It deliberately does NOT implement FR-307's multi-path
control-credit rule (AC-12: "a transform on one branch cannot make the full
flow green") — that needs comparing MULTIPLE paths to the same sink, a
distinct, larger follow-up (D2), named here and not silently attempted.

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
| `aggregate` | `unknown` | **disclosed, not a drive-by decision**: `HANDLING_VALUES` carries its own `aggregated` value, but awarding it needs shape-level reasoning about a WHOLE collection (is EVERY record aggregated, or just this one hop's local variable?) that a single-hop, single-path classifier cannot do soundly. Deferred to D2/later — `classifyHandling` never emits `'aggregated'` in this increment, the same way `transform-catalog.js` itself never emits `custom`/`unknown` as a recognized kind: an honest gap, not a guess. |

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

## 5. Explicitly deferred (named, not silently skipped)

- **FR-307's multi-path control-credit rule (AC-12)** — "a transform on one
  branch cannot make the full flow green" needs enumerating every path to
  a sink and checking a transform applies on ALL of them, not one. This is
  D2, a distinct and larger follow-up.
- **`aggregate`'s own `'aggregated'` verdict** — needs shape-level
  reasoning about a WHOLE collection, not a single hop. See §2's table.
  D2 or later.
- **Any UI/display of the handling taxonomy.**
- **Re-deriving `handling` for a flow whose reconstructed path changes**
  after a later Sub-project A/E change — this increment computes it once,
  at graph-build time, same as every other flow field.
- **Populating `edge.protection.handling`'s own verdict** from this
  taxonomy — a later Milestone 2 analyzer's job, not this increment's
  (§2's naming note).
