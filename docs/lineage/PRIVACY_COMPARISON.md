# Privacy classification: old privacy-taint engine vs. new lineage engine

Sub-project G, increment G1 of the Data Flow Explorer PRD (Milestone 1
exit-gate closure plan). This is a **static** write-up — the table below is
transcribed from a real run of `bench/privacy-recall/compare-lineage.mjs
--json`, not regenerated automatically. Re-run that script if you need
current numbers; if a re-run disagrees with this table, that is a real
behavior drift worth investigating, not something to silently paper over.

## What was measured

This repo has two independent engines that both, in some sense, decide
whether a piece of data is privacy-sensitive:

- The **old** privacy-taint engine (`scanner/src/dataflow/privacy-taint.js`),
  which annotates findings from a shallow, name-in-text regex pass plus an
  opt-in intraprocedural walker.
- The **new** Data Flow Explorer lineage engine (`scanner/src/lineage/`),
  which builds a `DataFlowGraph v1` document and classifies each
  `dataElement` at the point it is seeded from a matched source expression.

`bench/privacy-recall/fixtures/*/app.js` is a small, already-existing corpus
of 4 real fixtures, originally authored to exercise the OLD engine
(`bench/privacy-recall/measure.mjs`, `bench/privacy-recall/BASELINE.json`).
Running the NEW engine over the same fixtures is a genuine independent
comparison — the corpus was not built to agree with itself.

Measured via `node bench/privacy-recall/compare-lineage.mjs --json`
(2026-08-31):

| fixture | old shallow | old deep | new lineage-classified |
|---|---|---|---|
| `clean-negative` | 0 | 0 | 0 |
| `interprocedural` | 0 | 1 | 0 |
| `renamed-before-sink` | 0 | 1 | 0 |
| `same-name-direct` | 1 | 1 | 0 |

`shallow`/`deep` are finding counts from the old engine's `pii-exposure`
family (`measure.mjs`, reused verbatim). `lineage-classified` is the count of
`graph.dataElements` entries the new engine assigned a non-empty
`dataClasses` array — a **dataElement count, not a finding count**; the two
are different units, shown side by side for comparability, never summed or
otherwise conflated as though they measured the same thing.

The new engine scores 0 across every fixture in this corpus, including
`same-name-direct`, where the old engine's shallow pass fires.

## Root cause: two different, defensible classification bases

The old annotator classifies by the **declared variable name**:
`privacy-taint.js` line 123, `classifyFieldAgainst(d.name, compiled)`, where
`d` comes from `ir.decls` (`universal-ir.js`) — the LHS identifier of a local
declaration. `const socialSecurityNumber = req.body.value;` matches because
`socialSecurityNumber` reads as sensitive by name, regardless of where the
value actually came from.

The new lineage engine classifies by the **source expression's own
field/property name**, at the point a source is seeded:
`classifyDataElementName(canonicalName)` in
`scanner/src/lineage/source-seeding.js`, called on the field the matched
source expression itself names (`req.body.value` → the literal string
`value`), and it never inspects any downstream variable name a value is
later assigned to.

All 4 `bench/privacy-recall/` fixtures share the same source shape —
`req.body.value`, a deliberately generic wire-format field name, assigned to
a descriptive local (`socialSecurityNumber`, or in `clean-negative`, an
undescriptive one). That shape is exactly what exposes the asymmetry: the
old engine catches "a variable that LOOKS sensitive by name"; the new engine
catches "a wire-format field that IS the sensitive one." Each misses what
the other catches. Where the two agree is the opposite fixture shape — a
source expression whose OWN field name is already descriptive, e.g.
`req.body.card_number` (the AC-01 fixture) — which neither engine has reason
to disagree on.

## This is a disclosed scope boundary, not a bug

Both classification bases are legitimate and each has real cases the other
misses. The new lineage engine's scope, as shipped through Milestone 1, is
field-name-at-the-source only — this is documented behavior, not an
oversight this report exists to flag for a fix.

**Changing this is a future-milestone design decision, not made here.**
Whether the lineage engine should ALSO inspect assignment-LHS names (closing
the gap this report measures) is a real design question — it would change
what counts as evidence for a data class, with real precision/recall
trade-offs on both sides — and is explicitly out of scope for this
increment. This report's job is to make the asymmetry visible and measured,
not to resolve it.

## Reproducing

```
node bench/privacy-recall/compare-lineage.mjs          # plain-text table
node bench/privacy-recall/compare-lineage.mjs --json   # machine-readable
```
