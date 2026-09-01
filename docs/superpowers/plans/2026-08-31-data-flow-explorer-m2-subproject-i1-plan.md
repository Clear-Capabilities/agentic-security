# Milestone 2, Sub-project I, increments 1-3: `flow.protectionSummary` + exit-gate closure

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-i-scoping.md`.
That document found ONE real code gap (`flow.protectionSummary` never
computed, violating PRD line 909) and two disclosed-but-unproven
properties (AC-06, AC-08). This plan implements I1 (the fix), I2 (the
two proof fixtures), and I3 (verification + the exit-gate status table)
as one increment, since I1/I2 are both small and I3 depends on both.

## What already exists (confirmed by direct read, this session, HEAD `ece190ed`)

- `graph-builder.js`'s flow-construction loop mints the edge first
  (`edgesById.set(edgeIdStr, {...})`, transit set at mint time via the
  composed `opts.resolveTransitProtection` hook), THEN mutates
  `edge.protection.atRest` in place (the `handlingResult === 'encrypted'
  && snk.kind === 'store'` block), THEN — later in the SAME loop
  iteration — calls `flowsById.set(fId, {...})` with the literal
  `protectionSummary: 'not_assessed',` at line ~826. By the time
  `flowsById.set` runs, `edgesById.get(edgeIdStr)` already carries its
  FINAL transit and atRest verdicts for this iteration — confirmed by
  reading the exact relative line ordering (edge mint → atRest mutation
  → flow mint, no interleaving). **Re-verify this exact ordering against
  the current file before writing code** — this block has been extended
  by five different sub-projects already this session.
- `protection.js`'s `aggregateVerdicts(verdicts)` (confirmed, exported,
  already tested in `protection.test.js`): `verdicts.length === 0`
  returns `'not_assessed'`; otherwise picks the worst by
  `_PRECEDENCE` (unprotected > mixed > unknown > protected >
  not_applicable > not_assessed, matching PRD line 674 exactly); throws
  on an unrecognized verdict string.
- `edge.protection.handling` is never written by any code today (Sub-
  project H's own scoping finding) — every real edge's `handling`
  dimension stays `emptyProtection()`'s default `{verdict:
  'not_assessed', evidenceGrade: 'none'}`. Including it in the
  aggregation is still correct (matching PRD line 909's literal "the
  individual edge verdicts" — an edge has exactly three dimensions) and
  harmless (`not_assessed` never outranks a real verdict from
  `transit`/`atRest` per `aggregateVerdicts`'s own precedence), and
  future-proofs this code for whenever a `handling` producer ships.
- `bench/data-lineage/fixtures/js-api-to-log-disconnected/` — the
  existing AC-11 fixture pattern (a matched sink with no connecting
  flow) to mirror for I2's own AC-08 fixture. Read its `source.js` +
  `expected.json` shape before writing the new one.
- The Milestone 1 exit-gate status table already in
  `scanner/src/lineage/CLAUDE.md` (search "## Milestone 1 exit-gate
  status") — the exact table shape and "what this does NOT mean"
  disclaimer paragraph I3's own Milestone 2 table should mirror.

## Scope for this increment

**I1 — `graph-builder.js`:**
```js
const flowEdge = edgesById.get(edgeIdStr);
const protectionSummary = flowEdge
  ? aggregateVerdicts([
      flowEdge.protection.transit.verdict,
      flowEdge.protection.atRest.verdict,
      flowEdge.protection.handling.verdict,
    ])
  : 'not_assessed';
```
placed immediately before the `flowsById.set(fId, {...})` call, replacing
the `protectionSummary: 'not_assessed',` literal with
`protectionSummary,`. Import `aggregateVerdicts` from `./protection.js`
at the top of the file (check the current import list first — this file
likely already imports something from `protection.js`, e.g.
`emptyProtection`; add to that same import line rather than a new one).
The `flowEdge ? ... : 'not_assessed'` guard mirrors this file's own
established "never assume, defensive fallback" convention (matching the
existing `if (edge) edge.protection.atRest = ...` guard a few lines
above) — `flowEdge` should always be found (same id this flow's own
`edgeIds: [edgeIdStr]` uses, minted earlier in this same call), so the
fallback is precautionary, not expected to fire on real code.

**I2 — two new test fixtures, real end-to-end proofs:**
1. AC-06: a PHI field (a real data-class-recognized name, e.g.
   `diagnosis`) written unencrypted to a real `store`-kind sink (a
   `db.query(...)`-shaped call, matching the shape
   `at-rest-protection.test.js`'s own negative case already uses) →
   `edge.protection.atRest.verdict === 'not_assessed'` AND the new
   `flow.protectionSummary === 'not_assessed'` — never `'protected'`.
   Place in `test/lineage/at-rest-protection.test.js` (the existing
   negative case there may already cover most of this — check before
   duplicating; if it does, extend that SAME test with the new
   `protectionSummary` assertion rather than writing a parallel one) or
   a small addition to the new `protectionSummary`-specific test file
   (see below) — implementer's judgment.
2. AC-08: a real AI-provider sink call (mirror the AC-07 fixture's own
   `anthropic.messages.create(...)` shape) with NO tainted/classified
   field reaching it at all (a hardcoded string argument, or simply no
   call to it from any function that also has a matched source) → the
   AI-provider node is still minted, still visible, carries a
   `coverageReason`, and — the actual AC-08 property — no `flow`/data
   element anywhere in the resulting graph claims a `dataClasses` value
   reaching that node (confirm via `graph.flows.filter(f => f.sink ===
   thatNodeId).length === 0` and, separately, that the node itself
   exists in `graph.nodes`). Mirror `js-api-to-log-disconnected/`'s own
   real-code pattern; a real-code proof in
   `test/lineage/graph-builder.test.js` (or a new small test file if
   that one is getting crowded — implementer's judgment) rather than a
   `bench/data-lineage/` corpus fixture, since this is a structural
   graph-shape proof, not a scored corpus entry.
3. New `test/lineage/protection-summary.test.js` (or fold into an
   existing file if a natural home exists — implementer's judgment,
   name it clearly either way): the core I1 proof — a real fixture
   producing a `protected` transit verdict AND a `protected` atRest
   verdict on the SAME edge → `flow.protectionSummary === 'protected'`;
   a fixture with one dimension `protected` and another
   `not_assessed`/`unprotected` → the correct `aggregateVerdicts`
   precedence result (not `'protected'`); the two-sibling-flow AC-12
   proof named in the scoping doc (one flow to a store with real
   `atRest: protected`, a sibling flow to the SAME store/field with no
   encryption → the protected sibling reads `protectionSummary:
   'protected'`, the other reads `'not_assessed'`, never
   `'protected'`); and a regression check that `validateGraph` still
   passes (`protectionSummary` must stay one of `FLOW_SUMMARY_VALUES` —
   it already is, since `aggregateVerdicts` only ever returns a
   `PROTECTION_VERDICTS` member, all five of which are also
   `FLOW_SUMMARY_VALUES` members plus `'mixed'`, confirmed by comparing
   the two arrays directly before assuming this holds).

**I3 — verification + documentation:**
1. Run `npm run test:lineage`, `npm run bench:protection-verdict:check`,
   and the full gate (`npm test`), fresh, real captured exit codes.
2. Write a Milestone 2 exit-gate status table into
   `scanner/src/lineage/CLAUDE.md`, mirroring the Milestone 1 table's
   own shape (search "## Milestone 1 exit-gate status" for the template
   — a markdown table with `AC | Proof | Where` columns), covering
   AC-03 through AC-09 plus AC-12, each row citing the real proof
   location from the scoping doc's own per-AC verification section
   above (re-verify each citation against the current file/line before
   writing it into a permanent doc — this plan's own citations may have
   drifted by the time this increment lands). Include a "what this does
   NOT mean" paragraph naming C2/C3, F2/F3, H's own `handling`
   dimension, and Sub-project A's remaining increments as still open,
   mirroring the Milestone 1 table's own disclaimer paragraph.
3. Update the "Milestone 2 status note" paragraph (search
   `scanner/src/lineage/CLAUDE.md` for that exact phrase) to record
   Sub-project I's own completion, following the same one-paragraph
   status-note pattern every prior sub-project's own completion used.

## Do NOT touch

`edge.protection.handling`'s own write side (still unimplemented,
Sub-project H's deferred territory — this increment only READS it via
aggregation, never writes it). `appliesToAllPaths` (D2's own, unrelated
field — do not conflate with `protectionSummary`). Any cross-branch
coarse-group-level aggregate (explicitly named out of scope in the
scoping doc — `protectionSummary` stays per-flow). `transit-
protection.js`, the inline atRest block, `classifyHandling` (read-only —
this increment consumes their output). C2/C3, F2/F3. Any language beyond
JS/TS.

## Test plan

The three I2 fixture/test additions above, plus:
1. `npm run test:lineage` full run, green, real count.
2. `npm run bench:protection-verdict:check` (Sub-project H's own gate) —
   confirm it still passes; this increment does not change transit/
   atRest verdict COMPUTATION, only reads it, so no change expected, but
   confirm anyway.
3. `npm test` full gate, real captured exit code.
4. A quick manual sanity check (not necessarily a permanent test) that
   `FLOW_SUMMARY_VALUES` and `PROTECTION_VERDICTS` genuinely overlap the
   way item 3 of I2's third fixture assumes, before writing that
   assertion as a hard equality check.

## Explicitly deferred

A cross-branch/coarse-group-level protection aggregate beyond per-flow
`protectionSummary` (undecided). C2/C3's at-rest evidence sources. F2/F3.
H's own `handling` dimension. Sub-project A's remaining destination-
resolution increments. AC-01, AC-02, AC-10, AC-11, AC-13 onward (not
named in the Milestone 2 exit gate's own wording). Any language beyond
JS/TS.

## IMPORTANT CORRECTION (added after further verification, before implementation)

Direct re-read of `protection.js` found `aggregateVerdicts`'s own
`_PRECEDENCE` table is explicitly documented as built for **cross-branch,
same-dimension** aggregation (PRD §8.4's own wording, quoted verbatim in
the module's comment: *"one branch protected, one branch unprotected"*)
— NOT for combining a single edge's own three DIFFERENT dimensions
(transit/atRest/handling). Applying it naively across dimensions risks
exactly the false-protected bug class Sub-project H's own gate exists to
catch: `aggregateVerdicts(['protected', 'not_assessed', 'not_assessed'])`
returns `'protected'` (rank 3 beats rank 5) — so if one dimension is
genuinely protected while a DIFFERENT, RELEVANT dimension was simply
never evaluated, the aggregate would silently claim full protection,
violating PRD line 121 ("missing evidence is displayed as unknown or not
assessed, never as protected or absent").

**Verified this does NOT happen for any real edge in the codebase
today, and why**: `resolveTransitProtectionForSite` is gated to
`site.decision?.category === 'external-api'` only (`transit-
protection.js` line ~98) — which `sink-registry.js`'s
`CATEGORY_NODE_KIND` maps to `kind: 'external'`, never `kind: 'store'`.
The inline atRest block is gated to `snk.kind === 'store'` only. These
two gates are **mutually exclusive by construction** — a real edge is
never both `kind: 'external'` and `kind: 'store'` simultaneously. And
`edge.protection.handling` is never written by any code at all (Sub-
project H's own finding, unchanged). **So for every real edge today, at
most ONE of the three dimensions can ever be non-default** — the
`aggregateVerdicts` call reduces, in practice, to "whichever single
dimension actually applies to this edge kind, use its own real verdict;
everything else is honestly `not_assessed` and never masks it." The
design is correct for today's code, but this correctness rests on an
**implicit, fragile assumption** that must be disclosed, not silently
relied on forever.

**Required additions to the implementation, not optional:**
1. The code comment at the `aggregateVerdicts([...])` call site MUST
   state this mutual-exclusivity assumption explicitly and name exactly
   what would break it: any future analyzer that makes TWO of
   `transit`/`atRest`/`handling` genuinely co-applicable to the SAME edge
   (e.g., `handling` ever getting a real writer that fires alongside a
   `store`-kind edge's own `atRest`, or a future dimension applying to
   both `store` and `external` edges) must revisit whether this
   cross-dimension use of `aggregateVerdicts` is still safe, or whether a
   different combination rule (e.g., filtering to only genuinely
   evaluated dimensions before picking the worst, or a dedicated
   cross-dimension precedence separate from the cross-branch one) is
   needed instead.
2. **A synthetic test is required, not optional**, proving the
   PRECEDENCE ITSELF handles a genuinely-mixed case correctly even
   though no real code path produces one today: hand-construct (not via
   `buildDataFlowGraph` — via a direct call to whatever the aggregation
   call site becomes, or by hand-editing a built graph's edge before
   computing summary, implementer's choice) an edge with
   `transit.verdict: 'protected'` AND `atRest.verdict: 'unprotected'`
   simultaneously, and confirm the resulting `protectionSummary` is
   `'unprotected'` (the pessimistic, safe answer — `_PRECEDENCE` ranks
   `unprotected` above `protected`), never `'protected'`. This is the
   regression guard against the false-protected risk this correction
   describes, and is one of I2's required tests, not an optional
   addition.
3. `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-i-scoping.md`'s
   own I1 description should be read together with this correction —
   the scoping doc's original text did not surface this nuance; this
   plan document is now the authoritative description of I1's actual
   design.
