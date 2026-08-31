# Sub-project G scoping: comparison report + light performance harness

Parent: `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`,
Decision 4 / §5 table row G ("Comparison report + light performance harness,"
sized Small). Research/scoping only — no production code changed.

## G0: the PRD's literal wording doesn't fit what exists

§26's exit-gate text (and the parent scoping doc's row G) frame G as diffing
the engine's real output on "the flagship demo repo" against
`flagship-graph.json`. That target does not exist: `flagship-graph.json` is
hand-authored by `scanner/src/lineage/fixtures/build-flagship-fixture.mjs`
from Appendix D's fixed design — there is no underlying source repo for the
real engine to scan and diff against. Reinterpreting literally would mean
inventing a repo whose only purpose is to match a fixture, which proves
nothing. `bench/privacy-recall/`'s 4 real fixtures are a better, already-real
target: real source files, an existing baseline
(`bench/privacy-recall/BASELINE.json`), and — critically — they were authored
to exercise the OLD privacy-taint engine, so running the NEW lineage engine
over them is a genuine independent comparison, not a fixture built to agree
with itself.

## G1: comparison report — old privacy-taint engine vs. new lineage engine

**What was measured** (live, via `buildGraphWithCoverage` against all 4
`bench/privacy-recall/fixtures/*/app.js`):

| fixture | old shallow | old deep | new lineage engine |
|---|---|---|---|
| `clean-negative` | 0 | 0 | 0 PII-classified dataElements (correct) |
| `interprocedural` | 0 | 1 | flow structure correct (2 flows), 0 PII-classified |
| `renamed-before-sink` | 0 | 1 | flow structure correct, 0 PII-classified |
| `same-name-direct` | 1 | 1 | flow structure correct, 0 PII-classified |

**Root cause, confirmed by reading `privacy-taint.js`:** the old annotator
classifies by the **declared variable name** — `classifyFieldAgainst(d.name,
compiled)` at line 123, where `d` comes from `ir.decls` (`universal-ir.js`),
i.e. the LHS identifier of a local declaration (`const socialSecurityNumber
= req.body.value`). The new lineage engine classifies by the **source
expression's own field/property name** at the seed (`classifyDataElementName`
on `req.body.value` itself — the literal string `value`), and never inspects
downstream variable names. These are genuinely different, defensible bases:
the old engine catches "a variable that LOOKS sensitive by name," the new
engine catches "a wire-format field that IS the sensitive one" — and each
misses what the other catches. `req.body.card_number` (AC-01's own fixture)
is a case where the two AGREE, because the field name itself is descriptive;
`bench/privacy-recall/`'s fixtures were deliberately authored with a generic
wire field (`req.body.value`) and a descriptive local name, which is exactly
the shape that exposes the asymmetry.

**G1 scope:** a new report, `docs/lineage/PRIVACY_COMPARISON.md` (or a
`bench/data-lineage/` script emitting it), that:
1. Runs both engines over `bench/privacy-recall/`'s 4 fixtures (already-built
   tooling: `bench/privacy-recall/measure.mjs` for the old engine,
   `buildGraphWithCoverage` for the new one).
2. States the measured agreement/disagreement per fixture (table above).
3. Documents the root cause (variable-name vs. field-name classification
   basis) as a disclosed, load-bearing scope boundary of the new engine —
   not a bug — consistent with `scanner/src/lineage/CLAUDE.md`'s existing
   "what is and isn't modelled" convention.
4. Does **not** propose changing the new engine's classification basis
   (that's a real design decision — whether to also inspect assignment-LHS
   names — deliberately out of scope here; flag it as a candidate for a
   future milestone, not decide it in a report).

No competitor/named-external-tool comparisons are in scope (repo convention:
compare only against this codebase's own artifacts, per `posture/comparison.js`'s
established pattern and this session's own no-competitor-names rule).

Estimated size: Small — one new script/doc, no new fixtures, no engine
changes. A half-day increment.

## G2: performance harness — close the real gap

`bench/data-lineage/perf/{generate-synthetic-graph.mjs,runner.mjs}` already
exist (Milestone 0) and run cleanly today (verified: 30.9ms synthetic
generation, 8.6ms `validateGraph` over 5,000 nodes/10,000 edges). But they
measure the wrong thing for PRD §21's actual P0 target:

> **Graph build overhead: no more than 35% p50 over the equivalent deep scan
> for supported P0 languages.**

The current harness never invokes `buildGraphWithCoverage` (the real,
now-shipped M1 engine) — it only times synthetic-graph *generation* (a
fixture-building helper, not the engine) and schema *validation*. It cannot
answer §21's own question: how much does building the lineage graph add on
top of a deep scan someone already runs?

**G2 scope:**
1. Extend `runner.mjs` (or add a sibling script) to time `buildGraphWithCoverage`
   itself against a real call graph — reuse an existing sizeable fixture
   (e.g. run a deep scan over this repo's own `scanner/src/` tree, or a
   synthetic call graph shaped like the existing synthetic *DataFlowGraph*
   generator but at the call-graph/IR layer instead) rather than a
   post-hoc graph.
2. Time the deep scan alone vs. deep scan + lineage build, and report the
   overhead ratio in the same units §21 uses (p50 %).
3. Keep the "exits 0 always, no baseline gate yet" posture the existing file
   documents — Milestone 3 is where a checkable baseline against real UI
   timings makes sense, per the file's own header comment. G2 should NOT
   invent a premature gate.
4. Leave the existing synthetic-graph generation/validation timings in place
   (they're still useful for the later render/query/layout work) — extend,
   don't replace.

Estimated size: Small — one new timing path reusing existing scan
infrastructure, no new corpus, no gate.

## Recommended increment breakdown

- **G1**: comparison report (`docs/lineage/PRIVACY_COMPARISON.md`), reusing
  `bench/privacy-recall/`'s existing fixtures and `measure.mjs`. No engine
  changes.
- **G2**: extend `bench/data-lineage/perf/runner.mjs` to time
  `buildGraphWithCoverage` against a real IR/call-graph input, reporting
  overhead vs. a plain deep scan per §21's own metric. No new gate.

Both are additive, non-blocking, and independent of each other — safe to run
as two small worktree/SDD cycles, or combined into one if the coordinator
judges the combined diff small enough to review as a unit.
