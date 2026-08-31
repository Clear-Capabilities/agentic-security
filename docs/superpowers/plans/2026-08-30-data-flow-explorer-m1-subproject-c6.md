# Data Flow Explorer — M1 Sub-project C, Increment 6: FR-306 Edge Grading (Design + PoC)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve, and prove against real parsed code, the design for grading a reconstructed path's evidence quality per FR-306 — "Implicit/control-dependent and unknown-field widened flows must be visually distinct and lower-confidence. They may not be displayed as the same evidence grade as an explicit field assignment." This is the LAST increment of Sub-project C (C1-C5 all merged): the raw material FR-306 needs (`widenedHopCount`/`lossHopCount`/`ambiguousHopCount`/`crossScopeCount` on every reconstructed `Path`, and each individual hop's `widenReason`/`lossReason`/`ambiguousCorrelation`/`annotations[]` via `path-query.js`'s own `hopOf`) already exists and was built anticipating exactly this use — C5's own final whole-branch review confirmed this explicitly ("`hopOf()` denormalizes all four grading inputs C6 needs... verbatim off the edge, so C6 can grade a path without carrying the store... The `shape` signature is explicitly built to take a `transformation` and `protection` component later without changing the mechanism"). C6's job is narrow: define the actual GRADE — the taxonomy, the per-hop-to-per-path aggregation rule, and where the annotation-only markers (like §13.6's context-cap-degraded loss marker, which lives ONLY in `edge.annotations[]`, never `edge.lossReasons` — a gap C5's own review explicitly warned a C6 implementer could silently drop) factor in. This is a design-and-PoC increment (mirrors every prior increment's Task 1 in this sub-project), not a full implementation — it produces a committed design-doc addendum and a proof-of-concept regression test; the mechanical implementation is a follow-up task appended to this same plan once the design lands.

**Architecture:** A small, pure grading function (or pair of functions — a per-hop grade and a per-path aggregate) consuming ONLY the fields `path-query.js`'s existing `Path`/`Hop` shapes already carry (§15.2) — no new dependency on `path-store.js`'s internals, no change to `path-store.js` or `path-query.js`'s existing exports unless Task 1's own research finds a genuine, narrow gap (e.g. a hop's `annotations[]` not being visible where grading needs it — check this against the LIVE shape before assuming either way). Whether this lives as new exports inside `path-query.js` itself, or as a new small module (e.g. `flow-grade.js`), is one of this task's own open questions to resolve, not a foregone conclusion.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` §13.0/§13.6 (the `widenReason`/`lossReason`/`annotations[]` vocabulary this task grades), §15.2 (the exact `Path`/`Hop` shape this task consumes — read the LIVE, merged version, not any earlier draft), and `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §13 (FR-306, quoted below) and §8 (the visual grammar / visual state matrix, if it names anything relevant to evidence-grade display — check, don't assume it's silent) and `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md` (row C6 of §4's table).

**FR-306, quoted verbatim:** "Implicit/control-dependent and unknown-field widened flows must be visually distinct and lower-confidence. They may not be displayed as the same evidence grade as an explicit field assignment."

## Global Constraints

- The grading function(s) must NEVER import `engine.js`, `summaries.js`, or `driver.js` — same boundary `path-store.js`/`path-query.js` already established.
- Must consume ONLY the already-shipped `Path`/`Hop` fields (or `PathStore`'s existing public read API, if grading genuinely needs to read something beyond what a materialized `Path` already carries — justify this carefully if so, since the whole point of `path-query.js`'s design was to let a path be graded "without also carrying the store back to the caller," per §15.2's own stated reasoning).
- Every existing lineage test must keep passing (`npm run test:lineage`, 310/310 as of C5's merge) — verify before AND after any change.
- Do NOT invent a new grading vocabulary disconnected from what already exists in this codebase — check whether `protection.js`'s `EVIDENCE_GRADES` (Milestone 0: `['runtime', 'code_and_config', 'code', 'config', 'declared', 'manual', 'none']`) is the right vocabulary to reuse, extend, or deliberately NOT reuse (it grades PROTECTION evidence — transit/at-rest/handling — a different concept from flow-explicitness; decide and justify which is correct, don't silently conflate them).
- Follow this repo's root `CLAUDE.md` verification discipline: every claim about behavior (does the grade genuinely distinguish an explicit assignment from a widened one, does the aggregation rule behave sensibly on a real multi-hop path with mixed explicit/implicit hops) must be demonstrated by running real code in this task, not asserted from reading.

---

### Task 1: Resolve and document FR-306's edge-grading design, with a proof-of-concept

**Files:**
- Modify: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` — add a new `## 16. FR-306 edge grading (Sub-project C, increment 6)` section (after existing §15; do not renumber anything above it).
- Create: `scanner/test/lineage/flow-grade-poc.test.js` (or an equivalently-named throwaway PoC test file — mirrors every prior increment's own Task 1 precedent).
- Read only: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` in full (§2.2's annotation-vs-edge rule, §13.0/§13.6, §14.2's node-kind table, §15.2's exact `Path`/`Hop` shape — this task needs the complete picture, not a partial read, matching every prior increment's own stated lesson about what happens when a reviewer works from a partial read), `scanner/src/lineage/path-query.js` in full (especially `hopOf`/`materialize` — the exact fields a `Path`/`Hop` carries today), `scanner/src/lineage/protection.js` (the `EVIDENCE_GRADES`/`aggregateVerdicts` precedent — read it even if you conclude it's the wrong vocabulary to reuse, so that conclusion is grounded rather than assumed), `scanner/test/lineage/path-query.test.js` (for real, already-proven fixtures to reuse — especially any fixture already producing a mix of explicit and widened/ambiguous hops on one path).

**Interfaces:**
- Consumes: `path-query.js`'s `Path`/`Hop` shape exactly as shipped (§15.2) — read the LIVE fields (do not assume the field list from memory; `path-query.js`'s own final whole-branch review found and fixed real drift between an early design draft and what actually shipped, more than once in this sub-project's history).
- Produces (for the follow-up implementation task to consume — do not implement these yet, just settle their exact shape in the addendum and prove them via the PoC):
  - **The grade taxonomy itself.** FR-306's own text implies at minimum a two-tier distinction (explicit vs. not), but decide with evidence whether a richer taxonomy is warranted given what's ALREADY measurable per hop: a plain, unwidened, unambiguous, intraprocedural assignment is the highest grade; what's the NEXT tier down for a hop that's cross-scope but otherwise clean (an interprocedural stitch, sound but structurally different — does this even count as lower-confidence at all, given C3/C4's own extensive work proving cross-function stitching is SOUND, not merely plausible)? What's the grade for a hop carrying a real `widenReason` (an actual imprecision) vs. one merely carrying an `ambiguousCorrelation` marker (a real fact, just correlationally uncertain, per §9.1's own careful distinction between "sound but ambiguous" and "imprecise")? Decide with evidence, not by assumption — build a fixture with each of these hop shapes and confirm your proposed taxonomy actually separates them the way FR-306 requires (an explicit assignment must never share a grade with a widened one).
  - **The per-path aggregation rule.** A path has multiple hops, each with its own grade. Does the path's overall grade become the WORST (lowest-confidence) grade among its hops — mirroring `protection.js`'s own `aggregateVerdicts()` risk-precedence reduction, an established precedent in this exact package — or is per-hop grading alone sufficient (i.e., FR-306 is satisfied by grading each hop individually, with no single scalar "path grade" needed at all)? Decide and justify against FR-306's own text ("visually distinct and lower-confidence" — is this a claim about the PATH as a whole, or about EACH hop that's implicit/widened?).
  - **Whether `annotations[]` factors into grading, and how.** §13.6's context-cap-degraded loss marker and any other annotation-only signal (per §2.2's rule: an annotation attaches to a real edge without being one of its two edge-forming halves) lives in `edge.annotations[]`, never in the edge's own top-level `lossReasons`/`widenReasons` arrays — C5's own final review explicitly flagged this as a trap a C6 implementer could fall into by reading only the top-level fields. Decide: does an annotation-only marker (e.g. a degraded call) affect the hop's grade at all, or is it a SEPARATE signal (e.g. a `degraded: true` flag alongside the grade, not folded into it)? Prove your decision against a real fixture carrying a context-cap-degraded hop (reuse `C4/Q2c`'s or `C5`'s own degraded-call fixture pattern).
  - **Where the grading function(s) live, and their exact exported signature(s).** A strong starting candidate to evaluate, not treat as decided: `gradeHop(hop)` and `gradePath(path)`, exported from `path-query.js` itself (since they consume nothing `path-query.js` doesn't already produce) — or a new, small, separate module if there's a real reason to keep grading logic out of the reconstruction module (e.g., if Milestone 4's later work needs to grade a path WITHOUT reconstructing one, or if C6's own scope genuinely warrants its own file for clarity). Decide and justify.
  - **The exact enum/string values the grade takes**, and whether they're a NEW vocabulary or deliberately reuse/extend `protection.js`'s `EVIDENCE_GRADES` (decide this explicitly — don't silently pick one without stating why the other was rejected, especially since a shared vocabulary would need updating in `schema.js`/`dataflow-graph.schema.json`/`validate.js` per this package's own stated "every enum here is a single source of truth" convention, while a new, separate vocabulary would not need to touch those files at all this increment — which is itself a factor in the decision, not an afterthought).

- [ ] **Step 1: Read the current state (grounding, not a step that produces a diff)**

Read `DESIGN_PATH_PROVENANCE.md` in full — the sections named above at minimum, but the whole document is short enough now that a full read is still cheaper than re-deriving context piecemeal, and every prior increment's own history in this sub-project shows a partial read is where defects hide. Read `path-query.js` in full. Read `protection.js` in full. Read `path-query.test.js` for reusable fixtures.

- [ ] **Step 2: Build the PoC harness**

Write the PoC test file. Structure it around real, already-proven reconstruction (reuse `path-query.test.js`'s own hand-seeding/real-parser technique — do not invent a new testing style for this task). At minimum, prove:

1. **A pure explicit-assignment path** (no widening, no ambiguity, no cross-scope, no annotations) grades at the HIGHEST tier.
2. **A path with a genuinely widened hop** (a real `widenReason`, e.g. an unresolved call or a dynamic-property-key hop from an already-proven C1/C2 fixture) grades LOWER than the explicit case — and, critically, NEVER at the same grade, per FR-306's own literal wording.
3. **A path with only an `ambiguousCorrelation` marker** (no `widenReason`/`lossReason`) — resolve and prove whether this is graded the same as, or differently from, a genuinely widened hop; either answer is defensible, but it must be a proven, deliberate decision, not an accident of implementation.
4. **A cross-scope (interprocedural) but otherwise CLEAN path** (a real resolved call chain, e.g. reusing `C4/Q2`'s or `C5`'s own resolved-call fixture) — prove whether crossing a function boundary alone lowers the grade, or whether a sound interprocedural stitch grades identically to an equally-clean intraprocedural one.
5. **A path with a §13.6 context-cap-degraded annotation** — prove how the chosen design surfaces this in the grade (or as a separate signal alongside it), and that it is NEVER silently invisible to a consumer reading only the grade.
6. **The aggregation rule** — a real multi-hop path with a deliberate MIX of grades across its hops (at least one clean hop, at least one lower-grade hop), proving the path-level aggregate (if one exists per your Step 3 decision) behaves as designed — worst-case-wins, or whatever rule you chose.

- [ ] **Step 3: Decide, and write §16 of `DESIGN_PATH_PROVENANCE.md`**

Using Step 2's PROVEN results, write `## 16. FR-306 edge grading (Sub-project C, increment 6)` with subsections mirroring §13's/§14's/§15's own style: the grade taxonomy and its exact values; the per-hop grading rule (which fields map to which grade, in what precedence order); the per-path aggregation rule (or the decision that none is needed); how `annotations[]`-only markers factor in; the exported function(s) and their exact signatures; a short "what the follow-up implementation task must do" checklist in the file/line-precise style §10.1/§13.7/§14.10/§15.10 already established.

- [ ] **Step 4: Verify nothing existing regressed**

Run `npm run test:lineage` from `scanner/`. All 310 pre-existing tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/DESIGN_PATH_PROVENANCE.md scanner/test/lineage/flow-grade-poc.test.js
git commit -m "docs(lineage): design C6's FR-306 edge grading (taxonomy, aggregation, annotation handling), with PoC"
```

---

## Post-Task-1 note

This plan gains its implementation task(s) here, scoped exactly to what §16's checklist specifies, once Task 1's addendum is committed and reviewed. Do not pre-write them — §16 does not exist yet at the time this plan file was first saved.
