# Data Flow Explorer — M1 Sub-project C, Increment 5: Bounded Path Reconstruction + Truncation Semantics (Design + PoC)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve, and prove against real parsed code, the design for the backward-walk RECONSTRUCTION query that reads `scanner/src/lineage/path-store.js`'s DAG (Sub-project C, increment 4, merged) and turns it into bounded, ordered, human-readable paths from a sink back to candidate sources — the query layer `path-store.js` deliberately left entirely unbuilt ("No backward walk, no reconstruction, no path budget, no prioritization. C5's, entirely." — §14.9). This is a design-and-PoC increment (mirrors C1's/C3 Task 1's/C4 Task 1's own role in this sub-project), not a full implementation — it produces a committed design-doc addendum and a proof-of-concept regression test; the mechanical implementation is a follow-up task appended to this same plan once the design lands.

**Architecture:** A NEW module (working name `path-query.js`, to be confirmed or corrected by Task 1) that consumes a `PathStore` instance purely through its existing read API (`nodes()`, `edges()`, `getNode`, `getEdge`, `edgesFrom`, `edgesTo`, `hasEdge`, `nodeIdFor`, `stats()`, `diagnostics()`) — it must never reach into `PathStore`'s private state, and (mirroring `path-store.js`'s own isolation boundary) must never import `engine.js`/`summaries.js`/`driver.js` either. Unlike `path-store.js`'s construction (a single linear pass, provably non-recursive), this module's whole job is graph TRAVERSAL — so it must be cycle-safe not "by construction" but by an explicit, tested visited-set/budget discipline, since §9.3 already established the DAG can genuinely contain cycles (a real mutual-recursion fixture builds one today).

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` §14 in full (the binding record of what `path-store.js` actually built and reads — §14.2's node-kind table and §14.6's read API are this task's primary interface; §14.9 is the explicit boundary this task now crosses) and `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §13 (FR-303, FR-305, FR-306 — quoted in full below so this task doesn't need to hunt for them) and §18.4 (path-explosion controls, quoted in full below) and AC-10 (partial-scan banner requirement — the UI-facing consequence of this task's own truncation shape, even though the UI itself is Milestone 3's job) and `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md` (row C5 of §4's table).

**PRD requirements this increment must satisfy, quoted verbatim:**

- **FR-303 (Path reconstruction):** "The engine must retain a compact predecessor/provenance DAG from which ordered paths can be reconstructed. It must not eagerly materialize every possible path during scanning because that creates path explosion." (`path-store.js` already satisfies the DAG half; this increment is the "ordered paths can be reconstructed" half.)
- **FR-305 (Multiple paths):** "When several paths connect the same source and sink, the UI must show a path count and allow the user to inspect each path. Deduplication may collapse identical internal segments but cannot hide materially different transformations or controls."
- **FR-306 (Implicit and widened flows):** "Implicit/control-dependent and unknown-field widened flows must be visually distinct and lower-confidence. They may not be displayed as the same evidence grade as an explicit field assignment." (C6's job to fully wire — see the C-scoping doc's own row — but this increment's path OUTPUT must carry whatever's needed for C6 to grade it, i.e. must not discard `widenReasons`/`lossReasons`/`ambiguousCorrelation`/`annotations[]` while assembling a path.)
- **§18.4 (Path-explosion controls), the binding constraints on the data structure itself:**
  - Store a provenance DAG, not a list of every expanded path. (Satisfied by C4; this increment's OUTPUT is necessarily a materialized list of paths, but only ever a bounded, on-demand slice — never eager, never during scanning.)
  - Cap alternate paths per source/sink pair with an explicit truncation count.
  - Prioritize paths that differ in boundary, transformation, or protection state.
  - Never translate "path budget exhausted" into "no path." **This is the single most load-bearing constraint in this increment** — a truncated reconstruction must be distinguishable, in the data itself, from "we looked and there genuinely is no path."
- **AC-10 (the UI-facing consequence, Milestone 3's job to render — but this increment's data shape is what makes it possible):** "Given one parser fails or a path budget is exhausted, then the website displays a persistent partial-coverage banner... A zero-flow filter result must say that the scope is incomplete."

## Global Constraints

- The new module must NEVER import `engine.js`, `summaries.js`, or `driver.js` — same boundary `path-store.js` established, for the same reason (testable independent of Sub-project D/E's continued absence).
- The new module must consume `PathStore` ONLY through its existing public read API — never reach into `_groups`/`_build()`/`_peerSourced`/any other private field (all prefixed `_` by convention in `path-store.js`).
- `path-store.js` itself must not change in this increment unless Task 1's own research finds a genuine gap in its read API that reconstruction cannot work around (if so, that's a real finding to document and scope carefully, not to patch silently).
- Every existing lineage test must keep passing (`npm run test:lineage`, 279/279 as of C4's merge) — verify before AND after any change.
- Cycle safety must be explicit and tested — a mutual-recursion fixture already exists in `path-store.test.js` (`C4/4`) and produces a genuinely cyclic DAG (8 nodes, 11 edges); reuse it, don't re-derive a new cyclic fixture from scratch.
- Follow this repo's root `CLAUDE.md` verification discipline: every claim about behavior (does the budget cap genuinely stop expansion, does truncation surface honestly, does the prioritization rule actually reorder) must be demonstrated by running real code in this task, not asserted from reading.

---

### Task 1: Resolve and document the bounded reconstruction query's design, with a proof-of-concept

**Files:**
- Modify: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` — add a new `## 15. Bounded path reconstruction (Sub-project C, increment 5)` section (after existing §14; do not renumber anything above it).
- Create: `scanner/test/lineage/path-query-poc.test.js` — a throwaway-named PoC test file (mirrors C1's/C3 Task 1's/C4 Task 1's own precedent).
- Read only: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` §14 in full (§14.1-§14.11 — the node-kind table in §14.2, the read API in §14.6/§14.10, and §14.9's exact boundary this task crosses, are all load-bearing), `scanner/src/lineage/path-store.js` in full (the read API's actual behavior, not just its signatures — e.g. `edgesFrom`/`edgesTo` return live arrays computed from an index, `nodeIdFor` needs a full node descriptor not just an id string), `scanner/test/lineage/path-store.test.js` (for existing fixtures to reuse — especially `C4/4`'s mutual-recursion cyclic fixture and `C4/1b`'s §6 worked-example fixture, which §14.11 already proves builds "the two field-distinct three-hop paths §6 predicts" — this increment's job is to make that reconstruction real, not re-derive it).

**Interfaces:**
- Consumes: `PathStore`'s public read API exactly as `path-store.js` ships it today. Does NOT consume raw hop records — this module never sees a hop, only the already-built DAG.
- Produces (for the follow-up implementation task to consume — do not implement these yet, just settle their exact shape in the addendum and prove them via the PoC):
  - The exported surface of the new module — a strong starting candidate to evaluate and correct, not treat as decided: a single entry point, something like `reconstructPaths(store, sinkNodeId, opts)` returning a bounded, ordered list of paths plus an explicit truncation signal, mirroring the shape the parent sub-project's own scoping doc (§3) already sketched: `{paths: [...], truncated: boolean, budgetExhausted: boolean, totalPathsFound: number}` — evaluate this candidate shape against real reconstruction scenarios and correct it where it's wrong, exactly as C4's own Task 1 corrected its own starting hypotheses.
  - **What a "path" actually IS in the output.** A sequence of node ids? Edge ids? Both, interleaved? Given FR-306's requirement that a path's OUTPUT must carry enough to grade each hop (implicit/widened vs. explicit), a bare node-id sequence is almost certainly insufficient — the edges traversed (with their `widenReasons`/`lossReasons`/`ambiguousCorrelation`/`annotations[]`/`crossScope`) are what carries that signal. Decide and justify the exact shape, and prove it round-trips correctly against a real fixture with a mix of explicit and widened hops.
  - **The backward-walk algorithm and its cycle safety.** `edgesTo(nodeId)` is the natural traversal primitive (walk backward from a sink toward candidate sources). This must be BUDGETED (a cap on total paths explored, not just total nodes visited — a single node can have many incoming edges, and naive DFS-without-a-budget over a cyclic graph does not terminate on its own the way `path-store.js`'s own linear-pass construction does). Design the exact termination/visited-set discipline, and PROVE it terminates on the real `C4/4` mutual-recursion fixture within a small, explicit budget, producing a genuinely truncated (not silently empty, not silently complete) result.
  - **The truncation-is-never-silent shape, concretely.** §18.4's single most load-bearing constraint. Prove, with a real fixture where the walk genuinely exhausts its budget, that the result distinguishes "truncated, and there might be more" from "not truncated, this is everything" — and separately, that a sink with GENUINELY zero incoming paths (an isolated node, or an `origin`-kind node itself, or an unreachable-in-the-real-parser scenario built by hand) produces a result that is NOT truncated and says so unambiguously. These are two different tests; do not let one stand in for the other.
  - **The alternate-path cap "per source/sink pair" (§18.4).** `path-store.js` has no notion of "source" or "sink" yet (no registry — Sub-project D). Decide what this increment's cap actually bounds in the absence of that vocabulary: most plausibly, the cap bounds "number of distinct paths returned by ONE `reconstructPaths` call, from one given starting node" — decide and state this explicitly, and name what changes once Sub-project D's registry exists (does the cap become genuinely per-source/sink-PAIR then, or does today's per-call cap already satisfy that once the caller always supplies one sink node per call? Reason it through, don't hand-wave it).
  - **Deduplication that "cannot hide materially different transformations or controls" (FR-305).** With no transformation-KIND recognition yet (Sub-project D) and no protection verdicts yet (Milestone 2), decide what "materially different" means with the signals THIS increment actually has available: distinct node sequences are obviously distinct paths; do two paths with the IDENTICAL node sequence but differing edge annotations (e.g. one edge marked `ambiguousCorrelation: true`, an otherwise-identical alternate edge not) count as one path or two? Decide, justify against FR-305's own text, and prove the decision against a real fixture that actually has this shape (the `§9.1` cross-join fixture in `path-store.test.js` is a strong candidate to build from).
  - **The prioritization rule ("paths that differ in boundary, transformation, or protection state").** Transformation-kind and protection-state don't exist yet. "Boundary" DOES have a real, already-available signal: `edge.crossScope` (a path that crosses a function boundary is architecturally more interesting than one that doesn't, per this whole document's own repeated emphasis on interprocedural stitching being the hard, load-bearing case). Decide a scoped, honest ordering rule using ONLY signals that exist today (boundary-crossing count, presence of `ambiguousCorrelation`/`widenReasons`/`lossReasons`), explicitly disclose what's deferred (transformation-kind, protection-state — name the sub-projects/milestones that will add them), and prove the ordering is real by constructing a fixture with 2+ genuinely different paths and showing the rule orders them as claimed.
  - Whether `path-store.js`'s existing read API is sufficient for all of the above, or whether a genuine gap exists (e.g. is there a cheap way to find every "sink-shaped" node — a `return`/`escape` kind — without a source/sink registry, for THIS task's own PoC fixtures to exercise reconstruction against? If the read API needs one narrow addition, name it precisely and justify why it belongs in `path-store.js` rather than in the new module).

- [ ] **Step 1: Read the current state (grounding, not a step that produces a diff)**

Read `DESIGN_PATH_PROVENANCE.md` §14 in full. Read `path-store.js` in full — actually read the code, not just the exported signatures, since this task needs to reason about what `edgesFrom`/`edgesTo`/`getNode` genuinely return under real conditions (a cyclic graph, an `origin` node, a `return` node aggregating multiple return sites — §14.2's own disclosed imprecision that C5 "cannot distinguish which return site a value left by, even where the CFG could"). Read `path-store.test.js` in full for reusable fixtures.

- [ ] **Step 2: Build the PoC harness**

Write `scanner/test/lineage/path-query-poc.test.js`. Structure it around real, already-proven `PathStore` instances (build them the same way `path-store.test.js` does — real parsed JS/TS source, hand-seeded entry states, the real interprocedural resolver machinery, feeding a real hop stream into a real `PathStore`) — do not invent a new hand-built-hop-array testing style for this task; reconstruction should be proven against the SAME kind of real DAGs C4's own suite already builds and trusts. At minimum, prove:

1. **A simple reconstruction round-trip**: the §6 worked-example fixture (`const b = a.email; return b;`-shaped, or the richer 2-field version `path-store.test.js`'s `C4/1b` already builds) reconstructed from its `return` node back to its `path` source node, producing the exact edge sequence a human would expect, with zero truncation.
2. **Cross-function reconstruction**: a resolved call chain (reuse `C4/Q2`'s or `C4/leg`'s fixture shape) reconstructed from the caller's own exit node, walking THROUGH the cross-scope edge into the callee's exit node and out to the callee's own source — proving the walk correctly crosses scope boundaries via `edgesTo`, not just within one function.
3. **Bounded, honest truncation**: the `C4/4` mutual-recursion fixture (a real, proven cycle), reconstructed with a small explicit budget, producing a result that both terminates AND correctly reports `truncated: true`/`budgetExhausted: true` — never a silent partial list.
4. **Honest "genuinely no path" vs. "truncated"**: a hand-built or real fixture where a given node genuinely has zero backward paths (an isolated `origin` node, or a source-shaped node with no incoming edges at all), producing a result that is explicitly NOT truncated and explicitly has zero paths — proving these two "empty-looking" results are actually distinguishable in the data.
5. **Deduplication and prioritization**: the `§9.1` cross-join fixture (`path-store.test.js`'s `C4/6b`), reconstructed and showing whether/how the ambiguous alternate paths are deduplicated or kept distinct per your Step-3 decision, and that any prioritization rule you design actually reorders a multi-path result as claimed.

- [ ] **Step 3: Decide, and write §15 of `DESIGN_PATH_PROVENANCE.md`**

Using Step 2's PROVEN results, write `## 15. Bounded path reconstruction (Sub-project C, increment 5)` with subsections mirroring §13's/§14's own style: the module's exported surface and exact signature; the path-output shape; the backward-walk algorithm and its termination/budget discipline; the truncation-is-never-silent data shape, concretely; the per-call alternate-path cap and what it means before/after Sub-project D; the dedup decision and its FR-305 justification; the prioritization rule and what's honestly deferred; a short "what the follow-up implementation task must do" checklist in the file/line-precise style §10.1/§13.7/§14.10 already established.

- [ ] **Step 4: Verify nothing existing regressed**

Run `npm run test:lineage` from `scanner/`. All 279 pre-existing tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/DESIGN_PATH_PROVENANCE.md scanner/test/lineage/path-query-poc.test.js
git commit -m "docs(lineage): design C5's bounded path reconstruction (backward walk, truncation, dedup, prioritization), with PoC"
```

---

## Post-Task-1 note

Task 1 landed as `DESIGN_PATH_PROVENANCE.md` §15 (commit `e9a86ec7`), a fix round closing one blocking finding plus 8 non-blocking ones (commit `99f26113`), a scoped re-review confirming the fix round genuinely closed the blocking finding, and a small direct follow-up fixing 3 more small findings (commit `14e1564e`). §15.10 is the accepted, binding file/line/signature checklist for Task 2 below; every reference in Task 2 is to that checklist's 17 rows (items 1-15, plus 11b).

---

### Task 2: Implement `path-query.js`, the `pathId` function, and absorb the PoC into the permanent suite

**Files:**
- Create: `scanner/src/lineage/path-query.js` (§15.10 items 4-11b)
- Modify: `scanner/src/lineage/ids.js` (§15.10 items 1-3)
- Modify: `scanner/test/lineage/ids.test.js` (§15.10 item 2)
- Rename/absorb: `scanner/test/lineage/path-query-poc.test.js` → `scanner/test/lineage/path-query.test.js`, re-pointed at the shipped module (§15.10 item 12)
- Modify: `scanner/package.json` — update the `test:lineage` script's file list to the renamed file (same commit as the rename, per §15.10 item 12 / C3's item-15 / C4's item-11 precedent)
- Modify: `scanner/src/lineage/CLAUDE.md` — new module-table row for `path-query.js`, mirroring the style of every prior increment's own row (see the existing `path-store.js` row for the density/citation bar)
- Read only: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` §15 in full (§15.1 through §15.11 — this is the binding spec; the PoC file being absorbed is a prototype of it, not a substitute for reading it — the prototype went through a fix round and a scoped re-review that corrected real defects in it, so read the LIVE §15 text, never an earlier mental model of what the PoC does), `scanner/test/lineage/path-query-poc.test.js` (what you're absorbing and deleting the prototype halves of), `scanner/src/lineage/path-store.js` and its read API (this module's only real dependency), `scanner/src/lineage/ids.js` in full (the convention `pathId` must match exactly)

**Interfaces:**
- Consumes: `PathStore`'s public read API exactly as `path-store.js` ships it, and nothing else — never a `_`-prefixed field.
- Produces: `pathId({ startNodeId, edgeIds }, discriminatorParts = [])` in `ids.js` (§15.10 item 1's exact signature — confirm against the LIVE §15.10/§15.2 text before writing, the same discipline every prior increment's brief has required). `reconstructPaths(store, startNodeId, opts)`, `sinkCandidates(store)`, `isIncompleteAnswer(result)`, and `comparePaths(a, b)` from `path-query.js` (§15.10 items 6, 10, 11, 11b — `comparePaths` is exported, not merely internal, per fix round 1's own correction to the original design's export list).

- [ ] **Step 1: Read §15 in full, then `path-store.js`'s read API and `ids.js` in full**

Do not start from the PoC file's prototype code as if it were the spec — it went through a fix round that corrected the per-terminal truncation-honesty defect (§15.5), the mixed-terminal-reason bug (§15.6), and two "prose stronger than proof" test weaknesses (§15.5/§15.6's own measurement fixtures) — §15's prose is the authority when the two differ, more so here than in any prior increment's Task 2 given how much the design changed after its own first draft. Confirm `ids.js`'s exact current `_hash`/`_canon`/`ID_HEX_LEN` shape and the `provenanceNodeId`/`provenanceEdgeId` precedent (§14.5) before writing `pathId`.

- [ ] **Step 2: `ids.js` — the `pathId` function (items 1-3)**

Add `pathId({ startNodeId, edgeIds }, discriminatorParts = [])` immediately after `provenanceEdgeId`, per §15.10 item 1's exact signature — object argument, matching the `provenanceNodeId`/`provenanceEdgeId` precedent. Prefix `ppath:`. Extend `test/lineage/ids.test.js` with idempotence (the same logical path, reconstructed twice, produces the same id) and non-collision (a changed edge id ANYWHERE in the sequence, and a REORDERED sequence, must both move the id — order matters for a path, unlike a node/edge discriminator's set-like fields). Confirm item 3: `validate.js` needs literally no change (`ppath:` is not a `DataFlowGraph v1` entity kind) — verify by running `npm run test:lineage` and confirming `json-schema-parity.test.js` stays green.

- [ ] **Step 3: `path-query.js` — the module (items 4-11b)**

Create the file. Imports: `ids.js` only (item 4) — add the same import-list self-check test `path-store.test.js`'s own boundary test uses, PLUS the `store\._`/private-field-by-name source scan the PoC's `C5/6` carries (read that test's own comment about its own limitation — a hand-written function list cannot detect an added, unscanned function; if you have a real module to introspect by the time you write this, use programmatic export enumeration instead of a hand-written list, per that test's own fix-round-1 note).

`DEFAULTS`: `{ maxPaths: 32, maxPathsPerTerminal: 8, maxCandidatePaths: 256, maxExpansions: 10000, maxDepth: 64 }`, all `opts`-overridable, documented as uncalibrated (§15.3 — every fixture measured against them so far is tiny; nothing bigger is measurable until a driver run emits real hops, Sub-project D/E).

`reconstructPaths(store, startNodeId, opts)`: an ITERATIVE DFS over an explicit stack — no recursion anywhere (the DAG can genuinely be cyclic, §9.3/proven by `C4/4`'s mutual-recursion fixture; recursion here would risk both infinite loops on a cycle and a stack-depth failure mode `path-store.js`'s own construction never had to worry about). A per-path visited set (not a global one — the SAME node can legitimately appear on two different candidate paths). `edgesTo` results sorted by edge id before expansion, for determinism. The zero-in-edges check must run BEFORE the depth check (§15.3's exact ordering constraint — get this backwards and a node that's a genuine, well-formed dead end gets mislabeled as depth-truncated).

Terminal classification: `'origin'` (a genuine `origin`-kind node, §14.2) / `'incomplete-record'` (the node appears in `store.diagnostics().orphanedPeerSources` — §14.4's disclosed stream-completeness gap surfacing here) / `'cycle'` (every continuation from this node was already visited on this path) / `'depth-limit'` (the per-path budget hit `maxDepth`). `'expansion-budget'` and `'candidate-cap'` are RESULT-level truncation reasons only — those two branches are ABANDONED when hit, never emitted as a marked partial path (§15.4 — only `'cycle'`/`'depth-limit'` produce an emitted `complete: false` path; the other two just stop expanding silently at the result level, which the result's own `truncated`/`truncationReasons` fields report).

The cap: apply `maxPathsPerTerminal` per `terminal.nodeId` FIRST, then a diversity-first round-robin over `(terminal.nodeId, shape)` buckets for the global `maxPaths` cap (§15.5/§15.7 — read §15.7's exact prioritization rule text, it uses only signals that exist today: `crossScopeCount`, presence of `ambiguousCorrelation`/`widenReasons`/`lossReasons`, and `complete` as the first sort key). `result.terminals[]` per §15.5's exact shape — **critical, this is what the blocking finding from Task 1's review was about**: `terminals[].truncated` and `terminals[].droppedPathCount` MUST be computed AFTER the global round-robin runs, never from the per-terminal cap alone — read §15.5's corrected text closely, it gives the exact formula (`enumeratedPathCount > returnedPathCount`) and explains exactly why the naive ordering is wrong.

The result shape: exactly §15.4's table, plus `startNodeId`/`startNodeKind`/`enumeratedPathCount`/`returnedPathCount`/`droppedPathCount`/`completePathCount`/`cyclesClipped`/`analysisTruncated`/`terminals[]`/`budget.expansionsUsed`. `noPathReason` must be computed ONLY when `truncated === false` — this ordering IS §18.4's own load-bearing constraint made concrete in code, not a stylistic choice: a truncated result must never look like "no path exists," and computing `noPathReason` unconditionally would risk exactly that confusion if the two fields were ever read independently.

`sinkCandidates(store)`: §15.9's filter over `store.nodes()` — read §15.9's own text for the exact filter and its "this is not a source/sink registry, just a shape-based candidate list for THIS task's own testing" disclaimer, since Sub-project D's eventual real registry is a different, later mechanism.

`isIncompleteAnswer(result)`: §15.4's five-term predicate, exported so AC-10's eventual UI banner has exactly one function deciding "should this show the partial-coverage banner," never a re-derived check at the call site.

`comparePaths(a, b)`: §15.7's total order, exported (not merely internal — fix round 1's own correction; the shipped tests call it directly to build contrast fixtures, so it must be part of the public surface, not deleted along with the rest of the local prototype in Step 4).

- [ ] **Step 4: Absorb the PoC, rename it, wire it into `test:lineage` (item 12)**

Re-point `path-query-poc.test.js`'s tests at the shipped `path-query.js`/`ids.js` (delete the local prototype block), rename the file to `path-query.test.js`, and update `scanner/package.json`'s `test:lineage` script entry in the SAME commit — mirrors C3's own item-15 and C4's own item-11 precedent exactly.

**Keep every assertion, and especially keep `C5/4b`** (the three empty-looking-but-distinguishable results as literal JSON — this is §18.4's own constraint made concrete) **and `C5/4c`** (the `'incomplete-record'` terminal reason) — together they are the only guard against §18.4's constraint being silently undone by a future refactor. Also keep `C5/5e` (the per-terminal truncation-honesty fix's own regression guard — fix round 1's blocking finding) and `C5/5f`/`C5/5d` (the two "prose stronger than proof" tests the fix round and scoped re-review both strengthened) intact; these are this increment's own hardened core, analogous to C4's `C4/Q2b`.

**Do not add a driver-level test yet** (item 15) — a driver run still emits zero hops today (no source registry, Sub-project D/E), so a driver-fed reconstruction test at this stage would assert on an empty store and be vacuous, matching the exact reasoning `path-store.js`'s own item 13 and `engine-provenance-interprocedural.test.js`'s own driver test note already established for the identical situation.

- [ ] **Step 5: `scanner/src/lineage/CLAUDE.md` — new module-table row**

Add a `path-query.js` row to the Sub-project C module table (or extend the existing increment grouping to "increments 1-5"), describing the module's role, the terminal-classification taxonomy (§15.4), the per-terminal-then-global cap and the truncation-honesty fix (§15.5), the dedup/prioritization decisions (§15.6/§15.7), and the `pathId` addition to `ids.js` — mirroring the density and citation style every prior row in this file already uses, including naming the fix round's own blocking finding the way `path-store.js`'s row names C4's own final-review finding. Update "What is NOT here yet" to move C5 from "still ahead" to done.

- [ ] **Step 6: Run the full scoped suite and doc-drift check**

```bash
npm run test:lineage
node ../scripts/check-doc-drift.mjs
```

Confirm test count and doc-drift status (the pre-existing `path-store.js`-shaped forward reference should now be fully resolved; C4 already closed its own instance of this — confirm nothing new appears for `path-query.js`).

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/path-query.js scanner/src/lineage/ids.js scanner/test/lineage/ids.test.js scanner/test/lineage/path-query.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
git rm scanner/test/lineage/path-query-poc.test.js
git commit -m "feat(lineage): implement path-query.js, bounded path reconstruction (Sub-project C, increment 5)"
```
