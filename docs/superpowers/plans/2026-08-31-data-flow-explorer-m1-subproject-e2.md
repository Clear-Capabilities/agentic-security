# Data Flow Explorer — M1 Sub-project E, Increment 2: `source-seeding.js`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract E1's already-designed-and-proven source-seeding mechanism out of its throwaway PoC (`test/lineage/graph-builder-poc.test.js`) into a real, permanent, shipped module — `scanner/src/lineage/source-seeding.js` — closing the measured "0 hops on real code" gap for good. This is mechanical implementation against an already-reviewed design (`DESIGN_GRAPH_BUILDER.md` §3, proven twice: once by E1's own design task, once independently by E1's own task review, which reproduced every headline number via its own from-scratch reimplementation), mirroring D1→D2's own precedent — the design phase is complete, this increment's job is to ship it as real, tested, permanent code and absorb the seeding half of the PoC.

**Architecture:** `source-seeding.js` exports `planSeeds(callGraph, opts)` (walks every function's CFG expressions, matches sources via `matchSource`, extends the match outward to the field per §3.2's rule, mints a `dataElementId` per §3.4, returns `{seeds, unseedable}`) and `seedEntryStateFactory(seeds)` (returns a `(fn) => state | undefined` function, the exact shape `driver.js`'s new `opts.seedEntryState` hook expects). Consumes `matchSource`/`accessPathOf` from `dataflow/` (the reuse boundary E1 §12 already confirmed), `reclassifySource` from `./source-registry.js`, `classifyDataElementName` and `dataElementId` from their existing modules. Does NOT touch `driver.js`, `path-store.js`, `path-query.js`, `engine.js`, `field-identity.js`, or any registry — those are already-shipped consumers/dependencies, not this increment's to modify.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` §3 in full (§3.1 through §3.7 — this is the binding ADR; every rule this task implements is already specified and proven there, not re-derived here) and §12 (the confirmed `matchSource`/`accessPathOf` reuse boundary). Also read `test/lineage/graph-builder-poc.test.js` in full — specifically `exprRoots`/`exprChildren`/`walkExpr`/`seedPathFor`/`planSeeds`/`seedEntryStateFactory` (the exact functions this task extracts) and `E1/1` through `E1/5` plus `E1/14` (the tests this task absorbs) — treat the PoC's own code as the reference implementation to port faithfully, and `DESIGN_GRAPH_BUILDER.md`'s prose as authoritative for the DECISION PROCEDURE if the two ever seem to differ (§9.1's own stated policy: "Where this document and that PoC disagree, the PoC is right and this document is stale — fix it here, do not fork it").

## Global Constraints

- `source-seeding.js` must import ONLY `matchSource`/`accessPathOf` from `dataflow/` (per §12's confirmed reuse boundary) — never `dataflow/engine.js`, never `dataflow/summaries.js`, never matcher internals beyond `matchSource` itself.
- Must NOT modify `driver.js`, `path-store.js`, `path-query.js`, `engine.js`, `field-identity.js`, `source-registry.js`, `sink-registry.js`, `transform-catalog.js`, `schema.js`, `validate.js`, `ids.js`, `classification.js`, or `protection.js` — this increment is a NEW module consuming all of these as already-shipped, already-correct dependencies.
- The seed-path rule (§3.2 — extend the matched expression outward through every enclosing pure-member access, seed the FIELD not the container) must be ported EXACTLY as the PoC implements it — this is the single most consequential rule in the whole design (§3.2's own text: "Classification is impossible without this rule").
- The `dataElementId` discriminator (§3.4 — `[repository, file, seedPath, category ?? '']`, function scope deliberately NOT included) must be ported exactly, including the deliberate omission of `qid` from the discriminator.
- A matched expression with no access path must be recorded in an `unseedable[]` list, never silently dropped (§3.3).
- `seedEntryStateFactory`'s returned function must be a drop-in match for `driver.js`'s existing `opts.seedEntryState(fn) -> state | falsy` contract — confirm this by actually wiring it into a real `runFieldIdentityAnalysis` call in this task's own tests, not just by shape-matching the signature on paper.
- Every claim about seeding behavior (does it produce the exact same hop/node/edge counts E1 measured, does the field-vs-container rule actually change classification outcomes) must be demonstrated by running real code in this task against `test/fixtures/vulnerable-js` — re-measure, don't copy E1's own numbers forward uncritically (confirm they're still current; if `engine.js`'s receiver-identity hotfix or the subtype-nullability hotfix changed them, use the CURRENT numbers).
- Every existing test suite this task touches or reads from must keep passing — run `npm run test:lineage` before AND after any change.
- Follow this repo's root `CLAUDE.md` verification discipline throughout.

## Coordination with E3

E3 (`graph-builder.js`) has not started. Per `DESIGN_GRAPH_BUILDER.md` §9.1's absorption protocol: this task (E2) absorbs `E1/1`–`E1/5` and `E1/14` from `graph-builder-poc.test.js` into `source-seeding.test.js`, re-pointed at the shipped module — it must NOT delete the PoC file (E3 still needs its own projection-half tests, `E1/6`–`E1/13`, which remain in the PoC until E3 absorbs them). Confirm the PoC's own remaining content after this task's absorption is exactly the projection half, nothing more — if E3 has somehow already landed by the time this task executes (check git log), follow §9.1's actual current state instead of this plan's assumption.

---

### Task 1: Extract and ship `source-seeding.js`, absorb the seeding-half PoC tests

**Files:**
- Create: `scanner/src/lineage/source-seeding.js`
- Create: `scanner/test/lineage/source-seeding.test.js`
- Modify: `scanner/test/lineage/graph-builder-poc.test.js` (remove the seeding-half tests and the now-redundant local helper functions this task extracted — leave the projection-half content, e.g. `receiverJustified`/`resolveSinkAtCallSite`/`enumerateSinkSites`/`degradedTerminals`/`calleeDescriptor`/`buildDataFlowGraph` and `E1/6`–`E1/13`, fully intact for E3; the PoC's own shared fixture helpers `irOf`/`vulnerableJs` are used by BOTH halves — do not delete them from the PoC if E3's own tests still need them; instead, decide whether to duplicate them into the new permanent test file or keep them in a small shared test-fixture helper module, and state your choice explicitly in your report)
- Modify: `scanner/package.json` (wire the new test file into `test:lineage`)
- Modify: `scanner/src/lineage/CLAUDE.md` (new module-table row for `source-seeding.js` under a new "Sub-project E, increment 2" heading; update "What is NOT here yet" to move source-seeding out of the pending list)
- Read only: `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` in full, `scanner/test/lineage/graph-builder-poc.test.js` in full, `scanner/src/dataflow/catalog.js` (`matchSource`'s exact signature/return shape), `scanner/src/ir/access-paths.js` (`accessPathOf`), `scanner/src/lineage/source-registry.js` (`reclassifySource`), `scanner/src/lineage/classification.js` (`classifyDataElementName` — confirm the exact export name), `scanner/src/lineage/ids.js` (`dataElementId`), `scanner/src/lineage/driver.js` (the `opts.seedEntryState` hook's exact contract, already shipped — this task is the hook's first real consumer).

**Interfaces:**
- Consumes: `matchSource(expr, file)` from `../dataflow/catalog.js`; `accessPathOf(expr)` from `../ir/access-paths.js`; `reclassifySource(entry)` from `./source-registry.js`; `classifyDataElementName` (confirm exact export) from `./classification.js`; `dataElementId(canonicalName, discriminatorParts)` from `./ids.js`.
- Produces: `planSeeds(callGraph, opts)` → `{seeds, unseedable}` (per §3.3's seed-record shape, confirmed against the live PoC); `seedEntryStateFactory(seeds)` → `(fn) => state | undefined`, wired directly into `runFieldIdentityAnalysis`'s `opts.seedEntryState`.

- [ ] **Step 1: Read the spec and the PoC's exact implementation in full**

Read `DESIGN_GRAPH_BUILDER.md` §3 end to end. Read the PoC's `exprRoots`/`exprChildren`/`walkExpr`/`seedPathFor`/`planSeeds`/`seedEntryStateFactory` functions in full — these are the reference implementation to port, not to redesign. Confirm `opts.repository` (used in the `dataElementId` discriminator per §3.4) is passed through correctly end to end.

- [ ] **Step 2: Implement `source-seeding.js`**

Port `exprRoots`/`exprChildren`/`walkExpr`/`seedPathFor`/`planSeeds`/`seedEntryStateFactory` faithfully. `planSeeds(callGraph, {repository})` returns `{seeds, unseedable}`. Each seed record carries exactly the §3.3 shape: `{file, qid, nodeId, line, entryId, seedPath, canonicalName, category, coverageStatus, externality, reason, dataElementId, dataClasses}`. `seedEntryStateFactory(seeds)` groups seeds by function (`qid`) and returns a function building a seeded `field-identity.js` state (via `addIdentity`) for that function, or `undefined`/falsy for a function with no seeds — confirm this exactly matches what `driver.js`'s `opts.seedEntryState` hook expects by reading `driver.js`'s own current code, not by assuming the PoC got the contract right (the PoC predates the hook's own shipped form in some earlier iteration — cross-check).

- [ ] **Step 3: Write `source-seeding.test.js`, absorbing `E1/1`–`E1/5` and `E1/14`**

Port these six tests from the PoC, re-pointed at the shipped `source-seeding.js` + the shipped `driver.js`. At minimum, this must include:
- **The core "0 becomes N" proof** (absorbs `E1/1`/`E1/4`): the shipped driver, unseeded, still produces 0 hops on `vulnerable-js` (regression-proving the gap E2 closes didn't silently reopen elsewhere); with `source-seeding.js`'s real seeding wired in via `opts.seedEntryState`, produces the CURRENT correct hop/pnode/pedge counts on `vulnerable-js` — re-measure these yourself in this task, do not copy E1's own possibly-stale numbers (the engine-receiver-identity hotfix changed them once already, from 19/14/8 to 23/15/9; confirm this is still current after any other work that's landed since).
- **The field-vs-container seed-path rule** (absorbs `E1/2`): proves `req.body.password` seeds distinctly from `req.body`, and that `classifyDataElementName` succeeds on the field-level name where it fails on the container-level name — the exact §3.2 proof.
- **`dataElementId` discriminator correctness** (absorbs `E1/3`): all four directions — same name in two files → two ids; two fields in one file → two ids; the same field read twice in one file → one id; function scope NOT in the discriminator (two handlers in one file reading the same field → one id, not two).
- **The escalated engine limitation, now resolved** (absorbs `E1/14`): confirm the current, post-hotfix behavior (the mask-then-log fixture now produces real flows, not the pre-hotfix zero) — this test's assertions should already reflect the fix per the engine-receiver-identity hotfix's own commit; re-verify they're still correct in this task, don't just copy them forward.
- An `unseedable[]` test proving a matched expression with no access path is recorded, never silently dropped.

- [ ] **Step 4: Trim the PoC, decide the shared-fixture-helper question, and update wiring**

Remove the six absorbed tests and the now-redundant `exprRoots`/`exprChildren`/`walkExpr`/`seedPathFor`/`planSeeds`/`seedEntryStateFactory` functions from `graph-builder-poc.test.js`, leaving the projection-half content (`E1/6`–`E1/13` and their own helper functions) fully intact — confirm by running the trimmed PoC file alone and seeing exactly `E1/6`–`E1/13` (8 tests) still pass. Decide and document (in your report) how `irOf`/`vulnerableJs` (used by both halves) are shared going forward — do not leave the PoC unable to run its own remaining tests.

- [ ] **Step 5: `scanner/src/lineage/CLAUDE.md` update**

Add a `source-seeding.js` row under a new "Sub-project E, increment 2" heading (matching the exact heading style already established for increment 1), describing the module's role, the seed-path rule, the `dataElementId` discriminator, and the measured hop/node/edge counts on `vulnerable-js` (the numbers you actually measured in Step 3, not copied from this plan). Update "What is NOT here yet" to reflect source-seeding is done; E3 (`graph-builder.js`) is still pending.

- [ ] **Step 6: Run the scoped suite and doc-drift check**

```bash
cd scanner
npm run test:lineage
node ../scripts/check-doc-drift.mjs
```

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/source-seeding.js scanner/test/lineage/source-seeding.test.js scanner/test/lineage/graph-builder-poc.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
git commit -m "feat(lineage): implement source-seeding.js, close the 0-hops gap for real (Sub-project E, increment E2)"
```
