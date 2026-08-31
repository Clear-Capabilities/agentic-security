# Data Flow Explorer — M1 Sub-project E, Increment 3: `graph-builder.js`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract E1's already-designed-and-proven graph-projection mechanism out of its throwaway PoC (`test/lineage/graph-builder-poc.test.js`, its remaining half after E2 absorbed the seeding tests) into a real, permanent, shipped module — `scanner/src/lineage/graph-builder.js` — producing, for the first time in this codebase, a real, validated `DataFlowGraph v1` document from an actual repository's real code. This is mechanical implementation against an already-reviewed design (`DESIGN_GRAPH_BUILDER.md` §4-§8, all proven by E1's own PoC — `E1/6` through `E1/13` all currently pass), mirroring D1→D2/D3's own precedent and this sub-project's own E1→E2 precedent — the design phase is complete, this increment's job is to ship it as real, tested, permanent code, absorb the projection half of the PoC, and — per §9.1's protocol — delete the PoC entirely, since E2 already landed as the confirmed first-lander.

**Architecture:** `graph-builder.js` exports `buildDataFlowGraph(callGraph, opts)`. Internally: seeds via `source-seeding.js` (E2, already shipped), drives `runFieldIdentityAnalysis`, builds a `PathStore`, enumerates registry-backed sink candidates (§4 — replacing `sinkCandidates()`'s security-blind stand-in), resolves multi-candidate sink matches (§4.3 — promote by receiver, else plurality + `partial`), reconstructs paths per sink via `reconstructPaths`, projects the result into `nodes`/`edges`/`dataElements`/`transformations`/`flows` per §6's "a node is a registry decision" rule, and returns a `validateGraph()`-clean `DataFlowGraph v1` envelope. Consumes `sink-registry.js`/`transform-catalog.js` (already shipped), `source-seeding.js` (E2, already shipped), `path-store.js`/`path-query.js`/`flow-grade.js` (already shipped), `ids.js`/`schema.js`/`protection.js`/`validate.js` (Milestone 0, already shipped). Does NOT touch any of these — this increment is a new module consuming all of them.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` §4 through §8 in full (§4 registry-backed sink enumeration, §5 the §16.7 enumerator, §6 the projection rule, §7 transformations, §8 flow/edge defaults) and §9.3 (E3's own file-precise checklist) — this is the binding ADR; every rule this task implements is already specified and proven there. Also read `test/lineage/graph-builder-poc.test.js` in full — specifically `receiverJustified`/`resolveSinkAtCallSite`/`enumerateSinkSites`/`degradedTerminals`/`calleeDescriptor`/`buildDataFlowGraph` (the exact functions this task extracts) and `E1/6` through `E1/13` (the tests this task absorbs) — treat the PoC's own code as the reference implementation to port faithfully, and `DESIGN_GRAPH_BUILDER.md`'s prose as authoritative for the DECISION PROCEDURE if the two ever seem to differ (§9.1's own stated policy: "Where this document and that PoC disagree, the PoC is right and this document is stale — fix it here, do not fork it").

## Global Constraints

- `graph-builder.js` must mirror `dataflow/index.js`'s `runDeepAnalysis` SHAPE (an opt-in, best-effort orchestration entry point) and import NOTHING from it (§9.3 item 1) — this task builds `buildDataFlowGraph` itself, not a wrapper calling `dataflow/index.js`.
- Must NOT modify `source-seeding.js`, `driver.js`, `path-store.js`, `path-query.js`, `flow-grade.js`, `engine.js`, `field-identity.js`, `source-registry.js`, `sink-registry.js`, `transform-catalog.js`, `schema.js`, `validate.js`, `ids.js`, `classification.js`, or `protection.js` — this increment is a NEW module consuming all of these as already-shipped, already-correct dependencies.
- **One real discrepancy the implementer must resolve, not silently pick one side of**: `DESIGN_GRAPH_BUILDER.md` §9.3 item 1 states the signature as `buildDataFlowGraph(perFileIR, callGraph, opts)` (three arguments), but the PoC's own shipped, tested implementation is `buildDataFlowGraph(callGraph, opts)` (two arguments — it never uses a separate `perFileIR` parameter, reading everything it needs from `callGraph.functions[*].cfg`). Per §9.1's own stated policy, the PoC is authoritative where the two disagree — ship the PoC's actual two-argument signature, and correct §9.3 item 1's prose to match in this task's own doc update (do not silently diverge; name the correction explicitly).
- Ship the four assertions `validate.js` structurally cannot make (§9.3 item 3, `E1/8`'s own proven checks): every `subtype` is in the registry vocabulary or `null`; every `node.dataElementIds` entry is referentially sound; no two DIFFERENT registry decisions collided onto one node id; no `pedge:`/`ppath:` id ever appears in `flow.edgeIds`.
- Determinism (§9.3 item 4): sort every entity array by id before emit; `generatedAt` must be injectable via `opts.generatedAt` (confirm this is already correct in the ported code — the PoC already does this) rather than defaulting to `new Date().toISOString()`.
- The projection rule (§6.1 — a node is a registry decision, never a provenance node, never a call site) must be ported EXACTLY as the PoC implements it (`mintNode`'s id discriminator: `[repository, subtypeKey ?? category ?? '', coverageStatus, externality, '']`) — this is the single most consequential design decision in the whole sub-project, and E1's own review independently confirmed it is sound (bounded by taxonomy, not repository size; measured constant at 9 nodes across a 200× scale test).
- Multi-candidate sink resolution (§4.3) must be ported exactly: promote via the receiver that actually matched where possible; else unanimous category among survivors; else plurality at `coverageStatus: 'partial'` with a reason naming the alternatives — never a silent pick.
- The §16.7 enumerator (§5 — the `diagnostics()`-union mechanism, NOT a new `path-store.js` node kind) must be ported exactly as proven.
- Every claim about the graph output (does it validate, does the node count stay taxonomy-bounded, do the four validator-blind-spot assertions actually catch a real violation) must be demonstrated by running real code in this task against `test/fixtures/vulnerable-js` — re-measure, don't copy E1's own numbers forward uncritically; confirm they're still current given the receiver-identity and subtype-nullability hotfixes that landed since E1.
- Every existing test suite this task touches or reads from must keep passing — run `npm run test:lineage` before AND after any change.
- Follow this repo's root `CLAUDE.md` verification discipline throughout.

## Coordination: this task is the confirmed second-lander

Per `DESIGN_GRAPH_BUILDER.md` §9.1's absorption protocol: E2 (already merged) absorbed `E1/1`–`E1/5` and `E1/14` and deliberately did NOT delete `test/lineage/graph-builder-poc.test.js`, leaving the projection half (`E1/6`–`E1/13`) intact for this task. **This task is therefore the confirmed second-lander** — after absorbing `E1/6`–`E1/13` into `graph-builder.test.js`, this task deletes `test/lineage/graph-builder-poc.test.js` entirely, removes it from `package.json`'s `test:lineage` script, and removes its row from `scanner/src/lineage/CLAUDE.md`. Confirm this state (the PoC still exists, contains only the projection half) at the start of this task by reading the file directly — do not assume this plan's own description is still current if other work has landed since.

---

### Task 1: Extract and ship `graph-builder.js`, absorb the projection-half PoC tests, delete the PoC

**Files:**
- Create: `scanner/src/lineage/graph-builder.js`
- Create: `scanner/test/lineage/graph-builder.test.js`
- Delete: `scanner/test/lineage/graph-builder-poc.test.js` (confirmed second-lander per §9.1's protocol — see Coordination above)
- Modify: `scanner/package.json` (wire the new test file into `test:lineage`; remove the PoC's entry)
- Modify: `scanner/src/lineage/CLAUDE.md` (new module-table row for `graph-builder.js` under a new "Sub-project E, increment 3" heading; remove the PoC's own row; update "What is NOT here yet" to reflect graph output now exists)
- Read only: `scanner/src/lineage/DESIGN_GRAPH_BUILDER.md` in full, `scanner/test/lineage/graph-builder-poc.test.js` in full (before deleting it), `scanner/src/lineage/source-seeding.js` (E2, already shipped), `scanner/src/lineage/sink-registry.js` (`reclassifySink`/`reclassifyPrivacySink`), `scanner/src/lineage/transform-catalog.js` (`recognizeTransformation`), `scanner/src/lineage/path-store.js`/`path-query.js`/`flow-grade.js`, `scanner/src/lineage/ids.js`/`schema.js`/`protection.js`/`validate.js`, `scanner/src/dataflow/catalog.js` (`matchSinkOrSanitizer`).

**Interfaces:**
- Consumes: `planSeeds`/`seedEntryStateFactory` from `./source-seeding.js`; `runFieldIdentityAnalysis` from `./driver.js`; `PathStore` from `./path-store.js`; `reconstructPaths`/`sinkCandidates` (or its registry-backed replacement) from `./path-query.js`; `gradeHop`/`gradePath` from `./flow-grade.js`; `reclassifySink`/`reclassifyPrivacySink` from `./sink-registry.js`; `recognizeTransformation` from `./transform-catalog.js`; `matchSinkOrSanitizer` from `../dataflow/catalog.js`; `nodeId`/`edgeId`/`dataElementId`/`flowId`/`transformationId`/`graphId` from `./ids.js`; `emptyGraphEnvelope` from `./schema.js`; `emptyProtection` from `./protection.js`; `validateGraph` from `./validate.js`.
- Produces: `buildDataFlowGraph(callGraph, opts)` → a `validateGraph()`-clean `DataFlowGraph v1` envelope (confirm the PoC's actual two-argument signature per the Global Constraints note above).

- [ ] **Step 1: Read the spec and the PoC's exact implementation in full**

Read `DESIGN_GRAPH_BUILDER.md` §4 through §9.3 end to end. Read the PoC's `receiverJustified`/`resolveSinkAtCallSite`/`enumerateSinkSites`/`degradedTerminals`/`calleeDescriptor`/`buildDataFlowGraph` functions in full — these are the reference implementation to port, not to redesign. Confirm the exact two-argument signature discrepancy named in Global Constraints and resolve it as instructed there.

- [ ] **Step 2: Implement `graph-builder.js`**

Port `receiverJustified`/`resolveSinkAtCallSite`/`enumerateSinkSites`/`degradedTerminals`/`calleeDescriptor`/`buildDataFlowGraph` faithfully — these functions already import `exprRoots`/`walkExpr` from `source-seeding.js` in the trimmed PoC (per E2's own resolution of the shared-helper question); confirm this import is correct in the shipped module too, don't accidentally duplicate those helpers. `buildDataFlowGraph` must: seed and drive the analysis; build the `PathStore`; enumerate sink candidates via the registry-backed mechanism (§4, replacing `sinkCandidates()`); resolve multi-candidate matches (§4.3); reconstruct and project into the graph envelope (§6-§8); return a graph that `validateGraph()` accepts.

- [ ] **Step 3: Write `graph-builder.test.js`, absorbing `E1/6`–`E1/13`**

Port these eight tests from the PoC, re-pointed at the shipped `graph-builder.js`. At minimum, this must include:
- **A validated graph on real code** (absorbs `E1/6`): `buildDataFlowGraph` on `vulnerable-js` produces a `validateGraph()`-clean envelope. Re-measure the exact current node/edge/flow counts yourself — do not copy E1's own possibly-stale numbers (E1 measured 9 nodes at 1×/10×/50×/200× scale; confirm this is still current after the receiver-identity and subtype-nullability hotfixes).
- **The node-count invariance proof** (absorbs `E1/7`): node count stays taxonomy-bounded (roughly constant) as the input scales, never bounded by repository size.
- **The four validator-blind-spot assertions** (absorbs `E1/8`): every `subtype` ∈ the registry vocabulary or `null`; every `node.dataElementIds` entry referentially sound; no two DIFFERENT registry decisions collided onto one node id (construct a case where this WOULD happen if the discriminator were wrong, and confirm the guard catches it); no `pedge:`/`ppath:` id in `flow.edgeIds`.
- **Multi-candidate sink resolution on real code** (absorbs `E1/9`): `res.send(x)`-shaped call promotes via receiver; a bare/ambiguous `send(x)` demotes to `partial` with alternatives named.
- **The §16.7 enumerator firing correctly** (absorbs `E1/10`): fires on real degraded code at a tight context cap, does NOT fire when the cap is generous enough that nothing degrades.
- **Transformation recognition end to end** (absorbs `E1/11`): a recognized `mask` call produces a real transformation entity; an unrecognized call produces an honest `unknown`; no control-credit key appears anywhere in the output.
- **The reuse boundary** (absorbs `E1/12`): confirm `graph-builder.js`'s own import list is exactly what's intended — mirror the self-checking pattern every sibling module in this package already uses (`path-query.js`'s exact `['./ids.js']` list, `source-seeding.js`'s exact `dataflow/` import pair, etc.).
- **AC-11's coarse half + ledger counts** (absorbs `E1/13`): a disconnected source/sink still appears in `nodes[]` with its `coverageStatus`/reason, participating in no flow.

- [ ] **Step 4: Confirm second-lander status, then delete the PoC**

Confirm (per the Coordination section above) `test/lineage/graph-builder-poc.test.js` currently contains ONLY the projection half (E2 already absorbed and removed the seeding half). Delete the file entirely, remove its entry from `package.json`'s `test:lineage` script, and remove its row from `scanner/src/lineage/CLAUDE.md`'s module table.

- [ ] **Step 5: `scanner/src/lineage/CLAUDE.md` update**

Add a `graph-builder.js` row under a new "Sub-project E, increment 3" heading, describing the module's role, the projection rule, multi-candidate resolution, the four validator-blind-spot assertions, and the measured node/edge/flow counts on `vulnerable-js` (the numbers you actually measured in Step 3, not copied from this plan). Update "What is NOT here yet" — this is the FIRST increment in this entire sub-project whose deliverable is a real `DataFlowGraph v1` document from real code; state this plainly. E4 (coverage ledger, FR-203 closure) and E5 (scan-path wiring) are still pending.

- [ ] **Step 6: Run the scoped suite and doc-drift check**

```bash
cd scanner
npm run test:lineage
node ../scripts/check-doc-drift.mjs
```

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/graph-builder.js scanner/test/lineage/graph-builder.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
git rm scanner/test/lineage/graph-builder-poc.test.js
git commit -m "feat(lineage): implement graph-builder.js, produce a real DataFlowGraph v1 from real code (Sub-project E, increment E3)"
```
