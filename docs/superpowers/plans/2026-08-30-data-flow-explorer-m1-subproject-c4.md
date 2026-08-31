# Data Flow Explorer — M1 Sub-project C, Increment 4: `path-store.js` (Design + PoC)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve, and prove against real parsed code, the design for `scanner/src/lineage/path-store.js` — the compact predecessor/provenance DAG structure that CONSUMES the hop-record stream C1-C3 already emit (intraprocedural fully instrumented since C2, interprocedural since C3) and turns it into a deduplicated, queryable graph, plus a new `pathId` (or equivalently-named) stable-ID function in `ids.js`. This is a design-and-PoC increment (mirrors C1's and C3 Task 1's own role in this sub-project), not a full implementation — it produces a committed design-doc addendum and a proof-of-concept regression test; full implementation (including wiring `path-store.js` into a real project-wide run) is a follow-up task appended to this same plan once the design lands.

**Architecture:** `path-store.js` is a NEW, pure-consumer module: it takes an iterable/array of hop records (the exact 14-field shape `DESIGN_PATH_PROVENANCE.md` §3/§13.0 define) and builds a DAG from them — it does not run analysis itself, does not import `engine.js`/`summaries.js`/`driver.js`'s internals, and has no dependency on how the hops were produced. This deliberately decouples `path-store.js`'s own correctness from Sub-project D/E's absence (there is currently no source registry, so a real project-wide driver run emits **zero** hops today — see `scanner/src/lineage/CLAUDE.md`'s C3 section, "driver+recorder path emits 0 hops" — `path-store.js` must be testable against a hand-fed hop array regardless of that gap, exactly the same testing strategy C1-C3's own test suites already use).

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` (the binding ADR for the hop-record shape this task consumes — read the whole document, but especially §2 (node granularity, the join rule, and the null-`fromPath`-is-an-annotation correction), §3 and §13.0 (the exact, final hop shape), §8 (worklist re-emission — "deduplicate at the consumer", i.e. THIS increment), §9 (disclosed imprecisions — §9.1 cross-join, §9.2 flow-insensitivity, §9.3 cyclic-DAG possibility, §9.5 unrepresented iteration-budget truncation — all of which `path-store.js` must either handle or explicitly, honestly decline to handle and say so) and `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md` (row C4 of §4's table, and §3's "recommended design direction" bullet on `path-store.js`'s own structure).

## Global Constraints

- `scanner/src/lineage/` may import PURE utilities from `scanner/src/dataflow/` but must NEVER import `dataflow/engine.js` or `dataflow/summaries.js`, and must never share mutable state with them (isolation principle, verified in every prior increment's review).
- `path-store.js` must NEVER import `engine.js`, `summaries.js`, or `driver.js` — it consumes their OUTPUT (a hop-record stream), never their internals. This is a stronger, additional isolation boundary this increment introduces on top of the existing dataflow-package boundary, and it is what lets `path-store.js` be tested with a hand-built hop array with zero dependency on a real analysis run.
- Every existing lineage test must keep passing (`npm run test:lineage`, 253/253 as of C3's merge) — verify before AND after any change.
- New stable-ID functions in `ids.js` must follow that file's existing convention exactly: `sha256` over a canonicalized, pipe-joined material string via the existing `_hash`/`_canon` helpers, truncated to `ID_HEX_LEN` (12 hex chars), prefixed by an entity-kind string (mirror `nodeId`/`edgeId`/`flowId`'s own shape — read `ids.js` in full before writing anything).
- Follow this repo's root `CLAUDE.md` verification discipline: every claim about behavior (does dedup work correctly, does cross-function stitching resolve the right node, is the structure genuinely compact rather than a materialized-path-list in disguise) must be demonstrated by running real code in this task, not asserted from reading.
- §18.4 of the PRD (quoted in the parent C-scoping doc) is binding on this structure even though its full implementation (bounded reconstruction, truncation count, prioritization) is C5's job, not this increment's: "Store a provenance DAG, not a list of every expanded path" and "Never translate 'path budget exhausted' into 'no path'" are constraints on the DATA STRUCTURE `path-store.js` builds, not just on a later query layer — this increment's design must not paint C5 into a corner where satisfying these constraints requires rearchitecting what C4 ships.

---

### Task 1: Resolve and document `path-store.js`'s design, with a proof-of-concept

**Files:**
- Modify: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` — add a new `## 14. path-store.js: the compact DAG (Sub-project C, increment 4)` section (after existing §13; do not renumber anything above it).
- Create: `scanner/test/lineage/path-store-poc.test.js` — a throwaway-named PoC test file (mirrors C1's and C3 Task 1's own precedent: the follow-up implementation task will likely absorb/replace this into a permanent test file once the design is accepted).
- Read only: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` (full document — this task needs the complete hop-shape and join-rule context, not just §13), `scanner/src/lineage/engine.js`, `scanner/src/lineage/summaries.js`, `scanner/src/lineage/driver.js` (to see every `recordHop` call site and understand exactly what shape of hop stream a real run produces), `scanner/src/lineage/ids.js` (the stable-ID convention this task's new function must match), `scanner/test/lineage/engine-provenance-interprocedural.test.js` (for the hand-seeding technique this task's own PoC will need to reuse, since a real driver run emits no hops today).

**Interfaces:**
- Consumes: the hop-record shape exactly as `DESIGN_PATH_PROVENANCE.md` §3/§13.0 define it (14 fields: `kind, subKind, scope, dataElementId, fromPath, toPath, syntacticPath, nodeId, line, widenReason, lossReason, context, peerScope, peerContext`). Do not invent or assume a different shape — read the CURRENT design doc text, not this brief's own paraphrase, since the shape has been corrected in place multiple times across C1-C3.
- Produces (for the follow-up implementation task to consume — do not implement these yet, just settle their exact shape in the addendum and prove them via the PoC):
  - `path-store.js`'s exported surface (function/class names, exact signatures) — a strong starting candidate, to evaluate and correct rather than treat as decided: a `PathStore` class (or equivalent) with a `addHop(hopRecord)` or `addHops(hopRecords)` method (matching the "consumes a stream" architecture) and query methods a later increment (C5) will build on — but C4 itself does NOT implement the backward-walk/reconstruction query, only the storage structure and whatever minimal read API is needed to prove the structure is correct in this task's own tests (e.g. "does this dataElementId have an edge from node A to node B").
  - The exact **node** representation and its stable ID — the design says a node is `(scope, accessPath, dataElementId)`, but this task must resolve two real complications found during scoping and NOT yet answered anywhere in the existing design doc:
    1. **Cross-function node addressing.** A `write-out` hop with non-null `peerScope`/`peerContext` (the `call-arg-bind` hop, §13.2) has its DESTINATION in the CALLEE's namespace, not the hop's own stamped `scope`/`context` — per §13.0's own rule ("the direction is read off `kind`... a `write-out` hop's peer is its *destination*"). Confirm: does this mean the destination node's identity is `(peerScope, toPath, dataElementId)` keyed against `peerContext` rather than `(scope, toPath, dataElementId)` keyed against `context`? Work this out with a real example (reuse `outer`/`middle`/`inner` or similar from the C3 test suite) and prove it, don't reason it out on paper alone.
    2. **The `call-resolved` hop's `fromPath: null` — does it ever contribute a real edge, or is it purely an annotation?** Per §2.2's own null-`fromPath`-is-an-annotation correction, a `production` hop with `fromPath: null` only forms a real edge when NO non-null in-half exists at the same join key — otherwise it annotates whatever real edge those non-null in-halves form. Trace through a real resolved-call scenario (e.g. `const out = helper(user); return out;`) and determine: what actually connects the CALLEE's own return value to the CALLER's `out` variable in the DAG? Is it the `call-resolved` hop's `peerScope`/`peerContext` pointing at a node inside the callee that some OTHER hop (a `return` write-out inside the callee) also names? If so, name exactly which hop and how the join works; if the current hop stream is **insufficient** to make this connection at all (a real, disclosable gap — not a design task failure to hide), say so explicitly and document it as a named limitation for a later increment to close, per this document's own stated culture of disclosing rather than hand-waving imprecision.
  - `pathId`'s (or whatever name Task 1 settles on) exact signature and discriminator fields, added to `ids.js` following that file's existing convention (see `nodeId`/`edgeId`/`flowId` for the pattern — a content hash over canonicalized parts, never a counter). Decide what uniquely identifies an EDGE in this DAG (candidate: `(fromNodeId, toNodeId, dataElementId, kind/subKind, widenReason, lossReason)` — but confirm against real duplicate-vs-distinct scenarios, mirroring the `flagship-fixture.mjs` precedent in this same package where an under-specified discriminator caused a real collision bug once already, per that module's own CLAUDE.md row).
  - The dedup strategy for repeated hops from a revisited CFG node (§8, "the worklist re-emits; deduplicate at the consumer" — THIS is that consumer). The test suite already has a `dedupeHops` helper (`JSON.stringify(h, Object.keys(h).sort())` as the key, per §13.0's own description) — decide whether `path-store.js` reuses an equivalent strategy internally, and where the dedup boundary sits (dedup raw hops before building nodes/edges, vs. dedup nodes/edges after building them from a possibly-duplicated hop stream — these are not equivalent when two DIFFERENT hop records happen to describe the same logical edge, e.g. via two different CFG paths reaching the same join).
  - How `path-store.js` stays honest about §9's disclosed imprecisions — specifically §9.3 (the DAG can genuinely be cyclic; the structure must not assume acyclicity, e.g. no naive unbounded recursive walk anywhere in this increment's own code, even though the actual bounded backward-walk query is C5's job) and §9.5 (the `ITER_BUDGET` truncation in `analyzeFunctionFieldIdentity`'s own worklist is currently unrepresented in the hop stream — decide whether this is in scope for C4 to represent structurally, e.g. reserving a field/convention now so C5 doesn't have to retrofit one later, or explicitly deferred with a stated reason).

- [ ] **Step 1: Read the current state (grounding, not a step that produces a diff)**

Read `DESIGN_PATH_PROVENANCE.md` in full (it is long — read it anyway; C3's own history shows real, load-bearing subtlety was missed by every reviewer who worked from a partial read). Read `engine.js`, `summaries.js`, `driver.js` in full to see every `recordHop` call site's exact emitted shape. Read `ids.js` in full. Read `engine-provenance-interprocedural.test.js`'s hand-seeding technique (how it gets real hop content without a working project-wide driver run).

- [ ] **Step 2: Build the PoC harness**

Write `scanner/test/lineage/path-store-poc.test.js`. Structure it around real parsed multi-function source (reuse or closely mirror fixtures already proven in C3's own test suite — do not invent new scenarios where an existing, already-debugged one covers the same ground), hand-seeding entry states and driving `analyzeFunctionFieldIdentity`/the real interprocedural resolver machinery exactly as `engine-provenance-interprocedural.test.js` already does, collecting the resulting hop stream, and feeding it into your prototype `path-store.js` implementation. At minimum, prove:

1. **A simple intraprocedural chain** (`const b = a.email; return b;`) produces a DAG with the expected 2-3 nodes and 1-2 edges, no more, no fewer — and that dedup collapses any hops the worklist re-emits from a revisited node.
2. **The cross-function node-addressing question** (interface bullet 1 above) — resolved and demonstrated, not just asserted.
3. **The `call-resolved`/return-value stitching question** (interface bullet 2 above) — resolved and demonstrated, including an honest test that FAILS (or is marked as a known gap) if the current hop stream genuinely cannot make the connection, rather than silently asserting something weaker than what the design doc claims.
4. **A cyclic call graph** (mutual recursion, reusing a B5-shaped fixture) — prove `path-store.js`'s own construction does not infinite-loop or stack-overflow, even though full cycle-safe QUERYING is C5's job.
5. **`pathId`'s collision behavior** — two structurally-different edges must never collide; the same logical edge encountered twice (e.g. via worklist re-visitation) must produce the identical id both times (idempotence, not just uniqueness).

- [ ] **Step 3: Decide, and write §14 of `DESIGN_PATH_PROVENANCE.md`**

Using Step 2's PROVEN results, write `## 14. path-store.js: the compact DAG (Sub-project C, increment 4)` with subsections mirroring §13's own style: exported surface and exact signatures; node/edge representation and identity; the `pathId` discriminator and its exact call site in `ids.js`; the dedup strategy; the cyclic-DAG-safety approach; the cross-function stitching mechanism (or the honest gap, if Step 2 found the hop stream insufficient); a short "what the follow-up implementation task must do" checklist in the same file/line-precise style §10.1/§10.2/§13.7 already established.

Update the parent scoping doc's own "recommended design direction" bullet for `path-store.js` (`docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md`, §3) if this task's actual design diverges from what was speculated there before any real code existed — note the divergence and why, don't silently ignore it.

- [ ] **Step 4: Verify nothing existing regressed**

Run `npm run test:lineage` from `scanner/`. All 253 pre-existing tests must still pass.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/DESIGN_PATH_PROVENANCE.md scanner/test/lineage/path-store-poc.test.js docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md
git commit -m "docs(lineage): design C4's path-store.js (compact DAG, pathId, cross-function stitching), with PoC"
```

---

## Post-Task-1 note

Task 1 landed as `DESIGN_PATH_PROVENANCE.md` §14 (commit `c53042c6`), reviewed with zero blocking findings (commit `8292287a` folds in the review's 4 most consequential findings directly — see the ledger). §14.10 is the accepted, binding file/line/signature checklist for Task 2 below; every reference in Task 2 is to that checklist's 13 rows.

---

### Task 2: Implement `path-store.js`, the two `ids.js` functions, and absorb the PoC into the permanent suite

**Files:**
- Create: `scanner/src/lineage/path-store.js` (§14.10 items 5-10)
- Modify: `scanner/src/lineage/ids.js` (§14.10 items 1-2)
- Modify: `scanner/test/lineage/ids.test.js` (§14.10 item 3)
- Rename/absorb: `scanner/test/lineage/path-store-poc.test.js` → `scanner/test/lineage/path-store.test.js`, re-pointed at the shipped module (§14.10 item 11)
- Modify: `scanner/package.json` — update the `test:lineage` script's file list to the renamed file (same commit as the rename, per §14.10 item 11 / C3's own item-15 precedent)
- Modify: `scanner/src/lineage/CLAUDE.md` — new module-table row for `path-store.js`, mirroring the style of every prior increment's own row
- Read only: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` §14 in full (§14.1 through §14.11 — this is the binding spec; the PoC file being absorbed is a prototype of it, not a substitute for reading it), `scanner/test/lineage/path-store-poc.test.js` (what you're absorbing and deleting the prototype halves of), `scanner/src/lineage/ids.js` in full (the convention `provenanceNodeId`/`provenanceEdgeId` must match exactly)

**Interfaces:**
- Consumes: the 14-field hop-record shape from §3/§13.0, exactly as C1-C3 shipped it. Consumes nothing from `engine.js`/`summaries.js`/`driver.js` directly — `path-store.js` must never import them (§14.1, §14.10 item 5's own enforcement test).
- Produces: `provenanceNodeId(...)`/`provenanceEdgeId(...)` in `ids.js` (§14.5's exact signatures — quoted in this plan's own text above, but confirm against the LIVE §14.5 before writing, the same discipline every prior increment's brief has required). `PathStore` from `path-store.js`: `addHop(hop) -> boolean`, `addHops(hops) -> number`, `markTruncated(scope, context, reason)`, plus the traversal-free read API §14.6 lists (`nodes()`, `edges()`, `getNode`, `getEdge`, `edgesFrom`, `edgesTo`, `hasEdge`, `nodeIdFor`, `stats`, `diagnostics`).

- [ ] **Step 1: Read §14 in full, then `ids.js` in full**

Do not start from the PoC file's prototype code as if it were the spec — it is a prototype OF the spec, written under this task's own predecessor's time pressure, and §14's prose (especially §14.2's node-kind table, §14.3's classification rules, §14.4's corrected join rule and its `lossReason === null` exception, §14.6's two dedup boundaries, §14.7's per-pairing ambiguity measure) is the authority when the two differ. Confirm `ids.js`'s exact current `_hash`/`_canon`/`ID_HEX_LEN` shape before writing the two new functions.

- [ ] **Step 2: `ids.js` — the two new stable-ID functions (items 1-3)**

Add `provenanceNodeId` and `provenanceEdgeId` immediately after the existing `edgeId` function, per §14.5's exact object-argument signatures (never `ids.js`'s usual positional-args form for these two — §14.5 explains why: a ten-field discriminator is exactly the shape a positional array silently drops a field from). Prefix `pnode:<kind>:` and `pedge:` respectively — **never** `node:`/`edge:`, which `validate.js` already regex-checks as `DataFlowGraph v1` entity prefixes (item 4: confirm `validate.js` needs literally no change, by running `npm run test:lineage` and confirming `json-schema-parity.test.js` stays green). Extend `test/lineage/ids.test.js` with the discriminator-separation and bulk-non-collision cases the PoC's own `C4/5`/`C4/5b` tests already prove — port them, don't reinvent.

- [ ] **Step 3: `path-store.js` — the module (items 5-10)**

Create the file. Imports: `ids.js` only (item 5) — add a test in the same file's test suite that reads `path-store.js`'s own source/import list and asserts no `engine.js`/`summaries.js`/`driver.js` import exists, so this boundary is enforced by a test, not just by discipline (a real prior increment's isolation violation would have been caught earlier by exactly this kind of self-checking test).

Define `HOP_FIELDS` as the explicit 14-field list from §3/§13.0, in a FIXED order (item 6) — never derive dedup/discriminator keys via `Object.keys(h)`, which is order-dependent and would let two differently-key-ordered-but-identical hop objects hash differently.

Implement `classifyIn`/`classifyOut` per §14.3's rules verbatim, including the `lossReason === null` exception in the peer-sourced branch (§14.4's correction — the single most load-bearing rule in this whole module, re-verify it against §14.4's live text one more time before writing it) and the `unclassified` fallthrough for anything §14.3 doesn't name.

Implement `PathStore` with the two-phase construction §14.6 describes (`addHop`/`addHops` accumulate into groups; nodes/edges materialize lazily on first read, cached until the next `addHop`) and BOTH dedup boundaries (raw-hop ingest dedup via the fixed-order `HOP_FIELDS` key; node/edge dedup via the content-hash ids from Step 2) — §14.6 is explicit these are not alternatives, ship both. Construction must be cycle-safe by construction (one linear pass plus a per-group cross product, never a graph walk) — no recursion anywhere in this file, matching §9.3/§14.6's "there is no recursion anywhere in this increment's code, by construction rather than by discipline."

Implement edge construction as the per-group cross product with the peer×peer exclusion (§14.3) and the per-pairing ambiguity measure — **not** the group-level measure §9.1's ORIGINAL text describes (§14.7's correction; the group-level form over-marks, confirmed by task review measuring it marking 3 of 5 edges at a plain resolved call including both correct call-boundary edges).

Implement `diagnostics()` returning `{ malformed, unclassified, truncations, orphanedPeerSources }` (item 10 — note the 4th bucket, `orphanedPeerSources`, added during Task 1's own review: a peer-sourced `call-resolved` hop, `lossReason: null`, whose named `(peerScope, peerContext, ⟨return⟩, dataElementId)` node has zero real in-edges once the whole stream is ingested — detectable via the store's own `inIndex`/`outIndex` at build-finalize time. Reachable via a cache warmed by a no-recorder run and reused by a later recorder-attached run, per §14.4's own disclosed precondition — record it, never fabricate an origin for it, never drop the edge). All four buckets: recorded, never thrown, never silently dropped.

- [ ] **Step 4: Absorb the PoC, rename it, wire it into `test:lineage` (item 11)**

Re-point `path-store-poc.test.js`'s tests at the shipped `path-store.js`/`ids.js` (delete the two local prototype blocks it currently carries), rename the file to `path-store.test.js`, and update `scanner/package.json`'s `test:lineage` script entry in the SAME commit — mirrors C3's own item-15 precedent exactly.

**Keep every assertion, and especially keep `C4/Q2b`** (item 12 — the literal-§2.2 store with a dead-end callee exit): it is the only guard that stops §14.4's correction being silently undone by a future refactor of `classifyIn`.

**Do not add a driver-level test yet** (item 13) — a driver run still emits zero hops today (no source registry, Sub-project D/E), so a driver test at this stage would assert on an empty stream and be vacuous, matching the exact reasoning `engine-provenance-interprocedural.test.js`'s own driver test note already states for the identical situation. Defer this to whichever later increment first makes a driver run hop-emitting.

- [ ] **Step 5: Close the 2 carried-forward findings from Task 1's review**

1. **(review finding 2)** §14.7's leg-based-pruning counter-example (`const o = { r: helper(a), s: b.email }`, proving the pruning rule the design considered and rejected would delete a genuine, purely-intraprocedural edge `b.email → o.s`) exists only as prose in the design doc and the task review's own report — it has no committed test. Add it as a real fixture in the permanent suite, asserting the bypass edge (`a.email → o.r`, skipping the callee) is present and marked `ambiguousCorrelation: true`, AND that the unrelated `b.email → o.s` edge is present and NOT marked. This is the test that makes §14.7's rejected-alternative reasoning re-verifiable rather than merely asserted in a design doc's prose.
2. **(review finding 3)** §14.11's measured-numbers table is mostly unpinned prose — only the simplest fixture's counts are asserted anywhere. Add explicit count assertions (nodes/edges/raw/dedup) for at least the §6 worked-example fixture (14 deduplicated records → 8 nodes / 6 edges — the FR-303 compactness proof this document treats as its headline result) and the mutual-recursion fixture, so a future refactor that silently changes these published numbers fails a test instead of just leaving `CLAUDE.md`/the design doc stale.

Nitpicks 7-10 from Task 1's review (return-node aggregation losing which return site fed a value — an undisclosed consequence for C5, worth one sentence in §14.2's `return` row if you have time; the §13.6 path-less-argument-at-a-degraded-call-site composite is untested; the PoC test file's prototype-export side effect; §14.10 item 6's `HOP_FIELDS` order being unnamed in the doc) are optional polish — address them if convenient, otherwise leave them for a later cleanup pass; none are load-bearing.

- [ ] **Step 6: `scanner/src/lineage/CLAUDE.md` — new module-table row**

Add a `path-store.js` row to the Sub-project C module table (or start a new "Sub-project C, increment 4" sub-table, matching how increments 1-3 got their own grouping), describing the module's role, the node-kind taxonomy (§14.2's table), the two dedup boundaries, and the `diagnostics()` contract — mirroring the density and citation style every prior row in this file already uses. Update "What is NOT here yet" to move C4 from "still ahead" to done, matching the exact edit pattern used after C3's own merge.

- [ ] **Step 7: Run the full scoped suite and doc-drift check**

```bash
npm run test:lineage
node ../scripts/check-doc-drift.mjs
```

Confirm the pre-existing `path-store.js` doc-drift item (`src/lineage/CLAUDE.md:75`, a forward reference to this exact file) is now RESOLVED — the file exists — and no new drift item appears.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/lineage/path-store.js scanner/src/lineage/ids.js scanner/test/lineage/ids.test.js scanner/test/lineage/path-store.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
git rm scanner/test/lineage/path-store-poc.test.js
git commit -m "feat(lineage): implement path-store.js, the compact DAG (Sub-project C, increment 4)"
```
