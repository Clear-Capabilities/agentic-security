# Data Flow Explorer — M1 Sub-project C, Increment 3: Interprocedural Hop Recording (Design + PoC)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve, and prove against real parsed code, the exact design for extending Sub-project C's path-provenance hop recording (increments C1-C2, both merged) across function-call boundaries — closing the three `ctx`-threading holes and the entry-context join-key gap that `DESIGN_PATH_PROVENANCE.md` §7.4 and §9.4 already named as C3's job. This is a design-and-PoC increment (mirrors C1's own role in this sub-project), not a full implementation — it produces a committed design-doc addendum and a proof-of-concept regression test; the mechanical wiring across `summaries.js`/`driver.js`/`engine.js` is a follow-up task appended to this same plan once the design lands.

**Architecture:** No change to `field-identity.js`'s core state shape (the isolation principle every prior increment has verified holds). The existing `ctx.recordHop`/`ctx.resolveCallSummary` threading mechanism (Decision 1, Decision 7) is extended, not replaced: `resolveCallSummary`'s call signature gains a `ctx` parameter so a caller's recorder can reach a resolved callee's own analysis; `entryStateFromCall` gains a hop-emission site for the argument→parameter binding; `analyzeFunctionFieldIdentity`'s existing per-node hop stamping (`stepCtx`, engine.js:864-866) gains an additional `context` field on every hop so hops from different entry contexts of the same function no longer collide on the same join key.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:** `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` (the binding ADR — read the whole document, but especially §7.4, §8, §9.1-§9.5, §10.3, §12) and `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-c-scoping.md` (the parent sub-project scoping doc, row C3 of §4's table).

## Global Constraints

- `scanner/src/lineage/` may import PURE utilities from `scanner/src/dataflow/` (e.g. `access-paths.js`) but must NEVER import `dataflow/engine.js` or `dataflow/summaries.js`, and must never share mutable state with them (isolation principle, verified in every prior increment's review).
- Zero behavior change to any existing caller that does not supply `ctx.recordHop` — every new site this task designs must be additive and no-op-when-absent, matching Decision 1.
- Every existing lineage test must keep passing (`npm run test:lineage`, 236/236 as of C2's merge) — verify before AND after any change, including throwaway PoC code.
- `FieldIdentitySummaryCache`'s `_recursive` flag is stripped before a summary is ever returned externally (summaries.js:217-222) — any new flag this task designs for degradation-marking must follow the same discipline: either also stripped before external use, or deliberately and explicitly a permanent, documented field. Do not leave an internal-only flag leaking into a cached summary's externally-visible shape without a stated reason.
- Follow this repo's root `CLAUDE.md` verification discipline: every claim about behavior (does a cache hit suppress hops, does the context field disambiguate correctly) must be demonstrated by running real code in this task, not asserted from reading.

---

### Task 1: Resolve and document C3's interprocedural hop-recording design, with a proof-of-concept

**Files:**
- Modify: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` — add a new `## 13. Interprocedural hop recording (Sub-project C, increment 3)` section (after existing §12; do not renumber anything above it).
- Create: `scanner/test/lineage/engine-provenance-interprocedural-poc.test.js` — a throwaway-named PoC test file (the mechanical-implementation task that follows this one will likely replace or absorb it into the main `engine-provenance.test.js` suite; keep it isolated here so this task's own scope is easy to review and revert if the design changes).
- Read only: `scanner/src/lineage/engine.js`, `scanner/src/lineage/summaries.js`, `scanner/src/lineage/driver.js`, `scanner/src/lineage/field-identity.js`, `scanner/test/lineage/engine-provenance.test.js` (to see the existing hop-record assertion style — this determines whether adding a `context` field to every hop record is truly additive or breaks existing exact-shape assertions).

**Interfaces:**
- Consumes: the existing `ctx.recordHop`/`ctx.resolveCallSummary` mechanism exactly as C1/C2 left it. Key facts already true in the merged code (verify, don't re-derive):
  - `analyzeFunctionFieldIdentity(fn, entryState, ctx)` (engine.js:837) builds a per-node `stepCtx` that wraps `ctx.recordHop` to stamp `{scope: fn.qid, nodeId: nid, line: node.line ?? null, ...h}` onto every hop (engine.js:848, 864-866). This is the ONE place hops are stamped with function identity today.
  - `resolveExprIdentities`'s `case 'call'` (engine.js:489-523) calls `ctx.resolveCallSummary(expr.callee, expr.args ?? [], state)` — **no `ctx` is passed to `resolveCallSummary` itself**. This is one of the three holes (§7.4).
  - `entryStateFromCall(paramNames, callArgs, callerState)` (summaries.js:286-299) calls `resolveExprIdentities(callerState, callArgs[i])` with **no `ctx` at all** — the second hole, and also the site where a new argument→parameter binding hop must be emitted (this hop type does not exist yet; C1/C2 only instrumented single-function analysis).
  - `createCallSummaryResolver`'s returned closure (summaries.js:333-361) constructs a **fresh** `{ resolveCallSummary }` object for the callee's own `analyzeFunctionFieldIdentity` call (summaries.js:357), discarding any `recordHop` the caller had — the third hole.
  - `runFieldIdentityAnalysis` (driver.js:52-96) does the same fresh-`{ resolveCallSummary }` construction for every top-level function (driver.js:65) — the project-wide entry point has no way to pass a recorder in at all today.
  - `contributingKeys(state, path, id)` is exported from engine.js (engine.js:99-101) for exactly this kind of cross-file provenance need — the internal `contributingKeysAllIds(state, path)` (engine.js:76-87) is NOT exported; reuse `contributingKeys` rather than exporting the internal helper unless you find a real reason the per-id wrapper is insufficient (document that reason if so).
  - `FieldIdentitySummaryCache.compute(qid, entryState, analyzeFn)` (summaries.js:76-227) MEMOIZES: `analyzeFn` (which is what would emit hops, transitively) only runs on a cache MISS. A second call site resolving the SAME `(qid, entryState)` key gets the cached summary WITHOUT `analyzeFn` running again — meaning, under a naive wiring, the callee's own internal hops fire once, for whichever call site happened to trigger the miss, and never again for a later cache-hitting call site. This is not hypothetical — B1-B6 already build and test caches with `maxContextsPerFn` as low as 1, and the driver (`driver.js`) analyzes every function in a project, so cache hits are the common case, not an edge case.
- Produces (for the follow-up implementation task to consume — do not implement these yet, just settle their exact shape in the addendum and prove them via the PoC):
  - The exact new signature for `resolveCallSummary` (does it become `(calleeExpr, callArgs, callerState, ctx)`? Where exactly does `case 'call'` change to pass its own `ctx` through?).
  - The exact new signature for `entryStateFromCall` (an added `ctx` parameter — confirm parameter position and whether `driver.js`/`createCallSummaryResolver`'s call sites of `entryStateFromCall` both need updating).
  - The exact shape of the new argument→parameter-binding hop record (kind/subKind — recommend `kind: 'write-out', subKind: 'call-arg-bind'`, matching how a normal `assign`'s write-out hop already represents "an identity lands at a new state key," but confirm or correct this by checking whether `kind: 'production'` fits better given Decision 2's "half-edges are production/selection/write-out" taxonomy and how the existing `call-resolved` production hop (engine.js:512-520) already uses `kind: 'production'` for a call's OUTPUT side — the binding hop is the call's INPUT side, so reason about which of the three types the INPUT direction is closer to and justify the choice in the addendum), what `fromPath`/`toPath` are (use `contributingKeys` against the argument's own `accessPathOf(...)` result, mirroring Decision 6's existing pattern; `toPath` is `paramName` or `paramName.subPath`), and how a non-path-shaped argument (e.g. a literal, a nested unresolved call) is represented (recommend `fromPath: null`, consistent with how other sites already handle "no state key to point to").
  - The exact `context` field mechanics: what value (recommend `hashState(entryState)`, reusing the exact primitive `FieldIdentitySummaryCache` already keys on, per §9.4's own suggestion), where it is computed and stamped (recommend: alongside `scope` at engine.js:848, added to the `stepCtx` wrapper's spread at engine.js:864-866 — this makes it stamp EVERY hop automatically, requiring zero change at each of the 15 individual `recordHop` call sites C1/C2 already instrumented), and — the concrete thing this task must actually verify by running code — whether adding this field to every hop record breaks any existing assertion in `engine-provenance.test.js`. If it does, the addendum must say so explicitly and the follow-up task inherits the job of updating those assertions; if it doesn't (because existing tests check hop objects by matching on specific fields via `.find()`/`.filter()` rather than exact-object `deepEqual`), say that too, with the evidence (which test(s) you checked).
  - A decided, evidence-based answer to the cache-hit hop-suppression question above: does this increment (a) accept it as a disclosed limitation (only the FIRST call site to reach a given `(qid, entryState)` gets that callee's internal hops recorded; every later cache-hitting call site gets only its own `call-arg-bind`/`call-resolved` hops, not the callee's internals) and document it in §9 alongside the other disclosed imprecisions, or (b) require a real fix (e.g. the cache storing a hop list per summary and replaying it on every hit). Build the PoC FIRST (two call sites to the same callee under the same entry context, one deliberately after the other so the second is a guaranteed cache hit) and let the actual observed behavior — not a prediction — decide which path the addendum recommends. If (b), scope how much a follow-up task would need to change (this task does not have to implement it, only size it honestly).
  - A decided answer on `hopSite` / call-site identity (§7.4's last paragraph, "there is also a missing call-site identity problem"): is stamping the call site's own `{scope, nodeId, line}` onto a cross-function hop in scope for THIS increment, or does the existing `call-resolved` production hop (already recorded at the CALLER's own node, since it's emitted inside `resolveExprIdentities`'s `case 'call'`, which already runs under the caller's `stepCtx`) already carry enough call-site identity for what C4/C5 need from provenance at this stage? Decide and justify; do not leave it unstated.
  - A decided answer on B5/B6 degradation marking: when `case 'call'`'s resolved branch (engine.js:504-523) receives a summary that came from a `_recursive` bottom-stub round (B5) or a context-cap degradation (B6, `FieldIdentitySummaryCache.compute`'s `seen.size >= this._maxContextsPerFn` branch, summaries.js:113-123), should the `call-resolved` hop it emits be marked differently (a new `lossReason` value, e.g. `'recursion-bottom-stub'` or `'context-cap-degraded'`)? This requires the summary object to carry a non-transient signal distinguishing "this summary is honestly incomplete because of B5/B6" from "this summary is precise" — `_recursive` is stripped before return (summaries.js:217-222) specifically because it's a transient recursion-in-progress marker, not a persistent quality signal, so a NEW field is needed if this is in scope. Decide whether this is in THIS increment's scope (recommend: yes, it's cheap — a boolean set once in `FieldIdentitySummaryCache.compute`'s cap-degradation branch and never cleared, since a degraded summary stays degraded even once cached) or deferred to C4 (where it might more naturally live as an edge-grading concern shared with C6's FR-306 work); justify whichever you pick.

- [ ] **Step 1: Read the current state (grounding, not a step that produces a diff)**

Read, in full: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` §7.4, §8, §9.1-§9.5, §10.1-§10.3, §12; `scanner/src/lineage/engine.js` (the whole file — it's ~900 lines and every existing `recordHop` call site is relevant context for matching this increment's new hops to the established shape/style); `scanner/src/lineage/summaries.js` (the whole file); `scanner/src/lineage/driver.js` (the whole file); `scanner/test/lineage/engine-provenance.test.js` (to learn the existing assertion idioms — specifically note whether any test does `assert.deepEqual(hops, [...])` against a full array of exact hop objects, versus `.filter()`/`.find()` style checks on specific fields, since this determines the additive-vs-breaking answer for the new `context` field).

- [ ] **Step 2: Build the interprocedural PoC harness**

Write `scanner/test/lineage/engine-provenance-interprocedural-poc.test.js`. It does not need to pass yet at this step — it is how you PROVE each design decision below, not a spec you're implementing blind. Structure it around one real parsed multi-function source (use `parseJsFile` from `../../src/ir/parser-js.js`, matching the import style `engine-provenance.test.js` already uses) with at least these scenarios, each as its own `test(...)`:

```js
const src = `
  function inner(u) { return { v: u.email }; }
  function middle(u) { const r = inner(u); return r; }
  function outer(a, b) {
    const x = middle(a);   // call site 1 to middle
    const y = middle(b);   // call site 2 to middle, SAME qid, potentially same/different entry context
    return { x, y };
  }
`;
```

1. **Argument binding hop scenario:** analyze `middle` alone (not through the cache/driver) with a hand-built `ctx` carrying `resolveCallSummary` (a stub that returns a canned summary for `inner`) and `recordHop` collecting into an array. Call `entryStateFromCall(['u'], [middleCallArgExpr], callerState, ctx)` — this call will fail until you've decided and prototyped the new signature; that failure, and fixing it, IS how you settle the signature. Assert a `call-arg-bind`-shaped hop appears with the right `fromPath`/`toPath`/`dataElementId`.

2. **Two-hole-closure scenario (the real fix):** run `outer` through a **real** `FieldIdentitySummaryCache` + `createCallGraphLookup`-style lookup (hand-built `lookupCallee` mapping `middle`/`inner` to their parsed `fn` records is fine — no need for the real `callgraph.js` here) with a `recordHop` collector attached at the TOP (outer's own `ctx`), and prove that hops recorded **inside `inner`'s own analysis** (e.g. its `ident`/`member` hops for `u.email`) show up in the collector when reached via `outer` → `middle` → `inner`'s two-hop resolved chain. Before your fix, this must FAIL (no hops from `inner` appear at all, since none of the three holes are closed) — run it, capture the failure, THEN apply your fix and show it passes. This is the load-bearing proof for holes 2 and 3.

3. **Cache-hit suppression scenario:** with a `maxContextsPerFn` cache and BOTH `outer`'s calls (`middle(a)`, `middle(b)`) resolving to the SAME entry context (e.g. both `a` and `b` carry the identical seeded identity, so `hashState` collides), run the full analysis and count how many hops attributable to `middle`'s OWN internal analysis (not the call-arg-bind or call-resolved hops, which fire per call site regardless) appear in the collector. If your two-hole-closure fix from scenario 2 is wired the straightforward way (hops recorded during `analyzeFn`, only invoked on a cache miss), this count will be for ONE call site's worth, not two — run it and confirm what actually happens, do not assume.

4. **Context-disambiguation scenario:** reproduce §9.4's own worked example almost verbatim — `function g(x) { const y = x; return y; }` called once under context A (`x.email` seeded) and once under context B (`x` itself seeded, coarser) — through the real cache (two distinct entry states, so BOTH compute, no cache-hit suppression to worry about here). Collect hops from both calls into one array (as if a project-wide driver had run both). Without your `context` field, show (assert, then remove the assertion or invert it once fixed) that a naive join on `(scope, nodeId, dataElementId)` alone would conflate hops from the two contexts (reconstruct the exact failure §9.4 describes: 2 in-halves × 2 out-halves = 4 joinable pairs, 2 of which never happened in either real context). With your `context` field added and folded into the join key, show the false pairs are excluded when joining is done correctly (`(scope, nodeId, dataElementId, context)`).

5. **Degradation-marking scenario (only if Step 3's decision puts this in scope):** force a context-cap degradation (`maxContextsPerFn: 1`, two distinct calling contexts to the same callee) or a recursion bottom-stub round, and confirm the `call-resolved` hop recorded at the CALLING site carries whatever new `lossReason`/marker value you decided on, versus a precise resolution's hop which does not.

- [ ] **Step 3: Decide, and write §13 of `DESIGN_PATH_PROVENANCE.md`**

Using Step 2's PROVEN results (not predictions), write `## 13. Interprocedural hop recording (Sub-project C, increment 3)` with subsections mirroring the existing document's style (short prose decisions, each justified, each naming the exact file/line/signature it binds):

- §13.1 The `resolveCallSummary` signature change and its one call site.
- §13.2 The argument→parameter binding hop (`entryStateFromCall`'s new hop, exact shape).
- §13.3 The `context` field: what it is, where it's stamped, the join-key update `(scope, nodeId, dataElementId)` → `(scope, nodeId, dataElementId, context)`, and whether it breaks any existing test (name the file(s) if so).
- §13.4 The cache-hit hop-suppression finding: what you observed in Step 2's scenario 3, and whether this increment accepts it as a disclosed limitation (extend §9 with a new §9.6) or requires the bigger cache-replay fix (if so, size it — do not implement it in this task).
- §13.5 The `hopSite`/call-site-identity decision (in scope now, or deliberately deferred — say to which later increment and why).
- §13.6 The B5/B6 degradation-marking decision (in scope now or deferred to C4/C6, and why).
- §13.7 A short "what the follow-up implementation task must do" checklist — exact files, exact signatures, exact new hop sites — written the way §10.1/§10.2 were written for C2, since that checklist is what makes the next task's brief possible to write without re-deriving any of this.

Update §12 ("What this document deliberately does NOT decide") to remove anything §13 now resolves, and add anything §13 explicitly punts further (mirroring how C1's own document evolved).

- [ ] **Step 4: Verify nothing existing regressed**

Run `npm run test:lineage` from `scanner/`. All 236 pre-existing tests must still pass — this task has not touched any of the C1/C2 instrumentation sites yet (that's the follow-up task's job), only added new, isolated files/sections, so this should be a clean pass; if it is not, something in Step 2's PoC accidentally imported/mutated shared state and needs isolating.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/DESIGN_PATH_PROVENANCE.md scanner/test/lineage/engine-provenance-interprocedural-poc.test.js
git commit -m "docs(lineage): design C3's interprocedural hop recording (context field, three ctx holes, cache-hit finding), with PoC"
```

---

## Post-Task-1 note

Task 1 landed as `DESIGN_PATH_PROVENANCE.md` §13 (commit `a2d42695`), a fix round closing one blocking backward-compat finding (commit `fa27354e`), and a small text-only correction to the fix round's own guard wording (commit `a8846463`) applied directly after a scoped re-review confirmed the design otherwise ready. §13.7 is the accepted, binding file/line/signature checklist for the two implementation tasks below — every reference in Tasks 2-3 is to that checklist's 18 rows (items 1-17 plus 15b), which a scoped re-review independently verified against live source line-by-line.

Split rationale: §13.7's checklist is one cohesive deliverable, but its 3 source files plus test suite is too much for one dispatch. Task 2 delivers "the three `ctx` holes are closed and the context field disambiguates entry contexts, end to end, provably" — the load-bearing correctness work, including the golden-baseline regression (item 15b) that guards the exact hazard Task 1's fix round found, added at the same time the hazard's fix lands rather than deferred. Task 3 delivers B5/B6 degradation marking (a smaller, lower-risk addition sharing `summaries.js`) and retires the PoC file into the permanent suite (item 15) only once everything it was proving is covered by permanent tests — never before.

---

### Task 2: Close the three `ctx` holes, add the `context`/`peerScope`/`peerContext` fields, wire the argument→parameter binding hop

**Files:**
- Modify: `scanner/src/lineage/engine.js` (§13.7 items 1-5)
- Modify: `scanner/src/lineage/summaries.js` (§13.7 items 6-10)
- Modify: `scanner/src/lineage/driver.js` (§13.7 item 14)
- Create: `scanner/test/lineage/engine-provenance-interprocedural.test.js` (permanent test file — NOT the throwaway PoC, which stays untouched by this task; item 15's absorption/deletion of the PoC is Task 3's job, after Task 3's own marking work also has permanent coverage)
- Modify: `scanner/package.json` — add the new test file to the `test:lineage` script (required per `scanner/CLAUDE.md`'s "if you add a new test file, also add it to the matching script" rule; the pre-existing PoC entry stays as-is for this task, Task 3 removes it)
- Read only: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` §13.0-§13.4, §13.7 (items 1-10, 14, 15b); `scanner/test/lineage/engine-provenance-interprocedural-poc.test.js` (the accepted design's own PoC — mirror its scenarios into permanent tests against the now-real shipped code, do not just copy-paste the prototypes verbatim since they exist specifically to stand in for code this task now writes for real)

**Interfaces:**
- Consumes: `contributingKeys(state, path, id)`, exported from `engine.js` (unchanged this task); `hashState`, exported from `field-identity.js` (already used elsewhere; not yet imported into `engine.js` — item 1 adds that).
- Produces: `resolveCallSummary(calleeExpr, callArgs, callerState, ctx)` — 4th param, optional; `entryStateFromCall(paramNames, callArgs, callerState, ctx)` — 4th param, optional; every hop record now additionally carries `context` (string|null), `peerScope` (string|null), `peerContext` (string|null) — Task 3 consumes these for its own marking hop, and both fields are additive to the record shape every C1/C2 hop-emission site already produces (no existing site's OWN code changes — only the wrapper that stamps `scope`/`nodeId`/`line` onto every hop gains 3 more stamped fields).

- [ ] **Step 1: `engine.js` — imports, context stamping, `case 'call'` ctx forwarding (items 1-5)**

At the top of `scanner/src/lineage/engine.js`, add `hashState` to the existing `field-identity.js` import (currently `import { identitiesAt, emptyState, removeIdentitiesAt, addIdentity, joinStates, statesEqual } from './field-identity.js';`) — item 1.

In `analyzeFunctionFieldIdentity` (~line 848, right after `const scope = fn.qid ?? null;`), add:

```js
const context = ctx?.recordHop ? hashState(entryState) : null;
```

— item 2 (computed once per analysis run, not per hop; `null` when no recorder is present, matching every other conditional field this file already stamps).

In the `stepCtx` wrapper (~lines 864-866), currently:

```js
const stepCtx = ctx?.recordHop
  ? { ...ctx, recordHop: (h) => ctx.recordHop({ scope, nodeId: nid, line: node.line ?? null, ...h }) }
  : ctx;
```

change the stamped object to also carry `context, peerScope: null, peerContext: null` before the `...h` spread — item 3. `peerScope`/`peerContext` default to `null` here because most hops are NOT cross-function; only the `call-resolved` hop (below) and `call-arg-bind` hop (Task 2 Step 2) ever set them non-null, and `...h` lets those two sites override the default exactly like every other per-hop field already does.

In `resolveExprIdentities`'s `case 'call'` (line ~505), currently `ctx.resolveCallSummary(expr.callee, expr.args ?? [], state)` — change to pass `ctx` as a 4th argument: `ctx.resolveCallSummary(expr.callee, expr.args ?? [], state, ctx)` — item 4. **This is the only place the full `ctx` crosses from `engine.js` into `summaries.js`.** Task 2 Step 2's changes to `entryStateFromCall`/`createCallSummaryResolver` must not let `resolveCallSummary` (as opposed to a recorder-only derivation) reach any further `resolveExprIdentities` call — that is exactly the hazard Task 1's fix round found and closed in the design; Step 2 below implements the closed version, not the original.

In the same `case 'call'`'s resolved branch (~lines 512-520), the existing `call-resolved` hop-emission loop:

```js
if (ctx?.recordHop) {
  for (const id of flat) {
    ctx.recordHop({
      kind: 'production', subKind: 'call-resolved',
      fromPath: null, toPath: null, dataElementId: id,
      syntacticPath: null, widenReason: null, lossReason: null,
    });
  }
}
```

add `peerScope: summary.resolvedQid ?? null, peerContext: summary.resolvedContext ?? null` to the object literal — item 5. Use `?? null`, never a bare reference — a 3-argument `resolveCallSummary` stub (e.g. an older/hand-built test fixture that hasn't been updated to return `resolvedQid`/`resolvedContext`) must not throw or stamp `undefined`.

- [ ] **Step 2: `summaries.js` — close holes 2 and 3, emit the argument→parameter binding hop (items 6-10)**

In `entryStateFromCall` (line 286), add an optional 4th parameter `ctx`. At the top of the function body (before the `for` loop), derive:

```js
const argCtx = ctx?.recordHop ? { recordHop: ctx.recordHop } : undefined;
```

and change the existing `resolveExprIdentities(callerState, callArgs[i])` call (line 291) to `resolveExprIdentities(callerState, callArgs[i], argCtx)` — item 6. **Deriving `argCtx` inside `entryStateFromCall` itself (not at a call site) is load-bearing, not stylistic** — it means no future second caller of `entryStateFromCall` can reintroduce the hazard by passing the full `ctx` through a different path. Never pass `ctx` itself to `resolveExprIdentities` here — only `argCtx`, which strips `resolveCallSummary` and keeps only `recordHop`. Passing the full `ctx` changes the ANALYSIS RESULT with no recorder attached anywhere (an argument that is itself a resolvable call would resolve interprocedurally where the shipped engine takes the unresolved fallback), in the unsound direction under a tight B6 context cap — this is exactly Task 1's fix-round finding; Step 3's own regression test (item 15b) is what proves this stays closed.

After deriving `argCtx` and inside the existing per-parameter loop (which already computes `resolved`, `residual`, and writes to `entryState` — do not change that write logic), when `ctx?.recordHop` is present, emit one `write-out/call-arg-bind` hop per identity written this iteration (both the residual write at `paramName` and each `byPath` write at `paramName.subPath`), matching this file's own §13.2(b) shape:

```js
kind: 'write-out', subKind: 'call-arg-bind',
fromPath: null, toPath: <paramName or `${paramName}.${subPath}`>, dataElementId: id,
syntacticPath: null, widenReason: null, lossReason: null,
```

`fromPath` is deliberately `null` — read §13.2(a)'s rationale in the design doc before changing this (the argument's own in-halves, emitted by the now-ctx-forwarded `resolveExprIdentities` call inside `argCtx`, already carry the real contributing keys at the join key `(callerScope, callerNodeId, id, callerContext)`; a non-null `fromPath` here would double-emit the same information in a differently-shaped record). This is item 6's second half (the design doc's item 6 row covers only the ctx-stripping; the hop emission is specified in §13.2(b), referenced from item 6's own text) — confirm against the live §13.2(b) text before writing this, since it is the exact shape a task review will check byte-for-byte.

In `createCallSummaryResolver`'s returned closure (line 334), add an optional 4th parameter `ctx`, and pass it straight through to `entryStateFromCall`'s new 4th parameter (`entryStateFromCall(fn.params, callArgs, callerState, ctx)`) — item 7. `entryStateFromCall` does the stripping (Step 2's item 6 code above), so this call site forwards the caller's `ctx` unmodified; the hazard cannot reappear here because the strip happens one level down, not at each call site.

Immediately after that `entryStateFromCall` call, compute `const calleeContext = hashState(entryState);` — item 8's first half.

Inside `cache.compute`'s callback (line 357), the existing callee-ctx construction is `{ resolveCallSummary }` (a fresh object every time, discarding any recorder — this is hole 3). Change it to:

```js
const calleeCtx = ctx?.recordHop
  ? { resolveCallSummary, recordHop: ctx.recordHop }
  : { resolveCallSummary };
const result = analyzeFunctionFieldIdentity(fn, es, calleeCtx);
```

— item 9. **Do not re-stamp `context` here** — the callee's own `analyzeFunctionFieldIdentity` call (Step 1's item 2/3 changes) computes and stamps its own `context` from ITS OWN `entryState` (`es`, the callee's entry state — different from the caller's `entryState`), and its `stepCtx` wrapper's stamps win over anything this object would set, by spread order (`{ ...ctx, ..., ...h }` — the innermost `h` from the deepest call always wins). Passing a `context` field here would be silently overwritten and is dead code.

At `cache.compute`'s return point (still inside the same callback, where it currently does `return summaryFromAnalysisResult(result);`), wrap the result: `return { ...summaryFromAnalysisResult(result), resolvedQid: qid, resolvedContext: calleeContext };` — item 10. A fresh object via spread, never a mutation of `summaryFromAnalysisResult`'s return value (which `fieldSummaryEq` and the cache's own equality checks read elsewhere — mutating it risks a subtle aliasing bug with whatever else holds a reference).

Then, still in `createCallSummaryResolver`, when `ctx?.recordHop` is present, emit the `write-out/call-arg-bind` hop's cross-function complement: this is item 8's second half — but re-check the live §13.2(b) text for the exact record shape (it specifies whether this second hop belongs here or was already fully covered by Step 2's per-parameter loop in `entryStateFromCall` above; do not assume — the design doc is the authority, this brief is not a substitute for reading it).

- [ ] **Step 3: `driver.js` — thread `opts.recordHop` (item 14)**

In `runFieldIdentityAnalysis` (line 65), the current per-function ctx construction is `{ resolveCallSummary }`. Change to accept an optional `opts.recordHop` and spread it in conditionally:

```js
const ctx = opts.recordHop ? { resolveCallSummary, recordHop: opts.recordHop } : { resolveCallSummary };
const result = analyzeFunctionFieldIdentity(fn, emptyState(), ctx);
```

so a caller that supplies no `opts.recordHop` gets a byte-identical `{ resolveCallSummary }` object to what this function constructs today — Decision 7.2's "true by construction" property, extended to the driver.

- [ ] **Step 4: Write `engine-provenance-interprocedural.test.js` (permanent tests proving items 1-10, 14, and the golden-baseline regression, item 15b)**

Cover, against the REAL shipped functions (import from `../../src/lineage/summaries.js`, `../../src/lineage/driver.js`, `../../src/lineage/engine.js` — no local reimplementation, unlike the PoC this mirrors):

1. **Argument-binding hop**: a real 2-function fixture (caller passes an argument to a callee), asserting a `write-out/call-arg-bind` hop appears with the right `toPath`/`dataElementId` when a recorder is attached, and that identity resolution is unaffected when no recorder is attached (mirrors PoC scenario 1, against shipped `entryStateFromCall`).
2. **Two-hole-closure**: a 3-function resolved chain (`outer` → `middle` → `inner`), through a real `FieldIdentitySummaryCache` + hand-built `lookupCallee`, proving hops recorded INSIDE `inner`'s own analysis are visible in the top-level `outer` recorder (mirrors PoC scenario 2, now against shipped `createCallSummaryResolver`/`resolveCallSummary`).
3. **Context disambiguation**: reconstruct §9.4's own worked example (`function g(x) { const y = x; return y; }` under two distinct entry contexts) through the real cache, and confirm joining on `(scope, nodeId, dataElementId, context)` excludes the phantom pairs a 3-part join would include (mirrors PoC scenario 4).
4. **Golden-baseline regression (item 15b)** — the guard for the exact hazard Task 1's fix round found and fixed:
   - Fixture A: `function scrub(u){return {safe:1}}; function sink(p){return p}; function caller(user){const out = sink(scrub(user)); return out;}`, seeded `user.email -> data:email`, run through the real driver/cache with **no recorder anywhere**. Assert the result's returned identity for `out` is `['data:email']` — a hardcoded golden literal, not a comparison against any other live code path (per the design doc's explicit correction: comparing against "the shipped resolver" is meaningless once this task's own wiring IS the shipped resolver).
   - Fixture B: a two-call-site, cap-1-cache B6 scenario (two calls to the same `id2`-shaped function under a tight cap), no recorder anywhere. Assert the golden literal `['data:other-email']` (or whichever identity the design doc's own reproduction pins — check the PoC's existing scenario for the exact expected value before writing this assertion; do not guess it).
   - Compare the FULL canonicalized `{exitState, returnFacts, mutatedParams, widenings}` shape for both fixtures (matching item 16's own canonicalization approach — reuse or adapt whatever canonicalization helper `engine-provenance.test.js` already defines for its write-only-invariant test), not just `returnFacts`' identities alone.
   - These two tests MUST currently pass against the code Step 1-3 just wrote (they are a regression guard, not a TDD-red step — the hazard was already fixed in the design's own PoC; this step proves the SHIPPED code has the same property). If either fails, Steps 1-3 have reintroduced the hazard — stop and fix before proceeding, do not weaken the assertion.

- [ ] **Step 5: Wire the new test file into `test:lineage` and run the full scoped suite**

Add `test/lineage/engine-provenance-interprocedural.test.js` to the `test:lineage` script's file list in `scanner/package.json` (follow the existing entries' exact pattern). Run `npm run test:lineage` from `scanner/` and confirm every test passes, including the pre-existing 257 (236 baseline + the 21-test PoC file, still present and untouched) plus this task's new tests.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/engine.js scanner/src/lineage/summaries.js scanner/src/lineage/driver.js scanner/test/lineage/engine-provenance-interprocedural.test.js scanner/package.json
git commit -m "feat(lineage): close C3's three ctx holes, add context/peerScope/peerContext fields, wire call-arg-bind hop (Sub-project C, increment 3, Task 2)"
```

---

### Task 3: B5/B6 degradation marking, absorb the PoC into the permanent suite, finish the write-only-invariant and driver coverage

**Depends on:** Task 2 (this task's marking hop reuses `peerScope`/`peerContext`/the `context` field Task 2 adds, and Step 3's PoC-deletion step must not run before Task 2's own permanent tests exist to replace what the PoC was proving).

**Files:**
- Modify: `scanner/src/lineage/summaries.js` (§13.7 items 11-13)
- Modify: `scanner/test/lineage/engine-provenance.test.js` (§13.7 item 16 — extend the existing write-only-invariant test)
- Create or modify: a `driver.test.js` addition (§13.7 item 17)
- Delete: `scanner/test/lineage/engine-provenance-interprocedural-poc.test.js`, and remove its entry from `scanner/package.json`'s `test:lineage` script (§13.7 item 15) — **only after** this task's own marking work has permanent test coverage elsewhere, so no property the PoC was proving goes uncovered even momentarily within this task's own commit history
- Read only: `scanner/src/lineage/DESIGN_PATH_PROVENANCE.md` §13.6, §13.7 (items 11-13, 15, 16, 17)

**Interfaces:**
- Consumes: Task 2's `context`/`peerScope`/`peerContext` fields, `resolvedQid`/`resolvedContext` on a resolved summary.
- Produces: `FieldSummary` objects gain an optional `degradedReason` field (string, e.g. `'context-cap'`) — permanent (not stripped like `_recursive`), diagnostic (excluded from `fieldSummaryEq`, matching `widenings`' own precedent).

- [ ] **Step 1: `FieldIdentitySummaryCache.compute`'s cap branch marks its fallback (item 11)**

In the cap-degradation branch (lines 115-123), currently:

```js
if (!seen.has(hash) && seen.size >= this._maxContextsPerFn) {
  const fallback = this._cache.get(this._key(qid, emptyState())) ?? emptyFieldSummary();
  this.set(qid, entryState, fallback);
  return fallback;
}
```

change to mark a **shallow copy** (never mutate the shared fallback object in place — the same object may already be cached under a different key, e.g. the function's own empty-entry summary):

```js
if (!seen.has(hash) && seen.size >= this._maxContextsPerFn) {
  const base = this._cache.get(this._key(qid, emptyState())) ?? emptyFieldSummary();
  const fallback = { ...base, degradedReason: 'context-cap' };
  this.set(qid, entryState, fallback);
  return fallback;
}
```

Per the design doc's own correction (§13.7 item 11's live text): do NOT port the PoC's `MarkingSummaryCache` subclass verbatim — that subclass re-derives the cap test outside `compute()` only because a subclass cannot see which branch its parent took; inline, mark `fallback` right here, at the one real call site, with no second cap test.

- [ ] **Step 2: emit the loss hop when a resolved call receives a degraded summary (item 12)**

In `createCallSummaryResolver`'s closure, after `cache.compute(...)` returns (wherever Task 2's Step 2 wrapped the result with `resolvedQid`/`resolvedContext`), when the summary carries `degradedReason` AND `ctx?.recordHop` is present, emit one loss hop per identity in the callee's entry state (`entryState`, already computed earlier in this closure):

```js
kind: 'production', fromPath: null, toPath: null, dataElementId: id,
syntacticPath: null, widenReason: null, lossReason: 'context-cap-degraded',
peerScope: qid, peerContext: calleeContext,
```

Confirm the exact field list against the live §13.6/§13.7 item 12 text before writing this — the design doc is the authority on whether `peerScope`/`peerContext` are included here (this brief's best reconstruction from context, not a verbatim quote).

- [ ] **Step 3: `fieldSummaryEq` excludes `degradedReason` (item 13)**

Add a one-line comment near `fieldSummaryEq`'s existing exclusion of `widenings` (it's already documented as deliberately not compared, being diagnostic) noting that `degradedReason` is excluded for the same reason. No behavior change — `fieldSummaryEq`'s existing field-by-field comparison already doesn't touch `degradedReason` since it was never in the comparison list; this step is documentation only, making the omission a stated decision rather than an accidental one a future reader might "fix."

- [ ] **Step 4: extend the write-only-invariant test (item 16)**

In `engine-provenance.test.js`'s existing write-only-invariant test (~line 245), add at least one multi-function fixture driven through a real `FieldIdentitySummaryCache`, run once with a recorder attached and once without, asserting the canonicalized `{exitState, returnFacts, mutatedParams, widenings}` is identical between the two runs. This is the guard against the C2-era bug class (a recorder's presence perturbing cache-cap accounting) — C3 adds three new recorder-conditional branches inside `summaries.js` (Task 2's items 6, 9, and this task's item 12), so the fixture must exercise all three: an argument-binding call, a resolved multi-hop chain, and a context-cap-degraded call.

- [ ] **Step 5: driver test for `opts.recordHop` (item 17)**

Add a test (in `driver.test.js` or a new file, following that suite's existing conventions) proving `opts.recordHop` reaches every function across a real multi-file project (hops recorded for functions in more than one file), AND that omitting `opts.recordHop` leaves `runFieldIdentityAnalysis`'s `results`/`cache` unchanged from calling it with no `opts` at all (byte-identical, matching Decision 7.2).

- [ ] **Step 6: absorb the PoC into the permanent suite, then delete it (item 15)**

Re-point any of the PoC file's assertions not already covered by Task 2's Step 4 or this task's Steps 4-5 into the permanent test files (most should already be redundant — confirm, don't assume). Delete `scanner/test/lineage/engine-provenance-interprocedural-poc.test.js` and its `test:lineage` entry in `scanner/package.json`, in the same commit as the re-pointing. The `this`-binding stand-in and the "hole is real"/hazard-reproduction tests are EXPECTED to have no permanent equivalent (they existed to prove a now-fixed hazard, not a lasting property) — do not try to preserve them; item 15b's golden-baseline regression (already added in Task 2) is what stays as the permanent guard against the same hazard class recurring.

- [ ] **Step 7: run the full scoped suite and doc-drift check**

```bash
npm run test:lineage
node ../scripts/check-doc-drift.mjs
```

Confirm test count and doc-drift status (the pre-existing `path-store.js` reference in `src/lineage/CLAUDE.md` is expected and pre-dates this task — C4's future file).

- [ ] **Step 8: update `scanner/src/lineage/CLAUDE.md`**

Move C3 from "designed but not yet implemented" to complete in the module table (mirroring how every prior increment's own completion was documented), and update "What is NOT here yet" to reflect C3's closure and C4-C6's continued absence.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/lineage/summaries.js scanner/test/lineage/engine-provenance.test.js scanner/test/lineage/driver.test.js scanner/src/lineage/CLAUDE.md scanner/package.json
git rm scanner/test/lineage/engine-provenance-interprocedural-poc.test.js
git commit -m "feat(lineage): B5/B6 degradation marking, absorb C3's PoC into the permanent suite (Sub-project C, increment 3, Task 3)"
```
