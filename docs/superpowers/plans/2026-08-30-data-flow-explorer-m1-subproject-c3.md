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

## Post-Task-1 note (filled in once Task 1 lands)

This plan gains its implementation task(s) here, scoped exactly to what §13.7's checklist specifies, once Task 1's addendum is committed and reviewed. Do not pre-write them — §13 does not exist yet at the time this plan file was first saved.
