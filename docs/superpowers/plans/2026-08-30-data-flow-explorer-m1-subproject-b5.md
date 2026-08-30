# Data Flow Explorer — Milestone 1, Sub-project B, Increment 5: Recursion Handling (Bounded Fixed-Point Refinement)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gap increment B1 deliberately left open and explicitly flagged in its own test suite (`test/lineage/summaries.test.js:82`: *"the bottom stub carries no facts — B5 will refine this, not this increment"*) — a self- or mutually-recursive function's summary, once it hits the `_stack`-based recursion guard, is currently permanently stuck at whatever the FIRST pass produced (treating the recursive self-reference as carrying zero identity), with no mechanism to ever revisit and improve it.

**Architecture:** Ported from `scanner/src/dataflow/summaries.js`'s own `SummaryCache.compute()` — the ONLY correct precedent for this exact problem already proven, tested, and hardened in this codebase (including a documented "Stage 3 correctness audit" bug fix this plan explicitly avoids reintroducing — see Task 1's Global Constraint below). The mechanism is a **local, per-`compute()`-call bounded fixed-point loop**, entirely contained inside `FieldIdentitySummaryCache.compute()` — NOT an outer, whole-project re-run. This is a deliberate, load-bearing design decision, not a simplification: research into dataflow's exact mechanics (verified by direct code reading, not assumption) confirmed that re-running `runFieldIdentityAnalysis` (increment B4's driver) an extra time would accomplish NOTHING — every call site's own lazy `cache.compute()` consultation checks `has()` first and short-circuits on any cache hit, so a full second driver pass would just re-read the same (unrefined) values from the cache without ever re-invoking the analysis. The refinement has to happen **before** `compute()` ever hands a value back to its caller, which is exactly what a local, contained loop does: when a nested self- or mutually-recursive call is detected mid-analysis (the existing `_stack` guard fires, exactly as increment B1 built it), the outer `compute()` call notices this happened (a new `_hitRecursion` flag) and, once its own `analyze()` call returns, re-invokes `analyze()` up to a small bounded number of additional times — each round benefiting from the PRIOR round's own (now-cached) result at the same key — stopping early once the summary stops changing (a genuine, **membership-based** equality check, not size-based — see Task 1's Global Constraint).

**Tech Stack:** Node.js ESM, `node:test`, `scanner/src/lineage/summaries.js` (existing, extended), `scanner/src/dataflow/summaries.js` (existing, READ-ONLY — the reference precedent this plan ports from, never modified), `scanner/src/ir/parser-js.js` (real JS/TS parser, for Task 2).

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` (repo root, untracked per this repo's PRD convention) — Milestone 1 requirement FR-301 (never silently merge/drop distinct data-element identities) and FR-302 (interprocedural resolution). This plan also argues from `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-b-scoping.md`'s own B5 row: *"Recursion handling — The bottom-stub + bounded re-analysis mechanism, proven against real mutually-recursive and self-recursive JS/TS functions."*

## Global Constraints

- **Isolation principle (non-negotiable, verified in every prior increment's review):** `scanner/src/lineage/` may READ `scanner/src/dataflow/summaries.js` as reference material while writing this plan and while implementing (it is cited throughout this document, and its exact mechanics matter — read it directly rather than trusting paraphrase), but the actual CODE this plan adds must live entirely in `scanner/src/lineage/summaries.js` and must NEVER import from `scanner/src/dataflow/summaries.js` or `scanner/src/dataflow/engine.js`. Verify with a grep at the end of Task 1, exactly as every prior increment has.
- **`FieldIdentitySummaryCache.compute()`'s existing public signature does not change.** `compute(qid, entryState, analyzeFn)` keeps exactly the same three parameters and the same "returns a summary" contract. This is purely an internal enhancement to what happens between "analyzeFn is invoked" and "a value is cached/returned" — no caller anywhere in this codebase (`createCallSummaryResolver`, `driver.js`, every existing test) needs to change.
- **The equality check MUST be membership-based, not size-based.** `scanner/src/dataflow/summaries.js` carries an explicit, documented lesson directly above its own `_summaryEq` function (read it — `grep -n "Stage 3 correctness audit" scanner/src/dataflow/summaries.js` and read the full comment above it): an earlier version of that function compared `mutatedParams` by SIZE only, so two summaries with the same cardinality but DIFFERENT membership were wrongly judged equal, causing the fixed-point loop to break early WITHOUT caching the fresher, more-correct summary — a real, previously-shipped bug. This plan's own `fieldSummaryEq` equivalent must compare `returnFlat` (a `Set`) and `mutatedParams` (a `Map<path, Set>`) by genuine membership (every element of one is present in the other, not just equal counts) from the start. Do not write the buggy version and "fix it later" — write it correctly the first time, citing dataflow's own precedent as the reason in a comment.
- **Bounded, never unbounded.** The refinement loop must have a hard round cap (mirror dataflow's own `FP_MAX = 3`) — this is a SAFETY property (no pathological input can hang the analysis), not a precision target. A function that never converges within the cap is left at whatever the last round produced — an honest, sound under-approximation, exactly the same philosophy every prior increment in this package has followed (never crash, never hang, degrade gracefully and disclose the limitation in comments).
- **The existing recursion-guard test must remain valid, unmodified, and still passing.** `test/lineage/summaries.test.js`'s existing test `'compute: a recursive call (same qid already being analyzed) gets an immediate bottom-stub summary, not infinite recursion'` (around line 69) exercises the IMMEDIATE, transient bottom-stub-return behavior of a NESTED `compute()` call hit mid-analysis — this behavior is NOT changed by this plan (B5 only adds logic that runs AFTER the outer `analyze()` call returns, inside the SAME `compute()` invocation that detected the recursion; the immediate nested-call bottom-stub return is untouched). If implementing this plan makes that test fail, the implementation is wrong, not the test.
- All new/changed code must keep `npm run test:lineage` fully green, and must not modify any file outside `scanner/src/lineage/`, `scanner/test/lineage/`, and this plan's own doc/ledger files.

---

## Task 1: The bounded fixed-point refinement loop in `FieldIdentitySummaryCache.compute()`

**Files:**
- Modify: `scanner/src/lineage/summaries.js`
- Test: `scanner/test/lineage/summaries.test.js`

**Interfaces:**
- Consumes: nothing new — this task modifies `FieldIdentitySummaryCache.compute()`'s internal implementation only. Read `scanner/src/dataflow/summaries.js`'s `SummaryCache.compute()` and its accompanying `_summaryEq` function (and the comment block directly above `_summaryEq` describing the "Stage 3 correctness audit" bug) as the reference precedent — port the STRUCTURE (the `_hitRecursion` flag, the post-`analyze()` refinement loop, the membership-based equality check, the defensive `_recursive` marker strip before returning) adapted to this package's own `FieldSummary` shape (`{returnFlat: Set, returnByPath: Map, mutatedParams: Map<path,Set>, widenings: Array}`), not a literal copy-paste (the two shapes differ: dataflow's summary has a boolean `returnTainted` and a flat `Set<paramName>` for `mutatedParams`; this package's summary has a `Set` for `returnFlat` and a `Map<path,Set>` for `mutatedParams`).
- Produces: `fieldSummaryEq(a, b)` — a new, EXPORTED function in `scanner/src/lineage/summaries.js` (exported so it can be unit-tested directly, matching the precedent increment B4 set with `summaryFromAnalysisResult`). `FieldIdentitySummaryCache.compute()`'s externally-observable behavior for a NON-recursive call is unchanged; for a call where recursion was detected mid-analysis, it now performs bounded refinement before returning.

- [ ] **Step 1: Read the reference precedent directly**

Run and read the FULL output of:
```bash
sed -n '1,220p' src/dataflow/summaries.js
```
(from the `scanner/` directory). Pay particular attention to: the `compute()` method's full body (the top cache-hit check, the context-cap branch, the `_stack.has(qid)` early-return branch, the `_hitRecursion` flag lifecycle, the `try`/`finally` structure, the post-`analyze()` refinement loop, and the defensive `if (summary._recursive) delete summary._recursive;` line at the end) and the `_summaryEq` function plus its preceding comment block. You will port this structure in Step 3 below — do not write it from memory or guess at the shape; the exact ordering of operations (in particular: `this._cache.set(k, summary)` happens BEFORE the `if (this._hitRecursion)` check, and inside the refinement loop, a round's result is only cached if it's NOT judged equal to the previous round) is load-bearing and easy to get subtly wrong.

- [ ] **Step 2: Write the failing tests**

Add to `scanner/test/lineage/summaries.test.js` (near the existing recursion test around line 69 — do NOT modify that existing test, add these as new tests after it):

```js
test('compute: recursion detected mid-analysis triggers a BOUNDED refinement loop — analyzeFn is re-invoked more than once, not just the initial pass (increment B5)', () => {
  const cache = new FieldIdentitySummaryCache();
  const state = emptyState();
  let callCount = 0;
  const analyzeFn = () => {
    callCount++;
    // fn1 "calls itself" during its own analysis — this is what sets
    // _hitRecursion (via the nested compute() call hitting the existing
    // _stack guard from increment B1).
    cache.compute('fn1', state, analyzeFn);
    // A different result each round (keyed off callCount) so this test
    // isolates "does the loop re-invoke analyzeFn at all" from "does it
    // correctly detect convergence" (Task 1's next test covers the latter).
    return { ...emptyFieldSummary(), returnFlat: new Set([`data:round${callCount}`]) };
  };

  const result = cache.compute('fn1', state, analyzeFn);

  assert.ok(callCount > 1, `analyzeFn must be re-invoked at least once beyond the initial pass when recursion was detected mid-analysis; got ${callCount} call(s)`);
  assert.ok(callCount <= 4, `must be BOUNDED — 1 initial pass + at most FP_MAX=3 refinement rounds — got ${callCount} calls`);
  assert.deepEqual([...result.returnFlat], [`data:round${callCount}`], 'the returned AND cached summary must reflect the LAST round actually computed, not the first');
  assert.equal(cache._stack.size, 0, 'the recursion guard stack must be fully unwound after compute() returns, even after multiple refinement rounds');
  assert.equal(cache.get('fn1', state).returnFlat.has(`data:round${callCount}`), true, 'the CACHED value (not just the returned one) must reflect the final round');
});

test('compute: refinement stops EARLY once the summary stops changing, not always running the full bound (increment B5)', () => {
  const cache = new FieldIdentitySummaryCache();
  const state = emptyState();
  let callCount = 0;
  const analyzeFn = () => {
    callCount++;
    cache.compute('fn1', state, analyzeFn);
    // SAME result every round (independent of callCount and of the
    // self-call's own — always-empty — contribution) — round 2 must be
    // judged identical to round 1 and the loop must break immediately,
    // not burn through all FP_MAX rounds needlessly.
    return { ...emptyFieldSummary(), returnFlat: new Set(['data:stable']) };
  };

  cache.compute('fn1', state, analyzeFn);

  assert.ok(callCount <= 2, `a stable (non-improving) recursive summary must converge almost immediately, not burn the full refinement budget; got ${callCount} calls`);
});

test('compute: a pathologically non-converging recursive summary is still BOUNDED by FP_MAX, never loops unboundedly (increment B5)', () => {
  const cache = new FieldIdentitySummaryCache();
  const state = emptyState();
  let callCount = 0;
  const analyzeFn = () => {
    callCount++;
    cache.compute('fn1', state, analyzeFn);
    // A DIFFERENT identity every single round, forever — this can never
    // converge. The loop must still terminate.
    return { ...emptyFieldSummary(), returnFlat: new Set([`data:unique${callCount}`]) };
  };

  cache.compute('fn1', state, analyzeFn);

  assert.ok(callCount <= 4, `must terminate within the bound (1 initial + FP_MAX=3) even when the summary never converges; got ${callCount} calls`);
});

test('fieldSummaryEq compares returnFlat and mutatedParams by MEMBERSHIP, not just size (regression for the exact bug class dataflow/summaries.js documents fixing — "Stage 3 correctness audit")', () => {
  const a = { ...emptyFieldSummary(), returnFlat: new Set(['data:a']), mutatedParams: new Map([['x', new Set(['data:a'])]]) };
  const b = { ...emptyFieldSummary(), returnFlat: new Set(['data:b']), mutatedParams: new Map([['x', new Set(['data:b'])]]) };
  // Same CARDINALITY (1 identity in returnFlat, 1 mutated param with 1
  // identity each) but DIFFERENT actual members — must be judged UNEQUAL.
  assert.equal(fieldSummaryEq(a, b), false, 'same-size but different-membership summaries must NOT be judged equal');

  const c = { ...emptyFieldSummary(), returnFlat: new Set(['data:a']), mutatedParams: new Map([['x', new Set(['data:a'])]]) };
  assert.equal(fieldSummaryEq(a, c), true, 'genuinely identical summaries must be judged equal');
});
```

Add `fieldSummaryEq` to the existing import from `../../src/lineage/summaries.js` at the top of the test file.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: the 4 new tests FAIL (`fieldSummaryEq is not a function`, and the recursion-refinement tests fail because `callCount` stays at 1 — today's `compute()` never re-invokes `analyzeFn` after detecting recursion). The PRE-EXISTING recursion test (line ~69) must still PASS unchanged.

- [ ] **Step 4: Implement the refinement loop**

In `scanner/src/lineage/summaries.js`, replace `FieldIdentitySummaryCache`'s `compute()` method (currently the version with the `try { const summary = analyzeFn(entryState); this.set(...); return summary; } finally { this._stack.delete(qid); }` body) with a version that:

1. At the TOP, before pushing onto `_stack`, initializes a `this._hitRecursion = false;` flag (mirroring `dataflow/summaries.js`'s exact placement — right before `this._stack.add(qid)`).
2. In the branch that currently does `if (this._stack.has(qid)) { return { ...emptyFieldSummary(), _recursive: true }; }`, ALSO set `this._hitRecursion = true;` before returning — this is what a nested, deeper `compute()` call signals back up to whichever OUTER `compute()` call is currently mid-`analyze()` (the flag lives on the cache INSTANCE, shared across the whole nested call chain, exactly as `dataflow/summaries.js` does it — this is deliberate, not an oversight, and mirrors that file's own tested, hardened design).
3. After the FIRST `const summary = analyzeFn(entryState); this.set(qid, entryState, summary);`, add: `if (this._hitRecursion) { const FP_MAX = 3; for (let fp = 0; fp < FP_MAX; fp++) { const prev = summary; summary = analyzeFn(entryState); if (fieldSummaryEq(prev, summary)) break; this.set(qid, entryState, summary); } }` — note the ordering: the comparison happens BEFORE the cache write for that round, so a round judged "equal to the previous" is never written (the cache still holds the prior round's — equal — value, which is correct and matches dataflow's own exact structure).
4. Before the `return summary;`, add the defensive strip: `if (summary._recursive) delete summary._recursive;` (mirrors dataflow's own defensive line — `analyzeFn`'s real return shape here never actually carries this field under normal operation, but this guards against a future change to `analyzeFn`'s callers accidentally leaking it through, exactly the same reasoning dataflow's own comment gives).

Also add, near the other module-level helpers (e.g. near `entryStateFromCall`), the new exported function:

```js
// Compares two FieldSummary objects for VALUE equality — by membership,
// never by size alone. dataflow/summaries.js's own equivalent (_summaryEq)
// carries a documented, previously-shipped bug ("Stage 3 correctness
// audit," see that file's comment directly above _summaryEq): an earlier
// version compared mutatedParams by SIZE only, so two summaries with the
// same cardinality but different actual members were wrongly judged
// equal — the fixed-point loop then broke early WITHOUT caching the
// fresher, more-correct summary, silently serving a stale one to any
// LATER cache read. This function is written correctly from the start,
// citing that precedent as the reason, not discovered the same way twice.
//
// Deliberately does NOT compare `widenings` — mirrors dataflow's own
// `_summaryEq`, which also excludes its diagnostic-list equivalent
// (`findings`) from the equality check. Two summaries that agree on their
// actual FACTS (returnFlat, returnByPath, mutatedParams) but happen to
// carry a differently-ordered or differently-worded widening-reason list
// should still be treated as converged — the facts are what a caller
// actually consumes; the widening list is diagnostic.
export function fieldSummaryEq(a, b) {
  if (!a || !b) return a === b;
  if (a.returnFlat.size !== b.returnFlat.size) return false;
  for (const id of a.returnFlat) if (!b.returnFlat.has(id)) return false;
  if (a.mutatedParams.size !== b.mutatedParams.size) return false;
  for (const [path, ids] of a.mutatedParams) {
    const bIds = b.mutatedParams.get(path);
    if (!bIds || bIds.size !== ids.size) return false;
    for (const id of ids) if (!bIds.has(id)) return false;
  }
  return true;
}
```

(`returnByPath` is deliberately NOT compared — it is currently always `new Map()` for every summary this cache ever stores, per B1's own disclosed, still-open limitation; comparing two always-empty Maps would be a no-op check, not a meaningful omission. If a future increment populates `returnByPath`, this function will need extending — leave a one-line comment noting that, do not silently extend the scope of this task to close that unrelated limitation.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: PASS, all tests including the 4 new ones AND the pre-existing recursion test unchanged.

- [ ] **Step 6: Confirm the isolation principle still holds**

Run: `grep -n "from '../dataflow/engine\|from '../dataflow/summaries" scanner/src/lineage/summaries.js`
Expected: no output.

- [ ] **Step 7: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 203/203 (199 prior + 4 new).

- [ ] **Step 8: Commit**

```bash
git add scanner/src/lineage/summaries.js scanner/test/lineage/summaries.test.js
git commit -m "feat(lineage): bounded fixed-point recursion refinement in FieldIdentitySummaryCache.compute() (Sub-project B, increment 5, Task 1)"
```

---

## Task 2: Real-parser proof against self- and mutually-recursive JS/TS functions

**Files:**
- Test: `scanner/test/lineage/driver.test.js` (extend the existing file, created in increment B4)

**Interfaces:**
- Consumes: `runFieldIdentityAnalysis` (`driver.js`, increment B4, unmodified — this task proves B5 works correctly THROUGH the existing driver, with zero driver changes needed, exactly as this plan's Architecture section explains), `buildCallGraph` (`scanner/src/ir/callgraph.js`), `parseJsFile` (`scanner/src/ir/parser-js.js`) — all already imported in `driver.test.js` from increment B4's own work.
- Produces: nothing new for later tasks — this is the final proof task for this increment.

- [ ] **Step 1: Investigate before writing — this task requires empirical construction, not a hardcoded fixture**

Increment B4's own final review already built and hand-verified (via a temporary, uncommitted script) a real-parser project containing BOTH a self-recursive function and a 3-function mutual-recursion cycle, confirming `runFieldIdentityAnalysis` terminates in ~1ms with `cache._stack.size === 0` afterward — that PROVES B5 doesn't need to worry about infinite loops or missing `finally`-unwinding at the driver level (already covered). Task 2's job is narrower and more specific: prove that **refinement is real** — that a recursive function's FINAL summary (after this increment's fixed-point loop) is DIFFERENT FROM (and more complete than) what a single, unrefined pass alone would have produced.

This requires empirical verification, not assumption, because the exact mechanics of WHEN a real recursive JS/TS function's summary actually changes across refinement rounds depend on subtle interactions this plan's own author traced by hand but did NOT run against real code (see the design reasoning: whether a given real recursive scenario shows VISIBLE improvement depends on whether the recursive self-reference's own contribution is masked by union-with-an-already-present fact, or whether it's genuinely load-bearing). Before writing a committed test, **write a temporary, throwaway script** (not committed — delete it before this task's own commit) that:

1. Constructs a real, multi-function JS/TS scenario with genuine self- or mutual-recursion where the recursive call's OWN return value plausibly contributes something to the caller's own field-identity result (a reasonable starting shape: a function returning a nested object whose structure recurses, e.g. something like `function chain(user, depth) { if (depth <= 0) return { leaf: user.email }; return { leaf: user.email, next: chain(user, depth - 1) }; }` — but do not assume this exact shape will show a measurable difference; investigate).
2. Runs it through `runFieldIdentityAnalysis` via the real parser + `buildCallGraph`, and inspects the actual resulting summary/result for the recursive function.
3. Temporarily forces `FP_MAX` down to `0` (or otherwise disables the refinement loop — e.g. by temporarily commenting out the `if (this._hitRecursion) { ... }` block added in Task 1) to get the UNREFINED, round-1-only baseline, and compares.
4. If the FIRST scenario you try shows no visible difference (a real, plausible outcome given how flat-Set-union interacts with the specifics documented in the recursion-refinement research this plan is based on), try a DIFFERENT shape — vary which identities are introduced independently vs. only through the recursive path — until you find (or conclusively determine you cannot find, in which case STOP and report this honestly rather than writing a misleading test) a real scenario where refinement demonstrably changes the outcome.

Revert your temporary `FP_MAX`/refinement-disabling edit before proceeding — Task 1's code must be committed exactly as Task 1 left it.

- [ ] **Step 2: Write the committed test(s)**

Based on what Step 1's investigation found, write ONE OR MORE real tests in `scanner/test/lineage/driver.test.js` that:
- Construct the real, empirically-verified scenario(s) from Step 1 (self-recursion AND, separately, a mutually-recursive pair — the scoping doc's own B5 row explicitly requires BOTH to be covered, not just one).
- Assert on whatever DISCRIMINATING signal Step 1's investigation established actually demonstrates refinement occurred (this could be a richer `returnFlat`/structure than the unrefined baseline, OR — if Step 1 honestly could not find a scenario where the OUTPUT visibly differs — assert instead on the MECHANISM directly: that `FieldIdentitySummaryCache`'s internal state shows multiple rounds occurred, e.g. by wrapping `analyzeFunctionFieldIdentity` or instrumenting a call counter the way Task 1's own hand-built tests did, adapted to run through the real parser. Do not write a test whose assertion would pass identically whether or not Task 1's code exists at all — that is the exact "vacuous assertion" class of defect increment B3's and B4's own implementers each independently found and fixed in this plan author's prior work; hold this task to the same standard).
- Also assert on safety: termination (the test itself completing is proof enough — `node --test` has its own timeout), `cache._stack.size === 0` after the driver run, and that BOTH the self-recursive and mutually-recursive functions get a non-crashing, real (not `_recursive: true`-flagged) final summary in `results`.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/driver.test.js`
Expected: PASS.

- [ ] **Step 4: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, all prior tests plus whatever new tests this task added, 0 failures.

- [ ] **Step 5: Confirm no temporary/throwaway files or edits remain**

Run: `git status --porcelain` and `git diff` — confirm only the intended test file changed, and that Step 1's temporary `FP_MAX`-disabling edit to `summaries.js` (if you made one) was fully reverted (Task 1's own file must show zero diff from what Task 1 committed).

- [ ] **Step 6: Commit**

```bash
git add scanner/test/lineage/driver.test.js
git commit -m "test(lineage): real self- and mutually-recursive JS/TS proof for bounded fixed-point refinement (Sub-project B, increment 5, Task 2)"
```

---

## Post-implementation: update `scanner/src/lineage/CLAUDE.md`

After both tasks are reviewed and clean, update the module table:
- The `summaries.js` row: note the `fieldSummaryEq` addition and the bounded fixed-point refinement loop now in `compute()`, replacing the "deliberately SAFE-only... not yet precision-refined (that's increment B5's job)" language (that job is now done) with an accurate description of what actually refines and what still doesn't (e.g., if Task 2's investigation found real-world refinement is subtle/narrow for typical recursive shapes, say so honestly — this package's own established convention throughout every prior increment's CLAUDE.md entry is to disclose exactly this kind of nuance rather than overclaim).
- Update the Sub-project B section header from "increments 1-4" to "increments 1-5".
- Correct the "What is NOT here yet" section's B5 status — this is exactly the class of self-contradiction a final whole-branch review has caught in EVERY prior increment of this sub-project; check it carefully.

This is not a separate task — fold it into a final `docs(lineage): ...` commit after both tasks, matching the established pattern.
