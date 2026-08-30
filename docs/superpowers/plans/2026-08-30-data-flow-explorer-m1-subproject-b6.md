# Data Flow Explorer — Milestone 1, Sub-project B, Increment 6: Context-Sensitivity Tuning (the Per-Function Cap's Env Var)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the final, smallest gap in the B1-B6 breakdown — `FieldIdentitySummaryCache`'s per-function distinct-context cap is already fully implemented and tested (increment B1: `compute()`'s graceful degradation to the empty-entry summary past the cap), but is currently only configurable via an explicit constructor argument (`new FieldIdentitySummaryCache(N)`), with no operator-facing way to tune it for a real project without editing code. This increment adds exactly one thing: an env-var-backed default, mirroring `dataflow/summaries.js`'s own `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS` pattern, but under a **separate, lineage-specific env var name** — per the isolation principle every prior increment in this sub-project has verified holds, the two engines' tuning knobs must stay decoupled, so an operator tuning one engine's cap never silently affects the other's.

**Architecture:** A single, small, additive change to `scanner/src/lineage/summaries.js`: replace the hardcoded `DEFAULT_MAX_CONTEXTS = 16` module-level constant with a small function that reads `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` from the environment (mirroring dataflow's exact validation logic — `Number.isFinite(...) && ... >= 0`, falling back to `16` on anything invalid), evaluated as the constructor's default parameter value (so it's read fresh on every `new FieldIdentitySummaryCache()` call with no explicit argument — this matters for testability, since JS default parameter expressions are evaluated at call time, not at class-definition/module-load time). An explicit constructor argument — the mechanism every prior increment's own tests already rely on (e.g. `new FieldIdentitySummaryCache(2)` in the existing context-cap test) — continues to override the env var exactly as it already overrides the hardcoded default today; this plan does not change that.

**Tech Stack:** Node.js ESM, `node:test`, `scanner/src/lineage/summaries.js` (existing, extended).

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` (repo root, untracked per this repo's PRD convention) — Milestone 1 requirement FR-302 (interprocedural resolution) and the general "bounded, tunable analysis" posture this whole sub-project has followed. This plan also argues from `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-b-scoping.md`'s own B6 row: *"Context-sensitivity / the per-function cap — The distinct-context cap with graceful empty-context fallback past the cap — a lineage-specific env var (not `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS`, a fresh one, keeping the two engines' tuning knobs decoupled per the isolation principle)."*

## Global Constraints

- **Isolation principle (non-negotiable, verified in every prior increment's review):** the new env var MUST be a distinct name from `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS` (dataflow's own). Use `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS`. `scanner/src/lineage/summaries.js` must continue to never import from `scanner/src/dataflow/engine.js` or `scanner/src/dataflow/summaries.js` — verify with the same grep every prior increment has used.
- **Backward-compatible.** Every existing caller of `new FieldIdentitySummaryCache(...)` anywhere in this codebase (`driver.js`, every test file across B1-B5) passes either an explicit number or nothing. With the env var UNSET (the default state for every existing test and every existing caller), behavior must be byte-identical to today: cap defaults to `16`. Do not change what happens when the env var is absent.
- **An explicit constructor argument always wins over the env var.** This is not a design choice this plan is free to revisit — it is required for backward compatibility with every prior increment's own test suite, several of which construct `new FieldIdentitySummaryCache(N)` with a small `N` specifically to exercise the cap's degradation behavior without needing environment manipulation.
- All new/changed code must keep `npm run test:lineage` fully green, and must not modify any file outside `scanner/src/lineage/`, `scanner/test/lineage/`, and this plan's own doc/ledger files.

---

## Task 1: The `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` env var

**Files:**
- Modify: `scanner/src/lineage/summaries.js`
- Test: `scanner/test/lineage/summaries.test.js`

**Interfaces:**
- Consumes: `process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS`.
- Produces: `FieldIdentitySummaryCache`'s constructor default changes from the hardcoded `DEFAULT_MAX_CONTEXTS = 16` constant to a function call that reads the env var (falling back to `16` on anything invalid/absent). No change to the class's public method signatures.

- [ ] **Step 1: Write the failing tests**

Add to `scanner/test/lineage/summaries.test.js` (near the existing context-cap test — read that test first, around `'compute: past the per-function distinct-context cap...'`, to match this file's existing style for manipulating `process.env` if any precedent exists elsewhere in this test suite; if none does, use a plain `try`/`finally` around the env var mutation to guarantee cleanup even if an assertion throws):

```js
test('FieldIdentitySummaryCache: AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS env var sets the default cap when no explicit constructor argument is given', () => {
  const prev = process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
  try {
    process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS = '2';
    const cache = new FieldIdentitySummaryCache();
    // Prove the cap is actually 2, not the hardcoded 16, by exercising the
    // SAME degradation behavior the existing cap test already proves works
    // — this is a behavioral proof, not just reading a private field.
    const emptyEntry = emptyState();
    cache.compute('fn1', emptyEntry, () => ({ ...emptyFieldSummary(), returnFlat: new Set(['data:base']) }));
    cache.compute('fn1', addIdentity(emptyState(), 'a', 'data:a'), () => ({ ...emptyFieldSummary(), returnFlat: new Set(['data:a']) }));
    let thirdCallRan = false;
    const result = cache.compute('fn1', addIdentity(emptyState(), 'b', 'data:b'), () => { thirdCallRan = true; return { ...emptyFieldSummary(), returnFlat: new Set(['data:b']) }; });
    assert.equal(thirdCallRan, false, 'with the env var set to 2, the 3rd distinct context must degrade to the cap, exactly as the hardcoded-16 test proves at a different threshold');
    assert.deepEqual([...result.returnFlat], ['data:base']);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
    else process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS = prev;
  }
});

test('FieldIdentitySummaryCache: an explicit constructor argument overrides the env var', () => {
  const prev = process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
  try {
    process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS = '2';
    const cache = new FieldIdentitySummaryCache(16); // explicit arg must win over the env var's 2
    const emptyEntry = emptyState();
    cache.compute('fn1', emptyEntry, () => ({ ...emptyFieldSummary(), returnFlat: new Set(['data:base']) }));
    cache.compute('fn1', addIdentity(emptyState(), 'a', 'data:a'), () => ({ ...emptyFieldSummary(), returnFlat: new Set(['data:a']) }));
    // This would degrade under the env var's cap of 2, but must NOT degrade
    // under the explicit constructor argument of 16.
    let thirdCallRan = false;
    cache.compute('fn1', addIdentity(emptyState(), 'b', 'data:b'), () => { thirdCallRan = true; return { ...emptyFieldSummary(), returnFlat: new Set(['data:b']) }; });
    assert.equal(thirdCallRan, true, 'an explicit constructor argument must override the env var, not merely supplement it');
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
    else process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS = prev;
  }
});

test('FieldIdentitySummaryCache: an invalid env var value (non-numeric or negative) falls back to the hardcoded default of 16, not a crash or a 0-context cap', () => {
  for (const badValue of ['not-a-number', '-5', '']) {
    const prev = process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
    try {
      process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS = badValue;
      const cache = new FieldIdentitySummaryCache();
      const emptyEntry = emptyState();
      cache.compute('fn1', emptyEntry, () => ({ ...emptyFieldSummary(), returnFlat: new Set(['data:base']) }));
      // Add 15 more distinct non-empty contexts (16 total with the empty
      // one) — must NOT degrade yet if the fallback is genuinely 16, not 0
      // or NaN-derived garbage.
      for (let i = 0; i < 15; i++) {
        cache.compute('fn1', addIdentity(emptyState(), `k${i}`, `data:${i}`), () => ({ ...emptyFieldSummary(), returnFlat: new Set([`data:${i}`]) }));
      }
      let ranFor16th = false;
      cache.compute('fn1', addIdentity(emptyState(), 'overflow', 'data:overflow'), () => { ranFor16th = true; return emptyFieldSummary(); });
      assert.equal(ranFor16th, false, `bad env value ${JSON.stringify(badValue)} must fall back to the cap of 16 (so the 17th distinct context — 1 empty + 16 real — degrades), not something smaller`);
    } finally {
      if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
      else process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS = prev;
    }
  }
});

test('FieldIdentitySummaryCache: with the env var UNSET, the default remains 16, byte-identical to pre-increment behavior', () => {
  const prev = process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
  try {
    delete process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
    const cache = new FieldIdentitySummaryCache();
    const emptyEntry = emptyState();
    cache.compute('fn1', emptyEntry, () => ({ ...emptyFieldSummary(), returnFlat: new Set(['data:base']) }));
    for (let i = 0; i < 15; i++) {
      cache.compute('fn1', addIdentity(emptyState(), `k${i}`, `data:${i}`), () => ({ ...emptyFieldSummary(), returnFlat: new Set([`data:${i}`]) }));
    }
    let ranFor17th = false;
    cache.compute('fn1', addIdentity(emptyState(), 'overflow', 'data:overflow'), () => { ranFor17th = true; return emptyFieldSummary(); });
    assert.equal(ranFor17th, false, 'unset env var must preserve the exact pre-increment default of 16');
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS;
    else process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS = prev;
  }
});
```

(`addIdentity` is already imported in this test file from increment B1's own tests — do not re-import it.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: the new tests referencing the env var behavior FAIL (the cap stays at the hardcoded 16 regardless of the env var, since nothing reads it yet) — the "unset env var" test should already PASS (it's asserting today's pre-existing behavior, included as a baseline/regression guard, not because it's expected to fail).

- [ ] **Step 3: Implement the env var**

In `scanner/src/lineage/summaries.js`, replace:

```js
const DEFAULT_MAX_CONTEXTS = 16; // matches dataflow/summaries.js's own default, chosen independently for this
                                  // package (a lineage-specific cap, not shared config, per the isolation
                                  // principle — see the constructor param below for how a caller can override it)
```

with:

```js
// Increment B6: the per-function distinct-context cap's operator-facing
// knob. `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` is DELIBERATELY a separate
// env var from dataflow/summaries.js's own `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS`
// — per the isolation principle every prior increment in this sub-project
// has verified holds, the two engines' tuning knobs must stay decoupled,
// so an operator tuning one engine's cap can never silently affect the
// other's. Mirrors dataflow's own exact validation logic
// (`Number.isFinite(...) && ... >= 0`, falling back to 16 on anything
// invalid or absent) — same reasoning, independently re-derived for this
// package rather than shared config.
//
// Evaluated as a FUNCTION (not a module-level constant) specifically so it
// is read fresh on every `new FieldIdentitySummaryCache()` call with no
// explicit constructor argument — JS default-parameter expressions are
// evaluated at CALL time, not at module-load time, which is what makes
// this testable via `process.env` mutation without needing to re-import
// the module between test cases.
function _defaultMaxContexts() {
  const envCap = Number(process.env.AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS);
  return Number.isFinite(envCap) && envCap >= 0 ? envCap : 16;
}
```

Then change the constructor's default parameter from:

```js
  constructor(maxContextsPerFn = DEFAULT_MAX_CONTEXTS) {
```

to:

```js
  constructor(maxContextsPerFn = _defaultMaxContexts()) {
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: PASS, all tests including the 4 new ones, and every PRE-EXISTING test (including the original hardcoded-16-implied cap test and every other test in this file that constructs `new FieldIdentitySummaryCache(N)`) unchanged and still passing.

- [ ] **Step 5: Confirm the isolation principle still holds**

Run: `grep -n "from '../dataflow/engine\|from '../dataflow/summaries" scanner/src/lineage/summaries.js`
Expected: no output.

Also run: `grep -n "AGENTIC_SECURITY_KCFA_MAX_CONTEXTS" scanner/src/lineage/summaries.js`
Expected: no output — confirms the new env var name is genuinely distinct, not accidentally reusing dataflow's.

- [ ] **Step 6: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 210/210 (206 prior + 4 new).

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/summaries.js scanner/test/lineage/summaries.test.js
git commit -m "feat(lineage): AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS env var for the per-function distinct-context cap (Sub-project B, increment 6, Task 1)"
```

---

## Post-implementation: update `scanner/src/lineage/CLAUDE.md`

After this task is reviewed and clean:
- Update the `summaries.js` row: note the new `AGENTIC_SECURITY_LINEAGE_MAX_CONTEXTS` env var, its validation logic, and that an explicit constructor argument still overrides it (matching the existing description of the per-function cap, extending it rather than replacing it).
- Update the Sub-project B section header from "increments 1-5" to "increments 1-6" — **this completes Sub-project B in full** (B1 through B6, all six increments of `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-b-scoping.md`).
- Correct the "What is NOT here yet" section's B6 status — move it from "still ahead" to done. Since this closes out ALL of Sub-project B, also update whatever top-level framing in this file or the parent Milestone 1 scoping doc references Sub-project B's own completion status, if any such reference exists (check `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md` for a Sub-project B status line — do not edit that file's content beyond what's already accurate, but DO check it, since a final whole-branch review has caught exactly this class of cross-document staleness before in this series).

This is not a separate task — fold it into a final `docs(lineage): ...` commit after Task 1, matching the established pattern from every prior increment in this sub-project.
