# Data Flow Explorer — Milestone 1, Sub-project B, Increment 4: The Project-Wide Two-Phase Driver

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the actual orchestration loop that runs the field-identity engine over an ENTIRE project's worth of functions, producing a real, interprocedurally-resolved summary for every one of them — not just whichever single caller function a hand-written test happens to analyze, which is all increments B1-B3 ever exercised.

**Architecture:** Increments B1-B3 already built a fully lazy, on-demand interprocedural resolution mechanism: `FieldIdentitySummaryCache` (B1), `createCallSummaryResolver` wired into `resolveExprIdentities`'s `call` case via `ctx` (B2), and `createCallGraphLookup` backed by the real call graph (B3). Nothing yet DRIVES this across a whole project. Unlike `dataflow/engine.js`'s `runTaintEngine`, which needs a 3-sub-pass "Phase A" pre-pass (empty-entry probe + two speculative precompute passes) specifically because some of ITS call-consultation points are non-computing cache *lookups* that need a pre-seeded conservative fallback, this package's ONE call-consultation point (`resolveCallSummary`, built in B1/B2) already lazily `cache.compute()`s on every miss — so a single pass over every function, each analyzed with its own empty entry state and a ctx wired for interprocedural resolution, is sufficient. This increment adds exactly that: `runFieldIdentityAnalysis(callGraph, opts)` in a new file, `scanner/src/lineage/driver.js`, plus a small, behavior-preserving refactor extracting the existing inline "raw analysis result → cached summary shape" conversion (currently only inside `createCallSummaryResolver`'s own callback) into a shared, reusable function the new driver also needs.

**Tech Stack:** Node.js ESM, `node:test`, `scanner/src/ir/parser-js.js` (real JS/TS parser), `scanner/src/ir/callgraph.js` (existing, unmodified — this plan only CONSUMES `buildCallGraph`), `scanner/src/lineage/summaries.js` (existing, extended), `scanner/src/lineage/driver.js` (NEW).

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` (repo root, untracked per this repo's PRD convention) — Milestone 1 requirement FR-301 (never silently merge/drop distinct data-element identities) and FR-302 (interprocedural resolution). This plan also argues from `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-b-scoping.md`'s own B4 row: *"The actual orchestration loop mirroring `runTaintEngine`'s Phase A/B, producing summaries for a whole small project's worth of functions, not just one call site at a time."*

## Global Constraints

- **Isolation principle (non-negotiable, verified in every prior increment's review):** `scanner/src/lineage/` may import PURE utilities from `scanner/src/ir/` but must NEVER import `scanner/src/dataflow/engine.js` or `scanner/src/dataflow/summaries.js`, and must never share mutable taint state with the dataflow engine. `scanner/src/lineage/driver.js` may depend on `scanner/src/lineage/summaries.js`, `scanner/src/lineage/engine.js`, and `scanner/src/lineage/field-identity.js`; none of those may ever import FROM `driver.js` (the dependency direction only runs one way, same as `summaries.js` → `engine.js`).
- **No fixed-point loop in this increment.** Recursion/cycle-convergence refinement is explicitly increment B5's job (see the scoping doc's B4/B5 rows). This driver does exactly ONE pass over `fnList`; a recursive or mutually-recursive call graph is handled entirely by B1's existing `_stack`-based bottom-stub (returns an honest, unrefined `{_recursive: true}` result) — do not attempt to detect or re-analyze past that.
- **Task 1's refactor must be BEHAVIOR-PRESERVING.** Every existing test in `scanner/test/lineage/summaries.test.js` and `scanner/test/lineage/engine-integration.test.js` must pass UNCHANGED after Task 1 — this is a pure extraction (moving existing logic into a named, exported function), not a logic change. If you find yourself wanting to change what the extracted logic actually computes, stop — that belongs in a different task, not this refactor.
- **`createCallSummaryResolver`'s and `createCallGraphLookup`'s existing signatures do not change.** The driver is a new CONSUMER of both, built on top of them exactly as any other caller would use them — not a reason to modify either.
- All new/changed code must keep `npm run test:lineage` fully green, and must not modify any file outside `scanner/src/lineage/`, `scanner/test/lineage/`, and this plan's own doc/ledger files. `scanner/src/ir/callgraph.js` is READ-ONLY for this plan.

---

## Task 1: Extract `summaryFromAnalysisResult` as a shared, reusable conversion

**Files:**
- Modify: `scanner/src/lineage/summaries.js`
- Test: `scanner/test/lineage/summaries.test.js`

**Interfaces:**
- Consumes: nothing new — this task reorganizes existing code within `summaries.js`.
- Produces: `summaryFromAnalysisResult(result)` — a new EXPORTED function in `scanner/src/lineage/summaries.js`, converting `analyzeFunctionFieldIdentity`'s raw return shape (`{exitState, returnFacts, mutatedParams, widenings}`) into the `FieldSummary` shape (`{returnFlat, returnByPath, mutatedParams, widenings}`) that `FieldIdentitySummaryCache` stores and `createCallSummaryResolver`'s consumers read. Task 2 (the driver) needs this exact same conversion and must not reimplement it a second time.

- [ ] **Step 1: Write the failing test**

Add to `scanner/test/lineage/summaries.test.js` (near the existing `createCallSummaryResolver` tests):

```js
test('summaryFromAnalysisResult unions identities across every return site, not just the first', () => {
  const analysisResult = {
    exitState: null,
    returnFacts: [
      { nodeId: 'n1', line: 2, identities: new Set(['data:email']) },
      { nodeId: 'n2', line: 4, identities: new Set(['data:ssn']) },
    ],
    mutatedParams: new Map([['x', new Set(['data:x'])]]),
    widenings: [{ reason: 'unresolved-call', atPath: 'y', line: 9 }],
  };

  const summary = summaryFromAnalysisResult(analysisResult);

  assert.deepStrictEqual([...summary.returnFlat].sort(), ['data:email', 'data:ssn']);
  assert.deepStrictEqual(summary.returnByPath, new Map());
  assert.strictEqual(summary.mutatedParams, analysisResult.mutatedParams);
  assert.strictEqual(summary.widenings, analysisResult.widenings);
});

test('summaryFromAnalysisResult with no return facts produces an empty returnFlat', () => {
  const analysisResult = { exitState: null, returnFacts: [], mutatedParams: new Map(), widenings: [] };
  const summary = summaryFromAnalysisResult(analysisResult);
  assert.strictEqual(summary.returnFlat.size, 0);
});
```

Add the import at the top of the test file, alongside the existing `summaries.js` imports:
```js
import { summaryFromAnalysisResult } from '../../src/lineage/summaries.js';
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: FAIL — `summaryFromAnalysisResult is not a function` (or a named-export import error).

- [ ] **Step 3: Extract the function**

In `scanner/src/lineage/summaries.js`, find `createCallSummaryResolver` (it currently ends with the block below — read the file first to confirm this is still the exact current text, since prior increments may have added comments around it):

```js
    return cache.compute(qid, entryState, (es) => {
      // Pass THIS SAME resolver down as the callee's own ctx — without
      // this, a chain of resolved calls (outer resolves to middle, middle
      // itself calls inner) would silently stop resolving after one hop:
      // middle's own analysis would run with no ctx, so its call to inner
      // would take the unresolved fallback, and outer would receive a
      // coarsely-widened summary reported as `widened: false` (since
      // resolveExprIdentities's call case only reads summary.returnFlat/
      // returnByPath, never summary.widenings) — a confident-looking
      // answer that's silently wrong one level down. A final whole-branch
      // review found and proved this exact gap via a real three-function
      // chain. Passing the resolver down makes resolution recurse through
      // as many resolved hops as `lookupCallee` can cover, with the
      // existing recursion guard (field-identity summary cache's `_stack`
      // bottom-stub) already sufficient to keep a self- or mutually-
      // recursive chain safe (verified: both terminate immediately,
      // returning an empty, honestly-unrefined result — precision there
      // is increment B5's job, not this fix's).
      const result = analyzeFunctionFieldIdentity(fn, es, { resolveCallSummary });
      // Union across EVERY return site, not just the first — a function
      // with multiple return statements (e.g. an early-return branch) must
      // have all of them reflected, not just whichever happened to be
      // recorded first. This is a genuine correctness improvement over
      // increment B1's own round-trip test's `returnFacts[0]` shortcut
      // (that test only ever exercised a single-return-site function, so
      // the shortcut was harmless there — this shared, reusable resolver is
      // the right place to do it correctly going forward).
      const returnFlat = new Set();
      for (const rf of result.returnFacts) {
        for (const id of rf.identities) returnFlat.add(id);
      }
      return {
        returnFlat,
        returnByPath: new Map(), // still flat-only — see B1's disclosed limitation in CLAUDE.md; not closed by this increment either
        mutatedParams: result.mutatedParams,
        widenings: result.widenings,
      };
    });
  };
}
```

Replace it with (moving the "union across every return site" comment onto the new function, leaving a short pointer comment behind at the call site):

```js
    return cache.compute(qid, entryState, (es) => {
      // Pass THIS SAME resolver down as the callee's own ctx — without
      // this, a chain of resolved calls (outer resolves to middle, middle
      // itself calls inner) would silently stop resolving after one hop:
      // middle's own analysis would run with no ctx, so its call to inner
      // would take the unresolved fallback, and outer would receive a
      // coarsely-widened summary reported as `widened: false` (since
      // resolveExprIdentities's call case only reads summary.returnFlat/
      // returnByPath, never summary.widenings) — a confident-looking
      // answer that's silently wrong one level down. A final whole-branch
      // review found and proved this exact gap via a real three-function
      // chain. Passing the resolver down makes resolution recurse through
      // as many resolved hops as `lookupCallee` can cover, with the
      // existing recursion guard (field-identity summary cache's `_stack`
      // bottom-stub) already sufficient to keep a self- or mutually-
      // recursive chain safe (verified: both terminate immediately,
      // returning an empty, honestly-unrefined result — precision there
      // is increment B5's job, not this fix's).
      const result = analyzeFunctionFieldIdentity(fn, es, { resolveCallSummary });
      return summaryFromAnalysisResult(result);
    });
  };
}

// Converts analyzeFunctionFieldIdentity's raw per-function result
// (`{exitState, returnFacts, mutatedParams, widenings}`) into the
// FieldSummary shape (`{returnFlat, returnByPath, mutatedParams,
// widenings}`) that FieldIdentitySummaryCache stores and every consumer of
// a resolved summary reads. Extracted (increment B4) from what was
// previously inline-only logic inside createCallSummaryResolver's own
// cache.compute callback, so increment B4's project-wide driver can seed
// the cache with the exact SAME conversion for a function's own top-level
// analysis, rather than reimplementing it a second time and risking the
// two copies drifting apart.
//
// Unions identities across EVERY return site, not just the first — a
// function with multiple return statements (e.g. an early-return branch)
// must have all of them reflected, not just whichever happened to be
// recorded first. This was a genuine correctness improvement over
// increment B1's own round-trip test's `returnFacts[0]` shortcut (that
// test only ever exercised a single-return-site function, so the shortcut
// was harmless there).
export function summaryFromAnalysisResult(result) {
  const returnFlat = new Set();
  for (const rf of result.returnFacts) {
    for (const id of rf.identities) returnFlat.add(id);
  }
  return {
    returnFlat,
    returnByPath: new Map(), // still flat-only — see B1's disclosed limitation in CLAUDE.md; not closed by this increment either
    mutatedParams: result.mutatedParams,
    widenings: result.widenings,
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: PASS, all tests including the 2 new ones.

- [ ] **Step 5: Confirm zero behavior change to existing tests**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 193/193 (191 prior + 2 new from this task's Step 1). `driver.test.js` doesn't exist yet at this point (Task 2 creates it) so it is not part of this count.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/summaries.js scanner/test/lineage/summaries.test.js
git commit -m "refactor(lineage): extract summaryFromAnalysisResult as a shared, reusable conversion (Sub-project B, increment 4, Task 1)"
```

---

## Task 2: The project-wide driver

**Files:**
- Create: `scanner/src/lineage/driver.js`
- Test: `scanner/test/lineage/driver.test.js` (NEW FILE)

**Interfaces:**
- Consumes: `emptyState` (`field-identity.js`), `analyzeFunctionFieldIdentity` (`engine.js`), `FieldIdentitySummaryCache`/`createCallGraphLookup`/`createCallSummaryResolver`/`summaryFromAnalysisResult` (`summaries.js`, the last one from Task 1 — Task 2 MUST be dispatched after Task 1 lands).
- Produces: `runFieldIdentityAnalysis(callGraph, opts = {})` — exported from the new `scanner/src/lineage/driver.js`. Returns `{results, cache}` where `results` is a `Map<qid, rawAnalysisResult>` (one entry per function in `callGraph.functions`, value shape = whatever `analyzeFunctionFieldIdentity` itself returns) and `cache` is the `FieldIdentitySummaryCache` instance used throughout.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/lineage/driver.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { FieldIdentitySummaryCache } from '../../src/lineage/summaries.js';

// Minimal hand-built callGraph fixture matching buildCallGraph's own
// output shape ({functions: Map<qid, fn>, resolveKnownCallee(name, callerFile)}) —
// isolates driver.js's own orchestration logic from real-parser/real-callgraph
// concerns (Task 3 covers those).
function fnRecord(qid, name, file, params = []) {
  return {
    qid, name, file, params,
    cfg: { entry: 'n0', exit: 'n1', nodes: {
      n0: { kind: 'entry', succ: ['n1'], pred: [] },
      n1: { kind: 'exit', succ: [], pred: ['n0'] },
    } },
  };
}

function handBuiltCallGraph(fns) {
  const functions = new Map(fns.map(fn => [fn.qid, fn]));
  const byFile = new Map();
  for (const fn of fns) {
    if (!byFile.has(fn.file)) byFile.set(fn.file, new Map());
    byFile.get(fn.file).set(fn.name, fn.qid);
  }
  return {
    functions,
    resolveKnownCallee(name, callerFile) {
      const local = byFile.get(callerFile);
      if (local && local.has(name)) return local.get(name);
      for (const m of byFile.values()) {
        if (m.has(name)) return m.get(name);
      }
      return null;
    },
  };
}

test('runFieldIdentityAnalysis produces one result per function in the call graph', () => {
  const fns = [
    fnRecord('a.js::f1@1', 'f1', 'a.js'),
    fnRecord('a.js::f2@2', 'f2', 'a.js'),
    fnRecord('b.js::f3@1', 'f3', 'b.js'),
  ];
  const callGraph = handBuiltCallGraph(fns);

  const { results, cache } = runFieldIdentityAnalysis(callGraph);

  assert.strictEqual(results.size, 3);
  assert.ok(results.has('a.js::f1@1'));
  assert.ok(results.has('a.js::f2@2'));
  assert.ok(results.has('b.js::f3@1'));
  assert.ok(cache instanceof FieldIdentitySummaryCache);
});

test('runFieldIdentityAnalysis handles an empty call graph gracefully', () => {
  const { results, cache } = runFieldIdentityAnalysis(handBuiltCallGraph([]));
  assert.strictEqual(results.size, 0);
  assert.strictEqual(cache.size(), 0);
});

test('runFieldIdentityAnalysis handles a null/undefined callGraph gracefully (no throw)', () => {
  const { results } = runFieldIdentityAnalysis(null);
  assert.strictEqual(results.size, 0);
});

test('runFieldIdentityAnalysis reuses a caller-supplied cache via opts.cache instead of creating a fresh one', () => {
  const fns = [fnRecord('a.js::f1@1', 'f1', 'a.js')];
  const callGraph = handBuiltCallGraph(fns);
  const suppliedCache = new FieldIdentitySummaryCache();

  const { cache } = runFieldIdentityAnalysis(callGraph, { cache: suppliedCache });

  assert.strictEqual(cache, suppliedCache);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scanner && node --test test/lineage/driver.test.js`
Expected: FAIL — `Cannot find module '../../src/lineage/driver.js'`.

- [ ] **Step 3: Implement the driver**

Create `scanner/src/lineage/driver.js`:

```js
import { emptyState } from './field-identity.js';
import { analyzeFunctionFieldIdentity } from './engine.js';
import {
  FieldIdentitySummaryCache,
  createCallGraphLookup,
  createCallSummaryResolver,
  summaryFromAnalysisResult,
} from './summaries.js';

// Project-wide driver (Sub-project B, increment 4) — mirrors
// dataflow/engine.js's runTaintEngine Phase A/B structure, adapted to this
// package's own machinery: B1-B3 already built a fully lazy, on-demand
// interprocedural resolution mechanism, but nothing yet DRIVES it across
// an entire project — every prior increment's test only ever analyzed ONE
// caller function, hand-picking which callee to resolve. This is the
// "producing summaries for a whole small project's worth of functions,
// not just one call site at a time" piece the scoping doc calls out.
//
// Unlike dataflow's own 3-sub-pass Phase A (empty-entry pre-pass plus two
// SPECULATIVE precompute passes, justified by that engine's need to
// pre-seed conservative summaries so a non-computing cache LOOKUP
// mid-expression-walk doesn't have to guess), this driver needs none of
// that: this package's one call-consultation point (`resolveCallSummary`,
// built in B1/B2) already lazily `cache.compute()`s on every miss — see
// `createCallSummaryResolver`. A single pass over every function, each
// analyzed with its own empty entry state and a ctx wired for
// interprocedural resolution, is therefore sufficient: whichever order
// functions are visited in, a call to an as-yet-unvisited callee still
// resolves correctly (lazily, on demand) rather than falling back to a
// conservative default. No fixed-point loop here — recursive/cyclic
// convergence refinement is increment B5's job; this driver relies
// entirely on B1's existing `_stack`-based bottom-stub for safety on a
// recursive/cyclic call graph, exactly as B1-B3 already did.
//
// `callGraph` must be a real object from
// `scanner/src/ir/callgraph.js#buildCallGraph` (`{functions,
// resolveKnownCallee, ...}`) or an equivalent hand-built fixture exposing
// the same shape (see this file's own tests). `opts.maxContextsPerFn` is
// forwarded to a fresh `FieldIdentitySummaryCache` unless `opts.cache` is
// supplied directly, letting a caller reuse/inspect the cache afterward or
// seed it before calling — mirrors dataflow's own `opts.summaryCache`
// escape hatch in `runTaintEngine`.
//
// Returns `{results, cache}`: `results` is a `Map<qid, rawAnalysisResult>`
// — the raw `{exitState, returnFacts, mutatedParams, widenings}` shape
// `analyzeFunctionFieldIdentity` itself returns, one entry per function in
// `callGraph.functions` — and `cache` is the `FieldIdentitySummaryCache`
// instance used throughout, seeded with every function's own empty-entry
// summary (converted via `summaryFromAnalysisResult`) plus whatever
// additional real-context entries were computed lazily along the way as
// call sites were resolved.
export function runFieldIdentityAnalysis(callGraph, opts = {}) {
  const cache = opts.cache instanceof FieldIdentitySummaryCache
    ? opts.cache
    : new FieldIdentitySummaryCache(opts.maxContextsPerFn);

  const fnList = callGraph && callGraph.functions
    ? [...callGraph.functions.values()].sort((a, b) => (a.qid < b.qid ? -1 : a.qid > b.qid ? 1 : 0))
    : [];

  const results = new Map();
  for (const fn of fnList) {
    const lookupCallee = createCallGraphLookup(callGraph, fn.file);
    const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
    const result = analyzeFunctionFieldIdentity(fn, emptyState(), { resolveCallSummary });
    results.set(fn.qid, result);
    // Seed the cache with this function's OWN empty-entry summary directly
    // (not via cache.compute, which is reserved for a CALL SITE resolving
    // an as-yet-uncomputed callee) — this is what lets a LATER function in
    // fnList that calls this one reuse the driver's own result instead of
    // silently recomputing it a second time. Safe to overwrite an entry a
    // callee-triggered lazy compute() may have already written for the
    // SAME (qid, emptyState()) key earlier in this loop — deterministic
    // analysis means both would agree; this is redundant work in that
    // case, never a correctness issue.
    cache.set(fn.qid, emptyState(), summaryFromAnalysisResult(result));
  }

  return { results, cache };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/driver.test.js`
Expected: PASS, all 4 tests.

- [ ] **Step 5: Wire the new test file into the scoped test script**

`scanner/package.json`'s `test:lineage` script is an EXPLICIT space-separated file list, not a glob — a new test file is invisible to it until added by hand (confirmed by reading the script directly; do not assume glob behavior). Add `test/lineage/driver.test.js` to the end of that list (append after the existing `test/lineage/summaries.test.js` entry, keeping the same `node --test ...` structure). Verify by running `npm run test:lineage` and confirming the new driver tests actually execute (check the printed test names, not just the pass count) — a missing wire-up would silently pass with the SAME count as before Task 2, which is the exact failure mode to watch for.

- [ ] **Step 6: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, all prior tests plus the 4 new driver tests, 0 failures.

- [ ] **Step 7: Confirm the isolation principle still holds**

Run: `grep -n "from '../dataflow/engine\|from '../dataflow/summaries" scanner/src/lineage/driver.js`
Expected: no output.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/lineage/driver.js scanner/test/lineage/driver.test.js scanner/package.json
git commit -m "feat(lineage): project-wide two-phase driver, runFieldIdentityAnalysis (Sub-project B, increment 4, Task 2)"
```

---

## Task 3: Real-parser, multi-file, whole-project integration proof

**Files:**
- Test: `scanner/test/lineage/driver.test.js` (extend the file created in Task 2)

**Interfaces:**
- Consumes: `runFieldIdentityAnalysis` (Task 2), `buildCallGraph` (`scanner/src/ir/callgraph.js`), `parseJsFile(file, code)` (`scanner/src/ir/parser-js.js`).
- Produces: nothing new for later tasks — this is the final proof task for this increment.

- [ ] **Step 1: Write the failing test**

Add these imports to `scanner/test/lineage/driver.test.js`:

```js
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
```

Add this test:

```js
test('real, whole-project integration: three real files (a caller, a callee, and dead code nobody calls) all get a result, and the caller resolves the callee\'s real field identity (Sub-project B, increment 4)', () => {
  const sourceA = `
function outer(id) {
  const u = getUser(id);
  return u;
}
`;
  const sourceB = `
function getUser(userId) {
  return { email: userId, ssn: 'unrelated' };
}
`;
  const sourceC = `
function neverCalled(x) {
  return { note: x };
}
`;

  const irA = parseJsFile('/x/a.js', sourceA);
  const irB = parseJsFile('/x/b.js', sourceB);
  const irC = parseJsFile('/x/c.js', sourceC);
  assert.ok(irA && irB && irC, 'real parser must successfully parse all three files');

  const perFileIR = { '/x/a.js': irA, '/x/b.js': irB, '/x/c.js': irC };
  const callGraph = buildCallGraph(perFileIR, { '/x/a.js': sourceA, '/x/b.js': sourceB, '/x/c.js': sourceC });

  const { results } = runFieldIdentityAnalysis(callGraph);

  // Every function in the project gets a result, including the one
  // nothing calls — a purely lazy, call-site-triggered scheme (B1-B3
  // alone) would never analyze `neverCalled` at all, since it's only ever
  // reached as a SIDE EFFECT of some caller's own call-site resolution.
  const outerFn = irA.functions.find(f => f.name === 'outer');
  const getUserFn = irB.functions.find(f => f.name === 'getUser');
  const neverCalledFn = irC.functions.find(f => f.name === 'neverCalled');
  assert.ok(results.has(outerFn.qid));
  assert.ok(results.has(getUserFn.qid));
  assert.ok(results.has(neverCalledFn.qid));
  assert.strictEqual(results.size, 3);

  // outer()'s own result must reflect real, resolved interprocedural
  // resolution of its call to getUser — not the widened unresolved-call
  // fallback. Same discriminating-signal choice as increment B3's own
  // proof (a return-fact's `widened` field does not exist; `widenings` is
  // the real, non-tautological signal — see B3's own regression test for
  // why the naive `returnFacts[0].widened` assertion is a dead end).
  const outerResult = results.get(outerFn.qid);
  assert.strictEqual(outerResult.widenings.length, 0);
});

test('real, whole-project integration: two independent driver runs against the same call graph (fresh cache each time) produce identical results (determinism)', () => {
  const sourceA = `
function outer(id) {
  return getUser(id);
}
`;
  const sourceB = `
function getUser(userId) {
  return { email: userId };
}
`;
  const irA = parseJsFile('/y/a.js', sourceA);
  const irB = parseJsFile('/y/b.js', sourceB);
  const perFileIR = { '/y/a.js': irA, '/y/b.js': irB };
  const callGraph = buildCallGraph(perFileIR, { '/y/a.js': sourceA, '/y/b.js': sourceB });

  const run1 = runFieldIdentityAnalysis(callGraph);
  const run2 = runFieldIdentityAnalysis(callGraph);

  assert.strictEqual(run1.results.size, run2.results.size);
  for (const [qid, result1] of run1.results) {
    const result2 = run2.results.get(qid);
    assert.ok(result2, `expected qid ${qid} to be present in both runs`);
    assert.strictEqual(result1.widenings.length, result2.widenings.length);
    assert.strictEqual(result1.returnFacts.length, result2.returnFacts.length);
  }
});
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/driver.test.js`
Expected: PASS on first try if Tasks 1-2 are correct — this test is a composition of already-proven pieces (`buildCallGraph`, `runFieldIdentityAnalysis`, `parseJsFile` are all independently tested elsewhere). If it fails, investigate the real cause rather than adjusting the test to match — in particular, if `outerResult.widenings.length !== 0`, verify by hand-tracing whether `createCallGraphLookup('/x/a.js')` actually resolves `getUser` (same mechanism increment B3 already proved works for a 2-file case) before assuming the driver itself is at fault.

- [ ] **Step 3: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, all prior tests plus the 2 new tests from this task, 0 failures.

- [ ] **Step 4: Commit**

```bash
git add scanner/test/lineage/driver.test.js
git commit -m "test(lineage): real, whole-project multi-file integration proof for the driver (Sub-project B, increment 4, Task 3)"
```

---

## Post-implementation: update `scanner/src/lineage/CLAUDE.md`

After all three tasks are reviewed and clean, update the module table (add a `driver.js` row, or extend the existing Sub-project B section header from "increments 1-3" to "increments 1-4") to document:
- `runFieldIdentityAnalysis(callGraph, opts)` exists, what it returns, and why it needed no fixed-point loop (the reasoning in this plan's Architecture section and `driver.js`'s own header comment).
- `summaryFromAnalysisResult` now exists as a shared, exported conversion (Task 1's refactor) — update the description of `createCallSummaryResolver` if it still describes the union-across-return-sites logic as living only inline there.
- Correct the "What is NOT here yet" section's "B4 (the project-wide two-phase driver)... still ahead" phrasing — B4 is this increment, done. (This is exactly the class of self-contradiction a final whole-branch review caught in increment B3 — check this section carefully before committing the doc update.)

This is not a separate task — fold it into a final `docs(lineage): ...` commit after all three tasks, matching the pattern established in increments B2/B3.
