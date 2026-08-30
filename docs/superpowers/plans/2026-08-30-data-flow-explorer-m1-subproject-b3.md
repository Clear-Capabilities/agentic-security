# Data Flow Explorer — Milestone 1, Sub-project B, Increment 3: Real Call-Graph Integration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-built `lookupCallee` maps that increments B1/B2 used for testing with a REAL resolver backed by `scanner/src/ir/callgraph.js`'s `buildCallGraph`/`resolveKnownCallee`, proven against the real JS/TS parser across multiple files.

**Architecture:** `createCallSummaryResolver(cache, lookupCallee)` (built in increment B1, wired into `resolveExprIdentities`'s `call` case in B2) already treats `lookupCallee` as an injected, opaque `(calleeExpr) => {qid, fn} | null` function — B1/B2's own tests hand-built this map. This increment adds the REAL implementation: a factory that, given a real `callGraph` (from `buildCallGraph`) and a fixed caller file, returns a `lookupCallee` closure resolving a call expression's bare-identifier callee to a real function record via `resolveKnownCallee` + `functionRecord`. No change to `createCallSummaryResolver`'s signature or to `resolveExprIdentities`'s `call` case — this increment is purely "give B1/B2's existing seam a real implementation," proven end-to-end across two real, separately-parsed files.

**Tech Stack:** Node.js ESM, `node:test`, `scanner/src/ir/parser-js.js` (Babel-based real JS/TS parser), `scanner/src/ir/callgraph.js` (existing, unmodified — this plan only CONSUMES it), `scanner/src/lineage/summaries.js` (existing, extended).

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` (repo root, untracked per this repo's PRD convention) — Milestone 1 requirement FR-301 (never silently merge/drop distinct data-element identities) and FR-302 (interprocedural resolution). This plan also argues from `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-b-scoping.md`'s own B3 row: *"Real call-graph integration — Wires `scanner/src/ir/callgraph.js`'s `buildCallGraph`/`resolveKnownCallee` in for real, proven against the real JS/TS parser across multiple files (mirrors Sub-project A's Task 5's 'real parser' discipline, this time for cross-file real call resolution too)."*

## Global Constraints

- **Isolation principle (non-negotiable, verified in every prior increment's review):** `scanner/src/lineage/` may import PURE utilities from `scanner/src/ir/` (this increment imports `buildCallGraph`, `functionRecord` — both pure, side-effect-free query functions over an IR the caller already built) but must NEVER import `scanner/src/dataflow/engine.js` or `scanner/src/dataflow/summaries.js`, and must never share mutable taint state with the dataflow engine. `scanner/src/lineage/summaries.js` may depend on `scanner/src/lineage/engine.js`; the dependency must never run the other direction.
- **Bare-identifier resolution only — do NOT add member-expression (CHA-based) callee resolution.** `scanner/src/dataflow/engine.js`'s OWN base case (`_resolvableCalleeName`, before its later CHA extension) resolves only `calleeExpr.kind === 'ident'` callees — a member-expression callee (`obj.method()`) needs class-hierarchy analysis to resolve safely, which is a separate, much larger mechanism dataflow built specifically for that purpose (`_resolveMemberCalleeViaCHA`, gated on a `_cha` object this package has no equivalent of). This increment MUST mirror only the safe, simple bare-ident base case. A member-expression callee must resolve to `null` (falls through to the existing unresolved-call fallback in `resolveExprIdentities`) — never guess.
- **Never fabricate a resolution.** `resolveKnownCallee` (not `resolve()`) is the only entry point to use — it is `callgraph.js`'s own "safe-by-default" resolver (see that file's comment above `resolveKnownCallee`'s definition) that never guesses from a dotted name's last segment. Using `resolve()` instead would silently reintroduce the exact class of fabricated-edge bug `callgraph.js`'s own comments describe as "worse than a missing one."
- **`createCallSummaryResolver`'s signature does not change.** `lookupCallee` stays a single-argument `(calleeExpr) => {qid, fn} | null` function. The caller file is baked into the closure at construction time (one `lookupCallee` per analyzed function/file, not a global one) — this is what lets the existing `resolveCallSummary(calleeExpr, callArgs, callerState)` call shape (no caller-file parameter) keep working unchanged.
- All new/changed code must keep `npm run test:lineage` fully green, and must not modify any file outside `scanner/src/lineage/`, `scanner/test/lineage/`, and this plan's own doc/ledger files. `scanner/src/ir/callgraph.js` is READ-ONLY for this plan — it is already correct and proven; if you think it needs a change, stop and flag it rather than editing it.

---

## Task 1: Real `lookupCallee` factory backed by the real call graph

**Files:**
- Modify: `scanner/src/lineage/summaries.js`
- Test: `scanner/test/lineage/summaries.test.js`

**Interfaces:**
- Consumes: `buildCallGraph(perFileIR, fileContents)`, `functionRecord(callGraph, resolved)` from `scanner/src/ir/callgraph.js` (both already exist, unmodified). A `callGraph` object built by `buildCallGraph` exposes `{ functions, edges, callersOf, resolve, resolveKnownCallee }`; `resolveKnownCallee(name, callerFile)` returns a qid string or `null` (never a record — see `functionRecord`'s own doc comment for why the two-step `resolveKnownCallee` → `functionRecord` bridge exists).
- Produces: `createCallGraphLookup(callGraph, callerFile)` — a new exported function in `scanner/src/lineage/summaries.js`. Returns a function of shape `(calleeExpr) => {qid: string, fn: object} | null`, directly usable as the second argument to the EXISTING `createCallSummaryResolver(cache, lookupCallee)` (from increment B1, already in this file, unchanged by this task).

- [ ] **Step 1: Write the failing tests**

Add to `scanner/test/lineage/summaries.test.js` (append near the existing `createCallSummaryResolver` tests — read that file first to match its existing style and its existing hand-built fixture helpers before adding these):

```js
import { buildCallGraph } from '../../src/ir/callgraph.js';

test('createCallGraphLookup resolves a bare-identifier call to a real function record via resolveKnownCallee', () => {
  // Hand-built IR shape matching the documented contract in ir/CLAUDE.md —
  // deliberately NOT going through the real parser here (Task 2 does that);
  // this test isolates createCallGraphLookup's own logic against a minimal,
  // exact-shape fixture.
  const calleeFn = {
    qid: 'a.js::helper@1#abc',
    name: 'helper',
    params: ['x'],
    file: 'a.js',
    cfg: { entry: 'n0', exit: 'n1', nodes: {
      n0: { kind: 'entry', succ: ['n1'], pred: [] },
      n1: { kind: 'exit', succ: [], pred: ['n0'] },
    } },
  };
  const perFileIR = { 'a.js': { functions: [calleeFn] } };
  const callGraph = buildCallGraph(perFileIR, {});

  const lookupCallee = createCallGraphLookup(callGraph, 'a.js');
  const result = lookupCallee({ kind: 'ident', name: 'helper' });

  assert.ok(result);
  assert.strictEqual(result.qid, 'a.js::helper@1#abc');
  assert.strictEqual(result.fn, calleeFn);
});

test('createCallGraphLookup returns null for an unresolvable bare identifier (no matching function)', () => {
  const perFileIR = { 'a.js': { functions: [] } };
  const callGraph = buildCallGraph(perFileIR, {});
  const lookupCallee = createCallGraphLookup(callGraph, 'a.js');

  assert.strictEqual(lookupCallee({ kind: 'ident', name: 'doesNotExist' }), null);
});

test('createCallGraphLookup returns null for a member-expression callee (no CHA — must not guess)', () => {
  const calleeFn = {
    qid: 'a.js::helper@1#abc',
    name: 'helper',
    params: [],
    file: 'a.js',
    cfg: { entry: 'n0', exit: 'n1', nodes: {
      n0: { kind: 'entry', succ: ['n1'], pred: [] },
      n1: { kind: 'exit', succ: [], pred: ['n0'] },
    } },
  };
  const perFileIR = { 'a.js': { functions: [calleeFn] } };
  const callGraph = buildCallGraph(perFileIR, {});
  const lookupCallee = createCallGraphLookup(callGraph, 'a.js');

  // obj.helper() must NOT resolve just because a same-named bare function
  // exists — that would be exactly the fabricated-edge class of bug the
  // isolation-from-CHA constraint above exists to prevent.
  const result = lookupCallee({ kind: 'member', object: { kind: 'ident', name: 'obj' }, prop: 'helper' });
  assert.strictEqual(result, null);
});

test('createCallGraphLookup returns null when given a falsy callGraph or one missing resolveKnownCallee', () => {
  assert.strictEqual(createCallGraphLookup(null, 'a.js')({ kind: 'ident', name: 'x' }), null);
  assert.strictEqual(createCallGraphLookup({}, 'a.js')({ kind: 'ident', name: 'x' }), null);
});
```

Also add the import at the top of the test file (alongside the existing imports from `../../src/lineage/summaries.js`):
```js
import { createCallGraphLookup } from '../../src/lineage/summaries.js';
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: FAIL — `createCallGraphLookup is not a function` (or a named-export import error).

- [ ] **Step 3: Implement `createCallGraphLookup`**

In `scanner/src/lineage/summaries.js`, add this import alongside the existing ones at the top of the file:

```js
import { functionRecord } from '../ir/callgraph.js';
```

(`buildCallGraph` itself is NOT imported here — this file only CONSUMES an already-built `callGraph`, exactly like `dataflow/engine.js`'s own `_resolveCalleeForSummary` does. Building the call graph is the caller's job — Task 2's test does that, and eventually Sub-project B increment 4's driver will.)

Add this function at the end of the file (after `createCallSummaryResolver`):

```js
// Resolves a call expression's callee to a bare, resolvable name — the
// lineage-engine analog of dataflow/engine.js's own `_resolvableCalleeName`
// BASE CASE (before that file's later, CHA-gated member-expression
// extension). Deliberately narrow: only a bare identifier callee
// (`helper(x)`) resolves to a name at all. A member-expression callee
// (`obj.helper(x)`) returns null here, on purpose — resolving THAT safely
// needs class-hierarchy analysis (which method does the object concretely
// carry), a separate, much larger mechanism dataflow built specifically for
// its own R11 requirement (`_resolveMemberCalleeViaCHA`, gated on a `_cha`
// object this package has no equivalent of and is not in scope to build
// here). Guessing from the property name alone would fabricate a call edge
// that may not exist — worse than leaving the call unresolved, matching
// this whole codebase's own stated doctrine (see callgraph.js's comments
// on `resolveKnownCallee` vs. the guessing `resolve()`).
function _resolvableCalleeName(calleeExpr) {
  if (!calleeExpr) return null;
  if (calleeExpr.kind === 'ident') return calleeExpr.name || null;
  return null;
}

// Builds a real `lookupCallee` closure — the shape `createCallSummaryResolver`
// expects as its second argument — backed by a real call graph from
// `scanner/src/ir/callgraph.js#buildCallGraph`. `callerFile` is fixed at
// construction time: one `lookupCallee` closure is built per analyzed
// function/file (mirroring how `dataflow/engine.js`'s own
// `_resolveCalleeForSummary` derives `_callerFile` fresh per call context),
// so `createCallSummaryResolver`'s existing single-argument `lookupCallee`
// shape (no caller-file parameter) does not need to change.
//
// Uses `resolveKnownCallee` — never `resolve()` — matching `callgraph.js`'s
// own documented distinction: `resolveKnownCallee` is "safe-by-default,"
// refusing the bare-name-tail guess `resolve()` is willing to make. This
// package's own doctrine (see FR-301, never silently merge/drop distinct
// identities) treats a fabricated call edge as strictly worse than a missed
// one, same as dataflow's own precedent.
export function createCallGraphLookup(callGraph, callerFile) {
  return function lookupCallee(calleeExpr) {
    if (!callGraph || typeof callGraph.resolveKnownCallee !== 'function') return null;
    const name = _resolvableCalleeName(calleeExpr);
    if (!name) return null;
    const resolved = callGraph.resolveKnownCallee(name, callerFile);
    if (!resolved) return null;
    const fn = functionRecord(callGraph, resolved);
    if (!fn) return null;
    return { qid: resolved, fn };
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: PASS, all tests including the 4 new ones.

- [ ] **Step 5: Confirm the isolation principle still holds**

Run: `grep -n "from '../dataflow" scanner/src/lineage/summaries.js scanner/src/lineage/engine.js`
Expected: no output (no matches) — confirms neither file imports anything from `scanner/src/dataflow/`.

- [ ] **Step 6: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 190/190 (186 prior + 4 new).

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/summaries.js scanner/test/lineage/summaries.test.js
git commit -m "feat(lineage): real call-graph-backed lookupCallee via resolveKnownCallee (Sub-project B, increment 3, Task 1)"
```

---

## Task 2: Real-parser, cross-file integration proof

**Files:**
- Test: `scanner/test/lineage/engine-integration.test.js`

**Interfaces:**
- Consumes: `createCallGraphLookup` (Task 1, `scanner/src/lineage/summaries.js`), `createCallSummaryResolver`/`FieldIdentitySummaryCache` (existing, increment B1, already imported in this test file), `buildCallGraph` (`scanner/src/ir/callgraph.js`), `parseJsFile(file, code)` (`scanner/src/ir/parser-js.js` — confirmed signature: takes a file path string and a source string, returns `{ functions: [...], topLevel }` or `null` on an unparseable/oversized file; already imported in this test file and already used by its existing `parseFn` helper). Function records returned by `parseJsFile` do NOT carry their own `.file` field — `buildCallGraph` groups by the `perFileIR` object KEY, not `fn.file`, so nothing needs to set one for this test.
- Produces: nothing new for later tasks — this is the final proof task for this increment.

- [ ] **Step 1: Write the failing test**

Add these imports at the top of `scanner/test/lineage/engine-integration.test.js`, alongside the existing ones (do not re-import `parseJsFile`, `createCallSummaryResolver`, or `FieldIdentitySummaryCache` — this file already imports all three):

```js
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { createCallGraphLookup } from '../../src/lineage/summaries.js';
```

Add this test, anywhere after the existing `createCallSummaryResolver`-based tests in this file:

```js
test('real call-graph integration: a function in one file calling a bare-identifier function in ANOTHER file resolves through the real call graph, not a hand-built map (Sub-project B, increment 3)', () => {
  // Two real, separately-parsed source files. File B defines a plain
  // function with no import wiring needed for `resolveKnownCallee` to find
  // it — bare-name project-wide fallback (see callgraph.js's `resolve`/
  // `resolveKnownCallee` precedence: same-file first, then any file
  // defining the name) is exactly the mechanism this test exercises,
  // deliberately not exercising import/export resolution (out of scope for
  // this increment — see the plan's Global Constraints).
  const sourceB = `
function getUser(userId) {
  return { email: userId, ssn: 'unrelated' };
}
`;
  const sourceA = `
function outer(id) {
  const u = getUser(id);
  return u;
}
`;

  const irA = parseJsFile('/x/a.js', sourceA);
  const irB = parseJsFile('/x/b.js', sourceB);
  assert.ok(irA, 'real parser must successfully parse file A');
  assert.ok(irB, 'real parser must successfully parse file B');

  const perFileIR = { '/x/a.js': irA, '/x/b.js': irB };
  const callGraph = buildCallGraph(perFileIR, { '/x/a.js': sourceA, '/x/b.js': sourceB });

  const outerFn = irA.functions.find(f => f.name === 'outer');
  assert.ok(outerFn, 'expected to find outer() in the real parsed IR for a.js');

  const cache = new FieldIdentitySummaryCache();
  const lookupCallee = createCallGraphLookup(callGraph, '/x/a.js');
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);

  const { returnFacts } = analyzeFunctionFieldIdentity(outerFn, emptyState(), { resolveCallSummary });

  // outer()'s return value is getUser(id)'s real return value — the
  // identities should reflect getUser's ACTUAL structured return (an
  // object literal), not the generic unresolved-call fallback (flat +
  // widened:true) that this SAME test would produce if createCallGraphLookup
  // failed to resolve the cross-file call.
  assert.strictEqual(returnFacts.length, 1);
  assert.strictEqual(returnFacts[0].widened, false);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd scanner && node --test test/lineage/engine-integration.test.js`
Expected: FAIL — `createCallGraphLookup is not a function` if run before Task 1 exists on this branch. Once Task 1 is committed (and this task runs after it, same branch), this test should PASS on first try if Task 1 is correct — both tasks are straightforward compositions of already-proven pieces (`buildCallGraph`, `resolveKnownCallee`, `createCallSummaryResolver`, `analyzeFunctionFieldIdentity` are all independently tested elsewhere). If it fails for a DIFFERENT reason once Task 1 exists (e.g. `returnFacts[0].widened` is `true`), that is real signal of a genuine integration bug — investigate rather than adjusting the test to match.

- [ ] **Step 3: Mutation-test the real-parser integration**

Temporarily change the test's `lookupCallee` line to `const lookupCallee = () => null;` (simulating a broken/absent call-graph resolution) and confirm the assertion `returnFacts[0].widened === false` now FAILS (the unresolved-call fallback sets `widened: true`). This proves the test is real proof of the real call-graph wiring, not a tautology that would pass regardless. Revert the temporary change after confirming, and re-run to confirm it passes again.

- [ ] **Step 4: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 191/191 (190 from Task 1 + 1 new).

- [ ] **Step 5: Commit**

```bash
git add scanner/test/lineage/engine-integration.test.js
git commit -m "test(lineage): real cross-file call-graph integration proof (Sub-project B, increment 3, Task 2)"
```

---

## Post-implementation: update `scanner/src/lineage/CLAUDE.md`

After both tasks are reviewed and clean, update the `summaries.js` row of the module table in `scanner/src/lineage/CLAUDE.md`:
- Note that `createCallGraphLookup(callGraph, callerFile)` now exists, backed by the real `scanner/src/ir/callgraph.js#resolveKnownCallee`/`functionRecord`, and is proven against the real parser across two files.
- Correct the stale "no real call-graph/parser integration yet (`scanner/src/ir/callgraph.js` is untouched by this increment — increment B3's job)" sentence — B3 is this increment; it is no longer untouched.
- Note the explicit, deliberate scope boundary: bare-identifier callees only, no member-expression/CHA-based resolution (that gap is real and NOT closed by this increment — a future increment could add it, mirroring dataflow's own CHA mechanism, but nothing in the B1-B6 breakdown currently commits to doing so).

This is not a separate task — fold it into whichever of Task 1/Task 2's commits is more natural, or add one small `docs(lineage): ...` commit after both tasks, matching the pattern established in increment B2's own final doc-fix commit.
