# Data Flow Explorer Milestone 1, Sub-project B, Increment 1: Summary Cache Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the field-identity summary cache core — the mechanism that lets a caller's real field-identity facts flow into a callee's analysis, and the callee's results flow back — proven against **hand-built two-function call graphs**, no real call-graph/parser integration yet (that's increments B2-B3). This is the highest-uncertainty, most load-bearing piece of Sub-project B: get the cache-key shape and the caller↔callee data flow wrong here and every later increment inherits it.

**Architecture:** New module `scanner/src/lineage/summaries.js`, structurally mirroring `scanner/src/dataflow/summaries.js`'s `SummaryCache` (cache-key shape: hash of a canonicalized entry state, a per-function distinct-context cap with graceful degradation, a stack-based recursion guard) but built on Sub-project A's field-identity primitives instead of the taint engine's boolean access-path sets — never imports or shares mutable state with `scanner/src/dataflow/`. Full recursion *refinement* (retrying analysis until a recursive summary converges) is explicitly deferred to increment B5 — this increment's recursion guard only needs to be SAFE (never infinite-loops), not precise.

**Tech Stack:** Same as Sub-project A — plain ESM, Node's built-in `node:test`.

**Spec:** `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-b-scoping.md` (this increment's own scoping entry, "B1"). `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-lineage-engine-scoping.md`'s Decision 1 (the reuse-boundary ruling this increment tests for real). Read `scanner/src/lineage/CLAUDE.md`, `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md`, and `scanner/src/dataflow/CLAUDE.md`'s `SummaryCache` section before starting.

## Global Constraints

- **Never import `scanner/src/dataflow/engine.js` or `scanner/src/dataflow/summaries.js`, and never share mutable state with either.** Structural mirroring of their ALGORITHM (already researched and cited precisely in each task below) is the whole point; importing their code or state is exactly what the architecture forbids.
- **Reuse `scanner/src/dataflow/access-paths.js`'s pure utilities and `scanner/src/lineage/field-identity.js`'s already-built primitives wherever they apply** — this increment should need almost no new low-level state operations, only new orchestration on top of what Sub-project A already built and hardened across 6 rounds.
- **Every fixture-fact claim in a test must be verified against the real current code**, not assumed from this plan's prose — re-read `scanner/src/lineage/engine.js` and `field-identity.js` yourself before relying on an exact function signature this plan quotes, since minor details may have shifted.
- **Run `cd scanner && npm run test:lineage` after every task** and report the exact pass/fail count. New test files must be added to `scanner/package.json`'s `"test:lineage"` script (an explicit file list, not a glob).
- **No placeholders.** Where this plan is uncertain about something (there shouldn't be much, given how directly this reuses Sub-project A's already-proven primitives), it says so explicitly rather than guessing.

---

## Task 1: The summary cache + `entryStateFromCall`

**Files:**
- Create: `scanner/src/lineage/summaries.js`
- Modify: `scanner/src/lineage/engine.js` (export `residualFlat`, currently module-local)
- Test: `scanner/test/lineage/summaries.test.js`

**Background:** `scanner/src/dataflow/summaries.js`'s `SummaryCache` class (real code, already researched) has this shape: `_key(qid, taintedParams, receiverType)` builds a cache key as `${qid}::${hashOfCanonicalizedState}` (optionally suffixed for call-string sensitivity / receiver type — this increment skips both, deferred to later increments per the scoping doc); `get`/`set`/`has` are thin `Map` wrappers keyed by that string; `compute(qid, taintedParams, analyzeFn)` is the real workhorse — checks the cache first, then a per-function distinct-context cap (past it, degrades to the empty-context summary rather than computing an unbounded number of contexts), then a stack-based recursion guard (a function already being analyzed, hit again, gets an immediate "bottom" placeholder rather than recursing further).

This task builds the field-identity analog. Sub-project A's `field-identity.js` already has the exact primitive the taint engine's cache key needs (`hashState`), and `engine.js`'s `analyzeFunctionFieldIdentity` already returns almost exactly what a "summary" needs to be (`{exitState, returnFacts, mutatedParams, widenings}`) — this task doesn't redesign that shape, it wraps it in a cache keyed the same way the taint engine's cache is keyed.

**Interfaces:**
- Consumes: `hashState`, `emptyState`, `addIdentity` (all from `field-identity.js`, unchanged); `resolveExprIdentities`, `residualFlat` (from `engine.js` — `residualFlat` needs to become exported by this task, since it's currently module-local).
- Produces: `emptyFieldSummary() → {returnFlat: Set, returnByPath: Map, mutatedParams: Map, widenings: []}`; `class FieldIdentitySummaryCache` with `has(qid, entryState)`, `get(qid, entryState)`, `set(qid, entryState, summary)`, `compute(qid, entryState, analyzeFn)`, `size()`, `clear()`; `entryStateFromCall(paramNames, callArgs, callerState) → calleeEntryState`. Task 2 consumes all of these.

- [ ] **Step 1: Export `residualFlat` from `engine.js`**

Find the current module-local declaration (near the top of `scanner/src/lineage/engine.js`, alongside `unionOfByPath`):

```js
function residualFlat(flat, byPath) {
```

Change to:

```js
export function residualFlat(flat, byPath) {
```

Run `cd scanner && npm run test:lineage` immediately after this one-line change to confirm nothing about the existing 159 tests depended on it staying unexported (it shouldn't — this is a pure additive export) — expect PASS, 159/159, before moving on.

- [ ] **Step 2: Write failing tests for `emptyFieldSummary` and the cache's basic get/set/has**

Create `scanner/test/lineage/summaries.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { emptyFieldSummary, FieldIdentitySummaryCache, entryStateFromCall } from '../../src/lineage/summaries.js';

test('emptyFieldSummary returns an empty, correctly-shaped summary', () => {
  const s = emptyFieldSummary();
  assert.equal(s.returnFlat.size, 0);
  assert.equal(s.returnByPath.size, 0);
  assert.equal(s.mutatedParams.size, 0);
  assert.deepEqual(s.widenings, []);
});

test('cache: a summary computed for one (qid, entryState) pair is retrievable via get/has', () => {
  const cache = new FieldIdentitySummaryCache();
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  assert.equal(cache.has('fn1', entryState), false);
  const summary = { ...emptyFieldSummary(), returnFlat: new Set(['data:email']) };
  cache.set('fn1', entryState, summary);
  assert.equal(cache.has('fn1', entryState), true);
  assert.deepEqual([...cache.get('fn1', entryState).returnFlat], ['data:email']);
});

test('cache: two DIFFERENT entry states for the same qid are cached separately, not collapsed', () => {
  const cache = new FieldIdentitySummaryCache();
  const stateA = addIdentity(emptyState(), 'user.email', 'data:email');
  const stateB = addIdentity(emptyState(), 'user.ssn', 'data:ssn');
  cache.set('fn1', stateA, { ...emptyFieldSummary(), returnFlat: new Set(['data:email']) });
  cache.set('fn1', stateB, { ...emptyFieldSummary(), returnFlat: new Set(['data:ssn']) });
  assert.deepEqual([...cache.get('fn1', stateA).returnFlat], ['data:email']);
  assert.deepEqual([...cache.get('fn1', stateB).returnFlat], ['data:ssn']);
});

test('cache: two DIFFERENT qids with the SAME entry state are cached separately, not collapsed', () => {
  const cache = new FieldIdentitySummaryCache();
  const state = addIdentity(emptyState(), 'user.email', 'data:email');
  cache.set('fn1', state, { ...emptyFieldSummary(), returnFlat: new Set(['data:email']) });
  cache.set('fn2', state, { ...emptyFieldSummary(), returnFlat: new Set(['data:different']) });
  assert.deepEqual([...cache.get('fn1', state).returnFlat], ['data:email']);
  assert.deepEqual([...cache.get('fn2', state).returnFlat], ['data:different']);
});

test('compute: calls analyzeFn on a cache miss, caches the result, does not re-call analyzeFn on a hit', () => {
  const cache = new FieldIdentitySummaryCache();
  const state = addIdentity(emptyState(), 'user.email', 'data:email');
  let calls = 0;
  const analyzeFn = () => { calls++; return { ...emptyFieldSummary(), returnFlat: new Set(['data:email']) }; };
  const first = cache.compute('fn1', state, analyzeFn);
  const second = cache.compute('fn1', state, analyzeFn);
  assert.equal(calls, 1, 'analyzeFn must only run once; the second compute() call must hit the cache');
  assert.deepEqual([...first.returnFlat], [...second.returnFlat]);
});

test('compute: past the per-function distinct-context cap, degrades to the empty-entry-state summary rather than computing an unbounded number of contexts', () => {
  const cache = new FieldIdentitySummaryCache(2); // cap of 2 distinct contexts for this test
  const emptyEntry = emptyState();
  cache.compute('fn1', emptyEntry, () => ({ ...emptyFieldSummary(), returnFlat: new Set(['data:base']) }));
  cache.compute('fn1', addIdentity(emptyState(), 'a', 'data:a'), () => ({ ...emptyFieldSummary(), returnFlat: new Set(['data:a']) }));
  // This is the 3rd distinct context for 'fn1' — over the cap of 2 (empty + one real context already seen).
  let thirdCallRan = false;
  const thirdState = addIdentity(emptyState(), 'b', 'data:b');
  const result = cache.compute('fn1', thirdState, () => { thirdCallRan = true; return { ...emptyFieldSummary(), returnFlat: new Set(['data:b']) }; });
  assert.equal(thirdCallRan, false, 'past the cap, analyzeFn must not run for a brand-new context');
  assert.deepEqual([...result.returnFlat], ['data:base'], 'past the cap, the result must be the empty-entry-state summary, not empty/undefined');
});

test('compute: a recursive call (same qid already being analyzed) gets an immediate bottom-stub summary, not infinite recursion', () => {
  const cache = new FieldIdentitySummaryCache();
  const state = emptyState();
  let recursiveResult = null;
  cache.compute('fn1', state, () => {
    // Simulate fn1 calling itself recursively during its own analysis.
    recursiveResult = cache.compute('fn1', state, () => {
      throw new Error('must never reach here — this would be true unbounded recursion');
    });
    return { ...emptyFieldSummary(), returnFlat: new Set(['data:outer']) };
  });
  assert.ok(recursiveResult, 'the recursive inner compute() call must return SOMETHING, not throw or hang');
  assert.equal(recursiveResult._recursive, true, 'the bottom-stub summary must be marked so a caller can tell it is an under-approximation');
  assert.equal(recursiveResult.returnFlat.size, 0, 'the bottom stub carries no facts — B5 will refine this, not this increment');
});
```

- [ ] **Step 2b: Write failing tests for `entryStateFromCall`**

Add to the same file:

```js
test('entryStateFromCall maps each call argument\'s resolved identities onto the corresponding parameter name', () => {
  const callerState = addIdentity(emptyState(), 'req.body.email', 'data:email');
  const paramNames = ['user'];
  const callArgs = [{ kind: 'member', object: { kind: 'member', object: { kind: 'ident', name: 'req' }, prop: 'body' }, prop: 'email' }];
  const entryState = entryStateFromCall(paramNames, callArgs, callerState);
  assert.deepEqual([...entryState.get('user')], ['data:email']);
});

test('entryStateFromCall preserves field-level distinctness for an object-shaped argument (the direct FR-301 proof for this new code path)', () => {
  let callerState = addIdentity(emptyState(), 'user.email', 'data:email');
  callerState = addIdentity(callerState, 'user.ssn', 'data:ssn');
  const paramNames = ['arg'];
  // f(user) — a plain alias argument, whose byPath structure (round 2's
  // fix, already proven) must survive into the callee's entry state.
  const callArgs = [{ kind: 'ident', name: 'user' }];
  const entryState = entryStateFromCall(paramNames, callArgs, callerState);
  assert.deepEqual([...entryState.get('arg.email')], ['data:email']);
  assert.deepEqual([...entryState.get('arg.ssn')], ['data:ssn']);
  assert.ok(!entryState.has('arg'), 'must not ALSO have a coarse "arg" entry merging both fields together — the exact bug class Sub-project A spent 6 rounds closing');
});

test('entryStateFromCall with more call args than params ignores the extras; fewer args than params leaves the rest with no entry', () => {
  const callerState = addIdentity(emptyState(), 'x', 'data:x');
  const entryState = entryStateFromCall(['a', 'b'], [{ kind: 'ident', name: 'x' }], callerState);
  assert.deepEqual([...entryState.get('a')], ['data:x']);
  assert.equal(entryState.has('b'), false);
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: FAIL — `summaries.js` doesn't exist yet.

- [ ] **Step 4: Implement `scanner/src/lineage/summaries.js`**

```js
import { hashState, emptyState, addIdentity } from './field-identity.js';
import { resolveExprIdentities, residualFlat } from './engine.js';

export function emptyFieldSummary() {
  return { returnFlat: new Set(), returnByPath: new Map(), mutatedParams: new Map(), widenings: [] };
}

const DEFAULT_MAX_CONTEXTS = 16; // matches dataflow/summaries.js's own default, chosen independently for this
                                  // package (a lineage-specific cap, not shared config, per the isolation
                                  // principle — see the constructor param below for how a caller can override it)

export class FieldIdentitySummaryCache {
  constructor(maxContextsPerFn = DEFAULT_MAX_CONTEXTS) {
    this._cache = new Map();
    this._stack = new Set();
    this._contextsByQid = new Map();
    this._maxContextsPerFn = maxContextsPerFn;
  }

  _key(qid, entryState) {
    return `${qid}::${hashState(entryState)}`;
  }

  has(qid, entryState) {
    return this._cache.has(this._key(qid, entryState));
  }

  get(qid, entryState) {
    return this._cache.get(this._key(qid, entryState));
  }

  set(qid, entryState, summary) {
    this._cache.set(this._key(qid, entryState), summary);
    const hash = hashState(entryState);
    const seen = this._contextsByQid.get(qid) ?? new Set();
    seen.add(hash);
    this._contextsByQid.set(qid, seen);
  }

  compute(qid, entryState, analyzeFn) {
    if (this.has(qid, entryState)) return this.get(qid, entryState);

    const hash = hashState(entryState);
    const seen = this._contextsByQid.get(qid) ?? new Set();
    if (!seen.has(hash) && seen.size >= this._maxContextsPerFn) {
      // Past this function's distinct-context cap: degrade to the
      // empty-entry summary (if one exists) rather than computing an
      // unbounded number of contexts. Mirrors
      // dataflow/summaries.js's own graceful degradation past its own cap.
      const fallback = this._cache.get(this._key(qid, emptyState())) ?? emptyFieldSummary();
      this.set(qid, entryState, fallback);
      return fallback;
    }

    if (this._stack.has(qid)) {
      // Recursion guard, THIS INCREMENT'S SCOPE: return a bottom stub
      // immediately, never recurse further, and do NOT attempt any
      // fixed-point refinement here — that precision improvement is
      // increment B5's job. This guard's only job in B1 is safety (never
      // infinite-loop on a hand-built recursive call graph), not
      // precision. A caller receiving `_recursive: true` knows this
      // summary may under-approximate the function's real behavior.
      return { ...emptyFieldSummary(), _recursive: true };
    }

    this._stack.add(qid);
    const summary = analyzeFn(entryState);
    this.set(qid, entryState, summary);
    this._stack.delete(qid);
    return summary;
  }

  size() {
    return this._cache.size;
  }

  clear() {
    this._cache.clear();
    this._stack.clear();
    this._contextsByQid.clear();
  }
}

// Maps a call site's argument expressions onto a fresh entry state for the
// callee, keyed by the callee's own parameter names — the interprocedural
// analog of `engine.js`'s `assign` transfer function: each argument is
// resolved against the CALLER's current state via `resolveExprIdentities`,
// and its residual (root-level) identities plus its byPath (field-level)
// structure are both written into the callee's entry state at the
// corresponding parameter name, using the exact same residual+byPath split
// `assign` already uses — this is a direct, deliberate reuse of Sub-project
// A's already-hardened write pattern, not a new mechanism.
export function entryStateFromCall(paramNames, callArgs, callerState) {
  let entryState = emptyState();
  const n = Math.min(paramNames.length, callArgs.length);
  for (let i = 0; i < n; i++) {
    const paramName = paramNames[i];
    const resolved = resolveExprIdentities(callerState, callArgs[i]);
    const residual = residualFlat(resolved.flat, resolved.byPath);
    for (const id of residual) entryState = addIdentity(entryState, paramName, id);
    for (const [subPath, ids] of resolved.byPath) {
      for (const id of ids) entryState = addIdentity(entryState, `${paramName}.${subPath}`, id);
    }
  }
  return entryState;
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: PASS, all tests.

- [ ] **Step 6: Wire into `test:lineage`, run the full lineage suite**

Add `test/lineage/summaries.test.js` to `scanner/package.json`'s `"test:lineage"` list. Run `cd scanner && npm run test:lineage` — expect PASS, 159 pre-existing + however many this task added, 0 failures.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/summaries.js scanner/src/lineage/engine.js scanner/test/lineage/summaries.test.js scanner/package.json
git commit -m "feat(lineage): add the field-identity summary cache core + entryStateFromCall (Sub-project B, increment 1)"
```

---

## Task 2: `applyAtCallSite` + a full hand-built round-trip proof

**Files:**
- Modify: `scanner/src/lineage/summaries.js`
- Test: `scanner/test/lineage/summaries.test.js`

**Background:** Task 1 built the "send state INTO a callee" half. This task builds the "get results BACK from a callee" half — `applyAtCallSite`, the analog of `dataflow/summaries.js`'s function of the same name, which maps a callee's summary (specifically its `mutatedParams`) back onto the CALLER's own variables at the call site. The taint engine's version has a confirmed limitation: it only propagates a mutation back when the call argument at that position is a bare identifier — a `member`-expression argument (`f(obj.field)`) is silently dropped. This task's version does NOT inherit that limitation (a deliberate, scoped improvement, not scope creep — field mutations will plausibly target `obj.field`-shaped arguments often).

**Interfaces:**
- Consumes: `accessPathOf` (from `scanner/src/dataflow/access-paths.js` — already an established, confirmed-pure reuse per Sub-project A's ADR).
- Produces: `applyAtCallSite(summary, paramNames, callArgs) → {returnFlat, returnByPath, mutations: [{path, dataElementIds}]}`. `mutations` is a plain array (not yet applied to any state) — Task 2's own integration test applies it via `addIdentity` directly, matching how a future increment's real `step()` integration will do the same.

- [ ] **Step 1: Write failing tests**

Add to `scanner/test/lineage/summaries.test.js`:

```js
import { addIdentity as addId2 } from '../../src/lineage/field-identity.js'; // not needed, addIdentity already imported above — remove this line, use the existing import
import { applyAtCallSite } from '../../src/lineage/summaries.js';

test('applyAtCallSite maps a callee\'s mutatedParams back onto the caller\'s ident-argument variable', () => {
  const summary = { ...emptyFieldSummary(), mutatedParams: new Map([['target', new Set(['data:email'])]]) };
  const paramNames = ['target'];
  const callArgs = [{ kind: 'ident', name: 'callerVar' }];
  const result = applyAtCallSite(summary, paramNames, callArgs);
  assert.deepEqual(result.mutations, [{ path: 'callerVar', dataElementIds: ['data:email'] }]);
});

test('applyAtCallSite ALSO maps a mutation back onto a member-expression argument (deliberate improvement over the taint engine\'s ident-only precedent)', () => {
  const summary = { ...emptyFieldSummary(), mutatedParams: new Map([['target', new Set(['data:email'])]]) };
  const paramNames = ['target'];
  const callArgs = [{ kind: 'member', object: { kind: 'ident', name: 'obj' }, prop: 'field' }];
  const result = applyAtCallSite(summary, paramNames, callArgs);
  assert.deepEqual(result.mutations, [{ path: 'obj.field', dataElementIds: ['data:email'] }]);
});

test('applyAtCallSite correctly rebases a sub-path mutation (e.g. "target.inner") onto the caller\'s argument path', () => {
  const summary = { ...emptyFieldSummary(), mutatedParams: new Map([['target.inner', new Set(['data:x'])]]) };
  const paramNames = ['target'];
  const callArgs = [{ kind: 'ident', name: 'callerVar' }];
  const result = applyAtCallSite(summary, paramNames, callArgs);
  assert.deepEqual(result.mutations, [{ path: 'callerVar.inner', dataElementIds: ['data:x'] }]);
});

test('applyAtCallSite returns no mutation for an argument it cannot resolve to a path (e.g. a literal)', () => {
  const summary = { ...emptyFieldSummary(), mutatedParams: new Map([['target', new Set(['data:x'])]]) };
  const paramNames = ['target'];
  const callArgs = [{ kind: 'literal', value: 42 }];
  const result = applyAtCallSite(summary, paramNames, callArgs);
  assert.deepEqual(result.mutations, []);
});

test('applyAtCallSite forwards the summary\'s return facts unchanged', () => {
  const summary = { ...emptyFieldSummary(), returnFlat: new Set(['data:a']), returnByPath: new Map([['field', new Set(['data:b'])]]) };
  const result = applyAtCallSite(summary, [], []);
  assert.deepEqual([...result.returnFlat], ['data:a']);
  assert.deepEqual([...result.returnByPath.get('field')], ['data:b']);
});
```

Now the full round-trip integration test — this proves Task 1 and Task 2 compose correctly end-to-end, using a HAND-BUILT two-function scenario (no real call graph yet, per this increment's scope):

```js
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';

test('full round-trip: a caller\'s field identity flows into a callee via entryStateFromCall, the callee\'s real analysis runs via analyzeFunctionFieldIdentity, its summary is cached, and its return facts + mutations apply back onto the caller — all with field-level distinctness preserved throughout', () => {
  // Hand-built callee: function copyEmail(source) { const out = { copied: source.email }; return out; }
  const callee = {
    params: ['source'],
    cfg: {
      entry: 'c0', exit: 'c2',
      nodes: {
        c0: { kind: 'entry', line: 1, succ: ['c1'], pred: [] },
        c1: {
          kind: 'return', line: 1, succ: ['c2'], pred: ['c0'],
          value: { kind: 'object', props: [{ key: 'copied', value: { kind: 'member', object: { kind: 'ident', name: 'source' }, prop: 'email' } }] },
        },
        c2: { kind: 'exit', line: 1, succ: [], pred: ['c1'] },
      },
    },
  };

  const cache = new FieldIdentitySummaryCache();
  const calleeQid = 'callee::copyEmail';

  // Caller-side state: user.email and user.ssn are two DISTINCT fields.
  let callerState = addIdentity(emptyState(), 'user.email', 'data:email');
  callerState = addIdentity(callerState, 'user.ssn', 'data:ssn');

  // Call site: copyEmail(user) — build the callee's entry state from the caller's real state.
  const callArgs = [{ kind: 'ident', name: 'user' }];
  const calleeEntryState = entryStateFromCall(callee.params, callArgs, callerState);

  // Compute (and cache) the callee's summary for this real entry state.
  const summary = cache.compute(calleeQid, calleeEntryState, (entryState) => {
    const result = analyzeFunctionFieldIdentity(callee, entryState);
    return {
      returnFlat: result.returnFacts[0]?.identities ?? new Set(),
      returnByPath: new Map(), // this increment doesn't thread byPath through returnFacts — a known,
                                 // deliberately out-of-scope limitation, see the Self-Review Notes below
      mutatedParams: result.mutatedParams,
      widenings: result.widenings,
    };
  });

  // The callee only reads source.email, never source.ssn — the summary's
  // return facts must reflect ONLY data:email, proving field identity
  // survived the full round trip (caller state -> entryStateFromCall ->
  // real intraprocedural analysis -> cached summary).
  assert.deepEqual([...summary.returnFlat], ['data:email']);

  // Apply the summary back at the call site (this call has no mutations to
  // apply, since copyEmail never writes to `source` — this proves
  // applyAtCallSite correctly reports "no mutations" rather than
  // fabricating one).
  const applied = applyAtCallSite(summary, callee.params, callArgs);
  assert.deepEqual(applied.mutations, []);
  assert.deepEqual([...applied.returnFlat], ['data:email']);

  // Second call, same qid, DIFFERENT entry state (a caller passing a
  // DIFFERENT object with a DIFFERENT field) must get a genuinely
  // different, independently-computed and independently-cached summary —
  // not the first call's cached result reused incorrectly.
  const otherState = addIdentity(emptyState(), 'other.email', 'data:other-email');
  const otherEntryState = entryStateFromCall(callee.params, [{ kind: 'ident', name: 'other' }], otherState);
  const otherSummary = cache.compute(calleeQid, otherEntryState, (entryState) => {
    const result = analyzeFunctionFieldIdentity(callee, entryState);
    return { returnFlat: result.returnFacts[0]?.identities ?? new Set(), returnByPath: new Map(), mutatedParams: result.mutatedParams, widenings: result.widenings };
  });
  assert.deepEqual([...otherSummary.returnFlat], ['data:other-email']);
  assert.equal(cache.size(), 2, 'two distinct entry-state contexts for the same qid must produce two distinct cache entries');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: FAIL — `applyAtCallSite` doesn't exist yet.

- [ ] **Step 3: Implement `applyAtCallSite` in `scanner/src/lineage/summaries.js`**

```js
import { accessPathOf } from '../dataflow/access-paths.js';

// Maps a callee's summary back onto the CALLER's own state at the call
// site — the interprocedural analog of reading a function's return value
// and observing its side effects. Unlike dataflow/summaries.js's
// applyAtCallSite (which only propagates a mutation back for a bare
// `ident` argument, silently dropping a `member`-expression argument like
// `f(obj.field)`), this version also resolves a member-expression argument
// via `accessPathOf` — a deliberate, scoped improvement: field mutations
// plausibly target `obj.field`-shaped arguments often enough that
// dropping them silently would be a real, avoidable under-approximation.
export function applyAtCallSite(summary, paramNames, callArgs) {
  const mutations = [];
  for (const [paramPath, ids] of summary.mutatedParams) {
    const [rootParamName, ...rest] = paramPath.split('.');
    const idx = paramNames.indexOf(rootParamName);
    if (idx === -1) continue;
    const arg = callArgs[idx];
    const argPath = accessPathOf(arg);
    if (!argPath) continue;
    const fullPath = rest.length > 0 ? `${argPath}.${rest.join('.')}` : argPath;
    mutations.push({ path: fullPath, dataElementIds: [...ids] });
  }
  return { returnFlat: summary.returnFlat, returnByPath: summary.returnByPath, mutations };
}
```

Remove the stray `import { addIdentity as addId2 } ...` line from Step 1's test code if you included it verbatim — it was a copy-paste artifact in this brief, not real code; the file already imports `addIdentity` once at the top.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scanner && node --test test/lineage/summaries.test.js`
Expected: PASS, all tests including the full round-trip integration test.

- [ ] **Step 5: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage` — expect PASS, 0 failures, report the exact count.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/summaries.js scanner/test/lineage/summaries.test.js
git commit -m "feat(lineage): add applyAtCallSite + a full hand-built round-trip proof (Sub-project B, increment 1)"
```

---

## Self-Review Notes (from the plan author)

- **Spec coverage:** this increment covers B1 exactly as scoped — the cache core, `entryStateFromCall`, `applyAtCallSite`, proven against a hand-built two-function call graph. No real call-graph integration (B3), no `resolveExprIdentities`'s `call` case consulting the cache (B2), no recursion *refinement* (B5), no context-sensitivity tuning beyond the basic cap (B6) — all correctly out of scope here per the parent scoping document.
- **Known, disclosed limitation, not silently glossed over**: this increment's summary shape does not thread `byPath` through `returnFacts` — `analyzeFunctionFieldIdentity`'s `returnFacts` currently only ever carries a flat `Set` per return site (a documented limitation from Sub-project A's own final review: "`returnFacts` carries only `flat`, never `byPath`... The plan explicitly blesses that"). This means a callee returning a STRUCTURED object (like this plan's own `copyEmail` example, which returns `{copied: source.email}`) has its return fact correctly resolved as `flat` (proven by this increment's integration test), but a caller receiving that return value and immediately reading ONE field off it (`const r = copyEmail(user); return r.copied;`) would not yet get field-level precision from the summary alone — it would get the flattened `data:email` fact attributed to the whole return value, which is SOUND (never wrong, only imprecise) but not as precise as Sub-project A's own intraprocedural object-literal handling. Closing this gap requires giving `returnFacts` (or this increment's own summary shape) a `byPath` dimension — reasonable scope for increment B2, when `resolveExprIdentities`'s `call` case starts consuming real summaries, not for B1, which only needs to prove the cache/data-flow mechanics work end-to-end.
- **Type/interface consistency check:** `entryStateFromCall`'s output (a `field-identity.js` state `Map`) is exactly what `analyzeFunctionFieldIdentity`'s `entryState` parameter already expects (Sub-project A's own signature, unchanged) — no adapter needed. `applyAtCallSite`'s `mutations` array shape (`{path, dataElementIds}`) is designed to be directly consumable by a future `addIdentity(callerState, path, id)` loop, matching how every other write site in this package already works.
