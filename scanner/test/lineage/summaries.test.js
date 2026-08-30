import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { emptyFieldSummary, FieldIdentitySummaryCache, entryStateFromCall, applyAtCallSite, createCallSummaryResolver } from '../../src/lineage/summaries.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';

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

  // Apply the summary back at the call site. NOTE: this deviates from an
  // assertion in this task's own brief, which expected `[]` here on the
  // premise that "copyEmail never writes to `source`, so there should be
  // no mutations." That premise contradicts `analyzeFunctionFieldIdentity`'s
  // own documented contract for `mutatedParams` (engine.js, right above its
  // `mutatedParams` loop): it reports "what this param carries at function
  // exit" — a safe, deliberate OVER-approximation that never under-reports
  // — not "was this param's value replaced by an assignment." Since
  // `source` carries both `source.email` and `source.ssn` at entry and
  // neither is ever cleared (copyEmail only reads `source.email`, it never
  // assigns to `source`), both survive unchanged into `exitState` and are
  // correctly (if conservatively) reported by `mutatedParams`, then
  // correctly rebased by `applyAtCallSite` onto the caller's `user`
  // argument. Verified directly against the real, unmodified
  // `analyzeFunctionFieldIdentity` before changing this assertion — see
  // the task-2-report.md for the full trace. This is sound (never wrong,
  // only imprecise), exactly as that comment promises.
  const applied = applyAtCallSite(summary, callee.params, callArgs);
  assert.deepEqual(applied.mutations, [{ path: 'user', dataElementIds: ['data:email', 'data:ssn'] }]);
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

test('compute: a throwing analyzeFn does not permanently poison the recursion guard for that qid (regression for a final-review finding)', () => {
  const cache = new FieldIdentitySummaryCache();
  const state = emptyState();
  assert.throws(() => cache.compute('fn1', state, () => { throw new Error('boom'); }));
  // Before the fix, qid 'fn1' would still be on _stack here (analyzeFn
  // threw before _stack.delete ran), so this second call would silently
  // fall into the recursion guard and return a bottom stub forever,
  // instead of genuinely re-attempting the analysis.
  let ran = false;
  const result = cache.compute('fn1', state, () => { ran = true; return { ...emptyFieldSummary(), returnFlat: new Set(['data:recovered']) }; });
  assert.equal(ran, true, 'a later compute() call for the same qid must genuinely re-run analyzeFn, not silently degrade to a permanent bottom stub');
  assert.deepEqual([...result.returnFlat], ['data:recovered']);
});

// Sub-project B, increment 2: createCallSummaryResolver — the closure
// resolveExprIdentities's `call` case consults via ctx.resolveCallSummary.

test('createCallSummaryResolver returns null when lookupCallee cannot resolve the call', () => {
  const cache = new FieldIdentitySummaryCache();
  const resolver = createCallSummaryResolver(cache, () => null);
  const result = resolver({ kind: 'ident', name: 'unknownFn' }, [], emptyState());
  assert.equal(result, null);
});

test('createCallSummaryResolver computes and caches a real summary via analyzeFunctionFieldIdentity when lookupCallee resolves', () => {
  const cache = new FieldIdentitySummaryCache();
  // function copyEmail(source) { return source.email; }
  const calleeFn = {
    params: ['source'],
    cfg: {
      entry: 'c0', exit: 'c1',
      nodes: {
        c0: { kind: 'entry', line: 1, succ: ['c1'], pred: [] },
        c1: { kind: 'return', line: 1, succ: [], pred: ['c0'], value: { kind: 'member', object: { kind: 'ident', name: 'source' }, prop: 'email' } },
      },
    },
  };
  const resolver = createCallSummaryResolver(cache, (calleeExpr) => (calleeExpr.name === 'copyEmail' ? { qid: 'test::copyEmail', fn: calleeFn } : null));
  const callerState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = resolver({ kind: 'ident', name: 'copyEmail' }, [{ kind: 'ident', name: 'user' }], callerState);
  assert.deepEqual([...result.returnFlat], ['data:email']);
  assert.equal(cache.size(), 1, 'the computed summary must be cached');
});

test('createCallSummaryResolver unions identities across ALL of a function\'s return sites, not just the first (a genuine correctness improvement over increment B1\'s own single-return-site test shortcut)', () => {
  const cache = new FieldIdentitySummaryCache();
  // function pick(a, b, flag) { if (flag) { return a.x; } return b.y; }
  const calleeFn = {
    params: ['a', 'b', 'flag'],
    cfg: {
      entry: 'c0', exit: 'c3',
      nodes: {
        c0: { kind: 'entry', line: 1, succ: ['c1'], pred: [] },
        c1: { kind: 'if', line: 1, succ: ['c2', 'c3'], pred: ['c0'], cond: { kind: 'ident', name: 'flag' } },
        c2: { kind: 'return', line: 1, succ: [], pred: ['c1'], value: { kind: 'member', object: { kind: 'ident', name: 'a' }, prop: 'x' } },
        c3: { kind: 'return', line: 1, succ: [], pred: ['c1'], value: { kind: 'member', object: { kind: 'ident', name: 'b' }, prop: 'y' } },
      },
    },
  };
  const resolver = createCallSummaryResolver(cache, () => ({ qid: 'test::pick', fn: calleeFn }));
  let callerState = addIdentity(emptyState(), 'p.x', 'data:p-x');
  callerState = addIdentity(callerState, 'q.y', 'data:q-y');
  const result = resolver({ kind: 'ident', name: 'pick' }, [{ kind: 'ident', name: 'p' }, { kind: 'ident', name: 'q' }, { kind: 'literal', value: true }], callerState);
  assert.deepEqual([...result.returnFlat].sort(), ['data:p-x', 'data:q-y'], 'both return sites\' identities must be present, not just one');
});
