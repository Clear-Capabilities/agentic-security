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
