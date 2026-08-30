import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  emptyState, identitiesAt, addIdentity, removeIdentitiesAt, joinStates, statesEqual, hashState,
} from '../../src/lineage/field-identity.js';

test('emptyState has no identities anywhere', () => {
  assert.equal(identitiesAt(emptyState(), 'x').size, 0);
});

test('addIdentity records an identity at an exact path', () => {
  const s = addIdentity(emptyState(), 'user.email', 'data:email');
  assert.deepEqual([...identitiesAt(s, 'user.email')], ['data:email']);
});

test('addIdentity is a no-op if the identity is already recorded at that exact path', () => {
  const s1 = addIdentity(emptyState(), 'x', 'data:a');
  const s2 = addIdentity(s1, 'x', 'data:a');
  assert.ok(statesEqual(s1, s2));
});

test('an ancestor path\'s identity is visible when querying a descendant path', () => {
  const s = addIdentity(emptyState(), 'user', 'data:whole-object');
  assert.deepEqual([...identitiesAt(s, 'user.email')], ['data:whole-object']);
});

test('a descendant path\'s identity IS visible when querying its ancestor (whole-container reads aggregate every field)', () => {
  const s = addIdentity(emptyState(), 'user.email', 'data:email');
  assert.deepEqual([...identitiesAt(s, 'user')], ['data:email']);
});

test('two distinct fields on the same object coexist without merging, and querying either field individually never sees the other (FR-301 core case)', () => {
  let s = emptyState();
  s = addIdentity(s, 'combined.email', 'data:email');
  s = addIdentity(s, 'combined.ssn', 'data:ssn');
  assert.deepEqual([...identitiesAt(s, 'combined.email')], ['data:email']);
  assert.deepEqual([...identitiesAt(s, 'combined.ssn')], ['data:ssn']);
  assert.deepEqual([...identitiesAt(s, 'combined')].sort(), ['data:email', 'data:ssn'],
    'querying the container as a whole aggregates every field recorded under it');
});

test('two distinct fields recorded via byPath-only writes remain isolated from each other when queried individually (FR-301, no coarse root entry)', () => {
  let s = emptyState();
  s = addIdentity(s, 'rec.email', 'data:email');
  s = addIdentity(s, 'rec.ssn', 'data:ssn');
  assert.deepEqual([...identitiesAt(s, 'rec.email')], ['data:email']);
  assert.deepEqual([...identitiesAt(s, 'rec.ssn')], ['data:ssn']);
});

test('querying the container as a whole aggregates every field recorded under it', () => {
  let s = emptyState();
  s = addIdentity(s, 'rec.email', 'data:email');
  s = addIdentity(s, 'rec.ssn', 'data:ssn');
  assert.deepEqual([...identitiesAt(s, 'rec')].sort(), ['data:email', 'data:ssn']);
});

test('removeIdentitiesAt clears the exact path and every descendant, leaving unrelated paths untouched', () => {
  let s = emptyState();
  s = addIdentity(s, 'x.a', 'data:a');
  s = addIdentity(s, 'x.b', 'data:b');
  s = addIdentity(s, 'y', 'data:c');
  const cleared = removeIdentitiesAt(s, 'x');
  assert.equal(identitiesAt(cleared, 'x.a').size, 0);
  assert.equal(identitiesAt(cleared, 'x.b').size, 0);
  assert.deepEqual([...identitiesAt(cleared, 'y')], ['data:c']);
});

test('removeIdentitiesAt on an exact leaf path only clears that path, not siblings', () => {
  let s = emptyState();
  s = addIdentity(s, 'x.a', 'data:a');
  s = addIdentity(s, 'x.b', 'data:b');
  const cleared = removeIdentitiesAt(s, 'x.a');
  assert.equal(identitiesAt(cleared, 'x.a').size, 0);
  assert.deepEqual([...identitiesAt(cleared, 'x.b')], ['data:b']);
});

test('joinStates unions label sets for a path present in both states', () => {
  const a = addIdentity(emptyState(), 'x', 'data:a');
  const b = addIdentity(emptyState(), 'x', 'data:b');
  const joined = joinStates(a, b);
  assert.deepEqual([...identitiesAt(joined, 'x')].sort(), ['data:a', 'data:b']);
});

test('joinStates keeps a path present in only one of the two states', () => {
  const a = addIdentity(emptyState(), 'x', 'data:a');
  const joined = joinStates(a, emptyState());
  assert.deepEqual([...identitiesAt(joined, 'x')], ['data:a']);
});

test('statesEqual is true for two states built differently but holding the same facts', () => {
  let s1 = emptyState();
  s1 = addIdentity(s1, 'x', 'data:a');
  s1 = addIdentity(s1, 'y', 'data:b');
  let s2 = emptyState();
  s2 = addIdentity(s2, 'y', 'data:b');
  s2 = addIdentity(s2, 'x', 'data:a');
  assert.ok(statesEqual(s1, s2));
});

test('statesEqual is false when a label set differs', () => {
  const s1 = addIdentity(emptyState(), 'x', 'data:a');
  const s2 = addIdentity(emptyState(), 'x', 'data:b');
  assert.ok(!statesEqual(s1, s2));
});

test('hashState is stable regardless of insertion order', () => {
  let s1 = emptyState();
  s1 = addIdentity(s1, 'x', 'data:a');
  s1 = addIdentity(s1, 'y', 'data:b');
  let s2 = emptyState();
  s2 = addIdentity(s2, 'y', 'data:b');
  s2 = addIdentity(s2, 'x', 'data:a');
  assert.equal(hashState(s1), hashState(s2));
});

test('hashState differs when facts differ', () => {
  const s1 = addIdentity(emptyState(), 'x', 'data:a');
  const s2 = addIdentity(emptyState(), 'x', 'data:b');
  assert.notEqual(hashState(s1), hashState(s2));
});

test('addIdentity and removeIdentitiesAt never mutate their input state (pure/immutable contract)', () => {
  const original = addIdentity(emptyState(), 'x', 'data:a');
  const originalHash = hashState(original);
  addIdentity(original, 'x', 'data:b');
  removeIdentitiesAt(original, 'x');
  assert.equal(hashState(original), originalHash, 'input state must be unchanged after calling either function on it');
});
