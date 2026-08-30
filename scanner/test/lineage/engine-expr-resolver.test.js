import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { resolveExprIdentities } from '../../src/lineage/engine.js';

function stateWith(pairs) {
  let s = emptyState();
  for (const [path, id] of pairs) s = addIdentity(s, path, id);
  return s;
}

test('ident resolves via the state at that exact variable name', () => {
  const state = stateWith([['user', 'data:x']]);
  const r = resolveExprIdentities(state, { kind: 'ident', name: 'user' });
  assert.deepEqual([...r.flat], ['data:x']);
  assert.equal(r.widened, false);
});

test('member resolves via the dotted access path', () => {
  const state = stateWith([['user.email', 'data:email']]);
  const r = resolveExprIdentities(state, { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' });
  assert.deepEqual([...r.flat], ['data:email']);
});

test('literal never carries an identity', () => {
  const r = resolveExprIdentities(emptyState(), { kind: 'literal', value: 'hello' });
  assert.equal(r.flat.size, 0);
});

test('object literal attributes each property to its own byPath sub-key, distinctly (FR-301 core case)', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn']]);
  const expr = {
    kind: 'object',
    props: [
      { key: 'email', value: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } },
      { key: 'ssn', value: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'ssn' } },
    ],
  };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:email', 'data:ssn']);
  assert.deepEqual([...r.byPath.get('email')], ['data:email']);
  assert.deepEqual([...r.byPath.get('ssn')], ['data:ssn']);
});

test('nested object literal produces dotted sub-paths', () => {
  const state = stateWith([['x', 'data:inner']]);
  const expr = { kind: 'object', props: [{ key: 'a', value: { kind: 'object', props: [{ key: 'b', value: { kind: 'ident', name: 'x' } }] } } ] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.byPath.get('a.b')], ['data:inner']);
});

test('array literal flattens all elements, no index sensitivity', () => {
  const state = stateWith([['a', 'data:1'], ['b', 'data:2']]);
  const expr = { kind: 'array', elements: [{ kind: 'ident', name: 'a' }, { kind: 'ident', name: 'b' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:1', 'data:2']);
  assert.equal(r.byPath.size, 0);
});

test('template literal interpolation propagates identity, NOT flagged as widened', () => {
  const state = stateWith([['email', 'data:email']]);
  const expr = { kind: 'tpl', parts: [{ kind: 'ident', name: 'email' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:email']);
  assert.equal(r.widened, false);
});

test('binary (string concatenation) propagates identity from both sides, not widened', () => {
  const state = stateWith([['a', 'data:1'], ['b', 'data:2']]);
  const expr = { kind: 'binary', op: '+', left: { kind: 'ident', name: 'a' }, right: { kind: 'ident', name: 'b' } };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:1', 'data:2']);
  assert.equal(r.widened, false);
});

test('logical (?? / ||) propagates identity from both sides, not widened', () => {
  const state = stateWith([['a', 'data:1']]);
  const expr = { kind: 'logical', op: '??', left: { kind: 'ident', name: 'a' }, right: { kind: 'literal', value: 'default' } };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:1']);
});

test('ternary (union) merges both branches conservatively', () => {
  const state = stateWith([['a', 'data:1'], ['b', 'data:2']]);
  const expr = { kind: 'union', branches: [{ kind: 'ident', name: 'a' }, { kind: 'ident', name: 'b' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:1', 'data:2']);
});

test('an unresolved call is flagged as widened when its arguments carry an identity', () => {
  const state = stateWith([['secret', 'data:x']]);
  const expr = { kind: 'call', callee: { kind: 'ident', name: 'someFn' }, args: [{ kind: 'ident', name: 'secret' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:x']);
  assert.equal(r.widened, true);
});

test('an unresolved call with no identity-carrying arguments is NOT flagged as widened', () => {
  const expr = { kind: 'call', callee: { kind: 'ident', name: 'someFn' }, args: [{ kind: 'literal', value: 1 }] };
  const r = resolveExprIdentities(emptyState(), expr);
  assert.equal(r.flat.size, 0);
  assert.equal(r.widened, false);
});

test('unknown-kind expression resolves to no identity, fails open', () => {
  const r = resolveExprIdentities(emptyState(), { kind: 'unknown' });
  assert.equal(r.flat.size, 0);
  assert.equal(r.widened, false);
});
