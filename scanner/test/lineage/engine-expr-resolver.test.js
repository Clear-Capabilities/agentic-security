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

test('resolving a bare ident whose value has recorded field structure populates byPath from its descendants (fixes an aliasing gap a final review found)', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn']]);
  const r = resolveExprIdentities(state, { kind: 'ident', name: 'user' });
  assert.deepEqual([...r.flat].sort(), ['data:email', 'data:ssn']);
  assert.deepEqual([...r.byPath.get('email')], ['data:email']);
  assert.deepEqual([...r.byPath.get('ssn')], ['data:ssn']);
});

test('resolving an ident with BOTH a coarse fact at its own path AND descendant field facts keeps the coarse fact as residual only, never merged into a field entry', () => {
  let state = stateWith([['rec.email', 'data:email']]);
  state = addIdentity(state, 'rec', 'data:generic');
  const r = resolveExprIdentities(state, { kind: 'ident', name: 'rec' });
  assert.deepEqual([...r.flat].sort(), ['data:email', 'data:generic']);
  assert.deepEqual([...r.byPath.get('email')], ['data:email'], 'the field entry must contain ONLY its own field\'s identity, not the coarse one too');
});

test('an object literal property that is itself an aliased/structured object keeps its fields isolated, not coarsely re-merged at the property key', () => {
  const state = stateWith([['src.x', 'data:x'], ['src.y', 'data:y']]);
  const expr = { kind: 'object', props: [{ key: 'a', value: { kind: 'ident', name: 'src' } }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.byPath.get('a.x')], ['data:x']);
  assert.deepEqual([...r.byPath.get('a.y')], ['data:y']);
  assert.ok(!r.byPath.has('a'), 'must NOT also have a coarse "a" entry duplicating both nested fields together');
});

test('logical (??) can select an existing structured value, and must forward its field structure, not flatten it', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn']]);
  const expr = { kind: 'logical', op: '??', left: { kind: 'ident', name: 'user' }, right: { kind: 'object', props: [] } };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.byPath.get('email')], ['data:email']);
  assert.deepEqual([...r.byPath.get('ssn')], ['data:ssn']);
});

test('ternary (union) unions branch byPath PER SUB-PATH, never coarsely at the root — same principle as a CFG branch join', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn'], ['other.name', 'data:name']]);
  const expr = { kind: 'union', branches: [{ kind: 'ident', name: 'user' }, { kind: 'ident', name: 'other' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.byPath.get('email')], ['data:email']);
  assert.deepEqual([...r.byPath.get('ssn')], ['data:ssn']);
  assert.deepEqual([...r.byPath.get('name')], ['data:name']);
  assert.ok(!r.byPath.has(''), 'must never have a coarse root-level entry merging all three fields together');
});

test('a ternary between the SAME object on both branches must not merge that object\'s own distinct fields (there is no real alternative to justify a union)', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn']]);
  const expr = { kind: 'union', branches: [{ kind: 'ident', name: 'user' }, { kind: 'ident', name: 'user' }] };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.byPath.get('email')], ['data:email'], 'must not pick up ssn just because the ternary syntax is present');
  assert.deepEqual([...r.byPath.get('ssn')], ['data:ssn']);
});

test('member selection off a ternary base correctly selects the field instead of silently dropping the identity (regression for a gap a final review found)', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn'], ['other.name', 'data:name']]);
  const expr = {
    kind: 'member',
    object: { kind: 'union', branches: [{ kind: 'ident', name: 'user' }, { kind: 'ident', name: 'other' }] },
    prop: 'email',
  };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:email'], 'must select only the email field, not silently return nothing');
});

test('member selection off a logical (??) base correctly selects the field', () => {
  const state = stateWith([['user.email', 'data:email']]);
  const expr = {
    kind: 'member',
    object: { kind: 'logical', op: '??', left: { kind: 'ident', name: 'user' }, right: { kind: 'object', props: [] } },
    prop: 'email',
  };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:email']);
});

test('assign-expr resolves to its source\'s identity and forwards byPath, without a false widening flag', () => {
  const state = stateWith([['user.email', 'data:email']]);
  const expr = { kind: 'assign-expr', target: 'x', source: { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: 'email' } };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat], ['data:email']);
  assert.equal(r.widened, false, 'no call is involved, this must not be flagged as an unresolved-call widening');
});

// Round 5: a statically-unknown computed member key (`obj[k]`, lowered by
// accessPathOf/the parser to a trailing '*' path segment) must never
// silently resolve to nothing (FR-306's "never launder identity into a
// clean value" principle) — it must conservatively resolve the whole base
// object's aggregate identity, flagged widened. See DESIGN_INTRAPROCEDURAL.md
// §4 and scanner/src/lineage/CLAUDE.md.
test('a computed member access with an unknown key resolves the container\'s full aggregate, flagged widened, instead of silently returning nothing', () => {
  const state = stateWith([['user.email', 'data:email'], ['user.ssn', 'data:ssn']]);
  const expr = { kind: 'member', object: { kind: 'ident', name: 'user' }, prop: '*' };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:email', 'data:ssn']);
  assert.equal(r.widened, true);
});

test('a computed member access with an unknown key on a NON-path base (e.g. `(user ?? other)[k]`) also resolves the base\'s aggregate, flagged widened', () => {
  const state = stateWith([['user.email', 'data:email'], ['other.name', 'data:name']]);
  const expr = {
    kind: 'member',
    object: { kind: 'logical', op: '??', left: { kind: 'ident', name: 'user' }, right: { kind: 'ident', name: 'other' } },
    prop: '*',
  };
  const r = resolveExprIdentities(state, expr);
  assert.deepEqual([...r.flat].sort(), ['data:email', 'data:name']);
  assert.equal(r.widened, true);
});
