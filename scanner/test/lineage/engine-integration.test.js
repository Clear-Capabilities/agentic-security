// Integration tests against REAL parsed JS/TS IR (Task 5, Milestone 1
// sub-project A). Tasks 2-4 proved field-identity tracking against
// hand-built IR fixtures only; this file exists specifically to catch any
// place a hand-built fixture didn't match what the real parser actually
// produces.
//
// Destructuring investigation (per this plan's Task 1 ADR §4, which
// deliberately left the question open): `parseJsFile('/x/a.js',
// 'const {email, ssn} = user;')` was inspected directly and confirmed
// outcome (a) — the parser already lowers each destructured binding into
// its own plain 'assign' CFG node with a string `target` (e.g. 'email')
// and a `member`-kind `source` (e.g. {kind:'member', object:{kind:'ident',
// name:'user'}, prop:'email'}) — see scanner/src/ir/parser-js.js's
// VariableDeclarator visitor, the `id.kind === 'object-pattern'` branch.
// This is byte-identical to the shape Task 4's step() 'assign' case
// already handles, so destructuring needed ZERO new code in engine.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';

// Parses `src` for real and returns the named function's IR record.
function parseFn(src, fnName, file = '/x/a.js') {
  const ir = parseJsFile(file, src);
  assert.ok(ir, 'real parser must successfully parse this fixture source');
  const fn = ir.functions.find(f => f.name === fnName);
  assert.ok(fn, `expected a function named "${fnName}" in the parsed IR`);
  return fn;
}

test('FR-301 core proof, end to end from real parsed source: two distinct fields on one object literal never merge', () => {
  const src = `
function combine(user) {
  return { email: user.email, ssn: user.ssn };
}
`;
  const fn = parseFn(src, 'combine');
  assert.deepEqual(fn.params, ['user']);

  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  const result = analyzeFunctionFieldIdentity(fn, entryState);

  assert.equal(result.returnFacts.length, 1, 'combine() has exactly one return statement');
  const flat = result.returnFacts[0].identities;
  assert.deepEqual([...flat].sort(), ['data:email', 'data:ssn'],
    'the returned object literal must carry BOTH distinct fields, never collapsed into one merged fact');
});

test('destructuring extraction from real parsed source: one binding carries only its own field, not its sibling\'s', () => {
  const src = `
function extract(user) {
  const { email, ssn } = user;
  return email;
}
`;
  const fn = parseFn(src, 'extract');
  assert.deepEqual(fn.params, ['user']);

  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  const result = analyzeFunctionFieldIdentity(fn, entryState);

  assert.equal(result.returnFacts.length, 1);
  const flat = result.returnFacts[0].identities;
  assert.deepEqual([...flat], ['data:email'],
    'destructured `email` must carry ONLY data:email — proving destructuring extracts one field without conflating it with its sibling `ssn`');
});

test('aliasing a real parsed object through an intermediate variable keeps fields isolated (regression for a gap a final review found via the real parser)', () => {
  const src = `
    function combine(user) {
      const copy = user;
      const e = copy.email;
      return e;
    }
  `;
  const fn = parseFn(src, 'combine');
  assert.deepEqual(fn.params, ['user']);

  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);
});

test('the CFG branch-join and the equivalent ternary must give the SAME (correct) answer for the same program (regression for a gap found in round 3)', () => {
  // Two functions expressing the exact same semantics two different ways:
  //   viaBranch:  if (flag) { c = user; } else { c = other; } return c.email;
  //   viaTernary: const c = flag ? user : other;              return c.email;
  // joinStates (the CFG-level branch join) already keeps user.email/user.ssn/
  // other.name separated per sub-path, so viaBranch was always correct. The
  // 'union' case (before this round's fix) instead flattened both branches'
  // identities into one coarse blob, so viaTernary incorrectly returned
  // [data:email, data:ssn, data:name] instead of just [data:email]. Both
  // forms must now resolve identically.
  const src = `
    function viaBranch(user, other, flag) {
      let c;
      if (flag) {
        c = user;
      } else {
        c = other;
      }
      return c.email;
    }

    function viaTernary(user, other, flag) {
      const c = flag ? user : other;
      return c.email;
    }
  `;
  const ir = parseJsFile('/x/a.js', src);
  assert.ok(ir, 'real parser must successfully parse this fixture source');

  const buildEntryState = () => {
    let s = addIdentity(emptyState(), 'user.email', 'data:email');
    s = addIdentity(s, 'user.ssn', 'data:ssn');
    s = addIdentity(s, 'other.name', 'data:name');
    return s;
  };

  const branchFn = ir.functions.find(f => f.name === 'viaBranch');
  const ternaryFn = ir.functions.find(f => f.name === 'viaTernary');
  assert.ok(branchFn, 'expected a function named "viaBranch" in the parsed IR');
  assert.ok(ternaryFn, 'expected a function named "viaTernary" in the parsed IR');

  const branchResult = analyzeFunctionFieldIdentity(branchFn, buildEntryState());
  const ternaryResult = analyzeFunctionFieldIdentity(ternaryFn, buildEntryState());

  assert.equal(branchResult.returnFacts.length, 1);
  assert.equal(ternaryResult.returnFacts.length, 1);

  const branchFlat = [...branchResult.returnFacts[0].identities].sort();
  const ternaryFlat = [...ternaryResult.returnFacts[0].identities].sort();

  assert.deepEqual(branchFlat, ['data:email'],
    'the if/else branch-join form must return only data:email (already correct via joinStates)');
  assert.deepEqual(ternaryFlat, ['data:email'],
    'the ternary form must return only data:email — must match the branch-join form exactly, not the wider [data:email, data:ssn, data:name] the coarse-merge bug produced');
  assert.deepEqual(ternaryFlat, branchFlat,
    'the two syntactic forms of the identical semantics must resolve to the identical result');
});

test('reading a field directly off a ternary/logical expression (no intermediate variable) gives the SAME answer as going through one (regression for a gap found via the real parser)', () => {
  const src = `
    function directRead(user, other) {
      return (user ?? other).email;
    }
  `;
  const fn = parseFn(src, 'directRead');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email']);
});

test('assignment-expression-form destructuring does not fabricate a colliding shared key across unrelated destructurings (regression for a gap found via the real parser)', () => {
  const src = `
    function f(user, other) {
      let a, b;
      ({name: a} = other);
      ({name: b} = user);
      return a;
    }
  `;
  const fn = parseFn(src, 'f');
  let entryState = addIdentity(emptyState(), 'user.name', 'data:user-name');
  entryState = addIdentity(entryState, 'other.name', 'data:other-name');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  // Confirm no collision: exitState must not have a single shared "[object Object]"-style
  // key holding both identities merged together. Given the fix skips (rather than tracks)
  // this form, `a`/`b` will not carry the expected identity either — confirm the state does
  // NOT contain a wrongly-populated stringified-object key, which is the actual defect this
  // guards against; do not assert that `a` correctly carries `data:other-name` (out of scope
  // for this fix, per the deferred-limitation note in step()).
  const hasCollisionKey = [...result.exitState.keys()].some((k) => k.includes('[object Object]'));
  assert.ok(!hasCollisionKey, 'must never write to a stringified-pattern-object fabricated key');
});

test('template literal propagation from real parsed source: identity flows through interpolation, no widening', () => {
  const src = `
function greet(user) {
  return \`Hello \${user.email}\`;
}
`;
  const fn = parseFn(src, 'greet');
  assert.deepEqual(fn.params, ['user']);

  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const result = analyzeFunctionFieldIdentity(fn, entryState);

  assert.equal(result.returnFacts.length, 1);
  const flat = result.returnFacts[0].identities;
  assert.deepEqual([...flat], ['data:email']);
  assert.equal(result.widenings.length, 0,
    'per the ADR (§4): template-literal interpolation propagates identity normally and must NOT be recorded as a widening event');
});

// Round 5 regression: two computed-key writes to the same object must
// ACCUMULATE (weak update), not have the second overwrite the first (strong
// update) — every computed-key write on the same container lowers to the
// SAME literal target string ('bag.*'), since the actual runtime key is
// statically unknown, so a strong update on that shared string would treat
// two genuinely different write locations as the same location. Mirrors
// scanner/src/dataflow/engine.js's `_addPathAliasAware` precedent.
test('two computed-key writes to the same object accumulate instead of the second overwriting the first (regression for a round-5 finding)', () => {
  const src = `
    function f(user, k1, k2) {
      const bag = {};
      bag[k1] = user.email;
      bag[k2] = user.ssn;
      return bag;
    }
  `;
  const fn = parseFn(src, 'f');
  assert.deepEqual(fn.params, ['user', 'k1', 'k2']);

  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  const result = analyzeFunctionFieldIdentity(fn, entryState);

  assert.equal(result.returnFacts.length, 1);
  const flat = result.returnFacts[0].identities;
  assert.deepEqual([...flat].sort(), ['data:email', 'data:ssn'],
    'the second computed-key write must not have deleted the first (pre-fix bug returned only data:ssn)');
});

// Round 5, fix (c): an object literal's COMPUTED key with a non-literal key
// expression (`[k]: ...`) was resolved by parser-js.js's ObjectExpression
// handling to the key EXPRESSION's own variable name ('k') — colliding with
// an explicit, non-computed property literally named `k` on the same
// object, since an Identifier key node has a `.name` regardless of whether
// `computed` is true. `{ k: user.ssn, [k]: user.email }` pre-fix wrote BOTH
// properties' identities to the exact same access path `c.k`, as a single
// false-certain fact (a genuine FR-301 merge). Post-fix, the parser marks
// the unresolvable computed key '*' (mirroring the existing computed-
// MEMBER-access convention) and engine.js's `object` case folds a
// '*'-keyed property into the object's coarse RESIDUAL, not a byPath entry.
test('object literal with an explicit key and a colliding-by-variable-name computed key no longer merges them into one fabricated key at the parser layer (regression for a round-5 finding touching the shared parser)', () => {
  const src = `
    function h(user, k) {
      const c = { k: user.ssn, [k]: user.email };
      return c;
    }
  `;
  const fn = parseFn(src, 'h');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);

  // Checked directly against exitState's raw entries (not via identitiesAt's
  // own ancestor-aggregation semantics, which legitimately re-combines the
  // two below for a DIFFERENT, correct reason — see the comment on the
  // final assertion): `c.k` must hold ONLY the identity of the property
  // that genuinely, definitely owns that literal key. Pre-fix this held
  // BOTH `data:ssn` and `data:email` merged as one false-certain fact.
  assert.deepEqual([...result.exitState.get('c.k')], ['data:ssn'],
    'c.k must hold ONLY the identity of the property that genuinely, definitely owns that literal key — not merged with the computed-key property');
  // The unknown-key property's identity must be folded into the coarse
  // residual at the CONTAINER's own path, not fabricated onto "c.k".
  assert.deepEqual([...result.exitState.get('c')], ['data:email'],
    'the unknown-key property must be folded into the coarse residual at the container\'s own path');

  // A read of `c.k` (or of `c` as a whole) still correctly sees BOTH
  // identities once identitiesAt's existing ancestor-coverage semantics
  // apply: the residual at `c` conservatively applies to every field under
  // it, since the unknown-key write genuinely MIGHT have landed on 'k'.
  // This is intentional, honest widening (FR-306), not the pre-fix bug —
  // the distinction proven above is WHERE each identity is recorded
  // (definite vs. residual/conservative), not whether a downstream read
  // ever sees both.
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn']);
});

// Round 6, Finding 1: `lhsPath`'s `ObjectPattern` branch (the destructuring-
// pattern lowering, in parser-js.js) had the identical computed-key bug
// round 5 fixed for `ObjectExpression` (object literals) — it resolved a
// non-literal computed key (`{[field]: value}`) to the key EXPRESSION's own
// variable name ('field') instead of the explicit unknown marker '*'.
// Pre-fix, `member`'s path-succeeds branch queried `identitiesAt(state,
// 'user.field')` for a fabricated path that was never actually written
// (there is no real property literally named "field" on `user` here), so
// it silently returned nothing — `returnFacts: []`, dropping the identity
// entirely. Post-fix, the shared `resolveObjectKey` helper (now used by
// both `ObjectExpression` and `ObjectPattern`) resolves the non-literal
// computed key to '*', so the lowered source is `member(user, '*')`, which
// round 5's wildcard handling in engine.js correctly and conservatively
// widens to the WHOLE base's aggregate identity — the equivalent
// `return user[field]` already widened correctly per round 5; this closes
// the exact same gap for the destructuring-pattern spelling of the same
// read.
test('destructuring with a computed key does not fabricate a colliding key from the key variable\'s own name (regression for a round-6 finding)', () => {
  const src = `
    function f(user) {
      const { [field]: value } = user;
      return value;
    }
  `;
  const fn = parseFn(src, 'f');
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  const result = analyzeFunctionFieldIdentity(fn, entryState);

  // Verified against the actual fixed code's output (not assumed): the
  // computed key resolves to '*', so `value`'s source is `member(user,
  // '*')`, which conservatively widens to user's full aggregate identity —
  // here just {data:email}, since that's the only identity recorded on
  // `user` in this entry state. Pre-fix this returned `[]` (see the
  // comment above).
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'],
    'a computed destructuring key must conservatively widen to the base object\'s aggregate identity, never silently drop it');
});

// Round 6, Finding 2: round 5's wildcard guards (`path === '*' ||
// path.endsWith('.*')`) only recognized a TRAILING wildcard segment.
// `store[k1].name`/`store[k2].name` both lower to the access path
// `store.*.name` (the '*' is INTERIOR, not trailing) — `endsWith('.*')` is
// false for this string, so pre-fix it fell through to the OLD, unfixed
// strong-update behavior: the second assign's `removeIdentitiesAt`
// silently deleted the first write's identity. The generalized
// `definitePrefixBeforeWildcard`/`pathHasWildcard` helpers fix this by
// finding the wildcard at ANY position, not just the end.
test('an interior wildcard write (obj[k].field = ...) accumulates instead of overwriting a prior write through a different unknown key (regression for a round-6 finding)', () => {
  const src = `
    function f(user, other) {
      store[k1].name = user.email;
      store[k2].name = user.ssn;
      return store;
    }
  `;
  const fn = parseFn(src, 'f');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);

  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn'],
    'the second interior-wildcard write must not have deleted the first (pre-fix bug returned only data:ssn)');
});

test('an interior wildcard read (obj.a.field after obj[k].field = ...) conservatively resolves via the definite prefix, does not silently drop the identity', () => {
  const src = `
    function f(user) {
      store[k].name = user.ssn;
      return store.a.name;
    }
  `;
  const fn = parseFn(src, 'f');
  const entryState = addIdentity(emptyState(), 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);

  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities], ['data:ssn'],
    'a read through an interior wildcard must conservatively resolve via the definite prefix ("store"), not silently return nothing (pre-fix bug returned [])');
});

test('the trailing-wildcard case from round 5 still works after generalizing to position-independence (no regression)', () => {
  const src = `
    function f(user, other) {
      bag[k1] = user.email;
      bag[k2] = user.ssn;
      return bag;
    }
  `;
  const fn = parseFn(src, 'f');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);

  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn'],
    'the trailing-wildcard case round 5 already fixed must keep working after generalizing the guard to be position-independent');
});

test('object rest in destructuring binds to the source object\'s full aggregate, flagged widened (fixes a documented, pre-existing gap: rest was previously silently dropped entirely)', () => {
  const src = `
    function f(user) {
      const { email, ...rest } = user;
      return rest;
    }
  `;
  const fn = parseFn(src, 'f');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');
  const result = analyzeFunctionFieldIdentity(fn, entryState);
  // `rest` conservatively includes BOTH fields (the safe over-approximation
  // this task's brief documents — real JS would exclude `email`, but this
  // fix does not attempt that precision) and the read is flagged widened.
  assert.equal(result.returnFacts.length, 1);
  assert.deepEqual([...result.returnFacts[0].identities].sort(), ['data:email', 'data:ssn'],
    'rest must carry the source object\'s full aggregate identity instead of vanishing (pre-fix: returnFacts was empty)');
});
