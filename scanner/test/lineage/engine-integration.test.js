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
