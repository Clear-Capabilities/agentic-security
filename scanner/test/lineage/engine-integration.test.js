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
