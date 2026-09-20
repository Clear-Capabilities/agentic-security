// v0.69 #4a — string-domain regex lattice tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  TOP, BOTTOM,
  makeConst, makeConcat, makeRegex,
  abstract, join, render, provablyMatches,
  isSafeValidationPattern,
} from '../src/dataflow/string-domain.js';

test('makeRegex rejects unanchored patterns', () => {
  // Unanchored regex would be unsound — could match a substring.
  assert.equal(makeRegex(/[A-Z]+/), TOP);
  assert.equal(makeRegex(/^[A-Z]+/), TOP);
  assert.equal(makeRegex(/[A-Z]+$/), TOP);
  // Anchored both sides → real Regex value.
  const r = makeRegex(/^[A-Z]+$/);
  assert.equal(r.kind, 'Regex');
});

test('abstract recognizes encodeURIComponent as regex-constrained output', () => {
  const expr = { kind: 'call', callee: 'encodeURIComponent', args: [{ kind: 'ident', name: 'x' }] };
  const a = abstract(expr);
  assert.equal(a.kind, 'Regex');
  assert.match(a.pattern.source, /^\^/);
  assert.match(a.pattern.source, /\$$/);
});

test('abstract returns TOP for unknown calls', () => {
  const expr = { kind: 'call', callee: 'mysteryFn', args: [] };
  const a = abstract(expr);
  assert.equal(a.kind, 'Unknown');
});

test('provablyMatches: constant fits within a safe charset', () => {
  const v = makeConst('hello123');
  assert.equal(provablyMatches(v, /^[A-Za-z0-9]*$/), true);
  assert.equal(provablyMatches(v, /^\d+$/), false);
});

test('provablyMatches: regex value matches identical safe-charset regex', () => {
  const r = makeRegex(/^[A-Za-z0-9\-_.!~*'()%]*$/);
  // Same source → provable.
  assert.equal(provablyMatches(r, /^[A-Za-z0-9\-_.!~*'()%]*$/), true);
  // Different (looser) → not provable in v1 (we don't do regex subset).
  assert.equal(provablyMatches(r, /^.*$/), false);
});

test('provablyMatches: Concat of provably-safe parts matches a starred-charset safe regex', () => {
  const a = makeConst('abc');
  const b = makeConst('123');
  const c = makeConcat([a, b]);
  // Safe regex permits arbitrary repetition.
  assert.equal(provablyMatches(c, /^[A-Za-z0-9]*$/), true);
  // Safe regex requires exact ^digits$ — concat of "abc"+"123" doesn't fit.
  assert.equal(provablyMatches(c, /^\d+$/), false);
});

test('join: Regex ⊔ matching Const = Regex', () => {
  const r = makeRegex(/^[A-Z]+$/);
  const c = makeConst('HELLO');
  const j = join(r, c);
  assert.equal(j.kind, 'Regex');
  assert.equal(j.pattern.source, '^[A-Z]+$');
});

test('join: Regex ⊔ non-matching Const = Unknown', () => {
  const r = makeRegex(/^[A-Z]+$/);
  const c = makeConst('hello');
  const j = join(r, c);
  assert.equal(j.kind, 'Unknown');
});

test('join: same-pattern Regexes meet to themselves', () => {
  const r1 = makeRegex(/^\d+$/);
  const r2 = makeRegex(/^\d+$/);
  const j = join(r1, r2);
  assert.equal(j.kind, 'Regex');
});

test('join: different Regex patterns become Unknown (no regex-subset in v1)', () => {
  const r1 = makeRegex(/^\d+$/);
  const r2 = makeRegex(/^\d{1,3}$/);
  const j = join(r1, r2);
  assert.equal(j.kind, 'Unknown');
});

test('render: regex value renders its pattern source', () => {
  const r = makeRegex(/^[A-Z]+$/);
  assert.equal(render(r), '^[A-Z]+$');
});

test('parseInt is recognized as integer-output', () => {
  const expr = { kind: 'call', callee: 'parseInt', args: [{ kind: 'ident', name: 'x' }] };
  const a = abstract(expr);
  assert.equal(a.kind, 'Regex');
  assert.ok(a.pattern.test('42'));
  assert.ok(a.pattern.test('-7'));
  assert.equal(a.pattern.test('1e5'), false);
});

// Next-gen taint capability #2 — regex-validation guard safety
// (`isSafeValidationPattern`). Every "safe" case here must be one where
// observing a MATCH provably rules out injection metacharacters for every
// family this catalog covers; every "unsafe" case is either a pattern that
// can match dangerous characters, or one this conservative parser cannot
// fully reason about (which must reject, not guess).

test('isSafeValidationPattern: accepts simple anchored character classes', () => {
  assert.equal(isSafeValidationPattern(/^[a-zA-Z]+$/), true);
  assert.equal(isSafeValidationPattern(/^[0-9]*$/), true);
  assert.equal(isSafeValidationPattern(/^[a-zA-Z0-9]+$/), true);
  assert.equal(isSafeValidationPattern(/^\d+$/), true);
  assert.equal(isSafeValidationPattern(/^\w+$/), true);
  assert.equal(isSafeValidationPattern(/^\d{1,10}$/), true);
  assert.equal(isSafeValidationPattern(/^[a-z_.\-@]+$/), true);
});

test('isSafeValidationPattern: rejects unanchored patterns', () => {
  assert.equal(isSafeValidationPattern(/[a-zA-Z]+/), false);
  assert.equal(isSafeValidationPattern(/^[a-zA-Z]+/), false);
  assert.equal(isSafeValidationPattern(/[a-zA-Z]+$/), false);
});

test('isSafeValidationPattern: rejects the wildcard-everything pattern (the real generator\'s own "no_filtering" unsafe sample)', () => {
  assert.equal(isSafeValidationPattern(/^.*$/), false);
});

test('isSafeValidationPattern: rejects negated character classes', () => {
  assert.equal(isSafeValidationPattern(/^[^<>]*$/), false);
});

test('isSafeValidationPattern: rejects negated shorthand classes (\\D, \\W, \\S)', () => {
  assert.equal(isSafeValidationPattern(/^\D+$/), false);
  assert.equal(isSafeValidationPattern(/^\W+$/), false);
  assert.equal(isSafeValidationPattern(/^\S+$/), false);
  assert.equal(isSafeValidationPattern(/^\s+$/), false); // \s permits newlines — CRLF-injection relevant
});

test('isSafeValidationPattern: rejects alternation, groups, and backreferences', () => {
  assert.equal(isSafeValidationPattern(/^(a|b)+$/), false);
  assert.equal(isSafeValidationPattern(/^(abc)+$/), false);
  assert.equal(isSafeValidationPattern(/^(\w)\1+$/), false);
});

test('isSafeValidationPattern: rejects the multiline flag even on an otherwise-safe body', () => {
  assert.equal(isSafeValidationPattern(new RegExp('^[a-z]+$', 'm')), false);
});

test('isSafeValidationPattern: rejects a dangerous character sneaking into a bracket class', () => {
  assert.equal(isSafeValidationPattern(/^[a-zA-Z'"<>;]+$/), false);
});

test('isSafeValidationPattern: rejects the degenerate empty-body pattern', () => {
  assert.equal(isSafeValidationPattern(/^$/), false);
});

test('isSafeValidationPattern: rejects a malformed quantifier', () => {
  assert.equal(isSafeValidationPattern(/^[a-z]{2,x}$/), false);
});

test('isSafeValidationPattern: rejects non-RegExp input', () => {
  assert.equal(isSafeValidationPattern('^[a-z]+$'), false);
  assert.equal(isSafeValidationPattern(null), false);
  assert.equal(isSafeValidationPattern(undefined), false);
});
