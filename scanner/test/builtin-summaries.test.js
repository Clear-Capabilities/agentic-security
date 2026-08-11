// posture/CLAUDE.md precedent — same class of bug as elsewhere this session:
// code that computes the right answer and then discards it. lookupBuiltinSummary's
// dotted-name fallback (`Number.parseInt` -> the bare `parseInt` entry) looked
// up the bare-name summary into `fallback`, checked `if (fallback)`, and then
// returned `null` in the truthy branch instead of `fallback` — identical to the
// not-found case. Real, if narrow, effect: any dotted callee whose tail matches
// one of the ~10 bare-key builtins (parseInt, parseFloat, Number, Boolean, int,
// float, str, fetch, got, cors) fell through to "no summary" instead of the
// summary its own fallback logic found.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lookupBuiltinSummary } from '../src/dataflow/builtin-summaries.js';

test('lookupBuiltinSummary resolves an exact match directly', () => {
  const direct = lookupBuiltinSummary('str');
  assert.ok(direct, 'expected a summary for the bare "str" builtin');
});

test('lookupBuiltinSummary falls back to the bare-name entry for a dotted callee', () => {
  const direct = lookupBuiltinSummary('str');
  const dotted = lookupBuiltinSummary('obj.str');
  assert.ok(dotted, 'expected the dotted callee to fall back to the bare "str" entry, not null');
  assert.deepEqual(dotted, direct);
});

test('lookupBuiltinSummary returns null for a callee with no exact or fallback match', () => {
  assert.equal(lookupBuiltinSummary('totally.unknown.method'), null);
  assert.equal(lookupBuiltinSummary('unknownBareCallee'), null);
});
