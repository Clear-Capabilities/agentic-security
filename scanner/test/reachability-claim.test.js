// PRD F3.2 — reachability is its OWN claim, with its own error costs.
//
// "A vulnerable version is present" and "the vulnerable FUNCTION is reachable"
// are different assertions, and they were reported as one number. The costs are
// not symmetric:
//
//   a false "unreachable" is a MISSED EXPLOIT — the finding is demoted to info
//     and a real vulnerability stops being shown to anyone;
//   a false "reachable" is noise — someone reads a finding that did not matter.
//
// A single accuracy figure spanning both is the wrong instrument, because it
// lets the cheap error hide behind the expensive one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeReachability } from '../src/posture/reachability-filter.js';

test('UNKNOWN is a first-class state, never folded into reachable', () => {
  // The failure that would inflate the claim: a finding the analysis had no
  // opinion about counted as "reachable" makes the feature look more decisive
  // than it is.
  const s = summarizeReachability([{ unreachable: true }, {}, {}]);
  assert.deepEqual(s.unknown, { n: 2, d: 3 });
  assert.equal(s.reachable.d, 1, 'only JUDGED findings belong in the reachability denominator');
});

test('the demotion rate is published — it says how much rests on the claim', () => {
  // Near zero means the feature is not earning its risk; high means a great
  // deal depends on it being right. Either way the reader needs the number.
  const s = summarizeReachability([{ unreachable: true }, { reachable: true }]);
  assert.deepEqual(s.demotionRate, { n: 1, d: 2 });
});

test('the ASYMMETRIC error costs are stated, not left to inference', () => {
  const s = summarizeReachability([{ unreachable: true }]);
  assert.match(s.errorCosts.falseUnreachable, /MISSED EXPLOIT/);
  assert.match(s.errorCosts.falseReachable, /noise/);
});

test('every rate carries its denominator', () => {
  const s = summarizeReachability([{ unreachable: true }, { reachable: true }, {}]);
  for (const k of ['judged', 'unknown', 'reachable', 'unreachable', 'demotionRate']) {
    assert.ok(typeof s[k].n === 'number' && typeof s[k].d === 'number', `${k} must be {n,d}`);
  }
});

test('an empty set does not fabricate a rate', () => {
  const s = summarizeReachability([]);
  assert.equal(s.total, 0);
  assert.match(s.caveat, /means nothing/);
});

test('reachable and unreachable partition the judged set exactly', () => {
  // If they stop summing, findings are being double-counted or dropped — and a
  // dropped finding always flatters whichever rate is published.
  const s = summarizeReachability([
    { unreachable: true }, { unreachable: true }, { reachable: true }, { functionReachable: 'yes' }, {},
  ]);
  assert.equal(s.reachable.n + s.unreachable.n, s.judged.n);
});
