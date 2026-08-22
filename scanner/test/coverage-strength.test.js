// Gate for measured evidence strength (PRD F10.2).
//
// The change being protected: a control mapped to a detector with 5% recall was
// "covered" in the coverage map and uncovered in reality. Strength now travels
// with the mapping. These tests pin the two ways that can go wrong — claiming
// evidence that does not exist, and denying evidence that does.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  strengthOf, strengthOfControl, isPartiallyEvidenced, cwesFor, formatStrength,
} from '../src/posture/coverage-strength.js';

test('a measured family reports its rate WITH the denominator', () => {
  const s = strengthOf('sql-injection');
  assert.ok(s.recall && s.recall.d > 0, 'sql-injection must have independent measurement');
  assert.ok(['measured', 'partial', 'weak'].includes(s.tier));
  assert.match(formatStrength(s), /\d+\/\d+/, 'a rate must never be rendered without its denominator');
});

test('a weak detector is labelled weak, not covered', () => {
  // The PRD's motivating case. xss carries CWE-79, measured 3/18 on the
  // independent corpus — a control mapped to it is nominally covered and
  // materially is not.
  const s = strengthOf('xss');
  assert.equal(s.tier, 'weak', `expected weak, got ${s.tier} (${JSON.stringify(s.recall)})`);
  assert.ok(s.recall.n / s.recall.d < 0.25);
});

test('an unmeasured family says so and is never given a default rate', () => {
  const s = strengthOf('crypto-tls-version');
  assert.equal(s.tier, 'unmeasured');
  assert.equal(s.recall, null, 'unmeasured must carry NO rate — inventing one is the failure being prevented');
  assert.match(s.reason, /corpus|nothing to measure/);
});

test('a family with no CWE at all is unmeasured for that reason specifically', () => {
  // license-graph emits findings carrying no CWE, so there is nothing to join
  // recall onto. The distinction matters: "we have no CWE" is a different defect
  // from "the corpus never exercised this CWE".
  const s = strengthOf('license-graph');
  assert.equal(s.tier, 'unmeasured');
  assert.match(s.reason, /no CWE observed/);
});

test('an ALIASED mapping resolves to the real family before measuring', () => {
  // Regression: looking the mapped name up literally reported "unmeasured" for
  // every aliased mapping. ASVS V5.1 maps to `family:sqli`; nothing emits
  // `sqli`; the real family `sql-injection` IS measured. Denying evidence that
  // exists is the mirror of claiming evidence that does not.
  const s = strengthOf('sqli');
  assert.ok(s.recall && s.recall.d > 0, 'family:sqli must resolve to sql-injection and inherit its measurement');
  assert.deepEqual(s.recall, strengthOf('sql-injection').recall);
});

test('a SUFFIXED family resolves through the same rule', () => {
  // Detectors emit `<family>-<rule-slug>`. `family:prompt-injection` must reach
  // `prompt-injection-http-user-input-in-llm-` when computing strength, exactly
  // as it does when counting open findings.
  const cwes = cwesFor('prompt-injection');
  const direct = cwesFor('prompt-injection-http-user-input-in-llm-');
  for (const c of direct) assert.ok(cwes.includes(c), `suffixed CWE ${c} must be reachable from the base mapping`);
});

test('a control is only as strong as its WEAKEST backing family', () => {
  // Averaging would let a strong leg hide a leg that finds nothing.
  const control = { id: 'T', mapsTo: ['family:sql-injection', 'family:crypto-tls-version'] };
  const s = strengthOfControl(control);
  assert.equal(s.tier, 'unmeasured', 'one unmeasured leg must drag the control down');
  assert.match(s.reason, /crypto-tls-version/);
});

test('weak and unmeasured controls are flagged partially-evidenced; measured ones are not', () => {
  assert.equal(isPartiallyEvidenced({ mapsTo: ['family:crypto-tls-version'] }), true, 'unmeasured');
  assert.equal(isPartiallyEvidenced({ mapsTo: ['family:xss'] }), true, 'weak');
  assert.equal(isPartiallyEvidenced({ mapsTo: ['family:sql-injection'] }), false, 'measured must not be flagged');
});

test('a small denominator is flagged indicative rather than presented as settled', () => {
  const s = strengthOf('sql-injection');
  if (s.recall.d < 5) {
    assert.equal(s.reliable, false);
    assert.match(formatStrength(s), /indicative/);
  }
});

test('a control with no family mapping is unmeasured, not silently strong', () => {
  const s = strengthOfControl({ id: 'T', mapsTo: ['module:sbom-diff'] });
  assert.equal(s.tier, 'unmeasured');
});
