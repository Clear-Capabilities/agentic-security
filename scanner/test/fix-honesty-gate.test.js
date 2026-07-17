// Unit tests for posture/fix-honesty-gate.js (#7) — deterministic honesty gates
// on fix / finding output. These gates reject the two silent-failure modes the
// project's verification discipline warns about: hand-wave residual-risk prose
// ("adequately handled", "future work", "tbd") that lies about what's left, and
// a false-positive / provably-safe verdict shipped WITHOUT a file:line citation
// to back it. The fix tier is computed conservative-first so a partial fix can
// never be labelled FULL.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkResidualHonesty,
  requireCitedEvidence,
  computeFixTier,
  gateFixOutput,
} from '../src/posture/fix-honesty-gate.js';

// ---------------------------------------------------------------------------
// checkResidualHonesty
// ---------------------------------------------------------------------------

const HANDWAVE_PHRASES = [
  'adequately handled',
  'adequately handles',
  'properly validated',
  'properly handled',
  'handled properly',
  'handled safely',
  'future work',
  'more work needed',
  'to be done',
  'tbd',
  'later',
];

test('checkResidualHonesty rejects every banned hand-wave phrase and names it', () => {
  for (const phrase of HANDWAVE_PHRASES) {
    const r = checkResidualHonesty(`Remaining risk: ${phrase}.`);
    assert.equal(r.ok, false, `expected "${phrase}" to be rejected`);
    assert.ok(
      r.violations.some((v) => v.toLowerCase().includes(phrase)),
      `expected a violation naming "${phrase}", got ${JSON.stringify(r.violations)}`,
    );
  }
});

test('checkResidualHonesty is case-insensitive', () => {
  assert.equal(checkResidualHonesty('FUTURE WORK').ok, false);
  assert.equal(checkResidualHonesty('This is Properly Handled by the middleware.').ok, false);
});

test('checkResidualHonesty accepts a concrete, honest residual', () => {
  const r = checkResidualHonesty(
    'Attacker with a stolen session cookie can still replay within the 5-minute TTL window.',
  );
  assert.equal(r.ok, true);
  assert.deepEqual(r.violations, []);
});

test('checkResidualHonesty treats empty / whitespace residual as ok (no residual to lie about)', () => {
  for (const empty of ['', '   ', '\n\t', undefined, null]) {
    const r = checkResidualHonesty(empty);
    assert.equal(r.ok, true, `expected ${JSON.stringify(empty)} to be ok`);
    assert.deepEqual(r.violations, []);
  }
});

test('checkResidualHonesty uses word boundaries — "collateral" does not trip "later"', () => {
  const r = checkResidualHonesty('Collateral cache invalidation is possible under load.');
  assert.equal(r.ok, true);
  assert.deepEqual(r.violations, []);
});

test('checkResidualHonesty reports multiple distinct offending phrases', () => {
  const r = checkResidualHonesty('The upload is handled safely; SSRF path is future work.');
  assert.equal(r.ok, false);
  assert.ok(r.violations.some((v) => v.includes('handled safely')));
  assert.ok(r.violations.some((v) => v.includes('future work')));
});

// ---------------------------------------------------------------------------
// requireCitedEvidence
// ---------------------------------------------------------------------------

const CITATION_VIOLATION = 'false-positive/safe verdict requires a file:line citation';

test('requireCitedEvidence: FP-class verdict without a citation is rejected', () => {
  for (const verdict of ['false-positive', 'provably-safe', 'FALSE_POSITIVE', 'safe']) {
    const r = requireCitedEvidence(verdict, []);
    assert.equal(r.ok, false, `expected "${verdict}" to require a citation`);
    assert.deepEqual(r.violations, [CITATION_VIOLATION]);
  }
});

test('requireCitedEvidence: FP verdict with a string file:line citation is accepted', () => {
  const r = requireCitedEvidence('false-positive', ['src/app.js:42']);
  assert.equal(r.ok, true);
  assert.deepEqual(r.violations, []);
});

test('requireCitedEvidence: FP verdict with an object {location} citation is accepted', () => {
  const r = requireCitedEvidence('provably-safe', [{ location: 'handlers/auth.ts:118' }]);
  assert.equal(r.ok, true);
  assert.deepEqual(r.violations, []);
});

test('requireCitedEvidence: evidence present but not citation-shaped is rejected', () => {
  const r = requireCitedEvidence('safe', ['reviewed by hand', { note: 'looks fine' }]);
  assert.equal(r.ok, false);
  assert.deepEqual(r.violations, [CITATION_VIOLATION]);
});

test('requireCitedEvidence: missing / null evidence is rejected for FP verdict', () => {
  assert.equal(requireCitedEvidence('safe', null).ok, false);
  assert.equal(requireCitedEvidence('safe', undefined).ok, false);
});

test('requireCitedEvidence: non-FP verdicts pass without any citation', () => {
  for (const verdict of ['confirmed', 'true-positive', 'needs-review', 'unsafe', '', null, undefined]) {
    const r = requireCitedEvidence(verdict, []);
    assert.equal(r.ok, true, `expected "${verdict}" to not require a citation`);
    assert.deepEqual(r.violations, []);
  }
});

// ---------------------------------------------------------------------------
// computeFixTier
// ---------------------------------------------------------------------------

const THREE = { sinkSignatureChanged: true, allCallersRouted: true, testDiscriminates: true };

test('computeFixTier: all three signals true and no downgrades => FULL', () => {
  assert.equal(computeFixTier({ ...THREE }), 'FULL');
});

test('computeFixTier: partialSanitization forces MITIGATION even with all three true', () => {
  assert.equal(computeFixTier({ ...THREE, partialSanitization: true }), 'MITIGATION');
});

test('computeFixTier: missing any of the three signals => MITIGATION', () => {
  assert.equal(computeFixTier({ ...THREE, sinkSignatureChanged: false }), 'MITIGATION');
  assert.equal(computeFixTier({ ...THREE, allCallersRouted: false }), 'MITIGATION');
  assert.equal(computeFixTier({ ...THREE, testDiscriminates: false }), 'MITIGATION');
});

test('computeFixTier: any workaround-only flag => WORKAROUND (wins over everything)', () => {
  assert.equal(computeFixTier({ ...THREE, rateLimitOnly: true }), 'WORKAROUND');
  assert.equal(computeFixTier({ ...THREE, docsOnly: true }), 'WORKAROUND');
  assert.equal(computeFixTier({ ...THREE, logOnlyNoReject: true }), 'WORKAROUND');
  // workaround beats partialSanitization too
  assert.equal(computeFixTier({ ...THREE, partialSanitization: true, docsOnly: true }), 'WORKAROUND');
});

test('computeFixTier: conservative default for empty / missing signals => MITIGATION', () => {
  assert.equal(computeFixTier({}), 'MITIGATION');
  assert.equal(computeFixTier(null), 'MITIGATION');
  assert.equal(computeFixTier(undefined), 'MITIGATION');
});

// ---------------------------------------------------------------------------
// gateFixOutput (composition)
// ---------------------------------------------------------------------------

test('gateFixOutput: clean FULL fix with no residual passes', () => {
  const r = gateFixOutput({
    residual: '',
    verdict: 'confirmed',
    evidence: [],
    signals: { ...THREE },
  });
  assert.equal(r.tier, 'FULL');
  assert.equal(r.ok, true);
  assert.deepEqual(r.violations, []);
});

test('gateFixOutput: FULL tier carrying a residual is a contradiction', () => {
  const r = gateFixOutput({
    residual: 'Race window remains between check and write.',
    verdict: 'confirmed',
    evidence: [],
    signals: { ...THREE },
  });
  assert.equal(r.tier, 'FULL');
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes('FULL tier cannot carry a residual'));
});

test('gateFixOutput: non-FULL tier without a residual is a contradiction', () => {
  const r = gateFixOutput({
    residual: '',
    verdict: 'confirmed',
    evidence: [],
    signals: { ...THREE, partialSanitization: true },
  });
  assert.equal(r.tier, 'MITIGATION');
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes('non-FULL tier must document a residual'));
});

test('gateFixOutput: clean MITIGATION with an honest documented residual passes', () => {
  const r = gateFixOutput({
    residual: 'Rate-limit only slows brute force; a distributed attacker can still enumerate.',
    verdict: 'confirmed',
    evidence: [],
    signals: { ...THREE, testDiscriminates: false },
  });
  assert.equal(r.tier, 'MITIGATION');
  assert.equal(r.ok, true);
  assert.deepEqual(r.violations, []);
});

test('gateFixOutput: composes the evidence-citation gate', () => {
  const r = gateFixOutput({
    residual: '',
    verdict: 'false-positive',
    evidence: [],
    signals: { ...THREE },
  });
  assert.equal(r.tier, 'FULL');
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes(CITATION_VIOLATION));
});

test('gateFixOutput: concatenates residual-honesty and tier-contradiction violations', () => {
  const r = gateFixOutput({
    residual: 'tbd',
    verdict: 'confirmed',
    evidence: [],
    signals: { ...THREE },
  });
  assert.equal(r.tier, 'FULL');
  assert.equal(r.ok, false);
  assert.ok(r.violations.some((v) => v.toLowerCase().includes('tbd')));
  assert.ok(r.violations.includes('FULL tier cannot carry a residual'));
});

test('gateFixOutput: never throws on missing / empty argument', () => {
  assert.doesNotThrow(() => gateFixOutput());
  assert.doesNotThrow(() => gateFixOutput({}));
});
