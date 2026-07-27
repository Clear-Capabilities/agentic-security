// Release gate: the committed accuracy scorecard must describe the current
// version. See scripts/scorecard-check.mjs for the full design rationale
// (why this CHECKS rather than regenerates, and why the bundle SHA is a
// warning not a failure).
//
// Tested against the exported decision function rather than shelling out —
// the shell-out path (npm run scorecard:check) is proven separately, once,
// by hand in the release report; these tests exercise the pure decision
// logic on constructed inputs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateScorecardFreshness } from '../../scripts/scorecard-check.mjs';

function baseInputs(overrides = {}) {
  return {
    pkgVersion: '1.2.3',
    scorecardJson: { provenance: { engineVersion: '1.2.3', bundleSha256: 'abc123' } },
    scorecardMdPresent: true,
    currentBundleSha256: 'abc123',
    ...overrides,
  };
}

test('scorecard-gate — version match, bundle match → pass, no warnings', () => {
  const r = evaluateScorecardFreshness(baseInputs());
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
});

test('scorecard-gate — version mismatch → fail with remedy message', () => {
  const r = evaluateScorecardFreshness(baseInputs({
    scorecardJson: { provenance: { engineVersion: '1.2.2', bundleSha256: 'abc123' } },
  }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /1\.2\.2/.test(e) && /1\.2\.3/.test(e)));
  assert.ok(r.errors.some(e => /npm run scorecard/.test(e)));
});

test('scorecard-gate — missing scorecard.json → fail', () => {
  const r = evaluateScorecardFreshness(baseInputs({ scorecardJson: null }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /scorecard\.json/.test(e)));
  assert.ok(r.errors.some(e => /npm run scorecard/.test(e)));
});

test('scorecard-gate — unparseable scorecard.json (no provenance) → fail', () => {
  const r = evaluateScorecardFreshness(baseInputs({ scorecardJson: { notProvenance: true } }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /provenance/.test(e) || /engineVersion/.test(e)));
});

test('scorecard-gate — missing SCORECARD.md → fail', () => {
  const r = evaluateScorecardFreshness(baseInputs({ scorecardMdPresent: false }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /SCORECARD\.md/.test(e)));
});

test('scorecard-gate — bundle SHA mismatch alone → still passes, warning only', () => {
  const r = evaluateScorecardFreshness(baseInputs({ currentBundleSha256: 'different-sha' }));
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
  assert.equal(r.warnings.length, 1);
  assert.ok(/bundle/i.test(r.warnings[0]));
});

test('scorecard-gate — bundle unbuilt (no dist) → does not warn or fail on that basis', () => {
  const r = evaluateScorecardFreshness(baseInputs({ currentBundleSha256: null }));
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings, []);
});
