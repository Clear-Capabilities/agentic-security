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

// --- corpus population ----------------------------------------------------
//
// The hole these close, found by adversarial review of a green gate: the
// version check alone let a scorecard reporting 200 corpus entries pass while
// the corpus held 210. Entries had been added without a version bump, so
// nothing noticed. Every corpus rate is computed over that population, so the
// published denominators described a corpus that no longer existed.

const withCorpus = (total, extra = {}) => baseInputs({
  scorecardJson: {
    provenance: { engineVersion: '1.2.3', bundleSha256: 'abc123' },
    corpus: { totalEntries: total, scoredEntries: total, notScored: [] },
  },
  ...extra,
});

test('scorecard-gate — corpus grew since the scorecard was measured → FAIL', () => {
  const r = evaluateScorecardFreshness({ ...withCorpus(200), actualCorpusEntries: 210 });
  assert.equal(r.ok, false, 'a scorecard measured over a different population must not publish');
  assert.ok(r.errors.some(e => /200 corpus entries, but 210/.test(e)), r.errors.join('; '));
});

test('scorecard-gate — corpus shrank since the scorecard was measured → FAIL', () => {
  // Entries deleted without re-measuring is the same defect in the other
  // direction, and it inflates every rate rather than deflating it.
  const r = evaluateScorecardFreshness({ ...withCorpus(210), actualCorpusEntries: 200 });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /210 corpus entries, but 200/.test(e)));
});

test('scorecard-gate — corpus population matches → pass', () => {
  const r = evaluateScorecardFreshness({ ...withCorpus(210), actualCorpusEntries: 210 });
  assert.equal(r.ok, true, r.errors.join('; '));
});

test('scorecard-gate — uncountable corpus skips the check rather than guessing', () => {
  // A wrong guess would either block every release or silently pass, and both
  // are worse than declining to check.
  const r = evaluateScorecardFreshness({ ...withCorpus(200), actualCorpusEntries: null });
  assert.equal(r.ok, true);
});

test('scorecard-gate — a scorecard with no corpus section is not failed by this check', () => {
  const r = evaluateScorecardFreshness({ ...baseInputs(), actualCorpusEntries: 210 });
  assert.equal(r.ok, true);
});
