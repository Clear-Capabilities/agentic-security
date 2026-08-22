// Gate for the calibration-holdout release check (PRD F7.4).
//
// The confidence number on every finding is a claim about how often the engine
// is right, and nothing verified that claim before a release. The trap in this
// item is that two obvious wirings both produce a check that passes forever:
//
//   calibration-drift.js  — reads per-project triage feedback, which does not
//                           exist at release time; returns no-feedback-data.
//   calibration-seed.json — FITTING data. Measuring ECE against the labels the
//                           table was fitted on is the error CLAUDE.md forbids.
//
// So the check fails by default and is waivable only with a dated, reasoned
// entry that expires — the `.dependency-holds.json` pattern, for the same
// reason: "temporarily unverified" must not become permanent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runCalibrationHoldoutCheck } from '../../scripts/calibration-holdout-check.mjs';

function repoWith(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'calib-'));
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(d, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return d;
}

const GOOD_WAIVER = {
  reason: 'No held-out labelled set exists yet; producing one is corpus-construction work rather than a code change, and the seed is fitting data.',
  reviewBy: '2099-01-01',
};

test('no held-out set and no waiver FAILS — unverified is not calibrated', () => {
  const r = runCalibrationHoldoutCheck(repoWith({}));
  assert.equal(r.ok, false);
  assert.match(r.detail, /UNVERIFIED/);
});

test('a dated waiver passes but still warns loudly', () => {
  const repo = repoWith({ '.calibration-waiver.json': JSON.stringify(GOOD_WAIVER) });
  const r = runCalibrationHoldoutCheck(repo);
  assert.equal(r.ok, true);
  assert.ok(r.warnings && r.warnings.length, 'a waiver must not pass silently');
  assert.match(r.warnings[0], /not evidence/);
});

test('an EXPIRED waiver fails', () => {
  // The anti-rot rule. Without it the waiver is permanent.
  const repo = repoWith({ '.calibration-waiver.json': JSON.stringify({ ...GOOD_WAIVER, reviewBy: '2020-01-01' }) });
  const r = runCalibrationHoldoutCheck(repo);
  assert.equal(r.ok, false);
  assert.match(r.detail, /expired/);
});

test('a waiver with no reviewBy fails', () => {
  const repo = repoWith({ '.calibration-waiver.json': JSON.stringify({ reason: GOOD_WAIVER.reason }) });
  assert.equal(runCalibrationHoldoutCheck(repo).ok, false);
});

test('a waiver with a token reason fails', () => {
  // A reason nobody can evaluate is indistinguishable from an oversight.
  const repo = repoWith({ '.calibration-waiver.json': JSON.stringify({ reason: 'later', reviewBy: '2099-01-01' }) });
  const r = runCalibrationHoldoutCheck(repo);
  assert.equal(r.ok, false);
  assert.match(r.detail, /real reason/);
});

test('the repo waiver is currently valid and has not expired', () => {
  // Guards the committed waiver itself, so the release gate cannot start
  // failing at an unrelated moment without someone having been told why.
  const repo = path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..');
  const r = runCalibrationHoldoutCheck(repo);
  assert.equal(r.ok, true, `the committed calibration waiver is not valid: ${r.detail}`);
});

test('a present-but-empty held-out set fails rather than passing vacuously', () => {
  // An empty file is the shape a half-finished corpus takes. It must not read
  // as "measured and fine".
  const repo = repoWith({
    '.calibration-waiver.json': JSON.stringify(GOOD_WAIVER),
    'bench/calibration-holdout/labels.jsonl': '   ',
  });
  const r = runCalibrationHoldoutCheck(repo);
  assert.equal(r.ok, false, 'an empty held-out set must not pass');
});
