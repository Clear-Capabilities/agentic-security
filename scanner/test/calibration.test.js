// Calibrated confidence tests (P1.3 / FR-UX-1, FR-UX-2).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  wilsonInterval,
  brierScore,
  buildCalibrationTable,
  annotateCalibratedConfidence,
  computeBrierOnHeldOut,
  loadCalibrationHistory,
  _internals,
} from '../src/posture/calibration.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'calib-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"calib-test"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function writeTriage(dir, { findings, transitions }) {
  const stateDir = path.join(dir, '.agentic-security');
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(
    path.join(stateDir, 'triage.json'),
    JSON.stringify({ findings, transitions }, null, 2)
  );
}

test('wilsonInterval is symmetric around 0.5 with large N', () => {
  const [lo, hi] = wilsonInterval(500, 1000);
  assert.ok(Math.abs((lo + hi) / 2 - 0.5) < 0.005);
  assert.ok(hi - lo < 0.07);
});

test('wilsonInterval is wide on small N', () => {
  const [lo, hi] = wilsonInterval(1, 3);
  // n=3 → CI width should be > 0.4; we're not pretending to know the rate
  assert.ok(hi - lo > 0.4);
});

test('wilsonInterval handles 0 and 1 without NaN', () => {
  const [lo0, hi0] = wilsonInterval(0, 10);
  assert.equal(lo0, 0);
  assert.ok(hi0 > 0 && hi0 < 0.4);
  const [lo1, hi1] = wilsonInterval(10, 10);
  // hi1 should be ≥ 0.999 (might be 1 - 1e-16 due to FP).
  assert.ok(hi1 >= 0.999);
  assert.ok(lo1 > 0.6);
});

test('wilsonInterval returns [0,1] for n=0 (no data)', () => {
  assert.deepEqual(wilsonInterval(0, 0), [0, 1]);
});

test('brierScore = 0 for perfect predictions', () => {
  const s = [
    { prediction: 1, actual: 1 },
    { prediction: 0, actual: 0 },
    { prediction: 0.5, actual: 0.5 },
  ];
  assert.equal(brierScore(s), 0);
});

test('brierScore = 1 for always-wrong predictions', () => {
  const s = [{ prediction: 1, actual: 0 }, { prediction: 0, actual: 1 }];
  assert.equal(brierScore(s), 1);
});

test('brierScore returns null for empty input', () => {
  assert.equal(brierScore([]), null);
  assert.equal(brierScore(null), null);
});

test('buildCalibrationTable computes rate only when N >= MIN_SAMPLES_FOR_CALIBRATION', () => {
  const history = {
    families: {
      'sql-injection':   { tp: 40, fp: 4 },         // n=44, calibrated
      'rare-vuln':       { tp: 2,  fp: 1 },         // n=3,  null
      'borderline':      { tp: 28, fp: 1 },         // n=29, null (< 30)
      'just-enough':     { tp: 25, fp: 5 },         // n=30, calibrated
    },
  };
  const t = buildCalibrationTable(history);
  assert.ok(t['sql-injection'].calibrated > 0.9);
  assert.equal(t['rare-vuln'].calibrated, null);
  assert.equal(t['borderline'].calibrated, null);
  assert.ok(typeof t['just-enough'].calibrated === 'number');
  assert.equal(t['just-enough'].n, 30);
});

test('annotateCalibratedConfidence sets fields on findings', () => {
  const history = {
    families: { 'sql-injection': { tp: 40, fp: 4 } },
  };
  const findings = [
    { family: 'sql-injection', vuln: 'X' },
    { family: 'unmapped', vuln: 'Y' },
    { vuln: 'Z' },
  ];
  annotateCalibratedConfidence(findings, { history });
  assert.ok(findings[0].calibrated_confidence > 0.85);
  assert.ok(findings[0].calibrated_confidence_ci.length === 2);
  assert.equal(findings[0].calibrated_n, 44);
  assert.equal(findings[1].calibrated_confidence, null);
  assert.equal(findings[1].calibration_reason, 'no-history');
  assert.equal(findings[2].calibration_reason, 'no-family');
});

test('annotateCalibratedConfidence flags insufficient-samples when N < min', () => {
  const history = { families: { 'sql-injection': { tp: 5, fp: 0 } } };
  const findings = [{ family: 'sql-injection' }];
  annotateCalibratedConfidence(findings, { history });
  assert.equal(findings[0].calibrated_confidence, null);
  assert.equal(findings[0].calibration_reason, 'insufficient-samples');
  assert.equal(findings[0].calibrated_n, 5);
});

test('annotateCalibratedConfidence does not throw on null input', () => {
  assert.doesNotThrow(() => annotateCalibratedConfidence(null));
  assert.doesNotThrow(() => annotateCalibratedConfidence([null, undefined, 'string', 42]));
});

test('computeBrierOnHeldOut returns null for empty', () => {
  const r = computeBrierOnHeldOut([]);
  assert.equal(r.brier, null);
});
test('computeBrierOnHeldOut scores real predictions vs labels', () => {
  // Perfect predictions → Brier 0.
  const r0 = computeBrierOnHeldOut([
    { family: 'sql', predicted: 1, actual: 1 },
    { family: 'sql', predicted: 0, actual: 0 },
  ]);
  assert.ok(r0.brier !== null && r0.brier < 1e-9);
  // Always-wrong predictions → Brier 1.
  const r1 = computeBrierOnHeldOut([
    { family: 'sql', predicted: 1, actual: 0 },
    { family: 'sql', predicted: 0, actual: 1 },
  ]);
  assert.ok(r1.brier > 0.99);
});

test('seed corpus loads via loadCalibrationHistory + buildCalibrationTable', async () => {
  const { loadCalibrationHistory } = await import('../src/posture/calibration.js');
  const h = loadCalibrationHistory(process.cwd());
  // Seed includes SQL injection with calibrated samples — should be a real number.
  const t = buildCalibrationTable(h);
  assert.ok(t['sql-injection'], 'seed must include sql-injection');
  assert.ok(typeof t['sql-injection'].calibrated === 'number');
});

test('_internals reports the calibration floor', () => {
  assert.equal(_internals.MIN_SAMPLES_FOR_CALIBRATION, 30);
});

// EA-01: loadCalibrationHistory must not count untriaged 'open' findings or
// auto-closed 'fixed' findings (triage.js's syncWithScan sets these with no
// human ever having looked at the finding) as true positives. Only a state a
// human actually chose is a real signal: a manual 'fixed' transition is TP,
// 'false-positive' is FP. 'open', 'in-progress', 'wont-fix', and an
// automatic 'fixed' contribute to neither bucket.
test('EA-01: an untouched open finding is not counted as a true positive', async () => {
  const p = await mkProject();
  try {
    writeTriage(p.dir, {
      findings: {
        'F-1': { id: 'F-1', family: 'made-up-family-xyz', state: 'open' },
      },
      transitions: [{ id: 'F-1', from: null, to: 'open', at: '2026-01-01T00:00:00Z' }],
    });
    const h = loadCalibrationHistory(p.dir);
    const fam = h.families['made-up-family-xyz'];
    assert.equal(fam ? fam.tp : 0, 0, 'an open, untriaged finding must not manufacture a TP');
    assert.equal(buildCalibrationTable(h)['made-up-family-xyz'], undefined,
      'a family with zero real signal must not enter the calibration table');
  } finally { await p.cleanup(); }
});

test('EA-01: an automatically auto-closed finding is not counted as a true positive', async () => {
  const p = await mkProject();
  try {
    writeTriage(p.dir, {
      findings: {
        'F-1': { id: 'F-1', family: 'made-up-family-xyz', state: 'fixed', fixed_at: '2026-01-02T00:00:00Z' },
      },
      transitions: [
        { id: 'F-1', from: null, to: 'open', at: '2026-01-01T00:00:00Z' },
        { id: 'F-1', from: 'open', to: 'fixed', at: '2026-01-02T00:00:00Z', automatic: true },
      ],
    });
    const h = loadCalibrationHistory(p.dir);
    const fam = h.families['made-up-family-xyz'];
    assert.equal(fam ? fam.tp : 0, 0,
      'an auto-closed finding (scanner just stopped seeing it) must not manufacture a TP');
  } finally { await p.cleanup(); }
});

// Stage 2 measurement-completeness audit: a 'fixed' finding with NO
// transition record at all (e.g. imported/migrated triage.json, or any
// write path that updates state without appending a transition) used to
// count as a manual TP by default — the check was `!== true` (absence of
// proof of automatic) rather than `=== false` (positive proof of manual),
// which fails OPEN exactly where this whole mechanism exists to fail
// closed on unproven signal.
test('EA-01: a fixed finding with NO transition record is not counted as a true positive (fails closed, not open)', async () => {
  const p = await mkProject();
  try {
    writeTriage(p.dir, {
      findings: {
        'F-1': { id: 'F-1', family: 'made-up-family-xyz', state: 'fixed', fixed_at: '2026-01-02T00:00:00Z' },
      },
      transitions: [], // no record of how this became "fixed"
    });
    const h = loadCalibrationHistory(p.dir);
    const fam = h.families['made-up-family-xyz'];
    assert.equal(fam ? fam.tp : 0, 0,
      'an untracked "fixed" state must not manufacture a TP absent positive proof of a manual transition');
  } finally { await p.cleanup(); }
});

test('EA-01: a manually-transitioned fixed finding IS counted as a true positive', async () => {
  const p = await mkProject();
  try {
    writeTriage(p.dir, {
      findings: {
        'F-1': { id: 'F-1', family: 'made-up-family-xyz', state: 'fixed', fixed_at: '2026-01-02T00:00:00Z' },
      },
      transitions: [
        { id: 'F-1', from: null, to: 'open', at: '2026-01-01T00:00:00Z' },
        { id: 'F-1', from: 'open', to: 'fixed', at: '2026-01-02T00:00:00Z' },
      ],
    });
    const h = loadCalibrationHistory(p.dir);
    assert.equal(h.families['made-up-family-xyz'].tp, 1);
    assert.equal(h.families['made-up-family-xyz'].fp, 0);
  } finally { await p.cleanup(); }
});

test('EA-01: a false-positive marked finding IS counted as a false positive', async () => {
  const p = await mkProject();
  try {
    writeTriage(p.dir, {
      findings: {
        'F-1': { id: 'F-1', family: 'made-up-family-xyz', state: 'false-positive' },
      },
      transitions: [
        { id: 'F-1', from: null, to: 'open', at: '2026-01-01T00:00:00Z' },
        { id: 'F-1', from: 'open', to: 'false-positive', at: '2026-01-02T00:00:00Z' },
      ],
    });
    const h = loadCalibrationHistory(p.dir);
    assert.equal(h.families['made-up-family-xyz'].tp, 0);
    assert.equal(h.families['made-up-family-xyz'].fp, 1);
  } finally { await p.cleanup(); }
});

test('EA-01: in-progress and wont-fix contribute to neither bucket', async () => {
  const p = await mkProject();
  try {
    writeTriage(p.dir, {
      findings: {
        'F-1': { id: 'F-1', family: 'made-up-family-xyz', state: 'in-progress' },
        'F-2': { id: 'F-2', family: 'made-up-family-xyz', state: 'wont-fix' },
      },
      transitions: [
        { id: 'F-1', from: null, to: 'open', at: '2026-01-01T00:00:00Z' },
        { id: 'F-1', from: 'open', to: 'in-progress', at: '2026-01-02T00:00:00Z' },
        { id: 'F-2', from: null, to: 'open', at: '2026-01-01T00:00:00Z' },
        { id: 'F-2', from: 'open', to: 'wont-fix', at: '2026-01-02T00:00:00Z' },
      ],
    });
    const h = loadCalibrationHistory(p.dir);
    const fam = h.families['made-up-family-xyz'];
    assert.equal(fam ? fam.tp : 0, 0);
    assert.equal(fam ? fam.fp : 0, 0);
  } finally { await p.cleanup(); }
});
