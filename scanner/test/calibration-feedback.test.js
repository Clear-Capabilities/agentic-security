// FR-806 (assurance-hardening PRD): "Validate model calibration against
// accepted and realized incidents where customers opt in | Calibration
// reports are aggregated and privacy-preserving."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  recordCalibrationFeedback, loadCalibrationFeedback, buildCalibrationReport,
  renderCalibrationReportSummary, CALIBRATION_FEEDBACK_FILE, OUTCOMES, _internals,
} from '../src/posture/calibration-feedback.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'scanner', 'bin', 'agentic-security.js');
const { RELIABLE_N } = _internals;

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: path.join(REPO_ROOT, 'scanner'), encoding: 'utf8', timeout: 30_000 });
}

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'calibration-feedback-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function writeLastScan(dir, findings) {
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings }));
}

// ── recordCalibrationFeedback ────────────────────────────────────────────

test('recordCalibrationFeedback: requires findingId and a valid outcome', async () => {
  const s = await mkSession();
  try {
    assert.equal(recordCalibrationFeedback(s.dir, { outcome: 'accepted-risk' }).ok, false);
    assert.equal(recordCalibrationFeedback(s.dir, { findingId: 'f1', outcome: 'not-a-real-outcome' }).ok, false);
  } finally { await s.cleanup(); }
});

test('recordCalibrationFeedback: snapshots the finding\'s OWN prediction signals, never file/line/vuln text', async () => {
  const s = await mkSession();
  try {
    // A real finding's own `.id` embeds the file path and line -- using a
    // neutral id here (e.g. 'f1') would let a findingId leak pass silently,
    // since the confound is exactly "the incidental identifier happens to be
    // safe already." Use the real, path-shaped id format.
    const realId = 'client-side:DANGEROUS_INNERHTML:secret/path.js:42';
    writeLastScan(s.dir, [{ id: realId, stableId: 'abc123stable', file: 'secret/path.js', line: 42, vuln: 'SQL Injection', severity: 'high', confidence: 0.85, confidenceTier: 'high', riskDollars: { ev: 12345 } }]);
    const r = recordCalibrationFeedback(s.dir, { findingId: realId, outcome: 'accepted-risk', note: 'reviewed, low risk in practice' });
    assert.equal(r.ok, true);
    assert.equal(r.record.predictedConfidence, 0.85);
    assert.equal(r.record.predictedConfidenceTier, 'high');
    assert.equal(r.record.predictedSeverity, 'high');
    assert.equal(r.record.predictedRiskEv, 12345);
    assert.ok(!('file' in r.record), 'must never persist the finding\'s file path');
    assert.ok(!('vuln' in r.record), 'must never persist the finding\'s vuln title');
    assert.ok(!('line' in r.record), 'must never persist the finding\'s line number');
    // FR-806 fix: the persisted findingId itself must not be the raw,
    // path-embedding .id -- it must be swapped for the finding's privacy-safe
    // stableId.
    assert.equal(r.record.findingId, 'abc123stable');
    assert.notEqual(r.record.findingId, realId);
    assert.ok(!r.record.findingId.includes('secret/path.js'), 'the persisted findingId must not contain the real file path');
  } finally { await s.cleanup(); }
});

test('recordCalibrationFeedback (FR-806 fix): a path-embedding findingId with NO matching finding is hashed before persisting, never written raw', async () => {
  const s = await mkSession();
  try {
    // No last-scan.json at all -- _findFinding returns null, so there is no
    // stableId to substitute. The raw input must still never reach disk.
    const realId = 'client-side:DANGEROUS_INNERHTML:src/very/secret/internal-billing-controller.js:142';
    const r = recordCalibrationFeedback(s.dir, { findingId: realId, outcome: 'accepted-risk' });
    assert.equal(r.ok, true);
    assert.notEqual(r.record.findingId, realId);
    assert.ok(!r.record.findingId.includes('internal-billing-controller'), 'the persisted findingId must never contain the real file path, even when no matching finding is found');
    assert.match(r.record.findingId, /^[0-9a-f]{16}$/, 'falls back to a real hash, not a truncated/mangled copy of the input');

    const raw = fs.readFileSync(path.join(s.dir, '.agentic-security', CALIBRATION_FEEDBACK_FILE), 'utf8');
    assert.ok(!raw.includes('internal-billing-controller'), 'the file actually written to disk must not contain the real file path either');
  } finally { await s.cleanup(); }
});

test('recordCalibrationFeedback: a finding no longer present in last-scan.json is still recordable, with null predicted signals (not an error)', async () => {
  const s = await mkSession();
  try {
    writeLastScan(s.dir, []); // f1 already fixed/removed
    const r = recordCalibrationFeedback(s.dir, { findingId: 'f1', outcome: 'realized-incident' });
    assert.equal(r.ok, true);
    assert.equal(r.record.predictedConfidence, null);
  } finally { await s.cleanup(); }
});

test('recordCalibrationFeedback: notes are truncated to 280 chars', async () => {
  const s = await mkSession();
  try {
    const r = recordCalibrationFeedback(s.dir, { findingId: 'f1', outcome: 'accepted-risk', note: 'x'.repeat(500) });
    assert.equal(r.record.note.length, 280);
  } finally { await s.cleanup(); }
});

// ── loadCalibrationFeedback ───────────────────────────────────────────────

test('loadCalibrationFeedback: no file present returns an empty array, never throws', async () => {
  const s = await mkSession();
  try { assert.deepEqual(loadCalibrationFeedback(s.dir), []); } finally { await s.cleanup(); }
});

test('loadCalibrationFeedback: a torn/malformed line is skipped, well-formed lines survive', async () => {
  const s = await mkSession();
  try {
    const good = JSON.stringify({ at: '2026-08-01T00:00:00Z', findingId: 'f1', outcome: 'accepted-risk' });
    fs.writeFileSync(path.join(s.dir, '.agentic-security', CALIBRATION_FEEDBACK_FILE), good + '\n{truncated-json-lin');
    assert.equal(loadCalibrationFeedback(s.dir).length, 1);
  } finally { await s.cleanup(); }
});

test('loadCalibrationFeedback: a record with an invalid outcome value is dropped', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', CALIBRATION_FEEDBACK_FILE), JSON.stringify({ findingId: 'f1', outcome: 'bogus' }) + '\n');
    assert.equal(loadCalibrationFeedback(s.dir).length, 0);
  } finally { await s.cleanup(); }
});

test('recordCalibrationFeedback + loadCalibrationFeedback round trip: multiple records accumulate (append-only)', async () => {
  const s = await mkSession();
  try {
    recordCalibrationFeedback(s.dir, { findingId: 'f1', outcome: 'accepted-risk' });
    recordCalibrationFeedback(s.dir, { findingId: 'f2', outcome: 'realized-incident' });
    assert.equal(loadCalibrationFeedback(s.dir).length, 2);
  } finally { await s.cleanup(); }
});

// ── buildCalibrationReport / renderCalibrationReportSummary ─────────────

test('buildCalibrationReport: zero events -> totalEvents 0, both buckets empty, possibleMiscalibration null', async () => {
  const s = await mkSession();
  try {
    const r = buildCalibrationReport(s.dir);
    assert.equal(r.totalEvents, 0);
    assert.equal(r.acceptedRisk.n, 0);
    assert.equal(r.realizedIncident.n, 0);
    assert.equal(r.possibleMiscalibration, null);
  } finally { await s.cleanup(); }
});

test('buildCalibrationReport: below RELIABLE_N in either bucket -> possibleMiscalibration stays null (not enough samples to say anything)', async () => {
  const s = await mkSession();
  try {
    writeLastScan(s.dir, [{ id: 'f1', confidence: 0.9 }]);
    recordCalibrationFeedback(s.dir, { findingId: 'f1', outcome: 'accepted-risk' });
    recordCalibrationFeedback(s.dir, { findingId: 'f1', outcome: 'realized-incident' });
    const r = buildCalibrationReport(s.dir);
    assert.equal(r.possibleMiscalibration, null);
  } finally { await s.cleanup(); }
});

test('buildCalibrationReport: well-calibrated data (realized-incident avg confidence > accepted-risk avg) -> possibleMiscalibration false', async () => {
  const s = await mkSession();
  try {
    for (let i = 0; i < RELIABLE_N; i++) {
      writeLastScan(s.dir, [{ id: `low${i}`, confidence: 0.2 }]);
      recordCalibrationFeedback(s.dir, { findingId: `low${i}`, outcome: 'accepted-risk' });
      writeLastScan(s.dir, [{ id: `high${i}`, confidence: 0.9 }]);
      recordCalibrationFeedback(s.dir, { findingId: `high${i}`, outcome: 'realized-incident' });
    }
    const r = buildCalibrationReport(s.dir);
    assert.equal(r.acceptedRisk.reliable, true);
    assert.equal(r.realizedIncident.reliable, true);
    assert.equal(r.possibleMiscalibration, false);
  } finally { await s.cleanup(); }
});

test('buildCalibrationReport: miscalibrated data (realized-incident avg confidence <= accepted-risk avg) -> possibleMiscalibration true', async () => {
  const s = await mkSession();
  try {
    for (let i = 0; i < RELIABLE_N; i++) {
      writeLastScan(s.dir, [{ id: `hi${i}`, confidence: 0.9 }]);
      recordCalibrationFeedback(s.dir, { findingId: `hi${i}`, outcome: 'accepted-risk' });
      writeLastScan(s.dir, [{ id: `lo${i}`, confidence: 0.2 }]);
      recordCalibrationFeedback(s.dir, { findingId: `lo${i}`, outcome: 'realized-incident' });
    }
    const r = buildCalibrationReport(s.dir);
    assert.equal(r.possibleMiscalibration, true);
  } finally { await s.cleanup(); }
});

test('renderCalibrationReportSummary: null when nothing was ever recorded (the expected default state for almost every project)', () => {
  assert.equal(renderCalibrationReportSummary({ totalEvents: 0 }), null);
  assert.equal(renderCalibrationReportSummary(null), null);
});

test('renderCalibrationReportSummary: populated when data exists, names both buckets', async () => {
  const s = await mkSession();
  try {
    writeLastScan(s.dir, [{ id: 'f1', confidence: 0.5 }]);
    recordCalibrationFeedback(s.dir, { findingId: 'f1', outcome: 'accepted-risk' });
    const report = buildCalibrationReport(s.dir);
    const summary = renderCalibrationReportSummary(report);
    assert.match(summary, /accepted-risk/);
    assert.match(summary, /realized-incident/);
  } finally { await s.cleanup(); }
});

// ── real CLI ──────────────────────────────────────────────────────────────

test('calibration-feedback record (real CLI): validates required flags', async () => {
  const s = await mkSession();
  try {
    const r = run(['calibration-feedback', 'record', '--finding-id', 'f1', '--root', s.dir]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /--outcome must be one of/);
  } finally { await s.cleanup(); }
});

test('calibration-feedback record (real CLI): a valid record succeeds and is readable back', async () => {
  const s = await mkSession();
  try {
    writeLastScan(s.dir, [{ id: 'f1', severity: 'critical', confidence: 0.95 }]);
    const r = run(['calibration-feedback', 'record', '--finding-id', 'f1', '--outcome', 'realized-incident', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Recorded "realized-incident" for finding f1/);
    const events = loadCalibrationFeedback(s.dir);
    assert.equal(events.length, 1);
    assert.equal(events[0].predictedSeverity, 'critical');
  } finally { await s.cleanup(); }
});

test('calibration-report (real CLI): reports "no data" honestly when nothing was ever recorded', async () => {
  const s = await mkSession();
  try {
    const r = run(['calibration-report', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /No calibration feedback recorded yet/);
  } finally { await s.cleanup(); }
});

test('calibration-report --format json (real CLI): emits a valid, parseable report', async () => {
  const s = await mkSession();
  try {
    writeLastScan(s.dir, [{ id: 'f1', confidence: 0.5 }]);
    run(['calibration-feedback', 'record', '--finding-id', 'f1', '--outcome', 'accepted-risk', '--root', s.dir]);
    const r = run(['calibration-report', '--format', 'json', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.totalEvents, 1);
  } finally { await s.cleanup(); }
});

test('calibration-feedback.jsonl is never deleted by a plain reset (it is operator-config, real ground truth)', async () => {
  const s = await mkSession();
  try {
    writeLastScan(s.dir, [{ id: 'f1', confidence: 0.5 }]);
    run(['calibration-feedback', 'record', '--finding-id', 'f1', '--outcome', 'accepted-risk', '--root', s.dir]);
    const r = run(['reset', '--yes', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(path.join(s.dir, '.agentic-security', CALIBRATION_FEEDBACK_FILE)), 'calibration ground truth must never be wiped by reset');
  } finally { await s.cleanup(); }
});
