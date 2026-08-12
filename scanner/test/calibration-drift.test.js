// FR-LEARN-9 — Stage 2 measurement-completeness audit.
//
// computeDrift's required fields (reportedConfidence, verdict values, and
// the timestamp field name it filtered the rolling window on) didn't match
// what the ONLY real production writer (commands/triage.md's Step 2)
// actually persists to triage-feedback.json: that script writes `at`, not
// `ts`; verdicts are 'tp'|'fp'|'wontfix', not 'tp'|'fp'|'wai'; and
// reportedConfidence was never written at all. Every real entry was
// silently filtered out before ever reaching byFamily, so the drift alarm
// could never fire against real data regardless of how badly a family's
// calibration had drifted — even though it runs on every scan
// (engine.js's _v3.calibrationDrift) and looks fully wired.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { computeDrift } from '../src/posture/calibration-drift.js';
import { safeWriteState } from '../src/posture/state-dir.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-drift-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"drift-test"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

// Matches commands/triage.md Step 2's real write shape exactly.
function realEntry({ family, verdict, reportedConfidence, at }) {
  return {
    stableId: 'stable-x', verdict, reason: '',
    family, file: 'a.js', line: 1, vuln: 'SQL Injection',
    sinkSnippet: '', reportedConfidence, at,
  };
}

test('computeDrift fires an alarm against real-shaped triage-feedback.json data (matches the real producer)', async () => {
  const p = await mkProject();
  try {
    const now = new Date();
    const entries = [];
    // 20 entries for one family: engine reported ~0.85 confidence, but the
    // realized TP rate is only 2/20 = 0.10 — severe overconfidence.
    for (let i = 0; i < 18; i++) {
      entries.push(realEntry({ family: 'sql-injection', verdict: 'fp', reportedConfidence: 0.85, at: now.toISOString() }));
    }
    for (let i = 0; i < 2; i++) {
      entries.push(realEntry({ family: 'sql-injection', verdict: 'tp', reportedConfidence: 0.85, at: now.toISOString() }));
    }
    safeWriteState(path.join(p.dir, '.agentic-security', 'triage-feedback.json'), JSON.stringify({ entries }));
    const r = computeDrift(p.dir);
    assert.equal(r.alarms.length, 1, `expected one drift alarm, got: ${JSON.stringify(r)}`);
    assert.equal(r.alarms[0].family, 'sql-injection');
    assert.equal(r.alarms[0].sampleSize, 20);
    assert.ok(r.alarms[0].reportedAccuracy > r.alarms[0].realizedAccuracy,
      'the scanner reported far higher confidence than the realized TP rate');
  } finally { await p.cleanup(); }
});

test('computeDrift does not alarm when reported and realized accuracy agree', async () => {
  const p = await mkProject();
  try {
    const now = new Date();
    const entries = [];
    for (let i = 0; i < 8; i++) entries.push(realEntry({ family: 'xss', verdict: 'tp', reportedConfidence: 0.8, at: now.toISOString() }));
    for (let i = 0; i < 2; i++) entries.push(realEntry({ family: 'xss', verdict: 'fp', reportedConfidence: 0.8, at: now.toISOString() }));
    safeWriteState(path.join(p.dir, '.agentic-security', 'triage-feedback.json'), JSON.stringify({ entries }));
    const r = computeDrift(p.dir);
    assert.equal(r.alarms.length, 0, `expected no alarm (0.8 reported ≈ 0.8 realized), got: ${JSON.stringify(r)}`);
  } finally { await p.cleanup(); }
});

test('computeDrift respects the rolling window — stale entries outside windowDays do not count', async () => {
  const p = await mkProject();
  try {
    const stale = new Date(Date.now() - 400 * 86_400_000).toISOString(); // >30d default window
    const entries = Array.from({ length: 15 }, () => realEntry({ family: 'idor', verdict: 'fp', reportedConfidence: 0.9, at: stale }));
    safeWriteState(path.join(p.dir, '.agentic-security', 'triage-feedback.json'), JSON.stringify({ entries }));
    const r = computeDrift(p.dir);
    assert.equal(r.alarms.length, 0, 'stale entries outside the rolling window must not contribute');
  } finally { await p.cleanup(); }
});
