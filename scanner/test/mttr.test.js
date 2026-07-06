// 0.8.0 Feat-11: MTTR / finding-age tracking tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { stampFindingTimestamps, buildBaselineMap, findingsExceedingSLA, computeMTTR, renderSlaSummary } from '../src/posture/mttr.js';

test('MTTR — first scan stamps firstSeenAt = lastSeenAt = now and ageDays = 0', () => {
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10 }];
  const now = Date.parse('2026-01-01T00:00:00Z');
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].firstSeenAt, '2026-01-01T00:00:00.000Z');
  assert.equal(findings[0].lastSeenAt,  '2026-01-01T00:00:00.000Z');
  assert.equal(findings[0].ageDays, 0);
});

test('MTTR — second scan preserves firstSeenAt from baseline', () => {
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10 }];
  const baseline = { findings: [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10, firstSeenAt: '2026-01-01T00:00:00.000Z' }] };
  const now = Date.parse('2026-02-15T00:00:00Z');
  stampFindingTimestamps(findings, buildBaselineMap(baseline), now);
  assert.equal(findings[0].firstSeenAt, '2026-01-01T00:00:00.000Z');
  assert.equal(findings[0].lastSeenAt,  '2026-02-15T00:00:00.000Z');
  assert.equal(findings[0].ageDays, 45);
});

test('MTTR — findingsExceedingSLA flags an old high-severity finding', () => {
  const findings = [
    { severity: 'high',     ageDays: 20 }, // under 30-day SLA → not flagged
    { severity: 'high',     ageDays: 45 }, // over → flagged
    { severity: 'critical', ageDays: 10 }, // over 7-day SLA → flagged
    { severity: 'low',      ageDays: 80 }, // under 90 → not flagged
  ];
  const flagged = findingsExceedingSLA(findings);
  assert.equal(flagged.length, 2);
});

test('MTTR — computeMTTR returns mean/median for fixed findings', () => {
  const removed = [
    { severity: 'high', firstSeenAt: '2026-01-01', lastSeenAt: '2026-01-11' }, // 10 days
    { severity: 'high', firstSeenAt: '2026-01-01', lastSeenAt: '2026-01-21' }, // 20 days
    { severity: 'low',  firstSeenAt: '2026-01-01', lastSeenAt: '2026-04-01' }, // 90 days
  ];
  const m = computeMTTR(removed);
  assert.equal(m.count, 3);
  assert.equal(Math.round(m.meanDays), 40);
  assert.equal(Math.round(m.medianDays), 20);
  assert.equal(m.perSeverity.high.count, 2);
  assert.equal(m.perSeverity.high.meanDays, 15);
});

test('renderSlaSummary (#10): flags findings past SLA with per-severity counts + median age', () => {
  const findings = [
    { severity: 'critical', ageDays: 10 }, // > 7d critical SLA → breach
    { severity: 'high', ageDays: 40 },     // > 30d high SLA → breach
    { severity: 'high', ageDays: 5 },      // within SLA
    { severity: 'low', ageDays: 1 },       // within SLA
  ];
  const s = renderSlaSummary(findings);
  assert.match(s, /2 finding\(s\) past remediation SLA/);
  assert.match(s, /1 critical/);
  assert.match(s, /1 high/);
  assert.match(s, /median open age/);
});

test('renderSlaSummary: null when nothing is past SLA', () => {
  assert.equal(renderSlaSummary([{ severity: 'high', ageDays: 5 }]), null);
  assert.equal(renderSlaSummary([]), null);
});
