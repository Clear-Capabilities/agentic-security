// 0.8.0 Feat-11: MTTR / finding-age tracking tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stampFindingTimestamps, buildBaselineMap, findingsExceedingSLA, computeMTTR, renderSlaSummary, fingerprintFinding } from '../src/posture/mttr.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../src/posture/provenance/schema.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.resolve(here, '..', 'dist', 'agentic-security.mjs');

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

// S7 (Stage 2 measurement-completeness audit): computeMTTR was fully built
// and unit-tested (above) but had zero real callers anywhere in bin/ or src/
// — the module's own comment calls it "true MTTR," distinct from the open-
// backlog median-age proxy renderSlaSummary already surfaced. The MTTR
// figure users actually saw came from an entirely different code path
// (posture/triage.js's trend()). Wired into cmdScan alongside the existing
// firstSeenAt/lastSeenAt stamping.
test('MTTR wiring: a real CLI scan reports mttr.count=0 with no baseline, then a real fix is measured on the next scan', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-mttr-cli-'));
  try {
    await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"mttr-cli-test"}');
    await fsp.writeFile(path.join(dir, 'app.js'), 'function h(req){ eval(req.body.x); }\n');

    const r1 = spawnSync('node', [cli, 'scan', dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(r1.status <= 3, `first scan must exit <=3; got ${r1.status}: ${r1.stderr}`);
    const scan1 = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
    assert.ok(scan1.mttr, `expected scan.mttr to be present after the first real scan. stderr: ${r1.stderr}`);
    assert.equal(scan1.mttr.count, 0, 'nothing can be "fixed" relative to a nonexistent baseline');

    // Fix it: remove the eval() call entirely.
    await fsp.writeFile(path.join(dir, 'app.js'), 'function h(req){ return 1; }\n');
    const r2 = spawnSync('node', [cli, 'scan', dir, '--format', 'json', '--no-network'], { encoding: 'utf8' });
    assert.ok(r2.status <= 3, `second scan must exit <=3; got ${r2.status}: ${r2.stderr}`);
    const scan2 = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
    assert.ok(scan2.mttr.count >= 1, `expected at least one fixed finding measured, got: ${JSON.stringify(scan2.mttr)}`);
    assert.equal(typeof scan2.mttr.medianDays, 'number');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('ageBasis: finding_origin when findingProvenance resolved complete with an authorDate', async () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'aaa1111', authorDate: '2026-01-01T00:00:00Z' } });
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10, findingProvenance: fp }];
  const now = Date.parse('2026-02-01T00:00:00Z'); // 31 days after authorDate
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].ageBasis, 'finding_origin');
  assert.equal(findings[0].provenAgeDays, 31);
});

test('ageBasis: earliest_observable when findingProvenance resolved partial with an authorDate', async () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.PARTIAL, { findingOrigin: { commit: 'bbb2222', authorDate: '2026-01-01T00:00:00Z' } });
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10, findingProvenance: fp }];
  const now = Date.parse('2026-01-11T00:00:00Z');
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].ageBasis, 'earliest_observable');
  assert.equal(findings[0].provenAgeDays, 10);
});

test('ageBasis: uncommitted status falls back to wall-clock provenAgeDays', async () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.UNCOMMITTED);
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10, findingProvenance: fp }];
  const now = Date.parse('2026-01-01T00:00:00Z');
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].ageBasis, 'uncommitted');
  assert.equal(findings[0].provenAgeDays, findings[0].ageDays);
});

test('ageBasis: no findingProvenance at all degrades to first_observed, wall-clock unchanged', () => {
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10 }];
  const now = Date.parse('2026-01-01T00:00:00Z');
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].ageBasis, 'first_observed');
  assert.equal(findings[0].provenAgeDays, findings[0].ageDays);
  assert.equal(findings[0].ageDays, 0);
});
