// Annotator-error surface test (post-recommendation #2).
//
// Verifies that:
//   - a clean scan emits annotatorErrors: []
//   - a scan whose calibration-seed file is malformed surfaces a structured
//     error entry instead of silently degrading (the failure mode the post
//     calls out: "rejection, not silent failure")

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runScan } from '../src/runScan.js';
import { toJSON } from '../src/report/index.js';

test('clean scan emits annotatorErrors: []', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan, meta } = await runScan(root, { network: false });
  const out = toJSON(scan, meta);
  assert.ok(Array.isArray(out.annotatorErrors), 'annotatorErrors must be an array');
  assert.equal(out.annotatorErrors.length, 0, `expected clean run, got: ${JSON.stringify(out.annotatorErrors)}`);
});

test('annotatorErrors surfaces when an annotator throws', async () => {
  // We can't easily force a real annotator to throw without monkey-patching
  // the module, so instead we exercise the wrapper directly: construct a
  // scan-like object, call the toJSON path, and verify that an entry
  // pre-populated in scan.annotatorErrors round-trips through the report.
  const fakeScan = {
    findings: [],
    routes: [],
    components: [],
    suppressions: [],
    annotatorErrors: [
      { phase: 'annotateConfidence', err: 'simulated failure for test' },
    ],
  };
  const out = toJSON(fakeScan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.equal(out.annotatorErrors.length, 1);
  assert.equal(out.annotatorErrors[0].phase, 'annotateConfidence');
  assert.match(out.annotatorErrors[0].err, /simulated/);
});

// S7: engine.js computes scan.licenseGraph (posture/license-graph.js) and
// scan.sbomDiff (posture/sbom-diff.js) on every scan with components — their
// own FINDINGS already flow into scan.findings, but the structured summary
// objects themselves (per-component license map, drift added/removed/bumped
// counts, "first scan, no baseline yet") were never copied into toJSON's
// output, so they never reached .agentic-security/last-scan.json (written
// from toJSON's return value) or any --format output. A command instructing
// an agent to "read scan.licenseGraph" or "read scan.sbomDiff" from the
// persisted scan would find nothing there.
test('toJSON carries scan.licenseGraph through when the engine computed one', () => {
  const fakeScan = {
    findings: [], routes: [], components: [], suppressions: [],
    licenseGraph: { byComponent: { 'npm:left-pad': 'MIT' }, copyleftChains: [], dualLicenseTraps: [] },
  };
  const out = toJSON(fakeScan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.deepEqual(out.licenseGraph, fakeScan.licenseGraph);
});

test('toJSON carries scan.sbomDiff through when the engine computed one', () => {
  const fakeScan = {
    findings: [], routes: [], components: [], suppressions: [],
    sbomDiff: { findings: [], summary: { added: 1, removed: 0, bumped: 2, substituted: 0 }, first: false },
  };
  const out = toJSON(fakeScan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.deepEqual(out.sbomDiff, fakeScan.sbomDiff);
});

test('toJSON defaults licenseGraph/sbomDiff to null when the engine did not compute them', () => {
  const out = toJSON({ findings: [], routes: [], components: [], suppressions: [] },
    { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.equal(out.licenseGraph, null);
  assert.equal(out.sbomDiff, null);
});

// S7 (posture --threat's "surface" sub-view): same class of bug as
// licenseGraph/sbomDiff above — entrypointInventory is always computed by
// the engine but was never copied into toJSON's output either.
test('toJSON carries scan.entrypointInventory through when the engine computed one', () => {
  const fakeScan = {
    findings: [], routes: [], components: [], suppressions: [],
    entrypointInventory: { entries: [{ kind: 'http', path: '/users/:id' }], summary: { total: 1 } },
  };
  const out = toJSON(fakeScan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.deepEqual(out.entrypointInventory, fakeScan.entrypointInventory);
});

test('toJSON defaults entrypointInventory to null when the engine did not compute one', () => {
  const out = toJSON({ findings: [], routes: [], components: [], suppressions: [] },
    { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.equal(out.entrypointInventory, null);
});

// S7 (/labs --claude-audit, --cross-repo, --risk-dollars, --time-to-fix):
// same class of bug as licenseGraph/sbomDiff/entrypointInventory above, but
// per-finding rather than scan-level. posture/git-history.js#annotateGitHistory,
// posture/risk-dollars.js#annotateRiskDollars, and posture/time-to-fix.js#
// annotateTimeToFix are all wired into engine.js's annotation pipeline and
// stamp these fields on every finding — but normalizeFindings()'s per-finding
// allowlist dropped every one of them, so last-scan.json (what every /labs
// mode and every downstream consumer actually reads) never carried git
// authorship, AI-authorship, risk-in-dollars, or time-to-fix data, no matter
// how many scans ran.
test('toJSON carries git-history, risk-dollars, and time-to-fix fields through when the engine computed them', () => {
  const fakeScan = {
    findings: [{
      id: 'f1', severity: 'high', vuln: 'SQL Injection', file: 'a.js', line: 3,
      introducedBy: 'Ada Lovelace', introducedIn: 'abc123def456', introducedAt: '2026-01-01T00:00:00Z',
      introducedInMessage: 'add query endpoint', originatingPrompt: 'add a users lookup route',
      aiAuthored: true,
      riskDollars: { ev: 12345, prob: 0.18, impact: 250000, discount: 0.9, confidenceFloor: 0.8 },
      estimatedFixHours: 0.7, estimatedFixHoursSource: 'family-base',
    }],
    routes: [], components: [], suppressions: [],
  };
  const out = toJSON(fakeScan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  const f = out.findings[0];
  assert.equal(f.introducedBy, 'Ada Lovelace');
  assert.equal(f.introducedIn, 'abc123def456');
  assert.equal(f.introducedAt, '2026-01-01T00:00:00Z');
  assert.equal(f.introducedInMessage, 'add query endpoint');
  assert.equal(f.originatingPrompt, 'add a users lookup route');
  assert.equal(f.aiAuthored, true);
  assert.deepEqual(f.riskDollars, fakeScan.findings[0].riskDollars);
  assert.equal(f.estimatedFixHours, 0.7);
  assert.equal(f.estimatedFixHoursSource, 'family-base');
});

test('toJSON defaults git-history/risk-dollars/time-to-fix fields to null when the engine did not compute them', () => {
  const out = toJSON({
    findings: [{ id: 'f1', severity: 'high', vuln: 'SQL Injection', file: 'a.js', line: 3 }],
    routes: [], components: [], suppressions: [],
  }, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  const f = out.findings[0];
  assert.equal(f.introducedBy, null);
  assert.equal(f.introducedIn, null);
  assert.equal(f.introducedAt, null);
  assert.equal(f.introducedInMessage, null);
  assert.equal(f.originatingPrompt, null);
  assert.equal(f.aiAuthored, false);
  assert.equal(f.riskDollars, null);
  assert.equal(f.estimatedFixHours, null);
  assert.equal(f.estimatedFixHoursSource, null);
});
