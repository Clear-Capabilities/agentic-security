// SARD_AGENTIC_SECURITY_PRD.md adversarial-premortem remediation, Round 1
// F4 / Round 2 F8 — bench/sard/scripts/compare-baseline.mjs used a flat 2pp
// regression tolerance for every metric regardless of how much data it was
// measured on, even though this session's own Phase 9 entry recorded real
// harness nondeterminism (an unrelated holdout app's F1 moved 16.6%->15.6%
// between two runs with zero code changes) — a flat tolerance is
// simultaneously too loose for a large-support metric (hides a real
// regression) and too tight for a tiny-support one (ordinary noise reads as
// a failure). `adaptiveTolerance` widens the band for low-support metrics
// only, one-directionally, so nothing that passed before can start failing
// because of this change.
//
// Also closes a real, separate gap found while writing this: no automated
// test previously existed for compare-baseline.mjs's CLI behavior at all —
// the ledger's own "proved both directions" claim for the ORIGINAL
// flat-tolerance version was a manual, one-off verification during the
// session, never a permanent regression test.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { adaptiveTolerance } from '../../bench/sard/scripts/compare-baseline.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.join(__dirname, '..', '..', 'bench', 'sard', 'scripts', 'compare-baseline.mjs');

test('adaptiveTolerance: at the reference support level (30), returns the base tolerance unchanged', () => {
  assert.equal(adaptiveTolerance(0.02, 30), 0.02);
});

test('adaptiveTolerance: widens for low-support metrics (more noise expected)', () => {
  const t1 = adaptiveTolerance(0.02, 1);
  assert.ok(t1 > 0.02, `expected support=1 to widen beyond the base tolerance, got ${t1}`);
});

test('adaptiveTolerance: widens even in the "twilight zone" ABOVE MIN_SUPPORT (5) but below REFERENCE_SUPPORT (30) — this is the exact window the per-CWE comparison actually reaches, since anything below MIN_SUPPORT is skipped before tolerance is ever consulted', () => {
  const t10 = adaptiveTolerance(0.02, 10);
  assert.ok(t10 > 0.02, `expected support=10 (above MIN_SUPPORT, below REFERENCE_SUPPORT) to still widen, got ${t10}`);
});

test('adaptiveTolerance: never returns LESS than the base tolerance, even for very large support', () => {
  const t100 = adaptiveTolerance(0.02, 100);
  const t100000 = adaptiveTolerance(0.02, 100000);
  assert.equal(t100, 0.02, 'large support must not tighten below the base tolerance');
  assert.equal(t100000, 0.02, 'very large support must not tighten below the base tolerance');
});

test('adaptiveTolerance: monotonically non-increasing as support grows (never gets MORE lenient with more data)', () => {
  const supports = [1, 2, 3, 5, 10, 50, 500];
  const tolerances = supports.map((s) => adaptiveTolerance(0.02, s));
  for (let i = 1; i < tolerances.length; i++) {
    assert.ok(tolerances[i] <= tolerances[i - 1],
      `tolerance must not increase as support grows: support=${supports[i]} gave ${tolerances[i]}, support=${supports[i - 1]} gave ${tolerances[i - 1]}`);
  }
});

test('adaptiveTolerance: degenerate/invalid support (0, negative, NaN) falls back to the base tolerance, never throws or returns Infinity', () => {
  for (const bad of [0, -1, NaN, undefined, null]) {
    assert.equal(adaptiveTolerance(0.02, bad), 0.02, `expected fallback to base tolerance for support=${bad}`);
  }
});

// ── End-to-end CLI proof, both directions — the gap this file also closes. ─

// Returns the REPORTS directory itself (matching what
// SARD_BASELINE_REPORTS_DIR_FOR_TESTS expects: a path directly containing
// latest.json/baseline.json, not a parent with a "reports" subfolder).
function mkReportsDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sard-baseline-cli-'));
}

function writeReport(reportsDir, file, data) {
  fs.writeFileSync(path.join(reportsDir, file), JSON.stringify(data, null, 2));
}

// Runs the REAL script as a subprocess against a disposable temp reports
// dir (via SARD_BASELINE_REPORTS_DIR_FOR_TESTS) — never the developer's own
// local baseline. `cwd` doesn't matter for this script's own path
// resolution (it's HERE-relative, i.e. relative to the script file), only
// the env var does; set anyway for hygiene.
function runCli(reportsDir, args) {
  try {
    const out = execFileSync(process.execPath, [SCRIPT, ...args], {
      encoding: 'utf8',
      env: { ...process.env, SARD_BASELINE_REPORTS_DIR_FOR_TESTS: reportsDir },
    });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status, out: (e.stdout || '') + (e.stderr || '') };
  }
}

function sampleReport(macroF1, microF1, precision, tp, fn) {
  return {
    apps: [{
      name: 'sard-juliet-java-strict',
      macroF1,
      aggregate: { tp, fp: 0, fn, precision, recall: tp / (tp + fn), microF1 },
      perCwe: [{ cwe: 'CWE89', tp, fp: 0, fn, precision, recall: tp / (tp + fn), f1: microF1, support: tp + fn }],
    }],
  };
}

test('compare-baseline CLI: --update-baseline then a clean, unregressed --check-baseline exits 0', () => {
  const dir = mkReportsDir();
  const report = sampleReport(0.60, 0.55, 0.70, 60, 40);
  writeReport(dir, 'latest.json', report);
  const update = runCli(dir, ['--update-baseline']);
  assert.equal(update.code, 0, `--update-baseline should succeed, got: ${update.out}`);
  assert.ok(fs.existsSync(path.join(dir, 'baseline.json')), 'baseline.json should now exist');

  // Re-check against the IDENTICAL report — zero drift, must pass.
  writeReport(dir, 'latest.json', report);
  const check = runCli(dir, ['--check-baseline']);
  assert.equal(check.code, 0, `identical report must pass the regression gate, got: ${check.out}`);
});

test('compare-baseline CLI: a genuine, large regression exits 1 and names the metric', () => {
  const dir = mkReportsDir();
  writeReport(dir, 'latest.json', sampleReport(0.60, 0.55, 0.70, 60, 40));
  assert.equal(runCli(dir, ['--update-baseline']).code, 0);

  // A genuine 20-point macro-F1 drop — must fail regardless of adaptive
  // widening (this is a real regression, not noise).
  writeReport(dir, 'latest.json', sampleReport(0.40, 0.35, 0.50, 40, 60));
  const check = runCli(dir, ['--check-baseline']);
  assert.equal(check.code, 1, `a genuine large regression must fail the gate, got exit ${check.code}: ${check.out}`);
  assert.match(check.out, /macro F1 regressed/);
});

test('compare-baseline CLI: a small, low-support per-CWE wobble that the OLD flat tolerance would have failed now passes (the noise-aware fix in action)', () => {
  // support=10: above MIN_SUPPORT (5, so the per-CWE check is NOT skipped —
  // it's genuinely reached and scored) and below REFERENCE_SUPPORT (30, so
  // it genuinely widens) — the exact "twilight zone" the fix targets. A
  // wobble sized STRICTLY between the old flat 2pp tolerance and the new,
  // wider one mirrors the real shape F4 measured (an unrelated holdout
  // app's F1 moving between two runs with zero code changes).
  const support = 10;
  const widened = adaptiveTolerance(0.02, support);
  assert.ok(widened > 0.02, 'sanity: support=10 must actually widen beyond the flat 2pp tolerance for this test to mean anything');
  const wobblePp = (0.02 + widened) / 2; // strictly between the old and new tolerance

  const dir = mkReportsDir();
  const baseF1 = 0.60;
  const base = sampleReport(0.60, baseF1, baseF1, 6, 4); // tp=6, fn=4 -> support=10
  writeReport(dir, 'latest.json', base);
  assert.equal(runCli(dir, ['--update-baseline']).code, 0);

  const wobbled = JSON.parse(JSON.stringify(base));
  wobbled.apps[0].perCwe[0].f1 = baseF1 - wobblePp;
  writeReport(dir, 'latest.json', wobbled);
  const check = runCli(dir, ['--check-baseline']);
  assert.equal(check.code, 0,
    `a ${(wobblePp*100).toFixed(2)}pp wobble at support=${support} (within the new ${(widened*100).toFixed(2)}pp tolerance) must pass, got: ${check.out}`);
});

test('compare-baseline: adaptiveTolerance-widened per-CWE check absorbs the exact class of noise F4 measured, without masking a real regression', () => {
  // Simulates exactly the scenario F4 found: a tiny-support CWE (support=2,
  // well under MIN_SUPPORT=5, so the existing MIN_SUPPORT gate alone would
  // already skip it — this proves the WIDENING itself, for a support level
  // ABOVE MIN_SUPPORT where the old flat tolerance previously applied
  // unscaled) with ordinary noise must not fail, while a genuinely large
  // regression on a high-support CWE must still fail regardless of widening.
  const baseTolerance = 0.02;
  // support=6 (just above MIN_SUPPORT): a small, real F1 wobble (1.5pp) that
  // the FLAT tolerance would already absorb too — this confirms widening
  // doesn't change behavior right at the boundary.
  const tolerance6 = adaptiveTolerance(baseTolerance, 6);
  assert.ok(0.015 < tolerance6, 'a 1.5pp wobble at support=6 must stay within tolerance');
  // support=1000 (large): a genuine 5pp regression must still fail — the
  // one-directional clamp means large-support tolerance never exceeds base.
  const tolerance1000 = adaptiveTolerance(baseTolerance, 1000);
  assert.ok(0.05 > tolerance1000, 'a genuine 5pp regression at support=1000 must still exceed the (unwidened) tolerance');
});
