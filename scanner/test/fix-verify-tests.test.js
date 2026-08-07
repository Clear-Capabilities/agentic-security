// R5 (partial) — test-suite verification stage.
//
// Covers `posture/test-runner.js` directly (detection + execution semantics)
// and its wiring into `posture/fix-verify.js`'s `verifyFix()`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { detectTestCommand, runProjectTests } from '../src/posture/test-runner.js';
import { verifyFix } from '../src/posture/fix-verify.js';
import { loadFixAttempts, fixDurationReport, FIX_STAGES } from '../src/posture/fix-metrics.js';

function mkTmpDir(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `fvt-${name}-`));
}

function writePkg(dir, testScript) {
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'fixture', version: '1.0.0',
    scripts: { test: testScript },
  }));
}

test('runProjectTests: passing test script -> status passed, ok stays true through verifyFix', async () => {
  const dir = mkTmpDir('pass');
  writePkg(dir, 'exit 0');
  const out = runProjectTests(dir, { timeoutMs: 30_000 });
  assert.equal(out.status, 'passed');
  assert.equal(out.passed, true);
  assert.equal(out.skipped, false);
  assert.equal(out.exitCode, 0);
  assert.equal(out.timedOut, false);

  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
  });
  assert.equal(verdict.tests.status, 'passed');
  assert.equal(verdict.ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: failing test script -> status failed, and verifyFix returns ok:false', async () => {
  const dir = mkTmpDir('fail');
  writePkg(dir, 'exit 1');
  const out = runProjectTests(dir, { timeoutMs: 30_000 });
  assert.equal(out.status, 'failed');
  assert.equal(out.passed, false);
  assert.equal(out.skipped, false);
  assert.equal(out.exitCode, 1);
  assert.equal(out.timedOut, false);

  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
  });
  assert.equal(verdict.tests.status, 'failed');
  assert.equal(verdict.ok, false);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectTestCommand + runProjectTests: no detectable suite -> skipped, verifyFix ok unaffected', async () => {
  const dir = mkTmpDir('none');
  assert.equal(detectTestCommand(dir), null);
  const out = runProjectTests(dir, { timeoutMs: 30_000 });
  assert.equal(out.status, 'skipped');
  assert.equal(out.passed, null);
  assert.equal(out.skipped, true);
  assert.ok(out.reason);

  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
  });
  assert.equal(verdict.tests.skipped, true);
  assert.equal(verdict.ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectTestCommand: npm placeholder script is not treated as a real test command', () => {
  const dir = mkTmpDir('placeholder');
  writePkg(dir, 'echo "Error: no test specified" && exit 1');
  assert.equal(detectTestCommand(dir), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: hanging test script -> timedOut:true, treated as failure not skip', () => {
  const dir = mkTmpDir('hang');
  writePkg(dir, 'sleep 30');
  const out = runProjectTests(dir, { timeoutMs: 300 });
  assert.equal(out.timedOut, true);
  assert.equal(out.status, 'failed');
  assert.equal(out.passed, false);
  assert.equal(out.skipped, false);
  assert.equal(out.reason, 'timed-out');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: durationMs is a positive number on a real run', () => {
  const dir = mkTmpDir('duration');
  writePkg(dir, 'exit 0');
  const out = runProjectTests(dir, { timeoutMs: 30_000 });
  assert.equal(typeof out.durationMs, 'number');
  assert.ok(out.durationMs >= 0);
  assert.ok(Number.isFinite(out.durationMs));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('verifyFix summary includes a tests line', async () => {
  const dir = mkTmpDir('summary');
  writePkg(dir, 'exit 0');
  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
  });
  assert.match(verdict.summary, /tests:/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- R5 (reporting half) — the metric is emitted from REAL verifyFix runs ---
//
// The distribution is only worth anything if it is fed by the actual pipeline
// rather than by hand-built records, so these drive `verifyFix` end to end and
// then read the log back off disk.

test('verifyFix records a real attempt, and the recorded stages sum to the total', async () => {
  const dir = mkTmpDir('metrics');
  writePkg(dir, 'exit 0');
  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
  });
  assert.equal(typeof verdict.durations.totalMs, 'number');

  const attempts = loadFixAttempts(dir);
  assert.equal(attempts.length, 1, 'one verification attempt must produce exactly one record');
  const a = attempts[0];
  assert.equal(a.ok, verdict.ok);
  assert.equal(a.testsRan, true);
  for (const stage of FIX_STAGES) {
    assert.equal(typeof a.stages[stage], 'number', `stage ${stage} was not timed`);
  }
  const summed = FIX_STAGES.reduce((n, s) => n + a.stages[s], 0);
  assert.ok(summed <= a.totalMs, 'the stage timings must not exceed the attempt they partition');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a real failing verification is recorded as failed, and stays out of the validated median', async () => {
  const dir = mkTmpDir('metrics-fail');
  writePkg(dir, 'exit 1');
  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
  });
  assert.equal(verdict.ok, false, 'a failing suite must fail verification');

  const report = fixDurationReport(dir);
  assert.equal(report.attempts, 1);
  assert.equal(report.counts.failed, 1);
  assert.equal(report.timeToValidatedFix.n, 0, 'a failed fix is not a time-to-validated-fix sample');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a project with no detectable suite is recorded as validated-without-tests', async () => {
  const dir = mkTmpDir('metrics-notests');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0' }));
  await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
  });
  const report = fixDurationReport(dir);
  assert.equal(report.counts.validatedWithoutTests, 1);
  assert.equal(report.timeToValidatedFix.n, 0,
    'no suite ran, so this must not be counted as a test-validated fix');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('recordMetrics:false writes nothing', async () => {
  const dir = mkTmpDir('metrics-off');
  writePkg(dir, 'exit 0');
  await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
    recordMetrics: false,
  });
  assert.deepEqual(loadFixAttempts(dir), []);
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- R5 — the PoC leg: verify_fix fails when the PoC still proves the bug ---
//
// Both directions are asserted, and the third case is the important one: an
// unprovable PoC must NOT be read as a fix.

// A PoC that writes the proof marker only when the code it imports is still
// vulnerable. `vuln.js` is supplied as the candidate patch, so the same PoC
// exercises the pre-fix and post-fix shapes with nothing else changed.
const MARKER_POC = {
  lang: 'js',
  code: [
    "import { unsafe } from './vuln.js';",
    "import fs from 'node:fs';",
    "if (unsafe('../../etc/passwd').includes('..')) fs.writeFileSync('PROVEN', 'x');",
  ].join('\n'),
};

test('poc leg: a patch the PoC still defeats FAILS verification', async (t) => {
  const dir = mkTmpDir('poc-bad');
  writePkg(dir, 'exit 0');
  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    // "Fixed" in name only — the traversal still gets through.
    files: { 'vuln.js': 'export const unsafe = (p) => String(p);\n' },
    poc: MARKER_POC,
  });
  if (verdict.poc.status === 'inconclusive') {
    t.skip(`SKIPPED, NOT PASSED: the PoC could not be executed here (${verdict.poc.reason})`);
    fs.rmSync(dir, { recursive: true, force: true });
    return;
  }
  assert.equal(verdict.poc.status, 'still-exploitable');
  assert.equal(verdict.ok, false, 'a patch the PoC still defeats must not verify');
  assert.match(verdict.summary, /poc:\s+FAIL/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('poc leg: a patch that closes the hole PASSES', async (t) => {
  const dir = mkTmpDir('poc-good');
  writePkg(dir, 'exit 0');
  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'vuln.js': "export const unsafe = (p) => String(p).replace(/\\.\\./g, '');\n" },
    poc: MARKER_POC,
  });
  if (verdict.poc.status === 'inconclusive') {
    t.skip(`SKIPPED, NOT PASSED: the PoC could not be executed here (${verdict.poc.reason})`);
    fs.rmSync(dir, { recursive: true, force: true });
    return;
  }
  assert.equal(verdict.poc.status, 'no-longer-proven');
  assert.equal(verdict.ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('poc leg: an unprovable PoC is inconclusive and never counted as a pass', async () => {
  const dir = mkTmpDir('poc-unprovable');
  writePkg(dir, 'exit 0');
  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'vuln.js': 'export const unsafe = (p) => String(p);\n' },
    // An unsupported language never executes, so nothing is learned.
    poc: { lang: 'ruby', code: 'puts 1' },
  });
  assert.equal(verdict.poc.status, 'inconclusive');
  assert.match(verdict.summary, /poc:\s+inconclusive/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('poc leg: absent by default — verification is unchanged when no PoC is supplied', async () => {
  const dir = mkTmpDir('poc-none');
  writePkg(dir, 'exit 0');
  const verdict = await verifyFix({
    scanRoot: dir,
    originalFindingStableId: 'no-such-id',
    files: { 'app.js': 'console.log(1);\n' },
  });
  assert.equal(verdict.poc.status, 'not-requested');
  assert.doesNotMatch(verdict.summary, /poc:/);
  assert.equal(verdict.ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});
