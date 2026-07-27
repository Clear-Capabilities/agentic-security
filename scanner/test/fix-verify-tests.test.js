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
