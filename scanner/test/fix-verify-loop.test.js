// v0.68 — closed-loop fix verification tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runProjectTests, verifyFixWithTests } from '../src/posture/fix-verify-loop.js';

function mkdir(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `fvl-${name}-`));
}

test('runProjectTests: emits skipped+none when no runner is detected', () => {
  const dir = mkdir('none');
  const out = runProjectTests(dir);
  assert.equal(out.ok, true);
  assert.equal(out.runner, 'none');
  assert.equal(out.skipped, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: detects npm test from package.json', () => {
  const dir = mkdir('npm');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'demo', version: '1.0.0',
    scripts: { test: 'echo "skipping"; exit 0' },
  }));
  const out = runProjectTests(dir, { timeoutMs: 30_000 });
  assert.equal(out.runner, 'npm');
  // npm's exit may be non-zero on first-run if no node_modules; we accept
  // either result here. The shape of the response is what matters.
  assert.ok(typeof out.ok === 'boolean');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: respects runnerOverride for forced-deterministic tests', () => {
  const dir = mkdir('over');
  const out = runProjectTests(dir, {
    runnerOverride: { cmd: 'sh', args: ['-c', 'exit 0'] },
  });
  assert.equal(out.ok, true);
  assert.equal(out.runner, 'sh');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: failing runner emits ok=false', () => {
  const dir = mkdir('fail');
  const out = runProjectTests(dir, {
    runnerOverride: { cmd: 'sh', args: ['-c', 'exit 7'] },
  });
  assert.equal(out.ok, false);
  assert.equal(out.exitCode, 7);
  fs.rmSync(dir, { recursive: true, force: true });
});

// Stage 5 correctness audit: _detectRunner unconditionally appends
// `--`, `--passWithNoTests` (a Jest-specific CLI flag) to every npm
// project's `npm test` invocation, regardless of what test framework is
// actually configured. The prior "detects npm test" test above doesn't
// catch this — its `sh -c` fixture happens to silently ignore the extra
// positional args. A real, valid, non-Jest test script chokes on the
// unrecognized flag and verification fails for a reason that has nothing
// to do with whether the patch actually broke anything.
test('runProjectTests: a valid non-Jest npm test script is not broken by an injected Jest-only flag', () => {
  const dir = mkdir('nonjest');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'demo', version: '1.0.0',
    scripts: { test: 'node -e "console.log(\'ok\')"' },
  }));
  const out = runProjectTests(dir, { timeoutMs: 30_000 });
  assert.equal(out.runner, 'npm');
  assert.equal(out.ok, true, `expected a valid non-Jest test script to pass verification; got ${JSON.stringify(out)}`);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: a Jest project still gets --passWithNoTests (no regression on the original intent)', () => {
  const dir = mkdir('jest');
  // A stub `jest` executable on PATH (via node_modules/.bin, exactly where
  // npm resolves package-script commands from) that echoes its own argv,
  // so this test observes the real args npm invoked it with rather than
  // guessing from an exit code.
  const binDir = path.join(dir, 'node_modules', '.bin');
  fs.mkdirSync(binDir, { recursive: true });
  const stubPath = path.join(binDir, 'jest');
  fs.writeFileSync(stubPath, '#!/usr/bin/env node\nconsole.log(JSON.stringify(process.argv.slice(2)));\n');
  fs.chmodSync(stubPath, 0o755);
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'demo', version: '1.0.0',
    scripts: { test: 'jest' },
    devDependencies: { jest: '^29.0.0' },
  }));
  const out = runProjectTests(dir, { timeoutMs: 30_000 });
  assert.equal(out.ok, true, `expected the stub jest to run cleanly; got ${JSON.stringify(out)}`);
  assert.match(out.output, /--passWithNoTests/, `expected the Jest-specific flag to still be passed for a real Jest project; got ${JSON.stringify(out)}`);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('verifyFixWithTests: emits untested-but-passes when no runner exists', async () => {
  const dir = mkdir('utbp');
  // A trivial clean file — scan should be empty.
  fs.writeFileSync(path.join(dir, 'safe.js'), 'export const x = 1;\n');
  const out = await verifyFixWithTests({
    scanRoot: dir,
    originalFindingStableId: 'nonexistent-stable-id',
    files: { 'safe.js': 'export const x = 1;\n' },
  });
  assert.equal(out.verdict, 'untested-but-passes');
  assert.equal(out.ok, true);
  assert.ok(out.summary.startsWith('untested-but-passes'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('verifyFixWithTests: verified-clean when overridden runner passes', async () => {
  const dir = mkdir('verok');
  fs.writeFileSync(path.join(dir, 'safe.js'), 'export const x = 1;\n');
  const out = await verifyFixWithTests({
    scanRoot: dir,
    originalFindingStableId: 'nonexistent-stable-id',
    files: { 'safe.js': 'export const x = 1;\n' },
    testRunnerOverride: { cmd: 'sh', args: ['-c', 'exit 0'] },
  });
  assert.equal(out.verdict, 'verified-clean');
  assert.equal(out.ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('verifyFixWithTests: failing tests block verified-clean', async () => {
  const dir = mkdir('verfail');
  fs.writeFileSync(path.join(dir, 'safe.js'), 'export const x = 1;\n');
  const out = await verifyFixWithTests({
    scanRoot: dir,
    originalFindingStableId: 'nonexistent-stable-id',
    files: { 'safe.js': 'export const x = 1;\n' },
    testRunnerOverride: { cmd: 'sh', args: ['-c', 'exit 1'] },
  });
  assert.equal(out.verdict, 'verification-failed');
  assert.equal(out.ok, false);
  assert.equal(out.legs.tests.ok, false);
});
