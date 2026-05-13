#!/usr/bin/env node
// Execute a single generated PoC test file under the project's detected
// framework. Captures pass/fail/error and emits a structured verdict.
//
// Usage: run-test.js <test-file>
// Output: JSON { framework, command, exitCode, durationMs, stdout, stderr, verdict }
//   verdict ∈ {'TEST_FAILED_AS_EXPECTED', 'TEST_PASSED_UNEXPECTEDLY', 'TEST_ERRORED'}
//
// Semantics:
//   - PoC test ASSERTS the vulnerable behaviour. Against unfixed code the
//     assertion should fire → test FAILS → this means the bug is real → verdict TEST_FAILED_AS_EXPECTED.
//   - If the test PASSES against the unfixed code, the assertion didn't
//     fire → the static finding is probably an FP → verdict TEST_PASSED_UNEXPECTEDLY.
//   - Any other error (compile, missing module, timeout) → TEST_ERRORED.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function detectFramework() {
  // Reuse detect-framework.mjs
  const out = spawnSync(process.execPath, [path.join(__dirname, 'detect-framework.mjs'), process.cwd()], {
    encoding: 'utf8', timeout: 5000,
  });
  if (out.status !== 0) return { framework: 'none', runner: null };
  try { return JSON.parse(out.stdout); } catch { return { framework: 'none', runner: null }; }
}

const testFile = process.argv[2];
if (!testFile) { console.error('Usage: run-test.js <test-file>'); process.exit(2); }
const abs = path.resolve(process.cwd(), testFile);
if (!fs.existsSync(abs)) { console.error(`Test file not found: ${abs}`); process.exit(2); }

const fw = detectFramework();
if (!fw.runner) {
  process.stdout.write(JSON.stringify({
    framework: 'none',
    command: null,
    exitCode: -1,
    durationMs: 0,
    verdict: 'TEST_ERRORED',
    reason: 'no test framework detected — cannot execute generated PoC',
  }, null, 2));
  process.exit(0);
}

// Build the command. Each runner has a different invocation shape.
const runners = {
  'jest':         ['npx', 'jest', '--', abs],
  'vitest':       ['npx', 'vitest', 'run', abs],
  'mocha':        ['npx', 'mocha', abs],
  'node-test':    [process.execPath, '--test', abs],
  'pytest':       ['pytest', abs, '-v'],
  'go-test':      ['go', 'test', '-run', '.', path.dirname(abs)],
  'cargo-test':   ['cargo', 'test', '--manifest-path', findCargoManifest(abs)],
  'dotnet-test':  ['dotnet', 'test', '--filter', `FullyQualifiedName~${path.basename(abs, '.cs')}`],
  'junit':        ['mvn', 'test', `-Dtest=${path.basename(abs, '.java')}`],
  'rspec':        ['bundle', 'exec', 'rspec', abs],
  'phpunit':      ['./vendor/bin/phpunit', abs],
};

function findCargoManifest(testPath) {
  let dir = path.dirname(testPath);
  while (dir !== '/' && dir !== path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, 'Cargo.toml'))) return path.join(dir, 'Cargo.toml');
    dir = path.dirname(dir);
  }
  return path.join(process.cwd(), 'Cargo.toml');
}

const argv = runners[fw.framework];
if (!argv) {
  process.stdout.write(JSON.stringify({
    framework: fw.framework,
    command: null,
    exitCode: -1,
    durationMs: 0,
    verdict: 'TEST_ERRORED',
    reason: `unknown runner shape for framework: ${fw.framework}`,
  }, null, 2));
  process.exit(0);
}

const t0 = Date.now();
const proc = spawnSync(argv[0], argv.slice(1), {
  cwd: process.cwd(), encoding: 'utf8', timeout: 60_000,  // 60s hard cap
  stdio: ['ignore', 'pipe', 'pipe'],
});
const durationMs = Date.now() - t0;
const exitCode = proc.status ?? -1;
const stdout = (proc.stdout || '').slice(0, 8000);
const stderr = (proc.stderr || '').slice(0, 4000);

// Heuristic: any non-zero exit means at least one test failed → the PoC
// successfully demonstrated the vuln. Exit 0 means all passed → the PoC
// failed to demonstrate (probable FP).
let verdict;
if (proc.error && proc.error.code === 'ETIMEDOUT') verdict = 'TEST_ERRORED';
else if (proc.error) verdict = 'TEST_ERRORED';
else if (exitCode === 0) verdict = 'TEST_PASSED_UNEXPECTEDLY';
else verdict = 'TEST_FAILED_AS_EXPECTED';

process.stdout.write(JSON.stringify({
  framework: fw.framework,
  command: argv.join(' '),
  exitCode,
  durationMs,
  stdout,
  stderr,
  verdict,
}, null, 2));
