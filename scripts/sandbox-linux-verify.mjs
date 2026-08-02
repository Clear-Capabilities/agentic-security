#!/usr/bin/env node
// Linux sandbox verification runner.
//
// WHY THIS EXISTS. The kernel-namespace backend's escape tests SKIP whenever
// the host cannot create the namespaces, and a skipped suite scrolling past in
// a green job is indistinguishable from a suite that passed. That is exactly
// the misread this repository has paid for before, so the verdict is made
// explicit here: this runner prints which backend was selected, prints RAN or
// SKIPPED for every escape test individually, and EXITS NON-ZERO unless the
// kernel-namespace suite actually ran. A job that cannot exercise the backend
// fails loudly rather than reporting success it did not earn.
//
// It weakens nothing: it does not pass flags to the tests, does not relax any
// assertion, and does not select a backend. It only runs the existing suite
// and refuses to call a skip a pass.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCANNER = path.join(ROOT, 'scanner');

// The suite whose skip is not allowed to be mistaken for a pass. Matched
// against the TAP test name.
const REQUIRED_SUITE = 'kernel-namespace confinement — escape attempts';

function line(s = '') { process.stdout.write(`${s}\n`); }

// ---------------------------------------------------------------- backend
const { detectBackend } = await import(
  path.join(SCANNER, 'src', 'sandbox', 'capabilities.js')
);
const backend = detectBackend();

line('=== sandbox backend selection ===');
line(`platform: ${process.platform}`);
line(`SELECTED BACKEND: ${backend}`);
line('');
line('Selection is functional: a backend is reported only if a trivial command');
line('just ran through its real code path under real confinement. "disabled"');
line('means confinement does not work here, not that a check was lenient.');
line('');

// ---------------------------------------------------------------- run suite
const files = ['test/sandbox-escape.test.js', 'test/sandbox.test.js'];
line(`=== running ${files.join(' ')} ===`);
const run = spawnSync(
  process.execPath,
  ['--test', '--test-reporter=tap', ...files],
  { cwd: SCANNER, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
);
const tap = `${run.stdout || ''}\n${run.stderr || ''}`;
process.stdout.write(tap);

// ---------------------------------------------------------------- verdict
const results = [];
for (const l of tap.split('\n')) {
  const m = /^\s*(not ok|ok)\s+\d+\s+-\s+(.*)$/.exec(l);
  if (!m) continue;
  const skipped = /#\s*SKIP/i.test(m[2]);
  const name = m[2].replace(/\s*#\s*(SKIP|TODO).*$/i, '').trim();
  results.push({ name, ok: m[1] === 'ok', skipped });
}

line('');
line('=== RAN / SKIPPED, per test ===');
for (const r of results) {
  line(`${r.skipped ? 'SKIPPED' : r.ok ? 'RAN+PASS' : 'RAN+FAIL '} :: ${r.name}`);
}

const required = results.find((r) => r.name === REQUIRED_SUITE);
const problems = [];
if (backend !== 'namespace') {
  problems.push(`the kernel-namespace backend was not selected (got '${backend}'), so its confinement was never exercised`);
}
if (!required) {
  problems.push(`the required suite "${REQUIRED_SUITE}" did not appear in the test output at all`);
} else if (required.skipped) {
  problems.push(`the required suite "${REQUIRED_SUITE}" SKIPPED — a skip is a declared gap in verification, never a pass`);
} else if (!required.ok) {
  problems.push(`the required suite "${REQUIRED_SUITE}" FAILED`);
}
if (run.status !== 0) problems.push(`the test process exited ${run.status}`);

line('');
line('=== verdict ===');
if (problems.length === 0) {
  line('VERIFIED: the kernel-namespace escape suite RAN on this host and passed.');
  process.exit(0);
}
line('NOT VERIFIED:');
for (const p of problems) line(`  - ${p}`);
process.exit(1);
