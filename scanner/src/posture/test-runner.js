// R5 (partial, roadmap) — the project's own test suite as a verification
// stage for `verifyFix()` (see `fix-verify.js`). Closes the gap where a
// "verified" fix only proved a finding's stableId stopped firing — a patch
// that deletes the feature entirely would satisfy that just as well as a
// real fix. Running the project's own tests is the cheapest available check
// that the application still works.
//
// Execution-safety note: this spawns the TARGET PROJECT's own test command
// in the target project's own directory. That is deliberately NOT routed
// through the R1 confinement sandbox (`../sandbox/`). That sandbox exists to
// contain untrusted proof-of-concept exploit code the scanner itself
// synthesizes — code nobody has vetted, being run for the first time. A
// project's pre-existing test suite is the opposite case: it is the
// project's own trusted source, already sitting on disk, and running it is
// exactly what a human developer does by hand before trusting a fix.
// Wrapping "npm test" / "pytest" / "go test" in the PoC sandbox's
// syscall/network/filesystem restrictions would break the large majority of
// real test suites (they bind local ports, spawn child processes, write temp
// fixtures, etc.) for no corresponding security benefit.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const DEFAULT_TIMEOUT_MS = 300_000;
const NPM_PLACEHOLDER = /Error: no test specified/i;

function _exists(scanRoot, rel) {
  try { return fs.existsSync(path.join(scanRoot, rel)); } catch { return false; }
}

function _isDir(scanRoot, rel) {
  try { return fs.statSync(path.join(scanRoot, rel)).isDirectory(); } catch { return false; }
}

function _binaryAvailable(cmd) {
  try {
    const r = spawnSync(cmd, ['--version'], { timeout: 5_000, stdio: 'ignore' });
    return !(r.error && r.error.code === 'ENOENT');
  } catch {
    return false;
  }
}

// Detect the project's test command. Read-only — never spawns the actual
// test run, only (optionally) a cheap `--version` probe to confirm a tool
// like `pytest` is actually installed before committing to it. Returns
// `null` when nothing detectable is found — most scanned repos will hit
// this path, and that must not be treated as a failure by callers.
export function detectTestCommand(scanRoot) {
  if (!scanRoot) return null;

  // JS/TS — package.json with a real (non-placeholder) `scripts.test`.
  let pkg = null;
  try { pkg = JSON.parse(fs.readFileSync(path.join(scanRoot, 'package.json'), 'utf8')); } catch { pkg = null; }
  const testScript = pkg && pkg.scripts && pkg.scripts.test;
  if (testScript && !NPM_PLACEHOLDER.test(String(testScript))) {
    if (_exists(scanRoot, 'pnpm-lock.yaml')) return { cmd: 'pnpm', args: ['test'], kind: 'pnpm' };
    if (_exists(scanRoot, 'yarn.lock')) return { cmd: 'yarn', args: ['test'], kind: 'yarn' };
    if (_exists(scanRoot, 'bun.lockb') || _exists(scanRoot, 'bun.lock')) return { cmd: 'bun', args: ['test'], kind: 'bun' };
    return { cmd: 'npm', args: ['test', '--silent'], kind: 'npm' };
  }

  // Python — pytest.ini / pyproject.toml / tox.ini / a tests/ dir, and the
  // `pytest` binary actually available. If pytest isn't installed we do NOT
  // report a python test command — falling through lets a later language
  // marker (e.g. go.mod in a polyglot repo) still be detected.
  const pyMarker = _exists(scanRoot, 'pytest.ini') || _exists(scanRoot, 'pyproject.toml') ||
    _exists(scanRoot, 'tox.ini') || _isDir(scanRoot, 'tests');
  if (pyMarker && _binaryAvailable('pytest')) {
    return { cmd: 'pytest', args: ['-q'], kind: 'pytest' };
  }

  // Go
  if (_exists(scanRoot, 'go.mod')) {
    return { cmd: 'go', args: ['test', './...'], kind: 'go' };
  }

  return null;
}

// Run the detected test command with a walltime budget. Always returns a
// result object — never throws. Distinguishes four outcomes:
//   - no detectable/runnable command  -> status: 'skipped'  (does NOT fail)
//   - ran and exited 0                -> status: 'passed'
//   - ran and exited non-zero         -> status: 'failed'
//   - ran past the timeout budget     -> status: 'failed', timedOut: true
export function runProjectTests(scanRoot, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const startedAt = Date.now();
  const command = detectTestCommand(scanRoot);
  if (!command) {
    return {
      status: 'skipped', passed: null, skipped: true,
      reason: 'no-test-command-detected', exitCode: null, timedOut: false,
      durationMs: Date.now() - startedAt,
    };
  }

  let r;
  try {
    r = spawnSync(command.cmd, command.args, {
      cwd: scanRoot,
      encoding: 'utf8',
      timeout: timeoutMs,
      env: { ...process.env, CI: '1' },
    });
  } catch (e) {
    // The spawn call itself threw (rare — e.g. cwd vanished). Treat as
    // "could not run", not "ran and failed".
    return {
      status: 'skipped', passed: null, skipped: true,
      reason: `spawn-error: ${e.message}`, exitCode: null, timedOut: false,
      durationMs: Date.now() - startedAt,
    };
  }
  const durationMs = Date.now() - startedAt;

  if (r.error && r.error.code === 'ENOENT') {
    // The detected tool isn't actually installed on this machine. Not a
    // test failure — the suite never ran.
    return {
      status: 'skipped', passed: null, skipped: true,
      reason: `${command.kind}-not-installed`, exitCode: null, timedOut: false, durationMs,
    };
  }

  if (r.status === null) {
    // spawnSync sets status:null both on timeout-kill and on being killed by
    // another signal; either way the run did not complete, which is a
    // verification failure, never a skip — we asked for a result and the
    // process was terminated before producing one.
    return {
      status: 'failed', passed: false, skipped: false,
      reason: 'timed-out', exitCode: null, timedOut: true, durationMs,
    };
  }

  return {
    status: r.status === 0 ? 'passed' : 'failed',
    passed: r.status === 0,
    skipped: false,
    reason: r.status === 0 ? null : 'test-failures',
    exitCode: r.status,
    timedOut: false,
    durationMs,
  };
}
