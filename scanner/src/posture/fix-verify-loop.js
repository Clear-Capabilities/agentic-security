// Closed-loop fix verification (v0.68).
//
// Existing `fix-verify.js` does scan + lint. This module adds the third
// leg: run the project's test suite against the patched file set. A fix
// is `verified-clean` only when:
//
//   1. Re-scan no longer fires the original finding's stableId
//   2. No new ≥medium findings introduced
//   3. Project linter (when present) passes on the patched files
//   4. Project test runner (when present) exits 0 within budget
//
// If the project has no detected test runner, we emit `untested-but-passes`
// rather than fail-closed — many small repos have no test suite and we
// don't want to refuse all fixes there. The verdict is honest.
//
// Design note: we run the tests against the WRITTEN patch, not an in-
// memory overlay — most real test runners can't be given an alternate
// filesystem cheaply. Callers are expected to apply the patch first
// (typically via fix-history.applyFix which creates a recovery backup),
// then call this. If verification fails, undoLast() rolls back.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyFix } from './fix-verify.js';

const DEFAULT_TIMEOUT_MS = 120_000;

// Test-runner discovery. Each entry: a sentinel-file check + a command +
// args. Order matters — JS first (most common), then Python, Go, Rust,
// Java/Maven, Java/Gradle, Ruby.
function _detectRunner(scanRoot) {
  const has = (p) => { try { return fs.existsSync(path.join(scanRoot, p)); } catch { return false; } };
  const pkg = (() => {
    try {
      const raw = fs.readFileSync(path.join(scanRoot, 'package.json'), 'utf8');
      return JSON.parse(raw);
    } catch { return null; }
  })();
  if (pkg && pkg.scripts && pkg.scripts.test && !/no test specified/.test(String(pkg.scripts.test))) {
    // --passWithNoTests is Jest-specific CLI syntax — appending it
    // unconditionally broke every non-Jest npm test script (mocha, vitest,
    // ava, tap, or a plain node script) with an "unrecognized option" exit,
    // failing verification for a reason that has nothing to do with
    // whether the patch actually broke anything. Only add it when Jest is
    // actually the configured runner.
    const usesJest = /\bjest\b/.test(String(pkg.scripts.test))
      || Boolean(pkg.devDependencies?.jest) || Boolean(pkg.dependencies?.jest);
    const args = usesJest ? ['test', '--silent', '--', '--passWithNoTests'] : ['test', '--silent'];
    return { runner: 'npm', cmd: 'npm', args };
  }
  if (has('pytest.ini') || has('pyproject.toml') || has('setup.cfg')) {
    return { runner: 'pytest', cmd: 'pytest', args: ['-q', '--no-header', '-x'] };
  }
  if (has('go.mod')) {
    return { runner: 'go-test', cmd: 'go', args: ['test', './...'] };
  }
  if (has('Cargo.toml')) {
    return { runner: 'cargo-test', cmd: 'cargo', args: ['test', '--quiet'] };
  }
  if (has('Gemfile')) {
    return { runner: 'rspec', cmd: 'bundle', args: ['exec', 'rspec', '--fail-fast'] };
  }
  if (has('pom.xml')) {
    return { runner: 'maven', cmd: 'mvn', args: ['-q', 'test', '-DfailIfNoTests=false'] };
  }
  if (has('build.gradle') || has('build.gradle.kts')) {
    return { runner: 'gradle', cmd: './gradlew', args: ['test', '--quiet', '--no-daemon'] };
  }
  return null;
}

// Run the detected test runner. Honors a walltime budget. Caller may pass
// `runnerOverride` to force a specific command (rare; mostly for tests).
export function runProjectTests(scanRoot, opts = {}) {
  if (!scanRoot) return { ok: true, runner: 'none', skipped: true };
  const choice = opts.runnerOverride
    ? { runner: opts.runnerOverride.cmd, cmd: opts.runnerOverride.cmd, args: opts.runnerOverride.args || [] }
    : _detectRunner(scanRoot);
  if (!choice) return { ok: true, runner: 'none', skipped: true, reason: 'no-test-runner-detected' };
  const timeout = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  let r;
  try {
    r = spawnSync(choice.cmd, choice.args, {
      cwd: scanRoot,
      encoding: 'utf8',
      timeout,
      env: { ...process.env, CI: '1' },
    });
  } catch (e) {
    return { ok: false, runner: choice.runner, reason: 'spawn-failed', error: e.message };
  }
  if (r.error && r.error.code === 'ENOENT') {
    // Runner not installed — different from "tests failed". Don't fail-closed.
    return { ok: true, runner: choice.runner, skipped: true, reason: 'binary-missing' };
  }
  if (r.status === null) {
    return {
      ok: false, runner: choice.runner, reason: 'timed-out',
      output: ((r.stderr || '') + (r.stdout || '')).slice(-2000),
    };
  }
  return {
    ok: r.status === 0,
    runner: choice.runner,
    exitCode: r.status,
    output: ((r.stderr || '') + (r.stdout || '')).slice(-2000),
  };
}

// Closed-loop verification: scan + lint + tests. Returns a single verdict
// with per-leg detail so the caller can render a precise summary.
//
// Returns:
//   {
//     ok: bool,
//     verdict: 'verified-clean' | 'verification-failed' | 'untested-but-passes',
//     legs: { scan: …, lint: …, tests: … },
//     summary: '<human-readable line>',
//   }
//
// The `untested-but-passes` verdict is real and intentional: scan+lint
// passed, but no test runner was found. This is honest signal — callers
// (the security-fixer agent, downstream MCP tools) can decide whether to
// require a stronger verdict.
export async function verifyFixWithTests({
  scanRoot,
  originalFindingStableId,
  files,
  depFileContents,
  runTests = true,
  testRunnerOverride,
  testTimeoutMs,
} = {}) {
  const scanLint = await verifyFix({ scanRoot, originalFindingStableId, files, depFileContents });
  const legs = {
    scan: { ok: scanLint.rescan?.ok ?? scanLint.ok, detail: scanLint.rescan ?? scanLint },
    lint: { ok: scanLint.lint?.ok ?? true, detail: scanLint.lint ?? null },
    tests: { ok: true, detail: null, skipped: true, reason: 'not-run' },
  };
  if (!legs.scan.ok || !legs.lint.ok) {
    return {
      ok: false,
      verdict: 'verification-failed',
      legs,
      summary: _summarize(legs, 'verification-failed'),
    };
  }
  if (runTests) {
    const tests = runProjectTests(scanRoot, { runnerOverride: testRunnerOverride, timeoutMs: testTimeoutMs });
    legs.tests = { ok: tests.ok, detail: tests, skipped: !!tests.skipped, reason: tests.reason };
  }
  const allOk = legs.scan.ok && legs.lint.ok && legs.tests.ok;
  const verdict = !allOk
    ? 'verification-failed'
    : (legs.tests.skipped ? 'untested-but-passes' : 'verified-clean');
  return { ok: allOk, verdict, legs, summary: _summarize(legs, verdict) };
}

function _summarize(legs, verdict) {
  const bits = [];
  bits.push(`scan: ${legs.scan.ok ? 'pass' : 'fail'}`);
  bits.push(`lint: ${legs.lint.skipped ? 'skip' : legs.lint.ok ? 'pass' : 'fail'}`);
  bits.push(`tests: ${legs.tests.skipped ? 'skip' : legs.tests.ok ? 'pass' : 'fail'}`);
  return `${verdict} (${bits.join(' · ')})`;
}
