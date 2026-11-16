// Run the project's tests against the PATCHED tree, in a throwaway copy (E3-05).
//
// verifyFix used to run the tests on the tree as it was before the patch was written, which says nothing about the patch. Here the
// patch is overlaid on a copy and the tests run there; the real tree is never touched.
//
// Runner discovery covers what the existing detector does (npm/pnpm/yarn/bun scripts, pytest, go test) plus cargo, dotnet, maven,
// gradle and rspec, and an explicit argv from the caller (`command`) which always wins. Commands are argv arrays, never a shell string.
// Both trees run and the verdict is the per-test delta (verified-remediation PRD FR-02, test-results.js); an exit-code-only runner keeps the
// older shape, with the two failures compared by signature so a DIFFERENT failure is never excused as "already red".
import { spawnSync } from 'node:child_process';
import { superviseSpawn } from '../sandbox/supervise.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { detectTestCommand } from '../posture/test-runner.js';
import { STATE_DIR_NAME } from '../posture/state-dir.js';
import { NODE_TEST_REPORTER, parseNodeTestReport, parseJestReport, parseVitestReport, exitCodeUnit, compareTestRuns, testSurfaceChanges, adapterFor } from './test-results.js';

const MAX_COPY_BYTES = 200 * 1024 * 1024;
const SKIP_DIRS = new Set(['.git', STATE_DIR_NAME, 'node_modules', 'target', 'dist', 'build', '.venv', '__pycache__', 'bin', 'obj']);
const DEFAULT_TIMEOUT_MS = 300_000;

const has = (root, rel) => { try { return fs.existsSync(path.join(root, rel)); } catch { return false; } };
const available = (cmd) => { try { const r = spawnSync(cmd, ['--version'], { timeout: 8000, stdio: 'ignore' }); return !(r.error && r.error.code === 'ENOENT'); } catch { return false; } };

/** @returns {{cmd:string,args:string[],kind:string}|null} */
export function discoverTestCommand(root, { available: avail = available } = {}) {
  const base = detectTestCommand(root);
  if (base) return base;
  if (has(root, 'Cargo.toml') && avail('cargo')) return { cmd: 'cargo', args: ['test', '--quiet'], kind: 'cargo' };
  try { if (fs.readdirSync(root).some((f) => /\.(sln|csproj)$/.test(f)) && avail('dotnet')) return { cmd: 'dotnet', args: ['test', '--nologo'], kind: 'dotnet' }; } catch { /* unreadable root */ }
  if (has(root, 'pom.xml') && avail('mvn')) return { cmd: 'mvn', args: ['-q', 'test'], kind: 'maven' };
  if ((has(root, 'build.gradle') || has(root, 'build.gradle.kts')) && avail('gradle')) return { cmd: 'gradle', args: ['test', '--quiet'], kind: 'gradle' };
  if ((has(root, '.rspec') || has(root, 'spec')) && has(root, 'Gemfile') && avail('bundle')) return { cmd: 'bundle', args: ['exec', 'rspec'], kind: 'rspec' };
  return null;
}

function copyTree(root, dest) {
  let bytes = 0;
  fs.cpSync(root, dest, {
    recursive: true, dereference: false, verbatimSymlinks: true,
    filter: (src) => {
      const rel = path.relative(root, src);
      if (!rel) return true;
      if (rel.split(path.sep).some((s) => SKIP_DIRS.has(s))) return false;
      try { const st = fs.lstatSync(src); if (st.isFile()) { bytes += st.size; if (bytes > MAX_COPY_BYTES) throw new Error('tree-too-large'); } } catch (e) { if (e.message === 'tree-too-large') throw e; }
      return true;
    },
  });
  // dependencies are linked, not copied: tests need them, and the copy must not be able to change them
  const nm = path.join(root, 'node_modules');
  if (fs.existsSync(nm)) { try { fs.symlinkSync(nm, path.join(dest, 'node_modules'), 'dir'); } catch { /* best effort */ } }
}

// Supervised (sandbox/supervise.js): the suite runs in its own process group and every descendant is ended when it exits or times out, with
// survivors reported. spawnSync's timeout signalled only npm, which traps SIGTERM and exits 143, so a hung test both read as an ordinary
// failure and could leave its node process running.
async function run(cwd, cmd, args, timeoutMs, extraEnv = {}) {
  const t0 = Date.now();
  // NODE_TEST_CONTEXT is the verifier's own test-runner context (set when it runs under node --test): inherited, it makes the project's
  // runner stream to a parent that is not listening instead of reporting, so the project would appear to run no tests.
  const { NODE_TEST_CONTEXT, ...inherited } = process.env;
  const r = await superviseSpawn(cmd, args, { cwd, env: { ...inherited, CI: '1', ...extraEnv }, timeoutMs, maxOutputBytes: 16 * 1024 * 1024 });
  const durationMs = Date.now() - t0;
  const output = `${r.stdout || ''}\n${r.stderr || ''}`;
  const termination = { survivors: r.termination?.survivors || [], signalled: r.termination?.signalled || null };
  if (r.spawnError && /ENOENT/.test(r.spawnError)) return { status: 'skipped', passed: null, skipped: true, reason: `${cmd}-not-installed`, exitCode: null, timedOut: false, durationMs, output, termination };
  if (r.spawnError) return { status: 'skipped', passed: null, skipped: true, reason: `spawn-failed: ${r.spawnError}`, exitCode: null, timedOut: false, durationMs, output, termination };
  if (r.timedOut) return { status: 'failed', passed: false, skipped: false, reason: 'timed-out', exitCode: r.exitCode, timedOut: true, durationMs, output, termination };
  if (r.outputCapped) return { status: 'failed', passed: false, skipped: false, reason: 'output-limit-exceeded', exitCode: r.exitCode, timedOut: false, durationMs, output, termination };
  const code = r.exitCode;
  return { status: code === 0 ? 'passed' : 'failed', passed: code === 0, skipped: false, reason: code === 0 ? null : `exit-${code ?? r.exitSignal}`, exitCode: code, timedOut: false, durationMs, output, termination };
}

const readPkgScript = (root) => { try { return JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))?.scripts?.test ?? null; } catch { return null; } };

// One execution of the suite on one tree, through the adapter: the run plus its parsed per-test report.
async function execute(tree, spec, adapter, work, label, timeoutMs) {
  let args = spec.args; const env = {};
  const reportFile = path.join(work, `${label}.report`);
  if (adapter === 'node-test') {
    const reporter = path.join(work, 'reporter.mjs');
    fs.writeFileSync(reporter, NODE_TEST_REPORTER); // the verifier's own module in its own temporary directory
    env.AS_TEST_REPORT_OUT = reportFile;
    env.NODE_OPTIONS = `${process.env.NODE_OPTIONS ? `${process.env.NODE_OPTIONS} ` : ''}--test-reporter=${reporter} --test-reporter-destination=${path.join(work, `${label}.unused`)}`;
  } else if (adapter === 'jest' || adapter === 'vitest') {
    const extra = adapter === 'jest' ? ['--json', `--outputFile=${reportFile}`] : ['--reporter=json', `--outputFile=${reportFile}`];
    args = ['npm', 'pnpm', 'yarn'].includes(spec.kind) ? [...spec.args.filter((a) => a !== '--silent'), '--', ...extra] : [...spec.args, ...extra];
  }
  const r = await run(tree, spec.cmd, args, timeoutMs, env);
  let report = null;
  if (adapter !== 'exit-code' && !r.skipped) {
    let text = null; try { text = fs.readFileSync(reportFile, 'utf8'); } catch { text = null; }
    if (text === null) report = { adapter, complete: false, malformed: 0, tests: [], missing: true };
    let root = tree; try { root = fs.realpathSync(tree); } catch { /* keep the given path */ }
    const parse = adapter === 'node-test' ? parseNodeTestReport : adapter === 'jest' ? parseJestReport : parseVitestReport;
    const a = parse(text, { root }); const b = root === tree ? a : parse(text, { root: tree });
    // whichever spelling of the tree the runner reported, ids are relative to it
    report = a.tests.every((t) => !t.file.startsWith('/')) ? a : b;
  }
  return { ...r, report };
}

const strip = ({ output, report, ...rest }) => rest;
const deltaView = (d) => ({ verdict: d.verdict, attribution: d.attribution, adapter: d.adapter, reasons: d.reasons, counts: d.counts,
  newlyFailing: d.newlyFailing.slice(0, 50), changedFailure: d.changedFailure.slice(0, 50), removed: d.removed.slice(0, 50), newlySkipped: d.newlySkipped.slice(0, 50),
  preExisting: d.preExisting.slice(0, 50), fixed: d.fixed.slice(0, 50), added: d.added.slice(0, 50), flaky: d.flaky.slice(0, 50), requiredBaselineFailing: d.requiredBaselineFailing.slice(0, 50) });

/**
 * Run the tests on the original tree and on the patched tree, and judge the patch by the per-test delta (FR-02).
 *
 * @param {{scanRoot:string, files:Record<string,string>, command?:string[], timeoutMs?:number, required?:(string|RegExp)[], flaky?:(string|RegExp)[]}} o
 * @returns {object} status passed|failed|skipped, plus `testDelta` (the comparison), `testSurface` (protected test files the patch touched),
 *   `adapter`, `attribution` and the legacy fields (passed, skipped, reason, exitCode, timedOut, onPatchedTree, preExistingFailure).
 *   `preExistingFailure` is true ONLY when an exit-code-only suite failed identically on both trees; a different failure is `failed`.
 */
export async function runTestsOnPatchedCopy({ scanRoot, files, command, timeoutMs = DEFAULT_TIMEOUT_MS, required = [], flaky = [] }) {
  const spec = command && command.length ? { cmd: command[0], args: command.slice(1), kind: 'explicit' } : discoverTestCommand(scanRoot);
  const base = { exitCode: null, timedOut: false, durationMs: 0, onPatchedTree: false, preExistingFailure: false };
  if (!spec) return { ...base, status: 'skipped', passed: null, skipped: true, reason: 'no-test-command-detected' };
  const readOrig = (rel) => { try { return fs.readFileSync(path.join(scanRoot, rel), 'utf8'); } catch { return null; } };
  // A patch may not earn acceptance by editing the tests that judge it, the runner configuration or the test script.
  const testSurface = testSurfaceChanges(files, readOrig);
  if (testSurface.blocked.length) return { ...base, status: 'failed', passed: false, skipped: false, reason: `patch-modifies-protected-test-surface: ${testSurface.blocked.map((b) => `${b.file} (${b.reason})`).join('; ')}`, testSurface, runner: spec.kind };
  const adapter = adapterFor(spec, readPkgScript(scanRoot));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'patched-tests-'));
  try {
    const patched = path.join(work, 'patched');
    try { copyTree(scanRoot, patched); } catch (e) { return { ...base, status: 'skipped', passed: null, skipped: true, reason: e.message === 'tree-too-large' ? 'tree-too-large-to-copy' : `copy-failed: ${e.message}` }; }
    for (const [rel, text] of Object.entries(files || {})) {
      const abs = path.resolve(patched, rel);
      if (abs !== patched && !abs.startsWith(patched + path.sep)) return { ...base, status: 'skipped', passed: null, skipped: true, reason: 'patch-path-escapes-the-copy' };
      if (text === null) { fs.rmSync(abs, { force: true }); continue; }
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, String(text));
    }
    const pristine = path.join(work, 'pristine');
    const after = await execute(patched, spec, adapter, work, 'patched', timeoutMs);
    const common = { runner: spec.kind, adapter, onPatchedTree: true, testSurface, exitCode: after.exitCode, timedOut: after.timedOut, durationMs: after.durationMs };
    if (after.skipped) return { ...base, ...strip(after), ...common };
    if (adapter === 'exit-code') {
      // Exit-code attribution: the pristine tree runs only when the patched one failed, and the two failures are compared by signature.
      if (after.status === 'passed') return { ...strip(after), ...common, preExistingFailure: false, attribution: 'suite-only' };
      let before;
      try { copyTree(scanRoot, pristine); before = await execute(pristine, spec, adapter, work, 'pristine', timeoutMs); } catch (e) { return { ...strip(after), ...common, attribution: 'suite-only', reason: `${after.reason}; the original tree could not be run for attribution (${e.message})` }; }
      const delta = compareTestRuns(exitCodeUnit({ ...before, roots: [pristine, work] }), exitCodeUnit({ ...after, roots: [patched, work] }));
      if (delta.verdict === 'failed') return { ...strip(after), ...common, preExistingFailure: false, attribution: 'suite-only', testDelta: deltaView(delta), baseline: strip(before), reason: `${after.reason}: ${delta.reasons[0]}` };
      return { ...strip(after), ...common, status: 'failed', passed: false, attribution: 'suite-only', preExistingFailure: true, testDelta: deltaView(delta), baseline: strip(before) };
    }
    copyTree(scanRoot, pristine);
    const before = await execute(pristine, spec, adapter, work, 'pristine', timeoutMs);
    if (before.skipped) return { ...base, ...strip(before), ...common, status: 'skipped', passed: null, skipped: true, reason: `the original tree could not run its tests (${before.reason})` };
    const policy = { required, flaky };
    const delta = compareTestRuns(before.report, after.report, policy);
    const failingInReport = after.report.tests.filter((t) => ['failed', 'timeout', 'error', 'cancelled'].includes(t.outcome)).length;
    if (delta.verdict === 'passed' && after.exitCode !== 0 && failingInReport === 0) {
      delta.verdict = 'inconclusive';
      delta.reasons.push(`the runner exited ${after.timedOut ? 'by timeout' : after.exitCode} on the patched tree with no failing test in its report (a build or load failure outside the tests)`);
    }
    if (after.timedOut && delta.verdict === 'passed') { delta.verdict = 'inconclusive'; delta.reasons.push('the patched run hit its time limit'); }
    const view = deltaView(delta);
    const rest = { ...common, attribution: delta.attribution, testDelta: view, baseline: { ...strip(before) } };
    if (delta.verdict === 'passed') return { ...base, ...rest, status: 'passed', passed: true, skipped: false, reason: delta.preExisting.length ? `passed; ${delta.preExisting.length} unchanged pre-existing failure(s) recorded, not required` : null };
    if (delta.verdict === 'failed') return { ...base, ...rest, status: 'failed', passed: false, skipped: false, reason: `test-delta: ${delta.reasons.join('; ')}` };
    return { ...base, ...rest, status: 'skipped', passed: null, skipped: true, reason: `tests-inconclusive: ${delta.reasons.join('; ')}` };
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
}
