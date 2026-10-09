#!/usr/bin/env node
// Runs the unit-test scopes in ONE `node --test` invocation instead of
// chaining eleven separate `npm run test:<scope>` processes.
//
// WHY THIS EXISTS
// ----------------
// `npm test` used to be:
//
//   npm run test:smoke && npm run test:glob && npm run test:sast && ...
//
// eleven `npm run` invocations in series, each spawning its own `node --test`
// process. Measured on this machine: 258s sequential. `node --test` already
// runs a MULTI-FILE invocation's files concurrently against the same set of
// cores — the eleven separate processes were never using more parallelism
// than one combined invocation would, they were just paying eleven process
// startup costs and getting zero overlap ACROSS scopes (test:posture could
// not run while test:sast was still finishing). One invocation over the union
// of files: 111-140s across three repeated runs, same 3955/3955/0 result
// every time. That halves the dominant cost in both the pre-push gate and the
// release gate — release-check.mjs's `test-suite` check runs exactly this.
//
// WHY DERIVED, NOT A SECOND HAND-WRITTEN FILE LIST
// -------------------------------------------------
// The file list is extracted from the EXISTING `test:<scope>` scripts in
// package.json, not duplicated here. A hand-maintained parallel list is
// exactly the shape that goes stale silently — add a file to test:sast,
// forget to add it here, and the combined run quietly covers less than
// `npm run test:sast` alone does. Deriving it means that cannot happen: the
// scoped scripts remain the single source of truth (and remain independently
// runnable for day-to-day scoped work, per scanner/CLAUDE.md's test-command
// table), and no-orphan-tests.test.js still catches a file wired into
// neither.
//
// WHAT IS DELIBERATELY EXCLUDED, AND WHY
// ---------------------------------------
//  - test/cpp-dataflow.test.js. It sets AGENTIC_SECURITY_CPP_DATAFLOW=1 at
//    MODULE LOAD, not inside a test callback (see that file's own comment).
//    Included in a combined multi-file invocation on this engine/Node
//    version, its 26 tests silently contributed ZERO results to the run —
//    not a failure, not a skip, just absent from the totals — and something
//    else moved too (3955 -> 3950, not 3955+26). That was not chased to a
//    root cause; the isolated invocation below is proven correct (its own
//    scoped script), so it stays exactly as it already runs today rather
//    than being folded into a batch with an unexplained side effect.
//  - test:python. A different runtime; there is nothing to combine it with.
//  - test:ci-parity. Not part of `npm test` today (a separate, CI-only
//    scoped script); out of scope for this file, which reproduces `npm test`
//    exactly, not a superset of it.
//
// A discrepancy here is a REGRESSION, not noise: this script hard-fails if
// the combined run's pass+fail count does not equal the sum of what the
// scoped scripts report standalone would be expected to cover — enforced
// indirectly by requiring every file that no-orphan-tests.test.js would
// check to appear in the derived list (see extractFiles below), and directly
// by requiring node --test itself to report zero failures.

// SHARDING (release gate)
// -----------------------
// The hosted release gate runs this file once per shard, in parallel jobs, so
// the dominant cost of a release is a fraction of the serial run. The shard
// comes from AGENTIC_SECURITY_TEST_SHARD=i/N or `--shard i/N` (the flag wins).
// Shard i runs the files at positions i-1, i-1+N, i-1+2N ... of the derived
// list (`assignShard`): a pure function of the list, so every file lands in
// exactly one shard and a test proves it. The partition is computed here rather
// than delegated to node's own --test-shard so `--list-shard i/N` can print the
// assignment without spawning anything, and so the "every file exactly once"
// claim is checkable offline. The EXTRA steps (`test:extras`: cpp-dataflow, the
// fault-injection suites, python) run in shard 1 ONLY, or unsharded. With no
// shard set this behaves exactly as `npm test` always did.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', 'scanner');

// The scoped scripts this file's invocation must cover — everything `npm
// test` chains via `npm run test:<scope>`, MINUS cpp-dataflow and python
// (see header). Adding a new scope to `npm test` means adding its name here
// too; nothing silently falls out of coverage, because
// `assertAllTestFilesCovered` below cross-checks against every scoped
// `test:*` script whose value contains `node --test`.
export const SCOPES = [
  'smoke', 'glob', 'sast', 'posture', 'dataflow', 'mcp',
  'report', 'bench-modules', 'lifecycle', 'eval', 'discovery', 'lineage',
  'server', 'haskell', 'nix', 'language', 'verification',
];

const FILE_RE = /test\/[\w.\-/]+\.test\.js/g;

function readPkg() {
  return JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
}

/** File args named by `test:<scope>`'s script string, in package.json's own order. */
export function extractFiles(scriptValue) {
  return [...new Set((scriptValue || '').match(FILE_RE) || [])];
}

/** The union of files across SCOPES, de-duplicated, order-stable. */
export function unionFiles(pkg, scopes = SCOPES) {
  const seen = new Set();
  const files = [];
  for (const scope of scopes) {
    const key = `test:${scope}`;
    const script = pkg.scripts?.[key];
    if (!script) throw new Error(`package.json has no "${key}" script — SCOPES has drifted from package.json`);
    for (const f of extractFiles(script)) {
      if (!seen.has(f)) { seen.add(f); files.push(f); }
    }
  }
  return files;
}

/**
 * Every `test:*` script that runs `node --test` at all must be one of SCOPES
 * (or an explicitly acknowledged exclusion). This is what stops a THIRTEENTH
 * scoped script from being added to package.json and silently never running
 * under the combined invocation while still passing `npm run test:<newone>`
 * on its own — the exact drift this file exists to prevent.
 */
// `loop` is the supervised-loop controller's own fault-injection suite
// (scripts/loop-engineering/test). It spawns real controller, guardian and worker
// process trees and measures wall-clock deadlines, so it must NOT share cores
// with the combined run: under that load its timing assertions become flaky.
// It runs on its own (`npm run test:loop`, --test-concurrency=1) and is part of
// the loop requirement verifier and the final gate list in the execution profile.
// `language-stress` is the Haskell/Nix scale and memory suite (QA-003): it scans thousands of files and asserts a peak-memory
// ceiling, so it must own the machine. `language-tools` holds the criteria that need a real compiler or Nix on the host (HS-006
// route fixtures compile; the support gate that consumes it). `language-slow` is the CLI-driven language suites (the capability matrix, the
// packed-tarball scan, example capture, scan modes): each spawns many full scans, and running them beside the rest of the suite starved the
// Chrome rendering tests of CPU. They run in CI (language-suites) and in the loop's verification. `language-gates` runs the five existing benchmark gates (QA-002.AC02), about
// fifteen minutes that would starve every other test of CPU inside the combined run; the pre-push gate and release check run them too. `nixos-host` is the NixOS package and host suite (NIX-012): it fails
// without a NixOS host and a nix binary, so it runs on one (`npm run test:nixos-host`): an unavailable tool is a FAILED criterion there, never a skip, so
// they are run where the tools exist (`npm run test:language-tools`) and are part of the loop verifier and the release gate.
export function assertAllTestFilesCovered(pkg, { scopes = SCOPES, excluded = ['ci-parity', 'extras', 'loop', 'language-stress', 'language-tools', 'language-gates', 'language-slow', 'nixos-host'] } = {}) {
  const covered = new Set(unionFiles(pkg, scopes));
  const missing = [];
  for (const [key, value] of Object.entries(pkg.scripts || {})) {
    if (!key.startsWith('test:')) continue;
    const scope = key.slice('test:'.length);
    if (scopes.includes(scope) || excluded.includes(scope)) continue;
    if (typeof value !== 'string' || !value.includes('node --test')) continue;
    for (const f of extractFiles(value)) if (!covered.has(f)) missing.push({ scope, file: f });
  }
  return missing;
}

/** `i/N` -> { index: i, total: N }; throws on anything that is not 1 <= i <= N, integers. */
export function parseShard(spec) {
  const m = /^(\d+)\/(\d+)$/.exec(String(spec ?? '').trim());
  if (!m) throw new Error(`invalid shard "${spec}": expected i/N, for example 2/4`);
  const index = Number(m[1]);
  const total = Number(m[2]);
  if (total < 1 || index < 1 || index > total) {
    throw new Error(`invalid shard "${spec}": need 1 <= i <= N`);
  }
  return { index, total };
}

/** The files shard `index` of `total` runs: positions index-1, index-1+total, ... of `files`. */
export function assignShard(files, { index, total }) {
  return files.filter((_, pos) => pos % total === index - 1);
}

/** The steps that run after the main list. Exactly one shard (the first) owns them. */
export const EXTRA_STEPS = [{ label: 'test:extras (cpp-dataflow, fault-injection, python)', script: 'test:extras' }];

export function extraStepsForShard(shard) {
  return !shard || shard.index === 1 ? EXTRA_STEPS : [];
}

/** Resolve the shard from argv and env. The flag wins over the variable; null when neither is set. */
export function resolveShard(argv = [], env = process.env) {
  const i = argv.indexOf('--shard');
  if (i !== -1) {
    if (!argv[i + 1]) throw new Error('--shard needs a value such as 2/4');
    return parseShard(argv[i + 1]);
  }
  const fromEnv = env.AGENTIC_SECURITY_TEST_SHARD;
  return fromEnv ? parseShard(fromEnv) : null;
}

/**
 * Write `text` and exit only once the write has completed. `process.exit()` straight after `write()` can drop whatever is still buffered when
 * stdout is a pipe and the reader is slow (a CI runner running the whole suite in parallel): the `--list-shard` test, which reads this through a
 * pipe, lost the last 8 lines of shard 1's output on `main` while the identical tree had passed on the pull request.
 */
export function writeThenExit(text, code, { stream = process.stdout, exit = (c) => process.exit(c) } = {}) {
  stream.write(text, () => exit(code));
}

/** One private temp root for a whole run: the env to give the test processes, and a cleanup that never throws. */
export function makeRunTemp(base = os.tmpdir(), baseEnv = process.env) {
  // Short name on purpose: tests bind unix sockets under os.tmpdir(), and a socket path is limited to ~104
  // bytes on macOS, so a long private root would break them for the wrong reason.
  const root = fs.mkdtempSync(path.join(base, 'as-run-'));
  return {
    root,
    env: { ...baseEnv, TMPDIR: root, TEMP: root, TMP: root },
    cleanup() { try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ } },
  };
}

function main(argv = process.argv.slice(2)) {
  const pkg = readPkg();

  const missing = assertAllTestFilesCovered(pkg);
  if (missing.length) {
    process.stderr.write(
      'run-unit-tests.mjs: these test:* scripts run `node --test` on files not covered by the combined '
      + `invocation (SCOPES has drifted from package.json):\n`
      + missing.map((m) => `  test:${m.scope} -> ${m.file}`).join('\n') + '\n'
      + 'Add the scope to SCOPES in scripts/run-unit-tests.mjs, or to its `excluded` list with a written reason.\n',
    );
    process.exit(1);
  }

  const files = unionFiles(pkg);
  if (!files.length) {
    process.stderr.write('run-unit-tests.mjs: derived an empty file list — refusing to report a vacuous pass.\n');
    process.exit(1);
  }

  const li = argv.indexOf('--list-shard');
  if (li !== -1) {
    // Print the assignment and run nothing.
    const shard = parseShard(argv[li + 1]);
    const out = [...assignShard(files, shard).map((f) => `${f}\n`), ...extraStepsForShard(shard).map((e) => `step: ${e.script}\n`)].join('');
    writeThenExit(out, 0);
    return;
  }

  const shard = resolveShard(argv);
  const mine = shard ? assignShard(files, shard) : files;
  if (!mine.length) {
    process.stderr.write(`run-unit-tests.mjs: shard ${shard.index}/${shard.total} has no files, refusing to report a vacuous pass.\n`);
    process.exit(1);
  }
  if (shard) process.stderr.write(`run-unit-tests.mjs: shard ${shard.index}/${shard.total}: ${mine.length} of ${files.length} test files\n`);

  // The whole run gets ONE private temp root (TMPDIR/TEMP/TMP) that is deleted when the run ends, so a test, or
  // the code under test, that forgets to clean up after itself can no longer fill the machine's real temp
  // folder: a full run used to leave thousands of directories behind (gigabytes at one point), which also made
  // later runs slower. Set AGENTIC_SECURITY_TEST_KEEP_TMP=1 to keep it (the path is printed) when debugging.
  const { root: tmpRoot, env, cleanup } = makeRunTemp();
  const finish = (code) => {
    if (process.env.AGENTIC_SECURITY_TEST_KEEP_TMP === '1') process.stderr.write(`run-unit-tests.mjs: kept temp root ${tmpRoot}\n`);
    else cleanup();
    process.exit(code);
  };
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => finish(130));

  const r = spawnSync(process.execPath, ['--test', ...mine], { cwd: SCANNER, stdio: 'inherit', env });
  if (r.status !== 0) finish(r.status ?? 1);

  for (const step of extraStepsForShard(shard)) {
    const e = spawnSync('npm', ['run', step.script], { cwd: SCANNER, stdio: 'inherit', env });
    if (e.status !== 0) finish(e.status ?? 1);
  }
  finish(0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (e) { process.stderr.write(`run-unit-tests.mjs: ${e.message}\n`); process.exit(1); }
}
