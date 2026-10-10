// Shared body of the protected suite wrappers (PRD section 11.1 step 4).
//
// A wrapper does NOT assert that files exist and does NOT re-implement the tests.
// It runs the REAL scoped test files for its suite in a bounded subprocess, reads
// the child's TAP stream, and re-emits every child test as one top-level test of
// its own with the child's name unchanged. The controller's verifier then sees the
// per-criterion `[ID.ACnn]` names it keys on, and a skipped or todo child stays
// skipped or todo (which fails its criterion; nothing here upgrades it).
//
// Fail-closed rules, each covered by a test in the loop suite:
//   - a child that exits non-zero, times out, or runs zero tests fails an
//     untagged "child run" test, so the suite as a whole cannot pass;
//   - an unparseable or empty file list fails instead of selecting nothing;
//   - the child's full output is digested and its tail is printed as TAP
//     comments, so the controller's retained log is authentic and bounded.
//
// This helper is not a registered protected file, so every wrapper pins its digest
// (expectHelper). A wrapper is frozen at `init`; a changed helper therefore makes
// the wrapper fail instead of silently changing what "pass" means.
import test from 'node:test';
import assert from 'node:assert/strict';
import { availableParallelism } from 'node:os';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { basename, dirname, join, resolve } from 'node:path';
import { parseTap } from '../../loop-engineering/lib/tap.mjs';
import { runLeasedChildren } from '../../loop-engineering/lib/child-leases.mjs';
import { suiteBounds } from '../../loop-engineering/lib/bounds.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(HERE, '..', '..', '..');
const SCANNER = join(REPO, 'scanner');
const TAIL_BYTES = 200 * 1024;
const FILE_RE = /test\/[\w.\-/]+\.test\.js/g;

export const sha256 = (b) => createHash('sha256').update(b).digest('hex');
export const helperSha256 = () => sha256(readFileSync(fileURLToPath(import.meta.url)));

/** Test files named by scanner/package.json script `test:<scope>`, in the script's own order. */
export function filesOfScript(scope) {
  const pkg = JSON.parse(readFileSync(join(SCANNER, 'package.json'), 'utf8'));
  const value = pkg.scripts?.[`test:${scope}`];
  if (typeof value !== 'string') throw new Error(`scanner/package.json has no "test:${scope}" script`);
  return [...new Set(value.match(FILE_RE) || [])];
}

/**
 * Run `files` (relative to scanner/) with the node test runner, ONE CHILD PER FILE, each under its own finite lease inside the suite's
 * ceiling (LOOP-002). A child that outlives its lease is killed as a process group and the result names the file. Returns the parsed result.
 * `ceilingMs` bounds the whole set and `leaseMs` each file; the children may run side by side up to `concurrency`.
 */
export async function runChildren(files, { ceilingMs, leaseMs, concurrency = Math.max(1, Math.min(4, availableParallelism() - 1)) }) {
  // NODE_TEST_CONTEXT marks "already inside a test run"; inherited, it makes the child runner refuse to run files and report zero tests (runBounded removes it).
  const lr = await runLeasedChildren({
    files, argvFor: (f) => [process.execPath, '--test', '--test-reporter=tap', f], cwd: SCANNER, env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' },
    ceilingSeconds: ceilingMs / 1000, childLeaseSeconds: leaseMs / 1000, graceMs: 2000, concurrency, label: 'wrapper-child',
  });
  const out = lr.children.map((c) => `${c.stdoutTail || ''}${c.stderrTail ? `\n--- stderr (${c.file}) ---\n${c.stderrTail}` : ''}`).join('\n');
  const tests = lr.children.flatMap((c) => parseTap(c.stdoutTail || '').tests);
  const spawnFailed = lr.children.find((c) => c.outcome === 'spawn-failed');
  return {
    status: lr.exitCode, signal: lr.children.find((c) => c.signal)?.signal ?? null, timedOut: lr.hung.length > 0 || lr.children.some((c) => c.outcome === 'not-run'),
    hung: lr.hung, children: lr.children, lease: lr.lease, ceilingSeconds: lr.ceilingSeconds,
    spawnError: spawnFailed ? String(spawnFailed.reason) : null, out, tap: { tests, summary: {} },
  };
}

/**
 * Register the wrapper's tests. Call once, at top level of the wrapper, with:
 *   suite           the registered suite key
 *   files | scope   explicit files (relative to scanner/) or the `test:<scope>` script that names them
 *   expectHelper    the helper digest the wrapper was frozen against
 *
 * The whole set's wall limit is the suite's own timeoutSeconds from the execution profile, less a margin so the wrapper can still report a
 * timeout instead of being killed by the controller first. Each file is a child with its own lease from the suite class (limits.suiteCeilings),
 * never more than what is left of that ceiling. `bounds` overrides both, for the wrapper's own tests only.
 */
export async function relaySuite({ suite, files, scope, expectHelper, bounds = null }) {
  if (helperSha256() !== expectHelper) {
    test(`[${suite}] the shared wrapper helper matches the digest this wrapper was frozen against`, () => {
      assert.fail(`relay.mjs changed (now ${helperSha256()}); the supervising session must review it and re-pin every wrapper`);
    });
    return;
  }
  let list = null;
  try { list = files ?? filesOfScript(scope); } catch (e) { test(`[${suite}] the suite names its test files`, () => assert.fail(e.message)); }
  if (!list) return;
  test(`[${suite}] the suite names at least one real test file`, () => {
    assert.ok(list.length > 0, 'an empty selection never passes');
    for (const f of list) assert.ok(existsSync(join(SCANNER, f)), `missing test file scanner/${f}`);
  });
  if (!list.length || list.some((f) => !existsSync(join(SCANNER, f)))) return;

  const profile = JSON.parse(readFileSync(join(REPO, 'scripts', 'loop-engineering', 'profiles', 'assurance-differentiation.json'), 'utf8'));
  const timeoutSeconds = profile.suites?.[suite]?.timeoutSeconds ?? 120;
  const sb = suiteBounds(profile, suite);
  const ceilingMs = bounds?.ceilingSeconds ? bounds.ceilingSeconds * 1000 : Math.max(1000, Math.min(timeoutSeconds - 10, sb?.ceilingSeconds ?? Infinity) * 1000);
  const leaseMs = bounds?.childLeaseSeconds ? bounds.childLeaseSeconds * 1000 : Math.min(ceilingMs, (sb?.childLeaseSeconds ?? timeoutSeconds) * 1000);
  const child = await runChildren(list, { ceilingMs, leaseMs, concurrency: bounds?.concurrency });
  const digest = sha256(child.out);
  const tail = child.out.length > TAIL_BYTES ? child.out.slice(-TAIL_BYTES) : child.out;
  process.stdout.write(`# child run: ${list.length} file(s), exit ${child.status}, signal ${child.signal}, ${child.tap.tests.length} test line(s), output sha256 ${digest}, ${child.out.length} bytes\n`);
  process.stdout.write(`# child leases: ${child.lease}s per file inside a ${child.ceilingSeconds}s ceiling; ${child.children.map((c) => `${c.file}=${c.outcome}`).join(', ')}\n`);
  process.stdout.write(`${tail.split('\n').map((l) => `# | ${l}`).join('\n')}\n`);

  // The node runner reports a file that registered no tests as one passing entry named after the file. That is not a test.
  const isFileEntry = (t) => t.depth === 0 && list.some((f) => t.name === f || t.name === basename(f) || t.name.endsWith(`/${basename(f)}`));
  const realTests = child.tap.tests.filter((t) => !isFileEntry(t));
  test(`[${suite}] the child run exited 0, ran tests, and was not cut short`, () => {
    assert.equal(child.spawnError, null, `could not start the test runner: ${child.spawnError}`);
    assert.equal(child.timedOut, false, `the child run timed out and was killed: ${child.children.filter((c) => c.outcome !== 'exited').map((c) => `${c.file} (${c.outcome})`).join(', ')}`);
    assert.equal(child.signal, null, `the child run was ended by ${child.signal}`);
    assert.equal(child.status, 0, `the child run exited ${child.status}`);
    assert.ok(realTests.length > 0, 'the child ran zero tests; an empty selection fails');
  });
  // One witness per file, so a hung or unstarted file is named in the result instead of vanishing into the aggregate.
  for (const c of child.children) {
    test(`[${suite}] ${c.file} finished within its lease`, () => assert.equal(c.outcome === 'exited', true, `${c.reason || c.outcome} (lease ${c.leaseSeconds}s of a ${child.ceilingSeconds}s ceiling)`));
  }
  for (const t of child.tap.tests) {
    const name = t.name || '(unnamed test)';
    if (isFileEntry(t) && t.ok) test(`[${suite}] ${name} registered at least one test`, () => assert.fail(`${name} ran no tests; an empty file is not a pass`));
    else if (t.skip) test(name, { skip: 'skipped in the child run' }, () => {});
    else if (t.todo) test(name, { todo: 'todo in the child run' }, () => {});
    else test(name, () => { assert.ok(t.ok, `failed in the child run (suite ${suite}); see the retained output tail, sha256 ${digest}`); });
  }
}
