// Pre-push gate — unit tests for the pure decision functions.
//
// See scripts/pre-push-gate.mjs for the full design rationale. The shape
// mirrors test/release-check.test.js on purpose: the I/O + child-process path
// is proven by hand (clean tree passes, deliberately broken tree fails, both
// directions with exit codes captured) and recorded in the change report;
// these tests pin the decision logic on constructed inputs so a refactor
// cannot quietly loosen the gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHECKS,
  orderedCheckIds,
  parsePushRefs,
  decidePushScope,
  evaluateCheckOutcome,
  evaluateHookActivation,
  summarize,
  HOOKS_PATH,
  envWithoutGitContext,
  evaluateWorktreeMatchesPush,
  evaluatePushBlastRadius,
} from '../../scripts/pre-push-gate.mjs';

const ZERO = '0'.repeat(40);
const A = 'a'.repeat(40);
const B = 'b'.repeat(40);

// ------------------------------------------------------------ ref parsing
test('pre-push-gate — parses a single well-formed ref line', () => {
  const { refs, malformed } = parsePushRefs(
    `refs/heads/main ${A} refs/heads/main ${B}\n`);
  assert.equal(malformed.length, 0);
  assert.deepEqual(refs, [{
    localRef: 'refs/heads/main',
    localSha: A,
    remoteRef: 'refs/heads/main',
    remoteSha: B,
  }]);
});

test('pre-push-gate — parses several ref lines and ignores blank lines', () => {
  const { refs } = parsePushRefs(
    `refs/heads/main ${A} refs/heads/main ${B}\n\nrefs/heads/x ${B} refs/heads/x ${ZERO}\n`);
  assert.equal(refs.length, 2);
  assert.equal(refs[1].localRef, 'refs/heads/x');
});

test('pre-push-gate — a malformed line is reported, never silently dropped', () => {
  const { refs, malformed } = parsePushRefs(`refs/heads/main ${A}\n`);
  assert.equal(refs.length, 0);
  assert.equal(malformed.length, 1);
  assert.match(malformed[0], /refs\/heads\/main/);
});

// ------------------------------------------------------------ push scope
test('pre-push-gate — a normal update of an existing branch is gated', () => {
  const d = decidePushScope([{ localRef: 'refs/heads/main', localSha: A, remoteRef: 'refs/heads/main', remoteSha: B }]);
  assert.equal(d.shouldRun, true);
  assert.equal(d.gated.length, 1);
});

test('pre-push-gate — a brand-new branch (zero remote sha) is gated', () => {
  const d = decidePushScope([{ localRef: 'refs/heads/feat', localSha: A, remoteRef: 'refs/heads/feat', remoteSha: ZERO }]);
  assert.equal(d.shouldRun, true);
  assert.equal(d.gated.length, 1);
});

test('pre-push-gate — a delete (zero local sha) is not gated', () => {
  const d = decidePushScope([{ localRef: '(delete)', localSha: ZERO, remoteRef: 'refs/heads/old', remoteSha: A }]);
  assert.equal(d.shouldRun, false);
  assert.equal(d.gated.length, 0);
  assert.match(d.reason, /delet/i);
});

test('pre-push-gate — a ref with no new commits (local == remote) is not gated', () => {
  const d = decidePushScope([{ localRef: 'refs/heads/main', localSha: A, remoteRef: 'refs/heads/main', remoteSha: A }]);
  assert.equal(d.shouldRun, false);
  assert.equal(d.gated.length, 0);
  assert.match(d.reason, /no new commits/i);
});

test('pre-push-gate — sha comparison is case-insensitive', () => {
  const d = decidePushScope([{ localRef: 'refs/heads/main', localSha: A.toUpperCase(), remoteRef: 'refs/heads/main', remoteSha: A }]);
  assert.equal(d.shouldRun, false);
});

test('pre-push-gate — one gatable ref among skippable ones still gates', () => {
  const d = decidePushScope([
    { localRef: '(delete)', localSha: ZERO, remoteRef: 'refs/heads/old', remoteSha: A },
    { localRef: 'refs/heads/main', localSha: A, remoteRef: 'refs/heads/main', remoteSha: A },
    { localRef: 'refs/heads/feat', localSha: B, remoteRef: 'refs/heads/feat', remoteSha: ZERO },
  ]);
  assert.equal(d.shouldRun, true);
  assert.deepEqual(d.gated.map(r => r.localRef), ['refs/heads/feat']);
});

test('pre-push-gate — no refs at all means nothing to push, so nothing to gate', () => {
  const d = decidePushScope([]);
  assert.equal(d.shouldRun, false);
  assert.match(d.reason, /nothing to push/i);
});

// ------------------------------------------------------------ ordering
test('pre-push-gate — checks run cheapest-first: the guards and bundle integrity precede the suites', () => {
  // The two leading guards answer "is the thing I am about to spend two minutes
  // measuring actually the thing being pushed?", so they come before everything.
  // `ci-parity` sits between package-contents and test-suite deliberately: it
  // runs only the env-sensitive subset (~45 s) against the full suite's ~4 min,
  // so under cheapest-first it precedes the suite. It exists because on
  // 2026-08-19 eight assertions passed this gate and then failed in hosted CI —
  // no local step set CI=1, so no local step could see it.
  const ids = orderedCheckIds();
  assert.deepEqual(ids, [
    'worktree-matches-push', 'push-blast-radius',
    'bundle-integrity', 'package-contents', 'ci-parity', 'test-suite', 'corpus-gate', 'self-scan-gate',
    'mutation-gate', 'provenance-accuracy-gate', 'layer-recall-gate',
  ]);
});

// Task 8 (Finding Provenance second-audit remediation). An independent PRD
// audit found bench:provenance-accuracy:check reachable from no gate at all,
// so its 12/13 known-origin-accuracy number could silently rot forever.
test('pre-push-gate — provenance-accuracy gate is present, cheap enough to sit before layer-recall', () => {
  const provenance = CHECKS.find(c => c.id === 'provenance-accuracy-gate');
  assert.ok(provenance, 'provenance-accuracy-gate must be a registered pre-push check');
  assert.equal(provenance.npmScript, 'bench:provenance-accuracy:check');
  // Measured this session: ~9s, well under layer-recall's ~11.5s.
  const ids = orderedCheckIds();
  assert.ok(ids.indexOf('mutation-gate') < ids.indexOf('provenance-accuracy-gate'),
    'mutation-gate (~0.85s) must run before provenance-accuracy-gate (~9s)');
  assert.ok(ids.indexOf('provenance-accuracy-gate') < ids.indexOf('layer-recall-gate'),
    'provenance-accuracy-gate (~9s) must run before layer-recall-gate (~11.5s)');
});

// M2 (Stage-0 audit, 2026). bench:mutation:check and bench:layer-recall:check
// were both built with both-direction verification recorded, but neither was
// reachable from pre-push, release-check, or any CI workflow — a repo-wide
// grep found the npm script names only in package.json and documentation.
// Both gates protected nothing that would actually stop a regressed push.
test('pre-push-gate — mutation and layer-recall gates are present, cheapest of the two first', () => {
  const mutation = CHECKS.find(c => c.id === 'mutation-gate');
  const layerRecall = CHECKS.find(c => c.id === 'layer-recall-gate');
  assert.ok(mutation, 'mutation-gate must be a registered pre-push check');
  assert.equal(mutation.npmScript, 'bench:mutation:check');
  assert.ok(layerRecall, 'layer-recall-gate must be a registered pre-push check');
  assert.equal(layerRecall.npmScript, 'bench:layer-recall:check');
  // Measured this session: mutation ~0.85s, layer-recall ~11.5s (forces deep
  // mode on all 210 corpus entries) — mutation goes first.
  const ids = orderedCheckIds();
  assert.ok(ids.indexOf('mutation-gate') < ids.indexOf('layer-recall-gate'),
    'the cheaper gate (mutation) must run before the pricier one (layer-recall)');
});

test('pre-push-gate — every check declares a title and a remedy', () => {
  for (const c of CHECKS) {
    assert.ok(c.title, `${c.id} has no title`);
    assert.ok(c.remedy, `${c.id} has no remedy`);
  }
});

test('pre-push-gate — the network-dependent publish checks are deliberately absent', () => {
  const ids = orderedCheckIds();
  for (const absent of ['dependency-currency', 'remote-ci-green', 'head-pushed']) {
    assert.ok(!ids.includes(absent), `${absent} must not run on push`);
  }
});

// ------------------------------------------------------------ outcomes
test('pre-push-gate — exit code 0 is the only pass', () => {
  assert.equal(evaluateCheckOutcome({ label: 'npm test', exitCode: 0 }).ok, true);
});

test('pre-push-gate — a non-zero exit fails and names the command', () => {
  const r = evaluateCheckOutcome({ label: 'npm test', exitCode: 1 });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /npm test/);
  assert.match(r.errors[0], /exited 1/);
});

test('pre-push-gate — a check that could not run is a FAILURE, never a skip', () => {
  const r = evaluateCheckOutcome({ label: 'npm run bench:self-scan:check', exitCode: null });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /could not be run/i);
  assert.match(r.errors[0], /not a passing gate/i);
});

test('pre-push-gate — a missing npm script surfaces as unrunnable-is-failure too', () => {
  const r = evaluateCheckOutcome({ label: 'npm run nope', exitCode: undefined });
  assert.equal(r.ok, false);
});

// ------------------------------------------------------------ activation
test('pre-push-gate — correct hooksPath is active, no warning', () => {
  const r = evaluateHookActivation({ configuredHooksPath: HOOKS_PATH });
  assert.equal(r.active, true);
  assert.equal(r.warnings.length, 0);
});

test('pre-push-gate — unset hooksPath warns loudly with the activation command', () => {
  const r = evaluateHookActivation({ configuredHooksPath: null });
  assert.equal(r.active, false);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /core\.hooksPath/);
  assert.match(r.warnings[0], new RegExp(HOOKS_PATH));
});

test('pre-push-gate — a hooksPath pointing elsewhere also warns', () => {
  const r = evaluateHookActivation({ configuredHooksPath: '.git/hooks' });
  assert.equal(r.active, false);
  assert.match(r.warnings[0], /\.git\/hooks/);
});

test('pre-push-gate — trailing whitespace on the configured path does not defeat detection', () => {
  const r = evaluateHookActivation({ configuredHooksPath: `${HOOKS_PATH}\n` });
  assert.equal(r.active, true);
});

// ------------------------------------------------------------ summary
test('pre-push-gate — all-pass summary is ok and states what was verified', () => {
  const s = summarize([
    { id: 'bundle-integrity', title: 'Bundle', result: { ok: true, errors: [] } },
    { id: 'test-suite', title: 'Tests', result: { ok: true, errors: [] } },
  ]);
  assert.equal(s.ok, true);
  assert.equal(s.failed.length, 0);
  assert.ok(s.lines.every(l => /^PASS/.test(l)));
});

test('pre-push-gate — a failure is reported with its remedy and the bypass escape hatch', () => {
  const s = summarize([
    { id: 'bundle-integrity', title: 'Bundle', result: { ok: true, errors: [] } },
    { id: 'test-suite', title: 'Tests', remedy: 'Run `npm test` and fix the failures.', result: { ok: false, errors: ['`npm test` exited 1.'] } },
  ]);
  assert.equal(s.ok, false);
  assert.deepEqual(s.failed.map(f => f.id), ['test-suite']);
  const text = s.lines.join('\n');
  assert.match(text, /FAIL {2}Tests/);
  assert.match(text, /Run `npm test` and fix the failures\./);
  assert.match(text, /--no-verify/);
});

// --- git context must not leak from the hook into the suites ------------------
//
// Git exports GIT_DIR into every hook. The gate spawns `npm test`, which
// inherited it, so every test that builds a temp repository and shells out to
// `git` operated on THIS repository instead of its fixture.
//
// The consequence was not a false failure. Two blocked pushes from a linked
// worktree ran the suite under the hook and the history-mining tests committed
// their fixtures into the real branch — ~30 commits that between them deleted
// 421 files and 90,282 lines from scanner/src, which then got pushed. From an
// ordinary clone GIT_DIR is the relative `.git` and stops resolving once a test
// chdirs away, which is why this went unseen for so long.

test('envWithoutGitContext strips every variable that could redirect a child git', () => {
  const out = envWithoutGitContext({
    GIT_DIR: '/repo/.git',
    GIT_WORK_TREE: '/repo',
    GIT_INDEX_FILE: '/repo/.git/index',
    GIT_OBJECT_DIRECTORY: '/repo/.git/objects',
    GIT_ALTERNATE_OBJECT_DIRECTORIES: '/other/objects',
    GIT_PREFIX: 'scanner/',
    GIT_COMMON_DIR: '/repo/.git',
  });
  assert.deepEqual(Object.keys(out), [], 'no git-context variable may survive');
});

test('envWithoutGitContext preserves everything a child actually needs', () => {
  // Over-scrubbing would break the spawn itself, failing the gate closed for a
  // different and even more confusing reason.
  const out = envWithoutGitContext({
    PATH: '/usr/bin', HOME: '/home/x', NODE_ENV: 'test',
    GIT_DIR: '/repo/.git', GIT_AUTHOR_NAME: 'keep me',
  });
  assert.equal(out.PATH, '/usr/bin');
  assert.equal(out.HOME, '/home/x');
  assert.equal(out.NODE_ENV, 'test');
  assert.equal(out.GIT_DIR, undefined);
  // GIT_AUTHOR_* cannot redirect which repository a command targets, so it is
  // deliberately kept: the list is a denylist of redirectors, not a blanket
  // "delete anything starting with GIT_".
  assert.equal(out.GIT_AUTHOR_NAME, 'keep me');
});

test('envWithoutGitContext does not mutate the source environment', () => {
  const source = { GIT_DIR: '/repo/.git', PATH: '/usr/bin' };
  envWithoutGitContext(source);
  assert.equal(source.GIT_DIR, '/repo/.git', 'process.env must not be modified in place');
});

// --- the gate must verify what it is PUSHING, not just what is on disk -------
//
// A run of this gate once passed all four checks in 184s on a branch whose
// committed tree was missing 421 files and 90,282 lines of scanner/src. The
// files still existed on disk as untracked, so every suite imported them and
// went green while the refs being uploaded did not contain them. These two
// checks exist so that cannot happen silently again; either one catches it.

test('worktree check fails when tracked files differ from HEAD', () => {
  const r = evaluateWorktreeMatchesPush(' M scanner/src/engine.js\nD  scanner/src/gone.js\n');
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /2 tracked file\(s\) differ/);
  assert.match(r.errors[0], /not in the commit being pushed/);
});

test('worktree check passes on a clean tree', () => {
  const r = evaluateWorktreeMatchesPush('');
  assert.equal(r.ok, true);
  assert.equal(r.warnings.length, 0);
});

test('worktree check tolerates a few untracked files but says so', () => {
  const r = evaluateWorktreeMatchesPush('?? notes.md\n?? scratch.txt\n');
  assert.equal(r.ok, true);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /2 untracked/);
});

test('worktree check fails on a flood of untracked files — the incident signature', () => {
  // The real incident looked exactly like this: the history was rewritten
  // underneath the working tree, so the whole project read as untracked.
  const porcelain = Array.from({ length: 40 }, (_, i) => `?? src/file${i}.js`).join('\n');
  const r = evaluateWorktreeMatchesPush(porcelain);
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /40 untracked files/);
  assert.match(r.errors[0], /reflog/);
});

test('blast-radius check fails on a mass deletion, quoting both counts', () => {
  const r = evaluatePushBlastRadius({ filesDeleted: 421, filesInBase: 900, base: 'abc123def456' });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /421 tracked file/);
});

test('blast-radius check fails on a large FRACTION even under the absolute cap', () => {
  // 30 of 100 is only 30 files — under the 50-file cap — but a third of the
  // repository. The fraction rule is what catches a small project.
  const r = evaluatePushBlastRadius({ filesDeleted: 30, filesInBase: 100 });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /30\.0%/);
});

test('blast-radius check passes an ordinary deletion', () => {
  const r = evaluatePushBlastRadius({ filesDeleted: 3, filesInBase: 900 });
  assert.equal(r.ok, true);
});

test('blast-radius check warns rather than fails when there is no base to measure', () => {
  // A genuinely first push has no previous state. That is a real condition,
  // not a broken check, so it must not block — but it must be visible.
  const r = evaluatePushBlastRadius({ measured: false });
  assert.equal(r.ok, true);
  assert.match(r.warnings[0], /NOT measured/);
});

test('the two new guards run before the expensive suites', () => {
  const ids = orderedCheckIds();
  assert.equal(ids[0], 'worktree-matches-push');
  assert.equal(ids[1], 'push-blast-radius');
  assert.ok(ids.indexOf('test-suite') > ids.indexOf('push-blast-radius'),
    'a guard that runs after the suites cannot save the minutes it exists to save');
});
