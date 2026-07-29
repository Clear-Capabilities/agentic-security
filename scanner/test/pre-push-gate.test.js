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
test('pre-push-gate — checks run cheapest-first: bundle integrity precedes the suites', () => {
  const ids = orderedCheckIds();
  assert.deepEqual(ids, ['bundle-integrity', 'test-suite', 'corpus-gate', 'self-scan-gate']);
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
