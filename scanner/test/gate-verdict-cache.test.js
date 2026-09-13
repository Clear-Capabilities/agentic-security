// Gate verdict cache — unit tests for the pure decision logic (PRD R1).
//
// The cache decides whether to SKIP verification. That makes its failure mode
// asymmetric and nasty: a bug does not fail loudly, it silently stops checking
// things. So every rejection path is pinned here, and the bias is always
// towards doing the work.
//
// The I/O path (a real cold run populating the cache, a warm run reusing it,
// tamper and corruption both discarding it) was proven by hand with captured
// timings — 255s cold, 3s warm — and recorded in the commit message.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  envFingerprint,
  computeVerdictKey,
  evaluateCachedVerdict,
  renderProvenance,
  cachingDisabled,
  DEFAULT_TTL_MS,
  computeWorkingTreeSha,
} from '../../scripts/gate-verdict-cache.mjs';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const PARTS = {
  commitSha: 'a'.repeat(40),
  treeSha: 'b'.repeat(40),
  bundleSha: 'c'.repeat(64),
  rulesetVersion: 'deadbeefdeadbeef',
  nodeVersion: 'v24.16.0',
  platform: 'darwin-arm64',
  envFingerprint: '',
};

// ---------------------------------------------------------------- the key
test('the key is stable across identical inputs', () => {
  assert.equal(computeVerdictKey(PARTS), computeVerdictKey({ ...PARTS }));
});

test('every key component changes the key', () => {
  // One assertion per component. Miss one and the cache starts reusing a
  // verdict across inputs that could have changed the outcome, which is the
  // only way this feature can be actively harmful.
  const base = computeVerdictKey(PARTS);
  for (const field of Object.keys(PARTS)) {
    const changed = computeVerdictKey({ ...PARTS, [field]: `${PARTS[field]}-changed` });
    assert.notEqual(changed, base, `changing ${field} must change the key`);
  }
});

test('an unreadable input yields a null key, which means "cannot cache"', () => {
  for (const field of ['commitSha', 'treeSha', 'bundleSha', 'rulesetVersion', 'nodeVersion', 'platform']) {
    assert.equal(computeVerdictKey({ ...PARTS, [field]: null }), null, `${field} null must void the key`);
    assert.equal(computeVerdictKey({ ...PARTS, [field]: '' }), null, `${field} empty must void the key`);
  }
});

test('an EMPTY env fingerprint is a real value, not a missing one', () => {
  // Regression. Treating '' as missing made the key null on every ordinary run
  // — no AGENTIC_SECURITY_* variable is set most of the time — so caching never
  // engaged at all. The feature looked implemented and did nothing.
  assert.notEqual(computeVerdictKey({ ...PARTS, envFingerprint: '' }), null);
});

test('envFingerprint captures values and is order-independent', () => {
  const a = envFingerprint({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_PROVE: '1', PATH: '/usr/bin' });
  const b = envFingerprint({ AGENTIC_SECURITY_PROVE: '1', AGENTIC_SECURITY_DEEP: '1', PATH: '/other' });
  assert.equal(a, b, 'enumeration order and unrelated variables must not matter');
  assert.notEqual(a, envFingerprint({ AGENTIC_SECURITY_DEEP: '0', AGENTIC_SECURITY_PROVE: '1' }),
    'a changed VALUE must change the fingerprint, not just a changed name');
});

// --------------------------------------------------------------- reuse rules
const KEY = computeVerdictKey(PARTS);
const rec = (over = {}) => ({
  checkId: 'test-suite', key: KEY, verdict: 'pass', by: 'pre-push',
  commitSha: PARTS.commitSha, durationMs: 1000, at: new Date().toISOString(), ...over,
});

test('a fresh matching pass is reusable', () => {
  assert.equal(evaluateCachedVerdict({ record: rec(), key: KEY, checkId: 'test-suite' }).usable, true);
});

test('no record means run it', () => {
  const r = evaluateCachedVerdict({ record: null, key: KEY, checkId: 'test-suite' });
  assert.equal(r.usable, false);
  assert.match(r.reason, /no cached verdict/);
});

test('a record for a different check is never reused', () => {
  const r = evaluateCachedVerdict({ record: rec(), key: KEY, checkId: 'corpus-gate' });
  assert.equal(r.usable, false);
});

test('a changed key is never reused', () => {
  const r = evaluateCachedVerdict({ record: rec(), key: 'different', checkId: 'test-suite' });
  assert.equal(r.usable, false);
  assert.match(r.reason, /inputs changed/);
});

test('ONLY a pass is reused — a failure is always re-run', () => {
  // Caching a failure would strand a developer who has fixed it: "still failing
  // after I fixed it" destroys trust in a gate faster than slowness does.
  for (const verdict of ['fail', 'error', 'skipped', undefined]) {
    const r = evaluateCachedVerdict({ record: rec({ verdict }), key: KEY, checkId: 'test-suite' });
    assert.equal(r.usable, false, `verdict ${verdict} must not be reused`);
  }
});

test('an expired record is re-run, not failed', () => {
  const old = rec({ at: new Date(Date.now() - DEFAULT_TTL_MS - 60000).toISOString() });
  const r = evaluateCachedVerdict({ record: old, key: KEY, checkId: 'test-suite' });
  assert.equal(r.usable, false);
  assert.match(r.reason, /older than/);
});

test('a record dated in the future is rejected', () => {
  // Clock skew or a doctored file. Either way, not evidence.
  const future = rec({ at: new Date(Date.now() + 3600000).toISOString() });
  assert.equal(evaluateCachedVerdict({ record: future, key: KEY, checkId: 'test-suite' }).usable, false);
});

test('a record with an unreadable timestamp is rejected', () => {
  assert.equal(evaluateCachedVerdict({ record: rec({ at: 'not-a-date' }), key: KEY, checkId: 'test-suite' }).usable, false);
});

// ------------------------------------------------------------- transparency
test('provenance names when, by which gate, and for which commit', () => {
  const line = renderProvenance(rec({ by: 'pre-push', durationMs: 172000 }));
  assert.match(line, /cached/);
  assert.match(line, /pre-push/);
  assert.match(line, new RegExp(PARTS.commitSha.slice(0, 7)));
  assert.match(line, /172s/);
});

// ------------------------------------------------------------- escape hatch
test('caching can be switched off by flag or environment', () => {
  assert.equal(cachingDisabled(['--no-cache'], {}), true);
  assert.equal(cachingDisabled([], { AGENTIC_SECURITY_GATE_NO_CACHE: '1' }), true);
  assert.equal(cachingDisabled([], {}), false);
});

// -------------------------------------------------------- dirty-tree safety
// Found incidentally while publishing 0.151.1: `git rev-parse HEAD^{tree}`
// (the ORIGINAL implementation) is the tree of the last COMMIT, not the
// working tree — confirmed live, it printed the identical hash before and
// after editing a tracked file. That directly contradicted this module's
// own header claim ("a dirty working tree never reuses a clean verdict"),
// meaning a stale PASS could have been reused across an uncommitted,
// potentially-breaking change for up to the 24h TTL. These tests build a
// real, disposable git repo (never the real project repo) to prove the FIX
// — `computeWorkingTreeSha` — actually distinguishes clean vs. dirty
// (tracked and untracked) working-tree states, is deterministic, and never
// mutates the repo it inspects.

function mkGitRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-cache-treesha-'));
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' });
  git('init', '--quiet');
  git('config', 'user.email', 'test@example.com');
  git('config', 'user.name', 'Test');
  fs.writeFileSync(path.join(dir, 'tracked.txt'), 'original content\n');
  git('add', '.');
  git('commit', '--quiet', '-m', 'initial');
  return { dir, git };
}

test('computeWorkingTreeSha: a clean working tree produces a stable, non-null value', () => {
  const { dir } = mkGitRepo();
  const a = computeWorkingTreeSha(dir);
  const b = computeWorkingTreeSha(dir);
  assert.ok(a, 'expected a non-null hash for a clean tree');
  assert.equal(a, b, 'a clean tree must hash identically on repeated calls');
});

test('computeWorkingTreeSha: editing a TRACKED file changes the hash (the exact bug this fixes)', () => {
  const { dir } = mkGitRepo();
  const clean = computeWorkingTreeSha(dir);
  fs.writeFileSync(path.join(dir, 'tracked.txt'), 'MODIFIED content\n');
  const dirty = computeWorkingTreeSha(dir);
  assert.notEqual(clean, dirty,
    'editing a tracked file MUST change the working-tree hash — this is the exact defect ' +
    '`git rev-parse HEAD^{tree}` had: it stayed identical across this exact edit');
});

test('computeWorkingTreeSha: adding a new UNTRACKED file changes the hash (git stash create alone does not cover this)', () => {
  const { dir } = mkGitRepo();
  const clean = computeWorkingTreeSha(dir);
  fs.writeFileSync(path.join(dir, 'new-untracked-file.txt'), 'brand new content\n');
  const dirty = computeWorkingTreeSha(dir);
  assert.notEqual(clean, dirty,
    'adding an untracked file MUST change the working-tree hash — confirmed live that ' +
    '`git stash create` alone omits untracked files entirely from its resulting tree');
});

test('computeWorkingTreeSha: reverting a tracked-file edit returns the hash to its original value', () => {
  const { dir } = mkGitRepo();
  const clean = computeWorkingTreeSha(dir);
  fs.writeFileSync(path.join(dir, 'tracked.txt'), 'MODIFIED content\n');
  fs.writeFileSync(path.join(dir, 'tracked.txt'), 'original content\n');
  const revertedBack = computeWorkingTreeSha(dir);
  assert.equal(clean, revertedBack, 'reverting an edit should return the identical hash a clean tree had');
});

test('computeWorkingTreeSha: is non-destructive — git status is unchanged after calling it', () => {
  const { dir, git } = mkGitRepo();
  fs.writeFileSync(path.join(dir, 'tracked.txt'), 'MODIFIED content\n');
  fs.writeFileSync(path.join(dir, 'untracked.txt'), 'x\n');
  const before = git('status', '--short');
  computeWorkingTreeSha(dir);
  computeWorkingTreeSha(dir); // twice, in case a single call happens to be idempotent by luck
  const after = git('status', '--short');
  assert.equal(before, after, '`git stash create` must never actually stash anything or otherwise mutate repo state');
});

test('computeWorkingTreeSha: an unreadable repo path fails closed (returns null), never throws or fabricates a hash', () => {
  const result = computeWorkingTreeSha('/nonexistent/path/that/is/not/a/git/repo/at/all');
  assert.equal(result, null);
});
