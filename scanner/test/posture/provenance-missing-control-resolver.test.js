import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { resolveMissingControl } from '../../src/posture/provenance/missing-control-resolver.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const containsRateLimit = async (scanRoot, sha, file) => {
  const { execFileSync } = await import('node:child_process');
  try {
    const blob = execFileSync('git', ['show', `${sha}:${file}`], { cwd: scanRoot, encoding: 'utf8' });
    return blob.includes('rateLimit(');
  } catch { return false; }
};

test('resolveMissingControl: a control present then removed resolves complete, naming both commits', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'app.post("/x", rateLimit(), handler);\n');
  fx.commit('add rate limiting');
  fx.writeFile('routes.js', 'app.post("/x", handler);\n');
  const removed = fx.commit('remove rate limiting (regression)');

  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: containsRateLimit });
  assert.equal(result.status, 'complete');
  assert.equal(result.removedAt.commit, removed);
});

test('resolveMissingControl (Scenario I): a control never present in any reachable commit resolves unknown, NEVER attributed to the root commit', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'app.post("/x", handler);\n');
  fx.commit('root — no rate limit, never had one');
  fx.writeFile('routes.js', 'app.post("/x", handler); // still no rate limit\n');
  fx.commit('later change, still no rate limit');

  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: containsRateLimit });
  assert.equal(result.status, 'unknown');
  assert.equal(result.removedAt, undefined, 'must never fabricate a removal event for a control that was never present');
});

test('resolveMissingControl: a control present at every checked commit (no removal yet) resolves unknown, not a false "still safe" complete', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'app.post("/x", rateLimit(), handler);\n');
  fx.commit('add rate limiting');
  fx.writeFile('routes.js', 'app.post("/x", rateLimit(), handler); // still here\n');
  fx.commit('unrelated touch, rate limit still present');

  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: containsRateLimit });
  assert.equal(result.status, 'unknown');
});

test('resolveMissingControl: no file/predicate resolves unknown without throwing', async () => {
  const result1 = await resolveMissingControl('/tmp', {});
  assert.equal(result1.status, 'unknown');
  const result2 = await resolveMissingControl('/tmp', { file: 'x.js' });
  assert.equal(result2.status, 'unknown');
});

test('resolveMissingControl: a predicate that throws is treated as "absent", never crashes the walk', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'x');
  fx.commit('a commit');
  const throwingPredicate = async () => { throw new Error('detector crashed'); };
  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: throwingPredicate });
  assert.equal(result.status, 'unknown');
});

test('resolveMissingControl: an unsafe `since` (shaped like a git flag) never reaches git argv', async (t) => {
  // Final whole-branch review item #4: this module reimplements its own git
  // invocation rather than routing through git-evidence.js's hardened
  // primitives, so `since` and `file` need their own validation — mirrored
  // from git-evidence.js's own test ("rejects path traversal, sha
  // flag-injection, and unsafe since values"), same canary-file technique:
  // if `since` reached `git log`'s argv as a bare token, a flag like
  // `--output=<canaryPath>` would make git actually write the file.
  const fx = createGitFixture();
  const canaryPath = path.join(os.tmpdir(), `as-missing-control-pwn-test-${process.pid}-${Date.now()}.txt`);
  t.after(() => { if (fs.existsSync(canaryPath)) fs.unlinkSync(canaryPath); fx.cleanup(); });

  fx.writeFile('routes.js', 'app.post("/x", rateLimit(), handler);\n');
  fx.commit('add rate limiting');
  fx.writeFile('routes.js', 'app.post("/x", handler);\n');
  fx.commit('remove rate limiting (regression)');

  const result = await resolveMissingControl(fx.root, {
    file: 'routes.js', predicate: containsRateLimit, since: `--output=${canaryPath}`,
  });
  assert.equal(result.status, 'unknown', 'an unsafe since must degrade to no candidates, never a partial result computed against a corrupted revision range');
  assert.equal(result.commitsConsidered, 0);
  assert.equal(fs.existsSync(canaryPath), false, 'the unsafe since value reached git argv and git wrote the canary file');
});

test('resolveMissingControl: a path escaping scanRoot never reaches git argv', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'app.post("/x", rateLimit(), handler);\n');
  fx.commit('add rate limiting');

  const result = await resolveMissingControl(fx.root, { file: '../outside.js', predicate: containsRateLimit });
  assert.equal(result.status, 'unknown');
  assert.equal(result.commitsConsidered, 0);
});

test('resolveMissingControl: respects deadlineAt, reporting budget_exhausted rather than hanging', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('routes.js', 'x');
  fx.commit('c1');
  fx.writeFile('routes.js', 'y');
  fx.commit('c2');
  const result = await resolveMissingControl(fx.root, { file: 'routes.js', predicate: containsRateLimit, deadlineAt: Date.now() - 1 });
  assert.equal(result.status, 'budget_exhausted');
});
