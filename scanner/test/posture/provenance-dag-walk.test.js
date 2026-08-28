import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkAbsentInAllParents, detectRevert, detectCherryPick } from '../../src/posture/provenance/dag-walk.js';
import { getAllParents } from '../../src/posture/provenance/git-evidence.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

test('checkAbsentInAllParents: root commit reports rootCommit:true, absentInAll:true', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  const root = fx.commit('root');
  const replay = async () => ({ present: false });
  const result = await checkAbsentInAllParents(fx.root, root, replay);
  assert.equal(result.rootCommit, true);
  assert.equal(result.absentInAll, true);
  assert.deepEqual(result.parents, []);
});

test('checkAbsentInAllParents: a merge commit is absentInAll only when EVERY parent lacks the predicate', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  fx.commit('root');
  // M3 Task 1's own review discovered this environment's `git init` default
  // branch is 'master', not 'main' (no init.defaultBranch config set) —
  // capture the real starting branch name rather than hardcoding 'main',
  // matching the fix Task 1's implementer already had to make for the same
  // reason (see build-git-fixture.js's currentBranch(), added in Task 1).
  const mainBranch = fx.currentBranch();
  fx.checkoutBranch('feature');
  fx.writeFile('b.txt', 'y');
  const featureTip = fx.commit('feature');
  fx.checkout(mainBranch);
  fx.writeFile('a.txt', 'z');
  const mainTip = fx.commit('mainline');
  const merge = fx.merge('feature', 'merge');
  const parents = getAllParents(fx.root, merge);
  assert.equal(parents.length, 2);
  // Predicate present only in the feature-branch parent — not absent in all.
  const replayPresentInFeature = async (sha) => ({ present: sha === featureTip });
  const notAbsent = await checkAbsentInAllParents(fx.root, merge, replayPresentInFeature);
  assert.equal(notAbsent.absentInAll, false);
  // Predicate present in neither parent — absent in all.
  const replayAbsent = async () => ({ present: false });
  const isAbsent = await checkAbsentInAllParents(fx.root, merge, replayAbsent);
  assert.equal(isAbsent.absentInAll, true);
});

test('detectRevert: a real git-revert of the immediately preceding commit is detected', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'safe\n');
  fx.commit('safe baseline');
  fx.writeFile('a.txt', 'eval(x)\n');
  const bad = fx.commit('introduce eval');
  const { execFileSync } = await import('node:child_process');
  execFileSync('git', ['revert', '--no-edit', bad], { cwd: fx.root });
  const revertSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim();
  const result = detectRevert(fx.root, revertSha, [bad]);
  assert.equal(result.isRevert, true);
  assert.equal(result.revertsCommit, bad);
});

test('detectRevert: a commit whose message says "Revert" but whose diff does NOT match is rejected (spoofing resistance)', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'safe\n');
  fx.commit('safe baseline');
  fx.writeFile('a.txt', 'eval(x)\n');
  const bad = fx.commit('introduce eval');
  fx.writeFile('a.txt', 'totally different content, not a real revert\n');
  const { execFileSync } = await import('node:child_process');
  execFileSync('git', ['add', '-A'], { cwd: fx.root });
  execFileSync('git', ['commit', '-m', 'Revert "introduce eval"'], { cwd: fx.root });
  const spoofSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim();
  const result = detectRevert(fx.root, spoofSha, [bad]);
  assert.equal(result.isRevert, false, 'a spoofed commit message alone must not be trusted');
});

test('detectCherryPick: a real cherry-pick -x trailer is parsed', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'v1\n');
  const original = fx.commit('original commit');
  const mainBranch = fx.currentBranch(); // see Task 1's build-git-fixture.js addition — this environment's git init default is 'master', not 'main'
  fx.checkoutBranch('other');
  fx.writeFile('a.txt', 'v2\n');
  fx.commit('unrelated');
  fx.checkout(mainBranch);
  const { execFileSync } = await import('node:child_process');
  fx.writeFile('b.txt', 'x\n');
  const target = fx.commit('target for cherry-pick message construction');
  // Simulate the trailer directly (git cherry-pick across these two branches
  // in a synthetic fixture with no shared content is fiddly) — this tests
  // the PARSER, which is the unit under test, not `git cherry-pick` itself.
  execFileSync('git', ['commit', '--allow-empty', '-m', `Some change\n\n(cherry picked from commit ${original})`], { cwd: fx.root });
  const cherrySha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim();
  const result = detectCherryPick(fx.root, cherrySha);
  assert.equal(result.isCherryPick, true);
  assert.equal(result.originalCommit, original);
});

test('detectCherryPick: a normal commit with no trailer is not classified as a cherry-pick', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  const sha = fx.commit('ordinary commit');
  const result = detectCherryPick(fx.root, sha);
  assert.equal(result.isCherryPick, false);
});
