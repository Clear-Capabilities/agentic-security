import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import {
  isGitRepo, getRepoState, commitMeta, getFirstParent, getAllParents, getBlobAtCommit,
  candidateCommitsForLine, candidateCommitsForFile, blameLine,
} from '../../src/posture/provenance/git-evidence.js';

test('git-evidence: repo state, blob fetch, candidates, blame', () => {
  const fx = createGitFixture();
  try {
    assert.equal(isGitRepo(fx.root), true);
    fx.writeFile('a.js', 'const x = 1;\n');
    const sha1 = fx.commit('add a.js', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('a.js', 'const x = 1;\nconst y = 2;\n');
    const sha2 = fx.commit('add y', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const state = getRepoState(fx.root);
    assert.equal(state.head, sha2);
    assert.equal(state.dirty, false);
    assert.equal(state.shallow, false);

    const meta = commitMeta(fx.root, sha2);
    assert.equal(meta.authorName, 'Bob');
    assert.equal(meta.summary, 'add y');

    assert.equal(getFirstParent(fx.root, sha2), sha1);
    assert.equal(getFirstParent(fx.root, sha1), null);

    assert.equal(getBlobAtCommit(fx.root, sha1, 'a.js'), 'const x = 1;\n');
    assert.equal(getBlobAtCommit(fx.root, sha2, 'a.js'), 'const x = 1;\nconst y = 2;\n');
    assert.equal(getBlobAtCommit(fx.root, sha1, 'missing.js'), null);

    const candidatesLine2 = candidateCommitsForLine(fx.root, 'a.js', 2);
    assert.deepEqual(candidatesLine2, [sha2]);

    const candidatesFile = candidateCommitsForFile(fx.root, 'a.js');
    assert.deepEqual(candidatesFile, [sha1, sha2]);

    const blame = blameLine(fx.root, 'a.js', 2);
    assert.equal(blame.commit, sha2);

    fx.writeFile('a.js', 'const x = 1;\nconst y = 2;\nconst z = 3;\n');
    const uncommittedBlame = blameLine(fx.root, 'a.js', 3);
    assert.equal(uncommittedBlame.uncommitted, true);
    assert.equal(getRepoState(fx.root).dirty, true);
  } finally {
    fx.cleanup();
  }
});

test('git-evidence: rejects path traversal, sha flag-injection, and unsafe since values', () => {
  const fx = createGitFixture();
  const canaryPath = path.join(os.tmpdir(), `as-git-evidence-pwn-test-${process.pid}-${Date.now()}.txt`);
  try {
    fx.writeFile('a.js', 'const x = 1;\n');
    const sha1 = fx.commit('add a.js', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });

    // Embedded (not leading) ".." must not resolve outside scanRoot.
    assert.equal(getBlobAtCommit(fx.root, sha1, 'sub/../../outside.js'), null);
    assert.equal(getBlobAtCommit(fx.root, sha1, '../outside.js'), null);
    assert.equal(candidateCommitsForLine(fx.root, 'sub/../../outside.js', 1).length, 0);
    assert.equal(candidateCommitsForFile(fx.root, 'sub/../../outside.js').length, 0);
    assert.equal(blameLine(fx.root, 'sub/../../outside.js', 1), null);

    // A "sha" shaped like a git flag must never reach argv as a bare token —
    // if it did, `git show --output=<canaryPath>` would actually write the file.
    const flagLikeSha = `--output=${canaryPath}`;
    assert.equal(commitMeta(fx.root, flagLikeSha), null);
    assert.equal(getFirstParent(fx.root, flagLikeSha), null);
    assert.equal(getBlobAtCommit(fx.root, flagLikeSha, 'a.js'), null);
    assert.equal(fs.existsSync(canaryPath), false);

    // A malformed / non-hex sha is rejected the same way.
    assert.equal(commitMeta(fx.root, 'not-a-sha'), null);
    assert.equal(getFirstParent(fx.root, 'not-a-sha'), null);

    // A "since" shaped like a flag must not be forwarded to git either.
    assert.deepEqual(candidateCommitsForLine(fx.root, 'a.js', 1, { since: `--output=${canaryPath}` }), []);
    assert.deepEqual(candidateCommitsForFile(fx.root, 'a.js', { since: `--output=${canaryPath}` }), []);
    assert.equal(fs.existsSync(canaryPath), false);
  } finally {
    if (fs.existsSync(canaryPath)) fs.unlinkSync(canaryPath);
    fx.cleanup();
  }
});

test('getAllParents: a root commit has zero parents', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  const root = fx.commit('root');
  const parents = getAllParents(fx.root, root);
  assert.deepEqual(parents, []);
});

test('getAllParents: a normal commit has exactly one parent, matching getFirstParent', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  fx.commit('root');
  fx.writeFile('a.txt', 'y');
  const second = fx.commit('second');
  const parents = getAllParents(fx.root, second);
  assert.equal(parents.length, 1);
  assert.equal(parents[0], getFirstParent(fx.root, second));
});

test('getAllParents: a merge commit reports every parent, not just the first', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.txt', 'x');
  const root = fx.commit('root');
  const mainBranch = fx.currentBranch();
  fx.checkoutBranch('feature');
  fx.writeFile('b.txt', 'feature-content');
  const featureTip = fx.commit('feature work');
  fx.checkout(mainBranch);
  fx.writeFile('a.txt', 'y');
  fx.commit('mainline work');
  const merge = fx.merge('feature', 'merge feature');
  const parents = getAllParents(fx.root, merge);
  assert.equal(parents.length, 2);
  assert.equal(parents[1], featureTip);
});

test('getAllParents: an invalid sha returns empty array, never throws', () => {
  assert.deepEqual(getAllParents('/tmp/does-not-matter', 'not-a-sha'), []);
});
