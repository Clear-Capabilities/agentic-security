import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import {
  isGitRepo, getRepoState, commitMeta, getFirstParent, getBlobAtCommit,
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
