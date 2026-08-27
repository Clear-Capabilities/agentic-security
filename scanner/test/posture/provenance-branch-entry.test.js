import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { resolveBranchEntry } from '../../src/posture/provenance/branch-entry.js';

test('Scenario D: merge — origin on feature branch, entry is the merge commit', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'safe();\n');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.checkoutBranch('feature');
    fx.writeFile('a.js', 'vuln();\n');
    const originSha = fx.commit('introduce on feature', { date: '2026-01-02T00:00:00Z' });
    fx.checkout('master');
    const mergeSha = fx.merge('feature', 'merge feature into master');

    const entry = resolveBranchEntry(fx.root, originSha, 'HEAD');
    assert.ok(entry);
    assert.equal(entry.commit, mergeSha);
    assert.equal(entry.relationship, 'merge');
  } finally {
    fx.cleanup();
  }
});

test('direct: origin commit is directly on the branch, no merge in between', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'vuln();\n');
    const sha = fx.commit('direct commit', { date: '2026-01-01T00:00:00Z' });
    const entry = resolveBranchEntry(fx.root, sha, 'HEAD');
    assert.equal(entry.commit, sha);
    assert.equal(entry.relationship, 'direct');
  } finally {
    fx.cleanup();
  }
});

test('validation: flag-shaped originCommit is rejected, not passed to git', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'vuln();\n');
    fx.commit('direct commit', { date: '2026-01-01T00:00:00Z' });
    const entry = resolveBranchEntry(fx.root, '--output=/tmp/x', 'HEAD');
    assert.equal(entry, null);
  } finally {
    fx.cleanup();
  }
});

test('validation: flag-shaped targetRef is rejected, not passed to git', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'vuln();\n');
    const sha = fx.commit('direct commit', { date: '2026-01-01T00:00:00Z' });
    const entry = resolveBranchEntry(fx.root, sha, '--upload-pack=evil');
    assert.equal(entry, null);
  } finally {
    fx.cleanup();
  }
});

test('unreachable origin commit (never merged into target) returns null', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.checkoutBranch('sibling');
    fx.writeFile('a.js', 'y\n');
    const siblingSha = fx.commit('never merged', { date: '2026-01-02T00:00:00Z' });
    fx.checkout('master'); // back to the target branch, sibling never merged in
    const entry = resolveBranchEntry(fx.root, siblingSha, 'HEAD');
    assert.equal(entry, null);
  } finally {
    fx.cleanup();
  }
});

test('validation: non-string / empty originCommit is rejected', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'vuln();\n');
    fx.commit('direct commit', { date: '2026-01-01T00:00:00Z' });
    assert.equal(resolveBranchEntry(fx.root, null, 'HEAD'), null);
    assert.equal(resolveBranchEntry(fx.root, '', 'HEAD'), null);
    assert.equal(resolveBranchEntry(fx.root, 'not-a-sha!', 'HEAD'), null);
  } finally {
    fx.cleanup();
  }
});
