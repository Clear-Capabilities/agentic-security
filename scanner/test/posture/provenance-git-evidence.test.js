import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import {
  isGitRepo, getRepoState, commitMeta, getFirstParent, getAllParents, getBlobAtCommit,
  candidateCommitsForLine, candidateCommitsForFile, blameLine, _relPath,
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

test('_relPath: a symlink inside scanRoot pointing outside it is rejected, not silently followed', () => {
  const fx = createGitFixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'as-symlink-target-'));
  try {
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside content');
    const linkPath = path.join(fx.root, 'innocent-looking.js');
    fs.symlinkSync(path.join(outside, 'secret.txt'), linkPath);
    fx.commit('add a symlink'); // git tracks the symlink itself, not its target's content

    const result = _relPath(fx.root, 'innocent-looking.js');
    assert.equal(result, null, 'a symlink escaping scanRoot must be rejected');
  } finally {
    fx.cleanup();
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('_relPath: an ordinary file (no symlink) still resolves normally', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('normal.js', 'x');
    fx.commit('c1');
    const result = _relPath(fx.root, 'normal.js');
    assert.equal(result, 'normal.js');
  } finally {
    fx.cleanup();
  }
});

test('_relPath: a symlink whose target resolves back inside scanRoot is still accepted', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('real.js', 'x');
    fx.commit('c1');
    fs.symlinkSync(path.join(fx.root, 'real.js'), path.join(fx.root, 'alias.js'));
    const result = _relPath(fx.root, 'alias.js');
    assert.equal(result, 'alias.js', 'a symlink that stays inside scanRoot is not an escape');
  } finally {
    fx.cleanup();
  }
});

// Second independent Finding Provenance PRD audit (FR-PROV-024 / Section 8
// control 3, "never run repository hooks or untrusted build scripts"):
// git-evidence.js's `_run` invoked `git` with no config hardening at all, so
// a repo whose .git/config sets core.fsmonitor to a script gets that script
// executed by getRepoState()'s own `git status --porcelain` -- no clone, no
// checkout, no deliberate command needed, just this module reading repo
// state. Verified against real git behaviour (see util/git-hardening.js's
// header) before writing this test: `git -c core.fsmonitor= status
// --porcelain` does NOT run the script; plain `git status --porcelain`
// does.
test('getRepoState: a hostile core.fsmonitor script is never executed (FR-PROV-024)', () => {
  const fx = createGitFixture();
  const markerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-fsmonitor-poc-'));
  const markerFile = path.join(markerDir, 'pwned');
  try {
    fx.writeFile('a.js', 'const x = 1;\n');
    fx.commit('c1');

    // Beyond the exploit side effect, this also implements the real
    // fsmonitor hook v2 protocol (write the SIDE effect, then echo the
    // update token git passed as argv[2] back on stdout with no changed
    // paths after it, meaning "nothing changed since that token"). A hook
    // that doesn't speak the protocol still gets EXECUTED (the exploit
    // already fired by then) but makes git fall back to a slower full
    // rescan, which raced against `_run`'s own 2s subprocess timeout and
    // made this test flaky. Speaking the protocol keeps `git status`
    // itself fast, decoupling the assertion from that race.
    const hookScript = path.join(fx.root, 'hostile-fsmonitor.sh');
    fs.writeFileSync(hookScript, `#!/bin/sh\necho PWNED > ${JSON.stringify(markerFile)}\necho "$2"\n`);
    fs.chmodSync(hookScript, 0o755);
    execFileSync('git', ['config', 'core.fsmonitor', hookScript], { cwd: fx.root });

    getRepoState(fx.root);

    assert.equal(fs.existsSync(markerFile), false,
      'a hostile core.fsmonitor script must never execute merely from getRepoState() reading repo status');
  } finally {
    fx.cleanup();
    fs.rmSync(markerDir, { recursive: true, force: true });
  }
});

test('_relPath: a nonexistent path (historical file, no working-tree copy) still resolves lexically', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('placeholder.js', 'x');
    fx.commit('c1');
    // 'gone-in-history.js' was never created on disk in this fixture at all --
    // mirrors a query about a file's state at a historical commit where the
    // current working tree doesn't have it (deleted, or renamed since).
    const result = _relPath(fx.root, 'gone-in-history.js');
    assert.equal(result, 'gone-in-history.js', 'ENOENT must fail OPEN, not fail closed');
  } finally {
    fx.cleanup();
  }
});

test('_relPath: a symlink loop (ELOOP, not ENOENT) fails CLOSED, not silently open', () => {
  const fx = createGitFixture();
  try {
    // Two symlinks pointing at each other form a cycle. realpathSync on
    // either throws ELOOP, never ENOENT -- this is the exact non-ENOENT
    // error class the fail-open branch must NOT swallow: a symlink cycle
    // isn't "file doesn't exist in a historical query," it's "couldn't be
    // verified at all," which this module fails closed on everywhere else.
    const linkA = path.join(fx.root, 'loop-a.js');
    const linkB = path.join(fx.root, 'loop-b.js');
    fs.symlinkSync(linkB, linkA);
    fs.symlinkSync(linkA, linkB);
    fx.commit('add a symlink loop');

    const result = _relPath(fx.root, 'loop-a.js');
    assert.equal(result, null, 'a symlink loop must fail closed, not fall through to the lexical path');
  } finally {
    fx.cleanup();
  }
});
