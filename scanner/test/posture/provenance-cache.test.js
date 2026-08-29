import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { makeCacheKey, cacheGet, cacheSet } from '../../src/posture/provenance/cache.js';
import { FINDING_PROVENANCE_SCHEMA_VERSION } from '../../src/posture/provenance/schema.js';

test('cache: content-addressed round trip, no TTL, repo-local', () => {
  const fx = createGitFixture();
  try {
    const key = makeCacheKey({ repoHead: 'abc123', stableId: 'sid1', detectorVersion: '2026.09', historyBoundary: '', mode: 'standard' });
    assert.equal(cacheGet(fx.root, key), null);
    cacheSet(fx.root, key, { status: 'complete', findingOrigin: { commit: 'abc123' } });
    const got = cacheGet(fx.root, key);
    assert.deepEqual(got, { status: 'complete', findingOrigin: { commit: 'abc123' } });
    assert.ok(fs.existsSync(`${fx.root}/.agentic-security/provenance-cache`));
  } finally {
    fx.cleanup();
  }
});

test('cache.js: writes to the new top-level provenance-cache/ directory, not nested under provenance/', () => {
  const fx = createGitFixture();
  try {
    const key = makeCacheKey({ repoHead: 'abc123', stableId: 'sid1', detectorVersion: '2026.09', historyBoundary: '', mode: 'standard' });
    cacheSet(fx.root, key, { status: 'complete', findingOrigin: { commit: 'abc123' } });

    const hash = crypto.createHash('sha256').update(key).digest('hex');
    const newPath = path.join(fx.root, '.agentic-security', 'provenance-cache', `${hash}.json`);
    const oldPath = path.join(fx.root, '.agentic-security', 'provenance', 'cache', `${hash}.json`);

    assert.ok(fs.existsSync(newPath), `expected the cache file at the new top-level location: ${newPath}`);
    assert.ok(!fs.existsSync(oldPath), `cache file must NOT be written to the old nested location: ${oldPath}`);
  } finally {
    fx.cleanup();
  }
});

test('cache: a read-only scan (--no-state) writes NOTHING into the scanned tree', () => {
  // The static guard in no-stray-state.test.js proves this module CONSULTS the
  // seam; only running it proves the seam actually stops the write. Asserting
  // the full path listing (not just the file) because directory creation is
  // mutation too — `.agentic-security/provenance-cache/` appearing in someone
  // else's repository is litter even when it is empty.
  const fx = createGitFixture();
  const prior = process.env.AGENTIC_SECURITY_NO_STATE;
  const listing = (dir) => {
    const out = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
        if (e.name === '.git') continue;
        out.push(e.name);
        if (e.isDirectory()) walk(`${d}/${e.name}`);
      }
    };
    walk(dir);
    return out;
  };
  try {
    const before = listing(fx.root);
    process.env.AGENTIC_SECURITY_NO_STATE = '1';
    const key = makeCacheKey({ repoHead: 'abc123', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard' });
    cacheSet(fx.root, key, { status: 'complete' });
    assert.deepEqual(listing(fx.root), before, 'a read-only scan must not add any path');
    assert.equal(cacheGet(fx.root, key), null, 'a refused write reads back as a miss, not as stale data');
  } finally {
    if (prior === undefined) delete process.env.AGENTIC_SECURITY_NO_STATE;
    else process.env.AGENTIC_SECURITY_NO_STATE = prior;
    fx.cleanup();
  }
});

test('cache: the key is scoped by schema version, so a bump invalidates every old entry', () => {
  // validate.js rejects a provenance object stamped with an unknown schema
  // version — but a cache HIT never reaches that check, because cacheGet
  // returns the parsed object as-is. With the version outside the key, entries
  // written under an older schema stayed live key hits after a bump and flowed
  // straight through, defeating the exact scenario the version field guards.
  // Leading position matters: every key changes when the constant changes.
  const key = makeCacheKey({ repoHead: 'h', stableId: 's', detectorVersion: 'v', historyBoundary: '', mode: 'standard' });
  assert.ok(
    key.startsWith(`${FINDING_PROVENANCE_SCHEMA_VERSION}|`),
    `cache key must be scoped by schema version, got: ${key}`,
  );
});

test('cache: different repoHead produces a different key/miss', () => {
  const fx = createGitFixture();
  try {
    const k1 = makeCacheKey({ repoHead: 'head1', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard' });
    const k2 = makeCacheKey({ repoHead: 'head2', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard' });
    cacheSet(fx.root, k1, { status: 'complete' });
    assert.equal(cacheGet(fx.root, k2), null);
  } finally {
    fx.cleanup();
  }
});

// Item 2 fix (M4 final-review): `repo-lineage.json`'s content was not part
// of the cache key, so an operator adding, removing, or repointing a
// declared cross-repo lineage link at the same HEAD kept being served a
// stale answer computed before/without the change. `lineageKey` closes that
// gap the same way `historyBoundary` already covers `--provenance-since`.
test('cache: a declared lineage link produces a different key than no link declared, at the same HEAD/stableId', () => {
  const fx = createGitFixture();
  try {
    const withLineage = makeCacheKey({
      repoHead: 'head1', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard',
      lineageKey: '/some/old-repo@abc123',
    });
    const withoutLineage = makeCacheKey({
      repoHead: 'head1', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard',
      lineageKey: 'none',
    });
    assert.notEqual(withLineage, withoutLineage);
    cacheSet(fx.root, withLineage, { status: 'partial', crossRepoLineage: true });
    // The pre-lineage answer must not be visible under the with-lineage key —
    // this is exactly the "operator adds the declaration and re-scans at the
    // same HEAD" bug: a stale cached pre-lineage result must not leak through.
    assert.equal(cacheGet(fx.root, withoutLineage), null);
  } finally {
    fx.cleanup();
  }
});

test('cache: a lineage link repointed to a different atCommit produces a different key/miss (edit/remove case)', () => {
  const fx = createGitFixture();
  try {
    const original = makeCacheKey({
      repoHead: 'head1', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard',
      lineageKey: '/some/old-repo@abc123',
    });
    const repointed = makeCacheKey({
      repoHead: 'head1', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard',
      lineageKey: '/some/old-repo@def456',
    });
    cacheSet(fx.root, original, { status: 'partial', findingOrigin: { commit: 'abc123' } });
    assert.equal(cacheGet(fx.root, repointed), null, 'a repointed atCommit must not serve the stale cached attribution');
  } finally {
    fx.cleanup();
  }
});

test('cache: omitting lineageKey defaults to the same key as an explicit "none" (backward-compatible default)', () => {
  const withDefault = makeCacheKey({ repoHead: 'h', stableId: 's', detectorVersion: 'v', historyBoundary: '', mode: 'standard' });
  const withExplicitNone = makeCacheKey({ repoHead: 'h', stableId: 's', detectorVersion: 'v', historyBoundary: '', mode: 'standard', lineageKey: 'none' });
  assert.equal(withDefault, withExplicitNone);
});

// Second independent Finding Provenance PRD audit: the cache stores the FULL
// (unredacted) provenance record, including raw authorEmail, so that
// redactFindingProvenance can apply a DIFFERENT policy per output call
// against the SAME cached record. See cache.js's module header. The accepted
// mitigation is a permissions floor — this pins that the directory and every
// entry file it writes actually land at the tightened mode, not just that a
// comment claims they do.
test('cache: cacheSet tightens the cache directory to 0700 and the entry file to 0600', { skip: process.platform === 'win32' ? 'POSIX file modes are not meaningful on Windows' : false }, () => {
  const fx = createGitFixture();
  try {
    const key = makeCacheKey({ repoHead: 'abc123', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard' });
    cacheSet(fx.root, key, { status: 'complete', findingOrigin: { commit: 'abc123', authorEmail: 'a@b.c' } });

    const dir = path.join(fx.root, '.agentic-security', 'provenance-cache');
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    const fp = path.join(dir, `${hash}.json`);

    const dirMode = fs.statSync(dir).mode & 0o777;
    const fileMode = fs.statSync(fp).mode & 0o777;
    assert.equal(dirMode, 0o700, `expected provenance-cache/ dir mode 0700, got ${dirMode.toString(8)}`);
    assert.equal(fileMode, 0o600, `expected cache entry file mode 0600, got ${fileMode.toString(8)}`);

    // Round-trip still works — the permissions floor must not break the
    // three-ways-to-present-one-cached-record property this cache exists for.
    const got = cacheGet(fx.root, key);
    assert.equal(got.findingOrigin.authorEmail, 'a@b.c');
  } finally {
    fx.cleanup();
  }
});
