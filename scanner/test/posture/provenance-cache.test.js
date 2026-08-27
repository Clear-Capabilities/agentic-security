import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { makeCacheKey, cacheGet, cacheSet } from '../../src/posture/provenance/cache.js';

test('cache: content-addressed round trip, no TTL, repo-local', () => {
  const fx = createGitFixture();
  try {
    const key = makeCacheKey({ repoHead: 'abc123', stableId: 'sid1', detectorVersion: '2026.09', historyBoundary: '', mode: 'standard' });
    assert.equal(cacheGet(fx.root, key), null);
    cacheSet(fx.root, key, { status: 'complete', findingOrigin: { commit: 'abc123' } });
    const got = cacheGet(fx.root, key);
    assert.deepEqual(got, { status: 'complete', findingOrigin: { commit: 'abc123' } });
    assert.ok(fs.existsSync(`${fx.root}/.agentic-security/provenance/cache`));
  } finally {
    fx.cleanup();
  }
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
