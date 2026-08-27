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

test('cache: a read-only scan (--no-state) writes NOTHING into the scanned tree', () => {
  // The static guard in no-stray-state.test.js proves this module CONSULTS the
  // seam; only running it proves the seam actually stops the write. Asserting
  // the full path listing (not just the file) because directory creation is
  // mutation too — `.agentic-security/provenance/cache/` appearing in someone
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
