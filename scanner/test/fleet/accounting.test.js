// GA-09 accounting (0.195.23): a stale cached result is not reused, an unverifiable artifact never leaves the organization green, the
// counts move from the state the repository really had, the artifact is written whole or not at all, and the manifest carries the
// cache age bound. Each property is pinned in both directions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { cacheFreshness, DEFAULT_CACHE_MAX_AGE_MS } from '../../src/posture/fleet/job-runner.js';
import { computeOrgHealth, applyArtifactProblems } from '../../src/posture/fleet/org-health.js';
import { validateFleetManifest } from '../../src/posture/fleet/fleet-manifest.js';
import { readCache, writeCache } from '../../src/posture/fleet/scan-cache.js';

const NOW = Date.parse('2026-11-04T12:00:00.000Z');
const H = 3600000;

test('cache freshness: a hit inside the bound is reused, one past it is stale, one with no recorded time is never reused', () => {
  assert.deepEqual(cacheFreshness({ cachedAt: new Date(NOW - 2 * H).toISOString() }, 24 * H, NOW), { fresh: true, cacheAgeMs: 2 * H });
  assert.deepEqual(cacheFreshness({ cachedAt: new Date(NOW - 25 * H).toISOString() }, 24 * H, NOW), { fresh: false, cacheAgeMs: 25 * H });
  assert.deepEqual(cacheFreshness({ entry: { total: 0 } }, 24 * H, NOW), { fresh: false, cacheAgeMs: null }, 'a record written before the time was recorded');
  assert.deepEqual(cacheFreshness(null, 24 * H, NOW), { fresh: false, cacheAgeMs: null });
  // no bound given: the default applies, and a clock that went backwards reads as age 0, not negative
  assert.equal(cacheFreshness({ cachedAt: new Date(NOW - DEFAULT_CACHE_MAX_AGE_MS - 1).toISOString() }, undefined, NOW).fresh, false);
  assert.equal(cacheFreshness({ cachedAt: new Date(NOW + H).toISOString() }, 24 * H, NOW).cacheAgeMs, 0);
  assert.equal(DEFAULT_CACHE_MAX_AGE_MS, 7 * 24 * H);
});

test('the cache writer records when a result was cached, and the reader keeps it', () => {
  const dir = mkTestTmp('fleet-cache-');
  const key = 'a'.repeat(64);
  assert.equal(writeCache(dir, key, { entry: { total: 1 }, findings: [] }), true);
  const hit = readCache(dir, key);
  assert.ok(typeof hit.cachedAt === 'string' && !Number.isNaN(Date.parse(hit.cachedAt)));
  assert.equal(cacheFreshness(hit, 24 * H, Date.now()).fresh, true);
});

test('the manifest accepts cacheMaxAge as a duration, defaults it to 7 days, and refuses a bad one', () => {
  const dir = mkTestTmp('fleet-manifest-');
  fs.mkdirSync(path.join(dir, 'a'));
  const base = { organization: 'x', repositories: [{ id: 'a', path: './a' }] };
  assert.equal(validateFleetManifest(base, { baseDir: dir }).manifest.cacheMaxAgeMs, 7 * 24 * H);
  assert.equal(validateFleetManifest({ ...base, cacheMaxAge: '12h' }, { baseDir: dir }).manifest.cacheMaxAgeMs, 12 * H);
  const bad = validateFleetManifest({ ...base, cacheMaxAge: 'soon' }, { baseDir: dir });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some((e) => /cacheMaxAge/.test(e)));
});

const manifest = { repositories: [{ id: 'req', required: true }, { id: 'opt', required: false }, { id: 'other', required: true }] };
const job = (repoId, status) => ({ repoId, status, attempts: 1, summary: { total: 0 } });

test('an unverifiable artifact for an optional repository degrades the organization (it used to stay green); for a required one it is red', () => {
  const green = computeOrgHealth({ manifest, jobs: [job('req', 'succeeded'), job('opt', 'succeeded'), job('other', 'succeeded')] });
  assert.equal(green.assurance, 'green');
  const degraded = applyArtifactProblems(computeOrgHealth({ manifest, jobs: [job('req', 'succeeded'), job('opt', 'succeeded'), job('other', 'succeeded')] }), manifest, [{ repoId: 'opt', problem: 'artifact does not match the recorded hash' }]);
  assert.equal(degraded.assurance, 'degraded');
  assert.equal(degraded.repositories.find((r) => r.id === 'opt').state, 'failed');
  assert.deepEqual([degraded.counts.complete, degraded.counts.failed], [2, 1]);
  assert.ok(degraded.reasons.some((r) => /could not be verified/.test(r)));
  const red = applyArtifactProblems(computeOrgHealth({ manifest, jobs: [job('req', 'succeeded'), job('opt', 'succeeded'), job('other', 'succeeded')] }), manifest, [{ repoId: 'req', problem: 'artifact is missing or unreadable' }]);
  assert.equal(red.assurance, 'red');
  assert.deepEqual([red.counts.complete, red.counts.failed], [2, 1]);
});

test('the counts move from the state the repository had: a partial result with a bad artifact leaves the complete count alone', () => {
  const h = applyArtifactProblems(computeOrgHealth({ manifest, jobs: [job('req', 'partial'), job('opt', 'succeeded'), job('other', 'succeeded')] }), manifest, [{ repoId: 'req', problem: 'artifact does not match the recorded hash' }]);
  assert.deepEqual([h.counts.complete, h.counts.partial, h.counts.failed], [2, 0, 1]);
  assert.equal(h.assurance, 'red');
  // a problem for a repository the manifest does not know changes nothing but the reason
  const unknown = applyArtifactProblems(computeOrgHealth({ manifest, jobs: [job('req', 'succeeded'), job('opt', 'succeeded'), job('other', 'succeeded')] }), manifest, [{ repoId: 'ghost', problem: 'x' }]);
  assert.equal(unknown.assurance, 'green');
  assert.deepEqual([unknown.counts.complete, unknown.counts.failed], [3, 0]);
  assert.equal(applyArtifactProblems(computeOrgHealth({ manifest, jobs: [] }), manifest, []).assurance, 'red', 'no problems, no results: still red');
});
