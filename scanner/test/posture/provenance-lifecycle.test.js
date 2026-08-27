import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { readLifecycle, updateLifecycle, latestOpenIntroduction } from '../../src/posture/provenance/lifecycle.js';

test('Scenario E: introduce, remediate, reintroduce produces three ordered events', async () => {
  const fx = createGitFixture();
  try {
    const finding = { stableId: 'sid-e', findingProvenance: { status: 'complete', findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z' } } };

    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    let store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 1);
    assert.equal(store['sid-e'][0].type, 'introduced');

    await updateLifecycle(fx.root, [], { scanId: 'scan2', observedAt: '2026-02-01T00:00:00Z' });
    store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 2);
    assert.equal(store['sid-e'][1].type, 'remediated');
    assert.equal(latestOpenIntroduction(store, 'sid-e'), null);

    await updateLifecycle(fx.root, [finding], { scanId: 'scan3', observedAt: '2026-03-01T00:00:00Z' });
    store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 3);
    assert.equal(store['sid-e'][2].type, 'reintroduced');
    const latest = latestOpenIntroduction(store, 'sid-e');
    assert.ok(latest);
    assert.equal(latest.type, 'reintroduced');
  } finally {
    fx.cleanup();
  }
});

test('a finding present across two consecutive scans does not double-introduce', async () => {
  const fx = createGitFixture();
  try {
    const finding = { stableId: 'sid-stable', findingProvenance: { status: 'not_available' } };
    await updateLifecycle(fx.root, [finding], { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    await updateLifecycle(fx.root, [finding], { scanId: 's2', observedAt: '2026-01-02T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-stable'].length, 1);
  } finally {
    fx.cleanup();
  }
});
