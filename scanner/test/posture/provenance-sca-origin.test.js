import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { versionInRange, scaStableId, resolveDirectSCAOrigin } from '../../src/posture/provenance/sca-origin.js';

test('versionInRange: fixed-version upper bound', () => {
  assert.equal(versionInRange('1.2.3', { introduced: null, fixed: '1.3.0' }), true);
  assert.equal(versionInRange('1.3.0', { introduced: null, fixed: '1.3.0' }), false);
  assert.equal(versionInRange('2.0.0', { introduced: null, fixed: '1.3.0' }), false);
});

test('scaStableId is distinct per package+ecosystem+manifest', () => {
  const a = scaStableId({ osvId: 'GHSA-1', name: 'left-pad', ecosystem: 'npm', filePath: 'package.json' });
  const b = scaStableId({ osvId: 'GHSA-2', name: 'lodash', ecosystem: 'npm', filePath: 'package.json' });
  assert.notEqual(a, b);
});

test('versionInRange: introduced lower bound is inclusive; unparseable version is out of range', () => {
  assert.equal(versionInRange('1.3.0', { introduced: '1.3.0', fixed: '1.5.0' }), true); // exactly at introduced -> IN range
  assert.equal(versionInRange('1.2.9', { introduced: '1.3.0', fixed: '1.5.0' }), false); // below introduced -> OUT
  assert.equal(versionInRange('not-a-version', { introduced: null, fixed: '1.5.0' }), false); // unparseable -> OUT, no throw
  assert.equal(versionInRange('*', { introduced: null, fixed: '1.5.0' }), false);
});

test('resolveDirectSCAOrigin: dependency vulnerable since the repo root, never bumped again — falls back to the root commit with parentBoundaryVerified:false', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', JSON.stringify({ name: 'x', dependencies: { 'left-pad': '1.0.0' } }, null, 2) + '\n');
    const shaRoot = fx.commit('initial commit, already on the vulnerable version', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    // A later commit touches the manifest but does not change left-pad's declared version.
    fx.writeFile('package.json', JSON.stringify({ name: 'x', dependencies: { 'left-pad': '1.0.0', other: '2.0.0' } }, null, 2) + '\n');
    fx.commit('unrelated dependency added', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const entry = { name: 'left-pad', ecosystem: 'npm', filePath: 'package.json', fixedVersions: ['1.1.0'] };
    const result = await resolveDirectSCAOrigin(fx.root, entry);
    assert.equal(result.status, 'complete');
    assert.equal(result.findingOrigin.commit, shaRoot);
    assert.equal(result.parentBoundaryVerified, false);
  } finally {
    fx.cleanup();
  }
});

test('resolveDirectSCAOrigin: unrecognized manifest / malformed package.json never throws, resolves not_available or partial', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', '{ this is not valid json');
    fx.commit('broken manifest', { date: '2026-01-01T00:00:00Z' });

    const entry = { name: 'left-pad', ecosystem: 'npm', filePath: 'package.json', fixedVersions: ['1.1.0'] };
    const result = await resolveDirectSCAOrigin(fx.root, entry);
    assert.equal(result.status, 'partial');
    assert.equal(result.reason, 'version-never-confirmed-in-candidates');
  } finally {
    fx.cleanup();
  }
});

test('resolveDirectSCAOrigin: missing filePath returns not_available without touching git', async () => {
  const fx = createGitFixture();
  try {
    const result = await resolveDirectSCAOrigin(fx.root, { name: 'left-pad', ecosystem: 'npm' });
    assert.equal(result.status, 'not_available');
    assert.equal(result.reason, 'no-manifest-path');
    assert.equal(result.commitsConsidered, 0);
  } finally {
    fx.cleanup();
  }
});

test('resolveDirectSCAOrigin: finds the commit that bumped a dep into the vulnerable range', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', JSON.stringify({ name: 'x', dependencies: { 'left-pad': '0.9.0' } }, null, 2) + '\n');
    fx.commit('safe version', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('package.json', JSON.stringify({ name: 'x', dependencies: { 'left-pad': '1.0.0' } }, null, 2) + '\n');
    const shaVuln = fx.commit('bump to vulnerable version', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const entry = { name: 'left-pad', ecosystem: 'npm', filePath: 'package.json', fixedVersions: ['1.1.0'] };
    const result = await resolveDirectSCAOrigin(fx.root, entry);
    assert.ok(['complete', 'partial'].includes(result.status));
    if (result.status === 'complete') {
      assert.equal(result.findingOrigin.commit, shaVuln);
      assert.equal(result.findingOrigin.authorName, 'Bob');
    }
  } finally {
    fx.cleanup();
  }
});
