// Coordinator — direct-SCA branch (Task 14).
//
// The SAST path is covered by provenance-coordinator.test.js; this file covers
// only what changes when `ctx.findingType === 'sca'`: the stableId backfill via
// scaStableId, the swap from resolveOrigin to resolveDirectSCAOrigin, and the
// simplified single-node `manifest` evidence attribution that replaces
// attributeEvidence (which reads source/sink/pathSteps shapes an SCA entry does
// not have).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { annotateGitProvenance } from '../../src/posture/provenance/coordinator.js';
import { scaStableId } from '../../src/posture/provenance/sca-origin.js';
import { validateFindingsProvenance } from '../../src/posture/provenance/validate.js';

const pkg = (deps) => JSON.stringify({ name: 'x', dependencies: deps }, null, 2) + '\n';

test('annotateGitProvenance with findingType sca resolves direct-dependency origin', async () => {
  const fx = createGitFixture();
  try {
    // The dependency is ABSENT in the first commit, so the parent blob is
    // genuinely out of range and the walk can reach `complete`. (A fixture that
    // merely bumps 0.9.0 -> 1.0.0 under a fixed-only advisory range is the
    // ambiguous case — see the next test.)
    fx.writeFile('package.json', pkg({ 'other-pkg': '2.0.0' }));
    fx.commit('initial', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('package.json', pkg({ 'other-pkg': '2.0.0', 'left-pad': '1.0.0' }));
    const introducedSha = fx.commit('add left-pad', { date: '2026-01-02T00:00:00Z', authorName: 'Bob', authorEmail: 'bob@example.com' });

    const entry = {
      type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm',
      filePath: 'package.json', line: 5, osvId: 'GHSA-xyz', fixedVersions: ['1.1.0'],
    };
    await annotateGitProvenance([entry], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-02T00:00:00Z',
      mode: 'standard', findingType: 'sca',
    });

    const fp = entry.findingProvenance;
    assert.ok(fp, 'SCA entry must be annotated');
    assert.ok(entry.stableId, 'coordinator should backfill stableId for SCA entries');
    assert.equal(fp.status, 'complete', `expected complete, got ${fp.status}: ${JSON.stringify(fp.limitations)}`);
    assert.equal(fp.findingOrigin.authorName, 'Bob');
    assert.equal(fp.findingOrigin.commit, introducedSha);
    assert.equal(fp.method, 'dependency-graph-diff');
    assert.equal(fp.analysisBasis.detector, 'sca-manifest-diff');
    assert.equal(validateFindingsProvenance([entry]).valid, true);
  } finally {
    fx.cleanup();
  }
});

test('SCA complete emits a single manifest evidence node, not SAST source/sink nodes', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', pkg({ 'other-pkg': '2.0.0' }));
    fx.commit('initial', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('package.json', pkg({ 'other-pkg': '2.0.0', 'left-pad': '1.0.0' }));
    const sha = fx.commit('add left-pad', { date: '2026-01-02T00:00:00Z' });

    const entry = {
      type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm',
      filePath: 'package.json', line: 5, osvId: 'GHSA-xyz', fixedVersions: ['1.1.0'],
    };
    await annotateGitProvenance([entry], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-02T00:00:00Z',
      mode: 'standard', findingType: 'sca',
    });

    const nodes = entry.findingProvenance.evidenceAttribution;
    assert.equal(nodes.length, 1);
    assert.deepEqual(nodes[0], { role: 'manifest', path: 'package.json', line: 5, commit: sha, depChain: null });
    assert.ok(entry.findingProvenance.evidenceDigest, 'digest is computed over the manifest node');
  } finally {
    fx.cleanup();
  }
});

test('SCA manifest node tolerates an entry with no line (older parsers)', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', pkg({ 'other-pkg': '2.0.0' }));
    fx.commit('initial', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('package.json', pkg({ 'other-pkg': '2.0.0', 'left-pad': '1.0.0' }));
    fx.commit('add left-pad', { date: '2026-01-02T00:00:00Z' });

    const entry = {
      type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm',
      filePath: 'package.json', osvId: 'GHSA-xyz', fixedVersions: ['1.1.0'],
    };
    await annotateGitProvenance([entry], {
      scanRoot: fx.root, scanId: 's2', observedAt: '2026-01-02T00:00:00Z',
      mode: 'standard', findingType: 'sca',
    });

    assert.equal(entry.findingProvenance.status, 'complete');
    assert.equal(entry.findingProvenance.evidenceAttribution[0].line, null);
  } finally {
    fx.cleanup();
  }
});

test('SCA partial threads the ambiguous-range reason through instead of dropping it', async () => {
  const fx = createGitFixture();
  try {
    // Both versions sit below the advisory's `fixed` bound and there is no
    // `introduced` bound, so a still-vulnerable patch bump is indistinguishable
    // from a bump INTO the vulnerable window. sca-origin.js refuses to guess and
    // returns partial/ambiguous-range-no-introduced-bound; the coordinator must
    // carry that reason into the record rather than flattening it to the SAST
    // "verified parent boundary" wording.
    fx.writeFile('package.json', pkg({ 'left-pad': '0.9.0' }));
    fx.commit('safe version', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('package.json', pkg({ 'left-pad': '1.0.0' }));
    fx.commit('bump to vulnerable version', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const entry = {
      type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm',
      filePath: 'package.json', osvId: 'GHSA-xyz', fixedVersions: ['1.1.0'],
    };
    await annotateGitProvenance([entry], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-02T00:00:00Z',
      mode: 'standard', findingType: 'sca',
    });

    const fp = entry.findingProvenance;
    assert.equal(fp.status, 'partial');
    assert.match(fp.limitations[0], /ambiguous-range-no-introduced-bound/);
    assert.match(fp.limitations[0], /manifest history/,
      'SCA partial must not borrow the SAST "verified parent boundary" wording');
    assert.equal(fp.confidence.level, 'low');
    assert.deepEqual(fp.confidence.reasons, ['ambiguous_version_range']);
    assert.equal(fp.analysisBasis.detector, 'sca-manifest-diff');
    assert.equal(validateFindingsProvenance([entry]).valid, true);
  } finally {
    fx.cleanup();
  }
});

test('SCA partial distinguishes never-confirmed from ambiguous-range', async () => {
  const fx = createGitFixture();
  try {
    // The declared version sits ABOVE the advisory's `fixed` bound in every
    // commit, so no candidate is ever in range: the resolver never confirms a
    // version, which is a different partial reason from the ambiguous bump and
    // must not be reported with the ambiguous-range confidence reason.
    fx.writeFile('package.json', pkg({ 'left-pad': '2.0.0' }));
    fx.commit('initial', { date: '2026-01-01T00:00:00Z' });

    const entry = {
      type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm',
      filePath: 'package.json', osvId: 'GHSA-xyz', fixedVersions: ['1.1.0'],
    };
    await annotateGitProvenance([entry], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z',
      mode: 'standard', findingType: 'sca',
    });

    const fp = entry.findingProvenance;
    assert.equal(fp.status, 'partial');
    assert.match(fp.limitations[0], /version-never-confirmed-in-candidates/);
    assert.deepEqual(fp.confidence.reasons, ['version_never_confirmed_in_manifest_history']);
  } finally {
    fx.cleanup();
  }
});

test('SCA stableId backfill matches scaStableId and an existing stableId is left alone', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', pkg({ 'left-pad': '1.0.0' }));
    fx.commit('initial', { date: '2026-01-01T00:00:00Z' });

    const base = { type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm', filePath: 'package.json', osvId: 'GHSA-xyz', fixedVersions: ['1.1.0'] };
    const backfilled = { ...base };
    const preset = { ...base, stableId: 'operator-supplied-id' };

    await annotateGitProvenance([backfilled, preset], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z',
      mode: 'standard', findingType: 'sca',
    });

    assert.equal(backfilled.stableId, scaStableId(base));
    assert.equal(preset.stableId, 'operator-supplied-id');
  } finally {
    fx.cleanup();
  }
});

test('SCA not_available propagates the resolver reason (no manifest path)', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', pkg({ 'left-pad': '1.0.0' }));
    fx.commit('initial', { date: '2026-01-01T00:00:00Z' });

    const entry = { type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm', osvId: 'GHSA-xyz' };
    await annotateGitProvenance([entry], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z',
      mode: 'standard', findingType: 'sca',
    });

    assert.equal(entry.findingProvenance.status, 'not_available');
    assert.equal(entry.findingProvenance.limitations[0], 'no-manifest-path');
  } finally {
    fx.cleanup();
  }
});

test('an SCA-shaped entry WITHOUT findingType:sca keeps the SAST behaviour (no backfill)', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', pkg({ 'left-pad': '1.0.0' }));
    fx.commit('initial', { date: '2026-01-01T00:00:00Z' });

    // No findingType => isSca false => scaStableId is never reached, and a
    // finding with no stableId terminates at not_available exactly as before.
    const entry = { type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm', filePath: 'package.json', osvId: 'GHSA-xyz' };
    await annotateGitProvenance([entry], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', mode: 'standard',
    });

    assert.equal(entry.stableId, undefined, 'the SAST path must not backfill stableId');
    assert.equal(entry.findingProvenance.status, 'not_available');
    assert.equal(entry.findingProvenance.limitations[0], 'finding has no stableId');
  } finally {
    fx.cleanup();
  }
});

test('annotateGitProvenance: findingType "sca-transitive" resolves via resolveTransitiveSCAOrigin, not resolveDirectSCAOrigin', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  const lockfile = (v) => JSON.stringify({ name: 'root', lockfileVersion: 3, packages: { '': {}, [`node_modules/express/node_modules/qs`]: { version: v } } });
  fx.writeFile('package-lock.json', lockfile('6.5.0'));
  fx.commit('safe');
  fx.writeFile('package-lock.json', lockfile('6.5.3'));
  fx.commit('vulnerable bump');

  const entry = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.3'], isDirect: false };
  const findings = [entry];
  await annotateGitProvenance(findings, { scanRoot: fx.root, scanId: 's1', observedAt: new Date().toISOString(), findingType: 'sca-transitive' });
  assert.equal(entry.findingProvenance.status, 'complete');
  assert.equal(entry.findingProvenance.analysisBasis.detector, 'sca-lockfile-history-diff');
});
