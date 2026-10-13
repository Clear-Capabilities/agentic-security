import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectSourceArtifactMismatch } from '../../src/artifact/mismatch.js';

function vuln(overrides) {
  return { type: 'vulnerable_dep', name: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.15', osvId: 'GHSA-xxxx', severity: 'high', ...overrides };
}

test('MM/1: Scenario A — the Killer Demonstration. An advisory present against the artifact\'s installed version but absent from source\'s is flagged as a still-vulnerable deployment', () => {
  const r = detectSourceArtifactMismatch({
    sourceVulnerabilities: [], // developer fixed it; source scan is clean
    artifactVulnerabilities: [vuln()], // Friday's image is still running the old vulnerable version
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.15', ecosystem: 'npm', name: 'lodash', version: '4.17.15' }],
  });
  assert.equal(r.scenarioA.length, 1);
  assert.equal(r.scenarioA[0].osvId, 'GHSA-xxxx');
  assert.equal(r.scenarioB.length, 0);
  assert.equal(r.hasMismatch, true);
});

test('MM/1b: Scenario A still fires even when source and artifact run DIFFERENT versions of the package, as long as the advisory id differs between them', () => {
  const r = detectSourceArtifactMismatch({
    sourceVulnerabilities: [vuln({ osvId: 'GHSA-source-only', purl: 'pkg:npm/lodash@4.17.21' })],
    artifactVulnerabilities: [vuln({ osvId: 'GHSA-artifact-only', purl: 'pkg:npm/lodash@4.17.4' })],
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.4', ecosystem: 'npm', name: 'lodash', version: '4.17.4' }],
  });
  assert.equal(r.scenarioA.length, 1);
  assert.equal(r.scenarioA[0].osvId, 'GHSA-artifact-only');
});

test('MM/1c: an advisory affecting BOTH source\'s and the artifact\'s installed versions is neither scenario (not a mismatch — both sides agree it is a real, current problem)', () => {
  const r = detectSourceArtifactMismatch({
    sourceVulnerabilities: [vuln({ osvId: 'GHSA-shared', purl: 'pkg:npm/lodash@4.17.4' })],
    artifactVulnerabilities: [vuln({ osvId: 'GHSA-shared', purl: 'pkg:npm/lodash@4.17.4' })],
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.4', ecosystem: 'npm', name: 'lodash', version: '4.17.4' }],
  });
  assert.equal(r.hasMismatch, false);
});

test('MM/2: Scenario B — source flags an advisory against a package that never shipped in this artifact at all', () => {
  const r = detectSourceArtifactMismatch({
    sourceVulnerabilities: [vuln()], // a dev-only dependency, vulnerable in the lockfile
    artifactVulnerabilities: [],
    artifactComponents: [{ purl: 'pkg:npm/express@4.18.0', ecosystem: 'npm', name: 'express', version: '4.18.0' }], // lodash never made it into the image at all
  });
  assert.equal(r.scenarioB.length, 1);
  assert.equal(r.scenarioA.length, 0);
  assert.equal(r.hasMismatch, true);
});

test('MM/2b: Scenario B does NOT fire when the package is present at a DIFFERENT (even if non-vulnerable) version — that is just a normal, non-alarming version difference', () => {
  const r = detectSourceArtifactMismatch({
    sourceVulnerabilities: [vuln({ purl: 'pkg:npm/lodash@4.17.4' })],
    artifactVulnerabilities: [],
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.21', ecosystem: 'npm', name: 'lodash', version: '4.17.21' }],
  });
  assert.equal(r.scenarioB.length, 0);
});

test('MM/3: no mismatch when source and artifact agree exactly', () => {
  const r = detectSourceArtifactMismatch({
    sourceVulnerabilities: [vuln()],
    artifactVulnerabilities: [vuln()],
    artifactComponents: [{ purl: 'pkg:npm/lodash@4.17.15', ecosystem: 'npm', name: 'lodash', version: '4.17.15' }],
  });
  assert.equal(r.hasMismatch, false);
  assert.deepEqual(r.scenarioA, []);
  assert.deepEqual(r.scenarioB, []);
});

test('MM/4: structural result types (unpinned_dep, no_lockfile) are never treated as vulnerabilities in either scenario', () => {
  const r = detectSourceArtifactMismatch({
    sourceVulnerabilities: [{ type: 'unpinned_dep', name: 'lodash' }],
    artifactVulnerabilities: [{ type: 'no_lockfile', file: 'package.json' }],
    artifactComponents: [],
  });
  assert.equal(r.hasMismatch, false);
});

test('MM/5: requires all three arguments to be arrays', () => {
  assert.throws(() => detectSourceArtifactMismatch({ sourceVulnerabilities: null, artifactVulnerabilities: [], artifactComponents: [] }), TypeError);
});

test('MM/6: an OS-package advisory with no osvId falls back to an ecosystem:name key rather than colliding across unrelated packages', () => {
  const r = detectSourceArtifactMismatch({
    sourceVulnerabilities: [{ type: 'vulnerable_dep', name: 'curl', ecosystem: 'Debian', osvId: null }],
    artifactVulnerabilities: [{ type: 'vulnerable_dep', name: 'openssl', ecosystem: 'Debian', osvId: null }],
    artifactComponents: [{ ecosystem: 'Debian', name: 'openssl', version: '1.1.1f-1' }],
  });
  assert.equal(r.scenarioA.length, 1);
  assert.equal(r.scenarioA[0].name, 'openssl');
  assert.equal(r.scenarioB.length, 1);
  assert.equal(r.scenarioB[0].name, 'curl');
});
