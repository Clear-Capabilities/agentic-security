// The exposure window joins to the artifact provenance graph: a deployment that names only an image digest is placed at the commit the
// image declares, a disagreement between the record and the image is refused, and an image that declares no commit is not guessed at.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { buildArtifactProvenanceGraph } from '../../src/artifact/provenance-graph.js';
import { artifactCommitMap, loadDeployments, computeExposureWindow } from '../../src/posture/dnr/exposure-window.js';

const REV = 'org.opencontainers.image.revision';
const D1 = 'sha256:' + '1'.repeat(64);
const D2 = 'sha256:' + '2'.repeat(64);
const D3 = 'sha256:' + '3'.repeat(64);
const graph = (digest, commit) => buildArtifactProvenanceGraph({ inventory: { digest, digestKind: 'image', buildLabels: commit ? { [REV]: commit } : {}, osPackages: [], appPackages: [], repoTags: [] } });
const file = (rows) => { const f = path.join(mkTestTmp('dnr-join-'), 'dep.json'); fs.writeFileSync(f, JSON.stringify(rows)); return f; };
const C1 = 'a'.repeat(40);
const C2 = 'b'.repeat(40);

test('the commit of a digest is the one its image declares; an image that declares none contributes nothing', () => {
  const { commits, problems } = artifactCommitMap([graph(D1, C1), { artifactProvenanceGraph: graph(D2, C2) }, graph(D3, null)]);
  assert.equal(commits.get(D1), C1);
  assert.equal(commits.get(D2), C2);
  assert.equal(commits.has(D3), false);
  assert.ok(problems.some(p => /declares no source commit/.test(p)));
});

test('two graphs that disagree about one digest resolve to neither', () => {
  const { commits, problems } = artifactCommitMap([graph(D1, C1), graph(D1, C2)]);
  assert.equal(commits.has(D1), false);
  assert.ok(problems.some(p => /disagree/.test(p)));
});

test('a deployment with only a digest is placed at the declared commit, and says where the commit came from', () => {
  const { commits } = artifactCommitMap([graph(D1, C1)]);
  const { deployments, problems } = loadDeployments(file([{ artifactDigest: D1, deployedAt: '2026-03-01T00:00:00Z', environment: 'prod' }]), { artifactCommits: commits });
  assert.deepEqual(problems, []);
  assert.equal(deployments[0].commit, C1);
  assert.equal(deployments[0].commitSource, 'artifact-provenance-graph');
});

test('without the graphs the same deployment is refused, never guessed', () => {
  const { deployments, problems } = loadDeployments(file([{ artifactDigest: D1, deployedAt: '2026-03-01T00:00:00Z' }]));
  assert.equal(deployments.length, 0);
  assert.match(problems[0], /commit must be a hex sha/);
});

test('a record and an image that disagree about the commit: the deployment is not used and the reason is listed', () => {
  const { commits } = artifactCommitMap([graph(D1, C1)]);
  const { deployments, problems } = loadDeployments(file([{ commit: C2, artifactDigest: D1, deployedAt: '2026-03-01T00:00:00Z' }]), { artifactCommits: commits });
  assert.equal(deployments.length, 0);
  assert.match(problems[0], /declares/);
});

test('a record and an image that agree keep the record as the source', () => {
  const { commits } = artifactCommitMap([graph(D1, C1)]);
  const { deployments } = loadDeployments(file([{ commit: C1, artifactDigest: D1, deployedAt: '2026-03-01T00:00:00Z' }]), { artifactCommits: commits });
  assert.equal(deployments[0].commitSource, 'deployment-record');
});

test('a digest the graphs do not know is listed as such', () => {
  const { commits } = artifactCommitMap([graph(D1, C1)]);
  const { deployments, problems } = loadDeployments(file([{ artifactDigest: D2, deployedAt: '2026-03-01T00:00:00Z' }]), { artifactCommits: commits });
  assert.equal(deployments.length, 0);
  assert.match(problems[0], /not in the artifact graphs/);
});

test('the window uses the joined commit: the first vulnerable deployment carries its source', () => {
  const { commits } = artifactCommitMap([graph(D1, C1)]);
  const { deployments } = loadDeployments(file([{ artifactDigest: D1, deployedAt: '2026-03-01T00:00:00Z', environment: 'prod' }]), { artifactCommits: commits });
  const finding = { stableId: 'F1', findingProvenance: { findingOrigin: { commit: C1, authorDate: '2026-01-01T00:00:00Z' } } };
  const w = computeExposureWindow({ finding, repo: '.', deployments, deps: { isAncestor: (a, d) => a === d, commitDate: () => null } });
  assert.equal(w.firstVulnerableDeployment.commit, C1);
  assert.equal(w.firstVulnerableDeployment.commitSource, 'artifact-provenance-graph');
});
