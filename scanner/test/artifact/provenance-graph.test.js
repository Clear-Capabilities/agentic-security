import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildArtifactProvenanceGraph, traceArtifactProvenanceGraph } from '../../src/artifact/provenance-graph.js';

function inv(overrides = {}) {
  return {
    digest: 'sha256:' + 'a'.repeat(64),
    digestKind: 'config',
    repoTags: ['example:latest'],
    buildLabels: {},
    osPackages: [],
    appPackages: [],
    ...overrides,
  };
}

test('PG/1a: a commit label produces a known commit node and a labeled edge', () => {
  const graph = buildArtifactProvenanceGraph({ inventory: inv({ buildLabels: { 'org.opencontainers.image.revision': 'deadbeef' } }) });
  const commit = graph.nodes.find((n) => n.kind === 'gitCommit');
  assert.equal(commit.sha, 'deadbeef');
  assert.equal(commit.known, true);
  const edge = graph.edges.find((e) => e.from === commit.id);
  assert.equal(edge.evidence, 'label:org.opencontainers.image.revision');
});

test('PG/1b: no commit label produces an UNKNOWN commit node, never a guessed sha', () => {
  const graph = buildArtifactProvenanceGraph({ inventory: inv() });
  const commit = graph.nodes.find((n) => n.kind === 'gitCommit');
  assert.equal(commit.sha, null);
  assert.equal(commit.known, false);
  const edge = graph.edges.find((e) => e.from === commit.id);
  assert.equal(edge.evidence, 'none');
});

test('PG/2: every component becomes an SBOM-component node reachable from the digest', () => {
  const graph = buildArtifactProvenanceGraph({
    inventory: inv({ osPackages: [{ name: 'curl', version: '1.0', ecosystem: 'Debian', purl: 'pkg:deb/debian/curl@1.0' }] }),
  });
  const comp = graph.nodes.find((n) => n.kind === 'sbomComponent');
  assert.equal(comp.purl, 'pkg:deb/debian/curl@1.0');
  const digest = graph.nodes.find((n) => n.kind === 'ociDigest');
  assert.ok(graph.edges.some((e) => e.from === digest.id && e.to === comp.id));
});

test('PG/3: a vulnerable_dep result becomes a Finding node linked to its component, other result types do not', () => {
  const graph = buildArtifactProvenanceGraph({
    inventory: inv({ appPackages: [{ name: 'lodash', version: '4.17.15', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.15', filePath: 'package.json' }] }),
    vulnerabilities: [
      { type: 'vulnerable_dep', name: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.15', osvId: 'GHSA-xxxx', severity: 'high', cveAliases: ['CVE-2020-1234'] },
      { type: 'unpinned_dep', name: 'lodash' },
    ],
  });
  const finding = graph.nodes.find((n) => n.kind === 'finding');
  assert.equal(finding.osvId, 'GHSA-xxxx');
  const comp = graph.nodes.find((n) => n.kind === 'sbomComponent');
  assert.ok(graph.edges.some((e) => e.from === comp.id && e.to === finding.id));
  assert.equal(graph.nodes.some((n) => n.kind === 'finding' && n.osvId === undefined), false);
});

test('PG/4a: no deployment supplied means the graph has no deployment node at all', () => {
  const graph = buildArtifactProvenanceGraph({ inventory: inv() });
  assert.equal(graph.nodes.some((n) => n.kind === 'deployment'), false);
});

test('PG/4b: a supplied deployment with a matching digest is flagged digestMatches: true', () => {
  const digest = 'sha256:' + 'a'.repeat(64);
  const graph = buildArtifactProvenanceGraph({ inventory: inv({ digest }), deployment: { id: 'prod-1', environment: 'production', digest } });
  const edge = graph.edges.find((e) => e.to === 'deployment:prod-1');
  assert.equal(edge.digestMatches, true);
});

test('PG/4c: a supplied deployment with a DIFFERENT digest is flagged digestMatches: false — this is the stale-deployment signal mismatch.js relies on', () => {
  const graph = buildArtifactProvenanceGraph({
    inventory: inv({ digest: 'sha256:' + 'a'.repeat(64) }),
    deployment: { id: 'prod-1', digest: 'sha256:' + 'b'.repeat(64) },
  });
  const edge = graph.edges.find((e) => e.to === 'deployment:prod-1');
  assert.equal(edge.digestMatches, false);
});

test('PG/4d: a deployment record without an id throws rather than silently using an undefined node id', () => {
  assert.throws(() => buildArtifactProvenanceGraph({ inventory: inv(), deployment: { environment: 'prod' } }), TypeError);
});

test('PG/5: requires an inventory with a digest', () => {
  assert.throws(() => buildArtifactProvenanceGraph({ inventory: {} }), TypeError);
});

test('TRACE/1: tracing from the commit reaches the digest, component, and finding nodes', () => {
  const graph = buildArtifactProvenanceGraph({
    inventory: inv({
      buildLabels: { 'org.opencontainers.image.revision': 'deadbeef' },
      appPackages: [{ name: 'lodash', version: '4.17.15', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.15', filePath: 'package.json' }],
    }),
    vulnerabilities: [{ type: 'vulnerable_dep', name: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.15', osvId: 'GHSA-xxxx', severity: 'high' }],
  });
  const commitId = graph.nodes.find((n) => n.kind === 'gitCommit').id;
  const trace = traceArtifactProvenanceGraph(graph, commitId);
  assert.equal(trace.found, true);
  const kinds = trace.reached.map((r) => r.node.kind);
  assert.ok(kinds.includes('ociDigest'));
  assert.ok(kinds.includes('sbomComponent'));
  assert.ok(kinds.includes('finding'));
});

test('TRACE/2: tracing from an unknown node id reports found: false', () => {
  const graph = buildArtifactProvenanceGraph({ inventory: inv() });
  const trace = traceArtifactProvenanceGraph(graph, 'nonexistent:node');
  assert.equal(trace.found, false);
});
