import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crossRepoLinkId } from '../../src/lineage/ids.js';
import {
  CROSS_REPO_LINK_VERSION,
  CROSS_REPO_LINKS_FILENAME,
  CROSS_REPO_LINK_RELATIONSHIP,
  validateCrossRepoLink,
} from '../../src/lineage/cross-repo-link.js';
import { EDGE_PROVENANCE_VALUES } from '../../src/lineage/schema.js';

function baseInputs() {
  return {
    localGraphId: 'dfg:repo-a:abc123:default',
    localGraphDigest: 'sha256:local-digest',
    localNodeId: 'node:sink:aaaaaaaaaaaa',
    remoteGraphId: 'dfg:repo-b:def456:default',
    remoteGraphDigest: 'sha256:remote-digest',
    remoteNodeId: 'node:source:bbbbbbbbbbbb',
    relationship: 'data_flow',
  };
}

test('crossRepoLinkId is deterministic for identical inputs and differs on any input change', () => {
  const inputs = baseInputs();
  const a = crossRepoLinkId(inputs);
  const b = crossRepoLinkId(inputs);
  assert.equal(a, b);
  assert.match(a, /^crosslink:[0-9a-f]+$/);
  assert.notEqual(a, crossRepoLinkId({ ...inputs, localGraphDigest: 'sha256:different' }));
  assert.notEqual(a, crossRepoLinkId({ ...inputs, remoteGraphDigest: 'sha256:different' }));
  assert.notEqual(a, crossRepoLinkId({ ...inputs, localNodeId: 'node:sink:cccccccccccc' }));
  assert.notEqual(a, crossRepoLinkId({ ...inputs, remoteNodeId: 'node:source:dddddddddddd' }));
  assert.notEqual(a, crossRepoLinkId(inputs, ['discriminator-1']));
});

test('crossRepoLinkId never collides two different repo pairs sharing identical bare node-shape strings', () => {
  // The referential-soundness finding this deliverable's scoping doc
  // settles: a plain node id string is never looked up against a merged
  // set — both graphs' own graphId+graphDigest are baked into the id.
  const pairA = crossRepoLinkId({
    localGraphId: 'dfg:repo-a:c1:default', localGraphDigest: 'd1', localNodeId: 'node:sink:xxxxxxxxxxxx',
    remoteGraphId: 'dfg:repo-b:c2:default', remoteGraphDigest: 'd2', remoteNodeId: 'node:source:yyyyyyyyyyyy',
    relationship: 'data_flow',
  });
  const pairB = crossRepoLinkId({
    localGraphId: 'dfg:repo-c:c3:default', localGraphDigest: 'd3', localNodeId: 'node:sink:xxxxxxxxxxxx',
    remoteGraphId: 'dfg:repo-d:c4:default', remoteGraphDigest: 'd4', remoteNodeId: 'node:source:yyyyyyyyyyyy',
    relationship: 'data_flow',
  });
  assert.notEqual(pairA, pairB);
});

test('CROSS_REPO_LINK_VERSION/CROSS_REPO_LINKS_FILENAME/CROSS_REPO_LINK_RELATIONSHIP are the expected literals', () => {
  assert.equal(CROSS_REPO_LINK_VERSION, '1.0.0');
  assert.equal(CROSS_REPO_LINKS_FILENAME, 'cross-repo-links.json');
  assert.equal(CROSS_REPO_LINK_RELATIONSHIP, 'data_flow');
});

function validRecord(overrides = {}) {
  const inputs = baseInputs();
  return {
    id: crossRepoLinkId(inputs),
    version: CROSS_REPO_LINK_VERSION,
    provenance: 'manual',
    relationship: 'data_flow',
    local: { graphId: inputs.localGraphId, graphDigest: inputs.localGraphDigest, nodeId: inputs.localNodeId },
    remote: {
      repository: 'remote-service', sourceFile: '/tmp/remote-export.json',
      graphId: inputs.remoteGraphId, graphDigest: inputs.remoteGraphDigest, nodeId: inputs.remoteNodeId,
    },
    rationale: "Payment events flow from remote-service into this repo's ingestion endpoint.",
    declaredBy: 'ross',
    declaredAt: '2026-09-02T00:00:00.000Z',
    ...overrides,
  };
}

test('validateCrossRepoLink: a well-formed record is valid', () => {
  const { valid, errors } = validateCrossRepoLink(validRecord());
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
});

test('validateCrossRepoLink: rationale may be null', () => {
  const { valid, errors } = validateCrossRepoLink(validRecord({ rationale: null }));
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
});

test('validateCrossRepoLink: non-object record is invalid', () => {
  assert.equal(validateCrossRepoLink(null).valid, false);
  assert.equal(validateCrossRepoLink('x').valid, false);
  assert.equal(validateCrossRepoLink([]).valid, false);
});

test('validateCrossRepoLink: id must start with "crosslink:"', () => {
  const { valid, errors } = validateCrossRepoLink(validRecord({ id: 'node:not-a-crosslink' }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.id'));
});

test('validateCrossRepoLink: provenance must be a real EDGE_PROVENANCE_VALUES member', () => {
  const bad = validateCrossRepoLink(validRecord({ provenance: 'made-up' }));
  assert.equal(bad.valid, false);
  assert.ok(bad.errors.some((e) => e.path === '$.provenance'));
  // Every real EDGE_PROVENANCE_VALUES member is structurally acceptable —
  // this deliverable's own CLI only ever writes 'manual', but the schema
  // reuse must not artificially narrow what the FIELD itself accepts.
  for (const v of EDGE_PROVENANCE_VALUES) {
    assert.equal(validateCrossRepoLink(validRecord({ provenance: v })).valid, true, `provenance "${v}" must validate`);
  }
});

test('validateCrossRepoLink: relationship must be exactly "data_flow"', () => {
  const { valid, errors } = validateCrossRepoLink(validRecord({ relationship: 'something_else' }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.relationship'));
});

test('validateCrossRepoLink: local must be an object with non-empty graphId/graphDigest/nodeId', () => {
  assert.equal(validateCrossRepoLink(validRecord({ local: null })).valid, false);
  assert.equal(validateCrossRepoLink(validRecord({ local: { graphId: '', graphDigest: 'd', nodeId: 'n' } })).valid, false);
  assert.equal(validateCrossRepoLink(validRecord({ local: { graphId: 'g', graphDigest: '', nodeId: 'n' } })).valid, false);
  assert.equal(validateCrossRepoLink(validRecord({ local: { graphId: 'g', graphDigest: 'd', nodeId: '' } })).valid, false);
});

test('validateCrossRepoLink: remote requires repository and sourceFile in addition to graphId/graphDigest/nodeId', () => {
  const inputs = baseInputs();
  const base = { graphId: inputs.remoteGraphId, graphDigest: inputs.remoteGraphDigest, nodeId: inputs.remoteNodeId };
  assert.equal(validateCrossRepoLink(validRecord({ remote: { ...base, sourceFile: '/tmp/x.json' } })).valid, false, 'missing repository');
  assert.equal(validateCrossRepoLink(validRecord({ remote: { ...base, repository: 'svc' } })).valid, false, 'missing sourceFile');
  assert.equal(validateCrossRepoLink(validRecord({ remote: { ...base, repository: '', sourceFile: '/tmp/x.json' } })).valid, false, 'empty repository');
});

test('validateCrossRepoLink: declaredBy/declaredAt are required non-empty strings', () => {
  assert.equal(validateCrossRepoLink(validRecord({ declaredBy: '' })).valid, false);
  assert.equal(validateCrossRepoLink(validRecord({ declaredAt: null })).valid, false);
});

test('validateCrossRepoLink: never confirms local.nodeId/remote.nodeId actually exist in any real graph — zero graph access', () => {
  // A record naming node ids that could never exist in ANY real graph
  // still validates structurally — this module has no graph to check
  // against, by design.
  const { valid } = validateCrossRepoLink(validRecord({
    local: { graphId: 'g', graphDigest: 'd', nodeId: 'node:this-id-cannot-possibly-exist-anywhere' },
  }));
  assert.equal(valid, true);
});

test('cross-repo-link.js imports only ./schema.js — zero graph/fs access, mirrors scenario.js\'s own boundary', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const src = readFileSync(fileURLToPath(new URL('../../src/lineage/cross-repo-link.js', import.meta.url)), 'utf8');
  const specifiers = [...src.matchAll(/^\s*import[^'"]*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  assert.deepEqual(specifiers, ['./schema.js']);
});
