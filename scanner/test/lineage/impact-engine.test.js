import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeImpactAssessment } from '../../src/lineage/impact-engine.js';

function _fixtureGraph() {
  return {
    graphId: 'graph:abc', schemaVersion: '1.0.0',
    nodes: [
      { id: 'node:source', kind: 'source', subtype: 'user-input' },
      { id: 'node:mid', kind: 'process', subtype: null },
      { id: 'node:sink', kind: 'sink', subtype: 'external-api' },
      { id: 'node:orphan', kind: 'sink', subtype: 'log' },
    ],
    edges: [
      { id: 'edge:1', from: 'node:source', to: 'node:mid', relationship: 'flows_to' },
      { id: 'edge:2', from: 'node:mid', to: 'node:sink', relationship: 'flows_to' },
    ],
    dataElements: [
      { id: 'data:1', name: 'email', dataClasses: ['PII'] },
      { id: 'data:2', name: 'ssn', dataClasses: ['PII', 'CONFIDENTIAL'] },
    ],
    flows: [
      { id: 'flow:1', dataElementIds: ['data:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1', 'edge:2'] },
      { id: 'flow:2', dataElementIds: ['data:2'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1', 'edge:2'] },
    ],
    recipientProfiles: [
      { id: 'recipient:vendor', provider: 'vendor', contributingGraphIds: ['node:sink'] },
      { id: 'recipient:unrelated', provider: 'other', contributingGraphIds: ['node:orphan'] },
    ],
    coverage: { languages: [
      { language: 'js', tier: 'partial', filesAnalyzed: 5, filesExpected: 5 },
      { language: 'python', tier: 'pattern-only', filesAnalyzed: 2, filesExpected: 2 },
    ] },
  };
}

test('computeImpactAssessment from a node target: affected set includes every downstream/upstream node and edge', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:mid');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:mid', 'node:sink', 'node:source']);
  assert.deepEqual([...record.affectedEdgeIds].sort(), ['edge:1', 'edge:2']);
  assert.equal(record.targetKind, 'node');
  assert.equal(record.scope, 'possible');
});

test('computeImpactAssessment: affectedDataClasses is the deduplicated union of every flow touching the affected edges', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.deepEqual([...record.affectedDataClasses].sort(), ['CONFIDENTIAL', 'PII']);
});

test('computeImpactAssessment: affectedRecipientProfileIds filters by contributingGraphIds intersection, excluding unrelated profiles', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:sink');
  assert.deepEqual(record.affectedRecipientProfileIds, ['recipient:vendor']);
});

test('computeImpactAssessment: an edge target resolves to its own from/to nodes', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'edge:2');
  assert.equal(record.targetKind, 'edge');
  assert.ok(record.affectedNodeIds.includes('node:mid'));
  assert.ok(record.affectedNodeIds.includes('node:sink'));
});

test('computeImpactAssessment: a flow target resolves to its own source/sink nodes', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'flow:1');
  assert.equal(record.targetKind, 'flow');
  assert.ok(record.affectedNodeIds.includes('node:source'));
  assert.ok(record.affectedNodeIds.includes('node:sink'));
});

test('computeImpactAssessment: a dataElement target resolves to every node touched by any flow carrying it', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'data:2');
  assert.equal(record.targetKind, 'dataElement');
  assert.deepEqual([...record.affectedNodeIds].sort(), ['node:mid', 'node:sink', 'node:source']);
});

test('computeImpactAssessment: a well-formed but non-existent target id degrades honestly to empty arrays, never throws', () => {
  assert.doesNotThrow(() => computeImpactAssessment(_fixtureGraph(), 'node:does-not-exist'));
  const record = computeImpactAssessment(_fixtureGraph(), 'node:does-not-exist');
  assert.deepEqual(record.affectedNodeIds, []);
  assert.deepEqual(record.affectedEdgeIds, []);
  assert.deepEqual(record.affectedDataClasses, []);
  assert.deepEqual(record.affectedRecipientProfileIds, []);
});

test('computeImpactAssessment: throws on a malformed targetId (no recognized prefix)', () => {
  assert.throws(() => computeImpactAssessment(_fixtureGraph(), 'not-a-real-prefix:x'));
});

test('computeImpactAssessment: coverageLimitations reports every non-full-tier language, whole-graph', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.equal(record.coverageLimitations.length, 2);
  assert.ok(record.coverageLimitations.some((s) => s.includes('js') && s.includes('partial')));
  assert.ok(record.coverageLimitations.some((s) => s.includes('python') && s.includes('pattern-only')));
});

test('computeImpactAssessment: graph.recipientProfiles absent degrades to empty array, never an error', () => {
  const graph = _fixtureGraph();
  delete graph.recipientProfiles;
  const record = computeImpactAssessment(graph, 'node:sink');
  assert.deepEqual(record.affectedRecipientProfileIds, []);
});

test('computeImpactAssessment: id, graphId, graphDigest, generatedAt are all real, non-placeholder values', () => {
  const record = computeImpactAssessment(_fixtureGraph(), 'node:source');
  assert.match(record.id, /^impact:[0-9a-f]+$/);
  assert.equal(record.graphId, 'graph:abc');
  assert.ok(record.graphDigest.length > 0);
  assert.ok(record.generatedAt.length > 0);
});
