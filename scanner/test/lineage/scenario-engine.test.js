import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyScenario } from '../../src/lineage/scenario-engine.js';
import { emptyProtection } from '../../src/lineage/protection.js';

function _fixtureGraph() {
  return {
    graphId: 'graph:abc', schemaVersion: '1.0.0', generatedAt: '2026-09-02T00:00:00.000Z',
    nodes: [
      { id: 'node:source', kind: 'source', subtype: 'user-input', destination: null, storeDetail: null },
      { id: 'node:sink-store', kind: 'sink', subtype: 'database', destination: { literalValue: 'db.internal.example.com' }, storeDetail: { operation: 'write' } },
      { id: 'node:sink-external', kind: 'sink', subtype: 'external-api', destination: { literalValue: 'api.vendor.example.com' }, storeDetail: null },
    ],
    edges: [
      { id: 'edge:1', from: 'node:source', to: 'node:sink-store', relationship: 'flows_to', protection: emptyProtection() },
      { id: 'edge:2', from: 'node:source', to: 'node:sink-external', relationship: 'flows_to', protection: emptyProtection() },
    ],
    dataElements: [
      { id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null },
    ],
    flows: [
      { id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink-store', edgeIds: ['edge:1'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} },
      { id: 'flow:2', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink-external', edgeIds: ['edge:2'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} },
    ],
    evidence: [], coverage: {},
  };
}

test('applyScenario never mutates the base graph', () => {
  const base = _fixtureGraph();
  const before = JSON.parse(JSON.stringify(base));
  applyScenario(base, {
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:2' }],
  });
  assert.deepEqual(base, before);
});

test('require_transit_protection overrides edge.protection.transit with assumed evidence and recomputes protectionSummary', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:2' }],
  });
  const edge = graph.edges.find((e) => e.id === 'edge:2');
  assert.deepEqual(edge.protection.transit, { verdict: 'protected', evidenceGrade: 'assumed' });
  const flow = graph.flows.find((f) => f.id === 'flow:2');
  assert.equal(flow.protectionSummary, 'protected');
  // Untouched flow/edge stay exactly as the base graph had them.
  assert.equal(graph.flows.find((f) => f.id === 'flow:1').protectionSummary, 'not_assessed');
});

test('apply_handling overrides flow.handling-driven atRest for a store sink and recomputes protectionSummary', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'apply_handling', targetEdgeId: 'edge:1', handling: 'encrypted' }],
  });
  const edge = graph.edges.find((e) => e.id === 'edge:1');
  assert.deepEqual(edge.protection.atRest, { verdict: 'protected', evidenceGrade: 'assumed' });
  assert.equal(graph.flows.find((f) => f.id === 'flow:1').protectionSummary, 'protected');
});

test('remove_entity cascades: removing a sink node drops its edges and flows too', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'remove_entity', targetNodeId: 'node:sink-external' }],
  });
  assert.equal(graph.nodes.find((n) => n.id === 'node:sink-external'), undefined);
  assert.equal(graph.edges.find((e) => e.id === 'edge:2'), undefined);
  assert.equal(graph.flows.find((f) => f.id === 'flow:2'), undefined);
  // Unrelated node/edge/flow survive untouched.
  assert.ok(graph.nodes.find((n) => n.id === 'node:sink-store'));
  assert.ok(graph.flows.find((f) => f.id === 'flow:1'));
});

test('replace_recipient_fact overrides node.destination and recomputes policyVerdict when a policy is supplied', () => {
  const policy = { allow: [{ sink: 'external-api', class: 'PII', destination: 'trusted\\.example\\.com' }] };
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'replace_recipient_fact', targetNodeId: 'node:sink-external', field: 'destination', value: { literalValue: 'trusted.example.com' } }],
  }, { privacySinkPolicy: policy });
  const node = graph.nodes.find((n) => n.id === 'node:sink-external');
  assert.equal(node.destination.literalValue, 'trusted.example.com');
  const flow = graph.flows.find((f) => f.id === 'flow:2');
  assert.equal(flow.policyVerdict, 'permitted');
});

test('policyVerdict recomputation is skipped (base value kept) when no policy is supplied', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'replace_recipient_fact', targetNodeId: 'node:sink-external', field: 'destination', value: { literalValue: 'trusted.example.com' } }],
  });
  const flow = graph.flows.find((f) => f.id === 'flow:2');
  assert.equal(flow.policyVerdict, 'not_evaluated');
});

test('change_storage_fact overrides node.storeDetail fields', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'change_storage_fact', targetNodeId: 'node:sink-store', field: 'retentionDays', value: 30 }],
  });
  const node = graph.nodes.find((n) => n.id === 'node:sink-store');
  assert.equal(node.storeDetail.retentionDays, 30);
  assert.equal(node.storeDetail.operation, 'write'); // untouched sibling field survives
});

test('change_governance_fact overrides flow.governanceRefs', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'change_governance_fact', targetFlowId: 'flow:1', field: 'lawfulBasis', value: 'consent' }],
  });
  const flow = graph.flows.find((f) => f.id === 'flow:1');
  assert.equal(flow.governanceRefs.lawfulBasis, 'consent');
});

test('an operation targeting a non-existent id is skipped, never throws', () => {
  const { graph, appliedOperations, skippedOperations } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:does-not-exist' }],
  });
  assert.equal(appliedOperations.length, 0);
  assert.equal(skippedOperations.length, 1);
  assert.match(skippedOperations[0].reason, /not found/);
  assert.deepEqual(graph, _fixtureGraph()); // clone is otherwise identical to base
});

test('multiple operations in one scenario apply in order and each is independently reported', () => {
  const { appliedOperations } = applyScenario(_fixtureGraph(), {
    operations: [
      { kind: 'require_transit_protection', targetEdgeId: 'edge:2' },
      { kind: 'apply_handling', targetEdgeId: 'edge:1', handling: 'encrypted' },
    ],
  });
  assert.equal(appliedOperations.length, 2);
});
