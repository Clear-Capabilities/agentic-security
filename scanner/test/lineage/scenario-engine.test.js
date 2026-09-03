import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyScenario } from '../../src/lineage/scenario-engine.js';
import { emptyProtection } from '../../src/lineage/protection.js';

function _fixtureGraph() {
  return {
    graphId: 'graph:abc', schemaVersion: '1.0.0', generatedAt: '2026-09-02T00:00:00.000Z',
    nodes: [
      { id: 'node:source', kind: 'source', subtype: 'user-input', destination: null, storeDetail: null },
      { id: 'node:sink-store', kind: 'store', subtype: 'database', destination: { literalValue: 'db.internal.example.com' }, storeDetail: { operation: 'write' } },
      { id: 'node:sink-external', kind: 'external', subtype: 'external-api', destination: { literalValue: 'api.vendor.example.com' }, storeDetail: null },
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

// Finding 1 (task-3-review.md): replace_recipient_fact must be restricted
// to exactly node.destination at the applier level — scenario.js's own
// SCENARIO_OPERATION_REQUIRED_FIELDS never restricts `field`'s value, so
// without this guard a real applied write to an arbitrary field (e.g.
// 'subtype') would land on the node but be completely invisible to
// scenario-diff.js's WATCHED_SCENARIO_FIELDS.node (which only watches
// 'destination'/'storeDetail').
test('replace_recipient_fact with a non-"destination" field is skipped, never applied', () => {
  const { graph, appliedOperations, skippedOperations } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'replace_recipient_fact', targetNodeId: 'node:sink-external', field: 'subtype', value: 'webhook' }],
  });
  assert.equal(appliedOperations.length, 0);
  assert.equal(skippedOperations.length, 1);
  assert.match(skippedOperations[0].reason, /only supports field "destination"/);
  const node = graph.nodes.find((n) => n.id === 'node:sink-external');
  assert.equal(node.subtype, 'external-api'); // unchanged — the write never happened
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

// Finding 1 (task-2-review.md): apply_handling('encrypted') must only set
// edge.protection.atRest on an edge whose sink node is store-kind (mirrors
// graph-builder.js's own gate, ~line 757: `handlingResult === 'encrypted'
// && snk.kind === 'store'`). For any other sink kind (e.g. edge:2's
// external-api sink), it must fall through to the 'handling' dimension
// instead — never claim a false 'protected' atRest verdict for a
// destination with no "at rest" concept at all.
test('apply_handling(encrypted) on a non-store-sink edge sets handling, not atRest', () => {
  const { graph } = applyScenario(_fixtureGraph(), {
    operations: [{ kind: 'apply_handling', targetEdgeId: 'edge:2', handling: 'encrypted' }],
  });
  const edge = graph.edges.find((e) => e.id === 'edge:2');
  assert.deepEqual(edge.protection.handling, { verdict: 'protected', evidenceGrade: 'assumed' });
  assert.deepEqual(edge.protection.atRest, emptyProtection().atRest);
});

// Finding 2 (task-2-review.md): protectionSummary recomputation must
// aggregate over EVERY edge in flow.edgeIds, not just the first one
// `graph.edges.find` happens to return. Build a two-edge flow and change
// the SECOND edge — the flow's protectionSummary must reflect it.
function _multiEdgeFlowGraph() {
  const base = _fixtureGraph();
  base.nodes.push({ id: 'node:mid', kind: 'process', subtype: 'process', destination: null, storeDetail: null });
  base.edges.push({ id: 'edge:mid-a', from: 'node:source', to: 'node:mid', relationship: 'flows_to', protection: emptyProtection() });
  base.edges.push({ id: 'edge:mid-b', from: 'node:mid', to: 'node:sink-external', relationship: 'flows_to', protection: emptyProtection() });
  base.flows.push({
    id: 'flow:multi', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink-external',
    edgeIds: ['edge:mid-a', 'edge:mid-b'], transformationIds: [], alternatePathCount: 0,
    policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [],
    confidence: { score: 0.8, tier: 'high' }, governanceRefs: {},
  });
  return base;
}

test('protectionSummary recomputation aggregates across ALL of a multi-edge flow\'s edges, not just the first', () => {
  const { graph } = applyScenario(_multiEdgeFlowGraph(), {
    // Targets edge:mid-b — the SECOND edge in flow:multi.edgeIds, not the
    // one graph.edges.find(...) would return first by array order.
    operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:mid-b' }],
  });
  const edgeB = graph.edges.find((e) => e.id === 'edge:mid-b');
  assert.deepEqual(edgeB.protection.transit, { verdict: 'protected', evidenceGrade: 'assumed' });
  const flow = graph.flows.find((f) => f.id === 'flow:multi');
  assert.equal(flow.protectionSummary, 'protected');
});
