import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffScenarioGraph, WATCHED_SCENARIO_FIELDS } from '../../src/lineage/scenario-diff.js';
import { applyScenario } from '../../src/lineage/scenario-engine.js';
import { emptyProtection } from '../../src/lineage/protection.js';

function _fixtureGraph() {
  return {
    graphId: 'graph:abc', schemaVersion: '1.0.0',
    nodes: [
      { id: 'node:source', kind: 'source', subtype: 'user-input', destination: null, storeDetail: null },
      { id: 'node:sink', kind: 'sink', subtype: 'external-api', destination: { literalValue: 'api.example.com' }, storeDetail: null },
    ],
    edges: [
      { id: 'edge:1', from: 'node:source', to: 'node:sink', relationship: 'flows_to', protection: emptyProtection() },
    ],
    dataElements: [{ id: 'de:1', name: 'email', aliases: [], dataClasses: ['PII'], aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: null }],
    flows: [{ id: 'flow:1', dataElementIds: ['de:1'], source: 'node:source', sink: 'node:sink', edgeIds: ['edge:1'], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 0.8, tier: 'high' }, governanceRefs: {} }],
    evidence: [], coverage: {},
  };
}

test('no operations applied -> no changed entities, no removed entities', () => {
  const base = _fixtureGraph();
  const { changedEntities, removedEntityIds } = diffScenarioGraph(base, base);
  assert.deepEqual(changedEntities, []);
  assert.deepEqual(removedEntityIds, []);
});

test('a require_transit_protection operation surfaces the edge AND its flow as changed', () => {
  const base = _fixtureGraph();
  const { graph } = applyScenario(base, { operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }] });
  const { changedEntities } = diffScenarioGraph(base, graph);
  const edgeChange = changedEntities.find((c) => c.id === 'edge:1');
  assert.equal(edgeChange.kind, 'edge');
  assert.ok(edgeChange.changedFields.some((f) => f.field === 'protection.transit'));
  const flowChange = changedEntities.find((c) => c.id === 'flow:1');
  assert.equal(flowChange.kind, 'flow');
  assert.ok(flowChange.changedFields.some((f) => f.field === 'protectionSummary' && f.before === 'not_assessed' && f.after === 'protected'));
});

test('a remove_entity operation reports removedEntityIds for the node, its edge, and its flow — never as a changedEntities row', () => {
  const base = _fixtureGraph();
  const { graph } = applyScenario(base, { operations: [{ kind: 'remove_entity', targetNodeId: 'node:sink' }] });
  const { changedEntities, removedEntityIds } = diffScenarioGraph(base, graph);
  assert.deepEqual([...removedEntityIds].sort(), ['edge:1', 'flow:1', 'node:sink']);
  assert.equal(changedEntities.find((c) => c.id === 'node:sink'), undefined);
});

// Finding 1 (task-3-review.md), the live reproduction: with
// replace_recipient_fact now restricted to field:'destination' at the
// applier level (scenario-engine.js), 'destination' is the ONLY field it
// can ever write on a node — and that field IS watched, so a real applied
// mutation is genuinely, verifiably visible to the diff. This is the
// regression test for the review's exact scenario (previously
// `field: 'subtype'`, silently invisible; now the one field the applier
// still allows, correctly surfaced).
test('a replace_recipient_fact operation surfaces node.destination as changed, and rejects a non-destination field so nothing else can ever go unwatched', () => {
  const base = _fixtureGraph();
  const { graph, skippedOperations } = applyScenario(base, {
    operations: [
      { kind: 'replace_recipient_fact', targetNodeId: 'node:sink', field: 'destination', value: { literalValue: 'moved.example.com' } },
      // Proves, in the same scenario, that a non-destination field never
      // reaches the node at all — so there is nothing WATCHED_SCENARIO_FIELDS
      // would need to additionally watch for this operation kind.
      { kind: 'replace_recipient_fact', targetNodeId: 'node:sink', field: 'subtype', value: 'webhook' },
    ],
  });
  assert.equal(skippedOperations.length, 1);
  assert.match(skippedOperations[0].reason, /only supports field "destination"/);

  const { changedEntities } = diffScenarioGraph(base, graph);
  const nodeChange = changedEntities.find((c) => c.id === 'node:sink');
  assert.equal(nodeChange.kind, 'node');
  const destinationChange = nodeChange.changedFields.find((f) => f.field === 'destination');
  assert.ok(destinationChange, 'node.destination change must be visible to diffScenarioGraph');
  assert.equal(destinationChange.after.literalValue, 'moved.example.com');

  // The rejected subtype write never happened, so the node's real subtype
  // is untouched — nothing for the diff to have missed.
  const node = graph.nodes.find((n) => n.id === 'node:sink');
  assert.equal(node.subtype, 'external-api');
});

// AC-26 ("What-if changes cannot masquerade as implementation"): the
// PRD's own worked example — "the user simulates TLS on a cleartext...
// edge" — must produce a changedEntities[] entry LITERALLY labeled
// HYPOTHETICAL, not just an evidenceGrade:'assumed' value buried in the
// before/after diff.
test('AC-26: a require_transit_protection operation labels its edge entry HYPOTHETICAL', () => {
  const base = _fixtureGraph();
  const { graph } = applyScenario(base, { operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }] });
  const { changedEntities } = diffScenarioGraph(base, graph);
  const edgeChange = changedEntities.find((c) => c.id === 'edge:1');
  assert.equal(edgeChange.label, 'HYPOTHETICAL');
});

test('AC-26: an apply_handling operation (also evidenceGrade:assumed) also labels its edge entry HYPOTHETICAL', () => {
  const base = _fixtureGraph();
  const { graph } = applyScenario(base, { operations: [{ kind: 'apply_handling', targetEdgeId: 'edge:1', handling: 'masked' }] });
  const { changedEntities } = diffScenarioGraph(base, graph);
  const edgeChange = changedEntities.find((c) => c.id === 'edge:1');
  assert.equal(edgeChange.kind, 'edge');
  assert.ok(edgeChange.changedFields.some((f) => f.field === 'protection.handling'));
  assert.equal(edgeChange.label, 'HYPOTHETICAL');
});

test('AC-26: a NODE-kind changed entity (replace_recipient_fact) never carries a label field at all', () => {
  const base = _fixtureGraph();
  const { graph } = applyScenario(base, {
    operations: [{ kind: 'replace_recipient_fact', targetNodeId: 'node:sink', field: 'destination', value: { literalValue: 'moved.example.com' } }],
  });
  const { changedEntities } = diffScenarioGraph(base, graph);
  const nodeChange = changedEntities.find((c) => c.id === 'node:sink');
  assert.equal(nodeChange.kind, 'node');
  assert.ok(!('label' in nodeChange), 'a node-kind changed entity must not carry a label field at all');
});

test('AC-26: a FLOW-kind changed entity never carries a label field at all', () => {
  const base = _fixtureGraph();
  const { graph } = applyScenario(base, { operations: [{ kind: 'require_transit_protection', targetEdgeId: 'edge:1' }] });
  const { changedEntities } = diffScenarioGraph(base, graph);
  const flowChange = changedEntities.find((c) => c.id === 'flow:1');
  assert.equal(flowChange.kind, 'flow');
  assert.ok(!('label' in flowChange), 'a flow-kind changed entity must not carry a label field at all');
});

test('WATCHED_SCENARIO_FIELDS never includes an entity-identity field like id/kind/from/to', () => {
  for (const fields of Object.values(WATCHED_SCENARIO_FIELDS)) {
    assert.ok(!fields.includes('id'));
  }
});

test('diffScenarioGraph never throws on a graph with zero flows/edges', () => {
  const empty = { ..._fixtureGraph(), nodes: [], edges: [], flows: [], dataElements: [] };
  assert.doesNotThrow(() => diffScenarioGraph(empty, empty));
});
