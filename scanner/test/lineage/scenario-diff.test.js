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

test('WATCHED_SCENARIO_FIELDS never includes an entity-identity field like id/kind/from/to', () => {
  for (const fields of Object.values(WATCHED_SCENARIO_FIELDS)) {
    assert.ok(!fields.includes('id'));
  }
});

test('diffScenarioGraph never throws on a graph with zero flows/edges', () => {
  const empty = { ..._fixtureGraph(), nodes: [], edges: [], flows: [], dataElements: [] };
  assert.doesNotThrow(() => diffScenarioGraph(empty, empty));
});
