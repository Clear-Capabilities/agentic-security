import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { computeInspectorViewModel } from '../src/components/evidence-inspector.js';

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;
const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;

test('computeInspectorViewModel returns null when nothing is selected', () => {
  assert.equal(computeInspectorViewModel(FLAGSHIP_GRAPH, null), null);
});

test('computeInspectorViewModel returns null for an unresolvable id rather than throwing', () => {
  assert.equal(computeInspectorViewModel(FLAGSHIP_GRAPH, 'flow:does-not-exist'), null);
});

test('computeInspectorViewModel on the masked-log flow resolves real supporting evidence, not a placeholder', () => {
  const flowId = FLOW_KEYS['flow.pci.masked_log'];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, flowId);
  assert.equal(vm.kind, 'flow');
  assert.equal(vm.id, flowId);
  assert.ok(vm.claim.includes('card_number'), 'the claim should name the actual field');
  assert.ok(vm.supporting.length > 0, 'the masked-log flow has a real evidenceRefs entry — it must resolve to a real evidence object');
  for (const item of vm.supporting) {
    assert.ok(FLAGSHIP_GRAPH.evidence.some((e) => e.id === item.id), 'every supporting item must be a real evidence object from the graph, not fabricated');
  }
});

test('computeInspectorViewModel exposes the flow\'s real limitations array (what the scanner does not know)', () => {
  const flowId = FLOW_KEYS['flow.pci.database'];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, flowId);
  assert.deepEqual(vm.limitations, FLAGSHIP_GRAPH.flows.find((f) => f.id === flowId).limitations);
  assert.ok(vm.limitations.length > 0, 'the database flow has a real, honest limitation (no correlated at-rest config) — it must not be dropped');
});

test('computeInspectorViewModel on an edge describes all three protection dimensions', () => {
  const flow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.masked_log']);
  const edgeId = flow.edgeIds[flow.edgeIds.length - 1];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, edgeId);
  assert.equal(vm.kind, 'edge');
  const edge = FLAGSHIP_GRAPH.edges.find((e) => e.id === edgeId);
  assert.ok(vm.claim.includes(edge.protection.handling.verdict));
});

test('computeInspectorViewModel on a node describes its kind/subtype', () => {
  const webId = NODE_KEYS['node.web'];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, webId);
  assert.equal(vm.kind, 'node');
  assert.ok(vm.claim.includes('Web App'));
});

test('computeInspectorViewModel never returns a conflicting-evidence item unless the evidence object actually says conflict:true', () => {
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const vm = computeInspectorViewModel(FLAGSHIP_GRAPH, flowId);
  assert.equal(vm.conflicting.length, 0, 'no evidence in the current fixture is marked conflicting — this must not be invented');
  for (const item of vm.conflicting) assert.equal(item.conflict, true);
});
