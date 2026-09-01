import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import {
  ZONE_ORDER, zoneForNode, resolveSelection, computeFlowSummary, computeArchitectureViewModel,
  computeClusteredLayout, aggregateEdgesForClusters,
} from '../src/views/architecture-view.js';

const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;
const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

test('ZONE_ORDER has the five PRD-named trust zones in order', () => {
  assert.deepEqual(ZONE_ORDER, ['Public Internet', 'Application Layer', 'Service Layer', 'Data Layer', 'External Zone']);
});

test('zoneForNode maps every kind present in the real fixture to one of the five zones', () => {
  for (const node of FLAGSHIP_GRAPH.nodes) {
    assert.ok(ZONE_ORDER.includes(zoneForNode(node)), `node ${node.id} (kind ${node.kind}) mapped to an unknown zone`);
  }
});

test('zoneForNode places the web source in Public Internet and the API gateway in Application Layer', () => {
  const web = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.web']);
  const gateway = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.gateway']);
  assert.equal(zoneForNode(web), 'Public Internet');
  assert.equal(zoneForNode(gateway), 'Application Layer');
});

test('zoneForNode places external and unresolved nodes in External Zone', () => {
  const paymentApi = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.payment_api']);
  const unresolved = FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS['node.unresolved']);
  assert.equal(zoneForNode(paymentApi), 'External Zone');
  assert.equal(zoneForNode(unresolved), 'External Zone');
});

test('computeArchitectureViewModel zones partition all 14 real nodes with no duplicates and no omissions', () => {
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  const allZoneNodeIds = vm.zones.flatMap((z) => z.nodeIds);
  assert.equal(allZoneNodeIds.length, FLAGSHIP_GRAPH.nodes.length);
  assert.equal(new Set(allZoneNodeIds).size, FLAGSHIP_GRAPH.nodes.length);
});

test('computeArchitectureViewModel with no selection: nothing is selected or dimmed', () => {
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  assert.ok(vm.nodes.every((n) => !n.selected && !n.dimmed));
  assert.ok(vm.edges.every((e) => !e.selected && !e.dimmed));
  assert.equal(vm.flowSummary, null);
});

test('resolveSelection on a flow ID includes its source and sink nodes and every one of its edges', () => {
  const maskedLogFlowId = FLOW_KEYS['flow.pci.masked_log'];
  const flow = FLAGSHIP_GRAPH.flows.find((f) => f.id === maskedLogFlowId);
  const selection = resolveSelection(FLAGSHIP_GRAPH, maskedLogFlowId);
  assert.ok(selection.active);
  assert.equal(selection.edgeIds.size, flow.edgeIds.length);
  for (const edgeId of flow.edgeIds) assert.ok(selection.edgeIds.has(edgeId));
  assert.ok(selection.nodeIds.has(flow.source));
  assert.ok(selection.nodeIds.has(flow.sink));
});

test('computeArchitectureViewModel dims every node/edge NOT part of a selected flow', () => {
  const rawLogFlowId = FLOW_KEYS['flow.pci.raw_log'];
  const flow = FLAGSHIP_GRAPH.flows.find((f) => f.id === rawLogFlowId);
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: rawLogFlowId, filters: {} });
  const selectedNodeCount = vm.nodes.filter((n) => n.selected).length;
  const dimmedNodeCount = vm.nodes.filter((n) => n.dimmed).length;
  assert.ok(selectedNodeCount > 0 && selectedNodeCount < FLAGSHIP_GRAPH.nodes.length, 'a flow selection should highlight some but not all nodes');
  assert.equal(selectedNodeCount + dimmedNodeCount, FLAGSHIP_GRAPH.nodes.length);
  assert.notEqual(vm.flowSummary, null);
  assert.equal(vm.flowSummary.flowId, rawLogFlowId);
});

test('resolveSelection on a node ID selects just that node plus its incident edges', () => {
  const webId = NODE_KEYS['node.web'];
  const selection = resolveSelection(FLAGSHIP_GRAPH, webId);
  assert.deepEqual([...selection.nodeIds], [webId]);
  const expectedEdgeCount = FLAGSHIP_GRAPH.edges.filter((e) => e.from === webId || e.to === webId).length;
  assert.equal(selection.edgeIds.size, expectedEdgeCount);
  assert.ok(expectedEdgeCount > 0, 'sanity check: the web node should have at least one incident edge in this fixture');
});

// NOTE: the brief this test was transcribed from asserted this against
// `node.retention`, on the claim that it "has no modeled edges in the real
// fixture". Reading scanner/src/lineage/fixtures/flagship-graph.json (via
// the generated frontend/src/data/flagship-graph.js) directly shows that is
// incorrect: node.retention (node:process:0ee928561e67) has TWO incident
// edges — edge:7e89a832924a (from Analytics API) and edge:45861b8f1424 (to
// node.deletion). It is disconnected from every *flow* (no flow.edgeIds
// list references either edge), but not from the raw edge graph, which is
// what resolveSelection(graph, nodeId) walks. The node that is genuinely
// disconnected at the edge-graph level — zero entries in FLAGSHIP_GRAPH.edges
// touch it at all — is node.gateway (API Gateway, node:api:02d844c7d1cd).
// Swapped to that node so the assertion matches the real fixture data.
test('resolveSelection on the disconnected API gateway node selects it with zero edges, not an error', () => {
  const gatewayId = NODE_KEYS['node.gateway'];
  const selection = resolveSelection(FLAGSHIP_GRAPH, gatewayId);
  assert.deepEqual([...selection.nodeIds], [gatewayId]);
  assert.equal(selection.edgeIds.size, 0, 'node.gateway has no modeled edges in the real fixture — a genuine disconnected-node case (AC-11), not a bug');
});

test('resolveSelection on an unknown ID returns an inactive selection rather than throwing', () => {
  const selection = resolveSelection(FLAGSHIP_GRAPH, 'node:this-id-does-not-exist');
  assert.equal(selection.active, false);
});

test('resolveSelection on null returns an inactive selection', () => {
  const selection = resolveSelection(FLAGSHIP_GRAPH, null);
  assert.equal(selection.active, false);
});

test('computeFlowSummary for the raw-log PCI flow reports it as unprotected with an internal-only recipient', () => {
  const rawLogFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.raw_log']);
  const summary = computeFlowSummary(FLAGSHIP_GRAPH, rawLogFlow);
  assert.equal(summary.dataElementName, 'card_number');
  assert.deepEqual(summary.dataClasses, ['PCI']);
  assert.equal(summary.protectionSummary, 'unprotected');
  assert.deepEqual(summary.externalRecipients, [], 'the raw-log flow stays internal — Application Logs is not external');
});

test('computeFlowSummary for the payment-API PCI flow reports an external recipient', () => {
  const paymentApiFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.payment_api']);
  const summary = computeFlowSummary(FLAGSHIP_GRAPH, paymentApiFlow);
  assert.ok(summary.externalRecipients.length > 0, 'the payment-API flow should surface Payment API as an external recipient');
});

test('computeFlowSummary aggregates per-dimension verdicts using worstVerdict across the flow\'s own edges', () => {
  const maskedLogFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.masked_log']);
  const summary = computeFlowSummary(FLAGSHIP_GRAPH, maskedLogFlow);
  assert.equal(summary.handlingVerdict, 'protected', 'the masked-log flow\'s handling dimension should reflect the proven maskCard() protection');
});

// I4 (final whole-branch review): a node with externality.value === 'unknown'
// must NOT be silently folded into "no external recipients" — that reads as
// false reassurance when the truth is "the scanner couldn't resolve this
// destination". The real fixture's flow.pii.unresolved flow sinks at
// "Unresolved Destination" (node:unresolved:b67f539cc277), whose
// externality.value is 'unknown', not 'external'.
test('computeFlowSummary surfaces an unknown-externality recipient separately from external recipients', () => {
  const unresolvedFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pii.unresolved']);
  const sinkNode = FLAGSHIP_GRAPH.nodes.find((n) => n.id === unresolvedFlow.sink);
  assert.equal(sinkNode.externality.value, 'unknown', 'sanity check: the fixture node this test targets must actually have unknown externality');

  const summary = computeFlowSummary(FLAGSHIP_GRAPH, unresolvedFlow);
  assert.deepEqual(summary.externalRecipients, [], 'a merely-unknown recipient must not be counted as external');
  assert.deepEqual(summary.unknownRecipients, [sinkNode.label]);
});

// I5 (final whole-branch review): totalDestinations was a hardcoded literal
// (always 1) masquerading as a computed field — this data model has each
// flow point at exactly one sink by construction, so the field was removed
// entirely rather than kept as fake computation.
test('computeFlowSummary does not report a totalDestinations field', () => {
  const rawLogFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.raw_log']);
  const summary = computeFlowSummary(FLAGSHIP_GRAPH, rawLogFlow);
  assert.equal('totalDestinations' in summary, false);
});

// I6 (final whole-branch review): resolveSelection's edge-ID branch had no
// test coverage. Selecting by a real edge ID (not a node or flow ID) should
// select exactly that edge and its two endpoint nodes.
test('resolveSelection on an edge ID selects that edge and its two endpoint nodes', () => {
  const maskedLogFlow = FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS['flow.pci.masked_log']);
  const edgeId = maskedLogFlow.edgeIds[0];
  const edge = FLAGSHIP_GRAPH.edges.find((e) => e.id === edgeId);

  const selection = resolveSelection(FLAGSHIP_GRAPH, edgeId);
  assert.equal(selection.active, true);
  assert.deepEqual(selection.nodeIds, new Set([edge.from, edge.to]));
  assert.deepEqual(selection.edgeIds, new Set([edgeId]));
});

function makeNode(id, kind, zone, overrides = {}) {
  return { id, label: id, kind, subtype: null, zone, selected: false, dimmed: false, ...overrides };
}

test('computeClusteredLayout: a zone under budget has no cluster', () => {
  const zones = [{ name: 'Data Layer', nodeIds: ['n1', 'n2', 'n3'] }];
  const nodes = [makeNode('n1', 'store', 'Data Layer'), makeNode('n2', 'store', 'Data Layer'), makeNode('n3', 'log', 'Data Layer')];
  const result = computeClusteredLayout(zones, nodes, 10);
  assert.equal(result.length, 1);
  assert.deepEqual(result[0].visibleNodeIds, ['n1', 'n2', 'n3']);
  assert.equal(result[0].cluster, null);
});

test('computeClusteredLayout: a zone over budget clusters the overflow, budget-1 stay individually visible', () => {
  const nodeIds = Array.from({ length: 10 }, (_, i) => `n${i}`);
  const zones = [{ name: 'Data Layer', nodeIds }];
  const nodes = nodeIds.map((id, i) => makeNode(id, i % 2 === 0 ? 'store' : 'log', 'Data Layer'));
  const result = computeClusteredLayout(zones, nodes, 4);
  assert.equal(result[0].visibleNodeIds.length, 3, 'budget of 4 leaves room for 1 cluster glyph slot: 3 individual + 1 cluster');
  assert.ok(result[0].cluster, 'expected a cluster for the overflow');
  assert.equal(result[0].cluster.count, 7, '10 total - 3 individually visible = 7 clustered');
  assert.ok(result[0].cluster.kindSummary.includes('store'));
  assert.ok(result[0].cluster.kindSummary.includes('log'));
});

test('computeClusteredLayout: a SELECTED node is always visible, bypassing the budget, even beyond the cutoff', () => {
  const nodeIds = Array.from({ length: 10 }, (_, i) => `n${i}`);
  const zones = [{ name: 'Data Layer', nodeIds }];
  const nodes = nodeIds.map((id, i) => makeNode(id, 'store', 'Data Layer', { selected: id === 'n9' }));
  const result = computeClusteredLayout(zones, nodes, 4);
  assert.ok(result[0].visibleNodeIds.includes('n9'), 'the selected node (last in graph order, would normally be clustered) must stay visible');
  assert.equal(result[0].cluster.count, 6, '10 total - 3 unselected-individual - 1 selected = 6 clustered (one fewer than the unselected-only case, since n9 no longer competes for a budget slot but also is not counted as clustered)');
});

test('computeClusteredLayout: cluster kindSummary is deduplicated and sorted (deterministic across renders)', () => {
  const nodeIds = Array.from({ length: 6 }, (_, i) => `n${i}`);
  const zones = [{ name: 'Data Layer', nodeIds }];
  const nodes = nodeIds.map((id) => makeNode(id, 'store', 'Data Layer'));
  const result = computeClusteredLayout(zones, nodes, 2);
  assert.equal(result[0].cluster.kindSummary, 'store', 'all-same-kind overflow should not repeat "store, store, store"');
});

function makeEdge(id, from, to, verdict, overrides = {}) {
  return { id, from, to, verdict, selected: false, dimmed: false, ...overrides };
}

test('aggregateEdgesForClusters: an edge between two individually-visible nodes passes through unchanged', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: ['a', 'b'], cluster: null }];
  const edges = [makeEdge('e1', 'a', 'b', 'protected')];
  const result = aggregateEdgesForClusters(edges, clusteredZones);
  assert.deepEqual(result, [{ ...edges[0], constituentCount: 1 }]);
});

test('aggregateEdgesForClusters: multiple edges into the same cluster aggregate into one, worst verdict wins', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: ['a'], cluster: { id: 'cluster:Z', count: 2, kindSummary: 'store', memberIds: ['b', 'c'] } }];
  const edges = [
    makeEdge('e1', 'a', 'b', 'protected'),
    makeEdge('e2', 'a', 'c', 'unprotected'),
  ];
  const result = aggregateEdgesForClusters(edges, clusteredZones);
  assert.equal(result.length, 1, 'both edges target the same cluster, from the same source — must aggregate to 1');
  assert.equal(result[0].from, 'a');
  assert.equal(result[0].to, 'cluster:Z');
  assert.equal(result[0].verdict, 'unprotected', 'worst of protected/unprotected is unprotected');
  assert.equal(result[0].constituentCount, 2);
});

test('aggregateEdgesForClusters: an edge selected if ANY constituent is selected', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: ['a'], cluster: { id: 'cluster:Z', count: 2, kindSummary: 'store', memberIds: ['b', 'c'] } }];
  const edges = [
    makeEdge('e1', 'a', 'b', 'protected', { selected: true }),
    makeEdge('e2', 'a', 'c', 'unprotected', { selected: false }),
  ];
  const result = aggregateEdgesForClusters(edges, clusteredZones);
  assert.equal(result[0].selected, true);
});

test('aggregateEdgesForClusters: an edge entirely within one cluster (both endpoints clustered into the SAME cluster) is dropped, not rendered as a self-loop', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: [], cluster: { id: 'cluster:Z', count: 2, kindSummary: 'store', memberIds: ['b', 'c'] } }];
  const edges = [makeEdge('e1', 'b', 'c', 'protected')];
  const result = aggregateEdgesForClusters(edges, clusteredZones);
  assert.equal(result.length, 0);
});

test('aggregateEdgesForClusters: aggregate edge id is stable/deterministic across two calls with the same input (no re-render churn)', () => {
  const clusteredZones = [{ name: 'Z', visibleNodeIds: ['a'], cluster: { id: 'cluster:Z', count: 2, kindSummary: 'store', memberIds: ['b', 'c'] } }];
  const edges = [makeEdge('e1', 'a', 'b', 'protected'), makeEdge('e2', 'a', 'c', 'unprotected')];
  const result1 = aggregateEdgesForClusters(edges, clusteredZones);
  const result2 = aggregateEdgesForClusters(edges, clusteredZones);
  assert.equal(result1[0].id, result2[0].id);
});
