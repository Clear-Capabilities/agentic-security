import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { LIFECYCLE_STAGES, stageForNode, computePrivacyRow, computePrivacyViewModel } from '../src/views/privacy-view.js';

const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;
const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;
const flowByKey = (key) => FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS[key]);
const nodeByKey = (key) => FLAGSHIP_GRAPH.nodes.find((n) => n.id === NODE_KEYS[key]);

test('LIFECYCLE_STAGES has the six PRD-named stages in order', () => {
  assert.deepEqual(LIFECYCLE_STAGES, ['collection', 'processing', 'storage', 'sharing', 'retention', 'deletion']);
});

test('stageForNode reads the real fixture\'s lifecycleStages field directly', () => {
  assert.equal(stageForNode(nodeByKey('node.web')), 'collection');
  assert.equal(stageForNode(nodeByKey('node.retention')), 'retention');
  assert.equal(stageForNode(nodeByKey('node.deletion')), 'deletion');
});

test('every real fixture node maps to one of the six known stages', () => {
  for (const node of FLAGSHIP_GRAPH.nodes) {
    assert.ok(LIFECYCLE_STAGES.includes(stageForNode(node)), `node ${node.id} has stage "${stageForNode(node)}" not in LIFECYCLE_STAGES`);
  }
});

test('computePrivacyRow for the masked-log PCI flow places its nodes in the correct stage cells', () => {
  const flow = flowByKey('flow.pci.masked_log');
  const row = computePrivacyRow(FLAGSHIP_GRAPH, flow);
  assert.equal(row.dataElementName, 'card_number');
  assert.deepEqual(row.dataClasses, ['PCI']);
  const collectionCell = row.stageCells.find((c) => c.stage === 'collection');
  const processingCell = row.stageCells.find((c) => c.stage === 'processing');
  const storageCell = row.stageCells.find((c) => c.stage === 'storage');
  assert.ok(collectionCell.nodeLabels.includes('Web App'));
  assert.ok(processingCell.nodeLabels.includes('Payments Service'));
  assert.ok(storageCell.nodeLabels.includes('Application Logs'));
});

test('computePrivacyRow surfaces real manual_required governance facts, never invents them', () => {
  const aiFlow = flowByKey('flow.pci.ai');
  const row = computePrivacyRow(FLAGSHIP_GRAPH, aiFlow);
  assert.deepEqual(row.governanceRefs, aiFlow.governanceRefs);
  assert.equal(row.governanceRefs.lawfulBasis, 'manual_required');

  const nonGovernedFlow = flowByKey('flow.pci.masked_log');
  const nonGovernedRow = computePrivacyRow(FLAGSHIP_GRAPH, nonGovernedFlow);
  assert.deepEqual(nonGovernedRow.governanceRefs, {}, 'a flow with no real governance facts must show an empty object, not fabricated manual_required markers');
});

test('computePrivacyRow reports AI relevance via topology, matching flow-path.js', () => {
  assert.equal(computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pci.ai')).isAiRelevant, true);
  assert.equal(computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pii.analytics')).isAiRelevant, false);
});

test('computePrivacyViewModel produces one row per real flow, in the same order as graph.flows', () => {
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  assert.equal(vm.rows.length, FLAGSHIP_GRAPH.flows.length);
  assert.deepEqual(vm.stages, LIFECYCLE_STAGES);
  assert.ok(vm.rows.every((r) => !r.selected));
});

test('computePrivacyViewModel marks the selected flow\'s row as selected and no others', () => {
  const selectedFlowId = FLOW_KEYS['flow.pci.raw_log'];
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: selectedFlowId, filters: {} });
  const selectedRows = vm.rows.filter((r) => r.selected);
  assert.equal(selectedRows.length, 1);
  assert.equal(selectedRows[0].flowId, selectedFlowId);
});

test('computePrivacyViewModel applies a dataClass filter (OR within the dimension)', () => {
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: { dataClass: ['PHI'] } });
  const visibleRows = vm.rows.filter((r) => r.visible);
  assert.ok(visibleRows.length > 0, 'at least the PHI flow should remain visible');
  assert.ok(visibleRows.every((r) => r.dataClasses.includes('PHI')));
});

test('computePrivacyViewModel with no filters marks every row visible', () => {
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  assert.ok(vm.rows.every((r) => r.visible));
});
