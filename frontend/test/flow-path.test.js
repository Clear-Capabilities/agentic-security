import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { flowPathNodeIds, isAiRelevantFlow } from '../src/lib/flow-path.js';

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;
const flowByKey = (key) => FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS[key]);

test('flowPathNodeIds includes the flow\'s own source and sink', () => {
  const flow = flowByKey('flow.pci.masked_log');
  const ids = flowPathNodeIds(FLAGSHIP_GRAPH, flow);
  assert.ok(ids.has(flow.source));
  assert.ok(ids.has(flow.sink));
});

test('flowPathNodeIds includes every edge endpoint for a multi-hop flow', () => {
  const flow = flowByKey('flow.pci.ai'); // 3 edges: web->payments->ai->model
  const ids = flowPathNodeIds(FLAGSHIP_GRAPH, flow);
  for (const edgeId of flow.edgeIds) {
    const edge = FLAGSHIP_GRAPH.edges.find((e) => e.id === edgeId);
    assert.ok(ids.has(edge.from), `missing edge.from ${edge.from}`);
    assert.ok(ids.has(edge.to), `missing edge.to ${edge.to}`);
  }
});

test('isAiRelevantFlow is true for flows whose path touches the AI assistant or model provider', () => {
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.pci.ai')), true);
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.phi.ai')), true);
});

test('isAiRelevantFlow is false for flows that never touch an AI-kind node', () => {
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.pci.masked_log')), false);
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.pii.analytics')), false);
});

test('isAiRelevantFlow does not rely on dataElement.aiContexts (which is empty for every field in this fixture)', () => {
  for (const de of FLAGSHIP_GRAPH.dataElements) {
    assert.deepEqual(de.aiContexts, [], 'sanity check: this fixture genuinely has no populated aiContexts anywhere');
  }
  // yet an AI-topology flow must still be detected:
  assert.equal(isAiRelevantFlow(FLAGSHIP_GRAPH, flowByKey('flow.pci.ai')), true);
});

test('isAiRelevantFlow recognizes the real backend AI subtype vocabulary', () => {
  const graph = {
    nodes: [
      { id: 'node:a', kind: 'process', subtype: null },
      { id: 'node:b', kind: 'sink', subtype: 'ai-model-provider' },
    ],
    edges: [],
  };
  const flow = { id: 'flow:1', source: 'node:a', sink: 'node:b', edgeIds: [] };
  assert.equal(isAiRelevantFlow(graph, flow), true);
});
