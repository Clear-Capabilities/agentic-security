import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyGraphEnvelope } from '../../src/lineage/schema.js';
import { nodeId, dataElementId, edgeId, flowId } from '../../src/lineage/ids.js';
import { emptyProtection } from '../../src/lineage/protection.js';
import { validateGraph } from '../../src/lineage/validate.js';

test('an empty-but-well-formed envelope is valid', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const result = validateGraph(graph);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});

test('non-object input never throws and reports one error', () => {
  assert.deepEqual(validateGraph(null), { valid: false, errors: [{ path: '$', message: 'graph must be an object' }] });
  assert.deepEqual(validateGraph('nope').valid, false);
  assert.deepEqual(validateGraph(undefined).valid, false);
});

test('wrong schemaVersion is an error', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.schemaVersion = '0.9.0';
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.schemaVersion'));
});

test('a well-formed node with a bad kind is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push({
    id: nodeId('source', ['x']), kind: 'not-a-real-kind', subtype: 'x', label: 'X',
    aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] },
    lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
    confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled',
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path.includes('nodes[0].kind')));
});

test('a valid two-node, one-edge, one-flow graph passes', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const src = nodeId('source', ['payments-platform', 'web']);
  const sink = nodeId('log', ['payments-platform', 'logs']);
  const de = dataElementId('card_number', ['payments-platform']);
  graph.nodes.push(
    { id: src, kind: 'source', subtype: 'web-app', label: 'Web App', aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: ['collection'], governanceRefs: {}, dataElementIds: [de], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled' },
    { id: sink, kind: 'log', subtype: 'application-logs', label: 'Application Logs', aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: ['storage'], governanceRefs: {}, dataElementIds: [de], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled' },
  );
  graph.dataElements.push({ id: de, name: 'card_number', aliases: [], declaredType: null, dataClasses: ['PCI'], aiContexts: [], sourceLocations: [], dataSubjectCategory: null, classificationEvidence: [], manualOverride: false });
  const edge = { id: edgeId(src, sink, 'data_flow'), from: src, to: sink, relationship: 'data_flow', fieldMappings: [{ fromPath: 'card_number', toPath: 'maskedPan', dataElementIds: [de], mappingType: 'transformation', transformationIds: [] }], protocol: { name: 'in-process', destinationResolution: 'literal' }, boundaryCrossings: [], protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled' };
  graph.edges.push(edge);
  graph.flows.push({ id: flowId(src, sink, [de]), dataElementIds: [de], source: src, sink: sink, edgeIds: [edge.id], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled', findingRefs: [], governanceRefs: {}, limitations: [] });
  const result = validateGraph(graph);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});

test('an edge referencing a nonexistent node id is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.edges.push({ id: 'edge:deadbeef0000', from: 'node:missing:aaa', to: 'node:missing:bbb', relationship: 'data_flow', fieldMappings: [], protocol: {}, boundaryCrossings: [], protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled' });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.message.includes('unknown node id')));
});
