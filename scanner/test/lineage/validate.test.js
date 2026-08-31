import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyGraphEnvelope, HANDLING_VALUES, STORE_OPERATION_VALUES } from '../../src/lineage/schema.js';
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

test('a node with wrong id prefix is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push({
    id: 'whatever:not-a-node', kind: 'source', subtype: 'x', label: 'X',
    aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] },
    lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
    confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled',
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.nodes[0].id' && e.message.includes('must start with "node:"')));
});

test('an edge with wrong id prefix is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.edges.push({
    id: 'bad-prefix:123', from: 'node:a', to: 'node:b', relationship: 'data_flow',
    fieldMappings: [], protocol: {}, boundaryCrossings: [], protection: emptyProtection(),
    evidenceRefs: [], coverageStatus: 'modeled',
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.edges[0].id' && e.message.includes('must start with "edge:"')));
});

test('a flow with wrong id prefix is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.flows.push({
    id: 'wrong:prefix', dataElementIds: [], source: 'node:a', sink: 'node:b',
    edgeIds: [], policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed',
    evidenceRefs: [], coverageStatus: 'modeled',
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.flows[0].id' && e.message.includes('must start with "flow:"')));
});

test('a dataElement with wrong id prefix is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.dataElements.push({
    id: 'notdata:123', name: 'field', aliases: [], dataClasses: [],
    aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: false,
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.dataElements[0].id' && e.message.includes('must start with "data:"')));
});

test('a dataElement with unknown dataClass is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.dataElements.push({
    id: dataElementId('field', []), name: 'field', aliases: [], dataClasses: ['PCI', 'TOTALLY_MADE_UP'],
    aiContexts: [], sourceLocations: [], classificationEvidence: [], manualOverride: false,
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.dataElements[0].dataClasses[1]' && e.message.includes('TOTALLY_MADE_UP')));
});

test('a dataElement with unknown aiContext is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.dataElements.push({
    id: dataElementId('field', []), name: 'field', aliases: [], dataClasses: ['PCI'],
    aiContexts: ['ai.model_input', 'not.a.real.context'], sourceLocations: [], classificationEvidence: [], manualOverride: false,
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.dataElements[0].aiContexts[1]' && e.message.includes('not.a.real.context')));
});

test('a graph.scope.source outside GRAPH_SCOPE_SOURCES is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg', scope: { source: 'banana' } });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.scope.source' && e.message.includes('banana')));
});

test('a flow with a bogus policyVerdict is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.flows.push({
    id: 'flow:abc', dataElementIds: [], source: 'node:a', sink: 'node:b',
    edgeIds: [], policyVerdict: 'TOTALLY_FINE', protectionSummary: 'not_assessed',
    evidenceRefs: [], coverageStatus: 'modeled',
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.flows[0].policyVerdict' && e.message.includes('TOTALLY_FINE')));
});

test('a flow with a bogus protectionSummary is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.flows.push({
    id: 'flow:abc', dataElementIds: [], source: 'node:a', sink: 'node:b',
    edgeIds: [], policyVerdict: 'not_evaluated', protectionSummary: 'super-protected',
    evidenceRefs: [], coverageStatus: 'modeled',
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.flows[0].protectionSummary' && e.message.includes('super-protected')));
});

test('an edge with a bogus protocol.destinationResolution is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.edges.push({
    id: 'edge:abc', from: 'node:a', to: 'node:b', relationship: 'data_flow',
    fieldMappings: [], protocol: { name: 'http', destinationResolution: 'teleportation' },
    boundaryCrossings: [], protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled',
  });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.edges[0].protocol.destinationResolution' && e.message.includes('teleportation')));
});

// ── Milestone 2, Sub-project A, increment 1: node.destination shape ──

function nodeWithDestination(destination) {
  return {
    id: nodeId('external', ['x']), kind: 'external', subtype: 'external-api', label: 'X',
    aliases: [], system: {}, externality: { value: 'external', evidenceRefs: [] },
    lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
    confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled', destination,
  };
}

test('a node with destination: null passes (the pre-M2 default, and every non-resolved node)', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithDestination(null));
  assert.deepEqual(validateGraph(graph).errors, []);
});

test('a node with a valid literal destination passes', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithDestination({ resolutionStatus: 'literal', raw: '"https://x"', literalValue: 'https://x', blockingExpression: null }));
  assert.deepEqual(validateGraph(graph).errors, []);
});

test('a node with a valid dynamic destination (literalValue null) passes', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithDestination({ resolutionStatus: 'dynamic', raw: 'url', literalValue: null, blockingExpression: 'url' }));
  assert.deepEqual(validateGraph(graph).errors, []);
});

test('a node with an unrecognized destination.resolutionStatus is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithDestination({ resolutionStatus: 'teleportation', raw: null, literalValue: null, blockingExpression: null }));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.nodes[0].destination.resolutionStatus' && e.message.includes('teleportation')));
});

test('a node with a non-null literalValue on a non-literal resolutionStatus is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithDestination({ resolutionStatus: 'dynamic', raw: 'url', literalValue: 'url', blockingExpression: 'url' }));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.nodes[0].destination.literalValue'));
});

test('a node with resolutionStatus: unknown and a non-null literalValue is rejected too', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithDestination({ resolutionStatus: 'unknown', raw: null, literalValue: 'oops', blockingExpression: null }));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.nodes[0].destination.literalValue'));
});

// ── Milestone 2, Sub-project E, increment 2: node.storeDetail shape ──

function nodeWithStoreDetail(storeDetail) {
  return {
    id: nodeId('store', ['x']), kind: 'store', subtype: 'database', label: 'X',
    aliases: [], system: {}, externality: { value: 'unknown', evidenceRefs: [] },
    lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
    confidence: { score: 0.6, tier: 'medium' }, coverageStatus: 'candidate', storeDetail,
  };
}

test('a node with storeDetail: null passes (the pre-E2 default, and every node this increment does not populate)', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithStoreDetail(null));
  assert.deepEqual(validateGraph(graph).errors, []);
});

test('a node with a valid, fully-populated storeDetail passes', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithStoreDetail({
    provider: null, host: null, database: null, schema: null,
    table: 'User', operation: 'create', columns: ['email', 'password'],
  }));
  assert.deepEqual(validateGraph(graph).errors, []);
});

test('every STORE_OPERATION_VALUES member is a valid storeDetail.operation', () => {
  for (const op of STORE_OPERATION_VALUES) {
    const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
    graph.nodes.push(nodeWithStoreDetail({
      provider: null, host: null, database: null, schema: null, table: 'X', operation: op, columns: [],
    }));
    assert.deepEqual(validateGraph(graph).errors, [], `operation "${op}" must validate`);
  }
});

test('a node with an unrecognized storeDetail.operation is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithStoreDetail({
    provider: null, host: null, database: null, schema: null, table: 'X', operation: 'teleport', columns: [],
  }));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.nodes[0].storeDetail.operation' && e.message.includes('teleport')));
});

test('a node with a null storeDetail.operation passes (unavailable, not unrecognized)', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithStoreDetail({
    provider: null, host: null, database: null, schema: null, table: null, operation: null, columns: [],
  }));
  assert.deepEqual(validateGraph(graph).errors, []);
});

test('a node whose storeDetail.columns is not an array is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithStoreDetail({
    provider: null, host: null, database: null, schema: null, table: 'X', operation: 'create', columns: 'email',
  }));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.nodes[0].storeDetail.columns'));
});

test('a node whose storeDetail.columns contains a non-string entry is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.nodes.push(nodeWithStoreDetail({
    provider: null, host: null, database: null, schema: null, table: 'X', operation: 'create', columns: ['email', 42],
  }));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.nodes[0].storeDetail.columns[1]'));
});

// ── Milestone 2, Sub-project D, increment 1: flow.handling taxonomy ──

function graphWithFlowHandling(handling) {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const src = nodeId('source', ['x']);
  const sink = nodeId('log', ['y']);
  const de = dataElementId('card_number', ['x']);
  graph.nodes.push(
    { id: src, kind: 'source', subtype: 'web-app', label: 'Web App', aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: ['collection'], governanceRefs: {}, dataElementIds: [de], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled' },
    { id: sink, kind: 'log', subtype: 'application-logs', label: 'Logs', aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: ['storage'], governanceRefs: {}, dataElementIds: [de], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled' },
  );
  graph.dataElements.push({ id: de, name: 'card_number', aliases: [], declaredType: null, dataClasses: ['PCI'], aiContexts: [], sourceLocations: [], dataSubjectCategory: null, classificationEvidence: [], manualOverride: false });
  const edge = { id: edgeId(src, sink, 'data_flow'), from: src, to: sink, relationship: 'data_flow', fieldMappings: [], protocol: { name: 'in-process', destinationResolution: 'unknown' }, boundaryCrossings: [], protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled' };
  graph.edges.push(edge);
  graph.flows.push({
    id: flowId(src, sink, [de]), dataElementIds: [de], source: src, sink: sink, edgeIds: [edge.id],
    transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed',
    evidenceRefs: [], coverageStatus: 'modeled', findingRefs: [], governanceRefs: {}, limitations: [], handling,
  });
  return graph;
}

test('a flow with handling: null passes (never populated by this graph, or a caller that skips this increment\'s wiring)', () => {
  const result = validateGraph(graphWithFlowHandling(null));
  assert.deepEqual(result.errors, []);
});

test('a flow with the handling field omitted entirely passes too (same as null)', () => {
  const graph = graphWithFlowHandling(undefined);
  delete graph.flows[0].handling;
  const result = validateGraph(graph);
  assert.deepEqual(result.errors, []);
});

test('a flow with a valid handling value passes, for every HANDLING_VALUES member', () => {
  for (const h of HANDLING_VALUES) {
    const result = validateGraph(graphWithFlowHandling(h));
    assert.deepEqual(result.errors, [], `handling "${h}" must validate cleanly`);
  }
});

test('a flow with an unrecognized handling value is rejected', () => {
  const result = validateGraph(graphWithFlowHandling('encrypted-with-a-typo'));
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.flows[0].handling' && e.message.includes('encrypted-with-a-typo')));
});

test('a transformation with a bogus kind or reversibility is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.transformations.push({ id: 'transform:abc', kind: 'BANANA', reversibility: 'sure-why-not' });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.transformations[0].kind' && e.message.includes('BANANA')));
  assert.ok(result.errors.some((e) => e.path === '$.transformations[0].reversibility' && e.message.includes('sure-why-not')));
});

test('a valid transformation entry passes (no regression)', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.transformations.push({ id: 'transform:abc', kind: 'mask', reversibility: 'irreversible' });
  const result = validateGraph(graph);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});

test('an evidence entry with a bogus evidenceType is rejected', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.evidence.push({ id: 'evidence:abc', claim: 'x', evidenceType: 'made-up' });
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.evidence[0].evidenceType' && e.message.includes('made-up')));
});

test('a valid evidence entry passes (no regression)', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  graph.evidence.push({ id: 'evidence:abc', claim: 'x', evidenceType: 'code' });
  const result = validateGraph(graph);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});

test('two nodes sharing an id are rejected as duplicates', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const dupId = nodeId('source', ['x']);
  const n = (id) => ({
    id, kind: 'source', subtype: 'x', label: 'X', aliases: [], system: {},
    externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: [], governanceRefs: {},
    dataElementIds: [], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled',
  });
  graph.nodes.push(n(dupId), n(dupId));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.nodes[1].id' && e.message.includes('duplicate id') && e.message.includes(dupId)));
});

test('two edges sharing an id are rejected as duplicates', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const dupId = edgeId('node:a', 'node:b', 'data_flow');
  const e = (id) => ({
    id, from: 'node:a', to: 'node:b', relationship: 'data_flow', fieldMappings: [],
    protocol: { name: 'in-process', destinationResolution: 'literal' }, boundaryCrossings: [],
    protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled',
  });
  graph.edges.push(e(dupId), e(dupId));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.edges[1].id' && e.message.includes('duplicate id') && e.message.includes(dupId)));
});

test('two dataElements sharing an id are rejected as duplicates', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const dupId = dataElementId('field', []);
  const d = (id) => ({
    id, name: 'field', aliases: [], dataClasses: [], aiContexts: [],
    sourceLocations: [], classificationEvidence: [], manualOverride: false,
  });
  graph.dataElements.push(d(dupId), d(dupId));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.dataElements[1].id' && e.message.includes('duplicate id') && e.message.includes(dupId)));
});

test('two flows sharing an id are rejected as duplicates', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const dupId = flowId('node:a', 'node:b', []);
  const f = (id) => ({
    id, dataElementIds: [], source: 'node:a', sink: 'node:b', edgeIds: [],
    policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], coverageStatus: 'modeled',
  });
  graph.flows.push(f(dupId), f(dupId));
  const result = validateGraph(graph);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.flows[1].id' && e.message.includes('duplicate id') && e.message.includes(dupId)));
});

test("reviewer's live reproduction: every stated bogus value now fails validation, never a thrown exception", () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg', scope: { source: 'banana' } });
  graph.transformations.push({ id: 'transform:abc', kind: 'BANANA', reversibility: 'sure-why-not' });
  graph.evidence.push({ id: 'evidence:abc', claim: 'x', evidenceType: 'made-up' });
  graph.flows.push({
    id: 'flow:abc', dataElementIds: [], source: 'node:a', sink: 'node:b', edgeIds: [],
    policyVerdict: 'TOTALLY_FINE', protectionSummary: 'super-protected', evidenceRefs: [], coverageStatus: 'modeled',
  });
  let result;
  assert.doesNotThrow(() => { result = validateGraph(graph); });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.scope.source'));
  assert.ok(result.errors.some((e) => e.path === '$.flows[0].policyVerdict'));
  assert.ok(result.errors.some((e) => e.path === '$.flows[0].protectionSummary'));
  assert.ok(result.errors.some((e) => e.path === '$.transformations[0].kind'));
  assert.ok(result.errors.some((e) => e.path === '$.transformations[0].reversibility'));
  assert.ok(result.errors.some((e) => e.path === '$.evidence[0].evidenceType'));
});

test('a valid two-node, one-edge, one-flow graph with valid dataClasses and aiContexts still passes (no regression)', () => {
  const graph = emptyGraphEnvelope({ graphId: 'dfg:repo:sha:cfg' });
  const src = nodeId('source', ['payments-platform', 'web']);
  const sink = nodeId('log', ['payments-platform', 'logs']);
  const de = dataElementId('card_number', ['payments-platform']);
  graph.nodes.push(
    { id: src, kind: 'source', subtype: 'web-app', label: 'Web App', aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: ['collection'], governanceRefs: {}, dataElementIds: [de], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled' },
    { id: sink, kind: 'log', subtype: 'application-logs', label: 'Application Logs', aliases: [], system: {}, externality: { value: 'internal', evidenceRefs: [] }, lifecycleStages: ['storage'], governanceRefs: {}, dataElementIds: [de], evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled' },
  );
  graph.dataElements.push({ id: de, name: 'card_number', aliases: [], declaredType: null, dataClasses: ['PCI'], aiContexts: ['ai.model_input'], sourceLocations: [], dataSubjectCategory: null, classificationEvidence: [], manualOverride: false });
  const edge = { id: edgeId(src, sink, 'data_flow'), from: src, to: sink, relationship: 'data_flow', fieldMappings: [{ fromPath: 'card_number', toPath: 'maskedPan', dataElementIds: [de], mappingType: 'transformation', transformationIds: [] }], protocol: { name: 'in-process', destinationResolution: 'literal' }, boundaryCrossings: [], protection: emptyProtection(), evidenceRefs: [], coverageStatus: 'modeled' };
  graph.edges.push(edge);
  graph.flows.push({ id: flowId(src, sink, [de]), dataElementIds: [de], source: src, sink: sink, edgeIds: [edge.id], transformationIds: [], alternatePathCount: 0, policyVerdict: 'not_evaluated', protectionSummary: 'not_assessed', evidenceRefs: [], confidence: { score: 1, tier: 'high' }, coverageStatus: 'modeled', findingRefs: [], governanceRefs: {}, limitations: [] });
  const result = validateGraph(graph);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});
