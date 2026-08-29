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
