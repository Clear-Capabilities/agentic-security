import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeInventoryViewModel } from '../src/views/inventory-view.js';
import { INVENTORY_TABLES } from '../src/lib/state.js';

function protectedDim(verdict) {
  return { verdict, evidenceGrade: 'direct' };
}

const GRAPH = {
  nodes: [
    { id: 'node:src1', kind: 'source', subtype: 'http-body', label: 'Signup body', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
    { id: 'node:sink1', kind: 'sink', subtype: 'database', label: 'Users table', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
    { id: 'node:store1', kind: 'store', subtype: 'database', label: 'Postgres', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] }, storeDetail: { operation: 'upsert', columns: ['email'] } },
    { id: 'node:ext1', kind: 'external', subtype: 'external-api', label: 'Stripe', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'external', evidenceRefs: [] }, destination: { resolutionStatus: 'literal', literalValue: 'api.stripe.com' } },
    { id: 'node:ai1', kind: 'sink', subtype: 'ai-model-provider', label: 'OpenAI', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'external', evidenceRefs: [] } },
    { id: 'node:manual1', kind: 'process', subtype: null, label: 'Manually declared batch job', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'manual', externality: { value: 'unknown', evidenceRefs: [] } },
    { id: 'node:unresolved1', kind: 'unresolved', subtype: null, label: 'Unresolved call site', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'partial', externality: { value: 'unknown', evidenceRefs: [] } },
    { id: 'node:candidate1', kind: 'process', subtype: null, label: 'Candidate framework call', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'candidate', externality: { value: 'unknown', evidenceRefs: [] } },
  ],
  edges: [
    { id: 'edge:1', from: 'node:src1', to: 'node:sink1', relationship: 'data_flow', fieldMappings: [], protection: { transit: protectedDim('protected'), atRest: protectedDim('unprotected'), handling: protectedDim('not_applicable') }, provenance: 'code' },
    { id: 'edge:2', from: 'node:sink1', to: 'node:ai1', relationship: 'data_flow', fieldMappings: [], protection: { transit: protectedDim('protected'), atRest: protectedDim('protected'), handling: protectedDim('protected') }, provenance: 'code' },
  ],
  dataElements: [
    { id: 'data:email', name: 'email', dataClasses: ['PII'], aiContexts: [] },
    { id: 'data:promptContext', name: 'prompt context', dataClasses: ['PII'], aiContexts: ['model-input'] },
  ],
  transformations: [
    { id: 'transform:mask1', kind: 'mask', reversibility: 'irreversible' },
  ],
  flows: [
    { id: 'flow:permitted1', source: 'node:src1', sink: 'node:sink1', dataElementIds: ['data:email'], edgeIds: ['edge:1'], policyVerdict: 'permitted', protectionSummary: 'unprotected', governanceRefs: {} },
    { id: 'flow:manualReview1', source: 'node:sink1', sink: 'node:ai1', dataElementIds: ['data:promptContext'], edgeIds: ['edge:2'], policyVerdict: 'manual_review_required', protectionSummary: 'protected', governanceRefs: {} },
  ],
};

test('computeInventoryViewModel exposes all 11 tables with correct counts', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: INVENTORY_TABLES[0] });
  const countFor = (id) => vm.tables.find((t) => t.id === id).count;
  assert.equal(countFor('sources'), 1);
  assert.equal(countFor('sinks'), 2); // node:sink1 + node:ai1 (kind:'sink', subtype:'ai-model-provider' -- AI systems and sinks overlap, matching the aiSystems=2 comment below)
  assert.equal(countFor('fields'), 2);
  assert.equal(countFor('externalDestinations'), 2); // node:ext1, node:ai1 -- node:manual1's externality is 'unknown', not 'external'
  assert.equal(countFor('stores'), 1);
  assert.equal(countFor('aiSystems'), 2); // node:ai1 + data:promptContext
  assert.equal(countFor('transformations'), 1);
  assert.equal(countFor('unprotectedEdges'), 1); // edge:1 (mixed: protected+unprotected -> worst 'unprotected')
  assert.equal(countFor('policyPermittedFlows'), 1); // flow:permitted1 only, strictly 'permitted'
  assert.equal(countFor('manualGovernanceGaps'), 2); // flow:manualReview1 + node:manual1
  assert.equal(countFor('unsupportedCandidates'), 2); // node:unresolved1 + node:candidate1
});

test('fields table rows carry dataClasses and respond to the dataClass filter', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: { dataClass: ['PII'] }, table: 'fields' });
  assert.ok(vm.rows.every((r) => r.visible), 'both fixture fields are PII, both should stay visible');
  const vmExcluded = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: { dataClass: ['PHI'] }, table: 'fields' });
  assert.ok(vmExcluded.rows.every((r) => !r.visible), 'neither fixture field is PHI');
});

test('a non-filterable table (sources) ignores filters entirely', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: { dataClass: ['PHI'] }, table: 'sources' });
  assert.equal(vm.filterable, false);
  assert.ok(vm.rows.every((r) => r.visible));
});

test('an empty graph produces zero-count tables without throwing', () => {
  const empty = { nodes: [], edges: [], dataElements: [], transformations: [], flows: [] };
  const vm = computeInventoryViewModel(empty, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  assert.ok(vm.tables.every((t) => t.count === 0));
  assert.deepEqual(vm.rows, []);
});

test('an invalid state.table falls back to the first category', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'not-a-real-table' });
  assert.equal(vm.activeTable, INVENTORY_TABLES[0]);
});
