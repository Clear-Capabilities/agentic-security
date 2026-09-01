import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeInventoryViewModel } from '../src/views/inventory-view.js';
import { INVENTORY_TABLES } from '../src/lib/state.js';
import { parseQuery, compileQuery } from '../src/lib/query-language.js';

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

// The 7 new per-row properties this task attaches (transitVerdict/
// atRestVerdict/handlingVerdict/sourceCategory/sinkCategory/
// destinationExternality/policyVerdict), computed the SAME way
// computePrivacyRow() does (this flow's own resolved edges, aggregated via
// worstVerdict()), for policyPermittedFlows' and manualGovernanceGaps'
// flow-shaped rows only. Values below were computed by hand from the real
// synthetic GRAPH fixture above, not guessed.
test('policyPermittedFlows rows carry the new filter-facet properties, computed from this flow\'s own real edges/nodes', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'policyPermittedFlows' });
  const row = vm.rows.find((r) => r.id === 'flow:permitted1');
  assert.ok(row, 'expected flow:permitted1\'s row to exist');
  // edge:1: transit protected, atRest unprotected, handling not_applicable -- worst of each single-element list is that element itself.
  assert.equal(row.transitVerdict, 'protected');
  assert.equal(row.atRestVerdict, 'unprotected');
  assert.equal(row.handlingVerdict, 'not_applicable');
  assert.equal(row.sourceCategory, 'http-body'); // node:src1.subtype
  assert.equal(row.sinkCategory, 'database'); // node:sink1.subtype
  assert.equal(row.destinationExternality, 'internal'); // node:sink1.externality.value
  assert.equal(row.policyVerdict, 'permitted');
});

test('manualGovernanceGaps\' "Flow"-subject rows carry the same new properties; its node/edge-subject rows carry none of them', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'manualGovernanceGaps' });
  const flowRow = vm.rows.find((r) => r.id === 'flow:manualReview1');
  assert.ok(flowRow, 'expected flow:manualReview1\'s row to exist');
  // edge:2 is all-protected.
  assert.equal(flowRow.transitVerdict, 'protected');
  assert.equal(flowRow.atRestVerdict, 'protected');
  assert.equal(flowRow.handlingVerdict, 'protected');
  assert.equal(flowRow.sourceCategory, 'database'); // node:sink1.subtype (flow.source here is node:sink1)
  assert.equal(flowRow.sinkCategory, 'ai-model-provider'); // node:ai1.subtype
  assert.equal(flowRow.destinationExternality, 'external'); // node:ai1.externality.value
  assert.equal(flowRow.policyVerdict, 'manual_review_required');

  const nonFlowRows = vm.rows.filter((r) => r.id !== 'flow:manualReview1');
  assert.ok(nonFlowRows.length > 0, 'expected at least one node/edge-subject manualGovernanceGaps row');
  for (const row of nonFlowRows) {
    for (const key of ['transitVerdict', 'atRestVerdict', 'handlingVerdict', 'sourceCategory', 'sinkCategory', 'destinationExternality', 'policyVerdict']) {
      assert.ok(!(key in row), `expected node/edge-subject row ${row.id} to carry no ${key}`);
    }
  }
});

test('a non-flow-shaped category (sources) carries none of the 7 new properties', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  assert.ok(vm.rows.length > 0);
  for (const row of vm.rows) {
    for (const key of ['transitVerdict', 'atRestVerdict', 'handlingVerdict', 'sourceCategory', 'sinkCategory', 'destinationExternality', 'policyVerdict']) {
      assert.ok(!(key in row), `expected sources row ${row.id} to carry no ${key}`);
    }
  }
});

// Integration-level proof (via the real, shared matchesFilters — Step 4)
// that the new facets genuinely narrow policyPermittedFlows' visible rows.
test('computeInventoryViewModel applies the new transitVerdict filter to policyPermittedFlows via the shared matchesFilters', () => {
  const matchVm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: { transitVerdict: ['protected'] }, table: 'policyPermittedFlows' });
  assert.equal(matchVm.rows.filter((r) => r.visible).length, 1, 'flow:permitted1 has transitVerdict "protected"');

  const noMatchVm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: { transitVerdict: ['unprotected'] }, table: 'policyPermittedFlows' });
  assert.equal(noMatchVm.rows.filter((r) => r.visible).length, 0, 'flow:permitted1\'s transitVerdict is "protected", not "unprotected"');
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

// Milestone 3, sub-project M3-UX-Query, Task 4: computeInventoryViewModel's
// optional 3rd parameter, a compiled query-language predicate, applied to
// FLOW-shaped rows only (policyPermittedFlows' rows use the real flow id as
// their own row id) — a real, compiled query genuinely narrows the visible
// row set, as an ADDITIONAL condition on top of any existing dataClass
// filter.
test('computeInventoryViewModel: a real compiled query predicate narrows a flow-shaped table (policyPermittedFlows)', () => {
  const { ast: piiAst } = parseQuery('class:PII');
  const piiPredicate = compileQuery(piiAst, GRAPH);
  const { ast: phiAst } = parseQuery('class:PHI');
  const phiPredicate = compileQuery(phiAst, GRAPH);

  const withPii = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'policyPermittedFlows' }, piiPredicate);
  const withPhi = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'policyPermittedFlows' }, phiPredicate);

  assert.equal(withPii.rows.filter((r) => r.visible).length, 1, 'flow:permitted1\'s own data element (email) is real PII, so class:PII must keep it visible');
  assert.equal(withPhi.rows.filter((r) => r.visible).length, 0, 'flow:permitted1\'s data element carries no PHI, so class:PHI must narrow it away entirely');
});

test('computeInventoryViewModel: the query predicate has no effect on a non-flow-shaped table (sources) — an honest, disclosed scope limit', () => {
  const { ast } = parseQuery('class:PHI'); // matches nothing in this fixture
  const predicate = compileQuery(ast, GRAPH);
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' }, predicate);
  assert.ok(vm.rows.every((r) => r.visible), 'source rows have no corresponding flow id, so the flow-scoped query predicate must not hide them');
});

test('computeInventoryViewModel: omitting the query predicate (2-arg call) behaves exactly as before this task', () => {
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'policyPermittedFlows' });
  assert.ok(vm.rows.every((r) => r.visible));
});
