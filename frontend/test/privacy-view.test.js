import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { LIFECYCLE_STAGES, stageForNode, computePrivacyRow, computePrivacyViewModel } from '../src/views/privacy-view.js';
import { parseQuery, compileQuery } from '../src/lib/query-language.js';

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

// The 6 new per-row properties this task attaches (transitVerdict/
// atRestVerdict/handlingVerdict/sourceCategory/sinkCategory/
// destinationExternality), computed against the real fixture. Values below
// were computed by reading each flow's real source/sink node subtype and
// externality plus its own resolved edges' protection verdicts directly,
// not guessed.
test('computePrivacyRow attaches transitVerdict/atRestVerdict/handlingVerdict as the worst verdict across this flow\'s own resolved edges', () => {
  // flow.pci.raw_log's two edges: handling is ['not_assessed', 'unprotected'] -> worst 'unprotected'; transit/atRest are both all-not_assessed.
  const rawLogRow = computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pci.raw_log'));
  assert.equal(rawLogRow.transitVerdict, 'not_assessed');
  assert.equal(rawLogRow.atRestVerdict, 'not_assessed');
  assert.equal(rawLogRow.handlingVerdict, 'unprotected');

  // flow.pci.masked_log's handling is ['not_assessed', 'protected'] -> worst 'protected'.
  const maskedLogRow = computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pci.masked_log'));
  assert.equal(maskedLogRow.handlingVerdict, 'protected');

  // flow.pci.payment_api's transit is ['not_assessed', 'unprotected'] (the external HTTP hop) -> worst 'unprotected'.
  const paymentApiRow = computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pci.payment_api'));
  assert.equal(paymentApiRow.transitVerdict, 'unprotected');

  // flow.pci.database's atRest is ['not_assessed', 'unknown'] -> worst 'unknown'.
  const databaseRow = computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pci.database'));
  assert.equal(databaseRow.atRestVerdict, 'unknown');
});

test('computePrivacyRow attaches sourceCategory/sinkCategory/destinationExternality from the real source/sink node subtype and externality', () => {
  const row = computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pci.masked_log'));
  assert.equal(row.sourceCategory, 'web-app');
  assert.equal(row.sinkCategory, 'application-logs');
  assert.equal(row.destinationExternality, 'internal');

  const externalRow = computePrivacyRow(FLAGSHIP_GRAPH, flowByKey('flow.pci.payment_api'));
  assert.equal(externalRow.sinkCategory, 'payment-api');
  assert.equal(externalRow.destinationExternality, 'external');
});

// The real, deliberate design property: a genuinely-absent value must leave
// the property OFF the row entirely (matchesFilters's own "absent =
// unaffected, never a hide" semantics), never present-but-null. The three
// verdict properties, by contrast, are always set — worstVerdict() always
// returns a real string, even 'not_assessed' for a flow with zero edges.
test('computePrivacyRow only sets sourceCategory/sinkCategory/destinationExternality when a real, non-null value exists — never a null placeholder', () => {
  const graph = {
    nodes: [
      { id: 'n:src', kind: 'source', subtype: null, label: 'Source', lifecycleStages: ['collection'], externality: { value: null } },
      { id: 'n:sink', kind: 'sink', subtype: null, label: 'Sink', lifecycleStages: ['storage'], externality: {} },
    ],
    edges: [],
    dataElements: [],
    flows: [{ id: 'f:1', source: 'n:src', sink: 'n:sink', dataElementIds: [], edgeIds: [], governanceRefs: {}, protectionSummary: 'not_assessed', policyVerdict: 'not_evaluated' }],
  };
  const row = computePrivacyRow(graph, graph.flows[0]);
  assert.ok(!('sourceCategory' in row), 'sourceCategory must be entirely absent, not null');
  assert.ok(!('sinkCategory' in row), 'sinkCategory must be entirely absent, not null');
  assert.ok(!('destinationExternality' in row), 'destinationExternality must be entirely absent, not null');
  // Verdict properties are always set, even for a flow with zero edges.
  assert.equal(row.transitVerdict, 'not_assessed');
  assert.equal(row.atRestVerdict, 'not_assessed');
  assert.equal(row.handlingVerdict, 'not_assessed');
});

// Integration-level proof (via the real, shared matchesFilters — Step 4)
// that the new facets genuinely narrow the visible row set, each in
// isolation.
test('computePrivacyViewModel applies the new transitVerdict/policyVerdict/destinationExternality filters via the shared matchesFilters', () => {
  const transitVm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: { transitVerdict: ['unprotected'] } });
  const transitVisible = transitVm.rows.filter((r) => r.visible);
  assert.ok(transitVisible.length > 0);
  assert.ok(transitVisible.every((r) => r.transitVerdict === 'unprotected'));

  const policyVm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: { policyVerdict: ['manual_review_required'] } });
  const policyVisible = policyVm.rows.filter((r) => r.visible);
  assert.ok(policyVisible.length > 0);
  assert.ok(policyVisible.every((r) => r.policyVerdict === 'manual_review_required'));

  const externalVm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: { destinationExternality: ['internal'] } });
  const externalVisible = externalVm.rows.filter((r) => r.visible);
  assert.ok(externalVisible.length > 0);
  assert.ok(externalVisible.every((r) => r.destinationExternality === 'internal'));
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

// Milestone 3, sub-project M3-UX-Query, Task 4: computePrivacyViewModel's
// optional 3rd parameter, a compiled query-language predicate — a REAL
// integration-level proof (against the real flagship fixture, via the real
// query-language.js parser/compiler, not a hand-built stub predicate) that
// applying a query genuinely narrows the rendered rows, and does so as an
// ADDITIONAL condition alongside the existing dataClass/protection/ai
// filters rather than replacing them.
test('computePrivacyViewModel: a real compiled query predicate narrows visible rows below the no-query count', () => {
  const { ast } = parseQuery('class:PCI');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);

  const withoutQuery = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  const withQuery = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} }, predicate);

  const visibleWithout = withoutQuery.rows.filter((r) => r.visible).length;
  const visibleWith = withQuery.rows.filter((r) => r.visible).length;
  assert.equal(visibleWithout, FLAGSHIP_GRAPH.flows.length, 'sanity: with no query active every row is visible');
  assert.ok(visibleWith > 0 && visibleWith < visibleWithout, 'a real class:PCI query should narrow, not empty out or leave unchanged, the visible row count');
  assert.ok(withQuery.rows.filter((r) => r.visible).every((r) => r.dataClasses.includes('PCI')));
});

test('computePrivacyViewModel: the query predicate is an ADDITIONAL condition, combined with an existing dataClass filter, not a replacement for it', () => {
  const { ast } = parseQuery('ai:true');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);

  const dataClassOnly = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: { dataClass: ['PCI'] } });
  const dataClassAndQuery = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: { dataClass: ['PCI'] } }, predicate);

  const visibleDataClassOnly = dataClassOnly.rows.filter((r) => r.visible).length;
  const visibleBoth = dataClassAndQuery.rows.filter((r) => r.visible).length;
  assert.ok(visibleBoth <= visibleDataClassOnly, 'adding a query on top of an existing filter must never show MORE rows than the filter alone');
});

test('computePrivacyViewModel: omitting the query predicate (2-arg call) matches every row, same as before this task', () => {
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  assert.ok(vm.rows.every((r) => r.visible));
});
