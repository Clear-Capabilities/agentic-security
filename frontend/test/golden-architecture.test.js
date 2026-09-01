// Golden-DOM regression tests for AC-17 (Architecture View reference
// composition). These prove the ALREADY-SHIPPED Architecture View still
// renders the PRD §7.8-named reference composition — the 9 named nodes, the
// 5 named trust zones, flow-selection dimming (present-but-dimmed, never
// removed), and distinct verdicts for the masked vs raw logging branches —
// against the REAL flagship fixture. Not new feature work; see
// docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md
// for why this is a regression-proving task.
//
// Follows the same dom-shim + real-fixture pattern as
// test/architecture-view-render.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computeArchitectureViewModel, renderArchitectureView } = await import('../src/views/architecture-view.js');

const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;
const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

// Confirmed against the real fixture this session (node -e import of
// flagship-graph.js): each of these is a real node.label in
// FLAGSHIP_GRAPH.nodes, and NODE_KEYS is referenced below only to keep this
// list honest against drift (a missing key throws instead of silently
// testing nothing).
const REFERENCE_NODE_LABELS = [
  'Web App', 'API Gateway', 'Payments Service', 'AI Assistant', 'PostgreSQL',
  'Application Logs', 'Payment API', 'Analytics API', 'Unresolved Destination',
];
for (const key of ['node.web', 'node.gateway', 'node.payments', 'node.ai', 'node.postgres', 'node.logs', 'node.payment_api', 'node.analytics', 'node.unresolved']) {
  if (!NODE_KEYS[key]) throw new Error(`fixtureNodeKeys missing expected key "${key}" — fixture may have drifted`);
}

const REFERENCE_ZONES = ['Public Internet', 'Application Layer', 'Service Layer', 'Data Layer', 'External Zone'];

function allElements(root) {
  const out = [];
  const walk = (node) => { for (const c of node.childNodes) { if (c.nodeType === 'element') { out.push(c); walk(c); } } };
  walk(root);
  return out;
}
function allText(root) {
  return allElements(root).flatMap((el) => el.childNodes.filter((c) => c.nodeType === 'text').map((c) => c.data)).join(' ');
}

test('AC-17: Architecture View renders all 9 named reference nodes from the flagship fixture', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  for (const label of REFERENCE_NODE_LABELS) {
    assert.ok(text.includes(label), `expected reference node "${label}" to render`);
  }
});

test('AC-17: Architecture View renders all 5 named trust zones', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  for (const zone of REFERENCE_ZONES) {
    assert.ok(text.includes(zone), `expected trust zone "${zone}" to render`);
  }
});

test('AC-17: selecting the cleartext payment flow dims unrelated content without removing it from the DOM', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: FLOW_KEYS['flow.pci.payment_api'], filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  const nodeElements = allElements(canvasEl).filter((el) => el.attrs.has('data-dimmed'));
  assert.ok(nodeElements.length > 0, 'sanity: expected at least one dimmable element');
  assert.ok(nodeElements.some((el) => el.attrs.get('data-dimmed') === 'true'), 'expected at least one unrelated node dimmed, not removed');
  assert.ok(nodeElements.some((el) => el.attrs.get('data-dimmed') === 'false'), 'expected the selected flow\'s own nodes to stay un-dimmed');
  // Still present in the DOM — dimming, never deletion:
  const text = allText(canvasEl);
  for (const label of REFERENCE_NODE_LABELS) assert.ok(text.includes(label), `"${label}" must still be in the DOM while dimmed`);
});

// Investigation (this session): architecture-view.js's renderEdge() exposes
// an edge's aggregate protection verdict (worstVerdict of transit/atRest/
// handling, via edgeVerdict()) two ways in the DOM — the .arch-edge <g>'s
// `aria-label` attribute (`Edge, protection ${visual.label}...`, e.g.
// "Edge, protection Protected") and a <text class="arch-edge-glyph"> child
// whose textContent is `visual.glyph` (e.g. "✓"/"✗"). There is no
// `data-verdict` attribute — the brief's guess was wrong; the real
// mechanism is aria-label + glyph text, both driven by protectionVisual().
//
// Confirmed directly against the real fixture data this session
// (flow.pci.masked_log / flow.pci.raw_log share their first hop
// edge:54d5b1db3415, whose own protection is entirely not_assessed, but
// diverge on their second, log-write hop: masked_log's edge:d613505336aa
// has protection.handling.verdict === 'protected' (edgeVerdict ==
// 'protected'), while raw_log's edge:a6fb8d3fdecc has
// protection.handling.verdict === 'unprotected' (edgeVerdict ==
// 'unprotected') — the exact "masked vs raw PCI in logs" distinction
// AC-17 names. Selecting each flow in turn and reading the aria-labels of
// its own selected (data-selected="true") edges is what proves this,
// rather than guessing DOM order for an unfiltered render.
test('AC-17: the raw and masked logging branches both render with distinct verdicts', () => {
  function selectedEdgeAriaLabels(flowKey) {
    const canvasEl = document.createElement('div');
    const vm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: FLOW_KEYS[flowKey], filters: {} });
    renderArchitectureView(vm, canvasEl, () => {});
    const edgeGroups = canvasEl.querySelectorAll('[class="arch-edge"]');
    return edgeGroups
      .filter((g) => g.attrs.get('data-selected') === 'true')
      .map((g) => g.getAttribute('aria-label'));
  }

  const maskedLabels = selectedEdgeAriaLabels('flow.pci.masked_log');
  const rawLabels = selectedEdgeAriaLabels('flow.pci.raw_log');

  assert.ok(maskedLabels.length > 0, 'sanity: masked_log flow should select at least one edge');
  assert.ok(rawLabels.length > 0, 'sanity: raw_log flow should select at least one edge');

  assert.ok(
    maskedLabels.some((l) => l.includes('protection Protected')),
    `expected the masked-log branch's log-write edge to render a Protected verdict; got: ${JSON.stringify(maskedLabels)}`,
  );
  assert.ok(
    rawLabels.some((l) => l.includes('protection Unprotected')),
    `expected the raw-log branch's log-write edge to render an Unprotected verdict; got: ${JSON.stringify(rawLabels)}`,
  );
  // The two branches must not present the same verdict set — this is what
  // makes the assertion non-trivial rather than merely "each renders A
  // verdict":
  assert.ok(!maskedLabels.some((l) => l.includes('protection Unprotected')), 'masked-log branch must not also show an Unprotected verdict');
  assert.ok(!rawLabels.some((l) => l.includes('protection Protected')), 'raw-log branch must not also show a Protected verdict');
});
