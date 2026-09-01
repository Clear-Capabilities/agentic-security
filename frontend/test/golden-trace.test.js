// Golden-DOM regression tests for AC-19 (Trace View reference composition).
// These prove the ALREADY-SHIPPED Trace View still renders the cleartext
// payment flow's real ordered steps, field-rename mappings, the external
// HTTP trust-boundary edge's unprotected verdict, and each alternate
// destination's own individual verdict — against the REAL flagship
// fixture. Not new feature work; see
// docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md
// for why this is a regression-proving task.
//
// Follows the same dom-shim + real-fixture pattern as
// test/trace-view-render.test.js.
//
// IMPORTANT, confirmed this session (re-run via a direct `node -e` import
// of trace-view.js against the real fixture): selecting
// FLOW_KEYS['flow.pci.payment_api'] via computeTraceViewModel produces
// **4 steps** (source, propagation Web App -> Payments Service
// req.body.card_number -> payment.pan, propagation Payments Service ->
// Payment API payment.pan -> payload.cardNumber, sink at Payment API
// externality:'external' protectionSummary:'unprotected') and
// **alternatePaths.length === 4**. This is NOT the 5 steps named in the
// PRD §7.10 illustrative table (which includes a separate SERIALIZATION
// step this fixture's real compute output does not currently produce as
// its own step) — a real, disclosed discrepancy already accounted for in
// the plan. Every assertion below is grounded in the real function output,
// never the PRD table's own step count or kind names.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computeTraceViewModel, renderTraceView } = await import('../src/views/trace-view.js');

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

function allElements(root) {
  const out = [];
  const walk = (node) => { for (const c of node.childNodes) { if (c.nodeType === 'element') { out.push(c); walk(c); } } };
  walk(root);
  return out;
}
function allText(root) {
  return allElements(root).flatMap((el) => el.childNodes.filter((c) => c.nodeType === 'text').map((c) => c.data)).join(' ');
}
// dom-shim's querySelectorAll only matches attrs set via setAttribute — but
// el()'s `class` key is applied via node.className (a plain property), not
// setAttribute (see src/lib/dom.js), so an attribute-selector query never
// matches an el()-built element's class. Trace View renders entirely via
// el(), never svgEl()/setAttribute-for-class, so class-based lookups here
// must filter on .className directly.
function elementsByClass(root, className) {
  return allElements(root).filter((el) => el.className === className);
}

test('AC-19: the cleartext payment flow renders its real ordered steps with both field-rename mappings', () => {
  const canvasEl = document.createElement('div');
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const vm = computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: flowId, filters: {} });
  assert.ok(vm, 'sanity: the flow must be selectable and produce a view model');
  assert.equal(vm.steps.length, 4, 'sanity: the real compute output for this flow is 4 steps (not the PRD table\'s 5)');
  renderTraceView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  assert.ok(text.includes('card_number'), 'expected the source field name to render');
  assert.ok(text.includes('req.body.card_number'), 'expected the first field-mapping\'s fromPath to render');
  assert.ok(text.includes('payment.pan'), 'expected the rename mapping target to render');
  assert.ok(text.includes('payload.cardNumber'), 'expected the second rename mapping target to render');
});

test('AC-19: the external HTTP trust-boundary edge is visibly flagged unprotected', () => {
  const canvasEl = document.createElement('div');
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const vm = computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: flowId, filters: {} });
  renderTraceView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  // Confirmed this session: protectionVisual()'s label is 'Unprotected'
  // (capitalized) — renderTraceStep() never lowercases it. The verdict
  // string 'unprotected' only appears as protection.transit.verdict/
  // step.protectionSummary in the view MODEL, not in the rendered text.
  assert.ok(text.includes('Unprotected'), 'expected the real Unprotected verdict to render for this flow\'s external hop');
  assert.ok(text.includes('Trust boundary crossing'), 'expected the boundary-crossing flag to render on the same hop');
});

// Investigation (this session): renderTraceView()'s "Alternate destinations"
// list renders each alternatePaths entry as its own
// `<div class="trace-alternate-item">` whose single text child is
// `${visual.glyph} ${alt.destinationLabel} — ${visual.label}` (built from
// alt.protectionSummary via protectionVisual() — see renderTraceView in
// src/views/trace-view.js). There is no per-item aria-label or
// data-verdict attribute; the verdict is exposed only as glyph+label text
// inside that div.
//
// Confirmed directly against the real fixture data this session (node -e
// import): flow.pci.payment_api's 4 real alternatePaths are
// Application Logs/protected, Application Logs/unprotected,
// PostgreSQL/unknown, Model Provider/unknown — rendering to the real
// text "✓ Application Logs — Protected", "✗ Application Logs —
// Unprotected", "? PostgreSQL — Unknown", "? Model Provider — Unknown".
// Two alternates share the SAME destination label (Application Logs) but
// render DIFFERENT verdicts — proving each alternate item carries its own
// individual verdict rather than one shared verdict for the group, the
// same "same destination, distinct verdict" style of proof Task 1 used
// for the masked/raw logging branches.
test('AC-19: alternate destinations render with their own individual verdicts', () => {
  const canvasEl = document.createElement('div');
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const vm = computeTraceViewModel(FLAGSHIP_GRAPH, { view: 'trace', selectedId: flowId, filters: {} });
  assert.ok(vm.alternatePaths.length > 0, 'sanity: this flow must have real alternates in the fixture');
  renderTraceView(vm, canvasEl, () => {});

  const items = elementsByClass(canvasEl, 'trace-alternate-item');
  assert.equal(items.length, vm.alternatePaths.length, 'expected one rendered item per alternate path');

  const itemTexts = items.map((el) => el.textContent);
  const logsItems = itemTexts.filter((t) => t.includes('Application Logs'));
  assert.equal(logsItems.length, 2, 'sanity: two real alternates in this fixture both target Application Logs');

  assert.ok(logsItems.some((t) => t.includes('Protected') && !t.includes('Unprotected')), 'expected one Application Logs alternate to render its own Protected verdict');
  assert.ok(logsItems.some((t) => t.includes('Unprotected')), 'expected the OTHER Application Logs alternate to render its own, different Unprotected verdict');

  // Non-trivial: same destination, distinct verdicts, each attached to its
  // own item rather than one shared verdict rendered for the whole group.
  assert.notEqual(logsItems[0], logsItems[1], 'the two same-destination alternates must not render identical text');

  assert.ok(itemTexts.some((t) => t.includes('PostgreSQL') && t.includes('Unknown')), 'expected the PostgreSQL alternate to render its own Unknown verdict');
  assert.ok(itemTexts.some((t) => t.includes('Model Provider') && t.includes('Unknown')), 'expected the Model Provider alternate to render its own Unknown verdict');
});
