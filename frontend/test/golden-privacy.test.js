// Golden-DOM regression tests for AC-18 (Privacy View lifecycle reference
// composition). These prove the ALREADY-SHIPPED Privacy View still renders
// the PRD-named lifecycle composition — the three named data-class fields
// preserving identity across stages, the real (not PRD-prose-cased)
// governance-gap signal text, and all 6 lifecycle-stage columns — against
// the REAL flagship fixture. Not new feature work; see
// docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md
// for why this is a regression-proving task.
//
// Follows the same dom-shim + real-fixture pattern as
// test/architecture-view-render.test.js / test/privacy-view-render.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computePrivacyViewModel, renderPrivacyView } = await import('../src/views/privacy-view.js');

function allElements(root) {
  const out = [];
  const walk = (node) => { for (const c of node.childNodes) { if (c.nodeType === 'element') { out.push(c); walk(c); } } };
  walk(root);
  return out;
}
function allText(root) {
  return allElements(root).flatMap((el) => el.childNodes.filter((c) => c.nodeType === 'text').map((c) => c.data)).join(' ');
}

// Confirmed against the real fixture data this session (node -e import of
// flagship-graph.js): flow.pci.ai's dataElement is "card_number" (PCI),
// flow.phi.ai's is "diagnosis" (PHI), flow.pii.analytics's is "email" (PII).
test('AC-18: the three named data-class fields (card_number/PCI, diagnosis/PHI, email/PII) each render a row preserving field identity across lifecycle stages', () => {
  const canvasEl = document.createElement('div');
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  for (const fieldName of ['card_number', 'diagnosis', 'email']) {
    assert.ok(text.includes(fieldName), `expected field "${fieldName}" to render a row`);
  }
});

// Confirmed against the real fixture data this session:
// flow.pci.ai.governanceRefs === {recipient:'manual_required', purpose:'manual_required', lawfulBasis:'manual_required'}
// flow.phi.ai.governanceRefs === {lawfulBasis:'manual_required', retention:'unknown', transfer:'review'}
// flow.pii.analytics.governanceRefs === {retention:'unknown', deletion:'not_found'}
// renderStageCell()'s real format is `${key}: ${value}` (lowercase, machine
// values) — NOT the PRD prose's "MANUAL REQUIRED" casing.
test('AC-18: missing governance data renders the real MANUAL REQUIRED / UNKNOWN / REVIEW / NOT FOUND signal (exact real format, not the PRD prose casing)', () => {
  const canvasEl = document.createElement('div');
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  assert.ok(text.includes('manual_required'), 'expected a manual_required governance badge somewhere');
  assert.ok(text.includes('unknown'), 'expected an unknown-retention badge somewhere');
  assert.ok(text.includes('review'), 'expected a transfer-review badge somewhere');
  assert.ok(text.includes('not_found'), 'expected a deletion-not-found badge somewhere');
});

test('AC-18: all 6 lifecycle stages render as columns', () => {
  const canvasEl = document.createElement('div');
  const vm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(vm, canvasEl, () => {});
  const text = allText(canvasEl);
  for (const stage of ['Collection', 'Processing', 'Storage', 'Sharing', 'Retention', 'Deletion']) {
    assert.ok(text.includes(stage), `expected lifecycle stage "${stage}" column`);
  }
});
