// Golden-DOM regression tests for AC-22 (PRD §8.4's 11-state visual matrix)
// — the 3 states that have real, already-shipped UI: Error, Selected,
// Hovered. The other 8 states have NO dedicated UI anywhere in src/ or
// styles/ today (confirmed by direct grep this sub-project's own scoping
// pass) and are NOT silently claimed here — see the disclosed
// `test.todo(...)` entries in test/golden-state-matrix-gaps.test.js instead.
// See docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md
// for the full reasoning behind this split.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { showError } = await import('../src/main.js');
const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computeArchitectureViewModel, renderArchitectureView } = await import('../src/views/architecture-view.js');
const { computePrivacyViewModel, renderPrivacyView } = await import('../src/views/privacy-view.js');

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

// AC-22 "Error" row. Exercises the REAL `showError` render function
// main.js's own init()/fetch-catch path calls on a failed graph fetch —
// see main.js's own comment on the export for why this is a direct call
// rather than a mocked-fetch integration test (no ESM module-mocking
// primitive is available in this repo's Node version, confirmed this
// session).
test('AC-22 Error state: a failed graph fetch shows the real error UI and never a clean/protected summary', () => {
  const rootEl = document.createElement('div');
  // Same message shape init()'s own catch block builds:
  // `Failed to load the data flow graph: ${err.message}`.
  showError(rootEl, 'Failed to load the data flow graph: fetch failed');

  const text = allText(rootEl);
  assert.ok(text.includes('Data Flow Explorer could not load'), 'expected the real error title');
  assert.ok(text.includes('Failed to load the data flow graph: fetch failed'), 'expected the real error message');

  // el() (lib/dom.js) sets `class` via the `.className` property, not
  // setAttribute — attrs.get('class')/getAttribute('class') would never see
  // it (the same gotcha test/privacy-view-render.test.js and
  // test/golden-trace.test.js already document). Filter on .className
  // directly instead.
  const errorEls = allElements(rootEl).filter((el) => (el.className || '').includes('app-error'));
  assert.ok(errorEls.length > 0, 'sanity: expected at least one .app-error-classed element');

  // The error state must never ALSO render a clean/protected summary
  // alongside it (AC-22's own cross-cutting requirement: "no non-clean
  // state may ever resemble a clean scan").
  for (const forbidden of ['Scan complete', 'Protected', 'Clean']) {
    assert.ok(!text.includes(forbidden), `error state must not also show "${forbidden}"`);
  }
});

// AC-22 "Selected" row. Reuses the SAME real data-selected mechanism
// golden-architecture.test.js's own dimming test and privacy-view.js's row
// rendering already exercise — this test asserts the same mechanism is
// present on at least two different views' own selected elements, not a
// new one invented for this file.
test('AC-22 Selected state: a selected element carries a real, visible selection marker across two different views', () => {
  const selectedFlowId = FLOW_KEYS['flow.pci.payment_api'];

  const archCanvas = document.createElement('div');
  const archVm = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: selectedFlowId, filters: {} });
  renderArchitectureView(archVm, archCanvas, () => {});
  const archSelected = allElements(archCanvas).filter((el) => el.attrs.get('data-selected') === 'true');
  assert.ok(archSelected.length > 0, 'expected at least one data-selected="true" element in Architecture View');

  const privacyCanvas = document.createElement('div');
  const privacyVm = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: selectedFlowId, filters: {} });
  renderPrivacyView(privacyVm, privacyCanvas, () => {});
  const privacySelected = allElements(privacyCanvas).filter((el) => el.attrs.get('data-selected') === 'true');
  assert.ok(privacySelected.length > 0, 'expected at least one data-selected="true" element in Privacy View');
});

// AC-22 "Hovered" row. `:hover` cannot be triggered or observed via
// dom-shim (no layout/pseudo-class engine), so this reads the real
// stylesheet text, same pattern test/tokens-contrast.test.js already uses
// for reading tokens.css. Selectors reconfirmed present this session via
// direct grep (not trusted from memory) before writing this assertion.
test('AC-22 Hovered state: a real :hover CSS rule exists for the interactive row class in each view stylesheet with a hover-capable row', () => {
  const readCss = (relPath) => readFileSync(fileURLToPath(new URL(`../${relPath}`, import.meta.url)), 'utf8');
  assert.ok(readCss('styles/privacy-view.css').includes('.privacy-row:hover'), 'expected .privacy-row:hover in styles/privacy-view.css');
  assert.ok(readCss('styles/inventory-view.css').includes('.inventory-row:hover'), 'expected .inventory-row:hover in styles/inventory-view.css');
  assert.ok(readCss('styles/trace-view.css').includes('.trace-alternate-item:hover'), 'expected .trace-alternate-item:hover in styles/trace-view.css');
});
