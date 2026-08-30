// Render-level regression tests for the two Privacy View bugs from the final
// whole-branch review (I3 in the review, Fix 3 in the fix-wave plan):
//
//   (a) renderStageCell() used to early-return '—' *before* the
//       governance-badge loop ever ran, for any stage cell whose
//       nodeLabels was empty — so retention/deletion governance facts
//       (e.g. deletion: 'not_found') were structurally unreachable
//       whenever a flow's path didn't touch a retention/deletion-stage
//       node, which is every flow in the real fixture.
//   (b) the flow-level protection verdict badge was only attached inside
//       the sharing-stage cell, so any flow whose path skipped a
//       sharing-stage node showed no protection verdict anywhere — 3 of 8
//       real rows, including the flow with raw unprotected PCI in logs.
//
// Both were render-layer defects invisible to privacy-view.test.js's
// pure-function tests (computePrivacyRow/computePrivacyViewModel never
// touch the DOM), which is exactly why this file exists — see
// frontend/CLAUDE.md and test/architecture-view-render.test.js for the
// established render-level-test pattern this follows: the dependency-free
// `document` shim (test/dom-shim.js) plus the real fixture, never synthetic
// data.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computePrivacyViewModel, renderPrivacyView } = await import('../src/views/privacy-view.js');

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

// dom-shim's querySelectorAll only understands `[attr]`/`[attr="value"]`
// selectors, and el() (lib/dom.js) sets `class` via the `.className`
// property rather than `setAttribute`, so a `[class="..."]` selector can't
// see it. Walk the tree and compare `.className` directly instead.
function findByClassName(root, className) {
  const results = [];
  const walk = (node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 'element') {
        if (child.className === className) results.push(child);
        walk(child);
      }
    }
  };
  walk(root);
  return results;
}

test('renderPrivacyView gives every row a non-empty, non-placeholder protection verdict cell (Fix 3b regression)', () => {
  const canvasEl = document.createElement('div');
  const viewModel = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(viewModel, canvasEl, () => {});

  const protectionCells = findByClassName(canvasEl, 'privacy-protection-cell');
  assert.equal(protectionCells.length, viewModel.rows.length, 'expected exactly one dedicated protection cell per row');
  assert.ok(protectionCells.length >= 8, 'sanity: the real fixture has 8 flows');

  for (const cell of protectionCells) {
    const text = cell.textContent.trim();
    assert.notEqual(text, '', 'protection verdict cell must never be empty');
    assert.notEqual(text, '—', 'protection verdict cell must never be the empty-stage-cell placeholder');
  }
});

test('renderPrivacyView surfaces retention/deletion governance facts even when their stage cell has no path nodes (Fix 3a regression)', () => {
  const flowId = FLOW_KEYS['flow.pii.analytics'];
  const viewModel = computePrivacyViewModel(FLAGSHIP_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  const row = viewModel.rows.find((r) => r.flowId === flowId);

  // Confirm the fixture assumption this test relies on before asserting
  // anything about rendering.
  assert.equal(row.governanceRefs.deletion, 'not_found');
  assert.ok(row.stageCells.find((c) => c.stage === 'deletion').nodeLabels.length === 0, 'this flow\'s path must not touch a deletion-stage node, or the bug this test guards against never reproduces');

  const canvasEl = document.createElement('div');
  renderPrivacyView(viewModel, canvasEl, () => {});

  const rowEls = findByClassName(canvasEl, 'privacy-row');
  const targetRowEl = rowEls.find((tr) => (tr.getAttribute('aria-label') ?? '').startsWith(row.dataElementName));
  assert.ok(targetRowEl, 'expected to find the rendered row for this flow');
  assert.match(targetRowEl.textContent, /deletion: not_found/);
});
