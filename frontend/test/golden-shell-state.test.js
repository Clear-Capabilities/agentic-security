// Golden-DOM regression test for AC-16 (shared shell / cross-view state
// persistence). Proves the ALREADY-SHIPPED shell still keeps selection and
// filters intact across a real view switch, and that the header/coverage
// content is unaffected by a view-only state change — against the REAL
// flagship fixture. Not new feature work; see
// docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md
// for why this is a regression-proving task.
//
// Follows the same dom-shim + real-fixture pattern as test/shell.test.js.
//
// Confirmed this session (read src/shell.js's full public API + its JSDoc):
// mountShell()'s returned object DOES expose a real, callable
// `setActiveView(viewName)` method (it's already covered by
// shell.test.js's "onStateChange fires ... on setSelection, setFilters,
// and setActiveView" test) — the brief's uncertainty about this name is
// resolved: it is real. This test still switches views via a REAL rendered
// tab click (`[data-view-id="privacy"]`'s `.dispatch('click')`), per the
// brief's own sample code, because that exercises the full real UI wiring
// (buildViewTabs' onClick -> updateState) end-to-end rather than only the
// programmatic shortcut — the same dom-shim `.dispatch('click')` mechanism
// already used throughout this codebase (see golden-architecture.test.js,
// shell.test.js's own "view-tab clicking" test). setActiveView is
// equally real and would prove the same underlying state-persistence
// contract, just without the tab-click wiring itself as part of the proof.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document, window } = createDomShim();
globalThis.document = document;
globalThis.window = window;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { mountShell } = await import('../src/shell.js');

// dom-shim's FakeElement implements only querySelectorAll, and only the
// `[attr]`/`[attr="value"]` selector shapes (see test/dom-shim.js's own
// header comment) — there is no `querySelector` and no `.class` selector
// support. buildHeader()'s meta lines are built via el() with a `class`
// attr, which el() applies via node.className (a plain property), not
// setAttribute (src/lib/dom.js) — so even an attribute-selector query
// would never match them. Confirmed against the real render this session:
// the flagship fixture's scope.source === 'fixture', so buildHeader()
// actually renders TWO elements sharing class 'shell__header-meta' (the
// "repo · env · Scan status" line and the "Illustrative demo data" line) —
// a single `.querySelector`-style first-match, if it existed, would only
// ever see one of them. Walking the tree and filtering on .className,
// then comparing the full array of header-meta texts before/after, is the
// real, working mechanism and also the more complete proof (both lines
// unchanged, not just one).
function allElements(root) {
  const out = [];
  const walk = (node) => { for (const c of node.childNodes) { if (c.nodeType === 'element') { out.push(c); walk(c); } } };
  walk(root);
  return out;
}
function headerMetaTexts(root) {
  return allElements(root)
    .filter((el) => el.className === 'shell__header-meta')
    .map((el) => el.textContent);
}

test('AC-16: selection and filters persist across a real view switch, and the header/coverage banner stay unchanged', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, FLAGSHIP_GRAPH);

  const flowId = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys['flow.pci.payment_api'];
  shell.setSelection(flowId);
  shell.setFilters({ dataClass: ['PCI'] });

  const headerTextsBefore = headerMetaTexts(root);
  assert.ok(headerTextsBefore.length > 0, 'sanity: expected at least one rendered header-meta line');

  // Switch views via a real tab click, from architecture (the default) to
  // privacy.
  const tabs = root.querySelectorAll('[data-view-id]');
  const privacyTab = tabs.find((t) => t.getAttribute('data-view-id') === 'privacy');
  assert.ok(privacyTab, 'sanity: expected a rendered tab button for the privacy view');
  privacyTab.dispatch('click');

  const state = shell.getState();
  assert.equal(state.view, 'privacy', 'sanity: the tab click must have actually switched the view');
  assert.equal(state.selectedId, flowId, 'selection must persist across the view switch');
  assert.deepEqual(state.filters, { dataClass: ['PCI'] }, 'filters must persist across the view switch');

  const headerTextsAfter = headerMetaTexts(root);
  assert.deepEqual(headerTextsAfter, headerTextsBefore, 'header/coverage content must not change when only the view changes');

  shell.destroy();
});
