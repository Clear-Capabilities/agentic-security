// Render-level regression test for I3 in the Privacy/Trace Views plan's
// final whole-branch review: computeFlowSummary() (architecture-view.js)
// was fully computed into viewModel.flowSummary whenever a flow was
// selected, but nothing rendered it -- confirmed dead code at the time via
// `grep -rn flowSummary frontend/src`. The fix-wave gave it a real
// consumer, renderFlowSummary(), wired into the shell's context rail by
// app.js -- but renderFlowSummary() itself has never had a dedicated
// render-level test (flagged as a non-blocking follow-up by the fix-wave's
// own re-review: only a live CDP check proved it actually renders). This
// file closes that gap: same dependency-free `document` shim
// (test/dom-shim.js) and real fixture pattern as every other
// *-render.test.js in this directory.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computeArchitectureViewModel, renderFlowSummary } = await import('../src/views/architecture-view.js');

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

test('renderFlowSummary renders the real selected flow\'s data element, path, counts, and dimension verdicts', () => {
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const state = { view: 'architecture', selectedId: flowId, filters: {} };
  const viewModel = computeArchitectureViewModel(FLAGSHIP_GRAPH, state);
  assert.ok(viewModel.flowSummary, 'expected a computed flow summary for this selection');
  assert.equal(viewModel.flowSummary.transitVerdict, 'unprotected', 'fixture assumption this test relies on');

  const contextRailEl = document.createElement('div');
  renderFlowSummary(viewModel.flowSummary, contextRailEl);

  const text = contextRailEl.textContent;
  assert.ok(text.includes(viewModel.flowSummary.dataElementName), 'expected the real data element name to render');
  assert.ok(text.includes(`${viewModel.flowSummary.sourceLabel} → ${viewModel.flowSummary.destinationLabel}`), 'expected the real source->destination path to render');
  assert.ok(text.includes(`${viewModel.flowSummary.protectedCount} protected`), 'expected the real protected-edge count to render');
  assert.match(text, /Transit: Unprotected/, 'the real unprotected transitVerdict must render, not be silently dropped');
});

test('renderFlowSummary(null, ...) clears the context rail rather than leaving stale content', () => {
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const state = { view: 'architecture', selectedId: flowId, filters: {} };
  const viewModel = computeArchitectureViewModel(FLAGSHIP_GRAPH, state);

  const contextRailEl = document.createElement('div');
  renderFlowSummary(viewModel.flowSummary, contextRailEl);
  assert.ok(contextRailEl.childNodes.length > 0, 'sanity: the rail actually had content before clearing');

  renderFlowSummary(null, contextRailEl);
  assert.equal(contextRailEl.childNodes.length, 0, 'renderFlowSummary(null, ...) must clear stale content — app.js relies on this to avoid showing a stale flow summary after deselecting or switching views');
});
