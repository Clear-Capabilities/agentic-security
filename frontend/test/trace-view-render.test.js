// Render-level regression test for the Critical bug (C-equivalent, Fix 1 in
// the fix-wave plan) from the final whole-branch review: renderTraceStep()
// only ever read step.protection.handling.verdict, silently discarding
// step.protection.transit.verdict and step.protection.atRest.verdict. The
// real fixture has the Payments Service -> Payment API edge
// (edge:b397f3640150, flow:a411014f471c / extensions key
// 'flow.pci.payment_api') with transit.verdict === 'unprotected' while
// handling.verdict === 'not_assessed' — the old code rendered only
// "Handling: Not assessed" for that hop, a false, contradictory claim vs.
// Architecture View's worstVerdict()-based "Unprotected" for the same edge.
//
// This was invisible to trace-view.test.js's pure-function tests
// (computeTraceSteps never touches the DOM), which is why this file exists
// — same dependency-free `document` shim (test/dom-shim.js) and real
// fixture pattern as test/architecture-view-render.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computeTraceViewModel, renderTraceView } = await import('../src/views/trace-view.js');

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

test('renderTraceView shows the unprotected-transit verdict for the Payments Service -> Payment API hop, not just a handling verdict (Fix 1 regression)', () => {
  const flowId = FLOW_KEYS['flow.pci.payment_api'];
  const flow = FLAGSHIP_GRAPH.flows.find((f) => f.id === flowId);

  // Confirm the fixture assumption this test relies on before asserting
  // anything about rendering: the real edge has transit unprotected while
  // handling is not_assessed — the exact shape the old code got wrong.
  const targetEdge = FLAGSHIP_GRAPH.edges.find((e) => flow.edgeIds.includes(e.id) && e.protection.transit.verdict === 'unprotected');
  assert.ok(targetEdge, 'expected this flow to contain an edge with transit: unprotected');
  assert.notEqual(targetEdge.protection.handling.verdict, 'unprotected', 'this edge must NOT also be unprotected on handling, or it would not distinguish the old bug from the fix');

  const state = { view: 'trace', selectedId: flowId, filters: {} };
  const viewModel = computeTraceViewModel(FLAGSHIP_GRAPH, state);
  assert.ok(viewModel, 'expected a trace view model for this flow');

  // Locate the specific step for this edge (by protection object identity —
  // computeTraceSteps assigns `protection: edge.protection` directly) rather
  // than searching the whole rendered trace's text, since an earlier hop in
  // this same flow legitimately has transit: not_assessed and would make a
  // whole-page substring check ambiguous.
  const targetStepIndex = viewModel.steps.findIndex((s) => s.protection === targetEdge.protection);
  assert.notEqual(targetStepIndex, -1, 'expected to find the rendered step for this edge');

  const canvasEl = document.createElement('div');
  renderTraceView(viewModel, canvasEl, () => {});

  const container = canvasEl.firstChild;
  const stepEl = container.childNodes[targetStepIndex];
  assert.ok(stepEl, 'expected a rendered step element at the target index');

  assert.match(stepEl.textContent, /Transit: Unprotected/, 'the rendered step must show the real unprotected-transit verdict');
  assert.doesNotMatch(stepEl.textContent, /Transit: Not assessed/, 'this step\'s edge has a real transit verdict; it must never render as "not assessed"');
});
