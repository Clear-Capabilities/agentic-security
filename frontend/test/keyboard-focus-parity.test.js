import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { computeArchitectureViewModel, renderArchitectureView } = await import('../src/views/architecture-view.js');
const { computePrivacyViewModel, renderPrivacyView } = await import('../src/views/privacy-view.js');
const { computeTraceViewModel, renderTraceView } = await import('../src/views/trace-view.js');
const { computeInventoryViewModel, renderInventoryView } = await import('../src/views/inventory-view.js');
const { ADVERSARIAL_GRAPH } = await import('./adversarial-fixture.js');

function allElements(root) {
  const out = [];
  const walk = (node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 'element') { out.push(child); walk(child); }
    }
  };
  walk(root);
  return out;
}

// An element counts as "interactive" for this sweep if it has role="button"
// (every view's own convention for a non-native clickable element) — a
// native <button> is excluded from the check below since it's natively
// focusable without an explicit tabindex.
function assertKeyboardReachable(canvasEl, viewName) {
  const interactive = allElements(canvasEl).filter((el) => el.tagName !== 'BUTTON' && el.attrs.get('role') === 'button');
  assert.ok(interactive.length > 0, `${viewName}: sanity — expected at least one non-<button> interactive element in this fixture`);
  for (const el of interactive) {
    assert.ok(el.attrs.has('tabindex'), `${viewName}: a role="button" element (<${el.tagName}>) has no tabindex — unreachable by keyboard`);
  }
}

test('AC-20/21 keyboard reachability: Architecture View', () => {
  const canvasEl = document.createElement('div');
  const vm = computeArchitectureViewModel(ADVERSARIAL_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(vm, canvasEl, () => {});
  assertKeyboardReachable(canvasEl, 'Architecture View');
});

test('AC-20/21 keyboard reachability: Privacy View', () => {
  const canvasEl = document.createElement('div');
  const vm = computePrivacyViewModel(ADVERSARIAL_GRAPH, { view: 'privacy', selectedId: null, filters: {} });
  renderPrivacyView(vm, canvasEl, () => {});
  assertKeyboardReachable(canvasEl, 'Privacy View');
});

// Trace View's ONLY role="button" elements are its "Alternate destinations"
// list items (see trace-view.js's renderTraceView), populated by
// computeAlternatePaths() from OTHER flows sharing a dataElementId with the
// selected flow. ADVERSARIAL_GRAPH has exactly one flow (flow:evil1), so
// computeAlternatePaths() is always empty there regardless of selectedId —
// confirmed by running this sub-test against ADVERSARIAL_GRAPH first, which
// failed its own sanity assertion (zero interactive elements). Per this
// task's own brief, using a small inline fixture for this one view instead
// of forcing ADVERSARIAL_GRAPH to fit — disclosed, not silently worked
// around. Two flows sharing one dataElement give flow:1 a real alternate
// (flow:2), which is all this structural keyboard-reachability check needs.
const TRACE_GRAPH = {
  nodes: [
    { id: 'node:source1', kind: 'source', label: 'Source One', externality: { value: 'internal' } },
    { id: 'node:sink1', kind: 'sink', label: 'Sink One', externality: { value: 'internal' } },
    { id: 'node:sink2', kind: 'sink', label: 'Sink Two', externality: { value: 'external' } },
  ],
  edges: [
    {
      id: 'edge:1', from: 'node:source1', to: 'node:sink1', fieldMappings: [], boundaryCrossings: [], evidenceRefs: [],
      protection: { transit: { verdict: 'protected' }, atRest: { verdict: 'protected' }, handling: { verdict: 'protected' } },
    },
    {
      id: 'edge:2', from: 'node:source1', to: 'node:sink2', fieldMappings: [], boundaryCrossings: [], evidenceRefs: [],
      protection: { transit: { verdict: 'unprotected' }, atRest: { verdict: 'unprotected' }, handling: { verdict: 'unprotected' } },
    },
  ],
  dataElements: [{ id: 'data:field1', name: 'Field One' }],
  transformations: [],
  flows: [
    { id: 'flow:1', dataElementIds: ['data:field1'], source: 'node:source1', sink: 'node:sink1', edgeIds: ['edge:1'], protectionSummary: 'protected' },
    { id: 'flow:2', dataElementIds: ['data:field1'], source: 'node:source1', sink: 'node:sink2', edgeIds: ['edge:2'], protectionSummary: 'unprotected' },
  ],
};

test('AC-20/21 keyboard reachability: Trace View', () => {
  const canvasEl = document.createElement('div');
  const vm = computeTraceViewModel(TRACE_GRAPH, { view: 'trace', selectedId: 'flow:1', filters: {} });
  renderTraceView(vm, canvasEl, () => {});
  assertKeyboardReachable(canvasEl, 'Trace View');
});

test('AC-20/21 keyboard reachability: Inventory View', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(ADVERSARIAL_GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  renderInventoryView(vm, canvasEl, () => {}, () => {});
  assertKeyboardReachable(canvasEl, 'Inventory View');
});
