// Render-level tests for Inventory View's render half (renderInventoryView).
// Follows privacy-view-render.test.js's own structure: the dependency-free
// `document` shim (test/dom-shim.js), then dynamic `await import(...)` of
// the module under test. Row/button click simulation uses dom-shim's real
// `.dispatch(type, event)` helper — the same mechanism already used by
// test/filter-rail.test.js, test/shell.test.js, and test/dom.test.js — not
// a synthetic `dispatchEvent` call, which dom-shim's FakeElement does not
// implement.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { computeInventoryViewModel, renderInventoryView } = await import('../src/views/inventory-view.js');

const GRAPH = {
  nodes: [
    { id: 'node:src1', kind: 'source', subtype: 'http-body', label: 'Signup body', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
  ],
  edges: [], dataElements: [], transformations: [], flows: [],
};

test('renderInventoryView renders a sub-nav strip with all 11 category buttons', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  renderInventoryView(vm, canvasEl, () => {}, () => {});
  const navButtons = canvasEl.querySelectorAll('[data-table-id]');
  assert.equal(navButtons.length, 11);
});

test('renderInventoryView renders one <tr> per row plus a header row, with the right column headers', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  renderInventoryView(vm, canvasEl, () => {}, () => {});
  const headerCells = findAllByTag(canvasEl, 'TH');
  assert.equal(headerCells.length, 4); // Label, Category, Coverage, Externality
  const bodyRows = findByTagUnderClass(canvasEl, 'TBODY', 'TR');
  assert.equal(bodyRows.length, 1);
});

test("clicking a row calls onSelect with the row's selectableId", () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  let selected = null;
  renderInventoryView(vm, canvasEl, (id) => { selected = id; }, () => {});
  const row = findAllByTag(canvasEl, 'TR').find((tr) => tr.className === 'inventory-row');
  row.dispatch('click');
  assert.equal(selected, 'node:src1');
});

test('clicking a sub-nav button calls onTableChange with that table id', () => {
  const canvasEl = document.createElement('div');
  const vm = computeInventoryViewModel(GRAPH, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  let changedTo = null;
  renderInventoryView(vm, canvasEl, () => {}, (id) => { changedTo = id; });
  const sinksButton = canvasEl.querySelectorAll('[data-table-id="sinks"]')[0];
  assert.ok(sinksButton);
  sinksButton.dispatch('click');
  assert.equal(changedTo, 'sinks');
});

test('clicking a column header sorts rows by that column', () => {
  const canvasEl = document.createElement('div');
  const twoRowGraph = {
    nodes: [
      { id: 'node:b', kind: 'source', subtype: null, label: 'Bravo', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
      { id: 'node:a', kind: 'source', subtype: null, label: 'Alpha', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
    ],
    edges: [], dataElements: [], transformations: [], flows: [],
  };
  const vm = computeInventoryViewModel(twoRowGraph, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });
  renderInventoryView(vm, canvasEl, () => {}, () => {});

  const firstCellTextBeforeSort = findByTagUnderClass(canvasEl, 'TBODY', 'TR')[0].childNodes[0].textContent;
  assert.equal(firstCellTextBeforeSort, 'Bravo', 'sanity: unsorted rows keep fixture order (Bravo, Alpha)');

  const firstHeader = findAllByTag(canvasEl, 'TH')[0];
  firstHeader.dispatch('click');
  const firstCellTextAfterSort = findByTagUnderClass(canvasEl, 'TBODY', 'TR')[0].childNodes[0].textContent;
  assert.equal(firstCellTextAfterSort, 'Alpha');
});

test('sortState does not leak between two separate renderInventoryView calls', () => {
  const twoRowGraph = {
    nodes: [
      { id: 'node:b', kind: 'source', subtype: null, label: 'Bravo', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
      { id: 'node:a', kind: 'source', subtype: null, label: 'Alpha', aliases: [], dataElementIds: [], evidenceRefs: [], coverageStatus: 'modeled', externality: { value: 'internal', evidenceRefs: [] } },
    ],
    edges: [], dataElements: [], transformations: [], flows: [],
  };
  const vm = computeInventoryViewModel(twoRowGraph, { view: 'inventory', selectedId: null, filters: {}, table: 'sources' });

  const canvas1 = document.createElement('div');
  renderInventoryView(vm, canvas1, () => {}, () => {});
  findAllByTag(canvas1, 'TH')[0].dispatch('click'); // sorts canvas1 ascending

  // A brand-new render call on a fresh canvas should start unsorted again,
  // independent of the sort state canvas1's own click handlers hold onto.
  const canvas2 = document.createElement('div');
  renderInventoryView(vm, canvas2, () => {}, () => {});
  const firstCellCanvas2 = findByTagUnderClass(canvas2, 'TBODY', 'TR')[0].childNodes[0].textContent;
  assert.equal(firstCellCanvas2, 'Bravo', 'a fresh renderInventoryView call must start with its own unsorted rows, not inherit another call\'s sort state');
});

// dom-shim's querySelectorAll only understands `[attr]`/`[attr="value"]`
// selectors (see test/dom-shim.js), so tag-based lookups need a manual walk,
// same pattern privacy-view-render.test.js uses for class-based lookups.
function findAllByTag(root, tagName) {
  const results = [];
  const walk = (node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 'element') {
        if (child.tagName === tagName) results.push(child);
        walk(child);
      }
    }
  };
  walk(root);
  return results;
}

function findByTagUnderClass(root, containerTag, childTag) {
  const container = findAllByTag(root, containerTag)[0];
  if (!container) return [];
  return findAllByTag(container, childTag);
}
