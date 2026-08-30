import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { computeFilterFacets, renderFilterRail } from '../src/components/filter-rail.js';

test('computeFilterFacets derives dataClasses from the real fixture\'s dataElements, deduplicated and sorted', () => {
  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  assert.deepEqual(facets.dataClasses, ['PCI', 'PHI', 'PII']);
});

test('computeFilterFacets\'s protectionTiers is the fixed enum, not derived from what happens to be present', () => {
  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  assert.deepEqual(facets.protectionTiers, ['protected', 'unprotected', 'mixed', 'unknown']);
});

test('computeFilterFacets never throws on a graph with zero dataElements', () => {
  const emptyGraph = { ...FLAGSHIP_GRAPH, dataElements: [] };
  assert.doesNotThrow(() => computeFilterFacets(emptyGraph));
  assert.deepEqual(computeFilterFacets(emptyGraph).dataClasses, []);
});

// Render-level test, added as part of the final fix wave: toggleListFilter()
// (the click handler wired to each chip button) had zero coverage since it's
// unreachable from the pure-function tests above — computeFilterFacets never
// touches the DOM or the click path. Uses the same dependency-free
// `document` shim (test/dom-shim.js) as test/architecture-view-render.test.js,
// dispatching a real click through the shim's click-dispatch mechanism.
test('renderFilterRail: clicking a chip calls onFiltersChange with the correctly toggled filter object', () => {
  const { document } = createDomShim();
  globalThis.document = document;

  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  const railEl = document.createElement('div');
  const calls = [];
  const onFiltersChange = (next) => calls.push(next);

  renderFilterRail(facets, {}, railEl, onFiltersChange);

  // Find the 'PCI' data-class chip button by its rendered label text.
  let pciChip = null;
  const walk = (node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 'element') {
        if (child.tagName === 'BUTTON' && child.textContent === 'PCI') pciChip = child;
        walk(child);
      }
    }
  };
  walk(railEl);
  assert.ok(pciChip, 'expected to find a rendered chip button labeled "PCI"');

  pciChip.dispatch('click');

  assert.equal(calls.length, 1, 'onFiltersChange should have been called exactly once');
  assert.deepEqual(calls[0], { dataClass: ['PCI'] });
});
