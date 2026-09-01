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

// The 6 new facets added for the filter-rail expansion (dataClass/
// protection/ai grow to 9 real facets). Every expected value below was
// computed by reading FLAGSHIP_GRAPH's real committed nodes/edges/flows
// directly, not guessed or copied from the PRD's illustrative vocabulary.
test('computeFilterFacets: sourceCategories are the real, distinct node.subtype values among kind===source nodes', () => {
  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  // The real fixture has exactly ONE kind:'source' node (Web App), subtype 'web-app'.
  assert.deepEqual(facets.sourceCategories, ['web-app']);
});

// Real, disclosed surprise found while grounding this test against the
// fixture: FLAGSHIP_GRAPH has ZERO nodes with kind==='sink' (confirmed also
// by test/xss-adversarial.test.js's own comment, "no node kind is 'sink'",
// and inventory-view.js's own Sinks table, which filters on the same
// kind==='sink' predicate and is empty for this fixture too). So
// sinkCategories is correctly an EMPTY array here, not the non-empty set
// the brief's own illustrative test comment implied every facet would be.
test('computeFilterFacets: sinkCategories, destinationExternalities, transitVerdicts, atRestVerdicts, handlingVerdicts, policyVerdicts are all real, deduplicated, sorted arrays grounded in the real fixture', () => {
  const facets = computeFilterFacets(FLAGSHIP_GRAPH);
  for (const key of ['sinkCategories', 'destinationExternalities', 'transitVerdicts', 'atRestVerdicts', 'handlingVerdicts', 'policyVerdicts']) {
    assert.ok(Array.isArray(facets[key]), `expected facets.${key} to be an array`);
  }
  // sinkCategories: no kind:'sink' node exists in the real fixture at all.
  assert.deepEqual(facets.sinkCategories, []);
  // destinationExternalities: real node.externality.value values present are internal/external/unknown.
  assert.deepEqual(facets.destinationExternalities, ['external', 'internal', 'unknown']);
  // transitVerdicts: every edge is 'not_assessed' except the one HTTP hop to Payment API ('unprotected').
  assert.deepEqual(facets.transitVerdicts, ['not_assessed', 'unprotected']);
  // atRestVerdicts: every edge is 'not_assessed' except the Payments Service -> PostgreSQL edge ('unknown').
  assert.deepEqual(facets.atRestVerdicts, ['not_assessed', 'unknown']);
  // handlingVerdicts: masked-log edge is 'protected', raw-log edge is 'unprotected', every other edge is 'not_assessed'.
  assert.deepEqual(facets.handlingVerdicts, ['not_assessed', 'protected', 'unprotected']);
  // policyVerdicts: the two AI-recipient flows are 'manual_review_required'; every other flow is 'not_evaluated'.
  assert.deepEqual(facets.policyVerdicts, ['manual_review_required', 'not_evaluated']);
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
