import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { computeFilterFacets } from '../src/components/filter-rail.js';

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
