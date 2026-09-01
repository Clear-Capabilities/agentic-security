// Regression test for the C1 finding from the final whole-branch review:
// renderNode()/renderEdge() built their outer <g> via el() (lib/dom.js),
// which calls document.createElement — the HTML namespace. Inside an <svg>
// tree (built via createElementNS), an HTML-namespaced <g> is a foreign
// element: neither it nor any of its children paint. The fix is svgEl()
// (architecture-view.js), which uses createElementNS consistently and wires
// onX handlers the same way el() does.
//
// This is proven two ways against the dependency-free dom shim (test/
// dom-shim.js, extended with createElementNS + classList.add for this):
//   1. Every element svgEl() produces is namespaceURI === SVG_NS.
//   2. A full renderArchitectureView() pass over the real fixture produces
//      .arch-node / .arch-edge groups (and their children) that are all
//      SVG-namespaced — not just the zone background/label, which is what
//      the old bug left as the only thing that actually painted.
//
// Against the OLD code (el('g', {...}) in renderNode/renderEdge), assertion
// (2) below would have failed: the .arch-node group's namespaceURI would
// have been the HTML namespace ('http://www.w3.org/1999/xhtml'), not SVG_NS,
// because el() calls document.createElement, not createElementNS.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { computeArchitectureViewModel, renderArchitectureView, svgEl } = await import('../src/views/architecture-view.js');

const SVG_NS = 'http://www.w3.org/2000/svg';

test('svgEl() always produces SVG-namespaced elements, distinct from the HTML namespace', () => {
  const g = svgEl('g', { class: 'arch-node' });
  assert.equal(g.namespaceURI, SVG_NS);
  assert.notEqual(g.namespaceURI, 'http://www.w3.org/1999/xhtml');
});

test('renderArchitectureView renders every node/edge group and its children in the SVG namespace', () => {
  const canvasEl = document.createElement('div');
  const viewModel = computeArchitectureViewModel(FLAGSHIP_GRAPH, { view: 'architecture', selectedId: null, filters: {} });
  renderArchitectureView(viewModel, canvasEl, () => {});

  const svg = canvasEl.firstChild;
  assert.ok(svg, 'renderArchitectureView should append an <svg> root to the canvas element');
  assert.equal(svg.namespaceURI, SVG_NS);

  const archNodeGroups = svg.querySelectorAll('[class="arch-node"]');
  assert.ok(archNodeGroups.length > 0, 'expected at least one .arch-node group to have rendered');
  for (const group of archNodeGroups) {
    assert.equal(group.namespaceURI, SVG_NS, `arch-node group should be SVG-namespaced, not "${group.namespaceURI}"`);
    for (const child of group.childNodes) {
      if (child.nodeType === 'element') {
        assert.equal(child.namespaceURI, SVG_NS, `arch-node child <${child.tagName}> should be SVG-namespaced, not "${child.namespaceURI}"`);
      }
    }
  }

  const archNodeBoxes = svg.querySelectorAll('[class="arch-node-box"]');
  assert.ok(archNodeBoxes.length > 0, 'expected at least one .arch-node-box rect to have rendered');
  assert.ok(archNodeBoxes.every((box) => box.namespaceURI === SVG_NS));

  const archEdgeGroups = svg.querySelectorAll('[class="arch-edge"]');
  assert.ok(archEdgeGroups.length > 0, 'expected at least one .arch-edge group to have rendered');
  for (const group of archEdgeGroups) {
    assert.equal(group.namespaceURI, SVG_NS, `arch-edge group should be SVG-namespaced, not "${group.namespaceURI}"`);
    for (const child of group.childNodes) {
      if (child.nodeType === 'element') {
        assert.equal(child.namespaceURI, SVG_NS, `arch-edge child <${child.tagName}> should be SVG-namespaced, not "${child.namespaceURI}"`);
      }
    }
  }
});

// --- Task 3: clustering/pan-zoom/culling wired into the real renderer ---
//
// architecture-view.js now carries module-level render state
// (currentViewport, expandedZones, dragState — see that file's own
// comments) so pan/zoom position survives an ordinary view switch. That
// state is shared by every test in a process that imports the module via
// the SAME specifier. The two tests above (and every OTHER test file in
// this repo that imports architecture-view.js) all use the plain
// '../src/views/architecture-view.js' specifier and only ever render the
// small, un-clustered 14-node flagship fixture, so they never observe this
// state. The three tests below build large/dense synthetic graphs
// specifically to force clustering, and each imports the module via its
// OWN cache-busting query-string specifier (confirmed this session: Node's
// ESM loader treats a different query string as a distinct module
// instantiation, e.g. `...architecture-view.js?dense-cluster`) so each
// test gets a fresh currentViewport === null / expandedZones === empty,
// independent of what any other test in this file (or a same-process
// sibling file, when the runner batches files together) already did.
function makeStoreNode(id) {
  return { id, label: id, kind: 'store', subtype: null };
}
function makeApiNode(id) {
  return { id, label: id, kind: 'api', subtype: null };
}
function makeMinimalEdge(id, from, to, verdict) {
  return {
    id,
    from,
    to,
    protection: {
      transit: { verdict: 'not_assessed' },
      atRest: { verdict: 'not_assessed' },
      handling: { verdict },
    },
  };
}
// Real, derived (not guessed) number: architecture-view.js's own
// computeZoneNodeBudget() — VISIBLE_ELEMENT_BUDGET 2000, 5 zones, 20% edge/
// chrome reserve, 3 elements/node — evaluates to 106 this session. These
// fixtures use counts well past that (150, 130) so clustering engages
// regardless of small future formula tweaks, without hardcoding 106 itself
// into the assertions below.
const DENSE_STORE_COUNT = 150;

test('a dense zone (over budget) renders exactly one cluster glyph, not one <g class="arch-node"> per overflow node', async () => {
  const { computeArchitectureViewModel: computeVM, renderArchitectureView: render } = await import('../src/views/architecture-view.js?dense-cluster-glyph');
  const denseGraph = { nodes: Array.from({ length: DENSE_STORE_COUNT }, (_, i) => makeStoreNode(`store-${i}`)), edges: [], flows: [], dataElements: [] };
  const canvasEl = document.createElement('div');
  const vm = computeVM(denseGraph, { view: 'architecture', selectedId: null, filters: {} });
  render(vm, canvasEl, () => {});
  const nodeGroups = canvasEl.querySelectorAll('[class="arch-node"]');
  const clusterGroups = canvasEl.querySelectorAll('[class="arch-node-cluster"]');
  assert.equal(clusterGroups.length, 1, 'expected exactly one cluster glyph for the single dense zone');
  assert.ok(nodeGroups.length < denseGraph.nodes.length, 'far fewer individual node groups than raw node count');
  assert.ok(nodeGroups.length > 0, 'sanity: some individual nodes should still render under budget');
});

test('clicking a cluster glyph expands it — the previously-clustered nodes now render individually', async () => {
  const { computeArchitectureViewModel: computeVM, renderArchitectureView: render } = await import('../src/views/architecture-view.js?dense-cluster-expand');
  const denseGraph = { nodes: Array.from({ length: DENSE_STORE_COUNT }, (_, i) => makeStoreNode(`store-${i}`)), edges: [], flows: [], dataElements: [] };
  const canvasEl = document.createElement('div');
  const vm = computeVM(denseGraph, { view: 'architecture', selectedId: null, filters: {} });
  render(vm, canvasEl, () => {});

  const clusterBefore = canvasEl.querySelectorAll('[class="arch-node-cluster"]');
  assert.equal(clusterBefore.length, 1, 'sanity: dense graph should start clustered');
  const lastNodeLabel = `store-${DENSE_STORE_COUNT - 1}`;
  const textBefore = canvasEl.querySelectorAll('[class="arch-node"]').map((g) => g.getAttribute('aria-label')).join(' | ');
  assert.ok(!textBefore.includes(lastNodeLabel), `sanity: "${lastNodeLabel}" should be clustered away, not individually rendered, before expansion`);

  clusterBefore[0].dispatch('click');

  const clusterAfter = canvasEl.querySelectorAll('[class="arch-node-cluster"]');
  assert.equal(clusterAfter.length, 0, 'expanding the only cluster should leave no cluster glyphs for that zone');
  const nodeGroupsAfter = canvasEl.querySelectorAll('[class="arch-node"]');
  assert.equal(nodeGroupsAfter.length, DENSE_STORE_COUNT, 'every previously-clustered node should now render individually');
  const labelsAfter = nodeGroupsAfter.map((g) => g.getAttribute('aria-label'));
  assert.ok(labelsAfter.some((l) => l.startsWith(lastNodeLabel)), `expected "${lastNodeLabel}" to render individually after expansion`);
});

test('an edge to a clustered node renders as a real, aggregated edge to the cluster glyph, with the worst constituent verdict', async () => {
  const { computeArchitectureViewModel: computeVM, renderArchitectureView: render } = await import('../src/views/architecture-view.js?cluster-edge-aggregation');
  const STORE_COUNT = 130;
  const storeNodes = Array.from({ length: STORE_COUNT }, (_, i) => makeStoreNode(`store-${i}`));
  const gateway = makeApiNode('gateway');
  // Both targets are well past any reasonable budget (~106 this session)
  // for a 130-node zone, so both are guaranteed clustered regardless of
  // small future formula tweaks.
  const protectedTarget = `store-${STORE_COUNT - 2}`;
  const unprotectedTarget = `store-${STORE_COUNT - 1}`;
  const graph = {
    nodes: [gateway, ...storeNodes],
    edges: [
      makeMinimalEdge('e-protected', 'gateway', protectedTarget, 'protected'),
      makeMinimalEdge('e-unprotected', 'gateway', unprotectedTarget, 'unprotected'),
    ],
    flows: [],
    dataElements: [],
  };
  const canvasEl = document.createElement('div');
  const vm = computeVM(graph, { view: 'architecture', selectedId: null, filters: {} });
  render(vm, canvasEl, () => {});

  const clusterGroups = canvasEl.querySelectorAll('[class="arch-node-cluster"]');
  assert.equal(clusterGroups.length, 1, 'sanity: both targets should have collapsed into one Data Layer cluster');

  const edgeGroups = canvasEl.querySelectorAll('[class="arch-edge"]');
  assert.equal(edgeGroups.length, 1, 'two edges into the same cluster must aggregate into exactly one rendered edge group');
  const aria = edgeGroups[0].getAttribute('aria-label');
  assert.ok(aria.includes('Unprotected'), `expected the aggregated edge to show the WORSE (Unprotected) verdict; got "${aria}"`);
  assert.ok(!aria.includes('protection Protected'), `aggregated edge must not show the better (Protected) verdict; got "${aria}"`);
});
