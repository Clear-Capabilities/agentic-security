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
