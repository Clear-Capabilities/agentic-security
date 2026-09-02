// bundle-frontend-golden.test.js — Milestone 4, sub-project Self-contained
// HTML report, Task 2's load-bearing proof for Task 1's whole approach:
// bundling frontend/src/export-entry.js (via bundleFrontendModules(),
// scanner/scripts/bundle-frontend.mjs) must behave IDENTICALLY to running
// the real, unbundled export-entry.js.
//
// Grounded in the REAL frontend/src/ tree (not a synthetic fixture) — Task
// 1's own test suite (test/bundle-frontend.test.js) already covers the
// bundler algorithm's correctness in isolation against small hand-built
// trees; this test proves it holds for the real, full app entry point that
// actually ships.
//
// Harness notes (re-verified against the real frontend/test/dom-shim.js and
// frontend/test/live-fetch-parity.test.js this session — the task-2 brief's
// own sketch for this file was explicitly marked unverified against the
// shim's real API):
//   - createDomShim() returns { document, window }, not a single object.
//     `document` has no `outerHTML`/serialization of its own — the
//     established in-repo pattern for comparing two independently-mounted
//     dom-shim trees (live-fetch-parity.test.js) is a hand-rolled
//     `serialize()` walk (tag/namespace/sorted-attrs/children) compared via
//     assert.deepEqual, not string equality — reused here verbatim.
//   - shell.js reads `window.location.hash` and registers a `hashchange`
//     listener, so `window` (not just `document`) must be set for
//     bootstrap() to run at all.
//   - document.getElementById() in the real shim is HARDCODED to always
//     return null (confirmed by reading the file — there is no real id
//     registry, only whatever a test builds by hand). export-entry.js's own
//     top-level guard AND its init() both call
//     document.getElementById('app-root') to find its mount point, so
//     under the shim as shipped that call can never resolve truthy and
//     export-entry.js's auto-init would never fire for either the bundled
//     or unbundled path. This test instance-patches getElementById on each
//     fresh shim (not the dom-shim.js source file) to resolve the literal
//     'app-root' id to the specific root element that run is mounting into
//     — a faithful model of what a real browser's getElementById does for
//     the one id this file ever queries, not a change to the shared shim.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bundleFrontendModules } from '../scripts/bundle-frontend.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_SRC = path.resolve(__dirname, '../../frontend/src');
const DOM_SHIM_PATH = path.resolve(__dirname, '../../frontend/test/dom-shim.js');
const FLAGSHIP_PATH = path.resolve(__dirname, '../src/lineage/fixtures/flagship-graph.json');

// Same shape as frontend/test/live-fetch-parity.test.js's own serialize() —
// tag, namespace, sorted attributes, and children only. Object identity and
// event-listener closures legitimately differ between two independent
// mounts and must never be part of the comparison.
function serialize(node) {
  if (!node) return null;
  if (node.nodeType === 'text') {
    return { type: 'text', data: node.data };
  }
  return {
    type: 'element',
    tag: node.tagName,
    ns: node.namespaceURI,
    attrs: Object.fromEntries([...node.attrs.entries()].sort(([a], [b]) => a.localeCompare(b))),
    children: node.childNodes.map(serialize),
  };
}

test('bundle-frontend-golden: bundled export-entry.js renders the same DOM as the unbundled export-entry.js', async () => {
  const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));
  const { createDomShim } = await import(DOM_SHIM_PATH);

  // --- Unbundled baseline: import the real, unmodified export-entry.js as
  // a genuine ES module (not a manual bootstrap() call) — this is the exact
  // entry point that gets bundled, so this is the truest possible baseline
  // for a bundling-equivalence proof. Its own top-level guard synchronously
  // calls init() -> bootstrap() when document.getElementById('app-root')
  // resolves, so the DOM is fully populated by the time the import settles
  // (bootstrap()/mountShell() are fully synchronous — no further await is
  // needed).
  const shimA = createDomShim();
  const rootA = shimA.document.createElement('div');
  shimA.document.getElementById = (id) => (id === 'app-root' ? rootA : null);
  globalThis.document = shimA.document;
  globalThis.window = shimA.window;
  globalThis.window.location.hash = '';
  globalThis.window.__AGENTIC_SECURITY_EXPORTED_GRAPH__ = flagship;
  await import(path.join(FRONTEND_SRC, 'export-entry.js'));
  const baseline = serialize(rootA);

  // --- Bundled: run bundleFrontendModules() over the real, unmodified
  // export-entry.js, then execute the bundle against a FRESH dom-shim
  // instance with the graph global set first, mirroring exactly what the
  // emitted HTML does (an inline <script> sets
  // window.__AGENTIC_SECURITY_EXPORTED_GRAPH__ before the bundled
  // <script> tag runs). Real, careful sandboxing: the bundled code
  // references bare `document`/`window` as free variables (matching what a
  // real <script> tag in the emitted HTML sees) — constructed via
  // `new Function` with explicit parameters rather than mutating globalThis
  // a second time mid-test.
  const bundled = bundleFrontendModules(path.join(FRONTEND_SRC, 'export-entry.js'));
  // Anchored to true statement position (start of line, no preceding `//`
  // or `*`) rather than a bare \bimport\b/\bexport\b word-boundary check —
  // the real frontend/src/ tree's own prose comments legitimately use both
  // words in English (e.g. this very file's own header talks about
  // "self-contained export"), which a bare word-boundary check would
  // misfire on. Task 1's own bundle-frontend.test.js uses the bare check
  // safely only because its fixtures are comment-free synthetic snippets.
  assert.doesNotMatch(bundled, /^\s*import\b/m, 'sanity: bundled output must contain no remaining import statements');
  assert.doesNotMatch(bundled, /^\s*export\b/m, 'sanity: bundled output must contain no remaining export statements');

  const shimB = createDomShim();
  const rootB = shimB.document.createElement('div');
  shimB.document.getElementById = (id) => (id === 'app-root' ? rootB : null);
  shimB.window.location.hash = '';
  shimB.window.__AGENTIC_SECURITY_EXPORTED_GRAPH__ = flagship;
  const runBundled = new Function('document', 'window', bundled);
  runBundled(shimB.document, shimB.window);
  const bundledResult = serialize(rootB);

  assert.deepEqual(bundledResult, baseline, 'bundled export-entry.js must render a DOM tree structurally identical to the unbundled export-entry.js');

  // Sanity check the comparison isn't vacuously true (an empty tree
  // trivially "matches" an empty tree) — the shell + architecture view must
  // have actually rendered real content on both sides.
  assert.ok(baseline.children.length > 0, 'sanity: the unbundled baseline must have produced real DOM content, not an empty tree');
  assert.ok(bundledResult.children.length > 0, 'sanity: the bundled run must have produced real DOM content, not an empty tree');
});

test('bundle-frontend-golden: bundled export-entry.js shows the error state (not a blank page) when no graph global is present', () => {
  const bundled = bundleFrontendModules(path.join(FRONTEND_SRC, 'export-entry.js'));
  return import(DOM_SHIM_PATH).then(({ createDomShim }) => {
    const shim = createDomShim();
    const root = shim.document.createElement('div');
    shim.document.getElementById = (id) => (id === 'app-root' ? root : null);
    // Deliberately no __AGENTIC_SECURITY_EXPORTED_GRAPH__ set on this window
    // — simulates a corrupted/truncated report file.
    const runBundled = new Function('document', 'window', bundled);
    runBundled(shim.document, shim.window);
    const text = allText(root);
    assert.ok(text.includes('Data Flow Explorer report could not load'), 'expected the bundled error state to render its title');
    assert.ok(text.includes('No embedded graph data found'), 'expected the bundled error state to render its message');
  });
});

function allText(root) {
  const out = [];
  const walk = (node) => {
    for (const c of node.childNodes) {
      if (c.nodeType === 'text') out.push(c.data);
      else walk(c);
    }
  };
  walk(root);
  return out.join(' ');
}
