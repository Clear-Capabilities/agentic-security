// AC-16 byte-for-byte equivalence proof — the M3-Wire plan's own "single
// most important test in this increment" (Decision 4 of the scoping doc).
//
// Starts a REAL `explore` server (scanner/src/server/http-server.js) over
// the REAL flagship-graph.json fixture, fetches it through the REAL
// api-client.js over a REAL loopback HTTP connection (Node's own global
// fetch — no mock anywhere in this file), and asserts that rendering the
// LIVE-fetched graph through bootstrap() produces a DOM tree structurally
// IDENTICAL to rendering the existing static-import baseline
// (FLAGSHIP_GRAPH, from src/data/flagship-graph.js) through the same
// bootstrap(). This is the proof that swapping WHERE the frontend gets its
// data changed nothing about WHAT gets rendered.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDomShim } from './dom-shim.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const FIXTURE_PATH = path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'fixtures', 'flagship-graph.json');

const { createExploreServer } = await import(path.join(REPO_ROOT, 'scanner', 'src', 'server', 'http-server.js'));
const { generateSessionToken } = await import(path.join(REPO_ROOT, 'scanner', 'src', 'server', 'security.js'));

const { FLAGSHIP_GRAPH } = await import('../src/data/flagship-graph.js');
const { fetchGraph } = await import('../src/lib/api-client.js');
const { bootstrap } = await import('../src/app.js');

/**
 * Serializes a dom-shim node tree into a plain, deep-comparable structure —
 * tag, namespace, attributes, and children — so two independently-mounted
 * trees can be compared with assert.deepEqual without caring about object
 * identity or event-listener closures (which legitimately differ between
 * two separate mounts and must NOT be part of the comparison).
 */
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

test('AC-16: the SAME flagship graph renders IDENTICALLY via the live fetch path and the static-import baseline', async (t) => {
  // 1. Start a REAL explore server over the REAL flagship graph fixture —
  // the same fixture file scanner/test/server/http-server.test.js itself
  // uses, and the same one test/fixture-module-parity.test.js already
  // proves is byte-identical to FLAGSHIP_GRAPH.
  const graph = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));
  const sessionToken = generateSessionToken();
  const { server, port } = await createExploreServer({
    graph,
    port: 0,
    sessionToken,
    idleTimeoutMs: 5 * 60 * 1000,
    keepOpen: false,
  });
  t.after(() => server.close());

  // 2. Fetch it through the REAL api-client.js, over a REAL loopback HTTP
  // connection (global fetch — Node >= 24 ships it, no mock).
  const liveGraph = await fetchGraph({ token: sessionToken, baseUrl: `http://127.0.0.1:${port}` });

  // 3. Confirm the live-fetched graph is content-identical to the static
  // import baseline BEFORE even getting to rendering — if this fails, a
  // rendering-level pass would not be a meaningful comparison.
  assert.deepEqual(liveGraph, FLAGSHIP_GRAPH, 'the live-fetched graph must be byte-for-byte identical to the static-import baseline');

  // 4. Render BOTH through the SAME, UNCHANGED bootstrap() call, using two
  // independent dom-shim instances so mounting one never leaks DOM/window
  // state into the other.
  const shimA = createDomShim();
  globalThis.document = shimA.document;
  globalThis.window = shimA.window;
  globalThis.window.location.hash = '';
  const rootLive = shimA.document.createElement('div');
  bootstrap(rootLive, liveGraph);

  const shimB = createDomShim();
  globalThis.document = shimB.document;
  globalThis.window = shimB.window;
  globalThis.window.location.hash = '';
  const rootStatic = shimB.document.createElement('div');
  bootstrap(rootStatic, FLAGSHIP_GRAPH);

  // 5. Assert the two rendered DOM trees are structurally identical.
  const serializedLive = serialize(rootLive);
  const serializedStatic = serialize(rootStatic);
  assert.deepEqual(serializedLive, serializedStatic, 'rendering the live-fetched graph must produce a DOM tree identical to rendering the static-import baseline');

  // Sanity check the comparison itself isn't vacuously true (an empty tree
  // trivially "matches" an empty tree) — the shell + architecture view
  // must have actually rendered real content.
  assert.ok(serializedLive.children.length > 0, 'the live-fetched render must have produced real DOM content, not an empty tree');
});
