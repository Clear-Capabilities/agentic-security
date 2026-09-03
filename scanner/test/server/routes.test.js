import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { handleScan, handleGraph, handleNode, handleEdge, handleFlow, handleQuery, wrapResponse } from '../../src/server/routes.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// The committed flagship reference fixture — small, real, and already used
// elsewhere in this repo's own test suite. Deliberately NOT the 5,000-node
// perf fixture (this is correctness testing, not scale testing).
const FIXTURE_PATH = path.join(__dirname, '..', '..', 'src', 'lineage', 'fixtures', 'flagship-graph.json');
const graph = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));

test('handleScan: metadata only (no node/edge arrays), envelope fields present', () => {
  const { status, body } = handleScan(graph);
  assert.equal(status, 200);
  assert.equal(body.digest, graph.graphId);
  assert.equal(body.schemaVersion, graph.schemaVersion);
  assert.deepEqual(body.extensions, graph.extensions);
  assert.deepEqual(body.scope, graph.scope);
  assert.deepEqual(body.coverage, graph.coverage);
  assert.deepEqual(body.limitations, graph.limitations);
  assert.equal(body.canonicalIds, null);
  assert.equal(body.data.graphId, graph.graphId);
  assert.equal(body.data.generatedAt, graph.generatedAt);
  assert.ok(!('nodes' in body.data), 'handleScan must not include the full nodes array');
  assert.ok(!('edges' in body.data), 'handleScan must not include the full edges array');
});

test('handleGraph: the full graph document, wrapped in the envelope', () => {
  const { status, body } = handleGraph(graph);
  assert.equal(status, 200);
  assert.equal(body.digest, graph.graphId);
  assert.equal(body.canonicalIds, null, 'the whole graph IS the canonical id set — see routes.js header comment');
  assert.deepEqual(body.data.nodes, graph.nodes);
  assert.deepEqual(body.data.edges, graph.edges);
  assert.deepEqual(body.data.flows, graph.flows);
});

test('handleQuery: valid filter narrows the graph via _filterGraph, same envelope as handleGraph', () => {
  const targetNode = graph.nodes[0];
  const { status, body } = handleQuery(graph, { nodeIds: [targetNode.id], edgeIds: [] });
  assert.equal(status, 200);
  assert.equal(body.digest, graph.graphId);
  assert.equal(body.canonicalIds, null);
  assert.deepEqual(body.data.nodes, [targetNode]);
  assert.equal(body.data.edges.length, 0);
});

test('handleQuery: an OMITTED filter (undefined) returns the whole graph, same as handleGraph', () => {
  const { status, body } = handleQuery(graph, undefined);
  assert.equal(status, 200);
  assert.deepEqual(body.data.nodes, graph.nodes);
});

// Final whole-branch review finding: {} is NOT the same as omitting the
// filter — _filterGraph treats an empty (but well-formed) filter object as
// "narrow to nothing," not "no restriction." A prior version of this test
// file was misleadingly TITLED "undefined/empty filter" but never actually
// exercised {}, which is exactly why this real behavior went unproven.
test('handleQuery: an EMPTY filter object ({}) narrows to an EMPTY graph — NOT the same as omitting the filter', () => {
  const { status, body } = handleQuery(graph, {});
  assert.equal(status, 200);
  assert.equal(body.data.nodes.length, 0);
  assert.equal(body.data.edges.length, 0);
  assert.equal(body.data.flows.length, 0);
  assert.equal(body.data.dataElements.length, 0);
});

test('handleQuery: malformed filter -> 400 with a clear message, never throws', () => {
  const { status, body } = handleQuery(graph, { nodeIds: 'not-an-array' });
  assert.equal(status, 400);
  assert.match(body.error, /must be a JSON object/);
});

test('handleNode: found -> 200 with the node and its own id as canonicalIds', () => {
  const target = graph.nodes[0];
  const { status, body } = handleNode(graph, target.id);
  assert.equal(status, 200);
  assert.deepEqual(body.data, target);
  assert.deepEqual(body.canonicalIds, [target.id]);
  // Envelope fields still present on an entity response.
  assert.equal(body.digest, graph.graphId);
  assert.deepEqual(body.coverage, graph.coverage);
});

test('handleNode: not found -> 404 with a clear body', () => {
  const { status, body } = handleNode(graph, 'node:does-not-exist');
  assert.equal(status, 404);
  assert.match(body.data.error, /not found/i);
  assert.deepEqual(body.canonicalIds, []);
});

test('handleEdge: found and not-found', () => {
  const target = graph.edges[0];
  const ok = handleEdge(graph, target.id);
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body.data, target);
  assert.deepEqual(ok.body.canonicalIds, [target.id]);

  const missing = handleEdge(graph, 'edge:does-not-exist');
  assert.equal(missing.status, 404);
  assert.match(missing.body.data.error, /not found/i);
});

test('handleFlow: found -> canonicalIds include the flow id plus its source/sink/edgeIds', () => {
  const flow = graph.flows[0];
  const { status, body } = handleFlow(graph, flow.id);
  assert.equal(status, 200);
  assert.deepEqual(body.data, flow);
  assert.ok(body.canonicalIds.includes(flow.id));
  assert.ok(body.canonicalIds.includes(flow.source));
  assert.ok(body.canonicalIds.includes(flow.sink));
  for (const eid of flow.edgeIds || []) assert.ok(body.canonicalIds.includes(eid));
  // No duplicates.
  assert.equal(new Set(body.canonicalIds).size, body.canonicalIds.length);
});

test('handleFlow: not found -> 404', () => {
  const { status, body } = handleFlow(graph, 'flow:does-not-exist');
  assert.equal(status, 404);
  assert.deepEqual(body.canonicalIds, []);
});

test('wrapResponse: degrades gracefully on a null/undefined graph rather than throwing', () => {
  assert.doesNotThrow(() => wrapResponse({ a: 1 }, null));
  const body = wrapResponse({ a: 1 }, null);
  assert.equal(body.digest, null);
  assert.equal(body.schemaVersion, null);
  assert.deepEqual(body.extensions, {});
  assert.equal(body.scope, null);
  assert.equal(body.coverage, null);
  assert.deepEqual(body.limitations, []);
  assert.equal(body.canonicalIds, null);
  assert.deepEqual(body.data, { a: 1 });
});
