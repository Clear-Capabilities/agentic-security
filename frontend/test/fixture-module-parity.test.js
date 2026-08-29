import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const BACKEND_FIXTURE_PATH = path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'fixtures', 'flagship-graph.json');
const FRONTEND_MODULE_PATH = path.join(HERE, '..', 'src', 'data', 'flagship-graph.js');

test('frontend/src/data/flagship-graph.js exists and is importable', async () => {
  assert.ok(fs.existsSync(FRONTEND_MODULE_PATH), 'run `node scripts/generate-fixture-module.mjs` first');
  const mod = await import(FRONTEND_MODULE_PATH);
  assert.ok(mod.FLAGSHIP_GRAPH, 'expected a named export FLAGSHIP_GRAPH');
});

test('the embedded copy is byte-identical in content to the real backend fixture', async () => {
  const backend = JSON.parse(fs.readFileSync(BACKEND_FIXTURE_PATH, 'utf8'));
  const mod = await import(FRONTEND_MODULE_PATH);
  assert.deepEqual(mod.FLAGSHIP_GRAPH, backend);
});

test('the embedded copy passes the REAL validateGraph() with zero errors', async () => {
  const { validateGraph } = await import(path.join(REPO_ROOT, 'scanner', 'src', 'lineage', 'validate.js'));
  const mod = await import(FRONTEND_MODULE_PATH);
  const result = validateGraph(mod.FLAGSHIP_GRAPH);
  assert.equal(result.valid, true, JSON.stringify(result.errors, null, 2));
  assert.deepEqual(result.errors, []);
});

test('extensions.fixtureNodeKeys and fixtureFlowKeys resolve to real ids in the embedded copy', async () => {
  const mod = await import(FRONTEND_MODULE_PATH);
  const graph = mod.FLAGSHIP_GRAPH;
  const nodeIds = new Set(graph.nodes.map((n) => n.id));
  const flowIds = new Set(graph.flows.map((f) => f.id));
  for (const [key, id] of Object.entries(graph.extensions.fixtureNodeKeys ?? {})) {
    assert.ok(nodeIds.has(id), `fixtureNodeKeys.${key} -> ${id} does not resolve to a real node`);
  }
  for (const [key, id] of Object.entries(graph.extensions.fixtureFlowKeys ?? {})) {
    assert.ok(flowIds.has(id), `fixtureFlowKeys.${key} -> ${id} does not resolve to a real flow`);
  }
});
