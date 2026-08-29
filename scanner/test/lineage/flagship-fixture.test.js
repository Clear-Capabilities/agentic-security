import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { validateGraph } from '../../src/lineage/validate.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const builderPath = path.join(__dirname, '../../src/lineage/fixtures/build-flagship-fixture.mjs');

function loadFixture() {
  return JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
}

test('flagship-graph.json exists and is valid JSON', () => {
  assert.ok(fs.existsSync(fixturePath));
  assert.doesNotThrow(() => loadFixture());
});

test('flagship fixture passes validateGraph with zero errors', () => {
  const result = validateGraph(loadFixture());
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
});

test('flagship fixture is marked as a fixture, not scan output (Appendix D.1)', () => {
  const graph = loadFixture();
  assert.equal(graph.scope.source, 'fixture');
});

test('re-running the builder produces byte-identical output (determinism, AC-14)', () => {
  const before = fs.readFileSync(fixturePath, 'utf8');
  execFileSync('node', [builderPath], { cwd: path.join(__dirname, '../..') });
  const after = fs.readFileSync(fixturePath, 'utf8');
  assert.equal(before, after, 'builder output drifted — regenerate is not idempotent');
});

test('all 13 Appendix D.2 reference nodes are present by stable fixture key', () => {
  const graph = loadFixture();
  const keys = graph.extensions.fixtureNodeKeys;
  for (const key of [
    'node.web', 'node.gateway', 'node.payments', 'node.ai', 'node.postgres',
    'node.logs', 'node.payment_api', 'node.analytics', 'node.model', 'node.vector',
    'node.unresolved', 'node.retention', 'node.deletion',
  ]) {
    assert.ok(keys[key], `missing fixture node key ${key}`);
    assert.ok(graph.nodes.some((n) => n.id === keys[key]), `node id for ${key} not in graph.nodes`);
  }
});

test('all 8 Appendix D.3 reference flows are present by stable fixture key', () => {
  const graph = loadFixture();
  const keys = graph.extensions.fixtureFlowKeys;
  for (const key of [
    'flow.pci.masked_log', 'flow.pci.raw_log', 'flow.pci.database', 'flow.pci.payment_api',
    'flow.pci.ai', 'flow.phi.ai', 'flow.pii.analytics', 'flow.pii.unresolved',
  ]) {
    assert.ok(keys[key], `missing fixture flow key ${key}`);
    assert.ok(graph.flows.some((f) => f.id === keys[key]), `flow id for ${key} not in graph.flows`);
  }
});
