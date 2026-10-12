import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readRepoManifest, buildFleetDependencyGraph, blastRadius } from '../../src/posture/fleet/fleet-graph.js';

function mkRepo(dir, manifestFile, content) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, manifestFile), content);
}

test('readRepoManifest: package.json name + dependencies', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fg-'));
  mkRepo(dir, 'package.json', JSON.stringify({ name: '@acme/lib', dependencies: { express: '^4.0.0' } }));
  const m = readRepoManifest(dir);
  assert.equal(m.name, '@acme/lib');
  assert.ok(m.deps.has('express'));
});

test('readRepoManifest: go.mod module + require block', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fg-'));
  fs.writeFileSync(path.join(dir, 'go.mod'), 'module github.com/acme/svc\n\nrequire (\n\tgithub.com/acme/authlib v1.0.0\n)\n');
  const m = readRepoManifest(dir);
  assert.equal(m.name, 'github.com/acme/svc');
  assert.ok(m.deps.has('github.com/acme/authlib'));
});

test('readRepoManifest: no manifest at all yields no name and no deps, never throws', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fg-'));
  const m = readRepoManifest(dir);
  assert.equal(m.name, null);
  assert.equal(m.deps.size, 0);
});

test('buildFleetDependencyGraph + blastRadius: the PRD test-org scenario (direct and transitive)', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'fg-org-'));
  const repos = [
    { id: 'frontend', name: '@acme/frontend', deps: { '@acme/shared-auth-lib': '^1.0.0' } },
    { id: 'payments-api', name: '@acme/payments-api', deps: { '@acme/shared-auth-lib': '^1.0.0' } },
    { id: 'shared-auth-lib', name: '@acme/shared-auth-lib', deps: {} },
    { id: 'payments-worker', name: '@acme/payments-worker', deps: { '@acme/payments-api': '^1.0.0' } },
  ];
  const repoList = repos.map((r) => {
    const dir = path.join(base, r.id);
    mkRepo(dir, 'package.json', JSON.stringify({ name: r.name, dependencies: r.deps }));
    return { id: r.id, path: dir };
  });
  const graph = buildFleetDependencyGraph(repoList);
  assert.equal(graph.nodes.length, 4);
  assert.ok(graph.edges.some((e) => e.from === 'frontend' && e.to === 'shared-auth-lib'));
  assert.ok(graph.edges.some((e) => e.from === 'payments-worker' && e.to === 'payments-api'));
  assert.ok(!graph.edges.some((e) => e.from === 'payments-worker' && e.to === 'shared-auth-lib'), 'no direct edge; the dependency is transitive');

  const radius = blastRadius(graph, 'shared-auth-lib');
  const ids = radius.map((r) => r.id);
  assert.deepEqual([...ids].sort(), ['frontend', 'payments-api', 'payments-worker']);
  const worker = radius.find((r) => r.id === 'payments-worker');
  assert.equal(worker.depth, 2);
  assert.deepEqual(worker.path, ['shared-auth-lib', 'payments-api', 'payments-worker']);
  const direct = radius.find((r) => r.id === 'frontend');
  assert.equal(direct.depth, 1);
});

test('blastRadius of a leaf with no dependents is empty', () => {
  const graph = { nodes: [{ id: 'a' }, { id: 'b' }], edges: [{ from: 'a', to: 'b' }] };
  assert.deepEqual(blastRadius(graph, 'a'), []);
});

test('two repos sharing a declared name are both treated as the target (disclosed limit, not silently merged)', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'fg-dup-'));
  mkRepo(path.join(base, 'a'), 'package.json', JSON.stringify({ name: 'shared', dependencies: {} }));
  mkRepo(path.join(base, 'b'), 'package.json', JSON.stringify({ name: 'shared', dependencies: {} }));
  mkRepo(path.join(base, 'c'), 'package.json', JSON.stringify({ name: 'c', dependencies: { shared: '^1' } }));
  const graph = buildFleetDependencyGraph([{ id: 'a', path: path.join(base, 'a') }, { id: 'b', path: path.join(base, 'b') }, { id: 'c', path: path.join(base, 'c') }]);
  assert.ok(graph.edges.some((e) => e.from === 'c' && e.to === 'a'));
  assert.ok(graph.edges.some((e) => e.from === 'c' && e.to === 'b'));
});
