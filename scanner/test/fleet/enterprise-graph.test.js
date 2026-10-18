// The enterprise graph (PRD 4 requirements 6 to 9): manifest metadata, federated edges that keep their evidence, cross-repository
// attack paths, shared-component blast radius, and the one fixed question shape the CLI recognises.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { validateFleetManifest } from '../../src/posture/fleet/fleet-manifest.js';
import { buildFleetDependencyGraph } from '../../src/posture/fleet/fleet-graph.js';
import { buildEnterpriseGraph, finalizeGraph, validateEnterpriseGraph, attackPaths, vulnerableSet, componentBlastRadius, renderBlastRadius, INTERNET } from '../../src/posture/fleet/enterprise-graph.js';
import { parseFleetQuestion } from '../../src/posture/fleet/cli.js';

function org() {
  const base = mkTestTmp('fleet-ent-');
  const repo = (id, name, deps) => { const d = path.join(base, id); fs.mkdirSync(d); fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name, version: '1.0.0', dependencies: deps })); return d; };
  repo('auth-library', '@acme/auth-library', {});
  repo('frontend', '@acme/frontend', { '@acme/auth-library': 'github:acme/auth-library#abc123' });
  repo('payments-api', '@acme/payments-api', { '@acme/auth-library': '^1.2.0' });
  repo('payments-worker', '@acme/payments-worker', { '@acme/auth-library': 'github:acme/auth-library#def456' });
  repo('reports', '@acme/reports', { '@acme/payments-api': '^1.0.0' });
  repo('admin-tool', '@acme/admin-tool', {});
  return base;
}
const doc = {
  organization: 'acme',
  resources: [
    { id: 'api-gateway', kind: 'gateway', internetFacing: true, environment: 'production' },
    { id: 'kafka', kind: 'queue', environment: 'production' },
    { id: 'card-db', kind: 'database', dataClasses: ['pci'], environment: 'production', trustZone: 'cardholder' },
    { id: 'stripe', kind: 'external-provider' },
  ],
  repositories: [
    { id: 'frontend', path: './frontend', kind: 'frontend', internetFacing: true, environment: 'production', calls: ['api-gateway', 'payments-api'] },
    { id: 'payments-api', path: './payments-api', kind: 'service', environment: 'production', dataClasses: ['pci'], produces: ['kafka'], providers: ['stripe'] },
    { id: 'payments-worker', path: './payments-worker', kind: 'worker', environment: 'production', dataClasses: ['pci'], consumes: ['kafka'], writes: ['card-db'] },
    { id: 'auth-library', path: './auth-library', kind: 'library' },
    { id: 'reports', path: './reports', kind: 'service', environment: 'staging', reads: ['card-db'] },
    { id: 'admin-tool', path: './admin-tool', kind: 'service', environment: 'production', internetFacing: false },
  ],
};
const build = () => {
  const base = org();
  const v = validateFleetManifest(structuredClone(doc), { baseDir: base });
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  return { base, manifest: v.manifest, graph: finalizeGraph(buildEnterpriseGraph({ manifest: v.manifest, dependencyGraph: buildFleetDependencyGraph(v.manifest.repositories) })) };
};

test('manifest: per-repository metadata and resources are validated closed-world, references must resolve and fit', () => {
  const base = org();
  const bad = (mutate, re) => { const d = structuredClone(doc); mutate(d); const v = validateFleetManifest(d, { baseDir: base }); assert.equal(v.ok, false); assert.match(v.errors.join('|'), re); };
  bad((d) => { d.repositories[0].calls = ['nowhere']; }, /neither a repository nor a resource/);
  bad((d) => { d.repositories[0].produces = ['card-db']; }, /cannot point at card-db \(a database\)/);
  bad((d) => { d.repositories[1].reads = ['kafka']; }, /cannot point at kafka \(a queue\)/);
  bad((d) => { d.repositories[0].internetFacing = 'yes'; }, /true or false/);
  bad((d) => { d.repositories[0].kind = 'mainframe'; }, /kind must be one of/);
  bad((d) => { d.repositories[0].secret = 'x'; }, /unknown key secret/);
  bad((d) => { d.resources[0].password = 'x'; }, /unknown key password/);
  bad((d) => { d.resources[1].id = 'frontend'; }, /collides/);
  bad((d) => { d.resources[2].dataClasses = ['PCI data']; }, /data class names/);
  bad((d) => { d.retries = 9; }, /retries/);
  bad((d) => { d.repositories[0].environment = 'prod'; }, /environment must be one of/);
  const ok = validateFleetManifest(structuredClone(doc), { baseDir: base });
  assert.equal(ok.manifest.repositories.find((r) => r.id === 'auth-library').required, true);
  assert.equal(ok.manifest.retries, 1);
  const optional = structuredClone(doc); optional.repositories[5].required = false;
  assert.equal(validateFleetManifest(optional, { baseDir: base }).manifest.repositories[5].required, false);
});

test('graph: every edge is traceable to evidence, reach and dependency edges are kept apart', () => {
  const { graph } = build();
  assert.deepEqual(validateEnterpriseGraph(graph), []);
  assert.ok(graph.edges.length > 10);
  for (const e of graph.edges) assert.ok(e.evidence.length && e.evidence.every((x) => typeof x.source === 'string'), e.id);
  const dep = graph.edges.find((e) => e.type === 'depends-on' && e.from === 'frontend');
  assert.equal(dep.reach, false);
  assert.deepEqual(dep.evidence[0], { source: 'package-manifest', repo: 'frontend', file: 'package.json', declared: '@acme/auth-library', spec: 'github:acme/auth-library#abc123' });
  const calls = graph.edges.find((e) => e.id === 'edge:calls:frontend:payments-api');
  assert.equal(calls.reach, true); assert.equal(calls.evidence[0].source, 'fleet-manifest'); assert.equal(calls.evidence[0].field, 'calls');
  assert.equal(graph.edges.find((e) => e.id === 'edge:exposes:internet:api-gateway').evidence[0].field, 'internetFacing');
  assert.ok(graph.digest);
  assert.equal(validateEnterpriseGraph({ nodes: [{ id: 'a' }], edges: [{ id: 'x', from: 'a', to: 'b', evidence: [] }] }).length, 2, 'an edge with no evidence and a dangling endpoint are both reported');
});

test('attack paths: the PRD chain from the Internet to a card database, hop by hop, each hop with its evidence', () => {
  const { graph } = build();
  const res = attackPaths({ graph, toDataClass: 'pci' });
  const chains = res.paths.map((p) => p.nodes.join(' > '));
  assert.ok(chains.includes('internet > frontend > payments-api'), chains.join('\n'));
  assert.ok(chains.includes('internet > frontend > payments-api > kafka > payments-worker'));
  assert.ok(chains.includes('internet > frontend > payments-api > kafka > payments-worker > card-db'));
  assert.ok(!chains.some((c) => c.includes('admin-tool')), 'a service nothing exposes is not on any path');
  const full = res.paths.find((p) => p.nodes.join('>') === 'internet>frontend>payments-api>kafka>payments-worker>card-db');
  assert.deepEqual(full.edges, ['edge:exposes:internet:frontend', 'edge:calls:frontend:payments-api', 'edge:produces:payments-api:kafka', 'edge:consumes:kafka:payments-worker', 'edge:writes:payments-worker:card-db']);
  assert.ok(full.evidence.every((x) => x.source === 'fleet-manifest' && x.edge));
  assert.equal(res.truncated, false);
});

test('attack paths: a path needs a declared way in; with nothing Internet-facing there are none', () => {
  const d = structuredClone(doc); d.repositories[0].internetFacing = false; d.resources[0].internetFacing = false;
  const base = org(); const v = validateFleetManifest(d, { baseDir: base });
  const g = finalizeGraph(buildEnterpriseGraph({ manifest: v.manifest, dependencyGraph: buildFleetDependencyGraph(v.manifest.repositories) }));
  assert.equal(attackPaths({ graph: g, toDataClass: 'pci' }).paths.length, 0);
  assert.equal(attackPaths({ graph: g, toDataClass: 'pii' }).targets.length, 0, 'no node holds pii, so there is nothing to reach');
});

test('attack paths: depth and count bounds are enforced and disclosed', () => {
  const { graph } = build();
  const shallow = attackPaths({ graph, toDataClass: 'pci', maxDepth: 2 });
  assert.equal(shallow.truncated, true); assert.ok(shallow.paths.every((p) => p.nodes.length <= 4));
  const few = attackPaths({ graph, toDataClass: 'pci', maxPaths: 1 });
  assert.equal(few.paths.length, 1); assert.equal(few.truncated, true);
});

test('"involving vulnerable authentication code": the flaw in the shared library reaches every dependent, and only paths through them count', () => {
  const { graph } = build();
  const findingsByRepo = new Map([['auth-library', [{ id: 'F1', cwe: 'CWE-306', family: 'missing-auth', file: 'index.js', line: 3 }]], ['reports', [{ id: 'F2', cwe: 'CWE-79', family: 'xss' }]]]);
  const set = vulnerableSet({ graph, findingsByRepo, selector: { family: 'auth' } });
  assert.deepEqual([...set.direct], ['auth-library']);
  assert.deepEqual([...set.all].sort(), ['auth-library', 'frontend', 'payments-api', 'payments-worker', 'reports'], 'reports depends on payments-api which depends on the library');
  assert.match(set.why.get('payments-api'), /depends on auth-library/); assert.match(set.why.get('auth-library'), /CWE-306/);
  const res = attackPaths({ graph, toDataClass: 'pci', involving: set });
  assert.ok(res.paths.length > 0);
  assert.ok(res.paths.every((p) => p.involving.length > 0 && p.involving.every((n) => set.all.has(n))));
  const none = attackPaths({ graph, toDataClass: 'pci', involving: vulnerableSet({ graph, findingsByRepo: new Map([['auth-library', [{ cwe: 'CWE-79' }]]]), selector: { family: 'auth' } }) });
  assert.equal(none.paths.length, 0, 'an unrelated flaw does not make a path "involve vulnerable authentication code"');
  const named = vulnerableSet({ graph, findingsByRepo: new Map(), selector: { repo: 'auth-library' } });
  assert.ok(named.all.has('frontend'));
});

test('shared-component blast radius: counts of repositories, Internet-facing, production and PCI-scoped, with version awareness', () => {
  const { graph } = build();
  const r = componentBlastRadius({ graph, component: 'auth-library' });
  assert.deepEqual(r.dependents.map((d) => [d.id, d.depth]), [['frontend', 1], ['payments-api', 1], ['payments-worker', 1], ['reports', 2]]);
  assert.equal(r.counts.repositories, 4); assert.equal(r.counts.internetFacing, 1); assert.equal(r.counts.production, 3); assert.equal(r.counts.byDataClass.pci, 2);
  const text = renderBlastRadius(r);
  assert.match(text, /^auth-library\n\nUsed by:\n4 repositories\n1 Internet-facing service\n3 production apps\n2 PCI-scoped services/);
  const pinned = componentBlastRadius({ graph, component: 'auth-library', version: 'abc123' });
  assert.deepEqual(pinned.dependents.filter((d) => d.versionMatch === 'matched').map((d) => d.id), ['frontend']);
  assert.deepEqual(pinned.excludedByVersion.sort(), ['payments-api', 'payments-worker'].sort(), 'a pin that does not name this version is excluded, and a semver range cannot be said to');
  assert.equal(pinned.counts.repositories, 1, 'reports is only reached through payments-api, which was ruled out, so it is not counted either');
  assert.ok(!pinned.dependents.some((d) => d.id === 'reports'));
  assert.equal(componentBlastRadius({ graph, component: 'nope' }), null);
});

test('one question shape is recognised and anything else is refused, not guessed at', () => {
  assert.deepEqual(parseFleetQuestion('Show every Internet-facing path to PCI data involving vulnerable authentication code'), { toDataClass: 'pci', involving: { family: 'auth' } });
  assert.deepEqual(parseFleetQuestion('show every internet-facing path to pii data.'), { toDataClass: 'pii', involving: null });
  assert.deepEqual(parseFleetQuestion('Show every Internet-facing path to PCI data involving vulnerable injection component'), { toDataClass: 'pci', involving: { family: 'injection' } });
  for (const s of ['what is the weather', 'Show every path to PCI data', 'Show every Internet-facing path to PCI data; do something else', '', null]) assert.equal(parseFleetQuestion(s), null, String(s));
  assert.equal(INTERNET, 'internet');
});
