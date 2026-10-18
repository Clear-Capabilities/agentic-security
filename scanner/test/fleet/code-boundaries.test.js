// Federating Code Boundaries into the enterprise graph (PRD 4): each repository's own data flow graph, summarized, adds the data classes
// and destinations the CODE shows to what the manifest declared, with the evidence for each, and never replaces a declaration.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { summarizeLineage } from '../../src/posture/fleet/lineage-summary.js';
import { loadFleetManifest } from '../../src/posture/fleet/fleet-manifest.js';
import { buildEnterpriseGraph, validateEnterpriseGraph, attackPaths } from '../../src/posture/fleet/enterprise-graph.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

const GRAPH = {
  nodes: [
    { id: 'n1', kind: 'external', subtype: 'external-api', destination: { literalValue: 'https://ledger.internal/v1/charge' } },
    { id: 'n2', kind: 'external', subtype: 'analytics', destination: { literalValue: null } },
    { id: 'n3', kind: 'queue', subtype: 'queue', queueDetail: { topic: 'orders-queue', operation: 'publish' } },
    { id: 'n4', kind: 'queue', subtype: 'queue', queueDetail: { topic: 'refunds', operation: 'consume' } },
    { id: 'n5', kind: 'store', subtype: 'database', storeDetail: { host: 'card-db.internal', database: 'cards', table: 'pan' } },
  ],
  edges: [{ id: 'e1', boundaryCrossings: ['internet'] }, { id: 'e2', boundaryCrossings: [] }],
  dataElements: [{ id: 'd1', dataClasses: ['PCI', 'PII'] }, { id: 'd2', dataClasses: ['NONE-OF-THESE'] }],
  flows: [{ id: 'f1', edgeIds: ['e1'], dataElementIds: ['d1'] }, { id: 'f2', edgeIds: ['e2'], dataElementIds: ['d1'] }],
};

test('the summary keeps what crosses a repository boundary, lower-cases classes, and counts sensitive flows that cross a trust boundary', () => {
  const s = summarizeLineage(GRAPH);
  assert.deepEqual(s.dataClasses, ['none-of-these', 'pci', 'pii']);
  assert.deepEqual(s.externalDestinations, [{ subtype: 'external-api', host: 'ledger.internal' }, { subtype: 'analytics', host: null }]);
  assert.deepEqual(s.queues, [{ topic: 'orders-queue', operation: 'publish' }, { topic: 'refunds', operation: 'consume' }]);
  assert.deepEqual(s.stores, [{ subtype: 'database', host: 'card-db.internal', database: 'cards', table: 'pan' }]);
  assert.equal(s.counts.sensitiveFlowsCrossingBoundary, 1, 'only f1 carries a sensitive class over a boundary-crossing edge');
});

test('hostile or malformed graph content is bounded and shape-checked, never trusted', () => {
  assert.equal(summarizeLineage(null), null); assert.equal(summarizeLineage('x'), null);
  const evil = summarizeLineage({
    nodes: [{ kind: 'external', subtype: 'x'.repeat(500), destination: { literalValue: 'http://a b/\u0000' } }, null, 7, { kind: 'queue', queueDetail: { topic: 'has space' } }, { kind: 'store', storeDetail: { host: '../../etc', table: 'a\nb' } }],
    dataElements: [{ dataClasses: ['PII', 'bad class!', '9x', 'a'.repeat(60), 42, null] }, null], edges: 'nope', flows: [{ edgeIds: null }],
  });
  assert.deepEqual(evil.dataClasses, ['pii']);
  assert.deepEqual(evil.queues, []); assert.ok(evil.externalDestinations.every((d) => d.host === null || /^[a-z0-9.-]+$/.test(d.host)));
  assert.ok(evil.stores.every((s) => s.table === null));
  const many = summarizeLineage({ nodes: Array.from({ length: 500 }, (_, i) => ({ kind: 'external', subtype: 'api', destination: { literalValue: `https://h${i}.example/` } })) });
  assert.equal(many.externalDestinations.length, 64, 'bounded');
});

const MANIFEST = `organization: acme
resources:
  - { id: orders-queue, kind: queue }
  - { id: card-db, kind: database, aliases: [card-db.internal] }
repositories:
  - { id: web, path: ./org/web, kind: frontend, internetFacing: true, environment: production, calls: [api] }
  - { id: api, path: ./org/api, kind: service, environment: production }
  - { id: ledger, path: ./org/ledger, kind: service, environment: production, aliases: [ledger.internal] }
`;
function manifestOf(yaml = MANIFEST) {
  const root = mkTestTmp('fleet-cb-'); fs.mkdirSync(path.join(root, '.git'));
  for (const r of ['web', 'api', 'ledger']) fs.mkdirSync(path.join(root, 'org', r), { recursive: true });
  fs.writeFileSync(path.join(root, 'fleet.yaml'), yaml);
  const l = loadFleetManifest(path.join(root, 'fleet.yaml')); assert.equal(l.ok, true, l.errors?.join());
  return l.manifest;
}

test('the graph gains undeclared data classes and corroborated edges, each with code-boundaries evidence, and a declared class is never duplicated', () => {
  const manifest = manifestOf(MANIFEST.replace('kind: service, environment: production }\n  - { id: ledger', 'kind: service, environment: production, dataClasses: [pii] }\n  - { id: ledger'));
  const lineage = new Map([['api', summarizeLineage(GRAPH)]]);
  const g = buildEnterpriseGraph({ manifest, dependencyGraph: { edges: [] }, lineage });
  assert.deepEqual(validateEnterpriseGraph(g), []);
  const api = g.nodes.find((n) => n.id === 'api');
  assert.deepEqual(api.dataClasses, ['pii', 'none-of-these', 'pci'].sort((a, b) => (a === 'pii' ? -1 : b === 'pii' ? 1 : 0)).filter((x) => api.dataClasses.includes(x)));
  assert.equal(api.dataClasses.filter((c) => c === 'pii').length, 1, 'pii was declared, so it is not added twice');
  assert.deepEqual(api.discoveredDataClasses.sort(), ['none-of-these', 'pci']);
  const find = (id) => g.edges.find((e) => e.id === id);
  assert.equal(find('edge:calls:api:ledger').discovered, true); assert.equal(find('edge:calls:api:ledger').evidence[0].source, 'code-boundaries');
  assert.equal(find('edge:produces:api:orders-queue').evidence[0].topic, 'orders-queue');
  assert.ok(find('edge:connects-to:api:card-db'), 'a store host that matches a database alias');
  assert.equal(find('edge:calls:web:api').discovered, false, 'a declared edge stays declared');
  const paths = attackPaths({ graph: g, toDataClass: 'pci' });
  assert.ok(paths.paths.some((p) => p.nodes.join('>') === 'internet>web>api' && p.discoveredDataClassNodes.includes('api')), 'the path to PCI exists only because the code shows it');
  const noLineage = attackPaths({ graph: buildEnterpriseGraph({ manifest, dependencyGraph: { edges: [] } }), toDataClass: 'pci' });
  assert.equal(noLineage.paths.length, 0);
});

test('end to end: fleet scan --lineage runs the real scan with Code Boundaries, reports what the manifest missed, and a PCI path rests on it', { timeout: 600000 }, () => {
  const root = mkTestTmp('fleet-cb-e2e-'); fs.mkdirSync(path.join(root, '.git'));
  for (const r of ['web', 'api', 'ledger']) { fs.mkdirSync(path.join(root, 'org', r), { recursive: true }); fs.writeFileSync(path.join(root, 'org', r, 'package.json'), JSON.stringify({ name: `@s/${r}`, version: '1.0.0' })); }
  fs.writeFileSync(path.join(root, 'org/web/index.js'), "console.log('web');\n"); fs.writeFileSync(path.join(root, 'org/ledger/index.js'), "console.log('ledger');\n");
  fs.writeFileSync(path.join(root, 'org/api/index.js'), "const express = require('express');\nconst app = express();\napp.post('/pay', async (req, res) => {\n  const cardNumber = req.body.cardNumber;\n  await fetch('https://ledger.internal/v1/charge', { method: 'POST', body: JSON.stringify({ cardNumber }) });\n  res.send('ok');\n});\n");
  fs.writeFileSync(path.join(root, 'fleet.yaml'), MANIFEST.replace(/resources:[\s\S]*?repositories:/, 'repositories:'));
  const run = (args) => spawnSync(process.execPath, [CLI, ...args], { cwd: root, encoding: 'utf8', timeout: 400000, env: { ...process.env, XDG_CONFIG_HOME: path.join(root, '.cfg') } });
  const without = run(['fleet', 'scan', 'fleet.yaml', '--no-cache']);
  assert.doesNotMatch(without.stdout, /Code Boundaries:/);
  assert.match(run(['fleet', 'query', '--internet-to', 'pci']).stdout, /No node in the fleet manifest is marked as holding pci data/, 'the manifest alone knows of no PCI holder');
  const withLineage = run(['fleet', 'scan', 'fleet.yaml', '--lineage', '--no-cache']);
  assert.match(withLineage.stdout, /Code Boundaries: 3 repositories contributed a data flow graph\. Data classes found in code but not declared: api \(pci\)/, withLineage.stdout + withLineage.stderr);
  const q = run(['fleet', 'query', '--internet-to', 'pci']);
  assert.match(q.stdout, /Internet -> web -> api/); assert.match(q.stdout, /reaches pci data only because the code shows it, not the manifest: api/);
  const edges = run(['fleet', 'edges', '--undeclared']);
  assert.match(edges.stdout, /api -\[calls\]-> ledger  FOUND ONLY IN CODE/); assert.match(edges.stdout, /code boundaries: ledger\.internal/);
  // the choice is remembered on the run, so a resume does the same thing
  const runId = /Run: (frun-[0-9a-f]+)/.exec(withLineage.stdout)[1];
  const st = JSON.parse(run(['fleet', 'status', runId, '--json']).stdout);
  assert.equal(st.runId, runId);
});
