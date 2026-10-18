// Edges found in code (PRD 4): exact-token matching, evidence with file and line, the declared/undeclared split, and the CLI showing an
// attack path that rests on an edge nobody wrote down.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { discoverEdges, splitDeclared } from '../../src/posture/fleet/discover-edges.js';
import { buildEnterpriseGraph, validateEnterpriseGraph, attackPaths } from '../../src/posture/fleet/enterprise-graph.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const write = (root, files) => { for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true }); fs.writeFileSync(path.join(root, f), c); } };

function org() {
  const root = mkTestTmp('fleet-disc-'); fs.mkdirSync(path.join(root, '.git'));
  write(root, {
    'org/web/index.js': "const r = await fetch('http://api.svc.cluster.local/orders');\n",
    'org/api/index.js': [
      "// http://ledger.internal/commented-out is a comment and must be ignored",
      "const res = await fetch('https://ledger.internal/v1/charge', { method: 'POST' });",
      "await sqs.sendMessage({ QueueUrl: 'orders-queue', MessageBody: 'x' });",
      "const pool = new Pool({ connectionString: 'postgres://user:pw@card-db.internal:5432/cards' });",
      "const reorders = 'reorders-queue-is-not-orders-queue-token-match';",
      "const other = 'http://notledger.internal/x';",
      '',
    ].join('\n'),
    'org/ledger/index.js': "queue.subscribe('orders-queue', handle);\n",
    'org/ledger/node_modules/dep/index.js': "fetch('http://api.svc.cluster.local/')\n",
  });
  return root;
}
const MANIFEST = (extra = '') => `organization: acme
resources:
  - { id: orders-queue, kind: queue }
  - { id: card-db, kind: database, dataClasses: [pci], aliases: [card-db.internal] }
repositories:
  - { id: web, path: ./org/web, kind: frontend, internetFacing: true, environment: production, calls: [api] }
  - { id: api, path: ./org/api, kind: service, environment: production, aliases: [api.svc.cluster.local] }
  - { id: ledger, path: ./org/ledger, kind: service, environment: production, dataClasses: [pci], aliases: [ledger.internal] ${extra} }
`;
import { loadFleetManifest } from '../../src/posture/fleet/fleet-manifest.js';
const manifestOf = (root, yaml = MANIFEST()) => { fs.writeFileSync(path.join(root, 'fleet.yaml'), yaml); const r = loadFleetManifest(path.join(root, 'fleet.yaml')); assert.equal(r.ok, true, r.errors?.join()); return r.manifest; };

test('aliases are validated: a list of up to 16 lower-case names, nothing else', () => {
  const root = org();
  assert.equal(loadFleetManifest((fs.writeFileSync(path.join(root, 'f.yaml'), MANIFEST().replace('[ledger.internal]', '[Ledger.Internal]')), path.join(root, 'f.yaml'))).ok, false);
  fs.writeFileSync(path.join(root, 'g.yaml'), MANIFEST().replace('[ledger.internal]', '"ledger.internal"'));
  assert.match(loadFleetManifest(path.join(root, 'g.yaml')).errors.join(), /aliases must be a list/);
});

test('discovery finds calls, produces, consumes and connects-to, each with file and line, matching whole tokens only', () => {
  const root = org(); const manifest = manifestOf(root);
  const d = discoverEdges({ manifest });
  const key = (e) => `${e.type}:${e.from}->${e.to}`;
  const got = d.edges.map(key);
  assert.deepEqual(got, ['calls:api->ledger', 'calls:web->api', 'connects-to:api->card-db', 'consumes:orders-queue->ledger', 'produces:api->orders-queue']);
  const ledger = d.edges.find((e) => key(e) === 'calls:api->ledger');
  assert.deepEqual({ file: ledger.evidence[0].file, line: ledger.evidence[0].line, host: ledger.evidence[0].host, declared: ledger.evidence[0].declared }, { file: 'index.js', line: 2, host: 'ledger.internal', declared: false });
  assert.ok(!got.some((k) => /notledger/.test(k)), 'notledger.internal is not ledger.internal');
  assert.equal(d.edges.find((e) => key(e) === 'produces:api->orders-queue').evidence[0].line, 3, 'the reorders literal on line 5 is not a token match');
  assert.ok(!JSON.stringify(d).includes('pw@') && !JSON.stringify(d).includes('user:pw'), 'no credential from a connection string is kept');
  assert.equal(d.scanned.ledger.files, 1, 'node_modules is skipped');
});

test('the declared/undeclared split, and a graph where discovered evidence sits beside declared evidence without replacing it', () => {
  const root = org(); const manifest = manifestOf(root);
  const d = discoverEdges({ manifest });
  const { undeclared, confirmed } = splitDeclared(d, manifest);
  assert.deepEqual(confirmed.map((e) => `${e.type}:${e.from}->${e.to}`), ['calls:web->api']);
  assert.equal(undeclared.length, 4);
  const g = buildEnterpriseGraph({ manifest, dependencyGraph: { edges: [] }, discovered: d });
  assert.deepEqual(validateEnterpriseGraph(g), []);
  const webApi = g.edges.find((e) => e.id === 'edge:calls:web:api');
  assert.equal(webApi.discovered, false); assert.deepEqual(webApi.evidence.map((x) => x.source).sort(), ['discovered-code-literal', 'fleet-manifest']);
  const apiLedger = g.edges.find((e) => e.id === 'edge:calls:api:ledger');
  assert.equal(apiLedger.discovered, true);
  const paths = attackPaths({ graph: g, toDataClass: 'pci' });
  const viaLedger = paths.paths.find((p) => p.nodes.includes('ledger'));
  assert.ok(viaLedger, 'the PCI holder is reachable from the Internet only through an edge found in code');
  assert.deepEqual(viaLedger.discoveredEdges, ['edge:calls:api:ledger']);
  const noDisc = attackPaths({ graph: buildEnterpriseGraph({ manifest, dependencyGraph: { edges: [] } }), toDataClass: 'pci' });
  assert.equal(noDisc.paths.length, 0, 'without discovery the declared graph has no such path');
});

test('bounds: a repository with too many files is cut off and says so; a symlink is never followed', () => {
  const root = mkTestTmp('fleet-disc-b-'); fs.mkdirSync(path.join(root, '.git'));
  for (let i = 0; i < 12; i++) write(root, { [`org/a/f${i}.js`]: `const x = ${i};\n` });
  write(root, { 'org/b/index.js': 'x\n' });
  fs.writeFileSync(path.join(root, 'outside.js'), "fetch('http://b.internal/')\n");
  fs.symlinkSync(path.join(root, 'outside.js'), path.join(root, 'org/a/link.js'));
  const manifest = manifestOf(root, "organization: t\nrepositories:\n  - { id: a, path: ./org/a }\n  - { id: b, path: ./org/b, aliases: [b.internal] }\n");
  const d = discoverEdges({ manifest, limits: { maxFilesPerRepo: 5 } });
  assert.equal(d.scanned.a.truncated, true);
  assert.deepEqual(d.edges, [], 'the symlink target outside the repository was not read');
});

test('end to end: fleet scan reports edges found in code, `fleet edges --undeclared` lists them, a PCI path is flagged as resting on one, --no-discover turns it off', { timeout: 600000 }, () => {
  const root = org(); manifestOf(root);
  const run = (args) => spawnSync(process.execPath, [CLI, ...args], { cwd: root, encoding: 'utf8', timeout: 300000 });
  const scan = run(['fleet', 'scan', 'fleet.yaml']);
  assert.match(scan.stdout, /Edges found in code: 4 not in the manifest, 1 matching a declared edge/, scan.stdout + scan.stderr);
  const edges = run(['fleet', 'edges', '--undeclared']);
  assert.equal(edges.status, 0, edges.stderr);
  assert.match(edges.stdout, /api -\[calls\]-> ledger  FOUND ONLY IN CODE  \(index\.js:2\)/);
  assert.doesNotMatch(edges.stdout, /web -\[calls\]-> api/, 'a declared edge is not listed as undeclared');
  assert.match(edges.stdout, /Limits: .*literals/);
  const q = run(['fleet', 'query', '--internet-to', 'pci']);
  assert.match(q.stdout, /Internet -> web -> api -> ledger/); assert.match(q.stdout, /rests on edge\(s\) found only in code, not declared: edge:calls:api:ledger/);
  const off = run(['fleet', 'scan', 'fleet.yaml', '--no-discover', '--no-cache']);
  assert.match(off.stdout, /Edge discovery skipped \(--no-discover\)/);
  const q2 = run(['fleet', 'query', '--internet-to', 'pci']);
  assert.match(q2.stdout, /No Internet-facing path to pci data/);
});
