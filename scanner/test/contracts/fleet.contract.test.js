// Contract test for fleet (docs/reference/fleet-contract.md): the manifest keys, the scan and status output, the assurance values and the
// enterprise graph. A real `fleet scan` runs over two fixture repositories, and each shape is held to the page in both directions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { validateFleetManifest, FLEET_MANIFEST_SCHEMA_KEYS, REPO_KEYS, RESOURCE_KEYS, REPO_KINDS, RESOURCE_KINDS, ENVIRONMENTS } from '../../src/posture/fleet/fleet-manifest.js';
import { ASSURANCE } from '../../src/posture/fleet/org-health.js';
import { JOB_STATUSES } from '../../src/posture/fleet/job-store.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const PAGE = readPage('docs/reference/fleet-contract.md');

function org() {
  const root = mkTestTmp('agsec-fleet-contract-');
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"org","version":"1.0.0"}');
  for (const [id, deps] of [['a', {}], ['b', { a: '^1.0.0' }]]) {
    fs.mkdirSync(path.join(root, id));
    fs.writeFileSync(path.join(root, id, 'package.json'), JSON.stringify({ name: id, version: '1.0.0', dependencies: deps }));
    fs.writeFileSync(path.join(root, id, 'index.js'), 'const x = 1;\n');
  }
  fs.writeFileSync(path.join(root, 'fleet.yaml'), [
    'organization: acme', 'resources:', '  - { id: q, kind: queue }',
    'repositories:', '  - { id: a, path: ./a, kind: library, required: false }', '  - { id: b, path: ./b, kind: service, produces: [q] }', '',
  ].join('\n'));
  return root;
}
const fleet = (root, ...a) => spawnSync(process.execPath, [CLI, 'fleet', ...a], { cwd: root, encoding: 'utf8', timeout: 120000 });
const json = (out) => JSON.parse(out.slice(out.indexOf('\n{') >= 0 && !out.startsWith('{') ? out.indexOf('\n{') + 1 : 0));

const root = org();
const scan = fleet(root, 'scan', 'fleet.yaml', '--json', '--no-discover');
const out = json(scan.stdout);
const graph = JSON.parse(fs.readFileSync(path.join(root, '.agentic-security', 'fleet', 'enterprise-graph.json'), 'utf8'));
const status = json(fleet(root, 'status', '--json').stdout);

test('contract: the manifest accepts exactly the documented keys, and the vocabulary matches', () => {
  assert.deepEqual([...FLEET_MANIFEST_SCHEMA_KEYS].sort(), fieldsUnder(PAGE, 'Manifest keys').sort());
  assert.deepEqual([...REPO_KEYS].sort(), fieldsUnder(PAGE, 'Repository keys').sort());
  assert.deepEqual([...RESOURCE_KEYS].sort(), fieldsUnder(PAGE, 'Resource keys').sort());
  for (const w of [...REPO_KINDS, ...RESOURCE_KINDS, ...ENVIRONMENTS]) assert.ok(PAGE.includes(`\`${w}\``), `${w} is on the page`);
});

test('contract: an unknown manifest key refuses the whole manifest, and a documented one does not', () => {
  const doc = { organization: 'x', repositories: [{ id: 'a', path: '.' }] };
  assert.equal(validateFleetManifest(doc, { baseDir: root }).ok, true);
  assert.equal(validateFleetManifest({ ...doc, surprise: 1 }, { baseDir: root }).ok, false);
  assert.equal(validateFleetManifest({ organization: 'x', repositories: [{ id: 'a', path: '.', surprise: 1 }] }, { baseDir: root }).ok, false);
});

test('contract: fleet scan --json has exactly the documented fields at every level', () => {
  assert.equal(scan.status, 0, scan.stderr);
  sameFields(out, fieldsUnder(PAGE, 'Scan output'), 'scan output');
  sameFields(out.health, fieldsUnder(PAGE, 'Health'), 'health');
  sameFields(out.health.repositories[0], fieldsUnder(PAGE, 'Health repository'), 'health repository');
  sameFields(out.rollup, fieldsUnder(PAGE, 'Rollup'), 'rollup');
  assert.deepEqual(Object.keys(out.health.counts).sort(), ['cancelled', 'complete', 'failed', 'notRun', 'partial', 'requested', 'timedOut']);
});

test('contract: fleet status --json carries the documented job fields, and the job statuses are the documented ones', () => {
  sameFields(status.jobs[0], fieldsUnder(PAGE, 'Job'), 'job');
  for (const s of JOB_STATUSES) assert.ok(PAGE.includes(`\`${s}\``), `${s} is on the page`);
});

test('contract: the assurance values are the documented three, and a healthy fixture is green', () => {
  assert.deepEqual([...ASSURANCE], ['green', 'degraded', 'red']);
  for (const v of ASSURANCE) assert.ok(PAGE.includes(`\`${v}\``));
  assert.equal(out.health.assurance, 'green');
});

test('contract: the enterprise graph file has exactly the documented fields, and every edge has evidence', () => {
  sameFields(graph, fieldsUnder(PAGE, 'Graph'), 'graph');
  assert.equal(graph.schema, 'agentic-security/enterprise-graph');
  assert.equal(graph.version, 1);
  for (const n of graph.nodes) sameFields(n, fieldsUnder(PAGE, 'Node'), `node ${n.id}`, ['discoveredDataClasses']);
  const types = new Set(fieldsUnder(PAGE, 'Edge'));
  for (const e of graph.edges) {
    sameFields(e, [...types], `edge ${e.id}`);
    assert.ok(e.evidence.length >= 1, `edge ${e.id} has evidence`);
  }
  for (const t of ['exposes', 'calls', 'produces', 'consumes', 'reads', 'writes', 'uses-provider', 'connects-to', 'depends-on']) assert.ok(PAGE.includes(`\`${t}\``));
  for (const e of graph.edges) assert.ok(['exposes', 'calls', 'produces', 'consumes', 'reads', 'writes', 'uses-provider', 'connects-to', 'depends-on'].includes(e.type), e.type);
});

test('contract: a manifest that names a missing directory is refused whole, not skipped', () => {
  const r = org();
  fs.writeFileSync(path.join(r, 'fleet.yaml'), 'organization: acme\nrepositories:\n  - { id: a, path: ./a }\n  - { id: b, path: ./b }\n');
  fs.rmSync(path.join(r, 'b'), { recursive: true, force: true });
  const res = fleet(r, 'scan', 'fleet.yaml', '--json', '--no-discover');
  assert.notEqual(res.status, 0, 'a manifest naming a missing directory is refused');
});

test('contract: the comparison fails when a field is added or dropped', () => {
  const doc = fieldsUnder(PAGE, 'Scan output');
  assert.throws(() => sameFields({ ...out, extra: 1 }, doc, 'scan'));
  const { rollup, ...rest } = out;
  assert.throws(() => sameFields(rest, doc, 'scan'));
  assert.ok(rollup);
});
