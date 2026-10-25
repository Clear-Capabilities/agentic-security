// Contract test for cross-repository graph federation (docs/reference/federation.md).
//
// The page is the contract. The test runs the real commands against a signed local graph and a remote export, reads the page's tables,
// and holds the link record, the `declare` report and the `list` report to them in both directions. It also pins the guarantees the page
// makes: a dry run writes nothing, neither graph file changes, the same fact is one link, and a declaration is never observed evidence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { signLastScan } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';
import { exportGraphJSON } from '../../src/lineage/export-json.js';
import { validateCrossRepoLink, CROSS_REPO_LINKS_FILENAME } from '../../src/lineage/cross-repo-link.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const REPO = path.resolve(SCANNER, '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const PAGE = fs.readFileSync(path.join(REPO, 'docs', 'reference', 'federation.md'), 'utf8');
const FLAGSHIP = JSON.parse(fs.readFileSync(path.join(SCANNER, 'src', 'lineage', 'fixtures', 'flagship-graph.json'), 'utf8'));

function rowsUnder(heading) {
  const lines = PAGE.split('\n');
  const at = lines.findIndex(l => l.startsWith(`**${heading}`));
  assert.ok(at >= 0, `the page has no "${heading}" table`);
  const rows = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (lines[i].startsWith('**') || lines[i].startsWith('## ')) break;
    const m = /^\| `([^`]+)` \|/.exec(lines[i]);
    if (m) rows.push(m[1]);
  }
  assert.ok(rows.length, `the "${heading}" table is empty`);
  return rows;
}
const LINK_FIELDS = rowsUnder('Link record');
const DECLARE_FIELDS = rowsUnder('`declare` report');
const LIST_FIELDS = rowsUnder('`list` report');
const keysOf = (o) => Object.keys(o).sort();
const sameKeys = (o, doc, msg) => assert.deepEqual(keysOf(o), [...doc].sort(), msg);

/** A project with a signed local graph, plus a remote export file made from the same fixture graph. */
function setup() {
  const root = mkTestTmp('agsec-federation-contract-');
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(FLAGSHIP, null, 2);
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  const remote = path.join(root, 'remote-export.json');
  fs.writeFileSync(remote, JSON.stringify(exportGraphJSON(FLAGSHIP), null, 2));
  const ids = FLAGSHIP.nodes.map(n => n.id);
  return { root, graphPath, remote, local: ids[0], remoteNode: ids[1] };
}
const run = (root, ...a) => spawnSync(process.execPath, [CLI, 'federate', ...a], { cwd: root, encoding: 'utf8', timeout: 60000 });
const declare = (s, ...extra) => run(s.root, 'declare', '.', '--local-node', s.local, '--remote-graph', s.remote, '--remote-node', s.remoteNode, ...extra);
const linksFile = (root) => statePath(root, CROSS_REPO_LINKS_FILENAME);

test('contract: a dry run prints the documented report, validates, and writes nothing', () => {
  const s = setup();
  const r = declare(s);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  sameKeys(out, DECLARE_FIELDS, 'declare report');
  sameKeys(out.record, LINK_FIELDS, 'link record');
  assert.equal(out.written, false);
  assert.equal(out.backupPath, null);
  assert.equal(validateCrossRepoLink(out.record).valid, true);
  assert.equal(fs.existsSync(linksFile(s.root)), false, 'a dry run creates no links file');
});

test('contract: --yes writes one link, neither graph file changes, and list reports the documented shape', () => {
  const s = setup();
  const before = { graph: fs.readFileSync(s.graphPath), remote: fs.readFileSync(s.remote) };
  const d = declare(s, '--yes');
  assert.equal(d.status, 0, d.stderr);
  assert.equal(JSON.parse(d.stdout).written, true);
  const doc = JSON.parse(fs.readFileSync(linksFile(s.root), 'utf8'));
  assert.equal(doc.links.length, 1);
  sameKeys(doc.links[0], LINK_FIELDS, 'stored record');
  const l = run(s.root, 'list', '.');
  assert.equal(l.status, 0, l.stderr);
  const listed = JSON.parse(l.stdout);
  sameKeys(listed, LIST_FIELDS, 'list report');
  assert.equal(listed.links.length, 1);
  assert.equal(listed.localGraphAvailable, true);
  assert.equal(listed.links[0].local.stillValid, true);
  assert.equal(listed.links[0].remote.ok, true);
  assert.equal(listed.links[0].remote.nodeStillPresent, true);
  assert.deepEqual(listed.links[0].evidence, { declared: true, observed: false });
  const ENTRY = ['id', 'local', 'remote', 'scope', 'evidence', 'rationale', 'declaredBy', 'declaredAt'];
  sameKeys(listed.links[0], ENTRY, 'list entry');
  for (const k of ENTRY) assert.ok(PAGE.includes(`\`${k}\``), `${k} is on the page`);
  assert.ok(before.graph.equals(fs.readFileSync(s.graphPath)), 'the local graph is byte-identical');
  assert.ok(before.remote.equals(fs.readFileSync(s.remote)), 'the remote export is byte-identical');
});

test('contract: the same fact is one link with the same id, and the previous file is backed up', () => {
  const s = setup();
  const first = JSON.parse(declare(s, '--yes').stdout);
  const second = JSON.parse(declare(s, '--yes').stdout);
  assert.equal(first.record.id, second.record.id);
  assert.equal(JSON.parse(fs.readFileSync(linksFile(s.root), 'utf8')).links.length, 1);
  assert.equal(first.backupPath, null, 'nothing to back up on the first write');
  assert.ok(second.backupPath && fs.existsSync(second.backupPath), 'the second write backs up the first');
});

test('contract: a declaration is never observed evidence, and the validator rejects one that says it is', () => {
  const s = setup();
  const { record } = JSON.parse(declare(s).stdout);
  assert.deepEqual(record.evidence, { declared: true, observed: false });
  assert.equal(record.provenance, 'manual');
  assert.equal(record.relationship, 'data_flow');
  const claimsObserved = validateCrossRepoLink({ ...record, evidence: { declared: true, observed: true } });
  assert.equal(claimsObserved.valid, false);
  assert.ok(claimsObserved.errors.some(e => e.path === '$.evidence'));
});

test('contract: the documented exit codes are the ones produced (0, 1, 2)', () => {
  const s = setup();
  assert.equal(declare(s).status, 0);
  assert.equal(run(s.root, 'declare', '.', '--remote-graph', s.remote, '--remote-node', s.remoteNode).status, 2, 'missing --local-node');
  assert.equal(run(s.root, 'declare', '.', '--local-node', 'node:nope', '--remote-graph', s.remote, '--remote-node', s.remoteNode).status, 2, 'unknown local node');
  assert.equal(run(s.root, 'declare', '.', '--local-node', s.local, '--remote-graph', s.remote, '--remote-node', 'node:nope').status, 2, 'unknown remote node');
  assert.equal(run(s.root, 'declare', '.', '--local-node', s.local, '--remote-graph', path.join(s.root, 'absent.json'), '--remote-node', s.remoteNode).status, 2, 'missing remote file');
  assert.equal(declare(s, '--base-digest', 'deadbeef').status, 2, 'a stale --base-digest');
  fs.rmSync(s.graphPath);
  assert.equal(declare(s).status, 1, 'no local graph');
  for (const code of ['`0`', '`1`', '`2`']) assert.ok(PAGE.includes(`| ${code} |`), `exit ${code} is on the page`);
});

test('contract: a links file that is not valid makes list exit 2 and a missing one is an empty list', () => {
  const s = setup();
  const empty = run(s.root, 'list', '.');
  assert.equal(empty.status, 0);
  assert.deepEqual(JSON.parse(empty.stdout).links, []);
  fs.mkdirSync(path.dirname(linksFile(s.root)), { recursive: true });
  fs.writeFileSync(linksFile(s.root), '{not json');
  assert.equal(run(s.root, 'list', '.').status, 2);
});

test('contract: list never claims a check it could not make (no local graph gives stillValid null)', () => {
  const s = setup();
  declare(s, '--yes');
  fs.rmSync(s.graphPath);
  const listed = JSON.parse(run(s.root, 'list', '.').stdout);
  assert.equal(listed.localGraphAvailable, false);
  assert.equal(listed.links[0].local.stillValid, null);
});

test('contract: a remote export that moved is reported, not repaired', () => {
  const s = setup();
  declare(s, '--yes');
  fs.rmSync(s.remote);
  const listed = JSON.parse(run(s.root, 'list', '.').stdout);
  assert.equal(listed.links[0].remote.ok, false);
  assert.equal(listed.links[0].remote.reason, 'missing');
});
