// federate-declare-list.test.js — M5 deliverable #8 (FR-304's "declared"
// half). CLI subprocess tests for `agentic-security federate
// declare|list`. Mirrors test/cli/governance-propose-edit.test.js's real
// -subprocess spawnSync pattern, plus test/cli/dataflow-recipients.test.js's
// real-git-fixture + real-deep-scan pattern for producing a genuine,
// signed local lineage graph and a genuine remote graph export.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { statePath } from '../../src/posture/state-dir.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

const SINK_SOURCE = 'function h(req, res){ const pw = req.body.password; res.send(pw); }';

function _scanWithLineage(fx) {
  return spawnSync(process.execPath, [CLI, 'scan', '.'], {
    cwd: fx.root, encoding: 'utf8', timeout: 60000,
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  });
}

function _localGraphNodeId(fx) {
  const graphPath = statePath(fx.root, 'lineage-graph.json');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  const n = graph.nodes.find((x) => x.kind === 'sink');
  assert.ok(n, 'the local fixture must produce a real sink node');
  return n.id;
}

function _buildRemoteExport(remoteExportPath) {
  const fx = createGitFixture();
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `remote scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);
  const exportR = spawnSync(process.execPath, [CLI, 'dataflow', 'export', '.', '--format', 'json', '--no-redact', '--output', remoteExportPath], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(exportR.status, 0, exportR.stderr);
  const exported = JSON.parse(fs.readFileSync(remoteExportPath, 'utf8'));
  const remoteNode = exported.graph.nodes.find((x) => x.kind === 'sink');
  assert.ok(remoteNode, 'the remote fixture must produce a real sink node');
  fx.cleanup();
  return remoteNode.id;
}

function _declare(fx, extraArgs) {
  return spawnSync(process.execPath, [CLI, 'federate', 'declare', '.', ...extraArgs], {
    cwd: fx.root, encoding: 'utf8', timeout: 15000,
  });
}

function _list(fx, extraArgs = []) {
  return spawnSync(process.execPath, [CLI, 'federate', 'list', '.', ...extraArgs], {
    cwd: fx.root, encoding: 'utf8', timeout: 15000,
  });
}

test('federate declare: without --yes, previews and does NOT write', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc']);
  assert.equal(r.status, 0, r.stderr);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), false, 'no --yes must never write');
  const report = JSON.parse(r.stdout);
  assert.equal(report.written, false);
  assert.match(report.record.id, /^crosslink:[0-9a-f]+$/);
});

test('federate declare: with --yes, writes atomically, no backup on the first write, and appends a real audit event', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--rationale', 'test link', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(written.links.length, 1);
  assert.equal(written.links[0].local.nodeId, localNodeId);
  assert.equal(written.links[0].remote.nodeId, remoteNodeId);
  assert.equal(written.links[0].remote.repository, 'remote-svc');
  assert.equal(written.links[0].provenance, 'manual');

  const backupDir = statePath(fx.root, 'cross-repo-links-backups');
  const backupCount = fs.existsSync(backupDir) ? fs.readdirSync(backupDir).length : 0;
  assert.equal(backupCount, 0, 'no backup on the very first write — nothing existed to back up');

  const auditLogPath = statePath(fx.root, 'mcp-audit.log');
  assert.ok(fs.existsSync(auditLogPath));
  const auditContent = fs.readFileSync(auditLogPath, 'utf8');
  assert.match(auditContent, /federate_declare/);
  assert.match(auditContent, /"outcome":"ok"/);
});

// B3 (final whole-branch review, M5 deliverable #8): a second declaration
// of the IDENTICAL (local, remote, relationship) fact now produces the
// SAME id (rationale is not part of the id discriminator) and DEDUPES on
// write — replacing the existing entry in place, never appending a
// duplicate. A backup is still made before every real write, dedupe or
// not — only the final CONTENT differs from the pre-fix behavior.
test('federate declare: a second declare of the IDENTICAL fact creates a backup of the first write and DEDUPES to one entry with the same id', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r1 = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--yes']);
  assert.equal(r1.status, 0, r1.stderr);
  const report1 = JSON.parse(r1.stdout);
  const r2 = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--rationale', 'a second link', '--yes']);
  assert.equal(r2.status, 0, r2.stderr);
  const report2 = JSON.parse(r2.stdout);

  // Same real-world fact -> same id, even though --rationale differs
  // (rationale is not part of crossRepoLinkId's own discriminator).
  assert.equal(report1.record.id, report2.record.id);

  const backupDir = statePath(fx.root, 'cross-repo-links-backups');
  const backups = fs.readdirSync(backupDir);
  assert.equal(backups.length, 1, 'a backup is still made before every real write, dedupe or not');

  const configPath = statePath(fx.root, 'cross-repo-links.json');
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(written.links.length, 1, 'the second declare of the identical fact must DEDUPE, never append a duplicate');
  assert.equal(written.links[0].id, report2.record.id);
  assert.equal(written.links[0].rationale, 'a second link', 'the dedupe write keeps the LATEST record content for that id');
});

// B3's own two-part live reproduction (brief's verification checklist,
// item 3): two identical `federate declare --yes` invocations (same
// flags) produce ONE entry with the SAME id.
test('federate declare: two IDENTICAL back-to-back declares (same flags) produce exactly one entry with the same id', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);
  const args = ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--yes'];

  const r1 = _declare(fx, args);
  assert.equal(r1.status, 0, r1.stderr);
  const r2 = _declare(fx, args);
  assert.equal(r2.status, 0, r2.stderr);

  const configPath = statePath(fx.root, 'cross-repo-links.json');
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(written.links.length, 1, 'two identical declarations must produce exactly ONE entry, not two');
  assert.equal(written.links[0].local.nodeId, localNodeId);
  assert.equal(written.links[0].remote.nodeId, remoteNodeId);
});

// B3's root-cause half: declaring the identical fact again after a RESCAN
// of the local repo must still produce the SAME id — the local graph's own
// digest must not be perturbed by a previously-declared crossRepoLinks
// entry being re-attached to it by the next scan.
test('federate declare: declaring the identical fact again after a rescan of the local repo produces the SAME id', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r1 = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--yes']);
  assert.equal(r1.status, 0, r1.stderr);
  const report1 = JSON.parse(r1.stdout);

  // Rescan — this re-attaches cross-repo-links.json's own content onto
  // graph.crossRepoLinks (Task 3's own wiring), which is exactly the
  // feedback loop B3's fix strips out of the digest computation.
  const rescanR = _scanWithLineage(fx);
  assert.ok(rescanR.status <= 3, rescanR.stderr);

  const r2 = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--yes']);
  assert.equal(r2.status, 0, r2.stderr);
  const report2 = JSON.parse(r2.stdout);

  assert.equal(report1.record.id, report2.record.id, 'the identical real-world fact must produce the same id across a rescan');
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(written.links.length, 1, 'still exactly one entry after the rescan + re-declare');
});

test('federate declare: missing --local-node/--remote-graph/--remote-node each exit 2', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);

  assert.equal(_declare(fx, ['--remote-graph', 'x.json', '--remote-node', 'node:x']).status, 2);
  assert.equal(_declare(fx, ['--local-node', 'node:x', '--remote-node', 'node:x']).status, 2);
  assert.equal(_declare(fx, ['--local-node', 'node:x', '--remote-graph', 'x.json']).status, 2);
});

test('federate declare: --local-node not present in the current locally-scanned graph exits 2, writes nothing', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', 'node:sink:doesnotexist000000', '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--local-node/);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), false);
});

test('federate declare: --remote-node not present in the remote export exits 2, writes nothing', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', 'node:source:doesnotexist000000', '--yes']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--remote-node/);
});

test('federate declare: a missing --remote-graph file exits 2 with a clear message, writes nothing', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', path.join(fx.root, 'no-such-file.json'), '--remote-node', 'node:x', '--yes']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /No remote graph export found/);
});

// Exit-code alignment (final whole-branch review, M5 deliverable #8):
// cmdFederateDeclare's loadSignedGraph failure path must exit 1, matching
// every OTHER call site of loadSignedGraph in bin/agentic-security.js
// (explore, dataflow export, scenario apply, impact assess, observations
// import, dataflow twin) — this deliverable had introduced the sole
// exit-2 outlier.
test('federate declare: no local lineage graph could be loaded (never scanned) exits 1, matching every other loadSignedGraph call site', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  // Deliberately never scanned — no .agentic-security/lineage-graph.json.
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', 'node:sink:doesnotexist000000', '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /could not load the local scanned graph/);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), false);
});

test('federate declare: --base-digest mismatch (a concurrent edit) is refused, exit 2, never writes', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const staleDigest = crypto.createHash('sha256').update('{"links":[{"someone-else-declared":true}]}').digest('hex');
  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes', '--base-digest', staleDigest]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /concurrent|changed|digest/i);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), false);
});

test('federate declare: a digest-mismatched remote export is a printed warning, but --yes still writes', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);

  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);
  // Tamper the bodyDigest AFTER building a genuinely valid export — B1's
  // own self-consistency field, which is what loadRemoteGraphExport
  // actually compares a recomputation against (final whole-branch review,
  // M5 deliverable #8, B1 — `digest` identifies the SOURCE graph
  // regardless of redaction and would never move here).
  const exported = JSON.parse(fs.readFileSync(remoteExportPath, 'utf8'));
  exported.bodyDigest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
  fs.writeFileSync(remoteExportPath, JSON.stringify(exported));

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /WARNING/);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), true, 'a digest mismatch must not block --yes — the operator is explicitly asserting this file');
});

test('federate list: no cross-repo-links.json at all — an empty list, exit 0', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);

  const r = _list(fx);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.deepEqual(report.links, []);
});

test('federate list: reports a real, valid declared link as still-valid on both sides', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);
  const declareR = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(declareR.status, 0, declareR.stderr);

  const r = _list(fx);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.localGraphAvailable, true);
  assert.equal(report.links.length, 1);
  assert.equal(report.links[0].local.stillValid, true);
  assert.equal(report.links[0].remote.ok, true);
  assert.equal(report.links[0].remote.nodeStillPresent, true);
  assert.equal(report.links[0].remote.digestMatches, true);
});

test('federate list: a declared link whose remote export file has since moved reports remote.ok:false, reason "missing" — never fabricates "still valid"', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);
  const declareR = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(declareR.status, 0, declareR.stderr);
  fs.unlinkSync(remoteExportPath);

  const r = _list(fx);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.links[0].remote.ok, false);
  assert.equal(report.links[0].remote.reason, 'missing');
});
