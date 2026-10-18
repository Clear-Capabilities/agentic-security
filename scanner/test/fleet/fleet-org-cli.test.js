// The five-repository test organization from the PRD, through the real spawned CLI: one flaw in the shared auth library, and the
// questions an organization asks about it. Also resume after timeouts and after a killed controller.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const run = (cwd, args, timeout = 240000) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] });

function mkOrg() {
  const root = mkTestTmp('fleet-org-'); fs.mkdirSync(path.join(root, '.git'));
  const repo = (id, name, deps, files) => { const d = path.join(root, 'org', id); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name, version: '1.0.0', dependencies: deps })); for (const [f, c] of Object.entries(files)) fs.writeFileSync(path.join(d, f), c); };
  repo('shared-auth-lib', '@acme/shared-auth-lib', {}, { 'index.js': "const express = require('express');\nconst app = express();\napp.post('/login', (req, res) => {\n  const { exec } = require('child_process');\n  exec('check-user ' + req.body.user, (e, out) => res.send(out));\n});\nmodule.exports = app;\n" });
  repo('frontend', '@acme/frontend', { '@acme/shared-auth-lib': 'github:acme/shared-auth-lib#abc123' }, { 'index.js': 'module.exports = {};\n' });
  repo('payments-api', '@acme/payments-api', { '@acme/shared-auth-lib': '^1.0.0' }, { 'index.js': 'module.exports = {};\n' });
  repo('payments-worker', '@acme/payments-worker', { '@acme/payments-api': '^1.0.0' }, { 'index.js': 'module.exports = {};\n' });
  repo('ledger-db-client', '@acme/ledger-db-client', {}, { 'index.js': 'module.exports = {};\n' });
  fs.writeFileSync(path.join(root, 'fleet.yaml'), `organization: acme
workers: 3
retries: 1
resources:
  - { id: edge-gateway, kind: gateway, internetFacing: true, environment: production }
  - { id: payments-queue, kind: queue, environment: production }
  - { id: card-db, kind: database, dataClasses: [pci], environment: production, trustZone: cardholder }
repositories:
  - { id: frontend, path: ./org/frontend, kind: frontend, internetFacing: true, environment: production, calls: [edge-gateway, payments-api] }
  - { id: payments-api, path: ./org/payments-api, kind: service, environment: production, dataClasses: [pci], produces: [payments-queue] }
  - { id: shared-auth-lib, path: ./org/shared-auth-lib, kind: library }
  - { id: payments-worker, path: ./org/payments-worker, kind: worker, environment: production, dataClasses: [pci], consumes: [payments-queue], writes: [card-db] }
  - { id: ledger-db-client, path: ./org/ledger-db-client, kind: library, required: false }
`);
  return root;
}

test('scan, health, the three questions, and the static graph page', { timeout: 600000 }, () => {
  const root = mkOrg();
  const scan = run(root, ['fleet', 'scan', 'fleet.yaml']);
  assert.equal(scan.status, 0, scan.stdout + scan.stderr);
  assert.match(scan.stdout, /Run: frun-[0-9a-f]+/);
  assert.match(scan.stdout, /Repositories requested: 5\nComplete: 5\nPartial: 0\nFailed: 0\nTimed out: 0\n\nAssurance: GREEN/);
  assert.match(scan.stdout, /critical|high/);
  const db = path.join(root, '.agentic-security', 'fleet', 'fleet.db');
  assert.ok(fs.existsSync(db));

  // 1. blast radius of the flaw's component: counts, not just names
  const br = run(root, ['fleet', 'query', '--blast-radius', 'shared-auth-lib']);
  assert.equal(br.status, 0, br.stderr);
  assert.match(br.stdout, /^shared-auth-lib\n\nUsed by:\n3 repositories\n1 Internet-facing service\n3 production apps\n2 PCI-scoped services/);
  const pinned = JSON.parse(run(root, ['fleet', 'query', '--blast-radius', 'shared-auth-lib', '--version', 'abc123', '--json']).stdout);
  assert.deepEqual(pinned.dependents.filter((d) => d.versionMatch === 'matched').map((d) => d.id), ['frontend']);

  // 2. the Internet-facing paths to cardholder data
  const paths = run(root, ['fleet', 'query', '--internet-to', 'pci']);
  assert.equal(paths.status, 0, paths.stderr);
  assert.match(paths.stdout, /Internet -> frontend -> payments-api -> payments-queue -> payments-worker -> card-db/);

  // 3. ... involving vulnerable authentication code: the PRD's question, answered from the real scan's findings
  const q = run(root, ['fleet', 'query', 'Show every Internet-facing path to PCI data involving vulnerable authentication code']);
  assert.equal(q.status, 0, q.stderr + q.stdout);
  const direct = JSON.parse(run(root, ['fleet', 'query', '--internet-to', 'pci', '--involving-vulnerable', 'shared-auth-lib', '--json']).stdout);
  assert.ok(direct.paths.length > 0 && direct.paths.every((p) => p.involving.length > 0));
  assert.ok(direct.involving.all.includes('payments-worker'), 'a repository that depends on the vulnerable library, through payments-api, is in the set');
  const none = run(root, ['fleet', 'query', '--internet-to', 'pii']);
  assert.match(none.stdout, /nothing to reach/);
  assert.equal(run(root, ['fleet', 'query', 'what is the weather']).status, 4);

  const html = path.join(root, 'graph.html');
  assert.equal(run(root, ['fleet', 'explore', '--out', html]).status, 0);
  const page = fs.readFileSync(html, 'utf8');
  assert.match(page, /edge-gateway/); assert.match(page, /package-manifest|fleet-manifest/); assert.doesNotMatch(page, /<script/i);

  // status by run id, and the rollup of the old shape still reads
  const runId = /Run: (frun-[0-9a-f]+)/.exec(scan.stdout)[1];
  const st = run(root, ['fleet', 'status', runId]);
  assert.equal(st.status, 0, st.stderr); assert.match(st.stdout, /Complete: 5/);
  assert.equal(run(root, ['fleet', 'status', 'frun-nope']).status, 4);
  // the PRD names `fleet status JOB-ID` / `fleet resume JOB-ID`: a job id resolves to the run it belongs to
  const jobId = JSON.parse(run(root, ['fleet', 'status', runId, '--json']).stdout).jobs[0].jobId;
  assert.match(jobId, /^\S+$/);
  const byJob = run(root, ['fleet', 'status', jobId]);
  assert.equal(byJob.status, 0, byJob.stderr); assert.match(byJob.stdout, /Complete: 5/); assert.match(byJob.stderr, new RegExp(`Job ${jobId} belongs to run ${runId}`));
  assert.match(run(root, ['fleet', 'resume', 'job-nope']).stderr, /No run job-nope/);
});

test('timeouts make the organization red, name the repositories, and resume --retry-failed finishes the job without redoing finished work', { timeout: 600000 }, () => {
  const root = mkOrg();
  const first = run(root, ['fleet', 'scan', 'fleet.yaml', '--timeout-ms', '100', '--retries', '0', '--workers', '5', '--no-cache']);
  assert.equal(first.status, 1, first.stdout + first.stderr);
  const runId = /Run: (frun-[0-9a-f]+)/.exec(first.stdout)[1];
  assert.match(first.stdout, /Assurance: RED/);
  const timedOut = Number(/Timed out: (\d+)/.exec(first.stdout)[1]);
  assert.equal(timedOut, 5, 'a 100 ms limit cannot fit any real scan');
  assert.match(first.stdout, new RegExp(`fleet resume ${runId} --retry-failed`));
  assert.equal(run(root, ['fleet', 'status', runId, '--json']).status, 0);
  const second = run(root, ['fleet', 'resume', runId, '--retry-failed', '--timeout-seconds', '120']);
  assert.equal(second.status, 0, second.stdout + second.stderr);
  assert.match(second.stdout, /Complete: 5/); assert.match(second.stdout, /Assurance: GREEN/);
  assert.match(second.stderr, /re-queued/);
  const again = run(root, ['fleet', 'resume', runId, '--timeout-seconds', '120']);
  assert.equal(again.status, 0); assert.match(again.stderr, /0 unfinished/);
  assert.equal(run(root, ['fleet', 'resume', 'frun-nope']).status, 4);
  // a manifest that changed since the run was planned is refused
  fs.appendFileSync(path.join(root, 'fleet.yaml'), '# edited\n');
  const changed = run(root, ['fleet', 'resume', runId]);
  assert.equal(changed.status, 4); assert.match(changed.stderr, /has changed since/);
});

test('a controller killed mid-run leaves a run that `fleet resume` completes', { timeout: 600000 }, async () => {
  const root = mkOrg();
  const child = spawn(process.execPath, [CLI, 'fleet', 'scan', 'fleet.yaml', '--workers', '2'], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; child.stdout.on('data', (d) => { out += d; });
  const { DatabaseSync } = await import('node:sqlite');
  const db = path.join(root, '.agentic-security', 'fleet', 'fleet.db');
  let runId = null;
  for (let i = 0; i < 400 && !runId; i++) {
    await new Promise((r) => setTimeout(r, 50));
    if (!fs.existsSync(db)) continue;
    try { const d = new DatabaseSync(db); const row = d.prepare("SELECT run_id FROM fleet_jobs WHERE status = 'leased' LIMIT 1").get(); d.close(); if (row) runId = row.run_id; } catch { /* the database is busy */ }
  }
  assert.ok(runId, 'a job was leased while the controller was running');
  child.kill('SIGKILL');
  await new Promise((r) => child.on('close', r));
  const mid = run(root, ['fleet', 'status', runId, '--json']);
  assert.equal(mid.status, 0, mid.stderr);
  const resumed = run(root, ['fleet', 'resume', runId, '--timeout-seconds', '120']);
  assert.equal(resumed.status, 0, resumed.stdout + resumed.stderr);
  assert.match(resumed.stdout, /Complete: 5/); assert.match(resumed.stdout, /Assurance: GREEN/);
  const d = new DatabaseSync(db);
  const jobs = d.prepare('SELECT repo_id, status, attempts FROM fleet_jobs WHERE run_id = ?').all(runId); d.close();
  assert.equal(jobs.length, 5, 'one job per repository, however many times the run was interrupted');
  assert.ok(jobs.every((j) => j.status === 'succeeded'));
  void out;
});
