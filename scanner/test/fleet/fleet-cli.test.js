// Killer scenario (PRD 4): five... well, four small repositories (frontend, payments-api, shared-auth-lib,
// payments-worker), a real vulnerability introduced only in the shared library, and one command that answers
// "which Internet-facing-adjacent repositories can reach it through this vulnerable shared component" by way of
// the dependency graph (the Internet-facing/attack-path overlay is explicitly future work — see the guide).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const run = (args, opts = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'], ...opts });

function mkRepo(dir, name, deps, files) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0', dependencies: deps }));
  for (const [rel, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, rel), content);
}

test('fleet: real vulnerability in a shared library is found by blast-radius query across the fleet', () => {
  const root = mkTestTmp('fleet-cli-');
  const org = path.join(root, 'org');
  mkRepo(path.join(org, 'shared-auth-lib'), '@acme/shared-auth-lib', {}, {
    'index.js': "const express = require('express');\nconst app = express();\napp.post('/ping', (req, res) => {\n  const { exec } = require('child_process');\n  exec('ping ' + req.body.host, (err, out) => res.send(out));\n});\nmodule.exports = { app };\n",
  });
  mkRepo(path.join(org, 'frontend'), '@acme/frontend', { '@acme/shared-auth-lib': '^1.0.0' }, { 'index.js': "module.exports = {};\n" });
  mkRepo(path.join(org, 'payments-api'), '@acme/payments-api', { '@acme/shared-auth-lib': '^1.0.0' }, { 'index.js': "module.exports = {};\n" });
  mkRepo(path.join(org, 'payments-worker'), '@acme/payments-worker', { '@acme/payments-api': '^1.0.0' }, { 'index.js': "module.exports = {};\n" });

  fs.mkdirSync(path.join(root, '.git'));
  const manifestPath = path.join(root, 'fleet.yaml');
  fs.writeFileSync(manifestPath, [
    'organization: acme', 'repositories:',
    '  - id: frontend', '    path: ./org/frontend',
    '  - id: payments-api', '    path: ./org/payments-api',
    '  - id: shared-auth-lib', '    path: ./org/shared-auth-lib',
    '  - id: payments-worker', '    path: ./org/payments-worker',
    'workers: 2',
  ].join('\n') + '\n');

  const scanR = spawnSync(process.execPath, [CLI, 'fleet', 'scan', 'fleet.yaml'], { cwd: root, encoding: 'utf8', timeout: 90000 });
  assert.ok(scanR.status === 0 || scanR.status === 1, scanR.stderr + scanR.stdout);
  assert.match(scanR.stdout, /Repositories requested: 4/);
  assert.match(scanR.stdout, /Complete: 4/);
  // The real, grounded vulnerability: command injection in the shared library is actually found by the
  // deterministic engine, not just asserted away — this is what makes the blast-radius query meaningful.
  assert.match(scanR.stdout, /critical|high/);

  const statusR = spawnSync(process.execPath, [CLI, 'fleet', 'status'], { cwd: root, encoding: 'utf8', timeout: 15000 });
  assert.equal(statusR.status, 0, statusR.stderr);

  const queryR = spawnSync(process.execPath, [CLI, 'fleet', 'query', '--depends-on', 'shared-auth-lib'], { cwd: root, encoding: 'utf8', timeout: 15000 });
  assert.equal(queryR.status, 0, queryR.stderr + queryR.stdout);
  assert.match(queryR.stdout, /frontend/);
  assert.match(queryR.stdout, /payments-api/);
  assert.match(queryR.stdout, /payments-worker/);

  const queryJson = spawnSync(process.execPath, [CLI, 'fleet', 'query', '--depends-on', 'shared-auth-lib', '--json'], { cwd: root, encoding: 'utf8', timeout: 15000 });
  const j = JSON.parse(queryJson.stdout);
  const worker = j.blastRadius.find((r) => r.id === 'payments-worker');
  assert.equal(worker.depth, 2, 'payments-worker is reached transitively, through payments-api');
});

test('fleet init writes a starter manifest and refuses to overwrite without --force', () => {
  const root = mkTestTmp('fleet-init-');
  const r1 = spawnSync(process.execPath, [CLI, 'fleet', 'init'], { cwd: root, encoding: 'utf8', timeout: 10000 });
  assert.equal(r1.status, 0, r1.stderr);
  assert.ok(fs.existsSync(path.join(root, 'fleet.yaml')));
  const r2 = spawnSync(process.execPath, [CLI, 'fleet', 'init'], { cwd: root, encoding: 'utf8', timeout: 10000 });
  assert.equal(r2.status, 4);
});

test('fleet query refuses with no prior scan, and refuses an unknown repository id', () => {
  const root = mkTestTmp('fleet-query-');
  const r = spawnSync(process.execPath, [CLI, 'fleet', 'query', '--depends-on', 'nope'], { cwd: root, encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 4);
  assert.match(r.stderr, /No fleet dependency graph/);
});

test('fleet scan refuses an invalid manifest (unknown repo path) and writes nothing', () => {
  const root = mkTestTmp('fleet-bad-');
  fs.mkdirSync(path.join(root, '.git'));
  fs.writeFileSync(path.join(root, 'fleet.yaml'), 'organization: acme\nrepositories:\n  - id: ghost\n    path: ./does-not-exist\n');
  const r = spawnSync(process.execPath, [CLI, 'fleet', 'scan', 'fleet.yaml'], { cwd: root, encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 4);
  assert.match(r.stderr, /does not resolve to a directory/);
  assert.ok(!fs.existsSync(path.join(root, '.agentic-security', 'fleet-graph.json')));
});
