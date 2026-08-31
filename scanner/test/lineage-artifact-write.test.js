// Sub-project E, increment 5 (Task 3): proves the lineage graph is persisted
// as its own signed artifact under .agentic-security/, and never duplicated
// inside last-scan.json. End-to-end CLI-level test — invokes the real
// `agentic-security scan` subcommand as a subprocess, mirroring
// test/no-stray-state.test.js's own CLI-invocation shape (spawnSync over the
// real bin, a temp dir carrying just a package.json project marker, target
// passed as an absolute path).
//
// `scan`'s own exit code is severity-based, not a pass/fail signal
// (report/index.js's exitCodeFor: 0 clean, 1 low/medium, 2 high, 3
// critical — measured live against this file's own fixture, which trips a
// finding and exits 1). Only >=4 means a genuine engine error, same
// convention cmdShip's own comment documents. So these tests assert the
// scan did not crash (`run.error === undefined` and `run.status < 4`),
// never that it exited 0.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const BIN = path.join(SCANNER, 'bin', 'agentic-security.js');

test('E5/artifact-1: a scan with AGENTIC_SECURITY_LINEAGE_DEEP=1 writes a signed lineage-graph.json under .agentic-security/, never duplicated in last-scan.json', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'lineage-artifact-'));
  try {
    await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
    await fsp.writeFile(path.join(dir, 'app.js'),
      "function h(req, res){ const pw = req.body.password; res.send(pw); }");

    const run = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], {
      env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
      encoding: 'utf8',
    });

    assert.equal(run.error, undefined, `scan failed to spawn: ${run.error?.message}`);
    assert.ok(run.status < 4, `scan reported an engine error (exit ${run.status}): stderr=${run.stderr}`);

    const graphPath = path.join(dir, '.agentic-security', 'lineage-graph.json');
    const sigPath = graphPath + '.sig';
    assert.ok(fs.existsSync(graphPath), 'lineage-graph.json must exist');
    assert.ok(fs.existsSync(sigPath), 'lineage-graph.json.sig must exist');

    const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
    assert.ok(graph.nodes && Array.isArray(graph.nodes), 'lineage-graph.json must be a DataFlowGraph v1 document');

    const lastScan = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
    assert.equal(lastScan.lineageGraph, undefined, 'lineageGraph must never be duplicated inside last-scan.json');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('E5/artifact-2: an ordinary scan (AGENTIC_SECURITY_LINEAGE_DEEP unset) writes no lineage-graph.json at all', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'lineage-artifact-off-'));
  try {
    await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
    await fsp.writeFile(path.join(dir, 'app.js'),
      "function h(req, res){ const pw = req.body.password; res.send(pw); }");

    const env = { ...process.env };
    delete env.AGENTIC_SECURITY_LINEAGE_DEEP;
    const run = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], {
      env,
      encoding: 'utf8',
    });

    assert.equal(run.error, undefined, `scan failed to spawn: ${run.error?.message}`);
    assert.ok(run.status < 4, `scan reported an engine error (exit ${run.status}): stderr=${run.stderr}`);

    const graphPath = path.join(dir, '.agentic-security', 'lineage-graph.json');
    assert.ok(!fs.existsSync(graphPath), 'lineage-graph.json must not be written when AGENTIC_SECURITY_LINEAGE_DEEP is unset');
    assert.ok(fs.existsSync(path.join(dir, '.agentic-security', 'last-scan.json')), 'last-scan.json must still be written as usual');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});
