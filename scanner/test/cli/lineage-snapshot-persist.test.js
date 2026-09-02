// M4 deliverable #8 (FR-503 §14, DFG-022, sub-project 8a): proves the
// GraphSnapshot history is persisted ADDITIVELY alongside the existing
// single-current-graph artifact during a real scan, and that `reset --yes`
// deletes both. End-to-end CLI-level test — invokes the real
// `agentic-security scan`/`reset` subcommands as subprocesses, mirroring
// test/lineage-artifact-write.test.js's own real-scan-then-check-disk
// pattern (spawnSync over the real bin, a temp dir carrying just a
// package.json project marker, target passed as an absolute path).
//
// Unlike lineage-artifact-write.test.js's own fixture, this one is a REAL
// git repo — persistGraphSnapshot() keys its history file by the real git
// HEAD (src/lineage/graph-snapshot.js's own header explains why: the
// graph's own graphId always embeds the literal string 'uncommitted'
// today, so the snapshot file NAME has to come from git directly), and this
// test asserts the exact HEAD-named file exists.
//
// `scan`'s own exit code is severity-based, not a pass/fail signal
// (report/index.js's exitCodeFor: 0 clean, 1 low/medium, 2 high, 3
// critical). Only >=4 means a genuine engine error. So these tests assert
// the scan did not crash (`run.error === undefined` and `run.status < 4`),
// never that it exited 0.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const BIN = path.join(SCANNER, 'bin', 'agentic-security.js');

function mkGitFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lineage-snapshot-cli-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
  fs.writeFileSync(path.join(dir, 'app.js'),
    "function h(req, res){ const pw = req.body.password; res.send(pw); }");
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: dir });
  return dir;
}

test('8a/persist-1: a real scan with AGENTIC_SECURITY_LINEAGE_DEEP=1 writes BOTH lineage-graph.json (unchanged) AND a commit-keyed lineage-snapshots/<HEAD>.json', async () => {
  const dir = mkGitFixture();
  try {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();

    const run = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], {
      env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
      encoding: 'utf8',
    });
    assert.equal(run.error, undefined, `scan failed to spawn: ${run.error?.message}`);
    assert.ok(run.status < 4, `scan reported an engine error (exit ${run.status}): stderr=${run.stderr}`);

    // Unchanged behavior: the single-current-graph artifact is still written.
    const graphPath = path.join(dir, '.agentic-security', 'lineage-graph.json');
    assert.ok(fs.existsSync(graphPath), 'lineage-graph.json must still exist (unchanged behavior)');

    // New: the SAME graph is also persisted into commit-keyed history.
    const snapshotPath = path.join(dir, '.agentic-security', 'lineage-snapshots', `${head}.json`);
    assert.ok(fs.existsSync(snapshotPath), `lineage-snapshots/${head}.json must exist`);

    const snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
    assert.equal(snapshot.commit, head);
    assert.ok(snapshot.id.startsWith('snapshot:'));
    assert.ok(snapshot.graph && Array.isArray(snapshot.graph.nodes), 'the persisted snapshot must carry the real DataFlowGraph v1 document');

    const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
    assert.deepEqual(snapshot.graph, graph, 'the snapshot must carry the SAME graph as lineage-graph.json, not a second, drifting copy');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('8a/persist-2: `agentic-security reset --yes` deletes both lineage-graph.json and lineage-snapshots/', async () => {
  const dir = mkGitFixture();
  try {
    const scanRun = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], {
      env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
      encoding: 'utf8',
    });
    assert.equal(scanRun.error, undefined, `scan failed to spawn: ${scanRun.error?.message}`);
    assert.ok(scanRun.status < 4, `scan reported an engine error (exit ${scanRun.status}): stderr=${scanRun.stderr}`);

    const graphPath = path.join(dir, '.agentic-security', 'lineage-graph.json');
    const snapshotsDir = path.join(dir, '.agentic-security', 'lineage-snapshots');
    assert.ok(fs.existsSync(graphPath), 'precondition: lineage-graph.json must exist before reset');
    assert.ok(fs.existsSync(snapshotsDir), 'precondition: lineage-snapshots/ must exist before reset');

    const resetRun = spawnSync(process.execPath, [BIN, 'reset', '--yes', '--root', dir], { encoding: 'utf8' });
    assert.equal(resetRun.error, undefined, `reset failed to spawn: ${resetRun.error?.message}`);
    assert.equal(resetRun.status, 0, `reset exited non-zero: stdout=${resetRun.stdout} stderr=${resetRun.stderr}`);

    assert.ok(!fs.existsSync(graphPath), 'lineage-graph.json must be deleted by reset --yes');
    assert.ok(!fs.existsSync(snapshotsDir), 'lineage-snapshots/ must be deleted by reset --yes');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});
