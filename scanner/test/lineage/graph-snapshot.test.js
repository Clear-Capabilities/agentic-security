import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  validateGraphSnapshot, persistGraphSnapshot, loadSnapshots, loadSnapshot,
  mostRecentPriorSnapshot, snapshotsComparable,
} from '../../src/lineage/graph-snapshot.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';

function _mkGitRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-snapshot-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  fs.writeFileSync(path.join(dir, 'README.md'), 'x');
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: dir });
  return dir;
}

function _realGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  return buildGraphWithCoverage(callGraph, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

const SOURCE_A = `function h(req, logger) { logger.info('x', req.body.email); }`;

test('validateGraphSnapshot: rejects a record missing a required §10.10 field, accepts a well-formed one', () => {
  const bad = validateGraphSnapshot({ id: 'snapshot:abc' });
  assert.equal(bad.valid, false);
  assert.ok(bad.errors.length > 0);

  const good = validateGraphSnapshot({
    id: 'snapshot:abc123', version: '1', graphId: 'dfg:r:abc:default',
    schemaVersion: '1.0.0', commit: 'abc123', capturedAt: '1970-01-01T00:00:00.000Z',
    coverage: {}, graph: {},
  });
  assert.deepEqual(good.errors, []);
  assert.equal(good.valid, true);
});

test('persistGraphSnapshot: writes a real, valid GraphSnapshot keyed by the REAL git HEAD, never the graph\'s own always-"uncommitted" graphId', () => {
  const repo = _mkGitRepo();
  try {
    const graph = _realGraph(SOURCE_A);
    assert.ok(graph.graphId.includes(':uncommitted:'), 'fixture assumption: buildGraphWithCoverage never receives a real commit today — confirms the plan\'s own Global Constraint');

    const snap = persistGraphSnapshot(graph, repo, { capturedAt: '2020-01-01T00:00:00.000Z' });
    const { valid, errors } = validateGraphSnapshot(snap);
    assert.deepEqual(errors, []);
    assert.equal(valid, true);
    assert.notEqual(snap.commit, 'uncommitted', 'must resolve the REAL git HEAD, not the graph\'s own literal default');

    const realHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim();
    assert.equal(snap.commit, realHead);

    const onDisk = fs.readFileSync(path.join(repo, '.agentic-security', 'lineage-snapshots', `${realHead}.json`), 'utf8');
    assert.deepEqual(JSON.parse(onDisk), snap);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('persistGraphSnapshot: with no git repo, falls back to a content-hash key, matching sbom-diff.js\'s own precedent', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-snapshot-nogit-'));
  try {
    const graph = _realGraph(SOURCE_A);
    const snap = persistGraphSnapshot(graph, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    assert.ok(snap.commit.length > 0);
    assert.notEqual(snap.commit, 'uncommitted');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('loadSnapshots + mostRecentPriorSnapshot: real round trip across two real commits', () => {
  const repo = _mkGitRepo();
  try {
    const graphA = _realGraph(SOURCE_A);
    const snapA = persistGraphSnapshot(graphA, repo, { capturedAt: '2020-01-01T00:00:00.000Z' });

    fs.writeFileSync(path.join(repo, 'README.md'), 'y');
    execFileSync('git', ['add', '.'], { cwd: repo });
    execFileSync('git', ['commit', '-q', '-m', 'second'], { cwd: repo });
    const graphB = _realGraph(`function h(req, logger, db) { logger.info('x', req.body.email); db.query(req.body.email); }`);
    const snapB = persistGraphSnapshot(graphB, repo, { capturedAt: '2020-01-02T00:00:00.000Z' });

    assert.notEqual(snapA.commit, snapB.commit, 'fixture assumption: two real commits must produce two distinct keys');

    const all = loadSnapshots(repo);
    assert.equal(all.length, 2);
    assert.deepEqual(all.map((s) => s.commit).sort(), [snapA.commit, snapB.commit].sort());

    assert.deepEqual(loadSnapshot(repo, snapA.commit), snapA);

    const prior = mostRecentPriorSnapshot(repo, snapB.commit);
    assert.deepEqual(prior, snapA, 'the most recent PRIOR snapshot, excluding the current one, must be snapA');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('loadSnapshots: an empty/nonexistent history directory returns [], never throws', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-snapshot-empty-'));
  try {
    assert.deepEqual(loadSnapshots(dir), []);
    assert.equal(loadSnapshot(dir, 'anything'), null);
    assert.equal(mostRecentPriorSnapshot(dir, 'anything'), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('snapshotsComparable: same schemaVersion is comparable; a real, disclosed mismatch is not', () => {
  const graph = _realGraph(SOURCE_A);
  const a = persistGraphSnapshot(graph, _mkGitRepo(), { capturedAt: '2020-01-01T00:00:00.000Z' });
  const b = persistGraphSnapshot(graph, _mkGitRepo(), { capturedAt: '2020-01-02T00:00:00.000Z' });
  assert.deepEqual(snapshotsComparable(a, b), { comparable: true, reasons: [] });

  const mismatched = { ...b, schemaVersion: '2.0.0' };
  const result = snapshotsComparable(a, mismatched);
  assert.equal(result.comparable, false);
  assert.ok(result.reasons.length > 0);
  assert.match(result.reasons[0], /schemaVersion/);
});

test('snapshotsComparable: a missing snapshot is honestly not comparable, never a crash', () => {
  const graph = _realGraph(SOURCE_A);
  const a = persistGraphSnapshot(graph, _mkGitRepo(), { capturedAt: '2020-01-01T00:00:00.000Z' });
  assert.deepEqual(snapshotsComparable(a, null), { comparable: false, reasons: ['one or both snapshots are missing'] });
  assert.deepEqual(snapshotsComparable(null, null), { comparable: false, reasons: ['one or both snapshots are missing'] });
});

test('REAL CORPUS: sweeping bench/data-lineage/ fixtures never throws persisting or loading a snapshot', async () => {
  const { buildFixtureGraph } = await import('../../../bench/data-lineage/runner.mjs');
  const fs2 = await import('node:fs');
  const path2 = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const __dirname = path2.dirname(fileURLToPath(import.meta.url));
  const FIXTURES_ROOT = path2.join(__dirname, '../../../bench/data-lineage/fixtures');
  const fixtureIds = fs2.readdirSync(FIXTURES_ROOT).filter((f) => fs2.statSync(path2.join(FIXTURES_ROOT, f)).isDirectory());
  assert.ok(fixtureIds.length > 0);
  const dir = _mkGitRepo();
  try {
    let checked = 0;
    for (const fixtureId of fixtureIds) {
      const srcPath = path2.join(FIXTURES_ROOT, fixtureId, 'source.js');
      if (!fs2.existsSync(srcPath)) continue;
      const source = fs2.readFileSync(srcPath, 'utf8');
      const graph = buildFixtureGraph(fixtureId, source);
      assert.doesNotThrow(() => {
        const snap = persistGraphSnapshot(graph, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
        const { valid } = validateGraphSnapshot(snap);
        assert.ok(valid, `${fixtureId}: produced an invalid GraphSnapshot`);
      }, `${fixtureId}: persistGraphSnapshot threw`);
      checked++;
    }
    assert.ok(checked > 0, 'the sweep must exercise at least one real fixture, or this test is vacuous');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
