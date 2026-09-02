// graph-diff.test.js — sub-project 8b, Task 1. Real graphs via
// buildGraphWithCoverage, real git-committed GraphSnapshots via
// persistGraphSnapshot (mirroring graph-snapshot.test.js's own
// _mkGitRepo helper), a real corpus sweep.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

import { persistGraphSnapshot } from '../../src/lineage/graph-snapshot.js';
import { computeGraphDiff, validateGraphDiff, WATCHED_FLOW_FIELDS } from '../../src/lineage/graph-diff.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';

function _mkGitRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-diff-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  fs.writeFileSync(path.join(dir, 'README.md'), 'x');
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: dir });
  return dir;
}

function _advanceCommit(dir, marker) {
  fs.writeFileSync(path.join(dir, 'marker.txt'), marker);
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', marker], { cwd: dir });
}

function _realGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  return buildGraphWithCoverage(callGraph, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

function _realGraphFromCallGraph(callGraph, opts = {}) {
  return buildGraphWithCoverage(callGraph, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

// ── validateGraphDiff ───────────────────────────────────────────────

test('validateGraphDiff: rejects a malformed record, accepts a well-formed one', () => {
  const bad = validateGraphDiff({ id: 'diff:abc' });
  assert.equal(bad.valid, false);
  assert.ok(bad.errors.length > 0);

  assert.deepEqual(validateGraphDiff(null).valid, false);
  assert.deepEqual(validateGraphDiff('not an object').valid, false);

  const good = {
    id: 'diff:abc123', version: '1.0.0',
    beforeSnapshotId: 'snapshot:before', afterSnapshotId: 'snapshot:after',
    comparability: { comparable: true, reasons: [] },
    added: { nodes: [], edges: [], dataElements: [], flows: [] },
    removed: { nodes: [], edges: [], dataElements: [], flows: [] },
    changed: { flows: [] },
    generatedAt: '1970-01-01T00:00:00.000Z',
  };
  const goodResult = validateGraphDiff(good);
  assert.deepEqual(goodResult.errors, []);
  assert.equal(goodResult.valid, true);
});

test('validateGraphDiff: rejects a malformed added/removed/changed entry', () => {
  const base = {
    id: 'diff:abc123', version: '1.0.0',
    beforeSnapshotId: 'snapshot:before', afterSnapshotId: 'snapshot:after',
    comparability: { comparable: true, reasons: [] },
    added: { nodes: [], edges: [], dataElements: [], flows: [{ id: 'flow:x' }] }, // missing causeClassification/firstSeen
    removed: { nodes: [], edges: [], dataElements: [], flows: [] },
    changed: { flows: [] },
    generatedAt: '1970-01-01T00:00:00.000Z',
  };
  const { valid, errors } = validateGraphDiff(base);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path.includes('causeClassification')));
  assert.ok(errors.some((e) => e.path.includes('firstSeen')));
});

// ── computeGraphDiff: refuses on incomparable snapshots ────────────

test('computeGraphDiff: REFUSES (throws, names the reason) on two snapshots with different schemaVersion — never silently diffs them', () => {
  const graph = _realGraph(`function h(req, logger) { logger.info('x', req.body.email); }`);
  const dir = _mkGitRepo();
  try {
    const before = persistGraphSnapshot(graph, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    const after = { ...before, schemaVersion: '999.0.0' };
    assert.throws(() => computeGraphDiff(before, after), /schemaVersion/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('computeGraphDiff: REFUSES on a missing snapshot rather than crashing on a real fault', () => {
  const graph = _realGraph(`function h(req, logger) { logger.info('x', req.body.email); }`);
  const dir = _mkGitRepo();
  try {
    const before = persistGraphSnapshot(graph, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    assert.throws(() => computeGraphDiff(before, null), /missing/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── A real "field newly reaches a sink" case ────────────────────────

test('computeGraphDiff: a field newly reaching a sink appears in added.flows with application_change and a real firstSeen', () => {
  const dir = _mkGitRepo();
  try {
    const graphBefore = _realGraph(`function h(req, logger) { logger.info('static-message'); }`);
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const graphAfter = _realGraph(`function h(req, logger) { logger.info('static-message', req.body.email); }`);
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

    assert.ok(graphAfter.flows.length > graphBefore.flows.length, 'fixture assumption: AFTER must have a genuinely new flow');

    const diff = computeGraphDiff(before, after);
    const { valid, errors } = validateGraphDiff(diff);
    assert.deepEqual(errors, []);
    assert.equal(valid, true);

    assert.ok(diff.added.flows.length >= 1);
    const addedFlow = diff.added.flows[0];
    assert.equal(addedFlow.causeClassification, 'application_change');
    assert.deepEqual(addedFlow.firstSeen, { commit: after.commit, capturedAt: after.capturedAt });
    // the added flow id must be a real flow id from the AFTER graph, not
    // present in the BEFORE graph.
    assert.ok(graphAfter.flows.some((f) => f.id === addedFlow.id));
    assert.ok(!graphBefore.flows.some((f) => f.id === addedFlow.id));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── AC-27's own worked example: PHI newly reaching an AI sink ──────

// Reused verbatim from decision-story.test.js/export-briefing.test.js's
// own PHI_TO_AI_SOURCE fixture — the real, established shape for
// "PHI -> ai-model-provider" in this codebase.
const PHI_TO_AI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

// A companion snippet with the same sink call site present (so the sink
// node exists in both graphs) but the PHI flow itself absent — the
// message content is a static literal, not params.arguments.patient_record.
const AI_SINK_NO_PHI_SOURCE = `function summarizePatient(anthropic, params) {
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: 'static-content' }],
  });
}
`;

test('computeGraphDiff: AC-27 worked example — a PHI field newly reaching an AI-model-provider sink surfaces in added.flows with real dataElement/sink info', () => {
  const dir = _mkGitRepo();
  try {
    const graphBefore = _realGraph(AI_SINK_NO_PHI_SOURCE);
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const graphAfter = _realGraph(PHI_TO_AI_SOURCE);
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

    assert.ok(graphAfter.flows.length >= 1, 'fixture assumption drifted: expected a real PHI->AI flow in AFTER');

    const diff = computeGraphDiff(before, after);
    assert.equal(validateGraphDiff(diff).valid, true);

    assert.ok(diff.added.flows.length >= 1);
    const addedFlow = diff.added.flows[0];
    assert.equal(addedFlow.causeClassification, 'application_change');

    // Recover the real dataElement/sink info from the AFTER graph's own
    // entities, keyed by the added flow's id.
    const realFlow = graphAfter.flows.find((f) => f.id === addedFlow.id);
    assert.ok(realFlow, 'the added flow id must resolve to a real flow in the AFTER graph');
    const de = graphAfter.dataElements.find((d) => realFlow.dataElementIds.includes(d.id));
    assert.ok(de, 'the added flow must reference a real dataElement');
    assert.ok(de.dataClasses.includes('PHI'), 'the referenced dataElement must be classified PHI');
    const sinkNode = graphAfter.nodes.find((n) => n.id === realFlow.sink);
    assert.ok(sinkNode, 'the added flow must reference a real sink node');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── A real protectionSummary/policyVerdict change on a STABLE flow id ─

test('computeGraphDiff: a real policyVerdict change on a stable flow id appears in changed.flows, not added+removed', () => {
  const source = `
    function track(req, analytics) {
      const email = req.body.email;
      analytics.track('signup', { email });
    }
  `;
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);

  const graphBefore = _realGraphFromCallGraph(callGraph); // no policy -> not_evaluated
  const policy = { allow: [{ sink: 'analytics', class: 'PII', environment: 'production', reason: 'test' }] };
  const graphAfter = _realGraphFromCallGraph(callGraph, { privacySinkPolicy: policy, environment: 'production' });

  assert.equal(graphBefore.flows.length, 1);
  assert.equal(graphAfter.flows.length, 1);
  assert.equal(graphBefore.flows[0].id, graphAfter.flows[0].id, 'fixture assumption: flow identity must be stable across a pure policy-config change');
  assert.equal(graphBefore.flows[0].policyVerdict, 'not_evaluated');
  assert.equal(graphAfter.flows[0].policyVerdict, 'permitted');

  const dir = _mkGitRepo();
  try {
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

    const diff = computeGraphDiff(before, after);
    assert.equal(validateGraphDiff(diff).valid, true);

    assert.deepEqual(diff.added.flows, []);
    assert.deepEqual(diff.removed.flows, []);
    assert.equal(diff.changed.flows.length, 1);
    const changedFlow = diff.changed.flows[0];
    assert.equal(changedFlow.id, graphBefore.flows[0].id);
    assert.equal(changedFlow.causeClassification, 'application_change');
    const policyChange = changedFlow.changes.find((c) => c.field === 'policyVerdict');
    assert.ok(policyChange, 'the changes array must name the exact watched field that changed');
    assert.equal(policyChange.before, 'not_evaluated');
    assert.equal(policyChange.after, 'permitted');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── A real coverage-regression case ─────────────────────────────────

test('computeGraphDiff: a removed flow is tagged possible_coverage_regression when AFTER coverage is genuinely lower, not a clean application_change', () => {
  const BEFORE_SOURCE = `
    function h1(req, logger) { logger.info('x', req.body.email); }
    function h2(req, db) { db.query(req.body.ssn); }
  `;
  const AFTER_SOURCE = `
    function h1(req, logger) { logger.info('x', req.body.email); }
  `;

  const dir = _mkGitRepo();
  try {
    const graphBefore = _realGraph(BEFORE_SOURCE);
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const graphAfter = _realGraph(AFTER_SOURCE);
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

    assert.ok(graphAfter.coverage.sources.matched < graphBefore.coverage.sources.matched, 'fixture assumption: AFTER must genuinely regress source coverage');
    assert.ok(graphBefore.flows.length > graphAfter.flows.length, 'fixture assumption: a flow must genuinely disappear');

    const diff = computeGraphDiff(before, after);
    assert.equal(validateGraphDiff(diff).valid, true);

    assert.ok(diff.removed.flows.length >= 1);
    const regressed = diff.removed.flows.find((f) => f.causeClassification === 'possible_coverage_regression');
    assert.ok(regressed, 'at least one removed flow must be tagged possible_coverage_regression');
    assert.ok(regressed.coverageRegressionReasons.length > 0);
    assert.match(regressed.coverageRegressionReasons.join(' '), /sources\.matched/);
    assert.deepEqual(regressed.lastSeen, { commit: before.commit, capturedAt: before.capturedAt });

    // Judgment call (see graph-diff.js's own header, #2): the
    // coverage-regression signal is scoped to removed FLOW entries only
    // — a removed node/dataElement (h2's own db.query sink node and the
    // ssn dataElement, both real in this fixture) always reads
    // application_change, never possible_coverage_regression, since no
    // coverage-completeness signal exists at that granularity.
    assert.ok(diff.removed.nodes.length >= 1, 'fixture assumption: h2 disappearing must also remove its own sink node');
    for (const n of diff.removed.nodes) assert.equal(n.causeClassification, 'application_change');
    assert.ok(diff.removed.dataElements.length >= 1, 'fixture assumption: h2 disappearing must also remove its own dataElement');
    for (const d of diff.removed.dataElements) assert.equal(d.causeClassification, 'application_change');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('computeGraphDiff: a removed flow with NO coverage regression is a clean application_change', () => {
  // The field is still read (assigned to an unused local, so it still
  // matches as a source — coverage.sources.matched stays 2) and the sink
  // call site itself still exists (coverage.sinks.callStatementSites
  // stays 2) — only the ARGUMENT was dropped from that one call, severing
  // just that one flow. A genuine application-level removal with zero
  // measurable coverage delta, never an engine-coverage artifact.
  const BEFORE_SOURCE = `
    function h(req, logger) {
      logger.info('x', req.body.email);
      logger.warn('y', req.body.name);
    }
  `;
  const AFTER_SOURCE = `
    function h(req, logger) {
      const email = req.body.email;
      logger.info('x');
      logger.warn('y', req.body.name);
    }
  `;

  const dir = _mkGitRepo();
  try {
    const graphBefore = _realGraph(BEFORE_SOURCE);
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const graphAfter = _realGraph(AFTER_SOURCE);
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

    assert.equal(graphAfter.coverage.sources.matched, graphBefore.coverage.sources.matched, 'fixture assumption: sources.matched must stay level');
    assert.equal(graphAfter.coverage.sinks.callStatementSites, graphBefore.coverage.sinks.callStatementSites, 'fixture assumption: sinks.callStatementSites must stay level');
    assert.ok(graphBefore.flows.length > graphAfter.flows.length, 'fixture assumption: a flow must genuinely disappear');

    const diff = computeGraphDiff(before, after);
    assert.ok(diff.removed.flows.length >= 1);
    for (const f of diff.removed.flows) {
      assert.equal(f.causeClassification, 'application_change');
      assert.equal(f.coverageRegressionReasons, undefined);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── WATCHED_FLOW_FIELDS is a real, disclosed list ───────────────────

test('WATCHED_FLOW_FIELDS names the real flow schema fields plus governanceRefs', () => {
  assert.deepEqual(WATCHED_FLOW_FIELDS, [
    'protectionSummary', 'policyVerdict', 'handling', 'coverageStatus', 'governanceRefs',
  ]);
});

// ── REAL CORPUS sweep ────────────────────────────────────────────────

test('REAL CORPUS: computeGraphDiff never throws unexpectedly and every produced record validates, across all bench/data-lineage/ fixtures (each persisted at two commits)', async () => {
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

      const before = persistGraphSnapshot(graph, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
      _advanceCommit(dir, fixtureId);
      const after = persistGraphSnapshot(graph, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

      assert.doesNotThrow(() => {
        const diff = computeGraphDiff(before, after);
        const { valid, errors } = validateGraphDiff(diff);
        assert.ok(valid, `${fixtureId}: produced an invalid GraphDiff: ${JSON.stringify(errors)}`);
        // Same graph persisted twice -> genuinely nothing changed.
        assert.deepEqual(diff.added, { nodes: [], edges: [], dataElements: [], flows: [] }, `${fixtureId}: unexpected additions diffing a graph against itself`);
        assert.deepEqual(diff.removed, { nodes: [], edges: [], dataElements: [], flows: [] }, `${fixtureId}: unexpected removals diffing a graph against itself`);
        assert.deepEqual(diff.changed, { flows: [] }, `${fixtureId}: unexpected changes diffing a graph against itself`);
      }, `${fixtureId}: computeGraphDiff threw`);
      checked++;
    }
    assert.ok(checked > 0, 'the sweep must exercise at least one real fixture, or this test is vacuous');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
