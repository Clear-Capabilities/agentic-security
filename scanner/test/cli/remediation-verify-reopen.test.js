// CLI subprocess tests for `agentic-security remediation verify` /
// `reopen-check` — M5 deliverable #6 (Blast-Radius: Remediation Command
// Center), Task 4. THE AC-31-CRITICAL HALF: these two verbs are the only
// thing that makes AC-31 genuinely true — "marking work complete never
// sets verified," "only a real rescan or an explicitly-permitted manual
// attestation can," and "a later regression automatically reopens it."
//
// Modelled on `test/cli/remediation-open-update.test.js`'s own structure
// (a `_mkTmpProject()` helper writing a `package.json` marker;
// `spawnSync(process.execPath, [CLI, ...], {encoding:'utf8', timeout})`).
// Every test here hand-writes TWO real, persisted GraphSnapshot records
// (a real before/after pair is what verification needs) directly under
// `statePath(root, 'lineage-snapshots', '<commit>.json')`, with explicit
// mtimes so `loadSnapshots`' newest-first ordering is deterministic
// regardless of filesystem timestamp resolution.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { statePath } from '../../src/posture/state-dir.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const TIMEOUT = 20_000;

function _mkTmpProject(prefix = 'agsec-remediation-verify-cli-') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _run(argv) {
  return spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8', timeout: TIMEOUT });
}

function _ledgerPath(root) { return statePath(root, 'remediation', 'items.jsonl'); }
function _auditLogPath(root) { return statePath(root, 'mcp-audit.log'); }
function _ledgerLines(root) {
  const p = _ledgerPath(root);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
}
function _auditContent(root) {
  return fs.existsSync(_auditLogPath(root)) ? fs.readFileSync(_auditLogPath(root), 'utf8') : '';
}

// Hand-writes a real GraphSnapshot-shaped record. `mtimeSeconds` controls
// ordering deterministically (loadSnapshots sorts newest-mtime-first) —
// pass strictly increasing values for a sequence of snapshots.
function _writeSnapshot(root, { commit, capturedAt, schemaVersion = '1.0.0', graphId = 'graph:test-repo', graph, coverage = {}, mtimeSeconds }) {
  const dir = statePath(root, 'lineage-snapshots');
  fs.mkdirSync(dir, { recursive: true });
  const snapshot = {
    id: `snapshot:${commit}`,
    version: '1.0.0',
    graphId,
    schemaVersion,
    commit,
    capturedAt,
    coverage,
    graph,
  };
  const full = path.join(dir, `${commit}.json`);
  fs.writeFileSync(full, JSON.stringify(snapshot, null, 2));
  const t = new Date(mtimeSeconds * 1000);
  fs.utimesSync(full, t, t);
  return snapshot;
}

function _flow(id, source, sink, dataElementIds, extra = {}) {
  return {
    id, source, sink, dataElementIds,
    protectionSummary: extra.protectionSummary ?? 'not_assessed',
    policyVerdict: extra.policyVerdict ?? 'not_evaluated',
    handling: extra.handling ?? 'unknown',
    coverageStatus: extra.coverageStatus ?? 'modeled',
  };
}

function _coverage(sourcesMatched, sinkSites) {
  return { sources: { matched: sourcesMatched }, sinks: { callStatementSites: sinkSites }, languages: [{ language: 'js', filesAnalyzed: 10 }] };
}

function _assessment(overrides = {}) {
  return {
    id: 'impact:test123abc',
    version: '1.0.0',
    graphId: 'graph:test-repo',
    graphDigest: 'digest-abc123',
    targetId: 'flow:target',
    targetKind: 'flow',
    scope: 'possible',
    traceKind: 'flow_restricted',
    affectedNodeIds: [],
    affectedEdgeIds: [],
    affectedDataClasses: [],
    affectedRecipientProfileIds: [],
    coverageLimitations: [],
    generatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function _openArgs(root, assessmentPath, extra = {}) {
  return [
    'remediation', 'open', root,
    '--assessment', assessmentPath,
    '--owner', 'alice',
    '--due', '2026-12-31',
    '--control', 'Add field-level encryption and rotate credentials',
    '--required-evidence', extra.requiredEvidence ?? 'flow:target',
    ...(extra.id ? ['--id', extra.id] : []),
    ...(extra.allowManualAttestation ? ['--allow-manual-attestation'] : []),
    ...(extra.yes !== false ? ['--yes'] : []),
  ];
}

// Opens an item (against whatever snapshot is currently newest) and
// drives it to awaiting_verification via the real Task-3 CLI verbs.
function _openAndDriveToAwaitingVerification(root, assessmentPath, itemId, opts = {}) {
  const open = _run(_openArgs(root, assessmentPath, { id: itemId, requiredEvidence: opts.requiredEvidence, allowManualAttestation: opts.allowManualAttestation }));
  assert.equal(open.status, 0, `open failed: ${open.stderr}`);
  const toInProgress = _run(['remediation', 'update', root, '--id', itemId, '--state', 'in_progress', '--yes']);
  assert.equal(toInProgress.status, 0, `update to in_progress failed: ${toInProgress.stderr}`);
  if (opts.stopAtInProgress) return;
  const toAwaiting = _run(['remediation', 'update', root, '--id', itemId, '--state', 'awaiting_verification', '--yes']);
  assert.equal(toAwaiting.status, 0, `update to awaiting_verification failed: ${toAwaiting.stderr}`);
}

function _listItem(root, itemId) {
  const r = _run(['remediation', 'list', root, '--format', 'json']);
  assert.equal(r.status, 0, r.stderr);
  const { items } = JSON.parse(r.stdout);
  return items.find((i) => i.id === itemId);
}

// === V/1 — happy path =======================================================

test('remediation verify: happy path — required-evidence flow gone, no coverage regression -> verified (V/1)', () => {
  const root = _mkTmpProject();
  const s1 = _writeSnapshot(root, {
    commit: 'before1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000,
    coverage: _coverage(5, 3),
    graph: {
      graphId: 'graph:test-repo', schemaVersion: '1.0.0',
      nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
      edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
      flows: [_flow('flow:target', 'node:src', 'node:sink', ['data:card'])],
    },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v1');

  const s2 = _writeSnapshot(root, {
    commit: 'after1', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000,
    coverage: _coverage(5, 3), // no regression
    graph: {
      graphId: 'graph:test-repo', schemaVersion: '1.0.0',
      nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
      edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
      flows: [], // fixed — flow:target is gone
    },
  });

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v1', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.written, true);
  assert.equal(report.evidenceOutcome.outcome, 'verified');
  assert.equal(report.beforeSnapshotId, s1.id);
  assert.equal(report.afterSnapshotId, s2.id);
  assert.equal(report.beforeSnapshotSource, 'incident');

  const item = _listItem(root, 'rem-v1');
  assert.equal(item.state, 'verified');
  assert.equal(item.verificationSnapshotId, s2.id);

  // A/1: a real remediation_verify audit event on a real --yes verify.
  const audit = _auditContent(root);
  assert.match(audit, /remediation_verify/);
  assert.match(audit, /"outcome":"ok"/);
});

// === V/2 — coverage regression (PRD line 1975) ==============================

test('remediation verify: after-snapshot coverage regression -> unverifiable, item stays awaiting_verification (V/2)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'before2', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000,
    coverage: _coverage(5, 3),
    graph: {
      graphId: 'graph:test-repo', schemaVersion: '1.0.0',
      nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
      edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
      flows: [_flow('flow:target', 'node:src', 'node:sink', ['data:card'])],
    },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v2');

  _writeSnapshot(root, {
    commit: 'after2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000,
    coverage: _coverage(3, 3), // sources.matched REGRESSED 5 -> 3
    graph: {
      graphId: 'graph:test-repo', schemaVersion: '1.0.0',
      nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
      edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
      flows: [], // also "gone" -- but the scan is honestly incomplete
    },
  });

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v2', '--yes']);
  assert.equal(r.status, 0, r.stderr); // an unverifiable outcome is a recorded event, never a non-zero exit
  const report = JSON.parse(r.stdout);
  assert.equal(report.written, true);
  assert.equal(report.evidenceOutcome.outcome, 'unverifiable');
  assert.equal(report.evidenceOutcome.reason, 'possible_coverage_regression');
  assert.ok(Array.isArray(report.evidenceOutcome.coverageRegressionReasons) && report.evidenceOutcome.coverageRegressionReasons.length > 0);

  const item = _listItem(root, 'rem-v2');
  assert.equal(item.state, 'awaiting_verification');
  assert.equal(item.verificationSnapshotId, null);

  // The ledger must show verification was attempted and refused.
  const lines = _ledgerLines(root);
  const last = JSON.parse(lines[lines.length - 1]);
  assert.equal(last.type, 'scan_verification');
  assert.equal(last.outcome, 'unverifiable');
});

// === V/3 — flow still present ===============================================

test('remediation verify: required-evidence flow still present in after -> unverifiable/flows_still_present (V/3)', () => {
  const root = _mkTmpProject();
  const graphWithFlow = {
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
    flows: [_flow('flow:target', 'node:src', 'node:sink', ['data:card'])],
  };
  _writeSnapshot(root, { commit: 'before3', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: graphWithFlow });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v3');

  _writeSnapshot(root, { commit: 'after3', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graphWithFlow });

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v3', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.evidenceOutcome.outcome, 'unverifiable');
  assert.equal(report.evidenceOutcome.reason, 'flows_still_present');
  assert.deepEqual(report.evidenceOutcome.unsatisfiedFlowIds, ['flow:target']);

  const item = _listItem(root, 'rem-v3');
  assert.equal(item.state, 'awaiting_verification');
});

// === V/4 — reidentified flow ================================================

test('remediation verify: a reidentified flow (same correlation key, new id) -> unverifiable/reidentified (V/4)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'before4', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000,
    coverage: _coverage(5, 3),
    graph: {
      graphId: 'graph:test-repo', schemaVersion: '1.0.0',
      nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
      edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
      flows: [_flow('flow:old-id', 'node:src', 'node:sink', ['data:card'])],
    },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment({ targetId: 'flow:old-id' })));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v4', { requiredEvidence: 'flow:old-id' });

  _writeSnapshot(root, {
    commit: 'after4', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000,
    coverage: _coverage(5, 3),
    graph: {
      graphId: 'graph:test-repo', schemaVersion: '1.0.0',
      nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
      edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
      // Same (source, sink, dataElementIds) correlation key, DIFFERENT id.
      flows: [_flow('flow:new-id', 'node:src', 'node:sink', ['data:card'])],
    },
  });

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v4', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  // Assert the diff genuinely classified this as a reidentification FIRST,
  // so this case cannot silently degrade into a plain remove+add.
  assert.equal(report.evidenceOutcome.outcome, 'unverifiable');
  assert.equal(report.evidenceOutcome.reason, 'reidentified');
  assert.equal(report.evidenceOutcome.reidentifiedTo, 'flow:new-id');

  const item = _listItem(root, 'rem-v4');
  assert.equal(item.state, 'awaiting_verification');
});

// === V/5 — incomparable snapshots ===========================================

test('remediation verify: incomparable snapshots (differing schemaVersion) -> unverifiable/incomparable_snapshots, never an uncaught throw (V/5)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'before5', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, schemaVersion: '1.0.0',
    coverage: _coverage(5, 3),
    graph: {
      graphId: 'graph:test-repo', schemaVersion: '1.0.0',
      nodes: [], edges: [], dataElements: [],
      flows: [_flow('flow:target', 'node:src', 'node:sink', [])],
    },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v5');

  _writeSnapshot(root, {
    commit: 'after5', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, schemaVersion: '2.0.0', // DIFFERENT
    coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '2.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v5', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.evidenceOutcome.outcome, 'unverifiable');
  assert.equal(report.evidenceOutcome.reason, 'incomparable_snapshots');
  assert.match(String(report.evidenceOutcome.detail ?? ''), /schemaVersion/);

  const item = _listItem(root, 'rem-v5');
  assert.equal(item.state, 'awaiting_verification');
});

// === V/6 — wrong state ======================================================

test('remediation verify: from a state other than awaiting_verification exits 1 and writes nothing (V/6)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'before6', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  // Deliberately left in `open` state -- never driven to in_progress/awaiting_verification.
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-v6' }));
  assert.equal(open.status, 0, open.stderr);

  _writeSnapshot(root, {
    commit: 'after6', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });

  const before = fs.readFileSync(_ledgerPath(root), 'utf8');
  const r = _run(['remediation', 'verify', root, '--id', 'rem-v6', '--yes']);
  assert.equal(r.status, 1);
  const after = fs.readFileSync(_ledgerPath(root), 'utf8');
  assert.equal(after, before, 'no new ledger line for a verify attempted from the wrong state');
});

// === V/7 — manual attestation refused without --allow-manual-attestation ====

test('remediation verify --manual-attestation: refused when the item was opened WITHOUT --allow-manual-attestation (V/7)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'before7', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v7'); // no allowManualAttestation

  const before = fs.readFileSync(_ledgerPath(root), 'utf8');
  const r = _run(['remediation', 'verify', root, '--id', 'rem-v7', '--manual-attestation',
    '--approver', 'alice', '--reason', 'compensating control verified out of band', '--yes']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /--allow-manual-attestation/);
  // M9 (final-review fix round 1): the old message ("reopen with
  // --allow-manual-attestation") described an impossible action -- an
  // existing item's `opened` event cannot be replayed, and
  // reopen/reopen-check is a different concept in this same dispatcher.
  // The corrected message says what's actually possible instead.
  assert.match(r.stderr, /must be opened with --allow-manual-attestation/);
  assert.doesNotMatch(r.stderr, /reopen with --allow-manual-attestation/);
  const after = fs.readFileSync(_ledgerPath(root), 'utf8');
  assert.equal(after, before);
});

// === M15 — --against with --manual-attestation prints a warning but still
// succeeds (it has no effect on this branch) =================================

test('remediation verify --manual-attestation --against: prints a warning that --against has no effect here, still succeeds (M15)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'm15-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-m15', { allowManualAttestation: true });

  const r = _run(['remediation', 'verify', root, '--id', 'rem-m15', '--manual-attestation',
    '--approver', 'alice', '--reason', 'compensating control', '--against', 'm15-s1', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /--against has no effect with --manual-attestation/);
  assert.equal(_listItem(root, 'rem-m15').state, 'verified');
});

// === V/8 — manual attestation permitted =====================================

test('remediation verify --manual-attestation: succeeds when opened WITH --allow-manual-attestation, records manual evidence (V/8)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'before8', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v8', { allowManualAttestation: true });

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v8', '--manual-attestation',
    '--approver', 'alice', '--reason', 'compensating control verified out of band', '--yes']);
  assert.equal(r.status, 0, r.stderr);

  const item = _listItem(root, 'rem-v8');
  assert.equal(item.state, 'verified');
  // B3 (final-review fix round 1): a manual attestation now records the
  // newest available snapshot as its own baseline, so it survives the
  // very next reopen-check instead of being undone by a stale anchor.
  assert.equal(item.verificationSnapshotId, 'snapshot:before8');
  assert.equal(item.approvals.length, 1);
  assert.equal(item.approvals[0].evidenceKind, 'manual');
  assert.equal(item.approvals[0].approver, 'alice');
});

// === V/8b — manual attestation with no snapshot available at attestation time

test('remediation verify --manual-attestation: with no snapshot available at attestation time, still succeeds and leaves verificationSnapshotId null (V/8b)', () => {
  const root = _mkTmpProject();
  // `open` requires a persisted snapshot to fix the incident to, so a
  // snapshot must exist to get this far -- but B3's fix must not REQUIRE
  // one still being on disk at attestation time (e.g. deleted between
  // open and verify, or a genuinely snapshot-less history). Deleting the
  // snapshots directory before attesting exercises exactly that branch.
  _writeSnapshot(root, {
    commit: 'v8b-only', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v8b', { allowManualAttestation: true });

  fs.rmSync(statePath(root, 'lineage-snapshots'), { recursive: true, force: true });

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v8b', '--manual-attestation',
    '--approver', 'alice', '--reason', 'compensating control verified out of band', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const item = _listItem(root, 'rem-v8b');
  assert.equal(item.state, 'verified');
  assert.equal(item.verificationSnapshotId, null); // no snapshot was available to record
});

// === V/9 — manual-attestation argument validation ===========================

test('remediation verify --manual-attestation: missing --approver/--reason exits 2; an unregistered approver exits 1 (V/9)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'before9', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v9', { allowManualAttestation: true });

  const rNoApprover = _run(['remediation', 'verify', root, '--id', 'rem-v9', '--manual-attestation', '--reason', 'x', '--yes']);
  assert.equal(rNoApprover.status, 2);
  const rNoReason = _run(['remediation', 'verify', root, '--id', 'rem-v9', '--manual-attestation', '--approver', 'alice', '--yes']);
  assert.equal(rNoReason.status, 2);

  const registryPath = statePath(root, 'authorized-approvers.json');
  fs.mkdirSync(path.dirname(registryPath), { recursive: true });
  fs.writeFileSync(registryPath, JSON.stringify({ approvers: [{ identity: 'carol' }] }));
  const rUnregistered = _run(['remediation', 'verify', root, '--id', 'rem-v9', '--manual-attestation',
    '--approver', 'mallory', '--reason', 'x', '--yes']);
  assert.equal(rUnregistered.status, 1);
  assert.match(rUnregistered.stderr, /not in the authorized-approvers registry/);
});

// === V/10 — only one snapshot ================================================

test('remediation verify: only one persisted snapshot exists -> exit 2 with the honest "second lineage scan" message (V/10)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'only1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v10');
  // No second snapshot is ever written.

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v10', '--yes']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /second lineage scan exists/);
});

// === V/11 — dry-run preview =================================================

test('remediation verify: without --yes, previews the computed outcome (including unsatisfied flows) and appends nothing (V/11)', () => {
  const root = _mkTmpProject();
  const graphWithFlow = {
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
    flows: [_flow('flow:target', 'node:src', 'node:sink', ['data:card'])],
  };
  _writeSnapshot(root, { commit: 'before11', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: graphWithFlow });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-v11');
  _writeSnapshot(root, { commit: 'after11', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graphWithFlow });

  const before = fs.readFileSync(_ledgerPath(root), 'utf8');
  const r = _run(['remediation', 'verify', root, '--id', 'rem-v11']); // no --yes
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.written, false);
  assert.equal(report.evidenceOutcome.outcome, 'unverifiable');
  assert.deepEqual(report.evidenceOutcome.unsatisfiedFlowIds, ['flow:target']);
  const after = fs.readFileSync(_ledgerPath(root), 'utf8');
  assert.equal(after, before);
});

// === V/12 — B1: a chronologically OLDER "after" snapshot never grants
// `verified` =================================================================
//
// `loadSnapshots` sorts by file mtime (pre-existing, out of scope to fix
// here) -- so anything that rewrites snapshot files without preserving
// mtimes (`cp -R`, rsync without `-t`, a CI cache restore, a tar extract,
// a Docker COPY) can silently reorder "history." The reviewer's own live
// repro: touch an OLDER snapshot's mtime so it sorts as `snapshots[0]`.
// Reproduced here with an explicit, deterministic mtime swap (the same
// `_writeSnapshot`/`mtimeSeconds` mechanism every other test in this file
// already uses) rather than a real `touch`.

test('remediation verify: a chronologically OLDER "after" snapshot (later mtime) never grants verified -> unverifiable/stale_after_snapshot (V/12, B1)', () => {
  const root = _mkTmpProject();
  const graphFlow = {
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
    flows: [_flow('flow:target', 'node:src', 'node:sink', ['data:card'])],
  };
  const graphEmpty = { ...graphFlow, flows: [] };

  // Incident: captured LATER chronologically (09:10:36).
  const incident = _writeSnapshot(root, {
    commit: 'v12-incident', capturedAt: '2026-01-01T09:10:36.000Z', mtimeSeconds: 100, coverage: _coverage(5, 3), graph: graphFlow,
  });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  const open = _run([..._openArgs(root, assessmentPath, { id: 'rem-v12' }), '--snapshot', 'v12-incident']);
  assert.equal(open.status, 0, open.stderr);
  _run(['remediation', 'update', root, '--id', 'rem-v12', '--state', 'in_progress', '--yes']);
  _run(['remediation', 'update', root, '--id', 'rem-v12', '--state', 'awaiting_verification', '--yes']);

  // "After": captured EARLIER chronologically (09:05:37, 5 minutes before
  // the incident) -- but written with a NEWER mtime, so `loadSnapshots`'
  // pre-existing mtime-desc ordering (out of scope) puts it first.
  const staleAfter = _writeSnapshot(root, {
    commit: 'v12-stale-after', capturedAt: '2026-01-01T09:05:37.000Z', mtimeSeconds: 200, coverage: _coverage(5, 3), graph: graphEmpty,
  });
  assert.ok(staleAfter.capturedAt < incident.capturedAt, 'the "after" snapshot is genuinely OLDER than the incident');

  const r = _run(['remediation', 'verify', root, '--id', 'rem-v12', '--yes']);
  assert.equal(r.status, 0, r.stderr); // an unverifiable outcome is a recorded event, never a non-zero exit
  const report = JSON.parse(r.stdout);
  assert.equal(report.afterSnapshotId, staleAfter.id); // confirms the buggy mtime-based resolution really did pick it
  assert.equal(report.evidenceOutcome.outcome, 'unverifiable');
  assert.equal(report.evidenceOutcome.reason, 'stale_after_snapshot');
  assert.equal(report.evidenceOutcome.beforeCapturedAt, incident.capturedAt);
  assert.equal(report.evidenceOutcome.afterCapturedAt, staleAfter.capturedAt);

  const item = _listItem(root, 'rem-v12');
  assert.equal(item.state, 'awaiting_verification'); // never verified
  assert.equal(item.verificationSnapshotId, null);
});

// === R/1 — drift-policy reopen ==============================================

test('remediation reopen-check: a drift-policy new_flow rule matching a reappeared flow reopens the item (mechanism: drift-policy) (R/1)', () => {
  const root = _mkTmpProject();
  const flowGraph = (flowsPresent) => ({
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink-ext', kind: 'external', subtype: 'external-api' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
    flows: flowsPresent ? [_flow('flow:orig', 'node:src', 'node:sink-ext', ['data:card'])] : [],
  });

  _writeSnapshot(root, { commit: 'r1-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: flowGraph(true) });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment({ targetId: 'flow:orig' })));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r1', { requiredEvidence: 'flow:orig' });

  _writeSnapshot(root, { commit: 'r1-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: flowGraph(false) });
  const verify = _run(['remediation', 'verify', root, '--id', 'rem-r1', '--yes']);
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(_listItem(root, 'rem-r1').state, 'verified');

  // Regression: flow:orig reappears.
  _writeSnapshot(root, { commit: 'r1-s3', capturedAt: '2026-01-03T00:00:00.000Z', mtimeSeconds: 3000, coverage: _coverage(5, 3), graph: flowGraph(true) });

  const policyPath = path.join(root, 'drift-policy.json');
  fs.writeFileSync(policyPath, JSON.stringify({
    policies: [{ trigger: 'new_flow', dataClass: 'PCI', sinkCategory: 'external-api', reason: 'PCI reaching an external API' }],
  }));

  const auditBefore = _auditContent(root);
  const r = _run(['remediation', 'reopen-check', root, '--drift-policy', policyPath, '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.reopened.length, 1);
  assert.equal(report.reopened[0].itemId, 'rem-r1');
  assert.equal(report.reopened[0].mechanism, 'drift-policy');
  assert.match(report.reopened[0].reason, /drift-policy|new_flow/i);

  const item = _listItem(root, 'rem-r1');
  assert.equal(item.state, 'reopened');
  const lastEvent = item.history[item.history.length - 1];
  assert.equal(lastEvent.type, 'reopened');
  assert.match(lastEvent.reason, /drift-policy|new_flow/i);

  // A/1: a remediation_reopen_check audit event was appended.
  const auditAfter = _auditContent(root);
  assert.notEqual(auditAfter, auditBefore);
  assert.match(auditAfter, /remediation_reopen_check/);
});

// === R/2 — affected-flow-diff reopen (no drift policy): the CANONICAL
// scan-verified regression case (B2a, final-review fix round 1) ============
//
// A scan-verified item's flagged flow was, by construction, ABSENT from
// its own before-baseline (`verificationSnapshotId`) -- so a regression
// (the flow reappearing) can ONLY ever show up in `diff.added.flows`,
// never `diff.removed.flows`/`diff.changed.flows`. The pre-fix code read
// the wrong two buckets and was dead for exactly this case -- the
// reviewer's own B2a live repro, reproduced here as a permanent
// regression test.

test('remediation reopen-check: the exact required-evidence flow REAPPEARING (diff.added.flows) reopens a scan-verified item, no drift policy needed (mechanism: affected-flow-diff) (R/2, B2a)', () => {
  const root = _mkTmpProject();
  const graph = (present) => ({
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink-ext', kind: 'external', subtype: 'external-api' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
    flows: present ? [_flow('flow:orig', 'node:src', 'node:sink-ext', ['data:card'])] : [],
  });

  _writeSnapshot(root, { commit: 'r2-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: graph(true) });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment({ targetId: 'flow:orig' })));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r2', { requiredEvidence: 'flow:orig' });

  _writeSnapshot(root, { commit: 'r2-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graph(false) });
  const verify = _run(['remediation', 'verify', root, '--id', 'rem-r2', '--yes']);
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(_listItem(root, 'rem-r2').state, 'verified');

  // Genuine regression: the exact same flow id reappears.
  _writeSnapshot(root, { commit: 'r2-s3', capturedAt: '2026-01-03T00:00:00.000Z', mtimeSeconds: 3000, coverage: _coverage(5, 3), graph: graph(true) });

  const preview = _run(['remediation', 'reopen-check', root]); // no --yes: dry-run
  assert.equal(preview.status, 0, preview.stderr);
  const previewReport = JSON.parse(preview.stdout);
  assert.equal(previewReport.wouldReopen.length, 1);
  assert.equal(previewReport.wouldReopen[0].itemId, 'rem-r2');
  assert.equal(previewReport.wouldReopen[0].mechanism, 'affected-flow-diff');
  assert.match(previewReport.wouldReopen[0].reason, /diff\.added\.flows/);
  assert.equal(_listItem(root, 'rem-r2').state, 'verified', 'dry-run writes nothing');

  const r = _run(['remediation', 'reopen-check', root, '--yes']); // no --drift-policy
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.reopened.length, 1);
  assert.equal(report.reopened[0].itemId, 'rem-r2');
  assert.equal(report.reopened[0].mechanism, 'affected-flow-diff');
  assert.equal(report.reopened[0].beforeSnapshotSource, 'verification'); // M8

  const item = _listItem(root, 'rem-r2');
  assert.equal(item.state, 'reopened');
});

// === R/2b — B2b: a MANUALLY-ATTESTED item whose flow genuinely gets fixed
// (disappears) must NOT be reopened (the original code fired INVERTED here)

test('remediation reopen-check: a manually-attested item whose flow genuinely disappears is NOT reopened (mechanism never fires backwards) (R/2b, B2b)', () => {
  const root = _mkTmpProject();
  const graph = (present) => ({
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink-ext', kind: 'external', subtype: 'external-api' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
    flows: present ? [_flow('flow:orig', 'node:src', 'node:sink-ext', ['data:card'])] : [],
  });

  _writeSnapshot(root, { commit: 'r2b-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: graph(true) });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment({ targetId: 'flow:orig' })));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r2b', { requiredEvidence: 'flow:orig', allowManualAttestation: true });

  const attest = _run(['remediation', 'verify', root, '--id', 'rem-r2b', '--manual-attestation',
    '--approver', 'alice', '--reason', 'compensating control', '--yes']);
  assert.equal(attest.status, 0, attest.stderr);
  assert.equal(_listItem(root, 'rem-r2b').state, 'verified');

  // The fix is genuinely applied: flow:orig disappears for real.
  _writeSnapshot(root, { commit: 'r2b-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graph(false) });

  const r = _run(['remediation', 'reopen-check', root, '--yes']); // no --drift-policy
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.reopened.find((x) => x.itemId === 'rem-r2b'), undefined);

  const item = _listItem(root, 'rem-r2b');
  assert.equal(item.state, 'verified', 'a successful remediation must never reopen the item that fixed it');
});

// === R/2c — I6: a re-identified reappearance (new flow id, same
// correlation key) still triggers Mechanism B ================================
//
// A scan-verified item's OWN required-evidence flow is, by construction,
// absent from its verification baseline (Mechanism B's whole design) --
// so a reidentification pairing (a removed id AND an added id sharing a
// correlation key IN THE SAME DIFF) can only involve a DIFFERENT
// `affectedFlowIds` member that survived verification still present:
// here, `flow:ctrl` (the assessment's own `targetId`, distinct from the
// `flow:orig` required-evidence flow) — present through verification,
// then reidentified (same source/sink/dataElementIds, new id) in the
// regression.

test('remediation reopen-check: a re-identified flow (new id, causeClassification: reidentified) still reopens a scan-verified item (mechanism: affected-flow-diff) (R/2c, I6)', () => {
  const root = _mkTmpProject();
  const graph = (orig, ctrlId) => ({
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink', kind: 'log' }, { id: 'node:sink-ext', kind: 'external', subtype: 'external-api' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }, { id: 'data:other', name: 'other', dataClasses: [] }],
    flows: [
      ...(orig ? [_flow('flow:orig', 'node:src', 'node:sink', ['data:card'])] : []),
      ...(ctrlId ? [_flow(ctrlId, 'node:src', 'node:sink-ext', ['data:other'])] : []),
    ],
  });

  _writeSnapshot(root, { commit: 'r2c-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: graph(true, 'flow:ctrl') });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment({ targetId: 'flow:ctrl' })));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r2c', { requiredEvidence: 'flow:orig' });
  assert.deepEqual(_listItem(root, 'rem-r2c').affectedFlowIds, ['flow:ctrl', 'flow:orig']);

  // Verification: flow:orig (required evidence) genuinely disappears;
  // flow:ctrl (present but not required evidence) survives, unchanged.
  _writeSnapshot(root, { commit: 'r2c-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graph(false, 'flow:ctrl') });
  const verify = _run(['remediation', 'verify', root, '--id', 'rem-r2c', '--yes']);
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(_listItem(root, 'rem-r2c').state, 'verified');

  // Regression: flow:ctrl reappears under a NEW id, same (source, sink,
  // dataElementIds) correlation key -- computeGraphDiff classifies this
  // as `reidentified`, with `reidentifiedFrom: 'flow:ctrl'`.
  _writeSnapshot(root, { commit: 'r2c-s3', capturedAt: '2026-01-03T00:00:00.000Z', mtimeSeconds: 3000, coverage: _coverage(5, 3), graph: graph(false, 'flow:ctrl-v2') });

  const r = _run(['remediation', 'reopen-check', root, '--yes']); // no --drift-policy
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  const hit = report.reopened.find((x) => x.itemId === 'rem-r2c');
  assert.ok(hit, `expected rem-r2c to be reopened: ${JSON.stringify(report)}`);
  assert.equal(hit.mechanism, 'affected-flow-diff');
  assert.match(hit.reason, /reidentified from flow:ctrl/);

  assert.equal(_listItem(root, 'rem-r2c').state, 'reopened');
});

// === R/3 — non-verified items are never reopened =============================

test('remediation reopen-check: an item not in state "verified" is never reopened, even when the diff would otherwise match (R/3)', () => {
  const root = _mkTmpProject();
  const graph = (ctrlProtected) => ({
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink-ext', kind: 'external', subtype: 'external-api' }],
    edges: [], dataElements: [{ id: 'data:other', name: 'other', dataClasses: [] }],
    flows: [_flow('flow:ctrl', 'node:src', 'node:sink-ext', ['data:other'], { protectionSummary: ctrlProtected ? 'protected' : 'unprotected' })],
  });

  _writeSnapshot(root, { commit: 'r3-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: graph(true) });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment({ targetId: 'flow:ctrl' })));
  // Left in `in_progress` -- never verified.
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r3', { requiredEvidence: 'flow:ctrl', stopAtInProgress: true });
  assert.equal(_listItem(root, 'rem-r3').state, 'in_progress');

  _writeSnapshot(root, { commit: 'r3-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graph(false) });

  const before = fs.readFileSync(_ledgerPath(root), 'utf8');
  const r = _run(['remediation', 'reopen-check', root, '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.reopened.length, 0);
  const after = fs.readFileSync(_ledgerPath(root), 'utf8');
  assert.equal(after, before);
  assert.equal(_listItem(root, 'rem-r3').state, 'in_progress');
});

// === R/4 — nothing matches ===================================================

test('remediation reopen-check: nothing matching exits 0, reopens nothing, and says so (R/4)', () => {
  const root = _mkTmpProject();
  const graph = {
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [], edges: [], dataElements: [],
    flows: [_flow('flow:target', 'node:src', 'node:sink', [])],
  };
  const graphFixed = { ...graph, flows: [] };

  _writeSnapshot(root, { commit: 'r4-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r4');
  _writeSnapshot(root, { commit: 'r4-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graphFixed });
  const verify = _run(['remediation', 'verify', root, '--id', 'rem-r4', '--yes']);
  assert.equal(verify.status, 0, verify.stderr);

  // A third snapshot, byte-identical in content -- nothing regressed.
  _writeSnapshot(root, { commit: 'r4-s3', capturedAt: '2026-01-03T00:00:00.000Z', mtimeSeconds: 3000, coverage: _coverage(5, 3), graph: graphFixed });

  const auditBefore = _auditContent(root);
  const r = _run(['remediation', 'reopen-check', root, '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.reopened.length, 0);
  assert.equal(report.written, false);
  assert.equal(_listItem(root, 'rem-r4').state, 'verified');
  assert.equal(_auditContent(root), auditBefore, 'no audit event when nothing was reopened');
});

// === R/5 — dry-run preview ====================================================

test('remediation reopen-check: without --yes, previews every would-be reopen and appends nothing (R/5)', () => {
  const root = _mkTmpProject();
  const flowGraph = (flowsPresent) => ({
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink-ext', kind: 'external', subtype: 'external-api' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
    flows: flowsPresent ? [_flow('flow:orig', 'node:src', 'node:sink-ext', ['data:card'])] : [],
  });

  _writeSnapshot(root, { commit: 'r5-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: flowGraph(true) });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment({ targetId: 'flow:orig' })));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r5', { requiredEvidence: 'flow:orig' });
  _writeSnapshot(root, { commit: 'r5-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: flowGraph(false) });
  const verify = _run(['remediation', 'verify', root, '--id', 'rem-r5', '--yes']);
  assert.equal(verify.status, 0, verify.stderr);
  _writeSnapshot(root, { commit: 'r5-s3', capturedAt: '2026-01-03T00:00:00.000Z', mtimeSeconds: 3000, coverage: _coverage(5, 3), graph: flowGraph(true) });

  const policyPath = path.join(root, 'drift-policy.json');
  fs.writeFileSync(policyPath, JSON.stringify({
    policies: [{ trigger: 'new_flow', dataClass: 'PCI', sinkCategory: 'external-api' }],
  }));

  const before = fs.readFileSync(_ledgerPath(root), 'utf8');
  const r = _run(['remediation', 'reopen-check', root, '--drift-policy', policyPath]); // no --yes
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.written, false);
  assert.equal(report.wouldReopen.length, 1);
  assert.equal(report.wouldReopen[0].itemId, 'rem-r5');
  assert.equal(report.wouldReopen[0].mechanism, 'drift-policy');
  const after = fs.readFileSync(_ledgerPath(root), 'utf8');
  assert.equal(after, before);
  assert.equal(_listItem(root, 'rem-r5').state, 'verified');
});

// === R/6 — malformed drift-policy file =======================================

test('remediation reopen-check: a malformed --drift-policy file exits 2 (R/6)', () => {
  const root = _mkTmpProject();
  _writeSnapshot(root, {
    commit: 'r6-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  _writeSnapshot(root, {
    commit: 'r6-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3),
    graph: { graphId: 'graph:test-repo', schemaVersion: '1.0.0', nodes: [], edges: [], dataElements: [], flows: [] },
  });
  const policyPath = path.join(root, 'bad-drift-policy.json');
  fs.writeFileSync(policyPath, 'not valid json {{{');

  const r = _run(['remediation', 'reopen-check', root, '--drift-policy', policyPath, '--yes']);
  assert.equal(r.status, 2);
});

// === R/7 — B3: a permitted manual attestation is NOT undone by the very
// next reopen-check with nothing changed =====================================
//
// The reviewer's own live repro, end to end: scan-verify an item, a real
// regression happens and reopen-check correctly reopens it, the operator
// re-verifies via --manual-attestation (confirming the recorded item now
// carries the NEWEST snapshot's id as verificationSnapshotId, not the
// stale one from the original scan verification), then reopen-check runs
// again with NOTHING changed since the attestation -- confirming the item
// is NOT reopened a second time.

test('remediation reopen-check: a permitted manual attestation survives the very next reopen-check when nothing has changed (R/7, B3)', () => {
  const root = _mkTmpProject();
  const graph = (present) => ({
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink-ext', kind: 'external', subtype: 'external-api' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }],
    flows: present ? [_flow('flow:target', 'node:src', 'node:sink-ext', ['data:card'])] : [],
  });

  _writeSnapshot(root, { commit: 'r7-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: graph(true) });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment()));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r7', { allowManualAttestation: true });

  // Genuine scan verification: the flow disappears for real.
  _writeSnapshot(root, { commit: 'r7-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graph(false) });
  const verify1 = _run(['remediation', 'verify', root, '--id', 'rem-r7', '--yes']);
  assert.equal(verify1.status, 0, verify1.stderr);
  const afterVerify1 = _listItem(root, 'rem-r7');
  assert.equal(afterVerify1.state, 'verified');
  assert.equal(afterVerify1.verificationSnapshotId, 'snapshot:r7-s2');

  // Genuine regression, correctly reopened (via a drift-policy match, so
  // this half of the repro is decoupled from B2's own fix).
  _writeSnapshot(root, { commit: 'r7-s3', capturedAt: '2026-01-03T00:00:00.000Z', mtimeSeconds: 3000, coverage: _coverage(5, 3), graph: graph(true) });
  const policyPath = path.join(root, 'drift-policy.json');
  fs.writeFileSync(policyPath, JSON.stringify({
    policies: [{ trigger: 'new_flow', dataClass: 'PCI', sinkCategory: 'external-api', reason: 'PCI reaching an external API' }],
  }));
  const rc1 = _run(['remediation', 'reopen-check', root, '--drift-policy', policyPath, '--yes']);
  assert.equal(rc1.status, 0, rc1.stderr);
  assert.equal(_listItem(root, 'rem-r7').state, 'reopened');

  // Operator accepts a compensating control and re-attests manually --
  // AC-31 explicitly permits this route to `verified`.
  _run(['remediation', 'update', root, '--id', 'rem-r7', '--state', 'in_progress', '--yes']);
  _run(['remediation', 'update', root, '--id', 'rem-r7', '--state', 'awaiting_verification', '--yes']);
  const attest = _run(['remediation', 'verify', root, '--id', 'rem-r7', '--manual-attestation',
    '--approver', 'alice', '--reason', 'compensating control', '--yes']);
  assert.equal(attest.status, 0, attest.stderr);
  const afterAttest = _listItem(root, 'rem-r7');
  assert.equal(afterAttest.state, 'verified');
  // B3's own core assertion: the NEWEST snapshot's id, not the stale
  // original scan-verification anchor (snapshot:r7-s2).
  assert.equal(afterAttest.verificationSnapshotId, 'snapshot:r7-s3');
  assert.notEqual(afterAttest.verificationSnapshotId, 'snapshot:r7-s2');

  // NOTHING has changed: no edit, no commit, no new scan/snapshot.
  const rc2 = _run(['remediation', 'reopen-check', root, '--drift-policy', policyPath, '--yes']);
  assert.equal(rc2.status, 0, rc2.stderr);
  const report2 = JSON.parse(rc2.stdout);
  assert.equal(report2.reopened.find((x) => x.itemId === 'rem-r7'), undefined, `expected rem-r7 NOT reopened: ${JSON.stringify(report2)}`);

  const finalItem = _listItem(root, 'rem-r7');
  assert.equal(finalItem.state, 'verified', 'the permitted manual attestation must survive with nothing having changed');
});
