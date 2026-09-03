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
  const items = JSON.parse(r.stdout);
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
  const after = fs.readFileSync(_ledgerPath(root), 'utf8');
  assert.equal(after, before);
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
  assert.equal(item.verificationSnapshotId, null); // manual attestation never carries a snapshotId
  assert.equal(item.approvals.length, 1);
  assert.equal(item.approvals[0].evidenceKind, 'manual');
  assert.equal(item.approvals[0].approver, 'alice');
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

// === R/2 — affected-flow-diff reopen (no drift policy) ======================

test('remediation reopen-check: an affected flow regressing in diff.changed.flows reopens the item, no drift policy needed (mechanism: affected-flow-diff) (R/2)', () => {
  const root = _mkTmpProject();
  const graph = (ctrlProtected) => ({
    graphId: 'graph:test-repo', schemaVersion: '1.0.0',
    nodes: [{ id: 'node:src', kind: 'source' }, { id: 'node:sink-ext', kind: 'external', subtype: 'external-api' }],
    edges: [], dataElements: [{ id: 'data:card', name: 'card_number', dataClasses: ['PCI'] }, { id: 'data:other', name: 'other', dataClasses: [] }],
    flows: [
      _flow('flow:orig', 'node:src', 'node:sink-ext', ['data:card']), // will be fixed for verification
      _flow('flow:ctrl', 'node:src', 'node:sink-ext', ['data:other'], { protectionSummary: ctrlProtected ? 'protected' : 'unprotected' }),
    ],
  });
  const graphFixed = () => {
    const g = graph(true);
    g.flows = g.flows.filter((f) => f.id !== 'flow:orig');
    return g;
  };

  _writeSnapshot(root, { commit: 'r2-s1', capturedAt: '2026-01-01T00:00:00.000Z', mtimeSeconds: 1000, coverage: _coverage(5, 3), graph: graph(true) });
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_assessment({ targetId: 'flow:ctrl' })));
  _openAndDriveToAwaitingVerification(root, assessmentPath, 'rem-r2', { requiredEvidence: 'flow:orig' });

  _writeSnapshot(root, { commit: 'r2-s2', capturedAt: '2026-01-02T00:00:00.000Z', mtimeSeconds: 2000, coverage: _coverage(5, 3), graph: graphFixed() });
  const verify = _run(['remediation', 'verify', root, '--id', 'rem-r2', '--yes']);
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(_listItem(root, 'rem-r2').state, 'verified');

  // Regression: flow:ctrl's protectionSummary regresses.
  const graphRegressed = () => {
    const g = graphFixed();
    g.flows = [_flow('flow:ctrl', 'node:src', 'node:sink-ext', ['data:other'], { protectionSummary: 'unprotected' })];
    return g;
  };
  _writeSnapshot(root, { commit: 'r2-s3', capturedAt: '2026-01-03T00:00:00.000Z', mtimeSeconds: 3000, coverage: _coverage(5, 3), graph: graphRegressed() });

  const r = _run(['remediation', 'reopen-check', root, '--yes']); // no --drift-policy
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.reopened.length, 1);
  assert.equal(report.reopened[0].itemId, 'rem-r2');
  assert.equal(report.reopened[0].mechanism, 'affected-flow-diff');

  const item = _listItem(root, 'rem-r2');
  assert.equal(item.state, 'reopened');
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
