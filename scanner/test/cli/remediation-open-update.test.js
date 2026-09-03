// CLI subprocess tests for `agentic-security remediation open/update/
// accept-risk/list` — M5 deliverable #6 (Blast-Radius: Remediation Command
// Center), Task 3. Exercises the real CLI end to end: dry-run preview vs.
// `--yes` write, the real on-disk `.agentic-security/remediation/
// items.jsonl` hash-chained ledger, the real appended
// `.agentic-security/mcp-audit.log` entry (in `src/mcp/audit.js`'s own
// real NDJSON serialized form — confirmed by reading that file directly
// before writing this test: `JSON.stringify(entry)` with no added
// whitespace, so `"outcome":"ok"` matches verbatim), AC-31's
// verified-unreachable-from-state_changed rule at the CLI boundary, the
// `--base-event` optimistic-concurrency guard, approver/separation-of-
// duties gating on `accept-risk`, and the `isSafeStateDir` refusal.
//
// Modelled on `test/cli/governance-propose-edit.test.js`'s own structure
// (a `_mkTmpProject()` helper writing a `package.json` marker;
// `spawnSync(process.execPath, [CLI, ...], {encoding:'utf8', timeout})`).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { statePath } from '../../src/posture/state-dir.js';
import { buildGraphSnapshot } from '../../src/lineage/graph-snapshot.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const TIMEOUT = 20_000;

function _mkTmpProject(prefix = 'agsec-remediation-cli-') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

// Writes a real, structurally-real GraphSnapshot by hand into
// statePath(root, 'lineage-snapshots', '<commit>.json') — shaped exactly
// per buildGraphSnapshot's own real output ({id, version, graphId,
// schemaVersion, commit, capturedAt, coverage, graph}). A minimal graph is
// enough: `open`/`update`/`accept-risk`/`list` never diff, they only read
// `snapshot.id`.
function _writeSnapshotFixture(root) {
  const graph = {
    graphId: 'graph:test-repo',
    schemaVersion: '1.0.0',
    coverage: {},
    nodes: [], edges: [], dataElements: [], flows: [],
  };
  const snapshot = buildGraphSnapshot(graph, root, { capturedAt: '2026-01-01T00:00:00.000Z' });
  const dir = statePath(root, 'lineage-snapshots');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${snapshot.commit}.json`), JSON.stringify(snapshot, null, 2));
  return snapshot;
}

// A raw `dataflow impact assess --format json` report, shaped exactly per
// `impact-assessment.js`'s real ImpactAssessment record fields — the CLI
// resolves `snapshotId`/`assessmentId` itself; neither is read from here.
function _validAssessment(overrides = {}) {
  return {
    id: 'impact:test123abc',
    version: '1.0.0',
    graphId: 'graph:test-repo',
    graphDigest: 'digest-abc123',
    targetId: 'flow:test-flow-1',
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

function _setupProject() {
  const root = _mkTmpProject();
  const snapshot = _writeSnapshotFixture(root);
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_validAssessment()));
  return { root, snapshot, assessmentPath };
}

function _run(argv) {
  return spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8', timeout: TIMEOUT });
}

function _openArgs(root, assessmentPath, extra = {}) {
  return [
    'remediation', 'open', root,
    '--assessment', assessmentPath,
    '--owner', 'alice',
    '--due', '2026-12-31',
    '--control', 'Add field-level encryption and rotate credentials',
    '--required-evidence', 'flow:test-flow-1',
    ...(extra.id ? ['--id', extra.id] : []),
    ...(extra.yes !== false ? ['--yes'] : []),
  ];
}

function _ledgerPath(root) {
  return statePath(root, 'remediation', 'items.jsonl');
}
function _auditLogPath(root) {
  return statePath(root, 'mcp-audit.log');
}
function _ledgerLines(root) {
  const p = _ledgerPath(root);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
}

// --- C/1 -------------------------------------------------------------------

test('remediation open: without --yes, previews and writes nothing (C/1)', () => {
  const { root, snapshot, assessmentPath } = _setupProject();
  const r = _run(_openArgs(root, assessmentPath, { yes: false }));
  assert.equal(r.status, 0, r.stderr);
  const preview = JSON.parse(r.stdout);
  assert.equal(preview.written, false);
  assert.equal(preview.baseEvent, 'GENESIS');
  assert.ok(preview.wouldBe, 'preview must name the folded would-be item');
  assert.equal(preview.wouldBe.state, 'open');
  assert.equal(preview.wouldBe.assessment.snapshotId, snapshot.id, 'preview must name the resolved snapshotId');
  assert.deepEqual(_ledgerLines(root), []);
  // C/16: no audit event on a dry run.
  const auditContent = fs.existsSync(_auditLogPath(root)) ? fs.readFileSync(_auditLogPath(root), 'utf8') : '';
  assert.ok(!/remediation_/.test(auditContent));
});

// --- C/2 -------------------------------------------------------------------

test('remediation open: --yes writes exactly one JSONL line and appends a real audit event (C/2)', () => {
  const { root, assessmentPath } = _setupProject();
  const r = _run(_openArgs(root, assessmentPath));
  assert.equal(r.status, 0, r.stderr);
  assert.equal(_ledgerLines(root).length, 1);
  const auditContent = fs.readFileSync(_auditLogPath(root), 'utf8');
  assert.match(auditContent, /remediation_open/);
  assert.match(auditContent, /"outcome":"ok"/);
});

// --- C/3 -------------------------------------------------------------------

test('remediation open: a second --yes with the same --id exits 1 and appends no second line (C/3)', () => {
  const { root, assessmentPath } = _setupProject();
  const args = _openArgs(root, assessmentPath, { id: 'rem-fixed-id' });
  const r1 = _run(args);
  assert.equal(r1.status, 0, r1.stderr);
  const r2 = _run(args);
  assert.equal(r2.status, 1);
  assert.equal(_ledgerLines(root).length, 1);
});

// --- C/4 -------------------------------------------------------------------

test('remediation open: a malformed --assessment exits 2, names failing paths, and writes nothing (C/4)', () => {
  const root = _mkTmpProject();
  _writeSnapshotFixture(root);
  const assessmentPath = path.join(root, 'bad-assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify({ id: 'not-impact-prefixed' }));
  const r = _run(_openArgs(root, assessmentPath));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /\$\.id|\$\.targetId|\$\.version|\$\.graphId/);
  assert.deepEqual(_ledgerLines(root), []);
  // C/16: no audit event on a rejected write.
  const auditContent = fs.existsSync(_auditLogPath(root)) ? fs.readFileSync(_auditLogPath(root), 'utf8') : '';
  assert.ok(!/remediation_/.test(auditContent));
});

// --- C/5 -------------------------------------------------------------------

test('remediation open: no persisted snapshot exits 2 with the scan-first message (C/5)', () => {
  const root = _mkTmpProject(); // deliberately no snapshot written
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_validAssessment()));
  const r = _run(_openArgs(root, assessmentPath));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /AGENTIC_SECURITY_LINEAGE_DEEP=1/);
});

// --- C/6 -------------------------------------------------------------------

test('remediation open: a missing required flag exits 2 (C/6)', () => {
  const { root, assessmentPath } = _setupProject();
  const full = _openArgs(root, assessmentPath, { yes: false });
  for (const flagName of ['--assessment', '--owner', '--due', '--control', '--required-evidence']) {
    const idx = full.indexOf(flagName);
    assert.ok(idx >= 0, `test bug: ${flagName} not found in base args`);
    const withoutFlag = [...full.slice(0, idx), ...full.slice(idx + 2)];
    const r = _run(withoutFlag);
    assert.equal(r.status, 2, `expected exit 2 when ${flagName} is missing, got ${r.status}: ${r.stderr}`);
  }
});

// --- C/7 -------------------------------------------------------------------

test('remediation update: --state in_progress --yes from open succeeds and folds to in_progress (C/7)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c7' }));
  assert.equal(open.status, 0, open.stderr);
  const r = _run(['remediation', 'update', root, '--id', 'rem-c7', '--state', 'in_progress', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.written, true);
  const listR = _run(['remediation', 'list', root, '--format', 'json']);
  assert.equal(listR.status, 0, listR.stderr);
  const { items } = JSON.parse(listR.stdout);
  const item = items.find((i) => i.id === 'rem-c7');
  assert.ok(item);
  assert.equal(item.state, 'in_progress');
});

// --- C/8 (AC-31 at the CLI boundary) ---------------------------------------

test('remediation update (AC-31): --state verified exits 1, writes nothing, names remediation verify, appends no audit event (C/8, C/16)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c8' }));
  assert.equal(open.status, 0, open.stderr);
  const toInProgress = _run(['remediation', 'update', root, '--id', 'rem-c8', '--state', 'in_progress', '--yes']);
  assert.equal(toInProgress.status, 0, toInProgress.stderr);
  const toAwaiting = _run(['remediation', 'update', root, '--id', 'rem-c8', '--state', 'awaiting_verification', '--yes']);
  assert.equal(toAwaiting.status, 0, toAwaiting.stderr);

  const linesBefore = _ledgerLines(root).length;
  const auditBefore = fs.readFileSync(_auditLogPath(root), 'utf8');

  const r = _run(['remediation', 'update', root, '--id', 'rem-c8', '--state', 'verified', '--yes']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /remediation verify/i);

  assert.equal(_ledgerLines(root).length, linesBefore, 'no new ledger line for the rejected verified transition');
  const auditAfter = fs.readFileSync(_auditLogPath(root), 'utf8');
  assert.equal(auditAfter, auditBefore, 'no new audit event for the rejected verified transition');
});

// --- C/9 -------------------------------------------------------------------

test('remediation update: --state awaiting_verification directly from open (skipping in_progress) exits 1 and writes nothing (C/9)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c9' }));
  assert.equal(open.status, 0, open.stderr);
  const before = fs.readFileSync(_ledgerPath(root), 'utf8');
  const r = _run(['remediation', 'update', root, '--id', 'rem-c9', '--state', 'awaiting_verification', '--yes']);
  assert.equal(r.status, 1);
  const after = fs.readFileSync(_ledgerPath(root), 'utf8');
  assert.equal(after, before);
});

// --- C/10 ------------------------------------------------------------------

test('remediation update: --base-event mismatch exits 2 and writes nothing; a matching --base-event succeeds (C/10)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c10' }));
  assert.equal(open.status, 0, open.stderr);
  const openReport = JSON.parse(open.stdout);
  const realHash = openReport.eventHash;
  assert.equal(typeof realHash, 'string');
  assert.ok(realHash.length > 0);

  const staleHash = 'a'.repeat(64);
  const rBad = _run(['remediation', 'update', root, '--id', 'rem-c10', '--state', 'in_progress', '--yes', '--base-event', staleHash]);
  assert.equal(rBad.status, 2);
  assert.equal(_ledgerLines(root).length, 1);

  const rGood = _run(['remediation', 'update', root, '--id', 'rem-c10', '--state', 'in_progress', '--yes', '--base-event', realHash]);
  assert.equal(rGood.status, 0, rGood.stderr);
  assert.equal(_ledgerLines(root).length, 2);
});

// --- C/11 ------------------------------------------------------------------

test('remediation accept-risk: --yes with all four fields succeeds and folds to accepted_risk with a real exception carrying expiration (C/11)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c11' }));
  assert.equal(open.status, 0, open.stderr);
  const r = _run(['remediation', 'accept-risk', root, '--id', 'rem-c11',
    '--approver', 'bob', '--reason', 'compensating control in place',
    '--scope', 'production only', '--expires', '2027-01-01', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const listR = _run(['remediation', 'list', root, '--format', 'json']);
  const { items } = JSON.parse(listR.stdout);
  const item = items.find((i) => i.id === 'rem-c11');
  assert.ok(item);
  assert.equal(item.state, 'accepted_risk');
  assert.equal(item.exceptions.length, 1);
  assert.equal(item.exceptions[0].expiration, '2027-01-01');
  assert.equal(item.exceptions[0].approver, 'bob');
});

test('remediation accept-risk: missing any of --approver/--reason/--scope/--expires exits 2 (C/11)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c11b' }));
  assert.equal(open.status, 0, open.stderr);
  const full = ['remediation', 'accept-risk', root, '--id', 'rem-c11b',
    '--approver', 'bob', '--reason', 'x', '--scope', 'y', '--expires', '2027-01-01', '--yes'];
  for (const flagName of ['--approver', '--reason', '--scope', '--expires']) {
    const idx = full.indexOf(flagName);
    const withoutFlag = [...full.slice(0, idx), ...full.slice(idx + 2)];
    const r = _run(withoutFlag);
    assert.equal(r.status, 2, `expected exit 2 when ${flagName} is missing, got ${r.status}: ${r.stderr}`);
  }
});

// --- C/12 ------------------------------------------------------------------

test('remediation accept-risk: an unregistered approver is refused with verifyApprover\'s own reason; registered succeeds (C/12)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c12' }));
  assert.equal(open.status, 0, open.stderr);
  const registryPath = statePath(root, 'authorized-approvers.json');
  fs.mkdirSync(path.dirname(registryPath), { recursive: true });
  fs.writeFileSync(registryPath, JSON.stringify({ approvers: [{ identity: 'carol' }] }));

  const rBad = _run(['remediation', 'accept-risk', root, '--id', 'rem-c12',
    '--approver', 'mallory', '--reason', 'x', '--scope', 'y', '--expires', '2027-01-01', '--yes']);
  assert.equal(rBad.status, 1);
  assert.match(rBad.stderr, /not in the authorized-approvers registry/);
  assert.equal(_ledgerLines(root).length, 1); // only the opened event

  const rGood = _run(['remediation', 'accept-risk', root, '--id', 'rem-c12',
    '--approver', 'carol', '--reason', 'x', '--scope', 'y', '--expires', '2027-01-01', '--yes']);
  assert.equal(rGood.status, 0, rGood.stderr);
  assert.equal(_ledgerLines(root).length, 2);
});

// --- C/13 ------------------------------------------------------------------

test('remediation accept-risk: separation-of-duties refuses self-approval with checkSeparationOfDuties\'s own reason (C/13)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c13' }));
  assert.equal(open.status, 0, open.stderr);
  const registryPath = statePath(root, 'authorized-approvers.json');
  fs.mkdirSync(path.dirname(registryPath), { recursive: true });
  fs.writeFileSync(registryPath, JSON.stringify({
    approvers: [{ identity: 'dave' }],
    separationOfDuties: { enabled: true },
  }));

  const r = _run(['remediation', 'accept-risk', root, '--id', 'rem-c13',
    '--approver', 'dave', '--author', 'dave', '--reason', 'x', '--scope', 'y', '--expires', '2027-01-01', '--yes']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /separation-of-duties/);
  assert.equal(_ledgerLines(root).length, 1); // only the opened event
});

// --- C/14 ------------------------------------------------------------------

test('remediation list: --format json returns {items, integrity}; --format markdown returns a table (C/14)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-c14' }));
  assert.equal(open.status, 0, open.stderr);

  const rJson = _run(['remediation', 'list', root, '--format', 'json']);
  assert.equal(rJson.status, 0, rJson.stderr);
  const { items, integrity } = JSON.parse(rJson.stdout);
  assert.ok(Array.isArray(items));
  assert.equal(items.length, 1);
  assert.equal(items[0].id, 'rem-c14');
  assert.equal(integrity.ok, true); // I7: a clean, untampered ledger reports ok

  const rMd = _run(['remediation', 'list', root, '--format', 'markdown']);
  assert.equal(rMd.status, 0, rMd.stderr);
  assert.match(rMd.stdout, /\bid\b/);
  assert.match(rMd.stdout, /\bstate\b/);
  assert.match(rMd.stdout, /\bowner\b/);
  assert.match(rMd.stdout, /\bdueDate\b/);
  assert.match(rMd.stdout, /\brecommendedControl\b/);
  assert.match(rMd.stdout, /rem-c14/);
  assert.match(rMd.stdout, /alice/);
});

test('remediation list: exits 0 on an empty ledger for both formats (C/14)', () => {
  const root = _mkTmpProject();
  const rJson = _run(['remediation', 'list', root, '--format', 'json']);
  assert.equal(rJson.status, 0, rJson.stderr);
  assert.deepEqual(JSON.parse(rJson.stdout).items, []);
  const rMd = _run(['remediation', 'list', root, '--format', 'markdown']);
  assert.equal(rMd.status, 0, rMd.stderr);
  assert.match(rMd.stdout, /no remediation items/i);
});

// --- C/15 ------------------------------------------------------------------

test('remediation update/accept-risk: refuse exit 2 in a directory with no project marker, creating no state dir (C/15)', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-remediation-unsafe-'));
  const rUpdate = _run(['remediation', 'update', root, '--id', 'rem-x', '--state', 'in_progress', '--yes']);
  assert.equal(rUpdate.status, 2);
  assert.ok(!fs.existsSync(path.join(root, '.agentic-security')));

  const rAccept = _run(['remediation', 'accept-risk', root, '--id', 'rem-x',
    '--approver', 'a', '--reason', 'r', '--scope', 's', '--expires', '2027-01-01', '--yes']);
  assert.equal(rAccept.status, 2);
  assert.ok(!fs.existsSync(path.join(root, '.agentic-security')));
});

test('remediation open: refuses exit 2 via isSafeStateDir even with a snapshot/assessment present, creating no remediation ledger (C/15)', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-remediation-unsafe-open-'));
  // Seeded directly via fs, not through the app's own write guard — proves
  // the guard fires even when the earlier snapshot/assessment reads
  // otherwise succeed.
  _writeSnapshotFixture(root);
  const assessmentPath = path.join(root, 'assessment.json');
  fs.writeFileSync(assessmentPath, JSON.stringify(_validAssessment()));
  const r = _run(_openArgs(root, assessmentPath));
  assert.equal(r.status, 2);
  assert.ok(!fs.existsSync(_ledgerPath(root)));
});

// === I7 (final-review fix round 1): a tampered ledger surfaces a loud
// warning via `remediation list`, in both JSON and Markdown, instead of
// silently presenting a shorter/tampered history with no signal ============

test('remediation list: a tampered mid-file ledger line prints a stderr warning and integrity.ok:false in the JSON output (I7)', () => {
  const { root, assessmentPath } = _setupProject();
  const open1 = _run(_openArgs(root, assessmentPath, { id: 'rem-i7a' }));
  assert.equal(open1.status, 0, open1.stderr);
  const toInProgress = _run(['remediation', 'update', root, '--id', 'rem-i7a', '--state', 'in_progress', '--yes']);
  assert.equal(toInProgress.status, 0, toInProgress.stderr);

  // Tamper the FIRST (opened) line in place -- breaks the hash chain for
  // every line after it, exactly as the reviewer's own I7 repro did. This
  // silently reverts the item from `in_progress` back to `open` on a
  // plain read (the tampered line's own `prev` is untouched, so it still
  // verifies against GENESIS and IS returned with the tampered content;
  // it's the SECOND line's prev that no longer matches).
  const ledgerPath = _ledgerPath(root);
  const lines = fs.readFileSync(ledgerPath, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 2);
  const tampered = JSON.parse(lines[0]);
  tampered.owner = 'mallory';
  fs.writeFileSync(ledgerPath, [JSON.stringify(tampered), lines[1]].join('\n') + '\n', 'utf8');

  const rJson = _run(['remediation', 'list', root, '--format', 'json']);
  assert.equal(rJson.status, 0, rJson.stderr);
  assert.match(rJson.stderr, /WARNING/);
  assert.match(rJson.stderr, /ledger/i);
  const { items, integrity } = JSON.parse(rJson.stdout);
  assert.equal(integrity.ok, false);
  assert.equal(integrity.totalLines, 2);
  assert.equal(integrity.verifiedLines, 1);
  // The item list itself silently reflects the tampered, truncated view
  // (owner: mallory, state reverted to open) -- exactly what the warning
  // exists to flag, since nothing about the list ITSELF looks wrong.
  const item = items.find((i) => i.id === 'rem-i7a');
  assert.equal(item.owner, 'mallory');
  assert.equal(item.state, 'open');

  const rMd = _run(['remediation', 'list', root, '--format', 'markdown']);
  assert.equal(rMd.status, 0, rMd.stderr);
  assert.match(rMd.stderr, /WARNING/);
  assert.match(rMd.stdout, /WARNING/); // I7: also prepended into the markdown output itself
});

test('remediation list: a clean, untampered ledger prints no warning and reports integrity.ok:true (I7 does not over-warn)', () => {
  const { root, assessmentPath } = _setupProject();
  const open1 = _run(_openArgs(root, assessmentPath, { id: 'rem-i7b' }));
  assert.equal(open1.status, 0, open1.stderr);

  const rJson = _run(['remediation', 'list', root, '--format', 'json']);
  assert.equal(rJson.status, 0, rJson.stderr);
  assert.equal(rJson.stderr, '');
  const { integrity } = JSON.parse(rJson.stdout);
  assert.equal(integrity.ok, true);
});

// === M10 (final-review fix round 1): AGENTIC_SECURITY_NO_STATE=1 is a
// usage/environment refusal (exit 2), never a rejected transition (exit 1)

test('remediation open --yes with AGENTIC_SECURITY_NO_STATE=1 exits 2 (a usage/environment refusal, not exit 1) and writes nothing (M10)', () => {
  const { root, assessmentPath } = _setupProject();
  const r = spawnSync(process.execPath, [CLI, ...(_openArgs(root, assessmentPath, { id: 'rem-m10' }))], {
    encoding: 'utf8', timeout: TIMEOUT, env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1' },
  });
  assert.equal(r.status, 2);
  assert.ok(!fs.existsSync(_ledgerPath(root)));
});

test('remediation update --yes with AGENTIC_SECURITY_NO_STATE=1 exits 2, distinct from a genuine rejected-transition exit 1 (M10)', () => {
  const { root, assessmentPath } = _setupProject();
  const open = _run(_openArgs(root, assessmentPath, { id: 'rem-m10b' }));
  assert.equal(open.status, 0, open.stderr);

  // A genuine rejected transition still exits 1 -- this is the contrast
  // M10 exists to preserve: a real validation/state-machine rejection
  // must NOT be reclassified to 2 by this fix.
  const rejected = _run(['remediation', 'update', root, '--id', 'rem-m10b', '--state', 'awaiting_verification', '--yes']); // skips in_progress
  assert.equal(rejected.status, 1);

  const rNoState = spawnSync(process.execPath, [CLI, 'remediation', 'update', root, '--id', 'rem-m10b', '--state', 'in_progress', '--yes'], {
    encoding: 'utf8', timeout: TIMEOUT, env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1' },
  });
  assert.equal(rNoState.status, 2);
});
