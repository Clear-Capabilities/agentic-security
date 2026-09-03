// CLI subprocess tests for `agentic-security governance propose-edit` —
// M5 deliverable #5 (Governance Editing Workflow), Task 2. Exercises the
// real CLI end to end: dry-run preview vs. `--yes` write, the real
// on-disk backup, the real appended `.agentic-security/mcp-audit.log`
// entry (in `src/mcp/audit.js`'s own real NDJSON serialized form —
// confirmed by reading that file directly before writing this test:
// `JSON.stringify(entry)` with no added whitespace, so `"outcome":"ok"`
// matches verbatim), a validation failure, and the `--base-digest`
// version-guard rejection.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { statePath } from '../../src/posture/state-dir.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-governance-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _validEntry(overrides = {}) {
  return {
    provider: 'Acme Analytics', serviceType: 'analytics', legalEntity: 'Acme Inc',
    processorRole: 'processor', servicePurpose: 'usage analytics',
    subprocessorChain: [], processingCountries: ['US'], dataResidencyCommitment: null,
    dpaStatus: 'in_place', transferMechanism: null, transferImpactReviewStatus: null,
    retentionCommitment: null, ...overrides,
  };
}

function _writeConfig(root, recipients) {
  const configPath = statePath(root, 'recipient-profiles.json');
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  const body = JSON.stringify({ recipients }, null, 2);
  fs.writeFileSync(configPath, body);
  return { configPath, body };
}

test('governance propose-edit: without --yes, previews the diff and does NOT write', () => {
  const root = _mkTmpProject();
  const { configPath, body: before } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  const outFile = path.join(root, 'preview.json');
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--output', outFile], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(fs.readFileSync(configPath, 'utf8'), before, 'the real config file must be untouched without --yes');
  const preview = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.deepEqual(preview.diff.added, ['vendor1']);
  assert.equal(preview.written, false);
});

test('governance propose-edit: with --yes, writes atomically, backs up the original, and appends a real audit event', () => {
  const root = _mkTmpProject();
  const { configPath } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.ok(written.recipients.vendor1);
  // Backups live in a dedicated subdirectory (I5), never as a sibling
  // `.bak-*` file next to the config — see the backup-location test below
  // for the full assertion on filename shape.
  const backupDir = statePath(root, 'recipient-profiles-backups');
  const backups = fs.readdirSync(backupDir);
  assert.equal(backups.length, 1, 'exactly one backup file must exist after the first edit');
  const auditLogPath = statePath(root, 'mcp-audit.log');
  assert.ok(fs.existsSync(auditLogPath), 'a real audit-log entry must be appended');
  const auditContent = fs.readFileSync(auditLogPath, 'utf8');
  assert.match(auditContent, /governance_propose_edit/);
  assert.match(auditContent, /"outcome":"ok"/);
  // M2: the audit event carries enough to identify which bytes it
  // produced — `args` is itself a JSON-stringified blob (audit.js's own
  // `_summarize`), so it must be parsed a second time.
  const auditEntry = JSON.parse(auditContent.trim().split('\n').find((l) => l.includes('governance_propose_edit')));
  const auditArgs = JSON.parse(auditEntry.args);
  assert.equal(typeof auditArgs.beforeDigest, 'string');
  assert.ok(auditArgs.beforeDigest.length > 0);
  assert.equal(auditArgs.backupPath, path.join(backupDir, backups[0]));
});

test('governance propose-edit: a malformed patch entry exits 1, never writes, never backs up', () => {
  const root = _mkTmpProject();
  const { configPath, body: before } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  // NOTE: `{provider: 'x'}` alone (the brief's own original example) is
  // NOT actually malformed per `isValidRecipientConfigEntry` —
  // `provider`/`serviceType` are code-derived-only fields that function
  // never validates at all, and every field it DOES validate is
  // `undefined` here, which its `_isStringOrNull`/`!= null` guards all
  // treat as legitimately absent. Confirmed live before writing this
  // test: `isValidRecipientConfigEntry({provider: 'x'})` returns `true`.
  // A genuinely invalid entry needs a validated field holding a value
  // outside its real enum — `processorRole` outside
  // `RECIPIENT_PROCESSOR_ROLES` (`recipient-profile.js`) does that.
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: { provider: 'x', processorRole: 'not-a-real-role' } } }));
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 1);
  assert.equal(fs.readFileSync(configPath, 'utf8'), before);
  const backupDir = statePath(root, 'recipient-profiles-backups');
  const backupCount = fs.existsSync(backupDir) ? fs.readdirSync(backupDir).length : 0;
  assert.equal(backupCount, 0);
});

test('governance propose-edit: --base-digest mismatch (a concurrent edit) is refused, exit 2, never writes', () => {
  const root = _mkTmpProject();
  const { configPath } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  // Simulate a stale digest — computed against different content than
  // what's actually on disk now.
  const staleDigest = crypto.createHash('sha256').update('{"recipients":{"someone-else-edited-this":true}}').digest('hex');
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes', '--base-digest', staleDigest], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /concurrent|changed|digest/i);
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.deepEqual(written.recipients, {});
});

test('governance propose-edit (merge-patch semantics, fix round 1): a patch naming only a NEW vendor leaves a pre-existing, unmentioned recipient untouched in the written file', () => {
  // Reproduces the review's own live-reproduced data-loss bug: before the
  // fix, `--patch` was written to disk verbatim, so any recipient the
  // patch didn't name (like `vendor0-preexisting` here) silently vanished.
  const root = _mkTmpProject();
  const preexisting = _validEntry({ provider: 'Preexisting Vendor' });
  const { configPath } = _writeConfig(root, { 'vendor0-preexisting': preexisting });
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { 'vendor1-new': _validEntry({ provider: 'New Vendor' }) } }));
  const outFile = path.join(root, 'preview.json');
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--output', outFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.deepEqual(written.recipients['vendor0-preexisting'], preexisting, 'the pre-existing recipient must survive byte-identical');
  assert.ok(written.recipients['vendor1-new']);
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.deepEqual(report.diff.removed, []);
});

test('governance propose-edit (merge-patch semantics, fix round 1): an explicit null patch value deletes a recipient', () => {
  const root = _mkTmpProject();
  const { configPath } = _writeConfig(root, { 'vendor0-preexisting': _validEntry() });
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { 'vendor0-preexisting': null } }));
  const outFile = path.join(root, 'preview.json');
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--output', outFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.ok(!('vendor0-preexisting' in written.recipients));
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.deepEqual(report.diff.removed, ['vendor0-preexisting']);
});

test('governance propose-edit: a first-ever write (no prior config file) reports backupPath as null, not a phantom path', () => {
  const root = _mkTmpProject();
  // No _writeConfig call — the config file genuinely does not exist yet.
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  const outFile = path.join(root, 'preview.json');
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--output', outFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.equal(report.backupPath, null);
  const backupDir = statePath(root, 'recipient-profiles-backups');
  const backups = fs.existsSync(backupDir) ? fs.readdirSync(backupDir) : [];
  assert.equal(backups.length, 0, 'no backup file should exist when nothing existed to back up');
});

test('governance propose-edit: missing --patch exits 2', () => {
  const root = _mkTmpProject();
  _writeConfig(root, {});
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 2);
});

// --- Final review fix round 1 ---------------------------------------------

test('governance propose-edit (B1, end to end): an invalid legacy entry in the real on-disk config survives a --yes write BYTE-FOR-BYTE, and diff.removed is empty', () => {
  const root = _mkTmpProject();
  // Written directly via fs.writeFileSync (not _writeConfig/_validEntry,
  // which only ever produce valid entries) — this is what a real config
  // file with a pre-existing invalid entry looks like on disk, e.g. one
  // written before a stricter validation rule was added.
  const configPath = statePath(root, 'recipient-profiles.json');
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  const rawConfig = JSON.stringify({
    recipients: {
      'legacy-vendor': { provider: 'x', dpaStatus: 'not_a_real_status' },
      'good-vendor': _validEntry(),
    },
    version: 3,
  }, null, 2);
  fs.writeFileSync(configPath, rawConfig);
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { 'new-vendor': _validEntry({ provider: 'New Vendor' }) } }));
  const outFile = path.join(root, 'preview.json');
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--output', outFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.deepEqual(written.recipients['legacy-vendor'], { provider: 'x', dpaStatus: 'not_a_real_status' }, 'the invalid legacy entry must survive byte-for-byte, never dropped');
  assert.equal(written.version, 3, 'a non-recipients top-level key must survive too');
  assert.ok(written.recipients['new-vendor']);
  const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.deepEqual(report.diff.removed, []);
});

test('governance propose-edit (I2, end to end): a patch missing the recipients wrapper exits 1, writes nothing, creates no backup', () => {
  const root = _mkTmpProject();
  const { configPath, body: before } = _writeConfig(root, { vendor0: _validEntry() });
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ 'vendor-x': _validEntry() })); // forgot "recipients"
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 1, r.stderr);
  assert.equal(fs.readFileSync(configPath, 'utf8'), before, 'the config file must be byte-unchanged');
  const backupDir = statePath(root, 'recipient-profiles-backups');
  const backupCount = fs.existsSync(backupDir) ? fs.readdirSync(backupDir).length : 0;
  assert.equal(backupCount, 0, 'no backup should be created for a rejected patch');
});

test('governance propose-edit (I4): a --yes write preserves the config file\'s existing permissions', { skip: process.platform === 'win32' ? 'POSIX permission bits are not meaningful on Windows' : false }, () => {
  const root = _mkTmpProject();
  const { configPath } = _writeConfig(root, {});
  fs.chmodSync(configPath, 0o600);
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  const mode = fs.statSync(configPath).mode & 0o777;
  assert.equal(mode, 0o600, `expected mode 0600 to survive the write, got ${mode.toString(8)}`);
});

test('governance propose-edit (I5): the backup lands inside recipient-profiles-backups/, not as a sibling .bak-* file, with the expected filename shape', () => {
  const root = _mkTmpProject();
  const { configPath } = _writeConfig(root, {});
  const patchFile = path.join(root, 'patch.json');
  fs.writeFileSync(patchFile, JSON.stringify({ recipients: { vendor1: _validEntry() } }));
  const r = spawnSync(process.execPath, [CLI, 'governance', 'propose-edit', root, '--patch', patchFile, '--yes'], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(r.status, 0, r.stderr);
  // No sibling .bak-* file next to the config itself.
  const siblingBaks = fs.readdirSync(path.dirname(configPath)).filter((f) => f.startsWith('recipient-profiles.json.bak-'));
  assert.deepEqual(siblingBaks, []);
  const backupDir = statePath(root, 'recipient-profiles-backups');
  const backups = fs.readdirSync(backupDir);
  assert.equal(backups.length, 1);
  assert.match(backups[0], /^\d+-[0-9a-f]{8}\.bak$/);
});

// M5 (isSafeStateDir guard): not covered by a dedicated CLI test in this
// round. Constructing a real "unsafe" target directory that ALSO passes
// the (unrelated) config-shape/version-guard checks earlier in the
// function turned out to need more scaffolding than this round's other
// tests — see this round's own report for the concern, and
// state-dir.test.js's own direct unit tests of isSafeStateDir for the
// underlying guard's own coverage (it is exercised directly there, just
// not through this CLI command's own subprocess path).
