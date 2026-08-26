// FR-706 (assurance-hardening PRD): manifest-based export and deletion
// reports — "Operators can prove what was exported, deleted, retained, or
// failed."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  buildDeletionReport, writeDeletionReport, DELETION_REPORT_FILE,
  buildExportReport, writeExportReport, EXPORT_REPORT_FILE,
} from '../src/posture/state-lifecycle-report.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'scanner', 'bin', 'agentic-security.js');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: path.join(REPO_ROOT, 'scanner'), encoding: 'utf8', timeout: 30_000 });
}

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'state-lifecycle-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

// ── buildDeletionReport / buildExportReport (pure) ───────────────────────

test('buildDeletionReport: summary counts partition items by status correctly', () => {
  const r = buildDeletionReport({
    mode: 'reset', dryRun: false, root: '/x',
    items: [
      { name: 'a', status: 'deleted' },
      { name: 'b', status: 'deleted' },
      { name: 'c', status: 'failed', error: 'boom' },
    ],
    preserved: [{ name: 'rules.yml', reason: 'operator-authored configuration' }],
  });
  assert.equal(r.schema, 'agentic-security/deletion-report@1');
  assert.equal(r.summary.deleted, 2);
  assert.equal(r.summary.failed, 1);
  assert.equal(r.summary.preserved, 1);
  assert.equal(r.summary.planned, 0);
  assert.equal(typeof r.generatedAt, 'string');
});

test('buildDeletionReport: a dry run reports "planned" items, never "deleted"', () => {
  const r = buildDeletionReport({
    mode: 'reset', dryRun: true, root: '/x',
    items: [{ name: 'a', status: 'planned' }],
    preserved: [],
  });
  assert.equal(r.dryRun, true);
  assert.equal(r.summary.planned, 1);
  assert.equal(r.summary.deleted, 0);
});

test('buildDeletionReport: defaults items/preserved to empty arrays rather than throwing on missing input', () => {
  const r = buildDeletionReport({ mode: 'reset', dryRun: false, root: '/x' });
  assert.deepEqual(r.items, []);
  assert.deepEqual(r.preserved, []);
  assert.equal(r.summary.deleted, 0);
});

test('buildExportReport: summary counts exported vs failed', () => {
  const r = buildExportReport({
    root: '/x', outDir: '/y',
    items: [
      { name: 'a', status: 'exported', sha256: 'abc' },
      { name: 'b', status: 'failed', error: 'nope' },
    ],
  });
  assert.equal(r.schema, 'agentic-security/export-report@1');
  assert.equal(r.summary.exported, 1);
  assert.equal(r.summary.failed, 1);
});

// ── writeDeletionReport / writeExportReport (real filesystem) ───────────

test('writeDeletionReport: writes valid JSON to .agentic-security/deletion-report.json and returns its path', async () => {
  const s = await mkSession();
  try {
    const report = buildDeletionReport({ mode: 'reset', dryRun: false, root: s.dir, items: [{ name: 'a', status: 'deleted' }], preserved: [] });
    const fp = writeDeletionReport(s.dir, report);
    assert.ok(fp && fp.endsWith(DELETION_REPORT_FILE));
    const onDisk = JSON.parse(fs.readFileSync(fp, 'utf8'));
    assert.equal(onDisk.summary.deleted, 1);
  } finally { await s.cleanup(); }
});

test('writeExportReport: writes valid JSON to .agentic-security/export-report.json', async () => {
  const s = await mkSession();
  try {
    const report = buildExportReport({ root: s.dir, outDir: '/tmp/out', items: [{ name: 'a', status: 'exported', sha256: 'x' }] });
    const fp = writeExportReport(s.dir, report);
    assert.ok(fp && fp.endsWith(EXPORT_REPORT_FILE));
    const onDisk = JSON.parse(fs.readFileSync(fp, 'utf8'));
    assert.equal(onDisk.summary.exported, 1);
  } finally { await s.cleanup(); }
});

test('writeDeletionReport: returns null on a session with no project marker, never throws', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'state-lifecycle-nomarker-'));
  try {
    assert.doesNotThrow(() => writeDeletionReport(dir, buildDeletionReport({ mode: 'reset', dryRun: false, root: dir })));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ── real CLI: reset writes a deletion report ─────────────────────────────

test('reset (real CLI, dry-run): writes deletion-report.json with dryRun:true and "planned" items', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'last-scan.json'), '{}');
    const r = run(['reset', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    const reportPath = path.join(s.dir, '.agentic-security', DELETION_REPORT_FILE);
    assert.ok(fs.existsSync(reportPath), 'expected a deletion report to be written even on a dry run');
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.equal(report.dryRun, true);
    assert.ok(report.items.some(i => i.name === 'last-scan.json' && i.status === 'planned'));
    assert.ok(fs.existsSync(path.join(s.dir, '.agentic-security', 'last-scan.json')), 'dry run must not have deleted anything');
  } finally { await s.cleanup(); }
});

test('reset (real CLI, --yes): writes deletion-report.json with dryRun:false, "deleted" items, and preserved detail', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'last-scan.json'), '{}');
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'rules.yml'), 'custom: []\n');
    const r = run(['reset', '--yes', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Deletion report:/);
    const reportPath = path.join(s.dir, '.agentic-security', DELETION_REPORT_FILE);
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.equal(report.dryRun, false);
    assert.ok(report.items.some(i => i.name === 'last-scan.json' && i.status === 'deleted'));
    assert.ok(report.preserved.some(p => p.name === 'rules.yml' && p.reason === 'operator-authored configuration'));
    assert.equal(report.summary.deleted, report.items.filter(i => i.status === 'deleted').length);
  } finally { await s.cleanup(); }
});

// ── real CLI: export ──────────────────────────────────────────────────────

test('export (real CLI): --out is required', async () => {
  const s = await mkSession();
  try {
    const r = run(['export', '--root', s.dir]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /--out <dir> is required/);
  } finally { await s.cleanup(); }
});

test('export (real CLI): no state dir at all reports cleanly and exits 0', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'state-lifecycle-nostate-'));
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'state-lifecycle-out-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t"}');
    const r = run(['export', '--out', outDir, '--root', dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /No state to export/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(outDir, { recursive: true, force: true }); }
});

test('export (real CLI): copies BOTH generated and operator-config artifacts, writes a manifest with sha256, and records an export-report.json under .agentic-security/', async () => {
  const s = await mkSession();
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'state-lifecycle-out-'));
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'last-scan.json'), '{"findings":[]}'); // generated
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'rules.yml'), 'custom: []\n'); // operator-config

    const r = run(['export', '--out', outDir, '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Exported 2 artifact/);

    assert.ok(fs.existsSync(path.join(outDir, 'last-scan.json')), 'a generated artifact must be included in an export');
    assert.ok(fs.existsSync(path.join(outDir, 'rules.yml')), 'an operator-config artifact must ALSO be included in an export (unlike reset)');

    const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'export-manifest.json'), 'utf8'));
    assert.equal(manifest.summary.exported, 2);
    const lastScanEntry = manifest.items.find(i => i.name === 'last-scan.json');
    assert.equal(lastScanEntry.classification, 'generated');
    assert.equal(typeof lastScanEntry.sha256, 'string');
    assert.equal(lastScanEntry.sha256.length, 64, 'expected a real sha256 hex digest');

    const rulesEntry = manifest.items.find(i => i.name === 'rules.yml');
    assert.equal(rulesEntry.classification, 'operator-config');

    const reportPath = path.join(s.dir, '.agentic-security', EXPORT_REPORT_FILE);
    assert.ok(fs.existsSync(reportPath), 'expected a last-action export report under .agentic-security/ too');
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    assert.equal(report.summary.exported, 2);

    // Original files must still exist — export is a copy, never a move.
    assert.ok(fs.existsSync(path.join(s.dir, '.agentic-security', 'last-scan.json')));
    assert.ok(fs.existsSync(path.join(s.dir, '.agentic-security', 'rules.yml')));
  } finally { await s.cleanup(); fs.rmSync(outDir, { recursive: true, force: true }); }
});

test('export (real CLI): an artifact not present in this project is simply absent from the manifest, not reported as failed', async () => {
  const s = await mkSession();
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'state-lifecycle-out-'));
  try {
    // Empty .agentic-security/ — nothing registered is present.
    const r = run(['export', '--out', outDir, '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'export-manifest.json'), 'utf8'));
    assert.equal(manifest.items.length, 0);
    assert.equal(manifest.summary.failed, 0);
  } finally { await s.cleanup(); fs.rmSync(outDir, { recursive: true, force: true }); }
});
