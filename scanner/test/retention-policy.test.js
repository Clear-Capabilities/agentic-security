// FR-702 (assurance-hardening PRD): "Enforce default and maximum TTL by
// artifact class | Expired caches, scans, evidence, tickets, and backups
// are purged or archived according to policy."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  RETENTION_DEFAULTS, loadRetentionPolicy, effectiveTtlDays, findExpiredArtifacts,
} from '../src/posture/retention-policy.js';
import { listArtifactsWithRetentionClass, retentionClassOf } from '../src/posture/artifact-registry.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'scanner', 'bin', 'agentic-security.js');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: path.join(REPO_ROOT, 'scanner'), encoding: 'utf8', timeout: 30_000 });
}

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'retention-policy-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: async () => fsp.rm(dir, { recursive: true, force: true }) };
}

const DAY_MS = 24 * 60 * 60 * 1000;
function setAge(file, days) {
  const t = (Date.now() - days * DAY_MS) / 1000;
  fs.utimesSync(file, t, t);
}

// ── RETENTION_DEFAULTS sanity ────────────────────────────────────────────

test('RETENTION_DEFAULTS: all 5 named classes are present, each with default <= max', () => {
  for (const cls of ['cache', 'scan', 'evidence', 'ticket', 'backup']) {
    const b = RETENTION_DEFAULTS[cls];
    assert.ok(b, `expected a bound for '${cls}'`);
    assert.ok(b.defaultDays <= b.maxDays, `${cls}: defaultDays must not exceed maxDays`);
    assert.ok(b.defaultDays > 0 && b.maxDays > 0);
  }
});

test('artifact-registry: at least one real artifact is classed per named category', () => {
  const byClass = {};
  for (const a of listArtifactsWithRetentionClass()) byClass[a.retentionClass] = (byClass[a.retentionClass] || 0) + 1;
  for (const cls of ['cache', 'scan', 'evidence', 'ticket', 'backup']) {
    assert.ok(byClass[cls] > 0, `expected at least one artifact classed '${cls}'`);
  }
});

test('artifact-registry: an artifact whose deletion would be a real loss (not cleanup) carries NO retention class', () => {
  for (const name of ['AGENTS.md', 'validator-metrics.json', 'triage-feedback.json', 'streak.json', 'baseline.json', 'cve-alerts-state.json']) {
    assert.equal(retentionClassOf(name), null, `${name} must not be auto-expired`);
  }
});

// ── loadRetentionPolicy ───────────────────────────────────────────────────

test('loadRetentionPolicy: no file present returns null (the common, unconfigured case)', async () => {
  const sess = await mkSession();
  try { assert.equal(loadRetentionPolicy(sess.dir), null); }
  finally { await sess.cleanup(); }
});

test('loadRetentionPolicy: malformed YAML degrades to null, never throws', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'retention-policy.yml'), '{ not: valid: [[[');
    assert.doesNotThrow(() => loadRetentionPolicy(sess.dir));
    assert.equal(loadRetentionPolicy(sess.dir), null);
  } finally { await sess.cleanup(); }
});

test('loadRetentionPolicy: a well-formed override loads correctly', async () => {
  const sess = await mkSession();
  try {
    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'retention-policy.yml'), 'cache:\n  defaultDays: 3\n');
    assert.deepEqual(loadRetentionPolicy(sess.dir), { cache: { defaultDays: 3 } });
  } finally { await sess.cleanup(); }
});

// ── effectiveTtlDays ──────────────────────────────────────────────────────

test('effectiveTtlDays: no policy configured uses the built-in default', () => {
  assert.equal(effectiveTtlDays('cache', null), RETENTION_DEFAULTS.cache.defaultDays);
});

test('effectiveTtlDays: an operator override WITHIN the ceiling is honored', () => {
  assert.equal(effectiveTtlDays('cache', { cache: { defaultDays: 2 } }), 2);
});

test('effectiveTtlDays: an operator override EXCEEDING the ceiling is clamped, never raised past maxDays', () => {
  const huge = RETENTION_DEFAULTS.evidence.maxDays + 10000;
  assert.equal(effectiveTtlDays('evidence', { evidence: { defaultDays: huge } }), RETENTION_DEFAULTS.evidence.maxDays);
});

test('effectiveTtlDays: an unrecognised class returns null (not subject to a TTL)', () => {
  assert.equal(effectiveTtlDays('not-a-real-class', null), null);
});

// ── findExpiredArtifacts ──────────────────────────────────────────────────

test('findExpiredArtifacts: no state dir at all returns an empty array, never throws', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'retention-nostate-'));
  try {
    assert.doesNotThrow(() => findExpiredArtifacts(dir));
    assert.deepEqual(findExpiredArtifacts(dir), []);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('findExpiredArtifacts: a retention-classed artifact past its TTL is flagged; a fresh one is not', async () => {
  const sess = await mkSession();
  try {
    const oldFile = path.join(sess.dir, '.agentic-security', 'last-scan.json'); // retentionClass: 'scan'
    fs.writeFileSync(oldFile, '{}');
    setAge(oldFile, RETENTION_DEFAULTS.scan.defaultDays + 5);

    const freshFile = path.join(sess.dir, '.agentic-security', 'findings.json'); // retentionClass: 'scan'
    fs.writeFileSync(freshFile, '{}');

    const expired = findExpiredArtifacts(sess.dir);
    const names = expired.map(e => e.name);
    assert.ok(names.includes('last-scan.json'), 'the old scan artifact must be flagged');
    assert.ok(!names.includes('findings.json'), 'the fresh scan artifact must not be flagged');
  } finally { await sess.cleanup(); }
});

test('findExpiredArtifacts: an artifact with NO retention class is never flagged, no matter how old', async () => {
  const sess = await mkSession();
  try {
    const oldFile = path.join(sess.dir, '.agentic-security', 'streak.json'); // no retentionClass
    fs.writeFileSync(oldFile, '{}');
    setAge(oldFile, 10000);
    const expired = findExpiredArtifacts(sess.dir);
    assert.ok(!expired.map(e => e.name).includes('streak.json'));
  } finally { await sess.cleanup(); }
});

test('findExpiredArtifacts: an operator-configured shorter TTL expires an artifact that the built-in default would not', async () => {
  const sess = await mkSession();
  try {
    const f = path.join(sess.dir, '.agentic-security', 'last-scan.json');
    fs.writeFileSync(f, '{}');
    setAge(f, 5); // well within the built-in 90-day default
    assert.deepEqual(findExpiredArtifacts(sess.dir).map(e => e.name), []);

    await fsp.writeFile(path.join(sess.dir, '.agentic-security', 'retention-policy.yml'), 'scan:\n  defaultDays: 1\n');
    const expired = findExpiredArtifacts(sess.dir);
    assert.ok(expired.map(e => e.name).includes('last-scan.json'), 'a shorter operator-configured TTL must be honored');
  } finally { await sess.cleanup(); }
});

// ── real CLI: reset --expired ─────────────────────────────────────────────

test('reset --expired (real CLI): dry-run reports only expired artifacts, deletes nothing', async () => {
  const sess = await mkSession();
  try {
    const oldFile = path.join(sess.dir, '.agentic-security', 'last-scan.json');
    fs.writeFileSync(oldFile, '{}');
    setAge(oldFile, RETENTION_DEFAULTS.scan.defaultDays + 5);
    const freshFile = path.join(sess.dir, '.agentic-security', 'findings.json');
    fs.writeFileSync(freshFile, '{}');

    const r = run(['reset', '--expired', '--root', sess.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /will remove.*\n.*last-scan\.json/s);
    assert.match(r.stdout, /Preserving.*findings\.json/s, 'the fresh artifact must be reported as PRESERVED, not scheduled for removal');
    assert.doesNotMatch(r.stdout.split('Preserving')[0], /findings\.json/, 'findings.json must not appear in the removal list');
    assert.match(r.stdout, /Pass --yes to proceed/);
    assert.ok(fs.existsSync(oldFile), 'a dry run must not delete anything');
  } finally { await sess.cleanup(); }
});

test('reset --expired --yes (real CLI): deletes ONLY expired artifacts, preserving fresh generated artifacts and operator-config', async () => {
  const sess = await mkSession();
  try {
    const oldFile = path.join(sess.dir, '.agentic-security', 'last-scan.json');
    fs.writeFileSync(oldFile, '{}');
    setAge(oldFile, RETENTION_DEFAULTS.scan.defaultDays + 5);

    const freshFile = path.join(sess.dir, '.agentic-security', 'findings.json');
    fs.writeFileSync(freshFile, '{}');

    const operatorConfig = path.join(sess.dir, '.agentic-security', 'rules.yml');
    fs.writeFileSync(operatorConfig, 'custom: []\n');
    setAge(operatorConfig, RETENTION_DEFAULTS.scan.maxDays + 100); // ancient, but operator-config — must survive regardless

    const r = run(['reset', '--expired', '--yes', '--root', sess.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!fs.existsSync(oldFile), 'the expired artifact must be deleted');
    assert.ok(fs.existsSync(freshFile), 'a fresh generated artifact of the same class must survive');
    assert.ok(fs.existsSync(operatorConfig), 'operator-config must NEVER be auto-expired, no matter how old');
  } finally { await sess.cleanup(); }
});

test('reset --expired (real CLI): nothing expired reports cleanly and exits 0', async () => {
  const sess = await mkSession();
  try {
    const r = run(['reset', '--expired', '--root', sess.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Nothing expired/);
  } finally { await sess.cleanup(); }
});
