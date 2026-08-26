// FR-707 (assurance-hardening PRD): "Support legal hold and policy-
// authorized retention exceptions | Legal hold is identity-bound, reasoned,
// time-bounded where applicable, and auditable."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  loadLegalHolds, isUnderHold, listLegalHolds, addLegalHold, removeLegalHold, LEGAL_HOLD_FILE,
} from '../src/posture/legal-hold.js';
import { findExpiredArtifacts, RETENTION_DEFAULTS } from '../src/posture/retention-policy.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'scanner', 'bin', 'agentic-security.js');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: path.join(REPO_ROOT, 'scanner'), encoding: 'utf8', timeout: 30_000 });
}

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'legal-hold-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

const DAY_MS = 24 * 60 * 60 * 1000;
function setAge(file, days) {
  const t = (Date.now() - days * DAY_MS) / 1000;
  fs.utimesSync(file, t, t);
}

// ── loadLegalHolds / isUnderHold / listLegalHolds (pure-ish) ─────────────

test('loadLegalHolds: no file present returns an empty array, never throws', async () => {
  const s = await mkSession();
  try { assert.deepEqual(loadLegalHolds(s.dir), []); } finally { await s.cleanup(); }
});

test('loadLegalHolds: malformed JSON degrades to empty array', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', LEGAL_HOLD_FILE), '{ not valid json [[[');
    assert.deepEqual(loadLegalHolds(s.dir), []);
  } finally { await s.cleanup(); }
});

test('loadLegalHolds: malformed entries (missing owner/reason/artifact) are dropped, well-formed ones survive', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', LEGAL_HOLD_FILE), JSON.stringify([
      { artifact: 'last-scan.json', owner: 'legal@co', reason: 'litigation hold' },
      { artifact: 'no-owner.json', reason: 'x' },
      { owner: 'x', reason: 'x' },
      'not even an object',
    ]));
    const holds = loadLegalHolds(s.dir);
    assert.equal(holds.length, 1);
    assert.equal(holds[0].artifact, 'last-scan.json');
  } finally { await s.cleanup(); }
});

test('isUnderHold: no expires_at is an INDEFINITE hold, always active', () => {
  const holds = [{ artifact: 'a', owner: 'x', reason: 'y', expires_at: null }];
  assert.ok(isUnderHold('a', holds));
  assert.equal(isUnderHold('b', holds), null);
});

test('isUnderHold: a future expires_at is still active; a past one is not', () => {
  const future = new Date(Date.now() + DAY_MS).toISOString();
  const past = new Date(Date.now() - DAY_MS).toISOString();
  assert.ok(isUnderHold('a', [{ artifact: 'a', owner: 'x', reason: 'y', expires_at: future }]));
  assert.equal(isUnderHold('a', [{ artifact: 'a', owner: 'x', reason: 'y', expires_at: past }]), null);
});

test('listLegalHolds: excludes expired by default, includes with includeExpired', async () => {
  const s = await mkSession();
  try {
    const past = new Date(Date.now() - DAY_MS).toISOString();
    fs.writeFileSync(path.join(s.dir, '.agentic-security', LEGAL_HOLD_FILE), JSON.stringify([
      { artifact: 'a', owner: 'x', reason: 'y', expires_at: past },
      { artifact: 'b', owner: 'x', reason: 'y', expires_at: null },
    ]));
    assert.deepEqual(listLegalHolds(s.dir).map(h => h.artifact), ['b']);
    assert.deepEqual(listLegalHolds(s.dir, { includeExpired: true }).map(h => h.artifact).sort(), ['a', 'b']);
  } finally { await s.cleanup(); }
});

// ── addLegalHold / removeLegalHold ────────────────────────────────────────

test('addLegalHold: requires artifact, owner, and reason', async () => {
  const s = await mkSession();
  try {
    assert.equal(addLegalHold(s.dir, { owner: 'x', reason: 'y' }).ok, false);
    assert.equal(addLegalHold(s.dir, { artifact: 'last-scan.json', reason: 'y' }).ok, false);
    assert.equal(addLegalHold(s.dir, { artifact: 'last-scan.json', owner: 'x' }).ok, false);
  } finally { await s.cleanup(); }
});

test('addLegalHold: refuses an unregistered artifact name (almost always a typo)', async () => {
  const s = await mkSession();
  try {
    const r = addLegalHold(s.dir, { artifact: 'totally-made-up-name.json', owner: 'x', reason: 'y' });
    assert.equal(r.ok, false);
    assert.match(r.reason, /not a registered state artifact/);
  } finally { await s.cleanup(); }
});

test('addLegalHold: refuses an expires_at already in the past', async () => {
  const s = await mkSession();
  try {
    const past = new Date(Date.now() - DAY_MS).toISOString();
    const r = addLegalHold(s.dir, { artifact: 'last-scan.json', owner: 'x', reason: 'y', expires_at: past });
    assert.equal(r.ok, false);
    assert.match(r.reason, /already expired/);
  } finally { await s.cleanup(); }
});

test('addLegalHold: a valid hold is persisted and re-readable', async () => {
  const s = await mkSession();
  try {
    const r = addLegalHold(s.dir, { artifact: 'last-scan.json', owner: 'legal@co', reason: 'litigation hold #123' });
    assert.equal(r.ok, true);
    assert.equal(r.hold.artifact, 'last-scan.json');
    assert.equal(r.hold.expires_at, null);
    assert.equal(typeof r.hold.created_at, 'string');
    assert.deepEqual(loadLegalHolds(s.dir).map(h => h.artifact), ['last-scan.json']);
  } finally { await s.cleanup(); }
});

test('removeLegalHold: removes a matching hold and reports the count; a no-op for an unheld artifact returns 0', async () => {
  const s = await mkSession();
  try {
    addLegalHold(s.dir, { artifact: 'last-scan.json', owner: 'x', reason: 'y' });
    assert.equal(removeLegalHold(s.dir, 'last-scan.json'), 1);
    assert.deepEqual(loadLegalHolds(s.dir), []);
    assert.equal(removeLegalHold(s.dir, 'last-scan.json'), 0);
  } finally { await s.cleanup(); }
});

// ── findExpiredArtifacts integration (retention-policy.js) ────────────────

test('findExpiredArtifacts: an artifact past its TTL but under an active legal hold is NOT reported as expired', async () => {
  const s = await mkSession();
  try {
    const f = path.join(s.dir, '.agentic-security', 'last-scan.json'); // retentionClass: 'scan'
    fs.writeFileSync(f, '{}');
    setAge(f, RETENTION_DEFAULTS.scan.defaultDays + 5);
    assert.ok(findExpiredArtifacts(s.dir).map(e => e.name).includes('last-scan.json'), 'sanity: it IS expired before any hold');

    addLegalHold(s.dir, { artifact: 'last-scan.json', owner: 'legal@co', reason: 'litigation hold' });
    assert.ok(!findExpiredArtifacts(s.dir).map(e => e.name).includes('last-scan.json'), 'a held artifact must never be reported as expired');
  } finally { await s.cleanup(); }
});

test('findExpiredArtifacts: once the hold expires, the artifact is expired again (a hold is not permanent unless indefinite)', async () => {
  const s = await mkSession();
  try {
    const f = path.join(s.dir, '.agentic-security', 'last-scan.json');
    fs.writeFileSync(f, '{}');
    setAge(f, RETENTION_DEFAULTS.scan.defaultDays + 5);
    const soon = new Date(Date.now() + 100).toISOString(); // expires almost immediately
    addLegalHold(s.dir, { artifact: 'last-scan.json', owner: 'x', reason: 'y', expires_at: soon });
    const stillHeld = findExpiredArtifacts(s.dir, { now: Date.now() + 50 });
    assert.ok(!stillHeld.map(e => e.name).includes('last-scan.json'));
    const afterExpiry = findExpiredArtifacts(s.dir, { now: Date.now() + 200 });
    assert.ok(afterExpiry.map(e => e.name).includes('last-scan.json'));
  } finally { await s.cleanup(); }
});

// ── real CLI: legal-hold add/remove/list ─────────────────────────────────

test('legal-hold add (real CLI): validates required flags', async () => {
  const s = await mkSession();
  try {
    const r = run(['legal-hold', 'add', '--artifact', 'last-scan.json', '--reason', 'y', '--root', s.dir]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /--owner is required/);
  } finally { await s.cleanup(); }
});

test('legal-hold add/list/remove (real CLI): full round trip', async () => {
  const s = await mkSession();
  try {
    const add = run(['legal-hold', 'add', '--artifact', 'last-scan.json', '--owner', 'legal@co', '--reason', 'litigation hold', '--root', s.dir]);
    assert.equal(add.status, 0, add.stderr);
    assert.match(add.stdout, /Legal hold placed on "last-scan\.json"/);

    const list = run(['legal-hold', 'list', '--root', s.dir]);
    assert.equal(list.status, 0);
    assert.match(list.stdout, /last-scan\.json/);
    assert.match(list.stdout, /legal@co/);

    const remove = run(['legal-hold', 'remove', '--artifact', 'last-scan.json', '--root', s.dir]);
    assert.equal(remove.status, 0);
    assert.match(remove.stdout, /Removed 1 hold/);

    const listAfter = run(['legal-hold', 'list', '--root', s.dir]);
    assert.match(listAfter.stdout, /No active legal holds/);
  } finally { await s.cleanup(); }
});

// ── real CLI: reset honors an active hold on BOTH the plain and --expired paths ──

test('reset --yes (real CLI, plain mode): a held GENERATED artifact survives; an unheld one of the same kind is still deleted', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'last-scan.json'), '{}');
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'dpia.md'), '# DPIA\n');
    run(['legal-hold', 'add', '--artifact', 'last-scan.json', '--owner', 'legal@co', '--reason', 'litigation hold', '--root', s.dir]);

    const r = run(['reset', '--yes', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(path.join(s.dir, '.agentic-security', 'last-scan.json')), 'held artifact must survive a plain reset');
    assert.ok(!fs.existsSync(path.join(s.dir, '.agentic-security', 'dpia.md')), 'an unheld generated artifact must still be deleted');

    const report = JSON.parse(fs.readFileSync(path.join(s.dir, '.agentic-security', 'deletion-report.json'), 'utf8'));
    const preservedEntry = report.preserved.find(p => p.name === 'last-scan.json');
    assert.ok(preservedEntry, 'the held artifact must be named in the deletion report preserved list');
    assert.match(preservedEntry.reason, /active legal hold/);
  } finally { await s.cleanup(); }
});

test('reset --expired --yes (real CLI): a held, otherwise-expired artifact survives', async () => {
  const s = await mkSession();
  try {
    const f = path.join(s.dir, '.agentic-security', 'last-scan.json');
    fs.writeFileSync(f, '{}');
    setAge(f, RETENTION_DEFAULTS.scan.defaultDays + 5);
    run(['legal-hold', 'add', '--artifact', 'last-scan.json', '--owner', 'legal@co', '--reason', 'litigation hold', '--root', s.dir]);

    const r = run(['reset', '--expired', '--yes', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(f), 'a held, otherwise-expired artifact must survive --expired reset too');
  } finally { await s.cleanup(); }
});

test('legal-holds.json itself is never deleted by a plain reset, held or not (it is operator-config)', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', 'last-scan.json'), '{}');
    run(['legal-hold', 'add', '--artifact', 'last-scan.json', '--owner', 'legal@co', '--reason', 'litigation hold', '--root', s.dir]);
    const r = run(['reset', '--yes', '--root', s.dir]);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(path.join(s.dir, '.agentic-security', LEGAL_HOLD_FILE)), 'the hold registry itself must never be wiped by reset');
  } finally { await s.cleanup(); }
});
