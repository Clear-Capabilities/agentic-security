// On-disk layout, atomic state, the exclusive run lock and the controller lease.
// Everything the controller learns is written here, outside scanner-produced
// artifacts (.agentic-security/), so it can never be mistaken for scan evidence.
import { mkdirSync, openSync, closeSync, writeSync, unlinkSync, readFileSync, existsSync, readdirSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { atomicWriteJson, atomicWriteFile, readJson, appendJsonl, nowIso, redactDeep } from './util.mjs';
import { identityMatches, startTimeOf } from './procscan.mjs';

export const STATE_DIRNAME = '.loop-engineering';
export const HEARTBEAT_MS = 5000;
export const STALE_AFTER_MS = 15000;

export function layout(repoRoot, runId = null) {
  const base = resolve(repoRoot, STATE_DIRNAME);
  const l = {
    base,
    manifestDir: join(base, 'manifest'),
    lockFile: join(base, 'run.lock'),
    currentFile: join(base, 'current-run'),
    keyFile: join(base, 'evidence-key'),
    cacheDir: join(base, 'cache'),
  };
  if (runId) {
    const dir = join(base, 'runs', runId);
    Object.assign(l, {
      runId, dir,
      stateFile: join(dir, 'state.json'),
      leaseFile: join(dir, 'lease.json'),
      guardianLeaseFile: join(dir, 'guardian-lease.json'),
      controlFile: join(dir, 'control.json'),
      ownedFile: join(dir, 'owned.json'),
      eventsFile: join(dir, 'events.jsonl'),
      jobsFile: join(dir, 'jobs.jsonl'),
      leasesDir: join(dir, 'op-leases'),
      evidenceDir: join(dir, 'evidence'),
      attemptsDir: join(dir, 'attempts'),
      logsDir: join(dir, 'logs'),
      statusHtml: join(dir, 'status.html'),
      finalReport: join(dir, 'final-report.json'),
    });
  }
  return l;
}

export function ensureBase(repoRoot) {
  const l = layout(repoRoot);
  mkdirSync(l.base, { recursive: true, mode: 0o700 });
  return l;
}

// A per-checkout HMAC key used to sign evidence the verifier issues. It stops a
// casual hand-edited "pass"; it is not a defence against a worker with
// arbitrary code execution, which is why the final phase re-verifies from scratch.
export function evidenceKey(repoRoot) {
  const l = ensureBase(repoRoot);
  if (!existsSync(l.keyFile)) {
    atomicWriteFile(l.keyFile, randomBytes(32).toString('hex'), 0o600);
  }
  try { chmodSync(l.keyFile, 0o600); } catch { /* best effort */ }
  return readFileSync(l.keyFile, 'utf8').trim();
}

export function newRunId() {
  const ts = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return `run-${ts}-${randomBytes(3).toString('hex')}`;
}

export function currentRunId(repoRoot) {
  const l = layout(repoRoot);
  try { return readFileSync(l.currentFile, 'utf8').trim() || null; } catch { return null; }
}
export function setCurrentRun(repoRoot, runId) {
  atomicWriteFile(layout(repoRoot).currentFile, runId + '\n', 0o600);
}

export function listRunIds(repoRoot) {
  try { return readdirSync(join(layout(repoRoot).base, 'runs')).sort(); } catch { return []; }
}

export function appendEvent(L, type, data = {}) {
  appendJsonl(L.eventsFile, { at: nowIso(), type, ...redactDeep(data) });
}

export function readEvents(L, limit = 200) {
  try {
    const lines = readFileSync(L.eventsFile, 'utf8').trim().split('\n').filter(Boolean);
    return lines.slice(-limit).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}

export function recordJob(L, result) {
  const slim = { ...result, stdoutTail: undefined, stderrTail: undefined };
  appendJsonl(L.jobsFile, redactDeep(slim));
}

// ---- exclusive run lock ------------------------------------------------------
// The lock is a file created with O_EXCL. A lock whose owner is not the same
// (pid, start time) process is stale and may be taken over; a live owner is
// never overridden, whatever its lease says.
export function acquireRunLock(repoRoot, info) {
  const l = ensureBase(repoRoot);
  const mine = { pid: process.pid, start: startTimeOf(process.pid), ...info, acquiredAt: nowIso() };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(l.lockFile, 'wx', 0o600);
      writeSync(fd, JSON.stringify(mine, null, 2));
      closeSync(fd);
      return { ok: true, lock: mine };
    } catch (e) {
      if (e.code !== 'EEXIST') return { ok: false, reason: `lock error: ${e.code || e.message}` };
      const cur = readJson(l.lockFile, null);
      if (cur && cur.pid && identityMatches(cur.pid, cur.start)) {
        return { ok: false, reason: `run ${cur.runId || '?'} is active (pid ${cur.pid})`, holder: cur };
      }
      try { unlinkSync(l.lockFile); } catch { /* raced */ }
    }
  }
  return { ok: false, reason: 'could not acquire run lock' };
}

export function updateRunLock(repoRoot, patch) {
  const l = layout(repoRoot);
  const cur = readJson(l.lockFile, null);
  if (!cur) return;
  atomicWriteJson(l.lockFile, { ...cur, ...patch });
}

export function releaseRunLock(repoRoot, pid = process.pid) {
  const l = layout(repoRoot);
  const cur = readJson(l.lockFile, null);
  if (cur && cur.pid !== pid && identityMatches(cur.pid, cur.start)) return false;
  try { unlinkSync(l.lockFile); } catch { /* already gone */ }
  return true;
}

// ---- lease -------------------------------------------------------------------
export function writeLease(file, lease) {
  atomicWriteJson(file, { ...lease, wallAt: Date.now(), at: nowIso() });
}

// Judge liveness from the lease AND the process identity. A dead controller
// cannot update its own state, so this is computed by the reader.
export function judgeLease(file, now = Date.now()) {
  const lease = readJson(file, null);
  if (!lease) return { state: 'absent', lease: null };
  const ageMs = now - (lease.wallAt || 0);
  const alive = identityMatches(lease.pid, lease.start);
  if (!alive) return { state: 'dead', ageMs, lease };
  if (ageMs > STALE_AFTER_MS) return { state: 'stale', ageMs, lease };
  return { state: 'live', ageMs, lease };
}
