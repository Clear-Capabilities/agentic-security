// The fleet job store (PRD 4, requirements 2 and 3): jobs with a lease, a heartbeat, a retry count, a timeout and a result hash,
// behind one small interface so the storage can change without the scheduler noticing.
//
//   createSqliteJobStore({ file })   local deployment, one file, no server (node:sqlite)
//   createMemoryJobStore()           the reference implementation; the conformance tests run the SAME assertions against both,
//                                    which is what shows the interface does not secretly depend on SQLite. A PostgreSQL or a
//                                    queue-backed store would be a third implementation of the same methods.
//
// Semantics that matter (and are tested on both stores):
//   * IDEMPOTENT: a job's id is derived from its run, repository, commit and configuration, and `enqueue` of an existing id does
//     nothing. Enqueueing a run twice does not make two jobs.
//   * LEASED: `claim` hands one queued job to one worker, increments a fencing `epoch`, and starts a lease. A worker that stops
//     heartbeating loses the job when the lease expires; `reclaimExpired` puts it back in the queue.
//   * FENCED: `heartbeat`, `complete` and `fail` must present the epoch they were given. A worker that lost its lease (and whose
//     job another worker now holds) is refused, so a slow zombie can neither extend a lease it no longer has nor overwrite the
//     result of the worker that replaced it. That is what keeps a retry from duplicating findings.
//   * BOUNDED RETRIES: a failure puts the job back in the queue until `maxAttempts`, then it is `failed` (or `timed_out`),
//     terminal, and visible in the organization's health. A job is never silently dropped.
import fs from 'node:fs';
import path from 'node:path';

export const JOB_STATUSES = Object.freeze(['queued', 'leased', 'succeeded', 'partial', 'failed', 'timed_out', 'cancelled']);
const TERMINAL = new Set(['succeeded', 'partial', 'failed', 'timed_out', 'cancelled']);
export const isTerminal = (s) => TERMINAL.has(s);

const jobOf = (r) => (r ? {
  jobId: r.job_id, runId: r.run_id, repoId: r.repo_id, commit: r.commit_sha ?? null, cacheKey: r.cache_key ?? null, status: r.status, worker: r.worker ?? null,
  epoch: r.epoch, leaseExpiresAt: r.lease_expires_at ?? null, heartbeatAt: r.heartbeat_at ?? null, attempts: r.attempts, maxAttempts: r.max_attempts,
  timeoutMs: r.timeout_ms, nextAttemptAt: r.next_attempt_at ?? 0, artifactSha256: r.artifact_sha256 ?? null, summary: r.summary ? JSON.parse(r.summary) : null,
  error: r.error ?? null, createdAt: r.created_at, startedAt: r.started_at ?? null, finishedAt: r.finished_at ?? null, required: !!r.required,
} : null);

// ------------------------------------------------------------------------------------------------------- memory
export function createMemoryJobStore() {
  const runs = new Map(); const jobs = new Map();
  const all = (runId) => [...jobs.values()].filter((j) => j.runId === runId);
  const store = {
    kind: 'memory',
    begin(run) { if (!runs.has(run.runId)) runs.set(run.runId, { ...run }); return runs.get(run.runId); },
    getRun: (runId) => runs.get(runId) ?? null,
    listRuns: () => [...runs.values()].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))),
    enqueue(runId, list, { now = Date.now() } = {}) {
      let created = 0;
      for (const j of list) { if (jobs.has(j.jobId)) continue; jobs.set(j.jobId, { runId, repoId: j.repoId, jobId: j.jobId, commit: j.commit ?? null, cacheKey: j.cacheKey ?? null, status: 'queued', worker: null, epoch: 0, leaseExpiresAt: null, heartbeatAt: null, attempts: 0, maxAttempts: j.maxAttempts ?? 2, timeoutMs: j.timeoutMs, nextAttemptAt: 0, artifactSha256: null, summary: null, error: null, createdAt: now, startedAt: null, finishedAt: null, required: j.required !== false }); created++; }
      return created;
    },
    claim(runId, { worker, leaseMs, now = Date.now() }) {
      const j = all(runId).filter((x) => x.status === 'queued' && x.nextAttemptAt <= now).sort((a, b) => a.createdAt - b.createdAt || a.repoId.localeCompare(b.repoId))[0];
      if (!j) return null;
      Object.assign(j, { status: 'leased', worker, epoch: j.epoch + 1, attempts: j.attempts + 1, leaseExpiresAt: now + leaseMs, heartbeatAt: now, startedAt: now, error: null });
      return { ...j };
    },
    heartbeat(jobId, epoch, { now = Date.now(), leaseMs }) { const j = jobs.get(jobId); if (!j || j.status !== 'leased' || j.epoch !== epoch) return false; j.heartbeatAt = now; j.leaseExpiresAt = now + leaseMs; return true; },
    complete(jobId, epoch, { status = 'succeeded', artifactSha256 = null, summary = null, now = Date.now() }) {
      const j = jobs.get(jobId); if (!j || j.status !== 'leased' || j.epoch !== epoch) return false;
      Object.assign(j, { status, artifactSha256, summary, finishedAt: now, leaseExpiresAt: null, error: null }); return true;
    },
    fail(jobId, epoch, { error, timedOut = false, now = Date.now(), retryDelayMs = 0 }) {
      const j = jobs.get(jobId); if (!j || j.status !== 'leased' || j.epoch !== epoch) return null;
      j.error = String(error ?? '').slice(0, 500); j.leaseExpiresAt = null; j.worker = null;
      if (j.attempts < j.maxAttempts) { j.status = 'queued'; j.nextAttemptAt = now + retryDelayMs; return { state: 'queued', attempts: j.attempts }; }
      j.status = timedOut ? 'timed_out' : 'failed'; j.finishedAt = now; return { state: j.status, attempts: j.attempts };
    },
    reclaimExpired(runId, { now = Date.now() }) { let n = 0; for (const j of all(runId)) if (j.status === 'leased' && j.leaseExpiresAt != null && j.leaseExpiresAt <= now) { j.status = 'queued'; j.worker = null; j.leaseExpiresAt = null; j.nextAttemptAt = 0; j.error = 'lease expired'; n++; } return n; },
    reclaimWorker(runId, worker) { let n = 0; for (const j of all(runId)) if (j.status === 'leased' && j.worker === worker) { j.status = 'queued'; j.worker = null; j.leaseExpiresAt = null; j.nextAttemptAt = 0; j.error = 'worker is gone'; n++; } return n; },
    cancel(runId, { now = Date.now() }) { let n = 0; for (const j of all(runId)) if (!TERMINAL.has(j.status)) { j.status = 'cancelled'; j.finishedAt = now; j.leaseExpiresAt = null; n++; } return n; },
    retime(runId, timeoutMs) { let n = 0; for (const j of all(runId)) if (j.status === 'queued') { j.timeoutMs = timeoutMs; n++; } return n; },
    requeueTerminal(runId, statuses) { let n = 0; for (const j of all(runId)) if (statuses.includes(j.status)) { Object.assign(j, { status: 'queued', worker: null, attempts: 0, nextAttemptAt: 0, leaseExpiresAt: null, finishedAt: null, error: null }); n++; } return n; },
    listJobs: (runId) => all(runId).map((j) => ({ ...j })).sort((a, b) => a.repoId.localeCompare(b.repoId)),
    getJob: (jobId) => (jobs.get(jobId) ? { ...jobs.get(jobId) } : null),
    close() {},
  };
  return store;
}

// ------------------------------------------------------------------------------------------------------- sqlite
const SCHEMA = `
CREATE TABLE IF NOT EXISTS fleet_runs (run_id TEXT PRIMARY KEY, organization TEXT NOT NULL, manifest_hash TEXT NOT NULL, config_hash TEXT NOT NULL, scanner_identity TEXT, created_at INTEGER NOT NULL, meta TEXT);
CREATE TABLE IF NOT EXISTS fleet_jobs (
  job_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES fleet_runs(run_id), repo_id TEXT NOT NULL, commit_sha TEXT, cache_key TEXT,
  status TEXT NOT NULL, worker TEXT, epoch INTEGER NOT NULL DEFAULT 0, lease_expires_at INTEGER, heartbeat_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL, timeout_ms INTEGER NOT NULL, next_attempt_at INTEGER NOT NULL DEFAULT 0,
  artifact_sha256 TEXT, summary TEXT, error TEXT, created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER, required INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS fleet_jobs_run_status ON fleet_jobs (run_id, status);
`;

export async function createSqliteJobStore({ file }) {
  const { DatabaseSync } = await import('node:sqlite');
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(file);
  // the busy timeout comes FIRST: the very next statements (switching the journal mode, creating tables) take locks, and another process
  // opening the same file at the same instant must wait for them instead of failing with "database is locked"
  db.exec('PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  const tx = (fn) => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { try { db.exec('ROLLBACK'); } catch { /* already rolled back */ } throw e; } };
  const q = (sql, ...p) => db.prepare(sql).all(...p);
  const one = (sql, ...p) => db.prepare(sql).get(...p);
  const run = (sql, ...p) => db.prepare(sql).run(...p);
  return {
    kind: 'sqlite', file,
    begin(r) { run('INSERT OR IGNORE INTO fleet_runs (run_id, organization, manifest_hash, config_hash, scanner_identity, created_at, meta) VALUES (?,?,?,?,?,?,?)', r.runId, r.organization, r.manifestHash, r.configHash, r.scannerIdentity ?? null, r.createdAt, JSON.stringify(r.meta ?? {})); return this.getRun(r.runId); },
    getRun(runId) { const r = one('SELECT * FROM fleet_runs WHERE run_id = ?', runId); return r ? { runId: r.run_id, organization: r.organization, manifestHash: r.manifest_hash, configHash: r.config_hash, scannerIdentity: r.scanner_identity, createdAt: r.created_at, meta: JSON.parse(r.meta ?? '{}') } : null; },
    listRuns() { return q('SELECT * FROM fleet_runs ORDER BY created_at DESC').map((r) => ({ runId: r.run_id, organization: r.organization, manifestHash: r.manifest_hash, createdAt: r.created_at })); },
    enqueue(runId, list, { now = Date.now() } = {}) {
      return tx(() => { let created = 0; for (const j of list) { const r = run('INSERT OR IGNORE INTO fleet_jobs (job_id, run_id, repo_id, commit_sha, cache_key, status, max_attempts, timeout_ms, created_at, required) VALUES (?,?,?,?,?,?,?,?,?,?)', j.jobId, runId, j.repoId, j.commit ?? null, j.cacheKey ?? null, 'queued', j.maxAttempts ?? 2, j.timeoutMs, now, j.required === false ? 0 : 1); created += Number(r.changes); } return created; });
    },
    claim(runId, { worker, leaseMs, now = Date.now() }) {
      return tx(() => {
        const j = one("SELECT job_id FROM fleet_jobs WHERE run_id = ? AND status = 'queued' AND next_attempt_at <= ? ORDER BY created_at, repo_id LIMIT 1", runId, now);
        if (!j) return null;
        run("UPDATE fleet_jobs SET status = 'leased', worker = ?, epoch = epoch + 1, attempts = attempts + 1, lease_expires_at = ?, heartbeat_at = ?, started_at = ?, error = NULL WHERE job_id = ?", worker, now + leaseMs, now, now, j.job_id);
        return jobOf(one('SELECT * FROM fleet_jobs WHERE job_id = ?', j.job_id));
      });
    },
    heartbeat(jobId, epoch, { now = Date.now(), leaseMs }) { return Number(run("UPDATE fleet_jobs SET heartbeat_at = ?, lease_expires_at = ? WHERE job_id = ? AND status = 'leased' AND epoch = ?", now, now + leaseMs, jobId, epoch).changes) === 1; },
    complete(jobId, epoch, { status = 'succeeded', artifactSha256 = null, summary = null, now = Date.now() }) { return Number(run("UPDATE fleet_jobs SET status = ?, artifact_sha256 = ?, summary = ?, finished_at = ?, lease_expires_at = NULL, error = NULL WHERE job_id = ? AND status = 'leased' AND epoch = ?", status, artifactSha256, summary ? JSON.stringify(summary) : null, now, jobId, epoch).changes) === 1; },
    fail(jobId, epoch, { error, timedOut = false, now = Date.now(), retryDelayMs = 0 }) {
      return tx(() => {
        const j = one("SELECT attempts, max_attempts FROM fleet_jobs WHERE job_id = ? AND status = 'leased' AND epoch = ?", jobId, epoch);
        if (!j) return null;
        const msg = String(error ?? '').slice(0, 500);
        if (j.attempts < j.max_attempts) { run("UPDATE fleet_jobs SET status = 'queued', worker = NULL, lease_expires_at = NULL, next_attempt_at = ?, error = ? WHERE job_id = ?", now + retryDelayMs, msg, jobId); return { state: 'queued', attempts: j.attempts }; }
        const st = timedOut ? 'timed_out' : 'failed';
        run('UPDATE fleet_jobs SET status = ?, worker = NULL, lease_expires_at = NULL, finished_at = ?, error = ? WHERE job_id = ?', st, now, msg, jobId);
        return { state: st, attempts: j.attempts };
      });
    },
    reclaimExpired(runId, { now = Date.now() }) { return Number(run("UPDATE fleet_jobs SET status = 'queued', worker = NULL, lease_expires_at = NULL, next_attempt_at = 0, error = 'lease expired' WHERE run_id = ? AND status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?", runId, now).changes); },
    reclaimWorker(runId, worker) { return Number(run("UPDATE fleet_jobs SET status = 'queued', worker = NULL, lease_expires_at = NULL, next_attempt_at = 0, error = 'worker is gone' WHERE run_id = ? AND status = 'leased' AND worker = ?", runId, worker).changes); },
    cancel(runId, { now = Date.now() }) { return Number(run("UPDATE fleet_jobs SET status = 'cancelled', finished_at = ?, lease_expires_at = NULL WHERE run_id = ? AND status IN ('queued','leased')", now, runId).changes); },
    retime(runId, timeoutMs) { return Number(run("UPDATE fleet_jobs SET timeout_ms = ? WHERE run_id = ? AND status = 'queued'", timeoutMs, runId).changes); },
    requeueTerminal(runId, statuses) { return Number(run(`UPDATE fleet_jobs SET status = 'queued', worker = NULL, attempts = 0, next_attempt_at = 0, lease_expires_at = NULL, finished_at = NULL, error = NULL WHERE run_id = ? AND status IN (${statuses.map(() => '?').join(',')})`, runId, ...statuses).changes); },
    listJobs: (runId) => q('SELECT * FROM fleet_jobs WHERE run_id = ? ORDER BY repo_id', runId).map(jobOf),
    getJob: (jobId) => jobOf(one('SELECT * FROM fleet_jobs WHERE job_id = ?', jobId)),
    close() { try { db.close(); } catch { /* already closed */ } },
  };
}
