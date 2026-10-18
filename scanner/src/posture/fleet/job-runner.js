// The fleet scan controller (PRD 4, requirements 2 to 5). It turns a manifest into jobs in the job store and runs them with bounded
// workers, each scan in its own child process under a hard timeout, so one hung repository costs one worker for one timeout and
// nothing else. Every state change is in the store, which is what makes `fleet resume` an ordinary continuation.
//
//   plan      fingerprint each repository, derive its cache key, enqueue one idempotent job per repository
//   run       claim -> (cache hit | scan in a supervised child, heartbeating) -> complete | fail-with-retry
//   recover   an expired lease, or a lease held by a dead process on this host, goes back in the queue
//
// A worker that loses its lease (it stopped heartbeating long enough for another worker to take the job) is fenced out: its late
// result is refused by the store and its scan is aborted. Results are written per attempt (`<repo>.<epoch>.json`) and the job row
// points at the winning one, so a retry can never produce two sets of findings for one repository.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { superviseSpawn } from '../../sandbox/supervise.js';
import { statePath } from '../state-dir.js';
import { repoFingerprint, scannerIdentity, cacheKey, readCache, writeCache } from './scan-cache.js';
import { BEGIN, END } from './scan-child.js';

const SCAN_CHILD = fileURLToPath(new URL('./scan-child.js', import.meta.url));
const sha = (s) => createHash('sha256').update(s).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const DEFAULTS = Object.freeze({ leaseMs: 30_000, heartbeatMs: 10_000, retryDelayMs: 2_000, pollMs: 100 });

/** The default scan: one supervised child process per repository. Throws `{code: 'TIMEOUT'|'ERROR', message}`. */
export async function childScan(repoPath, { timeoutMs, signal }) {
  const r = await superviseSpawn(process.execPath, [SCAN_CHILD, repoPath], { cwd: repoPath, env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1' }, timeoutMs, signal, maxOutputBytes: 96 * 1024 * 1024 });
  const fail = (code, message) => Object.assign(new Error(message), { code });
  if (r.timedOut) throw fail('TIMEOUT', `no result within ${Math.round(timeoutMs / 1000)}s`);
  if (r.cancelled) throw fail('CANCELLED', 'cancelled');
  if (r.spawnError) throw fail('ERROR', `could not start the scan: ${r.spawnError}`);
  if (r.outputCapped) throw fail('ERROR', 'the scan produced more output than allowed');
  if (r.exitCode !== 0) throw fail('ERROR', `scan exited ${r.exitCode}: ${String(r.stderr).trim().split('\n').pop()?.slice(0, 200) ?? ''}`);
  const a = r.stdout.indexOf(BEGIN); const b = r.stdout.indexOf(END);
  if (a < 0 || b < a) throw fail('ERROR', 'the scan produced no result block');
  try { return JSON.parse(r.stdout.slice(a + BEGIN.length, b)); } catch (e) { throw fail('ERROR', `unreadable scan result: ${e.message}`); }
}

const hostId = () => os.hostname();
const pidAlive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };

/** Free jobs held by workers on THIS host whose process no longer exists. Other hosts are handled by lease expiry alone. */
export function reclaimDeadWorkers(store, runId, { host = hostId(), alive = pidAlive, self = null } = {}) {
  let freed = 0;
  const seen = new Set();
  for (const j of store.listJobs(runId)) {
    if (j.status !== 'leased' || !j.worker || seen.has(j.worker) || j.worker === self) continue;
    const m = /^(.*):(\d+):\d+$/.exec(j.worker);
    if (!m || m[1] !== host) continue;
    seen.add(j.worker);
    if (!alive(Number(m[2]))) freed += store.reclaimWorker(runId, j.worker);
  }
  return freed;
}

export function planRun({ manifest, manifestHash, store, runId = null, config = {}, now = Date.now(), identity = scannerIdentity(), fingerprint = repoFingerprint, retries = manifest.retries, meta = {} }) {
  const scanConfig = { provenance: false, ...config };
  const prints = manifest.repositories.map((r) => ({ r, fp: fingerprint(r.path) }));
  const configHash = sha(JSON.stringify(scanConfig));
  const id = runId ?? `frun-${sha(JSON.stringify({ manifestHash, configHash, identity, t: now, prints: prints.map((p) => [p.r.id, p.fp.content]) })).slice(0, 16)}`;
  store.begin({ runId: id, organization: manifest.organization, manifestHash, configHash, scannerIdentity: identity, createdAt: now, meta: { workers: manifest.workers, perRepoTimeoutMs: manifest.perRepoTimeoutMs, retries, ...meta } });
  const created = store.enqueue(id, prints.map(({ r, fp }) => ({ jobId: `${id}:${r.id}`, repoId: r.id, commit: fp.commit, cacheKey: cacheKey({ fingerprint: fp, config: scanConfig, identity }), timeoutMs: manifest.perRepoTimeoutMs, maxAttempts: retries + 1, required: r.required })), { now });
  return { runId: id, created, identity };
}

/**
 * Run (or continue) a planned run until no job is queued or leased by a live worker. Returns when the work is done, the signal
 * aborts, or `maxWaitMs` passes with only other workers' leases outstanding.
 */
export async function runJobs({ manifest, store, runId, root, scan = childScan, workers = manifest.workers, leaseMs = DEFAULTS.leaseMs, heartbeatMs = DEFAULTS.heartbeatMs, retryDelayMs = DEFAULTS.retryDelayMs, pollMs = DEFAULTS.pollMs, maxWaitMs = null, signal, now = () => Date.now(), onEvent = () => {}, cacheDir = null, artifactDir = null, useCache = true }) {
  const repoById = new Map(manifest.repositories.map((r) => [r.id, r]));
  const cacheD = cacheDir ?? statePath(root, 'fleet', 'cache');
  const artD = artifactDir ?? statePath(root, 'fleet', 'artifacts', runId);
  fs.mkdirSync(artD, { recursive: true, mode: 0o700 });
  const deadline = maxWaitMs ?? (manifest.perRepoTimeoutMs * 3 + leaseMs);
  const writeArtifact = (job, payload) => {
    const text = JSON.stringify({ schema: 'agentic-security/fleet-scan-artifact', version: 1, runId, repoId: job.repoId, epoch: job.epoch, commit: job.commit, ...payload });
    const file = path.join(artD, `${job.repoId}.${job.epoch}.json`);
    fs.writeFileSync(file, text, { mode: 0o600 });
    return { file, sha256: sha(text) };
  };

  async function worker(slot) {
    const id = `${hostId()}:${process.pid}:${slot}`;
    let idleSince = null;
    for (;;) {
      if (signal?.aborted) return;
      store.reclaimExpired(runId, { now: now() });
      const job = store.claim(runId, { worker: id, leaseMs, now: now() });
      if (!job) {
        const open = store.listJobs(runId).filter((j) => j.status === 'queued' || j.status === 'leased');
        if (!open.length) return;
        idleSince ??= now();
        if (now() - idleSince > deadline) return;
        await sleep(pollMs);
        continue;
      }
      idleSince = null;
      const repo = repoById.get(job.repoId);
      onEvent({ type: 'start', repo: job.repoId, attempt: job.attempts });
      const cached = useCache ? readCache(cacheD, job.cacheKey) : null;
      if (cached) {
        const a = writeArtifact(job, { entry: cached.entry, findings: cached.findings, findingsTruncated: !!cached.findingsTruncated, cached: true });
        const status = cached.entry?.scanHealth && cached.entry.scanHealth.status !== 'complete' ? 'partial' : 'succeeded';
        if (store.complete(job.jobId, job.epoch, { status, artifactSha256: a.sha256, summary: { total: cached.entry?.total ?? null, cached: true, artifact: path.basename(a.file) }, now: now() })) onEvent({ type: 'done', repo: job.repoId, cached: true, status });
        continue;
      }
      const ac = new AbortController();
      const onAbort = () => ac.abort();
      signal?.addEventListener('abort', onAbort, { once: true });
      let lost = false;
      const hb = setInterval(() => { if (!store.heartbeat(job.jobId, job.epoch, { now: now(), leaseMs })) { lost = true; ac.abort(); } }, heartbeatMs);
      try {
        const out = await scan(repo.path, { timeoutMs: job.timeoutMs, signal: ac.signal });
        clearInterval(hb);
        if (lost) { onEvent({ type: 'fenced', repo: job.repoId }); continue; }
        if (!out?.entry) throw Object.assign(new Error('the scan returned no entry'), { code: 'ERROR' });
        if (out.entry.ok === false) throw Object.assign(new Error(out.entry.error || 'the scan failed'), { code: 'ERROR' });
        const a = writeArtifact(job, { entry: out.entry, findings: out.findings ?? [], findingsTruncated: !!out.findingsTruncated });
        const status = out.entry.scanHealth && out.entry.scanHealth.status !== 'complete' ? 'partial' : 'succeeded';
        if (store.complete(job.jobId, job.epoch, { status, artifactSha256: a.sha256, summary: { total: out.entry.total ?? null, cached: false, artifact: path.basename(a.file) }, now: now() })) {
          if (useCache && status === 'succeeded') writeCache(cacheD, job.cacheKey, { entry: out.entry, findings: out.findings ?? [], findingsTruncated: !!out.findingsTruncated });
          onEvent({ type: 'done', repo: job.repoId, cached: false, status });
        } else onEvent({ type: 'fenced', repo: job.repoId });
      } catch (e) {
        clearInterval(hb);
        if (lost || e?.code === 'CANCELLED') { if (e?.code === 'CANCELLED' && !lost) store.fail(job.jobId, job.epoch, { error: 'cancelled', now: now(), retryDelayMs: 0 }); continue; }
        const r = store.fail(job.jobId, job.epoch, { error: e?.message ?? String(e), timedOut: e?.code === 'TIMEOUT', now: now(), retryDelayMs });
        onEvent({ type: 'failed', repo: job.repoId, error: e?.message ?? String(e), timedOut: e?.code === 'TIMEOUT', next: r?.state ?? null });
      } finally { clearInterval(hb); signal?.removeEventListener('abort', onAbort); }
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(workers, 32)) }, (_, i) => worker(i)));
  return { aborted: !!signal?.aborted };
}

/** Load the artifacts the jobs point at, verifying each against the hash the store recorded. A missing or altered artifact is reported, not used. */
export function loadArtifacts({ store, runId, root, artifactDir = null }) {
  const dir = artifactDir ?? statePath(root, 'fleet', 'artifacts', runId);
  const out = new Map(); const problems = [];
  for (const j of store.listJobs(runId)) {
    if (!['succeeded', 'partial'].includes(j.status)) continue;
    const file = path.join(dir, j.summary?.artifact ?? `${j.repoId}.${j.epoch}.json`);
    try {
      const text = fs.readFileSync(file, 'utf8');
      if (sha(text) !== j.artifactSha256) { problems.push({ repoId: j.repoId, problem: 'artifact does not match the recorded hash' }); continue; }
      out.set(j.repoId, JSON.parse(text));
    } catch { problems.push({ repoId: j.repoId, problem: 'artifact is missing or unreadable' }); }
  }
  return { artifacts: out, problems };
}
