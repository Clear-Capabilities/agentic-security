// The fleet job store (PRD 4 requirements 2 and 3): one conformance suite, run against BOTH implementations, so the interface is
// shown not to depend on SQLite; plus a real two-process claim race on the SQLite file.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { createMemoryJobStore, createSqliteJobStore, isTerminal, JOB_STATUSES } from '../../src/posture/fleet/job-store.js';

const STORE_MODULE = fileURLToPath(new URL('../../src/posture/fleet/job-store.js', import.meta.url));
const run = { runId: 'frun-1', organization: 'acme', manifestHash: 'm1', configHash: 'c1', createdAt: 1000 };
const job = (repoId, over = {}) => ({ jobId: `${run.runId}:${repoId}`, repoId, commit: 'abc', cacheKey: `k-${repoId}`, timeoutMs: 60000, maxAttempts: 2, ...over });

const makers = {
  memory: async () => createMemoryJobStore(),
  sqlite: async () => createSqliteJobStore({ file: path.join(mkTestTmp('fleet-db-'), 'fleet.db') }),
};

for (const [name, make] of Object.entries(makers)) {
  const T = (title, fn) => test(`[${name}] ${title}`, async () => { const s = await make(); try { s.begin(run); await fn(s); } finally { s.close(); } });

  T('enqueue is idempotent: the same job twice is one job', (s) => {
    assert.equal(s.enqueue(run.runId, [job('a'), job('b')], { now: 1 }), 2);
    assert.equal(s.enqueue(run.runId, [job('a'), job('b'), job('c')], { now: 2 }), 1);
    assert.deepEqual(s.listJobs(run.runId).map((j) => j.repoId), ['a', 'b', 'c']);
    assert.equal(s.begin(run).runId, run.runId);
    assert.equal(s.listRuns().length, 1);
  });

  T('a claim leases one job to one worker and no job is handed out twice', (s) => {
    s.enqueue(run.runId, [job('a'), job('b')], { now: 1 });
    const x = s.claim(run.runId, { worker: 'w1', leaseMs: 1000, now: 10 });
    const y = s.claim(run.runId, { worker: 'w2', leaseMs: 1000, now: 10 });
    assert.notEqual(x.jobId, y.jobId);
    assert.equal(s.claim(run.runId, { worker: 'w3', leaseMs: 1000, now: 10 }), null);
    assert.equal(x.status, 'leased'); assert.equal(x.epoch, 1); assert.equal(x.attempts, 1); assert.equal(x.leaseExpiresAt, 1010);
  });

  T('a heartbeat extends the lease only for the current holder', (s) => {
    s.enqueue(run.runId, [job('a')], { now: 1 });
    const j = s.claim(run.runId, { worker: 'w1', leaseMs: 1000, now: 10 });
    assert.equal(s.heartbeat(j.jobId, j.epoch, { now: 500, leaseMs: 1000 }), true);
    assert.equal(s.getJob(j.jobId).leaseExpiresAt, 1500);
    assert.equal(s.heartbeat(j.jobId, j.epoch + 1, { now: 600, leaseMs: 1000 }), false, 'a wrong epoch is refused');
    assert.equal(s.heartbeat('nope', 1, { now: 600, leaseMs: 1000 }), false);
  });

  T('an expired lease is reclaimed, and the zombie that lost it cannot complete, heartbeat or fail the job (fencing)', (s) => {
    s.enqueue(run.runId, [job('a')], { now: 1 });
    const first = s.claim(run.runId, { worker: 'w1', leaseMs: 100, now: 10 });
    assert.equal(s.reclaimExpired(run.runId, { now: 50 }), 0, 'not expired yet');
    assert.equal(s.reclaimExpired(run.runId, { now: 200 }), 1);
    const second = s.claim(run.runId, { worker: 'w2', leaseMs: 1000, now: 210 });
    assert.equal(second.epoch, 2); assert.equal(second.attempts, 2);
    assert.equal(s.complete(first.jobId, first.epoch, { artifactSha256: 'zombie', now: 220 }), false, 'the stale holder cannot write a result');
    assert.equal(s.heartbeat(first.jobId, first.epoch, { now: 220, leaseMs: 1000 }), false);
    assert.equal(s.fail(first.jobId, first.epoch, { error: 'late', now: 220 }), null);
    assert.equal(s.complete(second.jobId, second.epoch, { status: 'succeeded', artifactSha256: 'good', summary: { findings: 3 }, now: 230 }), true);
    const done = s.getJob(second.jobId);
    assert.equal(done.status, 'succeeded'); assert.equal(done.artifactSha256, 'good'); assert.deepEqual(done.summary, { findings: 3 });
  });

  T('a completed job is never completed twice, so a retry cannot duplicate a result', (s) => {
    s.enqueue(run.runId, [job('a')], { now: 1 });
    const j = s.claim(run.runId, { worker: 'w1', leaseMs: 1000, now: 10 });
    assert.equal(s.complete(j.jobId, j.epoch, { artifactSha256: 'first', now: 20 }), true);
    assert.equal(s.complete(j.jobId, j.epoch, { artifactSha256: 'second', now: 21 }), false);
    assert.equal(s.getJob(j.jobId).artifactSha256, 'first');
    assert.equal(s.claim(run.runId, { worker: 'w2', leaseMs: 1000, now: 30 }), null, 'a terminal job is not claimable');
  });

  T('failures retry with a delay until maxAttempts, then end as failed or timed_out, never silently', (s) => {
    s.enqueue(run.runId, [job('a'), job('t')], { now: 1 });
    let a = s.claim(run.runId, { worker: 'w', leaseMs: 1000, now: 10 });
    assert.equal(a.repoId, 'a');
    assert.deepEqual(s.fail(a.jobId, a.epoch, { error: 'boom', now: 20, retryDelayMs: 1000 }), { state: 'queued', attempts: 1 });
    const t = s.claim(run.runId, { worker: 'w', leaseMs: 1000, now: 21 });
    assert.equal(t.repoId, 't', 'the delayed job is skipped, the other one runs');
    assert.equal(s.claim(run.runId, { worker: 'w', leaseMs: 1000, now: 500 }), null, 'still inside the retry delay');
    a = s.claim(run.runId, { worker: 'w', leaseMs: 1000, now: 1100 });
    assert.equal(a.attempts, 2);
    assert.deepEqual(s.fail(a.jobId, a.epoch, { error: 'boom again', now: 1200 }), { state: 'failed', attempts: 2 });
    assert.equal(s.getJob(a.jobId).error, 'boom again');
    s.fail(t.jobId, t.epoch, { error: 'slow', timedOut: true, now: 1300 });
    const t2 = s.claim(run.runId, { worker: 'w', leaseMs: 1000, now: 1301 });
    assert.deepEqual(s.fail(t2.jobId, t2.epoch, { error: 'slow', timedOut: true, now: 1400 }), { state: 'timed_out', attempts: 2 });
    assert.ok(s.listJobs(run.runId).every((j) => isTerminal(j.status)));
  });

  T('reclaiming a gone worker frees only that worker, and cancel stops what has not finished', (s) => {
    s.enqueue(run.runId, [job('a'), job('b'), job('c')], { now: 1 });
    const a = s.claim(run.runId, { worker: 'host:1', leaseMs: 100000, now: 10 });
    const b = s.claim(run.runId, { worker: 'host:2', leaseMs: 100000, now: 10 });
    assert.equal(s.reclaimWorker(run.runId, 'host:1'), 1);
    assert.equal(s.getJob(a.jobId).status, 'queued'); assert.equal(s.getJob(b.jobId).status, 'leased');
    s.complete(b.jobId, b.epoch, { now: 20 });
    assert.equal(s.cancel(run.runId, { now: 30 }), 2);
    assert.deepEqual(s.listJobs(run.runId).map((j) => j.status).sort(), ['cancelled', 'cancelled', 'succeeded']);
  });

  T('requeueTerminal gives failed work another go without touching finished work', (s) => {
    s.enqueue(run.runId, [job('a', { maxAttempts: 1 }), job('b')], { now: 1 });
    const a = s.claim(run.runId, { worker: 'w', leaseMs: 1000, now: 10 }); s.fail(a.jobId, a.epoch, { error: 'x', now: 11 });
    const b = s.claim(run.runId, { worker: 'w', leaseMs: 1000, now: 12 }); s.complete(b.jobId, b.epoch, { now: 13 });
    assert.equal(s.requeueTerminal(run.runId, ['failed', 'timed_out']), 1);
    assert.equal(s.getJob(a.jobId).status, 'queued'); assert.equal(s.getJob(a.jobId).attempts, 0); assert.equal(s.getJob(b.jobId).status, 'succeeded');
  });

  T('retime changes the limit of queued work only', (s) => {
    s.enqueue(run.runId, [job('a'), job('b')], { now: 1 });
    const a = s.claim(run.runId, { worker: 'w', leaseMs: 1000, now: 10 });
    assert.equal(s.retime(run.runId, 5000), 1);
    assert.equal(s.getJob(a.jobId).timeoutMs, 60000); assert.equal(s.listJobs(run.runId).find((j) => j.repoId === 'b').timeoutMs, 5000);
  });

  T('required is kept per job', (s) => {
    s.enqueue(run.runId, [job('a'), job('opt', { required: false })], { now: 1 });
    assert.deepEqual(s.listJobs(run.runId).map((j) => [j.repoId, j.required]), [['a', true], ['opt', false]]);
  });
}

test('the job status vocabulary is closed', () => {
  assert.deepEqual([...JOB_STATUSES], ['queued', 'leased', 'succeeded', 'partial', 'failed', 'timed_out', 'cancelled']);
  assert.equal(isTerminal('leased'), false); assert.equal(isTerminal('partial'), true);
});

test('[sqlite] state survives closing and reopening the file (this is what makes a resume possible)', async () => {
  const file = path.join(mkTestTmp('fleet-db-'), 'fleet.db');
  const a = await createSqliteJobStore({ file }); a.begin(run); a.enqueue(run.runId, [job('a')], { now: 1 });
  const j = a.claim(run.runId, { worker: 'w1', leaseMs: 100, now: 10 }); a.close();
  const b = await createSqliteJobStore({ file });
  assert.equal(b.getJob(j.jobId).status, 'leased'); assert.equal(b.getJob(j.jobId).epoch, 1);
  assert.equal(b.reclaimExpired(run.runId, { now: 500 }), 1);
  b.close();
});

test('[sqlite] two real processes racing to claim the same jobs never receive the same one', async () => {
  const file = path.join(mkTestTmp('fleet-race-'), 'fleet.db');
  const s = await createSqliteJobStore({ file }); s.begin(run);
  s.enqueue(run.runId, Array.from({ length: 40 }, (_, i) => job(`r${String(i).padStart(2, '0')}`)), { now: 1 }); s.close();
  const START = Date.now() + 1500; // both processes wait for the same instant, so they really do race
  const script = `import { createSqliteJobStore } from ${JSON.stringify(STORE_MODULE)};
    const s = await createSqliteJobStore({ file: ${JSON.stringify(file)} }); const got = [];
    await new Promise((r) => setTimeout(r, Math.max(0, ${START} - Date.now())));
    for (;;) { const j = s.claim(${JSON.stringify(run.runId)}, { worker: 'p' + process.pid, leaseMs: 60000, now: Date.now() }); if (!j) break; got.push(j.jobId); await new Promise((r) => setTimeout(r, 8)); }
    s.close(); process.stdout.write(JSON.stringify(got));`;
  const child = () => new Promise((resolve, reject) => { const c = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] }); let out = ''; let err = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { err += d; }); c.on('close', (code) => (code === 0 ? resolve(JSON.parse(out)) : reject(new Error(`child exited ${code}: ${err.trim().split('\n').slice(-3).join(' | ').slice(0, 400)}`)))); });
  const [x, y] = await Promise.all([child(), child()]);
  assert.equal(x.length + y.length, 40, 'every job was handed out exactly once');
  assert.equal(new Set([...x, ...y]).size, 40);
  assert.ok(x.length > 0 && y.length > 0, 'both processes took part in the race');
});
