// LOOP-003: OS-owned background controller, exclusive lock, crash recovery, scheduling.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { MiniRepo, alive, sleep } from './helpers.js';

const TERMINAL = ['completed', 'blocked', 'crashed', 'failed', 'paused-budget', 'stopped'];
const longLimits = { workerIdleSeconds: 60, noProgressSeconds: 120, claudeAttemptSeconds: 90 };

async function begin(repo) {
  const i = await repo.init();
  assert.equal(i.code, 0, i.stderr);
  const s = await repo.cli(['start', '--background', '--serve', '127.0.0.1:0']);
  assert.equal(s.code, 0, s.stdout + s.stderr);
  return s;
}
const waitTerminal = (repo, timeoutMs = 60000) => repo.waitFor(async () => { const s = await repo.status(); return TERMINAL.includes(s.status) ? s : null; }, { timeoutMs, label: 'terminal status' });

test('[LOOP-003.AC01] start --background returns within 5s, prints run info, and the controller outlives the launcher; status stays responsive while a worker is busy', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { profile: { limits: longLimits }, workerMode: { default: 'silent-hang' } });
  try {
    await repo.init();
    const s = await repo.cli(['start', '--background', '--serve', '127.0.0.1:0']);
    assert.equal(s.code, 0, s.stdout + s.stderr);
    assert.ok(s.ms < 5000, `start took ${s.ms}ms`);
    assert.match(s.stdout, /run ID:\s+run-/);
    assert.match(s.stdout, /controller PID:\s+\d+/);
    assert.match(s.stdout, /dashboard:\s+http:\/\/127\.0\.0\.1:\d+/);
    assert.match(s.stdout, /verified completion: 0%/);
    assert.match(s.stdout, /stop:\s+node scripts\/loop-engineering\/run\.mjs stop --run run-/);
    const pid = Number(/controller PID:\s+(\d+)/.exec(s.stdout)[1]);
    // the launcher process has exited; the controller is still alive
    assert.equal(alive(pid), true);
    await repo.waitFor(async () => (await repo.status()).current?.phase === 'worker', { label: 'worker running' });
    const t = Date.now();
    const st = await repo.cli(['status', '--json']);
    assert.ok(Date.now() - t < 2000, `status took ${Date.now() - t}ms while busy`);
    const j = JSON.parse(st.stdout);
    assert.equal(j.status, 'running');
    assert.equal(j.controller.liveness, 'live');
    assert.equal(j.controller.pid, pid);
    assert.equal(j.current.requirement, 'HS-001');
    assert.equal(j.verifiedPercent, 0);
    // the dashboard answers too
    const res = await fetch(j.serve.url + '/api/status');
    assert.equal(res.status, 200);
  } finally { await repo.cleanup(); }
});

test('[LOOP-003.AC02] a second launch cannot mutate the same checkout; stop reclaims only owned processes within 15s', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { profile: { limits: longLimits }, workerMode: { default: 'silent-hang' } });
  const bystander = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore', detached: true });
  bystander.unref();
  try {
    await begin(repo);
    const j = await repo.waitFor(async () => { const s = await repo.status(); return s.current?.phase === 'worker' && s.current?.pid ? s : null; }, { label: 'worker pid' });
    const workerPid = j.current.pid, ctlPid = j.controller.pid, grdPid = j.guardian.pid;
    assert.ok(grdPid, 'a separate guardian process exists');
    const second = await repo.cli(['start', '--background']);
    assert.notEqual(second.code, 0);
    assert.match(second.stderr, /already has an active controller/);
    const t0 = Date.now();
    const stop = await repo.cli(['stop', '--run', repo.runId()], { timeoutMs: 20000 });
    assert.equal(stop.code, 0, stop.stderr);
    assert.ok(Date.now() - t0 < 15000, `stop took ${Date.now() - t0}ms`);
    await sleep(300);
    for (const [name, pid] of [['controller', ctlPid], ['worker', workerPid], ['guardian', grdPid]]) assert.equal(alive(pid), false, `${name} is gone`);
    assert.equal(alive(bystander.pid), true, 'a process the loop does not own is untouched');
    const st = await repo.status();
    assert.equal(st.status, 'stopped');
    assert.equal(st.verifiedPercent, 0);
  } finally { try { process.kill(bystander.pid, 'SIGKILL'); } catch { /* */ } await repo.cleanup(); }
});

test('[LOOP-003.AC03] killing a worker is a retried attempt, not a crash; the controller keeps running and persists the checkpoint', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { profile: { limits: { ...longLimits, retryBackoffMaxSeconds: 1 } }, workerMode: { default: 'silent-hang' } });
  try {
    await begin(repo);
    const j = await repo.waitFor(async () => { const s = await repo.status(); return s.current?.phase === 'worker' && s.current?.pid ? s : null; }, { label: 'worker pid' });
    process.kill(j.current.pid, 'SIGKILL');
    await repo.waitFor(() => repo.state().requirements['HS-001']?.attempts >= 1 && repo.state().requirements['HS-001']?.state !== 'running', { label: 'attempt settled' });
    const st = await repo.status();
    assert.equal(st.controller.liveness, 'live', 'the controller survived its worker; events: ' + readFileSync(repo.runPath('events.jsonl'), 'utf8').split('\n').slice(-8).join(' | ') + ' out: ' + (() => { try { return readFileSync(repo.runPath('controller.out'), 'utf8').slice(-600); } catch { return ''; } })());
    assert.notEqual(st.status, 'crashed');
    const events = readFileSync(repo.runPath('events.jsonl'), 'utf8');
    assert.match(events, /"type":"attempt-end"[^\n]*"kind":"signaled"/);
    assert.ok(repo.state().checkpoints >= 1, 'checkpoint persisted');
  } finally { await repo.cleanup(); }
});

test('[LOOP-003.AC03] killing the controller: owned processes (even a detached orphan) are reclaimed, the run is crashed, never complete', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { profile: { limits: longLimits }, workerMode: { default: 'orphan' } });
  try {
    await begin(repo);
    const j = await repo.waitFor(async () => { const s = await repo.status(); return s.current?.phase === 'worker' && s.current?.pid && repo.exists('orphan.pid') ? s : null; }, { label: 'worker and orphan' });
    const orphan = Number(repo.read('orphan.pid'));
    assert.equal(alive(orphan), true, 'the detached grandchild is running');
    process.kill(j.controller.pid, 'SIGKILL');
    const st = await repo.waitFor(async () => { const s = await repo.status(); return repo.state().status === 'crashed' && s.status === 'crashed' && !alive(orphan) ? s : null; }, { timeoutMs: 20000, label: 'crash detection and reclamation by the guardian' });
    assert.equal(alive(j.current.pid), false, 'worker reclaimed');
    assert.equal(alive(orphan), false, 'orphaned descendant reclaimed');
    assert.notEqual(st.status, 'completed');
    assert.ok(st.verifiedPercent < 100);
    assert.match(st.statusReason, /controller/);
    assert.ok(repo.state().requirements['HS-001'].attempts >= 1, 'checkpoint preserved');
    const events = readFileSync(repo.runPath('events.jsonl'), 'utf8');
    assert.match(events, /"type":"crash-detected"/);
  } finally { await repo.cleanup(); }
});

test('[LOOP-003.AC04] scheduling advances past an isolated blocked task, never runs its dependents, and keeps verified evidence', async () => {
  const repo = new MiniRepo([
    { id: 'HS-001', weight: 2, criteria: ['will block'] },
    { id: 'HS-002', weight: 3, criteria: ['independent'] },
    { id: 'HS-003', weight: 1, deps: ['HS-001'], criteria: ['depends on the blocked one'] },
  ], { workerMode: { default: 'fix', perReq: { 'HS-001': 'noop' } } });
  try {
    await begin(repo);
    const st = await waitTerminal(repo);
    assert.equal(st.status, 'blocked');
    const by = Object.fromEntries(st.requirements.map((r) => [r.id, r]));
    assert.equal(by['HS-002'].state, 'verified', 'independent work completed');
    assert.equal(by['HS-001'].state, 'blocked');
    assert.ok(by['HS-001'].blockers.some((b) => ['repeated-failure', 'attempts-exhausted'].includes(b.type)));
    assert.equal(by['HS-003'].attempts, 0, 'the dependent was never attempted');
    assert.notEqual(by['HS-003'].state, 'verified');
    const calls = repo.read('worker-calls.log');
    assert.ok(!/HS-003/.test(calls), 'no worker ever ran for the dependent');
    assert.ok(by['HS-002'].evidence?.fresh, 'verified evidence retained');
    assert.equal(st.verifiedWeight, 3); assert.equal(st.totalWeight, 6);
    assert.ok(st.verifiedPercent < 100);
    assert.match(st.statusReason, /HS-001/);
  } finally { await repo.cleanup(); }
});
