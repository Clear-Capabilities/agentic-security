// LOOP-002: bounded subprocesses, workers and watchdogs (fault injection).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { runBounded, reapOwned, OwnedSet } from '../lib/proc.mjs';
import { identityMatches, startTimeOf, signalIdentity, isAlive } from '../lib/procscan.mjs';
import { AttemptWatchdog } from '../lib/watchdog.mjs';
import { registerOpLease, activeOpLeases } from '../lib/oplease.mjs';
import { recordJob, layout } from '../lib/state.mjs';

const FX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const node = process.execPath;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WALL = 1500, GRACE = 500, SLACK = 10000;
const run = (file, extra = {}, args = []) => runBounded({ argv: [node, join(FX, file), ...args], cwd: FX, wallMs: WALL, graceMs: GRACE, ...extra });

for (const [label, file] of [['silent infinite loop', 'silent-loop.mjs'], ['noisy infinite loop', 'noisy-loop.mjs'], ['endless API retry', 'retry-loop.mjs']]) {
  test(`[LOOP-002.AC01] ${label} ends within its deadline plus 10 seconds`, async () => {
    const t = Date.now();
    const r = await run(file);
    // A flood may trip the output ceiling before the wall clock; both are enforced terminations.
    assert.ok(['timeout-wall', 'resource-limit'].includes(r.outcome), r.outcome);
    assert.ok(Date.now() - t < WALL + SLACK, `took ${Date.now() - t}ms`);
    assert.ok(!isAlive(r.pid), 'child is gone');
  });
}

test('[LOOP-002.AC01] a stdin prompt cannot block: stdin is closed so the child sees EOF', async () => {
  const t = Date.now();
  const r = await run('stdin-prompt.mjs');
  assert.equal(r.outcome, 'exited');
  assert.equal(r.exitCode, 3, 'child saw EOF and gave up rather than waiting');
  assert.ok(Date.now() - t < 5000);
});

test('[LOOP-002.AC01] a blocked output consumer is impossible: 40 MiB of output drains, caps hold, nothing hangs', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loop-wd-'));
  const t = Date.now();
  const r = await run('big-output.mjs', { wallMs: 20000, logPath: join(dir, 'o.log'), maxLogBytes: 100000, tailBytes: 4096 });
  assert.equal(r.outcome, 'exited'); assert.equal(r.exitCode, 0);
  assert.equal(r.bytes.stdout, 40 * 1024 * 1024);
  assert.equal(r.logTruncated, true);
  assert.ok(r.stdoutTail.length <= 4096);
  assert.ok(readFileSync(join(dir, 'o.log')).length <= 100000 + 16);
  assert.ok(Date.now() - t < 15000);
});

test('[LOOP-002.AC01] a never-ending test run is terminated at its deadline', async () => {
  const t = Date.now();
  const r = await runBounded({ argv: [node, '--test', join(FX, 'infinite-test.test.js')], cwd: FX, wallMs: WALL, graceMs: GRACE });
  assert.equal(r.outcome, 'timeout-wall');
  assert.ok(Date.now() - t < WALL + SLACK);
});

test('[LOOP-002.AC01] a noisy flood is also bounded by the total-output resource ceiling', async () => {
  const r = await run('noisy-loop.mjs', { wallMs: 30000, maxTotalBytes: 2 * 1024 * 1024 });
  assert.equal(r.outcome, 'resource-limit');
  assert.match(r.reason, /output exceeded/);
});

test('[LOOP-002.AC02] nested and deliberately detached descendants are contained and killed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loop-wd-'));
  const pidFile = join(dir, 'pids.json');
  const r = await run('detaching-parent.mjs', {}, [pidFile]);
  assert.equal(r.outcome, 'timeout-wall');
  const { nested, detached } = JSON.parse(readFileSync(pidFile, 'utf8'));
  assert.equal(isAlive(nested), false, 'nested child killed');
  assert.equal(isAlive(detached), false, 'setsid-detached grandchild killed');
  assert.ok(r.orphansKilled.length >= 1);
});

test('[LOOP-002.AC02] a descendant left behind after a CLEAN root exit is also reclaimed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loop-wd-'));
  const pidFile = join(dir, 'p.txt');
  const src = `const {spawn}=require('node:child_process');const fs=require('node:fs');const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});c.unref();fs.writeFileSync(${JSON.stringify(pidFile)},String(c.pid));setTimeout(()=>process.exit(0),700);`;
  const r = await runBounded({ argv: [node, '-e', src], cwd: dir, wallMs: 8000, graceMs: GRACE });
  assert.equal(r.outcome, 'exited'); assert.equal(r.exitCode, 0);
  const pid = Number(readFileSync(pidFile, 'utf8'));
  await sleep(100);
  assert.equal(isAlive(pid), false, 'the daemon the job left behind was killed');
});

test('[LOOP-002.AC02] an unrelated process with the same name survives', async () => {
  const bystander = spawn(node, [join(FX, 'unrelated.mjs')], { stdio: 'ignore', detached: true });
  bystander.unref();
  try {
    await sleep(150);
    const r = await run('silent-loop.mjs');
    assert.equal(r.outcome, 'timeout-wall');
    assert.equal(isAlive(bystander.pid), true, 'same executable, not ours, must not be killed');
  } finally { try { process.kill(bystander.pid, 'SIGKILL'); } catch { /* */ } }
});

test('[LOOP-002.AC02] pid reuse is guarded by start-time identity', async () => {
  const bystander = spawn(node, [join(FX, 'unrelated.mjs')], { stdio: 'ignore' });
  try {
    await sleep(150);
    const real = startTimeOf(bystander.pid);
    assert.ok(real);
    assert.equal(identityMatches(bystander.pid, real), true);
    // a recycled pid would carry a different start time
    const forged = real.replace(/\d{4}$/, (y) => String(Number(y) - 1));
    assert.equal(identityMatches(bystander.pid, forged), false);
    assert.equal(signalIdentity({ pid: bystander.pid, start: forged }, 'SIGKILL'), false);
    assert.equal(isAlive(bystander.pid), true, 'a mismatched identity is never signalled');
    // reapOwned honours the same rule
    const killed = await reapOwned([{ pid: bystander.pid, start: forged, pgid: 0 }], 'no-such-run', 300);
    assert.deepEqual(killed, []);
    assert.equal(isAlive(bystander.pid), true);
    assert.equal(signalIdentity({ pid: bystander.pid, start: real }, 'SIGKILL'), true);
  } finally { try { bystander.kill('SIGKILL'); } catch { /* */ } }
});

test('[LOOP-002.AC03] a quiet registered operation runs to its own deadline; an unregistered one is idle-killed', async () => {
  const quiet = await run('quiet-sleep.mjs', { wallMs: 8000, idleMs: 500, idleExempt: () => true }, ['1800']);
  assert.equal(quiet.outcome, 'exited'); assert.equal(quiet.exitCode, 0);
  const t = Date.now();
  const idle = await run('quiet-sleep.mjs', { wallMs: 8000, idleMs: 500, idleExempt: () => false }, ['5000']);
  assert.equal(idle.outcome, 'timeout-idle');
  assert.ok(Date.now() - t < 4000);
});

test('[LOOP-002.AC03] registered leases have fixed deadlines, die with their process, and gate the idle check', () => {
  const dir = mkdtempSync(join(tmpdir(), 'loop-lease-'));
  const l = registerOpLease(dir, { label: 'compile', deadlineSeconds: 60 });
  assert.equal(activeOpLeases(dir).length, 1);
  l.release();
  assert.equal(activeOpLeases(dir).length, 0);
  assert.throws(() => registerOpLease(dir, { label: 'x', deadlineSeconds: Infinity }), RangeError);
  // an expired lease is ignored
  const e = registerOpLease(dir, { label: 'old', deadlineSeconds: 1 });
  assert.equal(activeOpLeases(dir, Date.now() + 5000).length, 0);
  e.release();
  // a lease whose owner process is dead does not keep a worker alive
  registerOpLease(dir, { label: 'ghost', deadlineSeconds: 60, pid: 2147483000 });
  assert.equal(activeOpLeases(dir).length, 0);
});

test('[LOOP-002.AC03] heartbeat, activity, tokens and checklist edits cannot extend the no-progress deadline', () => {
  let t = 0;
  const wd = new AttemptWatchdog({ now: () => t, idleMs: 180_000, noProgressMs: 600_000, attemptMs: 1_200_000, maxTurns: 80 });
  for (let i = 0; i < 130; i++) {
    t += 5000; wd.heartbeat(); wd.activity();                   // chatty worker, live controller
    if (i % 4 === 0) wd.turn();                                  // model turns / tokens
    assert.equal(wd.recordProgress('heartbeat', 'x'), false);
    assert.equal(wd.recordProgress('checklist-edit', 'x'), false);
    assert.equal(wd.recordProgress('criterion-passed', null), false, 'progress without evidence is not progress');
    if (t < 600_000) assert.equal(wd.check(), null, `still inside the window at ${t}`);
  }
  assert.equal(wd.check().reason, 'no-substantive-progress');
  // verified progress DOES reset it
  const wd2 = new AttemptWatchdog({ now: () => t, noProgressMs: 600_000, attemptMs: 10_000_000, idleMs: 10_000_000 });
  t = 0; wd2.lastProgressAt = 0; t = 500_000;
  assert.equal(wd2.recordProgress('criterion-passed', 'ev-1'), true);
  t = 1_000_000;
  assert.equal(wd2.check(), null);
  t = 1_200_000;
  assert.equal(wd2.check().reason, 'no-substantive-progress');
});

test('[LOOP-002.AC03] idle, attempt, turn and lease rules in the watchdog policy', () => {
  let t = 0;
  const wd = new AttemptWatchdog({ now: () => t, idleMs: 180_000, noProgressMs: 10_000_000, attemptMs: 1_200_000, maxTurns: 80 });
  t = 181_000; assert.equal(wd.check().reason, 'idle');
  wd.activity(); assert.equal(wd.check(), null);
  t += 181_000; wd.setExternalLeases(1); assert.equal(wd.check(), null, 'a registered operation exempts idleness');
  wd.setExternalLeases(0); assert.equal(wd.check().reason, 'idle');
  assert.equal(wd.registerLease('vm', 5000), true);
  assert.equal(wd.registerLease('vm', 999999), false, 'a lease cannot be renewed');
  const wd2 = new AttemptWatchdog({ now: () => t, idleMs: 1e9, noProgressMs: 1e9, attemptMs: 1_200_000, maxTurns: 3 });
  for (let i = 0; i < 4; i++) wd2.turn();
  assert.equal(wd2.check().reason, 'turn-limit');
  const wd3 = new AttemptWatchdog({ now: () => t, idleMs: 1e9, noProgressMs: 1e9, attemptMs: 1_200_000, maxTurns: 80 });
  t += 1_200_001; assert.equal(wd3.check().reason, 'attempt-deadline');
});

test('[LOOP-002.AC04] timeout, signal, OOM-style resource limit and spawn failure are typed and persisted', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loop-job-'));
  const L = layout(dir, 'r1'); mkdirSync(L.dir, { recursive: true });
  const logPath = join(dir, 'job.log');
  const results = [];
  results.push(await run('silent-loop.mjs', { logPath, label: 'timeout' }));
  results.push(await run('self-kill.mjs', { label: 'signal' }));
  results.push(await run('memory-hog.mjs', { label: 'oom', wallMs: 20000, maxRssBytes: 120 * 1024 * 1024 }));
  results.push(await runBounded({ argv: ['/definitely/not/a/binary', '--x'], cwd: FX, wallMs: 2000, label: 'spawn' }));
  assert.deepEqual(results.map((r) => r.outcome), ['timeout-wall', 'signaled', 'resource-limit', 'spawn-failed']);
  assert.equal(results[1].signal, 'SIGKILL'); assert.equal(results[1].suspectedOom, true);
  assert.match(results[2].reason, /RSS/);
  assert.ok(results[3].reason);
  for (const r of results) recordJob(L, r);
  const rows = readFileSync(L.jobsFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(rows.length, 4);
  for (const row of rows) {
    assert.ok(row.outcome && row.argv && row.startedAt && row.endedAt, 'typed outcome, command and timestamps are persisted');
    assert.equal(row.stdoutTail, undefined, 'tails are not duplicated into the job ledger');
  }
  assert.ok(readFileSync(logPath).length >= 0 && results[0].logTruncated !== undefined, 'log path honoured');
});

test('[LOOP-002.AC04] a hung job does not damage other concurrent jobs: valid results are retained', async () => {
  const [hung, good, other] = await Promise.all([
    run('silent-loop.mjs'),
    runBounded({ argv: [node, '-e', 'console.log("analyzer-ok"); process.exit(0)'], cwd: FX, wallMs: 5000 }),
    runBounded({ argv: [node, '-e', 'console.error("warn"); process.exit(7)'], cwd: FX, wallMs: 5000 }),
  ]);
  assert.equal(hung.outcome, 'timeout-wall');
  assert.equal(good.outcome, 'exited'); assert.match(good.stdoutTail, /analyzer-ok/);
  assert.equal(other.exitCode, 7); assert.match(other.stderrTail, /warn/);
});

test('[LOOP-002.AC04] OwnedSet persists membership changes for crash recovery', () => {
  const seen = [];
  const o = new OwnedSet((l) => seen.push(l.length));
  o.add({ pid: 1, start: 'a' }); o.add({ pid: 2, start: 'b' }); o.remove(1);
  assert.deepEqual(seen, [1, 2, 1]);
});
