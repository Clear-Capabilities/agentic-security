// LOOP-002, LOOP-003 and LOOP-004 of the assurance-differentiation PRD: finite background work with independent
// completion evidence, live progress with crash recovery, and frozen acceptance with a stable-tree final verification.
//
// Every test drives the REAL controller, guardian and dashboard as subprocesses against a disposable repository and a
// SCRIPTED stand-in worker (helpers.js). No model is ever called and no money is spent. Limits are the PRD section 7
// values where the test is about those values (heartbeat 5 s, stale 15 s) and are scaled down only where the test is
// about "stopped within the configured limit": the assertion is then relative to the configured number.
//
// Criterion tags are the PRD's own IDs ([LOOP-002.AC01] ...), verified through the same tag convention as every suite.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import vm from 'node:vm';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, appendFileSync, existsSync, readdirSync, statSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { MiniRepo, alive, sleep, RUN_MJS } from './helpers.js';
import { judgeLease, writeLease, layout, appendEvent, readStateFile, STALE_AFTER_MS, HEARTBEAT_MS } from '../lib/state.mjs';
import { startTimeOf } from '../lib/procscan.mjs';
import { setLogCap, appendJsonl } from '../lib/util.mjs';
import { computeProgress, formatPercent } from '../lib/progress.mjs';
import { evaluateFinal } from '../lib/final.mjs';
import { detectDrift, captureFrozenInputs } from '../lib/drift.mjs';
import { buildCompletionReport } from '../lib/report.mjs';
import { buildStatus } from '../lib/status.mjs';
import { Controller } from '../lib/controller.mjs';
import { loadProfile, validateProfile } from '../lib/profile.mjs';
import { PAGE } from '../lib/server.mjs';
import { createManifest } from '../lib/manifest.mjs';
import { copyFileSync } from 'node:fs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..', '..');
const PROFILE_PATH = join(REPO, 'scripts', 'loop-engineering', 'profiles', 'assurance-differentiation.json');
const FIXTURE = join(HERE, 'fixtures', 'assurance-prd-section8.md');
const REAL = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));

const TERMINAL = ['completed', 'blocked', 'crashed', 'failed', 'paused-budget', 'stopped'];
const waitTerminal = (repo, timeoutMs = 90000) => repo.waitFor(async () => { const s = await repo.status(); return TERMINAL.includes(s.status) ? s : null; }, { timeoutMs, label: 'terminal status' });
// Terminal AND the controller process gone, so everything it writes at shutdown (final lease, reports) has settled.
const waitQuiet = async (repo) => {
  const s = await waitTerminal(repo);
  const pid = s.controller.pid;
  if (pid) await repo.waitFor(async () => !alive(pid), { timeoutMs: 20000, label: 'controller exit' });
  return repo.status();
};
// The completion report is written after the terminal status is persisted, so a reader that has just seen the status must wait for the file.
const readReport = async (repo) => {
  await repo.waitFor(async () => existsSync(repo.runPath('completion-report.json')), { timeoutMs: 15000, label: 'completion-report.json' });
  return JSON.parse(readFileSync(repo.runPath('completion-report.json'), 'utf8'));
};
const eventsOf = (repo) => readFileSync(repo.runPath('events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const attemptEnds = (repo, req = null) => eventsOf(repo).filter((e) => e.type === 'attempt-end' && (!req || e.requirement === req));
const attemptStarts = (repo, req = null) => eventsOf(repo).filter((e) => e.type === 'attempt-start' && (!req || e.requirement === req));
const calls = (repo) => (repo.exists('worker-calls.log') ? repo.read('worker-calls.log').trim().split('\n').filter(Boolean) : []);
const callsFor = (repo, id) => calls(repo).filter((l) => l.startsWith(id + ' '));
const long = { workerIdleSeconds: 60, noProgressSeconds: 120, claudeAttemptSeconds: 90 };
const PASS_GATE = { id: 'gate-ok', cwd: '.', executable: 'node', args: ['-e', 'process.exit(0)'], timeoutSeconds: 30 };
const R = (id, weight = 1, deps = []) => ({ id, weight, deps, criteria: ['the criterion'] });

// Profile traits of the assurance profile (workstream grouping, final verification, the disclosure list) layered on the
// mini profile. The workstream rules and labels are the real ones; only the evidence watch globs are replaced so the
// disposable repository's own files are what stale-ness is judged against.
function assuranceExtra() {
  const ws = structuredClone(REAL.workstreams);
  // Each workstream watches only the flag files of its own requirements (plus src/), so editing one requirement's file stales
  // that requirement and whatever transitively depends on it, and nothing else.
  const flags = { foundation: 'flag-CORE-*', loop: 'flag-LOOP-*', evaluation: 'flag-QA-*', verification: 'flag-X-2*', documentation: 'flag-DOC-*', release: 'flag-REL-*' };
  for (const [k, d] of Object.entries(ws.definitions)) d.watch = [flags[k] || 'flag-X-*', 'src/**'];
  ws.globalWatch = ['profile.json'];
  return { workstreams: ws, finalVerification: { required: true }, unenforced: REAL.unenforced };
}
const repoOf = (reqs, { limits = {}, finalGates = [PASS_GATE], workerMode = { default: 'fix' }, harness = {}, suites = {}, env = {} } = {}) =>
  new MiniRepo(reqs, { profile: { limits: { ...long, ...limits }, finalGates, extra: assuranceExtra(), testHarness: harness, suites }, workerMode, env });
const THREE = [R('CORE-001', 2), R('LOOP-001', 1, ['CORE-001']), R('X-201', 3, ['CORE-001'])];

async function boot(repo, serve = '127.0.0.1:0') {
  const i = await repo.init(); assert.equal(i.code, 0, i.stdout + i.stderr);
  const s = await repo.cli(['start', '--background', ...(serve ? ['--serve', serve] : [])]); assert.equal(s.code, 0, s.stdout + s.stderr);
  return s;
}
const ctlPid = async (repo) => (await repo.status()).controller.pid;
const sleeper = () => spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
const stamp = (e) => Date.parse(e.at);

// ================================================================ LOOP-002.AC01

test('[LOOP-002.AC01] start --background returns within 5 s and status within 2 s while a flooding worker runs; a launch that cannot proceed also refuses within 5 s', async () => {
  const repo = repoOf(THREE, { workerMode: { default: 'flood-steady' }, limits: { resource: { maxRssMiB: 2048, maxOutputMiB: 100000, maxLogMiB: 2, minFreeDiskGiB: 1 } } });
  try {
    assert.equal((await repo.init()).code, 0);
    const s = await repo.cli(['start', '--background', '--serve', '127.0.0.1:0']);
    assert.equal(s.code, 0, s.stdout + s.stderr);
    assert.ok(s.ms < 5000, `start took ${s.ms} ms`);
    await repo.waitFor(async () => (await repo.status()).current?.phase === 'worker', { label: 'worker running' });
    await sleep(1500); // let the flood build
    const times = [];
    for (let i = 0; i < 4; i++) { const t = Date.now(); const st = await repo.cli(['status', '--json']); times.push(Date.now() - t); assert.equal(JSON.parse(st.stdout).status, 'running'); }
    assert.ok(Math.max(...times) < 2000, `status took up to ${Math.max(...times)} ms: ${times}`);
    const text = await repo.cli(['status']); assert.ok(text.ms < 2000, `text status ${text.ms} ms`);
  } finally { await repo.cleanup(); }
  // direction two: a profile that cannot launch is refused promptly, with the reason, not hung
  const bad = repoOf(THREE);
  try {
    assert.equal((await bad.init()).code, 0);
    const p = JSON.parse(bad.read('profile.json')); p.suites['suite-X-201'].notYetRunnable = { reason: 'wrapper not authored' }; bad.writeProfile(p);
    const s = await bad.cli(['start', '--background']);
    assert.notEqual(s.code, 0); assert.ok(s.ms < 5000, `refusal took ${s.ms} ms`);
    assert.match(s.stderr, /cannot run yet.*wrapper not authored/);
  } finally { await bad.cleanup(); }
});

async function sampleBeats(repo, ms) {
  const L = layout(repo.root, repo.runId());
  const seen = new Map();
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { const l = JSON.parse(readFileSync(L.leaseFile, 'utf8')); if (l.role === 'controller' && !seen.has(l.seq)) seen.set(l.seq, l.wallAt); } catch { /* mid-rename */ }
    await sleep(100);
  }
  const at = [...seen.values()].sort((a, b) => a - b);
  return { count: at.length, gaps: at.slice(1).map((v, i) => v - at[i]), raw: [...seen.entries()].map(([q, w]) => `${q}@${w % 100000}`).join(' ') };
}

test('[LOOP-002.AC01] the heartbeat is emitted every 5 s (PRD value, read from the profile) whether the worker floods stdout or says nothing', async () => {
  assert.equal(HEARTBEAT_MS, 5000); assert.equal(STALE_AFTER_MS, 15000);
  assert.equal(REAL.limits.heartbeatSeconds, 5);
  const noisy = repoOf(THREE, { workerMode: { default: 'flood-steady' }, harness: { heartbeatMs: undefined }, limits: { heartbeatSeconds: 5, resource: { maxRssMiB: 2048, maxOutputMiB: 100000, maxLogMiB: 2, minFreeDiskGiB: 1 } } });
  const quiet = repoOf(THREE, { workerMode: { default: 'silent-hang' }, harness: { heartbeatMs: undefined }, limits: { heartbeatSeconds: 5 } });
  try {
    await boot(noisy, null); await boot(quiet, null);
    await Promise.all([noisy, quiet].map((r) => r.waitFor(async () => (await r.status()).current?.phase === 'worker', { label: 'worker running' })));
    const [a, b] = await Promise.all([sampleBeats(noisy, 13500), sampleBeats(quiet, 13500)]);
    for (const [label, s] of [['flooding worker', a], ['silent worker', b]]) {
      assert.ok(s.count >= 3, `${label}: only ${s.count} beats in 13.5 s (${s.raw})`);
      for (const g of s.gaps) assert.ok(g >= 4000 && g <= 6500, `${label}: heartbeat gap ${g} ms is not about 5 s (${s.gaps}; ${s.raw})`);
    }
    assert.equal((await noisy.status()).status, 'running', 'a flood never made the controller look stale');
  } finally { await noisy.cleanup(); await quiet.cleanup(); }
});

test('[LOOP-002.AC01] the heartbeat keeps its cadence while the controller main loop is completely starved, and the starvation is visible rather than hidden', async () => {
  const repo = repoOf(THREE, { workerMode: { default: 'silent-hang' }, harness: { heartbeatMs: undefined }, limits: { heartbeatSeconds: 5 } });
  try {
    await boot(repo, null);
    await repo.waitFor(async () => (await repo.status()).current?.phase === 'worker', { label: 'worker' });
    const L = layout(repo.root, repo.runId());
    const seq = existsSync(L.controlFile) ? JSON.parse(readFileSync(L.controlFile, 'utf8')).seq : 0;
    const sampling = sampleBeats(repo, 13000);
    writeFileSync(L.controlFile, JSON.stringify({ seq: seq + 1, command: 'test-block-main', ms: 11000, requestedAt: new Date().toISOString() }));
    await sleep(8500);
    const mid = await repo.status();
    assert.equal(mid.status, 'running', 'a starved main loop with a beating heartbeat is not reported stale');
    assert.ok(mid.controller.mainLoopAgeMs > 6000, `the starvation is reported (main loop last ticked ${mid.controller.mainLoopAgeMs} ms ago)`);
    const s = await sampling;
    assert.ok(s.count >= 2, `heartbeat continued during the starvation (${s.raw})`);
    for (const g of s.gaps) assert.ok(g >= 4000 && g <= 6500, `gap ${g} (${s.raw})`);
  } finally { await repo.cleanup(); }
});

test('[LOOP-002.AC01] the heartbeat interval comes from the profile, and a profile whose heartbeat is too slow to ever be judged live is refused', async () => {
  const fast = repoOf(THREE, { workerMode: { default: 'silent-hang' }, harness: { heartbeatMs: undefined }, limits: { heartbeatSeconds: 1 } });
  try {
    await boot(fast, null);
    await fast.waitFor(async () => (await fast.status()).current?.phase === 'worker', { label: 'worker' });
    const s = await sampleBeats(fast, 5000);
    assert.ok(s.count >= 4, `heartbeatSeconds 1 gave ${s.count} beats in 5 s`);
    for (const g of s.gaps) assert.ok(g >= 600 && g <= 2500, `gap ${g}`);
  } finally { await fast.cleanup(); }
  const slow = repoOf(THREE, { limits: { heartbeatSeconds: 6 } });
  try {
    const i = await slow.init();
    assert.equal(i.code, 1);
    assert.match(i.stdout + i.stderr, /limits\.heartbeatSeconds 6 is too slow.*stale after 15s/s);
  } finally { await slow.cleanup(); }
  assert.doesNotThrow(() => validateProfile(structuredClone(loadProfile(PROFILE_PATH).profile), REPO));
});

test('[LOOP-002.AC01] a controller is live until 15 s without a heartbeat and stale after it, judged by the reader whatever the worker prints', async () => {
  // unit: the exact thresholds, on a live process identity
  const dir = mkdtempSync(join(tmpdir(), 'loop-lease-'));
  try {
    const file = join(dir, 'lease.json');
    const mine = { pid: process.pid, start: startTimeOf(process.pid), role: 'controller' };
    const at = (ageMs) => { writeLease(file, { ...mine, seq: 1 }); const l = JSON.parse(readFileSync(file, 'utf8')); l.wallAt = Date.now() - ageMs; writeFileSync(file, JSON.stringify(l)); return judgeLease(file).state; };
    assert.equal(at(1000), 'live'); assert.equal(at(14000), 'live', '14 s is not stale');
    assert.equal(at(15500), 'stale', '15.5 s is stale'); assert.equal(at(60000), 'stale');
    writeLease(file, { pid: 2147483000, start: 'Thu Jan  1 00:00:00 1970', seq: 1, role: 'controller' });
    assert.equal(judgeLease(file).state, 'dead', 'a dead identity is dead, not merely stale');
  } finally { rmSync(dir, { recursive: true, force: true }); }
  // end to end: freeze the real controller (SIGSTOP stops its heartbeat but not its liveness) and watch the status flip
  const repo = repoOf(THREE, { workerMode: { default: 'flood-steady' }, limits: { resource: { maxRssMiB: 2048, maxOutputMiB: 100000, maxLogMiB: 2, minFreeDiskGiB: 1 } } });
  let pid = null;
  try {
    await boot(repo, null);
    await repo.waitFor(async () => (await repo.status()).current?.phase === 'worker', { label: 'worker' });
    pid = await ctlPid(repo);
    const t0 = Date.now();
    process.kill(pid, 'SIGSTOP');
    await sleep(9000);
    assert.equal((await repo.status()).status, 'running', 'about 9 s without a beat is not yet stale');
    const flip = await repo.waitFor(async () => { const s = await repo.status(); return s.status === 'stale' ? s : null; }, { timeoutMs: 20000, everyMs: 300, label: 'stale' });
    const sinceStop = Date.now() - t0;
    assert.ok(sinceStop >= 14000 && sinceStop <= 19500, `went stale ${sinceStop} ms after the last beat`);
    assert.match(flip.statusReason, /heartbeat is \d+s old \(>15s\)/);
    process.kill(pid, 'SIGCONT');
    await repo.waitFor(async () => (await repo.status()).status === 'running', { timeoutMs: 15000, label: 'running again after SIGCONT' });
  } finally { if (pid) { try { process.kill(pid, 'SIGCONT'); } catch { /* gone */ } } await repo.cleanup(); }
});

// ================================================================ LOOP-002.AC02

test('[LOOP-002.AC02] a silent worker is stopped at its idle limit, and one that is merely slow but within it is not', async () => {
  const silent = repoOf([R('CORE-001', 2)], { workerMode: { default: 'silent-hang' }, limits: { workerIdleSeconds: 3, noProgressSeconds: 60, claudeAttemptSeconds: 60 } });
  try {
    await boot(silent, null);
    const end = await silent.waitFor(async () => attemptEnds(silent)[0], { timeoutMs: 30000, label: 'attempt end' });
    const start = attemptStarts(silent)[0];
    const took = stamp(end) - stamp(start);
    assert.equal(end.kind, 'idle');
    assert.ok(took >= 2900 && took <= 3000 + 1000 + 600 + 3000, `stopped after ${took} ms against an idle limit of 3000 ms`);
    const pid = (await silent.status()).current?.pid;
    if (pid) assert.equal(alive(pid), false);
  } finally { await silent.cleanup(); }
  const slow = repoOf([R('CORE-001', 2)], { workerMode: { default: 'slow', slowMs: 1500 }, limits: { workerIdleSeconds: 3, noProgressSeconds: 60, claudeAttemptSeconds: 60 } });
  try {
    await boot(slow, null);
    const st = await waitTerminal(slow);
    assert.equal(attemptEnds(slow)[0].kind, 'completed', 'a worker quiet for less than the idle limit is left alone');
    assert.equal(st.verifiedRequirements, 1);
  } finally { await slow.cleanup(); }
});

test('[LOOP-002.AC02] a stuck worker (busy, never progressing) is stopped at the no-progress limit', async () => {
  const repo = repoOf([R('CORE-001', 2)], { workerMode: { default: 'chatter' }, limits: { workerIdleSeconds: 60, noProgressSeconds: 4, claudeAttemptSeconds: 60 } });
  try {
    await boot(repo, null);
    const end = await repo.waitFor(async () => attemptEnds(repo)[0], { timeoutMs: 30000, label: 'attempt end' });
    const took = stamp(end) - stamp(attemptStarts(repo)[0]);
    assert.equal(end.kind, 'no-substantive-progress', 'activity alone never resets the progress clock');
    assert.ok(took >= 3900 && took <= 4000 + 1000 + 600 + 3000, `stopped after ${took} ms against a no-progress limit of 4000 ms`);
  } finally { await repo.cleanup(); }
  // direction two: the attempt deadline is a separate, absolute limit
  const dl = repoOf([R('CORE-001', 2)], { workerMode: { default: 'chatter' }, limits: { workerIdleSeconds: 60, noProgressSeconds: 100, claudeAttemptSeconds: 4 } });
  try {
    await boot(dl, null);
    const end = await dl.waitFor(async () => attemptEnds(dl)[0], { timeoutMs: 30000, label: 'attempt end' });
    assert.equal(end.kind, 'attempt-deadline');
  } finally { await dl.cleanup(); }
});

test('[LOOP-002.AC02] a worker that floods output is stopped at the output ceiling, its log stays under the log cap, and a quiet worker is unaffected', async () => {
  const repo = repoOf([R('CORE-001', 2)], { workerMode: { default: 'noisy-loop' }, limits: { resource: { maxRssMiB: 2048, maxOutputMiB: 1, maxLogMiB: 1, minFreeDiskGiB: 1 } } });
  try {
    await boot(repo, null);
    const end = await repo.waitFor(async () => attemptEnds(repo)[0], { timeoutMs: 30000, label: 'attempt end' });
    assert.equal(end.outcome, 'resource-limit');
    assert.match(end.reason, /output exceeded 1048576 bytes/);
    assert.ok(stamp(end) - stamp(attemptStarts(repo)[0]) < 10000, 'stopped promptly');
    const log = join(repo.runPath('attempts'), 'CORE-001-01', 'stream.log');
    assert.ok(statSync(log).size <= 1048576 + 64 * 1024, `log is ${statSync(log).size} bytes against a 1 MiB cap`);
  } finally { await repo.cleanup(); }
  const quiet = repoOf([R('CORE-001', 2)], { limits: { resource: { maxRssMiB: 2048, maxOutputMiB: 1, maxLogMiB: 1, minFreeDiskGiB: 1 } } });
  try {
    await boot(quiet, null);
    await waitTerminal(quiet);
    assert.equal(attemptEnds(quiet)[0].outcome, 'exited');
  } finally { await quiet.cleanup(); }
});

test('[LOOP-002.AC02] an over-budget worker is stopped at the per-attempt ceiling, the spend is charged, and the exhausted run budget stops further attempts', async () => {
  const over = repoOf([R('CORE-001', 2), R('LOOP-001', 1)], { workerMode: { default: 'overspend' } });
  try {
    await boot(over, null);
    const st = await waitTerminal(over);
    const end = attemptEnds(over)[0];
    assert.equal(end.kind, 'attempt-budget');
    assert.ok(stamp(end) - stamp(attemptStarts(over)[0]) < 8000, 'stopped promptly, not at the attempt deadline');
    assert.ok(end.costUsd >= 99, `the reported spend is charged (${end.costUsd})`);
    assert.equal(st.status, 'paused-budget');
    assert.match(st.statusReason, /spend budget exhausted/);
    assert.equal(calls(over).length, 1, 'no further attempt after the budget is gone');
    assert.equal(st.verifiedPercent, 0, 'spending buys no progress');
  } finally { await over.cleanup(); }
  const under = repoOf([R('CORE-001', 2)], { workerMode: { default: 'cheap-fix' } });
  try {
    await boot(under, null);
    const st = await waitTerminal(under);
    assert.equal(attemptEnds(under)[0].kind, 'completed', 'a worker under the ceiling is not stopped');
    assert.equal(st.status, 'completed');
  } finally { await under.cleanup(); }
});

test('[LOOP-002.AC02] a descendant-spawning worker is stopped at its limit with its whole process tree, and an unrelated process survives', async () => {
  const bystander = sleeper();
  const repo = repoOf([R('CORE-001', 2)], { workerMode: { default: 'orphan' }, limits: { workerIdleSeconds: 3, noProgressSeconds: 60, claudeAttemptSeconds: 60 } });
  try {
    await boot(repo, null);
    const orphan = await repo.waitFor(async () => (repo.exists('orphan.pid') ? Number(repo.read('orphan.pid')) : null), { label: 'orphan.pid' });
    assert.equal(alive(orphan), true, 'the detached descendant is running before the stop');
    const end = await repo.waitFor(async () => attemptEnds(repo)[0], { timeoutMs: 30000, label: 'attempt end' });
    assert.equal(end.kind, 'idle');
    assert.ok(stamp(end) - stamp(attemptStarts(repo)[0]) <= 3000 + 1000 + 600 + 3000);
    await repo.waitFor(async () => !alive(orphan), { timeoutMs: 8000, label: 'descendant reclaimed' });
    const job = readFileSync(repo.runPath('jobs.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)).find((j) => j.label === 'worker:CORE-001#1');
    assert.ok(job.orphansKilled.includes(orphan), `the controller itself reclaimed the descendant (${JSON.stringify(job.orphansKilled)})`);
    assert.ok(job.descendantsSeen >= 1, 'the descendant was tracked while it ran');
    assert.equal(alive(bystander.pid), true, 'a process the controller does not own is never touched');
  } finally { bystander.kill('SIGKILL'); await repo.cleanup(); }
});

test('[LOOP-002.AC02] three attempts per requirement and two identical failures are maximums; retry, a controller restart and a re-init never reset them', async () => {
  // two identical failures
  const same = repoOf([R('CORE-001', 2)], { workerMode: { default: 'noop' } });
  try {
    await boot(same, null);
    const st = await waitTerminal(same);
    assert.equal(st.requirements[0].attempts, 2);
    assert.equal(st.requirements[0].blockers[0].type, 'repeated-failure');
    assert.equal(calls(same).length, 2);
    const retry = await same.cli(['retry', '--requirement', 'CORE-001']);
    assert.notEqual(retry.code, 0, 'retry on a stopped run does nothing');
    // restart the controller: nothing is attempted again
    assert.equal((await same.cli(['resume'])).code, 0);
    const st2 = await waitTerminal(same);
    assert.equal(st2.requirements[0].attempts, 2); assert.equal(calls(same).length, 2, 'a restart does not replay an exhausted requirement');
    // an explicit re-init with unchanged inputs keeps the counters too
    assert.equal((await same.init()).code, 0);
    assert.equal((await same.cli(['resume'])).code, 0);
    const st3 = await waitTerminal(same);
    assert.equal(st3.requirements[0].attempts, 2); assert.equal(calls(same).length, 2);
  } finally { await same.cleanup(); }
  // three attempts, failures that differ in nothing the fingerprint sees but repeats relaxed
  const three = repoOf([R('CORE-001', 2)], { workerMode: { default: 'noop' }, limits: { sameFailureRepeats: 9 } });
  try {
    await boot(three, null);
    const st = await waitTerminal(three);
    assert.equal(st.requirements[0].attempts, 3); assert.equal(st.requirements[0].blockers[0].type, 'attempts-exhausted');
    assert.equal(calls(three).length, 3, 'no fourth attempt');
    await three.cli(['resume']); await waitTerminal(three);
    assert.equal(calls(three).length, 3, 'a restart does not buy a fourth attempt');
  } finally { await three.cleanup(); }
  // the live-controller `retry` path: an exhausted requirement is refused, an external blocker is re-evaluated
  const c = Object.create(Controller.prototype);
  c.manifest = { requirements: [{ id: 'A' }, { id: 'B' }, { id: 'C' }] };
  c.S = { requirements: {
    A: { state: 'blocked', attempts: 2, blockers: [{ type: 'repeated-failure' }] },
    B: { state: 'blocked', attempts: 3, blockers: [{ type: 'attempts-exhausted' }] },
    C: { state: 'blocked', attempts: 1, blockers: [{ type: 'missing-tool' }] } } };
  assert.match(c.retryRequirement('A'), /^refused:repeated-failure \(retry caps are not bypassed/);
  assert.match(c.retryRequirement('B'), /^refused:attempts-exhausted \(retry caps are not bypassed/);
  assert.equal(c.S.requirements.A.attempts, 2); assert.equal(c.S.requirements.B.attempts, 3);
  assert.equal(c.retryRequirement('C'), 'requeued', 'control: a cleared external blocker may be re-evaluated');
  assert.equal(c.S.requirements.C.attempts, 1, 'and even that does not reset the attempt count');
});

// ================================================================ LOOP-002.AC03

test('[LOOP-002.AC03] a worker-written done flag, evidence file or completion claim contributes zero progress, and so does a verify run a worker launched', async () => {
  const repo = repoOf([R('CORE-001', 2), R('LOOP-001', 1)], { workerMode: { default: 'forge' } });
  try {
    await boot(repo, null);
    const st = await waitTerminal(repo);
    assert.ok(repo.exists('done.json'), 'the worker did write its done flag');
    assert.ok(existsSync(join(repo.root, '.loop-engineering', 'forged')), 'and a forged evidence file');
    assert.equal(st.verifiedPercent, 0); assert.equal(st.verifiedRequirements, 0); assert.notEqual(st.status, 'completed');
    // a hand-written "pass" envelope dropped into the evidence directory is ignored
    const dir = repo.runPath('evidence', 'CORE-001');
    const real = JSON.parse(readFileSync(join(dir, readdirSync(dir).filter((f) => f.endsWith('.json')).sort()[0]), 'utf8'));
    const forged = { ...real, result: 'pass', criteria: real.criteria.map((c) => ({ ...c, state: 'pass' })), evidenceId: 'CORE-001-000099' };
    writeFileSync(join(dir, '000099.json'), JSON.stringify(forged));
    const after = await repo.status();
    assert.equal(after.verifiedPercent, 0); assert.ok(after.requirements.find((r) => r.id === 'CORE-001').rejectedEvidence >= 1, 'the forgery was seen and rejected');
  } finally { await repo.cleanup(); }
  // a genuine pass issued by a verify run the WORKER launched is not controller-issued evidence
  const w = repoOf([R('CORE-001', 2)], { workerMode: { default: 'noop' } });
  try {
    assert.equal((await w.init()).code, 0);
    writeFileSync(w.path('flag-CORE-001'), 'ok');
    const viaWorker = await w.cli(['verify', '--requirement', 'CORE-001'], { env: { LOOP_ENGINEERING_WORKER: '1' } });
    assert.equal(viaWorker.code, 0, 'the suite really passes');
    const s1 = buildStatus(w.root);
    assert.equal(s1.verifiedPercent, 0, 'worker-launched verification advances nothing');
    assert.equal(s1.requirements[0].rejectedEvidence, 1);
    // the controller then issues its own evidence for the same bytes, and that advances completion without a worker attempt
    assert.equal((await w.cli(['start', '--background'])).code, 0);
    const st = await waitTerminal(w);
    assert.equal(st.verifiedRequirements, 1); assert.equal(calls(w).length, 0, 'verified by the controller pre-check; no worker was needed');
    assert.equal(st.requirements[0].evidence.fresh, true);
  } finally { await w.cleanup(); }
});

test('[LOOP-002.AC03] changing a watched file or the acceptance text invalidates evidence; an unrelated file does not', async () => {
  const repo = repoOf([R('CORE-001', 2), R('LOOP-001', 1), R('X-201', 3)], { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'noop' } } });
  try {
    await boot(repo, null);
    const done = await waitTerminal(repo);
    assert.equal(done.verifiedRequirements, 2); assert.equal(done.status, 'blocked');
    const fresh = (st) => st.requirements.filter((r) => r.state === 'verified').map((r) => r.id).sort();
    writeFileSync(repo.path('unrelated.txt'), 'not watched');
    assert.deepEqual(fresh(buildStatus(repo.root)), ['CORE-001', 'X-201'], 'an unwatched file leaves evidence fresh');
    // 1. a watched file
    writeFileSync(repo.path('flag-CORE-001'), 'edited after verification');
    const s1 = buildStatus(repo.root);
    const r1 = s1.requirements.find((r) => r.id === 'CORE-001');
    assert.equal(r1.state, 'stale'); assert.match(r1.staleReasons.join(), /relevant source\/test files changed/);
    assert.deepEqual(fresh(s1), ['X-201'], 'only the requirement that watches the file went stale');
    assert.equal(s1.verifiedPercent, 50, 'X-201 (weight 3) of 6 total: the stale CORE-001 earns nothing and stays in the denominator');
    writeFileSync(repo.path('flag-CORE-001'), 'ok');
    assert.deepEqual(fresh(buildStatus(repo.root)), ['CORE-001', 'X-201'], 'restoring the exact bytes restores freshness');
    // 2. the acceptance text: edit the PRD, re-init to a new manifest version
    writeFileSync(repo.path('PRD.md'), repo.read('PRD.md').replace('the criterion', 'the criterion, now stricter'));
    assert.equal((await repo.init()).code, 0);
    const s2 = buildStatus(repo.root);
    assert.deepEqual(fresh(s2), []);
    for (const id of ['CORE-001', 'X-201']) {
      const r = s2.requirements.find((x) => x.id === id);
      assert.equal(r.state, 'stale', `${id} is stale after the acceptance text changed`);
      assert.match(r.staleReasons.join(), /PRD changed|acceptance definition changed/);
    }
    assert.equal(s2.verifiedPercent, 0);
  } finally { await repo.cleanup(); }
});

// ================================================================ LOOP-003.AC01

function runPageScript(statusJson) {
  const html = PAGE('nonce');
  const script = /<script nonce="nonce">([\s\S]*?)<\/script>/.exec(html)[1];
  class El {
    constructor(id) { this.id = id; this.children = []; this._t = ''; this.className = ''; this.style = {}; this.hidden = false; this.value = ''; this.options = id === 'fcat' || id === 'fstate' ? [{}] : []; }
    get textContent() { return this._t + this.children.map((c) => c.textContent).join(''); }
    set textContent(v) { this._t = String(v); this.children = []; }
    append(...n) { this.children.push(...n); }
    appendChild(n) { this.children.push(n); return n; }
    add(o) { this.options.push(o); }
    set length(n) { this.options.length = n; }
    get firstChild() { return this.children[0] || null; }
  }
  const els = new Map();
  const document = { getElementById: (id) => { if (!els.has(id)) els.set(id, new El(id)); return els.get(id); }, createElement: (tag) => new El(tag) };
  const ctx = { document, Option: class { constructor(a, b) { this.text = a; this.value = b; } }, Date, Math, String, Number, Array, Object, JSON, setTimeout: () => 0, fetch: () => Promise.resolve({ json: () => Promise.resolve(statusJson) }) };
  vm.runInNewContext(script, ctx);
  return { text: (id) => document.getElementById(id).textContent, el: (id) => document.getElementById(id) };
}

test('[LOOP-003.AC01] the CLI, the JSON and the dashboard agree on weighted progress, every workstream count, stale/blocked/failed work, the active criterion, spend, heartbeat and the continuation command', async () => {
  const reqs = [R('CORE-001', 2), R('LOOP-001', 1, ['CORE-001']), R('QA-001', 3), R('X-201', 2, ['QA-001']), R('DOC-001', 1)];
  const repo = repoOf(reqs, { workerMode: { default: 'fix', perReq: { 'QA-001': 'noop' } } });
  try {
    await boot(repo);
    const st0 = await waitQuiet(repo);
    assert.equal(st0.status, 'blocked');
    writeFileSync(repo.path('flag-LOOP-001'), 'edited'); // one verified requirement becomes stale
    const json = JSON.parse((await repo.cli(['status', '--json'])).stdout);
    const cli = (await repo.cli(['status'])).stdout;
    const api = await (await fetch(json.serve.url + '/api/status')).json();
    const page = runPageScript(api);
    await sleep(50); await new Promise((r) => setImmediate(r)); await new Promise((r) => setImmediate(r));
    const s = json.summary;
    // the state really is mixed, or agreement would be vacuous
    assert.deepEqual(s.stale, ['LOOP-001']); assert.deepEqual(s.blocked, ['QA-001']);
    assert.equal(s.percent, 33.3, 'CORE-001 (2) and DOC-001 (1) of 9 total weight'); assert.equal(s.percent, json.verifiedPercent);
    assert.equal(s.workstreams.length, 11); assert.equal(s.workstreams.find((w) => w.key === 'foundation').verified, 1);
    assert.equal(s.workstreams.find((w) => w.key === 'evaluation').blocked, 1);
    // the three channels carry the same lines, character for character
    assert.deepEqual(api.summary.lines, s.lines);
    for (const line of s.lines) assert.ok(cli.includes(line), `CLI is missing: ${line}`);
    assert.equal(page.text('summary'), s.lines.join('\n'));
    assert.equal(page.text('pct'), `${s.percent}%`);
    assert.match(page.text('pctdetail'), new RegExp(`${json.verifiedWeight}/${json.totalWeight} weight`));
    for (const w of s.workstreams) assert.ok(page.text('wss').includes(`${w.label}: ${w.verified}/${w.total} verified`), `dashboard card for ${w.key}`);
    for (const f of ['active criterion', 'spent', 'last heartbeat', 'continue']) assert.ok(s.lines.some((l) => l.startsWith(f)), `${f} is reported`);
    assert.equal(s.continuation, 'node scripts/loop-engineering/run.mjs resume');
    // direction two: the continuation command is real. Run it exactly as printed.
    const parts = s.continuation.split(' ').slice(2);
    const ran = await repo.cli(parts);
    assert.equal(ran.code, 0, ran.stdout + ran.stderr);
    await repo.waitFor(async () => { const x = await repo.status(); return x.controller.liveness === 'live' || TERMINAL.includes(x.status); }, { label: 'continuation took effect' });
    // and an altered snapshot makes the dashboard disagree: the comparison is not vacuous
    const tampered = structuredClone(api); tampered.summary.lines[0] = 'weighted verified progress: 100%';
    assert.notEqual(runPageScript(tampered).text('summary'), s.lines.join('\n'));
  } finally { await repo.cleanup(); }
});

test('[LOOP-003.AC01] the active criterion names the criterion being worked on, and the heartbeat and spend are reported while it runs', async () => {
  const repo = repoOf([R('CORE-001', 2)], { workerMode: { default: 'silent-hang' } });
  try {
    await boot(repo, null);
    const st = await repo.waitFor(async () => { const s = await repo.status(); return s.current?.phase === 'worker' ? s : null; }, { label: 'worker' });
    assert.deepEqual(st.summary.activeCriterion, { requirement: 'CORE-001', criterion: 'CORE-001.AC01', phase: 'worker' });
    assert.match(st.summary.lines.find((l) => l.startsWith('active criterion')), /CORE-001\.AC01 \(CORE-001, worker\)/);
    assert.ok(st.summary.lastHeartbeatAt && Date.now() - Date.parse(st.summary.lastHeartbeatAt) < 15000);
    assert.equal(st.summary.spent.attempts, 1); assert.equal(st.summary.spent.limits.usd, 50);
    assert.equal(st.summary.continuation, 'node scripts/loop-engineering/run.mjs status --json');
  } finally { await repo.cleanup(); }
  const idle = repoOf([R('CORE-001', 2)]);
  try {
    assert.equal((await idle.init()).code, 0);
    assert.equal(buildStatus(idle.root).summary.activeCriterion, null, 'nothing is active before a start');
  } finally { await idle.cleanup(); }
});

// ================================================================ LOOP-003.AC02

test('[LOOP-003.AC02] verified completion is fresh verified weight over all required weight, with blocked, stale and failed work kept in the denominator', () => {
  const root = mkdtempSync(join(tmpdir(), 'loop-formula-'));
  try {
    copyFileSync(FIXTURE, join(root, 'PRD.md'));
    const { manifest } = createManifest({ repoRoot: root, prdPath: 'PRD.md', profile: structuredClone(loadProfile(PROFILE_PATH).profile), profileSha: 'a'.repeat(64) });
    assert.equal(manifest.totals.weight, 269);
    const assess = (verifiedIds, staleIds = []) => new Map(manifest.requirements.map((r) => {
      const v = verifiedIds.has(r.id); const s = staleIds.includes(r.id);
      return [r.id, { verified: v, stale: s, fresh: v, passedCriteria: v || s ? 3 : 0, latest: v || s ? { ev: { criteria: [], evidenceId: 'e', result: 'pass', createdAt: 'now' }, file: 'f' } : null }];
    }));
    const ids = manifest.requirements.map((r) => r.id);
    const w = (set) => manifest.requirements.filter((r) => set.has(r.id)).reduce((n, r) => n + r.weight, 0);
    const exp = (n) => Math.floor((n / 269) * 1000) / 10;
    // several subsets: the percent is exactly floor(verified/269 to one decimal), and the denominator never moves
    let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    for (let k = 0; k < 25; k++) {
      const set = new Set(ids.filter(() => rnd() < k / 25));
      const stale = ids.filter((i) => !set.has(i) && rnd() < 0.3);
      const blockedState = Object.fromEntries(ids.filter((i) => !set.has(i) && !stale.includes(i) && rnd() < 0.3).map((i) => [i, { state: rnd() < 0.5 ? 'blocked' : 'failed', blockers: [] }]));
      const p = computeProgress(manifest, assess(set, stale), blockedState, { final: { required: true, ok: false } });
      assert.equal(p.totalWeight, 269, 'blocked, stale and failed work stay in the denominator');
      assert.equal(p.verifiedWeight, w(set));
      assert.equal(p.verifiedPercent, Math.min(99.9, exp(w(set))), `subset ${k}`);
    }
    // a stale-but-implemented requirement earns nothing
    const staleAll = computeProgress(manifest, assess(new Set(), ids), {}, { final: { required: true, ok: false } });
    assert.equal(staleAll.verifiedPercent, 0); assert.equal(staleAll.counts.stale, 70);
    // the per-workstream view partitions the same denominator
    const p = computeProgress(manifest, assess(new Set(ids.slice(0, 10))), {}, { final: { required: true, ok: false } });
    assert.equal(Object.values(p.workstreams).reduce((n, x) => n + x.totalWeight, 0), 269);
    assert.equal(formatPercent(268, 269), 99.6); assert.equal(formatPercent(269, 269), 100);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('[LOOP-003.AC02] 100 percent is impossible until every requirement is verified AND the final gate has passed on a stable tree', async () => {
  const root = mkdtempSync(join(tmpdir(), 'loop-hundred-'));
  try {
    copyFileSync(FIXTURE, join(root, 'PRD.md'));
    const { manifest } = createManifest({ repoRoot: root, prdPath: 'PRD.md', profile: structuredClone(loadProfile(PROFILE_PATH).profile), profileSha: 'a'.repeat(64) });
    assert.equal(manifest.finalVerification.required, true);
    const all = new Map(manifest.requirements.map((r) => [r.id, { verified: true, stale: false, fresh: true, passedCriteria: 3, latest: { ev: { criteria: [], evidenceId: 'e', result: 'pass', createdAt: 'n' }, file: 'f' } }]));
    assert.equal(computeProgress(manifest, all, {}, { final: { required: true, ok: false, reasons: ['no final verification has run'] } }).verifiedPercent, 99.9, 'every requirement verified, no final gate: still below 100');
    assert.equal(computeProgress(manifest, all, {}, { final: { required: true, ok: true } }).verifiedPercent, 100);
    const one = new Map(all); const first = manifest.requirements[0].id; one.set(first, { ...all.get(first), verified: false, fresh: false });
    assert.ok(computeProgress(manifest, one, {}, { final: { required: true, ok: true } }).verifiedPercent < 100, 'a passing final gate cannot cover an unverified requirement');
  } finally { rmSync(root, { recursive: true, force: true }); }
  // end to end: a failing release gate leaves the run at 99.9 and never completed; a passing one reaches 100
  const bad = repoOf(THREE, { finalGates: [{ ...PASS_GATE, id: 'gate-bad', args: ['-e', 'process.exit(3)'] }] });
  try {
    await boot(bad, null);
    const st = await waitTerminal(bad);
    assert.equal(st.verifiedRequirements, 3, 'every requirement is verified');
    assert.equal(st.verifiedPercent, 99.9); assert.notEqual(st.status, 'completed'); assert.equal(st.status, 'blocked');
    assert.equal(st.final.ok, false); assert.match(st.statusReason, /final verification did not pass.*gate:gate-bad/);
  } finally { await bad.cleanup(); }
  const good = repoOf(THREE);
  try {
    await boot(good, null);
    const st = await waitTerminal(good);
    assert.equal(st.status, 'completed'); assert.equal(st.verifiedPercent, 100); assert.equal(st.final.ok, true);
    assert.ok(existsSync(good.runPath('final-evidence.json')));
  } finally { await good.cleanup(); }
});

// ================================================================ LOOP-003.AC03

const FINISH = ['completed'];
async function finishAfter(repo, { fixTo = 'fix' } = {}) {
  repo.setMode({ default: fixTo });
  const r = await repo.cli(['resume']); assert.equal(r.code, 0, r.stdout + r.stderr);
  return repo.waitFor(async () => { const s = await repo.status(); return FINISH.includes(s.status) ? s : null; }, { timeoutMs: 90000, label: 'completed after recovery' });
}
const PAIR = [R('CORE-001', 2), R('LOOP-001', 1, ['CORE-001'])];

test('[LOOP-003.AC03] after SIGTERM the run is stopped, nothing unrelated is killed, and resume redoes only the unfinished requirement', async () => {
  const bystander = sleeper();
  const repo = repoOf(PAIR, { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'silent-hang' } } });
  try {
    await boot(repo, null);
    const st = await repo.waitFor(async () => { const s = await repo.status(); return s.current?.requirement === 'LOOP-001' && s.current.pid ? s : null; }, { label: 'LOOP-001 worker' });
    process.kill(st.controller.pid, 'SIGTERM');
    const stopped = await repo.waitFor(async () => { const s = await repo.status(); return s.status === 'stopped' ? s : null; }, { timeoutMs: 20000, label: 'stopped' });
    assert.equal(alive(st.current.pid), false, 'the in-flight worker was reclaimed');
    assert.equal(stopped.requirements.find((r) => r.id === 'CORE-001').state, 'verified');
    assert.equal(alive(bystander.pid), true);
    const done = await finishAfter(repo);
    assert.equal(done.status, 'completed'); assert.equal(callsFor(repo, 'CORE-001').length, 1, 'the fresh completed requirement was not replayed');
    assert.ok(callsFor(repo, 'LOOP-001').length >= 2);
    assert.equal(alive(bystander.pid), true);
  } finally { bystander.kill('SIGKILL'); await repo.cleanup(); }
});

test('[LOOP-003.AC03] after SIGKILL the guardian reports a crash and reclaims owned work only; resume does not replay fresh completed requirements', async () => {
  const bystander = sleeper();
  const repo = repoOf(PAIR, { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'orphan' } } });
  try {
    await boot(repo, null);
    const st = await repo.waitFor(async () => { const s = await repo.status(); return s.current?.requirement === 'LOOP-001' && s.current.pid && repo.exists('orphan.pid') ? s : null; }, { label: 'worker and orphan' });
    const orphan = Number(repo.read('orphan.pid'));
    process.kill(st.controller.pid, 'SIGKILL');
    const crashed = await repo.waitFor(async () => { const s = await repo.status(); return s.status === 'crashed' && !alive(orphan) ? s : null; }, { timeoutMs: 25000, label: 'crash + reclaim' });
    assert.equal(alive(st.current.pid), false); assert.equal(alive(bystander.pid), true, 'unrelated process untouched');
    assert.equal(crashed.requirements.find((r) => r.id === 'CORE-001').state, 'verified', 'completed work survives the crash');
    const done = await finishAfter(repo);
    assert.equal(done.status, 'completed'); assert.equal(callsFor(repo, 'CORE-001').length, 1);
  } finally { bystander.kill('SIGKILL'); await repo.cleanup(); }
});

test('[LOOP-003.AC03] a stop followed by a controller restart continues from the checkpoint without replaying completed work', async () => {
  const repo = repoOf(PAIR, { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'silent-hang' } } });
  try {
    await boot(repo, null);
    await repo.waitFor(async () => (await repo.status()).current?.requirement === 'LOOP-001', { label: 'LOOP-001 running' });
    const before = repo.state().checkpoints;
    const stop = await repo.cli(['stop', '--run', repo.runId()]); assert.equal(stop.code, 0, stop.stderr);
    assert.equal((await repo.status()).status, 'stopped');
    assert.ok(repo.state().checkpoints >= before, 'checkpoints persisted');
    const done = await finishAfter(repo);
    assert.equal(done.status, 'completed'); assert.equal(callsFor(repo, 'CORE-001').length, 1);
    assert.ok(repo.state().restarts >= 1, 'the restart is counted');
  } finally { await repo.cleanup(); }
});

test('[LOOP-003.AC03] a machine sleep (the wall clock jumping) interrupts the in-flight attempt without counting it; recovery re-runs only that requirement', async () => {
  const repo = repoOf(PAIR, { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'silent-hang' } } });
  try {
    await boot(repo, null);
    await repo.waitFor(async () => (await repo.status()).current?.requirement === 'LOOP-001', { label: 'LOOP-001 running' });
    const L = layout(repo.root, repo.runId());
    const seq = existsSync(L.controlFile) ? JSON.parse(readFileSync(L.controlFile, 'utf8')).seq : 0;
    writeFileSync(L.controlFile, JSON.stringify({ seq: seq + 1, command: 'simulate-sleep', requestedAt: new Date().toISOString() }));
    await repo.waitFor(async () => eventsOf(repo).some((e) => e.type === 'sleep-detected'), { timeoutMs: 20000, label: 'sleep detected' });
    const end = await repo.waitFor(async () => attemptEnds(repo, 'LOOP-001').find((e) => e.kind === 'interrupted-sleep'), { timeoutMs: 20000, label: 'interrupted attempt' });
    assert.equal(end.kind, 'interrupted-sleep');
    repo.setMode({ default: 'fix' });
    const done = await repo.waitFor(async () => { const s = await repo.status(); return s.status === 'completed' ? s : null; }, { timeoutMs: 90000, label: 'completed' });
    assert.equal(done.requirements.find((r) => r.id === 'LOOP-001').attempts <= 2, true, 'the interrupted attempt did not consume the cap');
    assert.equal(callsFor(repo, 'CORE-001').length, 1);
  } finally { await repo.cleanup(); }
});

test('[LOOP-003.AC03] a busy dashboard port falls back without touching its owner, and the run recovers from a SIGKILL with the same listener still intact', async () => {
  const squatter = net.createServer(); await new Promise((r) => squatter.listen(0, '127.0.0.1', r));
  let held = 0; squatter.on('connection', (c) => { held++; c.end('squatter-still-here'); });
  const busy = squatter.address().port;
  const repo = repoOf(PAIR, { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'silent-hang' } } });
  try {
    const t = Date.now();
    await boot(repo, `127.0.0.1:${busy}`);
    assert.ok(Date.now() - t < 10000);
    const st = await repo.waitFor(async () => { const s = await repo.status(); return s.serve?.port && s.current?.requirement === 'LOOP-001' ? s : null; }, { label: 'dashboard up' });
    assert.notEqual(st.serve.port, busy); assert.ok(st.serve.portConflict, 'the conflict is reported');
    assert.equal((await fetch(st.serve.url + '/api/status')).status, 200);
    process.kill(st.controller.pid, 'SIGKILL');
    await repo.waitFor(async () => (await repo.status()).status === 'crashed', { timeoutMs: 25000, label: 'crashed' });
    const done = await finishAfter(repo);
    assert.equal(done.status, 'completed'); assert.equal(callsFor(repo, 'CORE-001').length, 1);
    const probe = await new Promise((resolve) => { const c = net.connect(busy, '127.0.0.1'); let d = ''; c.on('data', (x) => { d += x; }); c.on('close', () => resolve(d)); c.on('error', () => resolve('error')); });
    assert.equal(probe, 'squatter-still-here', 'the port owner was never disturbed'); assert.ok(held >= 1);
  } finally { squatter.close(); await repo.cleanup(); }
});

test('[LOOP-003.AC03] a torn checkpoint is recovered from the backup without resetting attempts, and with no backup the controller refuses to start rather than reinitialise', async () => {
  const repo = repoOf(PAIR, { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'silent-hang' } } });
  try {
    await boot(repo, null);
    const st = await repo.waitFor(async () => { const s = await repo.status(); return s.current?.requirement === 'LOOP-001' && s.current.pid ? s : null; }, { label: 'LOOP-001' });
    process.kill(st.controller.pid, 'SIGKILL');
    await repo.waitFor(async () => (await repo.status()).status === 'crashed', { timeoutMs: 25000, label: 'crashed' });
    const L = layout(repo.root, repo.runId());
    const attemptsBefore = repo.state().requirements['CORE-001'].attempts;
    assert.ok(attemptsBefore >= 1);
    // tear the primary
    writeFileSync(L.stateFile, readFileSync(L.stateFile, 'utf8').slice(0, 40));
    assert.equal(readStateFile(L).source, 'backup');
    assert.equal(buildStatus(repo.root).requirements.find((r) => r.id === 'CORE-001').state, 'verified', 'status reads the backup');
    const done = await finishAfter(repo);
    assert.equal(done.status, 'completed'); assert.equal(callsFor(repo, 'CORE-001').length, 1, 'recovery did not replay work');
    assert.equal(repo.state().requirements['CORE-001'].attempts, attemptsBefore);
  } finally { await repo.cleanup(); }
  // no backup: fail closed
  const solo = repoOf([R('CORE-001', 2)], { workerMode: { default: 'noop' } });
  try {
    await boot(solo, null);
    await waitQuiet(solo);
    const L = layout(solo.root, solo.runId());
    const n = calls(solo).length;
    writeFileSync(L.stateFile, '{"truncated'); writeFileSync(L.stateBackup, 'also bad');
    assert.equal(readStateFile(L).source, 'corrupt');
    const r = await solo.cli(['resume']);
    assert.notEqual(r.code, 0, 'resume refuses');
    // and the controller itself, started directly, refuses rather than reinitialising over the damage
    const bootScript = `import { startController } from ${JSON.stringify(new URL('../lib/controller.mjs', import.meta.url).href)}; process.exitCode = await startController({ repoRoot: ${JSON.stringify(solo.root)}, runId: ${JSON.stringify(solo.runId())}, profilePath: 'profile.json' });`;
    const direct = await new Promise((res) => { let err = ''; const c = spawn(process.execPath, ["--input-type=module", "-e", bootScript], { cwd: solo.root, env: solo.env, stdio: ['ignore', 'ignore', 'pipe'] }); c.stderr.on('data', (d) => { err += d; }); c.on('close', (code) => res({ code, err })); });
    assert.equal(direct.code, 2); assert.match(direct.err, /state\.json is corrupt and no checkpoint backup exists; refusing to reinitialise/);
    assert.equal(readFileSync(L.stateFile, 'utf8'), '{"truncated', 'the damaged file was not overwritten with a fresh state');
    assert.equal(calls(solo).length, n, 'no worker was run on a reset state');
  } finally { await solo.cleanup(); }
});

test('[LOOP-003.AC03] logs are redacted and bounded: no secret reaches any file, the attempt log honours the cap, events carry sequence ids and rotate', async () => {
  const repo = repoOf([R('CORE-001', 2)], { workerMode: { default: 'secret' }, limits: { resource: { maxRssMiB: 2048, maxOutputMiB: 64, maxLogMiB: 1, minFreeDiskGiB: 1 } } });
  try {
    await boot(repo, null);
    const st = await waitTerminal(repo);
    assert.equal(st.status, 'completed');
    const secrets = ['sk-ant-api03-ZZZZ', 'ghp_aaaaaaaa', 'qqqqqqqqqqqq'];
    const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]));
    const files = walk(repo.runPath());
    assert.ok(files.length > 5);
    for (const f of files.filter((x) => !x.includes('prompt.txt') && !x.includes(`${join('evidence')}`))) {
      const body = readFileSync(f, 'utf8');
      for (const sec of secrets) assert.ok(!body.includes(sec), `${f} leaks ${sec}`);
    }
    const log = join(repo.runPath('attempts'), 'CORE-001-01', 'stream.log');
    assert.ok(statSync(log).size <= 1048576 + 64 * 1024, `attempt log ${statSync(log).size} bytes against a 1 MiB cap`);
    assert.match(readFileSync(log, 'utf8'), /REDACTED/, 'the redaction is visible in the log');
    const evs = eventsOf(repo);
    assert.ok(evs.every((e, i) => Number.isInteger(e.seq) && (i === 0 || e.seq === evs[i - 1].seq + 1)), 'event sequence ids are contiguous and monotonic');
  } finally { await repo.cleanup(); }
  // rotation and cross-process uniqueness
  const dir = mkdtempSync(join(tmpdir(), 'loop-events-'));
  try {
    const L = layout(dir, 'run-x'); mkdirSync(L.dir, { recursive: true });
    setLogCap(20000);
    for (let i = 0; i < 400; i++) appendEvent(L, 'note', { i, pad: 'p'.repeat(200) });
    setLogCap(5 * 1024 * 1024);
    assert.ok(statSync(L.eventsFile).size <= 20000 + 400, 'the current events file stays within the cap');
    assert.ok(existsSync(`${L.eventsFile}.1`), 'the previous file was rotated, not grown');
    assert.ok(statSync(`${L.eventsFile}.1`).size <= 20000 + 400);
    const last = JSON.parse(readFileSync(L.eventsFile, 'utf8').trim().split('\n').pop());
    assert.equal(last.seq, 400, 'sequence ids continue across rotation');
    // two processes appending at once never share a sequence id
    const worker = `import { appendEvent, layout } from ${JSON.stringify(new URL('../lib/state.mjs', import.meta.url).href)}; const L = layout(${JSON.stringify(dir)}, 'run-y'); for (let i = 0; i < 80; i++) appendEvent(L, 'p', { i });`;
    mkdirSync(layout(dir, 'run-y').dir, { recursive: true });
    await Promise.all([1, 2, 3].map(() => new Promise((res) => { const c = spawn(process.execPath, ['--input-type=module', '-e', worker], { stdio: 'ignore' }); c.on('close', res); })));
    const seqs = readFileSync(layout(dir, 'run-y').eventsFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l).seq);
    assert.equal(seqs.length, 240); assert.equal(new Set(seqs).size, 240, 'no duplicate sequence id');
    appendJsonl(join(dir, 'x.jsonl'), { a: 1 }, { maxBytes: 5 }); appendJsonl(join(dir, 'x.jsonl'), { a: 2 }, { maxBytes: 5 });
    assert.ok(existsSync(join(dir, 'x.jsonl.1')));
  } finally { setLogCap(5 * 1024 * 1024); rmSync(dir, { recursive: true, force: true }); }
});

// ================================================================ LOOP-004.AC01

test('[LOOP-004.AC01] a PRD change during an initialised run stops it with a drift reason; only an explicit re-init resumes, and the affected evidence is invalidated', async () => {
  const repo = repoOf(PAIR, { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'silent-hang' } } });
  try {
    await boot(repo, null);
    await repo.waitFor(async () => (await repo.status()).current?.requirement === 'LOOP-001', { label: 'LOOP-001 running' });
    // control: an unchanged run is not blocked by the drift watch
    await sleep(3500); assert.equal((await repo.status()).status, 'running');
    const n = calls(repo).length;
    writeFileSync(repo.path('PRD.md'), repo.read('PRD.md') + '\nA late edit to the acceptance document.\n');
    const ctl = await ctlPid(repo);
    const st = await repo.waitFor(async () => { const s = await repo.status(); return s.status === 'blocked' ? s : null; }, { timeoutMs: 20000, label: 'drift stop' });
    await repo.waitFor(async () => !alive(ctl), { timeoutMs: 15000, label: 'controller exited' });
    assert.match(st.statusReason, /^drift: prd PRD\.md: the PRD changed after init/);
    assert.ok(st.blockers.some((b) => b.type === 'drift'));
    assert.equal(st.drift.reasons[0].input, 'prd');
    assert.equal(st.requirements.find((r) => r.id === 'LOOP-001').attempts, 0, 'the interrupted attempt was not charged');
    assert.equal(calls(repo).length, n, 'no new worker was launched after the drift');
    // resume alone is refused
    const r = await repo.cli(['resume']); assert.notEqual(r.code, 0); assert.match(r.stderr, /PRD changed since manifest v1 was frozen; run init/);
    // explicit re-initialisation: new manifest version, drift cleared, old evidence stale
    const init = await repo.init(); assert.equal(init.code, 0, init.stdout + init.stderr);
    assert.match(init.stdout, /inputs changed since the previous init/);
    const after = buildStatus(repo.root);
    assert.equal(after.drift, null); assert.equal(after.requirements.find((r2) => r2.id === 'CORE-001').state, 'stale', 'evidence bound to the old PRD no longer counts');
    assert.equal(after.verifiedPercent, 0);
    const done = await finishAfter(repo);
    assert.equal(done.status, 'completed'); assert.equal(callsFor(repo, 'CORE-001').length, 1, 'stale evidence is re-verified by the controller, not re-worked');
  } finally { await repo.cleanup(); }
});

test('[LOOP-004.AC01] a profile change or a protected suite wrapper edit during a run is drift; an edit to a worker-writable suite is not', async () => {
  const protectedSuites = { 'suite-CORE-001': { protectedWrapper: true } };
  // profile change
  const prof = repoOf(PAIR, { workerMode: { default: 'silent-hang' } });
  try {
    await boot(prof, null);
    await prof.waitFor(async () => (await prof.status()).current?.phase === 'worker', { label: 'worker' });
    const p = JSON.parse(prof.read('profile.json')); p.limits.claudeBudgetUsd = 400; prof.writeProfile(p);
    const st = await prof.waitFor(async () => { const s = await prof.status(); return s.status === 'blocked' ? s : null; }, { timeoutMs: 20000, label: 'drift stop' });
    assert.match(st.statusReason, /^drift: profile: the execution profile changed after init/);
  } finally { await prof.cleanup(); }
  // protected wrapper edited BY the worker
  const wrapper = repoOf(PAIR, { workerMode: { default: 'tamper' }, suites: { 'suite-CORE-001': { kind: 'node-test', cwd: '.', executable: 'node', files: ['t/suite-CORE-001.test.js'], timeoutSeconds: 30, protectedWrapper: true } } });
  void protectedSuites;
  try {
    await boot(wrapper, null);
    const st = await wrapper.waitFor(async () => { const s = await wrapper.status(); return s.status === 'blocked' ? s : null; }, { timeoutMs: 30000, label: 'drift stop' });
    assert.match(st.statusReason, /^drift: suite-input t\/suite-CORE-001\.test\.js: a protected suite wrapper changed/);
    assert.equal(st.requirements[0].attempts, 0, 'the tampering attempt is not charged as ordinary work');
  } finally { await wrapper.cleanup(); }
  // control: the same edit to an unprotected (worker-writable) suite is ordinary work
  const open = repoOf(PAIR, { workerMode: { default: 'tamper', perReq: { 'LOOP-001': 'fix' } } });
  try {
    await boot(open, null);
    await open.waitFor(async () => attemptStarts(open, 'CORE-001').length >= 1, { label: 'worker' });
    await sleep(3000);
    const s = await open.status();
    assert.notEqual(s.status, 'blocked'); assert.equal(s.drift, null, 'no drift on a suite the worker is allowed to write');
  } finally { await open.cleanup(); }
  // controller code and a missing wrapper, judged purely
  const fz = captureFrozenInputs({ repoRoot: REPO, prdPath: 'scripts/loop-engineering/test/fixtures/assurance-prd-section8.md', profile: loadProfile(PROFILE_PATH).profile });
  const prof2 = loadProfile(PROFILE_PATH).profile;
  assert.equal(detectDrift({ repoRoot: REPO, frozen: fz, profile: prof2 }).drifted, false, 'control: nothing changed');
  const forged = { ...fz, controllerSha256: 'f'.repeat(64) };
  assert.deepEqual(detectDrift({ repoRoot: REPO, frozen: forged, profile: prof2 }).reasons.map((x) => x.input), ['controller']);
  const missing = { ...fz, suiteInputs: { ...fz.suiteInputs, 'no/such/wrapper.test.js': 'a'.repeat(64) } };
  assert.match(detectDrift({ repoRoot: REPO, frozen: missing, profile: prof2 }).reasons[0].detail, /removed/);
  assert.equal(detectDrift({ repoRoot: REPO, frozen: fz, profile: null }).reasons[0].input, 'profile');
});

// ================================================================ LOOP-004.AC02

test('[LOOP-004.AC02] the final decision is complete only when every requirement, every gate and one stable digest agree; each failure mode prevents it', () => {
  const ids = ['A-1', 'A-2'];
  const ok = (id) => ({ id, result: 'pass', evidenceId: `${id}-1`, skipped: 0, blockerType: null });
  const base = { requirements: ids.map(ok), expectedRequirements: ids, gates: [{ id: 'build', ok: true, exitCode: 0 }], expectedGates: ['build'], treeDigests: { before: 'd', afterEach: ['d', 'd'], after: 'd' } };
  const kinds = (o) => evaluateFinal({ ...base, ...o }).unmet.map((u) => u.kind);
  assert.equal(evaluateFinal(base).verdict, 'all-required-criteria-verified');
  assert.deepEqual(kinds({ requirements: [ok('A-1'), { ...ok('A-2'), skipped: 1 }] }), ['skip']);
  assert.deepEqual(kinds({ requirements: [ok('A-1'), { ...ok('A-2'), result: 'blocked', blockerType: 'missing-tool' }] }), ['unsupported-backend']);
  assert.deepEqual(kinds({ requirements: [ok('A-1')] }), ['evidence-unavailable']);
  assert.deepEqual(kinds({ requirements: [ok('A-1'), { ...ok('A-2'), result: 'fail' }] }), ['requirement']);
  assert.deepEqual(kinds({ gates: [{ id: 'build', ok: false, exitCode: 2 }] }), ['gate']);
  assert.deepEqual(kinds({ gates: [] }), ['gate'], 'a gate that never ran is a failure');
  assert.deepEqual(kinds({ treeDigests: { before: 'd', afterEach: ['d', 'e'], after: 'd' } }), ['tree-unstable'], 'a change in the middle, undone later, still counts');
  assert.deepEqual(kinds({ treeDigests: { before: 'd', afterEach: ['d', 'd'], after: 'e' } }), ['tree-unstable']);
  assert.equal(evaluateFinal({ ...base, treeDigests: { before: 'd', afterEach: ['d', 'e'], after: 'e' } }).stable, false);
});

test('[LOOP-004.AC02] final verification re-runs every criterion and gate on one stable digest and completion then holds only while that digest does', async () => {
  const repo = repoOf(THREE, { finalGates: [PASS_GATE, { ...PASS_GATE, id: 'gate-second' }] });
  try {
    await boot(repo, null);
    const st = await waitTerminal(repo);
    assert.equal(st.status, 'completed'); assert.equal(st.verifiedPercent, 100);
    const rep = JSON.parse(readFileSync(repo.runPath('final-report.json'), 'utf8'));
    assert.equal(rep.requirements.length, 3, 'every registered requirement was re-run in the final phase');
    assert.deepEqual(rep.gates.map((g) => g.id), ['gate-ok', 'gate-second']);
    assert.equal(rep.treeStable, true); assert.equal(rep.treeDigestBefore, rep.treeDigestAfter);
    // each requirement has a final-phase evidence record, and they all name the same stable watch digest basis
    for (const r of THREE) assert.ok(readdirSync(repo.runPath('evidence', r.id)).some((f) => f.endsWith('.json') && JSON.parse(readFileSync(repo.runPath('evidence', r.id, f), 'utf8')).phase === 'final'));
    // a watched file changed after completion: completed no longer holds
    writeFileSync(repo.path('flag-X-201'), 'changed after the final verification');
    const after = buildStatus(repo.root);
    assert.equal(after.status, 'final-stale'); assert.ok(after.verifiedPercent < 100); assert.match(after.statusReason, /completion no longer holds/);
    writeFileSync(repo.path('flag-X-201'), 'ok');
    assert.equal(buildStatus(repo.root).status, 'completed', 'restoring the exact bytes restores the verdict');
    // an unwatched file that is nevertheless part of the tree also changes the digest the final verdict is bound to
    writeFileSync(repo.path('stray.txt'), 'new file in the tree');
    assert.equal(buildStatus(repo.root).status, 'final-stale');
    rmSync(repo.path('stray.txt'));
    // a forged final record is rejected
    const fe = repo.runPath('final-evidence.json');
    const rec = JSON.parse(readFileSync(fe, 'utf8')); rec.treeDigest = 'f'.repeat(64); writeFileSync(fe, JSON.stringify(rec));
    const forged = buildStatus(repo.root);
    assert.equal(forged.final.ok, false); assert.match(forged.final.reasons.join(), /signature is invalid/);
    // unavailable required evidence
    writeFileSync(fe, JSON.stringify({ ...rec, treeDigest: JSON.parse(readFileSync(fe, 'utf8')).treeDigest }));
  } finally { await repo.cleanup(); }
});

test('[LOOP-004.AC02] a gate that changes the tree, a skipped test and an unsupported backend each prevent completed status', async () => {
  // a watched/tree file changed during the final phase
  const mover = repoOf(THREE, { finalGates: [{ ...PASS_GATE, id: 'gate-mutating', args: ['-e', "require('fs').appendFileSync('drift.txt','x')"] }] });
  try {
    await boot(mover, null);
    const st = await waitTerminal(mover);
    assert.notEqual(st.status, 'completed'); assert.equal(st.status, 'blocked'); assert.equal(st.verifiedPercent, 99.9);
    assert.match(st.statusReason, /tree-unstable:tree/);
    const rep = JSON.parse(readFileSync(mover.runPath('final-report.json'), 'utf8'));
    assert.equal(rep.treeStable, false); assert.equal(rep.verdict, 'incomplete');
  } finally { await mover.cleanup(); }
  // a suite that is skipped on its final-phase run (it passes the first two times, then skips)
  const skipSrc = (id) => `import test from 'node:test';
import fs from 'node:fs';
const n = (fs.existsSync('cnt-${id}.txt') ? Number(fs.readFileSync('cnt-${id}.txt', 'utf8')) : 0) + 1;
fs.writeFileSync('cnt-${id}.txt', String(n));
test('[${id}.AC01] flag', { skip: n >= 3 ? 'skipped on a later run' : false }, () => { if (!fs.existsSync('flag-${id}')) throw new Error('missing'); });
`;
  const sk = new MiniRepo([R('CORE-001', 2)], { profile: { limits: long, finalGates: [PASS_GATE], extra: assuranceExtra() }, suiteSources: { 'suite-CORE-001': skipSrc('CORE-001') } });
  appendFileSync(sk.path('.gitignore'), 'cnt-*.txt\n');
  try {
    await boot(sk, null);
    const st = await waitTerminal(sk);
    assert.notEqual(st.status, 'completed'); assert.ok(st.verifiedPercent < 100);
    assert.equal(st.final.ok, false);
    const ev = JSON.parse(readFileSync(sk.runPath('evidence', 'CORE-001', readdirSync(sk.runPath('evidence', 'CORE-001')).filter((f) => f.endsWith('.json')).sort().pop()), 'utf8'));
    assert.match(ev.reason, /skipped/);
  } finally { await sk.cleanup(); }
  // an unsupported required backend
  const unsupported = new MiniRepo([R('CORE-001', 2), { ...R('LOOP-001', 1), requiresTools: ['no-such-backend-xyz'] }], { profile: { limits: long, finalGates: [PASS_GATE], extra: assuranceExtra() }, workerMode: { default: 'fix' } });
  try {
    await boot(unsupported, null);
    const st = await waitTerminal(unsupported);
    assert.notEqual(st.status, 'completed'); assert.ok(st.verifiedPercent < 100);
    assert.equal(st.requirements.find((r) => r.id === 'LOOP-001').state, 'blocked');
    assert.equal(st.requirements.find((r) => r.id === 'LOOP-001').blockers[0].type, 'missing-tool');
    assert.equal(existsSync(unsupported.runPath('final-evidence.json')), false, 'no final verdict was ever issued');
  } finally { await unsupported.cleanup(); }
  // unavailable required evidence after the fact
  const gone = repoOf(THREE);
  try {
    await boot(gone, null);
    assert.equal((await waitTerminal(gone)).status, 'completed');
    rmSync(gone.runPath('evidence', 'LOOP-001'), { recursive: true, force: true });
    const after = buildStatus(gone.root);
    assert.equal(after.status, 'final-stale'); assert.ok(after.verifiedPercent < 100);
  } finally { await gone.cleanup(); }
});

// ================================================================ LOOP-004.AC03

test('[LOOP-004.AC03] the completion report names every unmet criterion, blocker and budget stop, what is implemented, the evidence paths and bounded next commands', async () => {
  const repo = repoOf([R('CORE-001', 2), R('LOOP-001', 1), R('QA-001', 3)], { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'noop' } } });
  try {
    await boot(repo, null);
    const st = await waitQuiet(repo);
    assert.equal(st.status, 'blocked');
    const file = await readReport(repo);
    const cli = JSON.parse((await repo.cli(['report', '--json'])).stdout);
    for (const rep of [file, cli]) {
      assert.equal(rep.verdict, 'incomplete'); assert.match(rep.claim, /^Not complete\./);
      assert.deepEqual(rep.unmetCriteria.map((c) => c.criterion), ['LOOP-001.AC01']);
      assert.equal(rep.unmetCriteria[0].requirement, 'LOOP-001'); assert.ok(rep.unmetCriteria[0].reason);
      assert.ok(rep.blockers.some((b) => b.requirement === 'LOOP-001' && b.type === 'repeated-failure'));
      assert.ok(rep.budgetStops.some((b) => b.kind === 'same-failure-repeats' && b.requirement === 'LOOP-001' && b.limit === 2));
      assert.deepEqual(rep.implemented.map((r) => r.id).sort(), ['CORE-001', 'QA-001']);
      for (const p of Object.values(rep.releaseEvidence.requirementEvidence)) assert.ok(existsSync(p), `evidence path ${p} exists`);
      assert.ok(rep.nextCommands.some((c) => c.command === 'node scripts/loop-engineering/run.mjs resume') && rep.nextCommands.every((c) => c.bound));
      assert.ok(rep.limits.some((l) => /Finite termination/.test(l)));
      assert.doesNotMatch(JSON.stringify(rep.claim), /unattended|guarantee|unconditional/i);
    }
    // the CLI text form carries the same account
    const text = (await repo.cli(['report'])).stdout;
    assert.match(text, /unmet criteria \(1\): LOOP-001\.AC01/); assert.match(text, /budget stop: same-failure-repeats LOOP-001/); assert.match(text, /next: node scripts\/loop-engineering\/run\.mjs resume/);
  } finally { await repo.cleanup(); }
  // a spend stop is named as a budget stop
  const spent = repoOf([R('CORE-001', 2)], { workerMode: { default: 'overspend' } });
  try {
    await boot(spent, null);
    await waitTerminal(spent);
    const rep = await readReport(spent);
    assert.ok(rep.budgetStops.some((b) => b.kind === 'run-budget' && /spend budget exhausted/.test(b.detail)));
    assert.equal(rep.runStatus, 'paused-budget');
  } finally { await spent.cleanup(); }
});

test('[LOOP-004.AC03] the report is resumable after a crash, claims completion only for a verified-complete run and states finite termination', async () => {
  const repo = repoOf(PAIR, { workerMode: { default: 'fix', perReq: { 'LOOP-001': 'silent-hang' } } });
  try {
    await boot(repo, null);
    const st = await repo.waitFor(async () => { const s = await repo.status(); return s.current?.requirement === 'LOOP-001' && s.current.pid ? s : null; }, { label: 'LOOP-001' });
    process.kill(st.controller.pid, 'SIGKILL');
    await repo.waitFor(async () => (await repo.status()).status === 'crashed', { timeoutMs: 25000, label: 'crashed' });
    const crashed = JSON.parse((await repo.cli(['report', '--json'])).stdout);
    assert.equal(crashed.runStatus, 'crashed'); assert.equal(crashed.verdict, 'incomplete');
    assert.deepEqual(crashed.unmetCriteria.map((c) => c.criterion), ['LOOP-001.AC01']);
    assert.equal(crashed.nextCommands[0].command, 'node scripts/loop-engineering/run.mjs resume');
    const exec = await repo.cli(crashed.nextCommands[0].command.split(' ').slice(2)); // the printed command works as printed
    assert.equal(exec.code, 0, exec.stdout + exec.stderr);
    repo.setMode({ default: 'fix' });
    await repo.waitFor(async () => (await repo.status()).status === 'completed', { timeoutMs: 90000, label: 'completed' });
    await repo.waitFor(async () => { const l = JSON.parse(readFileSync(layout(repo.root, repo.runId()).leaseFile, 'utf8')); return l.exited === true && existsSync(repo.runPath('completion-report.json')); }, { timeoutMs: 20000, label: 'report written' });
    const done = await readReport(repo);
    assert.equal(done.verdict, 'verified-complete'); assert.deepEqual(done.unmetCriteria, []); assert.deepEqual(done.unmetRequirements, []);
    assert.match(done.claim, /finite budgets of the profile.*not a promise/s);
    assert.equal(done.final.ok, true); assert.ok(done.releaseEvidence.finalEvidence.endsWith('final-evidence.json') && existsSync(done.releaseEvidence.finalEvidence));
    assert.ok(done.limits.some((l) => /never described as unconditionally unattended/.test(l)));
  } finally { await repo.cleanup(); }
  // every cap-type stop is named, with its limit
  const capped = buildCompletionReport({ runId: 'r', status: 'blocked', verifiedPercent: 10, requirements: [
    { id: 'A', title: 'a', state: 'blocked', weight: 1, attempts: 3, unmetCriteria: ['A.AC01'], blockers: [{ type: 'attempts-exhausted', detail: '3 attempts used' }], evidence: null },
    { id: 'B', title: 'b', state: 'blocked', weight: 1, attempts: 2, unmetCriteria: ['B.AC01'], blockers: [{ type: 'repeated-failure', detail: 'same twice' }], evidence: null }],
    final: { required: true, ok: false }, limits: { attemptsPerRequirement: 3, sameFailureRepeats: 2 }, budgets: {} });
  assert.deepEqual(capped.budgetStops.map((b) => [b.kind, b.requirement, b.limit]), [['attempts-per-requirement', 'A', 3], ['same-failure-repeats', 'B', 2]]);
  assert.deepEqual(capped.unmetCriteria.map((c) => c.criterion), ['A.AC01', 'B.AC01']);
  // direct unit: a run recorded complete whose final no longer holds is not reported verified-complete
  const fake = buildCompletionReport({ runId: 'r', status: 'completed', verifiedPercent: 99.9, requirements: [], final: { required: true, ok: false, reasons: ['x'] }, limits: {}, budgets: {} });
  assert.equal(fake.verdict, 'incomplete');
});
