// E6-05: injected infinite loop and OOM terminate; partial successes are retained; no orphan process, indefinite wait or hidden crash; scan health degrades and strict assurance fails.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TERMINAL_STATUSES, pidAlive, runSupervised, summarizeSupervised } from '../../src/pipeline/supervised-analyzers.js';
import { computeScanHealth } from '../../src/pipeline/scan-health.js';
import { evaluateAssuranceMode } from '../../src/pipeline/assurance-mode.js';

const MOD = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'supervised-tasks.js');
const task = (id, exportName, args = [], over = {}) => ({ id, modulePath: MOD, exportName, args, ...over });
const byId = (rs) => Object.fromEntries(rs.map((r) => [r.id, r]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('a well-behaved analyzer completes with its result; every task ends in exactly one allowed terminal status', async () => {
  const rs = await runSupervised([task('a', 'good', ['a']), task('b', 'slowGood', [50, 'b'])], { timeoutMs: 20_000 });
  assert.deepEqual(rs.map((r) => r.status), ['completed', 'completed']); assert.equal(rs[0].result[0].id, 'f-a'); assert.equal(rs[1].result[0].id, 'f-b');
  for (const r of rs) { assert.ok(TERMINAL_STATUSES.includes(r.status)); assert.equal(r.ok, true); assert.ok(r.durationMs >= 0); }
  assert.deepEqual(await runSupervised([]), []);
});

test('INFINITE LOOP: terminated at the deadline, within a bounded time, as timed_out', async () => {
  const t0 = Date.now();
  const [r] = await runSupervised([task('loop', 'infiniteLoop')], { timeoutMs: 800 });
  assert.equal(r.status, 'timed_out'); assert.equal(r.ok, false); assert.match(r.error, /exceeded 800 ms/);
  assert.ok(Date.now() - t0 < 8000, `took ${Date.now() - t0} ms`);
  assert.equal(pidAlive(r.pid), false, 'the child is gone');
});

test('OOM: a memory hog is terminated and classified, not left to take the scanner down', async () => {
  const [r] = await runSupervised([task('hog', 'memoryHog', [], { maxHeapMb: 48, maxRssMb: 1500 })], { timeoutMs: 60_000 });
  assert.ok(['oom', 'rss_limit'].includes(r.status), r.status + ' ' + r.error); assert.equal(r.ok, false); assert.equal(pidAlive(r.pid), false);
});

test('RSS ceiling: the supervisor kills a process that exceeds the resident limit', async () => {
  const [r] = await runSupervised([task('hog', 'memoryHog', [], { maxHeapMb: 4096, maxRssMb: 150 })], { timeoutMs: 60_000, rssPollMs: 50 });
  assert.ok(['rss_limit', 'oom'].includes(r.status), r.status); assert.equal(pidAlive(r.pid), false);
});

test('PARTIAL SUCCESS: one analyzer hangs, one throws, one exits hard, one oversize; the good ones keep their findings and the failures are named', async () => {
  const rs = await runSupervised([task('ok1', 'good', ['one']), task('hang', 'infiniteLoop'), task('boom', 'throws'), task('ok2', 'good', ['two']), task('exit', 'hardExit'), task('big', 'bigResult')], { timeoutMs: 1500, concurrency: 3, maxResultBytes: 1024 * 1024 });
  const m = byId(rs);
  assert.equal(m.ok1.status, 'completed'); assert.equal(m.ok2.status, 'completed');
  assert.equal(m.hang.status, 'timed_out'); assert.equal(m.boom.status, 'failed'); assert.match(m.boom.error, /analyzer exploded/);
  assert.equal(m.exit.status, 'failed'); assert.match(m.exit.error, /exited without a result \(code 7/);
  assert.equal(m.big.status, 'failed'); assert.match(m.big.error, /exceeds the 1048576 byte cap/);
  const s = summarizeSupervised(rs);
  assert.deepEqual(s.findings.map((f) => f.id).sort(), ['f-one', 'f-two']); assert.deepEqual(s.completed.sort(), ['ok1', 'ok2']);
  assert.deepEqual(s.incomplete.map((x) => x.id).sort(), ['big', 'boom', 'exit', 'hang']);
  assert.equal(s.analyzerCoverage.failed, 4); assert.equal(s.analyzerCoverage.timedOut, 1); assert.equal(s.analyzerCoverage.completed, 2);
  assert.ok(s.conditions.every((c) => /did not finish/.test(c)));
});

test('SCAN HEALTH and ASSURANCE: the same partial run is `partial` and passes in standard mode, and FAILS in strict mode', async () => {
  const rs = await runSupervised([task('ok', 'good', ['one']), task('hang', 'infiniteLoop')], { timeoutMs: 800 });
  const s = summarizeSupervised(rs);
  const health = computeScanHealth({ analyzerCoverage: s.analyzerCoverage });
  assert.equal(health.status, 'partial'); assert.ok(health.conditions.length >= 1);
  const strict = evaluateAssuranceMode('strict', health, []);
  const standard = evaluateAssuranceMode('standard', health, []);
  assert.equal(strict.ok, false); assert.match(strict.reason, /1 analyzer\(s\) failed, 1 analyzer\(s\) timed out/);
  assert.equal(standard.ok, true);
  const clean = summarizeSupervised(await runSupervised([task('ok', 'good', ['one'])], { timeoutMs: 20_000 }));
  assert.equal(computeScanHealth({ analyzerCoverage: clean.analyzerCoverage }).status, 'complete');
  assert.equal(evaluateAssuranceMode('strict', computeScanHealth({ analyzerCoverage: clean.analyzerCoverage }), []).ok, true, 'a clean supervised run passes strict: the failure above is the analyzer, not the mode');
});

test('NO ORPHANS: a forked grandchild dies with its analyzer (process-group kill)', async () => {
  const pidFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e6-05-')), 'gc.pid');
  try {
    const [r] = await runSupervised([task('fork', 'forkThenHang', [pidFile])], { timeoutMs: 1500 });
    assert.equal(r.status, 'timed_out');
    const gc = Number(fs.readFileSync(pidFile, 'utf8'));
    assert.ok(gc > 1, 'the grandchild existed');
    await sleep(300);
    assert.equal(pidAlive(gc), false, 'the grandchild was killed with the group'); assert.equal(pidAlive(r.pid), false);
  } finally { fs.rmSync(path.dirname(pidFile), { recursive: true, force: true }); }
});

test('CANCELLATION: aborting stops the running analyzers and marks the queued ones cancelled; the call returns promptly', async () => {
  const ac = new AbortController();
  const p = runSupervised([task('a', 'infiniteLoop'), task('b', 'infiniteLoop'), task('c', 'good', ['c']), task('d', 'good', ['d'])], { timeoutMs: 60_000, concurrency: 2, signal: ac.signal });
  await sleep(800); const t0 = Date.now(); ac.abort();
  const rs = await p;
  assert.ok(Date.now() - t0 < 5000);
  assert.deepEqual(rs.map((r) => r.status), ['cancelled', 'cancelled', 'cancelled', 'cancelled']);
  for (const r of rs.slice(0, 2)) assert.equal(pidAlive(r.pid), false);
  const pre = new AbortController(); pre.abort();
  assert.deepEqual((await runSupervised([task('x', 'good', ['x'])], { signal: pre.signal })).map((r) => r.status), ['cancelled']);
});

test('BOUNDED QUEUE: concurrency is respected and tasks past the queue are rejected with a reason, not dropped', async () => {
  const tasks = Array.from({ length: 6 }, (_, i) => task(`t${i}`, 'slowGood', [300, `t${i}`]));
  const t0 = Date.now();
  const rs = await runSupervised(tasks, { concurrency: 2, maxQueue: 1, timeoutMs: 20_000 });
  assert.equal(rs.length, 6);
  const done = rs.filter((r) => r.status === 'completed'); const rej = rs.filter((r) => r.status === 'rejected');
  assert.equal(done.length, 3, 'two running plus one queued'); assert.equal(rej.length, 3);
  assert.ok(rej.every((r) => /queue_full/.test(r.error)));
  assert.ok(Date.now() - t0 >= 0);
  const s = summarizeSupervised(rs); assert.equal(s.analyzerCoverage.rejected, 3); assert.equal(s.analyzerCoverage.failed, 3);
});

test('OVERALL DEADLINE: the run cannot wait indefinitely even if every task has a long timeout', async () => {
  const t0 = Date.now();
  const rs = await runSupervised([task('a', 'infiniteLoop'), task('b', 'infiniteLoop')], { timeoutMs: 600_000, maxTotalMs: 1000 });
  assert.ok(Date.now() - t0 < 10_000);
  assert.deepEqual(rs.map((r) => r.status), ['overall_deadline', 'overall_deadline']);
  for (const r of rs) assert.equal(pidAlive(r.pid), false);
});

test('a missing module or export is a failed result with the reason, never a crash of the supervisor', async () => {
  const rs = await runSupervised([{ id: 'nomod', modulePath: '/nonexistent/x.js', exportName: 'f' }, task('noexp', 'doesNotExist')], { timeoutMs: 20_000 });
  assert.deepEqual(rs.map((r) => r.status), ['failed', 'failed']); assert.match(rs[1].error, /is not an exported function/);
});

test('LIMITS ARE NUMBERS: a limit that is shell syntax or not a number is refused before anything starts, and nothing is executed', async () => {
  const sent = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e6-05-inj-')), 'PWNED');
  try {
    const rs = await runSupervised([
      task('heap', 'good', ['a'], { maxHeapMb: `64; touch ${sent}` }), task('cpu', 'good', ['b'], { cpuSeconds: `1; touch ${sent}` }),
      task('rss', 'good', ['c'], { maxRssMb: 'lots' }), task('neg', 'good', ['d'], { timeoutMs: -5 }), task('ok', 'good', ['e'], { cpuSeconds: 30 }),
    ], { timeoutMs: 20_000 });
    assert.deepEqual(rs.map((r) => r.status), ['failed', 'failed', 'failed', 'failed', 'completed']);
    assert.match(rs[0].error, /invalid limit maxHeapMb/); assert.match(rs[1].error, /invalid limit cpuSeconds/);
    assert.equal(fs.existsSync(sent), false, 'no command was run');
    assert.equal(rs[4].result[0].id, 'f-e', 'a numeric CPU ceiling still works through the same path');
  } finally { fs.rmSync(path.dirname(sent), { recursive: true, force: true }); }
});

test('CPU ceiling (POSIX): a busy analyzer is stopped by its CPU-seconds limit before the wall deadline', { skip: process.platform === 'win32' }, async () => {
  const t0 = Date.now();
  const [r] = await runSupervised([task('cpu', 'busyCpu', [], { cpuSeconds: 1 })], { timeoutMs: 30_000 });
  assert.ok(['cpu_limit', 'timed_out'].includes(r.status), r.status);
  assert.equal(r.status, 'cpu_limit', `expected the CPU limit to fire, got ${r.status} after ${Date.now() - t0} ms`);
  assert.ok(Date.now() - t0 < 15_000); assert.equal(pidAlive(r.pid), false);
});
