// Supervised, resource-bounded analyzer execution (E6-05).
//
// A worker thread (analyzer-supervisor.js) can be terminated on a deadline, but it shares the process: it cannot be given a memory ceiling that
// does not take the scanner down with it, it cannot be CPU-limited, and anything it spawns outlives it. An analyzer that is expensive or runs
// code of uncertain behaviour belongs in its OWN PROCESS, and this module runs it there:
//
//   * own process GROUP (detached), so a kill takes the analyzer and everything it forked; a test proves a forked grandchild dies too
//   * wall-clock deadline, a resident-memory ceiling polled from outside (`maxRssMb`), a V8 heap ceiling (`maxHeapMb`, which turns exhaustion into an
//     abort the supervisor classifies as `oom`), and an optional CPU-seconds ceiling (`cpuSeconds`, POSIX `ulimit -t`)
//   * cancellation through an AbortSignal; a hard overall stop (`maxTotalMs`) so the run can never wait indefinitely
//   * a BOUNDED queue: at most `concurrency` run at once, at most `maxQueue` wait, the rest are `rejected: queue_full`, never dropped silently
//   * every task ends in exactly one terminal status. A failure is a result, not an exception: the other analyzers' results are kept
//
// `summarizeSupervised` turns the results into what the rest of the pipeline already understands: merged findings from the analyzers that
// completed, an `analyzerCoverage`-shaped object for computeScanHealth (so scan health degrades to `partial` and a strict assurance mode fails), and
// the exact list of analyzers that did not finish and why.
import { spawn } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CHILD = path.join(HERE, 'supervised-child.js');
export const TERMINAL_STATUSES = Object.freeze(['completed', 'failed', 'timed_out', 'oom', 'rss_limit', 'cpu_limit', 'cancelled', 'rejected', 'overall_deadline']);
const DEFAULTS = Object.freeze({ concurrency: 2, maxQueue: 64, timeoutMs: 60_000, maxHeapMb: 1024, maxRssMb: 2048, cpuSeconds: 0, maxResultBytes: 8 * 1024 * 1024, maxTotalMs: 30 * 60_000, rssPollMs: 200 });

const killGroup = (pid) => { try { process.kill(-pid, 'SIGKILL'); } catch { try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ } } };
const rssMb = (pid) => { try { return parseInt(execFileSync('ps', ['-o', 'rss=', '-p', String(pid)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000 }).trim(), 10) / 1024; } catch { return 0; } };

function runOne(task, o, state) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const lim = { timeoutMs: task.timeoutMs ?? o.timeoutMs, maxHeapMb: task.maxHeapMb ?? o.maxHeapMb, maxRssMb: task.maxRssMb ?? o.maxRssMb, cpuSeconds: task.cpuSeconds ?? o.cpuSeconds };
    // limits become command-line text, so each must be a plain positive number before it goes anywhere near a command line
    for (const [k, v] of Object.entries(lim)) {
      if (!(typeof v === 'number' && Number.isFinite(v) && v >= 0)) return resolve({ id: task.id, status: 'failed', ok: false, error: `invalid limit ${k}: must be a non-negative number`, durationMs: 0 });
    }
    const node = [`--max-old-space-size=${Math.ceil(lim.maxHeapMb)}`, CHILD];
    const posix = process.platform !== 'win32';
    // the CPU ceiling is applied with `ulimit` in a shell that then `exec`s node. The values are passed as positional parameters and quoted by the
    // shell itself, so nothing from the task is ever parsed as shell syntax
    const [cmd, args] = posix && lim.cpuSeconds > 0 ? ['/bin/sh', ['-c', 'ulimit -t "$1"; shift; exec "$@"', 'sh', String(Math.ceil(lim.cpuSeconds)), process.execPath, ...node]] : [process.execPath, node];
    const child = spawn(cmd, args, { detached: posix, stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: { ...process.env, AGENTIC_SECURITY_SUPERVISED_SPEC: JSON.stringify({ modulePath: task.modulePath, exportName: task.exportName, args: task.args || [] }) } });
    const pid = child.pid; state.pids.add(pid);
    let status = null; let msg = null; let stderr = ''; let settled = false;
    const done = (s, extra = {}) => {
      if (settled) return; settled = true;
      clearTimeout(timer); clearInterval(poll); state.kills.delete(kill);
      killGroup(pid); state.pids.delete(pid);
      resolve({ id: task.id, status: s, ok: s === 'completed', durationMs: Date.now() - t0, pid, ...extra });
    };
    const kill = (why) => { if (!status) status = why; killGroup(pid); };
    state.kills.add(kill);
    const timer = setTimeout(() => kill('timed_out'), lim.timeoutMs);
    const poll = setInterval(() => { if (!status && lim.maxRssMb > 0 && rssMb(pid) > lim.maxRssMb) kill('rss_limit'); }, o.rssPollMs);
    child.stderr.on('data', (d) => { if (stderr.length < 4000) stderr += d.toString(); });
    child.on('message', (m) => { msg = m; });
    child.on('error', (e) => done('failed', { error: `could not start: ${e.message}` }));
    child.on('close', (code, signal) => {
      if (status) return done(status, { error: status === 'timed_out' ? `exceeded ${lim.timeoutMs} ms` : status === 'rss_limit' ? `exceeded ${lim.maxRssMb} MB resident` : status, exitCode: code, signal });
      if (msg && msg.ok) {
        const bytes = Buffer.byteLength(JSON.stringify(msg.result ?? null));
        return bytes > o.maxResultBytes ? done('failed', { error: `result of ${bytes} bytes exceeds the ${o.maxResultBytes} byte cap`, exitCode: code, signal }) : done('completed', { result: msg.result, exitCode: code, signal });
      }
      if (msg && !msg.ok) return done('failed', { error: msg.error, exitCode: code, signal });
      if (/heap out of memory|allocation failed|ERR_WORKER_OUT_OF_MEMORY/i.test(stderr) || signal === 'SIGABRT' || code === 134) return done('oom', { error: 'ran out of memory', exitCode: code, signal });
      if (signal === 'SIGXCPU' || (lim.cpuSeconds > 0 && (code === 152 || signal === 'SIGKILL'))) return done('cpu_limit', { error: `exceeded ${lim.cpuSeconds} CPU seconds`, exitCode: code, signal });
      return done('failed', { error: `exited without a result (code ${code}, signal ${signal})${stderr ? `: ${stderr.trim().slice(0, 300)}` : ''}`, exitCode: code, signal });
    });
  });
}

/**
 * @param {{id:string, modulePath:string, exportName:string, args?:any[], timeoutMs?:number, maxHeapMb?:number, maxRssMb?:number, cpuSeconds?:number}[]} tasks
 * @param {{concurrency?, maxQueue?, timeoutMs?, maxHeapMb?, maxRssMb?, cpuSeconds?, maxResultBytes?, maxTotalMs?, signal?:AbortSignal}} opts
 * @returns {Promise<object[]>} one result per task, in task order, each with exactly one terminal status
 */
export async function runSupervised(tasks, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const state = { pids: new Set(), kills: new Set() };
  const results = new Array(tasks.length);
  const queue = []; let running = 0; let stopped = null;
  const stop = (why) => { if (stopped) return; stopped = why; for (const k of [...state.kills]) k(why); };
  const onAbort = () => stop('cancelled');
  if (o.signal) { if (o.signal.aborted) stopped = 'cancelled'; else o.signal.addEventListener('abort', onAbort, { once: true }); }
  const overall = setTimeout(() => stop('overall_deadline'), o.maxTotalMs);
  tasks.forEach((t, i) => {
    if (queue.length >= o.maxQueue + o.concurrency) results[i] = { id: t.id, status: 'rejected', ok: false, error: `queue_full: more than ${o.maxQueue} waiting`, durationMs: 0 };
    else queue.push(i);
  });
  await new Promise((resolve) => {
    const pump = () => {
      while (running < o.concurrency && queue.length) {
        const i = queue.shift();
        if (stopped) { results[i] = { id: tasks[i].id, status: stopped, ok: false, error: `not started: ${stopped}`, durationMs: 0 }; continue; }
        running++;
        runOne(tasks[i], o, state).then((r) => { results[i] = r; }, (e) => { results[i] = { id: tasks[i].id, status: 'failed', ok: false, error: String(e && e.message || e), durationMs: 0 }; }).finally(() => { running--; pump(); });
      }
      if (!running && !queue.length) resolve();
    };
    pump();
  });
  clearTimeout(overall); if (o.signal) o.signal.removeEventListener('abort', onAbort);
  // a task killed by the overall stop or a cancel reports that, not 'failed'
  return results.map((r) => (stopped && !r.ok && ['timed_out', 'failed'].includes(r.status) && r.error === stopped ? { ...r, status: stopped } : r));
}

/**
 * What the rest of the pipeline needs from a supervised run.
 * @returns {{findings:object[], completed:string[], incomplete:{id:string,status:string,error:string}[], analyzerCoverage:object, conditions:string[]}}
 */
export function summarizeSupervised(results) {
  const findings = []; const completed = []; const incomplete = [];
  for (const r of results) {
    if (r.status === 'completed') { completed.push(r.id); if (Array.isArray(r.result)) findings.push(...r.result); else if (r.result && Array.isArray(r.result.findings)) findings.push(...r.result.findings); }
    else incomplete.push({ id: r.id, status: r.status, error: r.error || r.status });
  }
  const n = (s) => incomplete.filter((x) => x.status === s).length;
  const analyzerCoverage = { analyzers: results.length, completed: completed.length, failed: incomplete.length, timedOut: n('timed_out') + n('overall_deadline'), outOfMemory: n('oom') + n('rss_limit'), cancelled: n('cancelled'), rejected: n('rejected'), skippedByPolicy: 0 };
  const conditions = incomplete.map((x) => `analyzer ${x.id} did not finish (${x.status}): ${x.error}`);
  return { findings, completed, incomplete, analyzerCoverage, conditions };
}

/** Is a process still alive? (test and diagnostics helper for "no orphan") */
export function pidAlive(pid) { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } }
