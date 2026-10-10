// Bounded subprocess supervisor (LOOP-002). Every child gets: a wall-clock
// deadline, an optional output-idle deadline, drained stdout+stderr with byte
// caps, stdin closed, its own process group, descendant tracking that survives
// reparenting, TERM->KILL escalation, and a guaranteed orphan sweep.
import { spawn } from 'node:child_process';
import { createWriteStream, mkdirSync } from 'node:fs';
import { StringDecoder } from 'node:string_decoder';
import { dirname } from 'node:path';
import { Deadline, randomId, sleep, tail, nowIso, redact } from './util.mjs';
import { listProcesses, descendantsOf, identityMatches, signalIdentity, scanEnvMarker, isAlive, startTimeOf } from './procscan.mjs';

export const JOB_ENV = 'LOOP_ENGINEERING_JOB';

export const DEFAULTS = Object.freeze({
  wallMs: 120_000,
  idleMs: 0,            // 0 = idle detection off
  graceMs: 10_000,      // TERM -> KILL
  maxLogBytes: 5 * 1024 * 1024,
  maxTotalBytes: 256 * 1024 * 1024, // resource ceiling on total output
  maxRssBytes: 0,       // 0 = unlimited
  tailBytes: 64 * 1024,
  maxLineBytes: 256 * 1024,
  trackIntervalMs: 400,
});

// An outer `node --test` run exports NODE_TEST_CONTEXT; a child `node` that
// inherits it behaves as a test-runner subprocess and misreports itself. The
// supervisor always hands children a clean runtime environment.
export function cleanEnv(env) {
  const e = { ...env };
  delete e.NODE_TEST_CONTEXT;
  return e;
}

class LineSplitter {
  constructor(max, onLine) { this.max = max; this.onLine = onLine; this.buf = []; this.len = 0; this.dropping = false; this.truncated = 0; }
  push(chunk) {
    let start = 0;
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] !== 10) continue;
      this._take(chunk.subarray(start, i));
      this._emit();
      start = i + 1;
    }
    if (start < chunk.length) this._take(chunk.subarray(start));
  }
  _take(part) {
    if (this.dropping) return;
    if (this.len + part.length > this.max) {
      const room = Math.max(0, this.max - this.len);
      if (room) { this.buf.push(part.subarray(0, room)); this.len += room; }
      this.dropping = true; this.truncated++;
      return;
    }
    this.buf.push(part); this.len += part.length;
  }
  _emit() {
    const line = Buffer.concat(this.buf).toString('utf8');
    const wasTruncated = this.dropping;
    this.buf = []; this.len = 0; this.dropping = false;
    this.onLine(line, wasTruncated);
  }
  flush() { if (this.len || this.dropping) this._emit(); }
}

// Registry of processes this controller is responsible for. Persisted by the
// caller (state layer) through onChange so a guardian can reap after a crash.
export class OwnedSet {
  constructor(onChange) { this.map = new Map(); this.onChange = onChange; }
  add(e) { this.map.set(`${e.pid}`, e); this._chg(); }
  remove(pid) { this.map.delete(`${pid}`); this._chg(); }
  list() { return [...this.map.values()]; }
  _chg() { if (this.onChange) { try { this.onChange(this.list()); } catch { /* best effort */ } } }
}

async function killTree(job, graceMs) {
  const killed = [];
  const targets = () => [...job.owned.values()];
  const sendAll = (sig) => {
    // Process group first (catches anything not yet tracked), then each
    // identity-verified tracked process.
    if (job.pgid) { try { process.kill(-job.pgid, sig); } catch { /* group gone */ } }
    for (const t of targets()) if (signalIdentity(t, sig)) killed.push(t.pid);
    for (const h of scanEnvMarker(JOB_ENV, job.marker, [process.pid])) {
      if (signalIdentity(h, sig)) killed.push(h.pid);
    }
  };
  sendAll('SIGTERM');
  const end = Date.now() + graceMs;
  while (Date.now() < end) {
    await sleep(50);
    if (!targets().some((t) => identityMatches(t.pid, t.start))) {
      // Group may still hold members that were never tracked.
      let groupAlive = false;
      if (job.pgid) { try { process.kill(-job.pgid, 0); groupAlive = true; } catch { groupAlive = false; } }
      if (!groupAlive) break;
    }
  }
  sendAll('SIGKILL');
  await sleep(30);
  return [...new Set(killed)];
}

/**
 * Run argv under supervision. Never rejects; always resolves with a typed result.
 * outcome: exited | signaled | timeout-wall | timeout-idle | resource-limit |
 *          spawn-failed | cancelled
 */
export async function runBounded(opts) {
  const o = { ...DEFAULTS, ...opts };
  if (!Array.isArray(o.argv) || !o.argv.length) throw new TypeError('argv must be a non-empty array (no shell strings)');
  const jobId = o.jobId || randomId(4);
  const marker = `${o.runId || 'adhoc'}:${jobId}`;
  const startedAt = nowIso();
  const wall = new Deadline(o.wallMs);
  const result = {
    jobId, label: o.label || o.argv[0], argv: o.argv, cwd: o.cwd || process.cwd(), startedAt, endedAt: null,
    outcome: null, exitCode: null, signal: null, pid: null, durationMs: 0,
    stdoutTail: '', stderrTail: '', bytes: { stdout: 0, stderr: 0 }, logTruncated: false, linesTruncated: 0,
    orphansKilled: [], descendantsSeen: 0, peakRssKb: 0, reason: null, suspectedOom: false,
  };

  let logStream = null;
  if (o.logPath) {
    mkdirSync(dirname(o.logPath), { recursive: true });
    logStream = createWriteStream(o.logPath, { flags: 'a', mode: 0o600 });
    logStream.on('error', () => { /* never let logging kill the supervisor */ });
  }
  let logged = 0;
  // With redactLog, the on-disk log is written line by line through the redactor, so a secret a child prints is never persisted.
  const decoders = { '': new StringDecoder('utf8'), err: new StringDecoder('utf8') };
  const pending = { '': '', err: '' };
  const emitRedacted = (tag, text) => rawWriteLog(tag, Buffer.from(redact(text), 'utf8'));
  const writeLog = (tag, chunk) => {
    if (!o.redactLog) return rawWriteLog(tag, chunk);
    if (logged >= o.maxLogBytes) { result.logTruncated = true; return; }
    pending[tag] += decoders[tag].write(chunk);
    let nl;
    while ((nl = pending[tag].indexOf('\n')) >= 0) { emitRedacted(tag, pending[tag].slice(0, nl + 1)); pending[tag] = pending[tag].slice(nl + 1); }
    if (pending[tag].length > 65536) { emitRedacted(tag, pending[tag]); pending[tag] = ''; }
  };
  const flushRedacted = () => { for (const tag of Object.keys(pending)) { const rest = pending[tag] + decoders[tag].end(); pending[tag] = ''; if (rest) emitRedacted(tag, rest); } };
  const rawWriteLog = (tag, chunk) => {
    if (!logStream) return;
    if (logged >= o.maxLogBytes) { result.logTruncated = true; return; }
    const room = o.maxLogBytes - logged;
    const slice = chunk.length > room ? chunk.subarray(0, room) : chunk;
    if (slice.length < chunk.length) result.logTruncated = true;
    logged += slice.length;
    logStream.write(tag ? Buffer.concat([Buffer.from(`[${tag}] `), slice]) : slice);
  };

  let child;
  try {
    child = spawn(o.argv[0], o.argv.slice(1), {
      cwd: o.cwd,
      env: cleanEnv({ ...(o.env || process.env), [JOB_ENV]: marker }),
      detached: true,           // own session + process group: the unit we can signal
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (e) {
    result.outcome = 'spawn-failed'; result.reason = String(e.message || e);
    result.endedAt = nowIso();
    return result;
  }

  const job = { pgid: child.pid, owned: new Map(), marker };
  result.pid = child.pid;
  const rootStart = startTimeOf(child.pid);
  if (rootStart) job.owned.set(child.pid, { pid: child.pid, start: rootStart, pgid: child.pid, role: 'root' });
  if (o.owned && rootStart) o.owned.add({ pid: child.pid, start: rootStart, pgid: child.pid, role: o.label || 'job', marker, runId: o.runId });
  if (o.onSpawn) { try { o.onSpawn({ pid: child.pid, start: rootStart, marker }); } catch { /* observer only */ } }

  let lastActivityMono = performance.now();
  let lastActivityWall = Date.now();
  const touch = () => { lastActivityMono = performance.now(); lastActivityWall = Date.now(); };
  let stdoutTail = Buffer.alloc(0), stderrTail = Buffer.alloc(0);
  const addTail = (cur, chunk) => {
    const next = Buffer.concat([cur, chunk]);
    return next.length > o.tailBytes ? next.subarray(next.length - o.tailBytes) : next;
  };
  const splitter = o.onLine ? new LineSplitter(o.maxLineBytes, (l, t) => o.onLine(l, t)) : null;

  let endedByUs = null;     // outcome we imposed
  let exited = false;
  let totalBytes = 0;
  const onData = (which) => (chunk) => {
    touch();
    totalBytes += chunk.length;
    result.bytes[which] += chunk.length;
    if (which === 'stdout') { stdoutTail = addTail(stdoutTail, chunk); if (splitter) splitter.push(chunk); }
    else stderrTail = addTail(stderrTail, chunk);
    writeLog(which === 'stderr' ? 'err' : '', chunk);
    if (o.onData) { try { o.onData(which, chunk); } catch { /* observer only */ } }
    if (totalBytes > o.maxTotalBytes && !endedByUs) { endedByUs = 'resource-limit'; result.reason = `output exceeded ${o.maxTotalBytes} bytes`; }
  };
  // Always keep consuming, even after limits, so a chatty child can never
  // block on a full pipe.
  child.stdout.on('data', onData('stdout'));
  child.stderr.on('data', onData('stderr'));
  child.stdout.on('error', () => {});
  child.stderr.on('error', () => {});
  child.stdin.on('error', () => {});
  try {
    if (o.stdin != null) child.stdin.end(o.stdin); else child.stdin.end();
  } catch { /* child already gone */ }

  let spawnError = null;
  child.once('error', (e) => { spawnError = e; });
  const exitPromise = new Promise((resolve) => {
    child.once('exit', (code, signal) => { exited = true; result.exitCode = code; result.signal = signal; resolve(); });
    child.once('error', () => resolve());
  });

  // Tracker + deadline watchdog in one timer so enforcement never depends on
  // the child's own behaviour.
  let tracking = false;
  const tick = async () => {
    if (tracking) return;
    tracking = true;
    try {
      if (!endedByUs) {
        if (o.signal?.aborted) endedByUs = 'cancelled';
        else if (wall.expired()) { endedByUs = 'timeout-wall'; result.reason = `wall deadline ${o.wallMs}ms exceeded`; }
        else if (o.idleMs > 0) {
          const idle = Math.max(performance.now() - lastActivityMono, Date.now() - lastActivityWall);
          const exempt = o.idleExempt ? !!o.idleExempt() : false;
          if (idle >= o.idleMs && !exempt) { endedByUs = 'timeout-idle'; result.reason = `no output for ${Math.round(idle)}ms with no registered bounded operation`; }
        }
      }
      if (!exited || job.owned.size > 1) {
        const rows = listProcesses();
        const kids = descendantsOf(child.pid, rows);
        for (const k of kids) {
          if (!job.owned.has(k.pid)) {
            const e = { pid: k.pid, start: k.start, pgid: k.pgid, role: 'descendant' };
            job.owned.set(k.pid, e);
            if (o.owned) o.owned.add({ ...e, marker, runId: o.runId });
          }
        }
        result.descendantsSeen = Math.max(result.descendantsSeen, job.owned.size - 1);
        const rows2 = new Map(rows.map((r) => [r.pid, r]));
        let rss = 0;
        for (const t of job.owned.values()) { const r = rows2.get(t.pid); if (r && r.start === t.start) rss += r.rssKb; }
        result.peakRssKb = Math.max(result.peakRssKb, rss);
        if (o.maxRssBytes && rss * 1024 > o.maxRssBytes && !endedByUs) {
          endedByUs = 'resource-limit'; result.reason = `process tree RSS ${Math.round(rss / 1024)}MiB exceeded ${Math.round(o.maxRssBytes / 1048576)}MiB`;
        }
      }
    } finally { tracking = false; }
  };
  const timer = setInterval(() => { tick().catch(() => {}); }, o.trackIntervalMs);
  await tick();

  // Wait for the root to exit, or for us to impose an ending.
  while (!exited && !spawnError) {
    if (endedByUs) break;
    await Promise.race([exitPromise, sleep(Math.min(100, o.trackIntervalMs))]);
  }

  if (spawnError && !exited) {
    clearInterval(timer);
    result.outcome = 'spawn-failed'; result.reason = String(spawnError.message || spawnError);
    result.endedAt = nowIso();
    if (logStream) logStream.end();
    return result;
  }

  if (endedByUs) {
    result.outcome = endedByUs;
    const killed = await killTree(job, o.graceMs);
    result.orphansKilled.push(...killed.filter((p) => p !== child.pid));
    await Promise.race([exitPromise, sleep(1000)]);
  } else {
    // Root exited on its own. Anything still running under it is an orphan:
    // a clean exit does not license leaving descendants behind.
    await tick();
    const stragglers = [...job.owned.values()].filter((t) => t.pid !== child.pid && identityMatches(t.pid, t.start));
    const marked = scanEnvMarker(JOB_ENV, marker, [process.pid]);
    if (stragglers.length || marked.length) {
      const killed = await killTree(job, Math.min(o.graceMs, 2000));
      result.orphansKilled.push(...killed.filter((p) => p !== child.pid));
    }
    if (result.signal) {
      result.outcome = 'signaled';
      result.suspectedOom = result.signal === 'SIGKILL';
    } else result.outcome = 'exited';
  }
  clearInterval(timer);
  // Give pipes a moment to drain, then release them; a detached grandchild
  // holding the pipe must not hold us.
  await sleep(40);
  child.stdout.destroy(); child.stderr.destroy();
  if (splitter) splitter.flush();
  result.linesTruncated = splitter ? splitter.truncated : 0;
  result.stdoutTail = stdoutTail.toString('utf8');
  result.stderrTail = stderrTail.toString('utf8');
  result.endedAt = nowIso();
  result.durationMs = Math.round(Math.max(wall.elapsed(), 0));
  if (o.owned) for (const t of job.owned.values()) o.owned.remove(t.pid);
  if (o.redactLog) flushRedacted();
  if (logStream) await new Promise((r) => logStream.end(r));
  return result;
}

// Reap everything a dead controller left behind. Returns pids signalled.
export async function reapOwned(entries, runId, graceMs = 2000) {
  const killed = [];
  const live = () => entries.filter((e) => identityMatches(e.pid, e.start));
  const markers = new Set(entries.map((e) => e.marker).filter(Boolean));
  const sweep = (sig) => {
    for (const e of live()) { if (e.pgid) { try { process.kill(-e.pgid, sig); } catch { /* gone */ } } if (signalIdentity(e, sig)) killed.push(e.pid); }
    for (const h of scanEnvMarker(JOB_ENV, `${runId}:`, [process.pid])) if (signalIdentity(h, sig)) killed.push(h.pid);
  };
  void markers;
  sweep('SIGTERM');
  const end = Date.now() + graceMs;
  while (Date.now() < end && live().length) await sleep(50);
  sweep('SIGKILL');
  await sleep(50);
  return [...new Set(killed)];
}

export { tail, isAlive };
