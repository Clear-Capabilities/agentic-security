#!/usr/bin/env node
// Bounded command runner for program tasks.
//   node runner.mjs --task E0-04 --kind test --timeout-ms 600000 [--idle-ms N] [--retries 0..2] [--cwd dir] [--no-block-on-timeout] -- <argv...>
// The command is an argument ARRAY, never a shell string. It runs under the repository's supervised process runner (own process group,
// wall and idle deadlines, TERM then KILL escalation, orphan sweep, redacted capped log). The outcome, exit code, log path and log hash are
// written to status.json, so a task can only be closed on commands that really ran. A timeout blocks the task and the next invocation
// resumes with whatever is ready. Exit code: the child's, 124 on timeout, 130 when interrupted, 127 when it could not start.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomId, nowIso, sleep } from '../loop-engineering/lib/util.mjs';
import { runBounded } from '../loop-engineering/lib/proc.mjs';
import { HEARTBEAT_MAX_GAP_MS, REPO_ROOT } from './lib/model.mjs';
import { blockTask, logPathFor, recordCommandEnd, recordCommandHeartbeat, recordCommandStart } from './lib/store.mjs';

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000; // PRD 3.6: build and scoped tests
const MAX_TIMEOUT_MS = 60 * 60 * 1000;     // authorised heavyweight shards
const TRANSIENT = new Set(['spawn-failed']);

// Names only, never values, and never a name that looks like a credential.
function envKeyNames() {
  return Object.keys(process.env).filter((k) => !/(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|KEY)/i.test(k)).sort().slice(0, 60);
}

export function parseArgs(argv) {
  const sep = argv.indexOf('--');
  if (sep < 0) throw new Error('missing `--` before the command');
  const head = argv.slice(0, sep); const cmd = argv.slice(sep + 1);
  if (!cmd.length) throw new Error('no command after `--`');
  const o = { task: null, kind: 'other', timeoutMs: DEFAULT_TIMEOUT_MS, idleMs: 0, retries: 0, cwd: REPO_ROOT, root: REPO_ROOT, blockOnTimeout: true, argv: cmd };
  for (let i = 0; i < head.length; i++) {
    const a = head[i];
    if (a === '--task') o.task = head[++i];
    else if (a === '--kind') o.kind = head[++i];
    else if (a === '--timeout-ms') o.timeoutMs = Number(head[++i]);
    else if (a === '--idle-ms') o.idleMs = Number(head[++i]);
    else if (a === '--retries') o.retries = Number(head[++i]);
    else if (a === '--cwd') o.cwd = resolve(head[++i]);
    else if (a === '--root') o.root = resolve(head[++i]);
    else if (a === '--no-block-on-timeout') o.blockOnTimeout = false;
    else throw new Error(`unknown runner option ${a}`);
  }
  if (!o.task) throw new Error('--task is required');
  if (!['test', 'build', 'bench', 'other'].includes(o.kind)) throw new Error(`--kind must be test, build, bench or other (got ${o.kind})`);
  if (!Number.isFinite(o.timeoutMs) || o.timeoutMs < 1000) throw new Error('--timeout-ms must be at least 1000');
  if (o.timeoutMs > MAX_TIMEOUT_MS) throw new Error(`--timeout-ms is capped at ${MAX_TIMEOUT_MS} (60 minutes); record a rationale and shard the work instead`);
  if (!Number.isInteger(o.retries) || o.retries < 0 || o.retries > 2) throw new Error('--retries must be 0, 1 or 2');
  return o;
}

export async function runTaskCommand(opts) {
  const o = { ...opts };
  let last = null;
  for (let attempt = 1; attempt <= o.retries + 1; attempt++) {
    const id = `c-${randomId(4)}`;
    const startedAt = nowIso();
    const { abs, rel } = logPathFor(o.root, o.task, id);
    recordCommandStart(o.root, o.task, { id, argv: o.argv, cwd: o.cwd, kind: o.kind, startedAt, endedAt: null, timeoutMs: o.timeoutMs, outcome: 'running', exitCode: null, signal: null, durationMs: null, log: rel, logSha256: null, attempt, envKeys: envKeyNames(), pid: process.pid }, { allowClosed: o.reverify === true });
    const ac = new AbortController();
    const onSig = () => ac.abort();
    process.once('SIGINT', onSig); process.once('SIGTERM', onSig);
    const beat = setInterval(() => { try { recordCommandHeartbeat(o.root, o.task, id); } catch { /* a missed beat is shown as stale, not fatal */ } }, Math.min(HEARTBEAT_MAX_GAP_MS - 5000, 20000));
    let res;
    try {
      res = await runBounded({ argv: o.argv, cwd: o.cwd, wallMs: o.timeoutMs, idleMs: o.idleMs, logPath: abs, redactLog: true, signal: ac.signal, label: `${o.task}:${o.kind}`, runId: `ee-${o.task}` });
    } finally { clearInterval(beat); process.removeListener('SIGINT', onSig); process.removeListener('SIGTERM', onSig); }
    let logSha256 = null;
    try { logSha256 = createHash('sha256').update(readFileSync(abs)).digest('hex'); } catch { /* an empty or missing log is recorded as no hash and never counts as evidence */ }
    recordCommandEnd(o.root, o.task, id, { endedAt: res.endedAt || nowIso(), outcome: res.outcome, exitCode: res.exitCode, signal: res.signal, durationMs: res.durationMs, log: rel, logSha256 });
    last = { id, rel, res, attempt };
    if (!TRANSIENT.has(res.outcome) || attempt > o.retries) break;
    await sleep(Math.min(8000, 1000 * 2 ** (attempt - 1)));
  }
  const { res } = last;
  if ((res.outcome === 'timeout-wall' || res.outcome === 'timeout-idle') && o.blockOnTimeout) {
    try { blockTask(o.root, o.task, { reason: `command timed out (${res.outcome}) after ${res.durationMs} ms: ${o.argv.join(' ').slice(0, 160)}`, nextAction: `inspect ${last.rel}, fix the hang or shard the command, then: task.mjs start ${o.task}`, kind: 'timeout' }); } catch { /* already moved by another actor */ }
  }
  return last;
}

export function exitCodeFor(res) {
  if (res.outcome === 'exited') return res.exitCode ?? 1;
  if (res.outcome === 'timeout-wall' || res.outcome === 'timeout-idle') return 124;
  if (res.outcome === 'cancelled') return 130;
  if (res.outcome === 'spawn-failed') return 127;
  return 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
    let o;
    try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`runner: ${e.message}`); process.exit(2); }
    try {
      const last = await runTaskCommand(o);
      const { res } = last;
      console.log(`runner: ${o.task} ${o.kind} ${res.outcome}${res.exitCode == null ? '' : ` exit ${res.exitCode}`} in ${res.durationMs} ms; log ${last.rel}`);
      process.exit(exitCodeFor(res));
    } catch (e) { console.error(`runner: ${e.message}`); process.exit(2); }
  })();
}
