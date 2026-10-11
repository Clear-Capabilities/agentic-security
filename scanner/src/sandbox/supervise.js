// Supervised execution: every process the target starts, and all of its
// descendants, end when the run ends (CORE-003.AC02).
//
// `spawnSync`'s timeout signals only the direct child (see CLAUDE.md, "Timeout
// does not kill the process tree"). This module is the repair for the backends
// where it can be proved:
//
//   1. The child starts in its own process group and session (`detached`), so
//      one signal to the negative pid reaches every member that did not move.
//   2. While it runs, the process table is swept on a short interval and every
//      descendant seen is remembered, so a member that left the group (for
//      example via setsid) while its parent was still alive is still killed.
//   3. Termination is SIGTERM to the group and the tracked set, a grace period,
//      then SIGKILL, then a poll that CONFIRMS nothing is left. Survivors are
//      reported, never assumed away.
//   4. The same cleanup runs on a normal exit, so a backgrounded grandchild
//      cannot outlive a run that "succeeded".
//
// KNOWN GAP on the userspace backend (not hidden): a descendant that
// double-forks and calls setsid between two sweeps, with its parent exiting
// before the next sweep, is reparented away from the tree and is not found. The
// sweep interval bounds the window; it does not close it. Only a PID-namespace
// or cgroup boundary closes it, and macOS has neither. The namespace backend
// has the boundary (see `runConfinedSupervised`).
import { spawn, spawnSync } from 'node:child_process';
import { detectBackend } from './capabilities.js';
import { runDisabled } from './backend-disabled.js';
import { buildUserspaceInvocation } from './backend-userspace.js';
import { buildNamespaceInvocation } from './backend-namespace.js';
import { buildResult, errorResult } from './result.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}
function groupAlive(pgid) {
  try { process.kill(-pgid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}
function signalPid(pid, sig) { try { process.kill(pid, sig); } catch { /* already gone */ } }
function signalGroup(pgid, sig) { try { process.kill(-pgid, sig); } catch { /* already gone */ } }

/** Descendants of `rootPid` plus members of its group, from one `ps` snapshot. */
function snapshotTree(rootPid) {
  const r = spawnSync('ps', ['-A', '-o', 'pid=,ppid=,pgid='], { encoding: 'utf8', timeout: 2000 });
  if (r.error || r.status !== 0) return [];
  const rows = [];
  for (const line of String(r.stdout).split('\n')) {
    const m = line.trim().split(/\s+/).map(Number);
    if (m.length === 3 && m.every(Number.isFinite)) rows.push({ pid: m[0], ppid: m[1], pgid: m[2] });
  }
  const kids = new Map();
  for (const x of rows) { if (!kids.has(x.ppid)) kids.set(x.ppid, []); kids.get(x.ppid).push(x.pid); }
  const found = new Set();
  const queue = [rootPid];
  while (queue.length) {
    const p = queue.pop();
    for (const c of kids.get(p) || []) if (!found.has(c)) { found.add(c); queue.push(c); }
  }
  for (const x of rows) if (x.pgid === rootPid && x.pid !== process.pid) found.add(x.pid);
  return [...found];
}

function _emptyTermination() { return { signalled: null, killedPids: [], survivors: [] }; }

/**
 * Spawn `bin args` as a supervised process tree.
 * @returns {Promise<object>} never rejects.
 */
export function superviseSpawn(bin, args, {
  cwd, env, timeoutMs = 10000, graceMs = 1000, signal, maxOutputBytes = 8 * 1024 * 1024, sweepMs = 100,
} = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      resolve({ spawnError: e.message, exitCode: null, stdout: '', stderr: '', timedOut: false, cancelled: false, outputCapped: false, termination: _emptyTermination() });
      return;
    }
    const pgid = child.pid;
    const tracked = new Set();
    let stdout = '', stderr = '', outBytes = 0;
    let timedOut = false, cancelled = false, outputCapped = false, spawnError = null;
    let exitCode = null, exitSignal = null;
    let finishing = null;
    let timer = null;

    const sweep = () => { if (pgid) for (const p of snapshotTree(pgid)) tracked.add(p); };
    // sweepMs <= 0 turns the periodic sweep off. Each sweep is a SYNCHRONOUS `ps`, which blocks the controller's event loop for as long as
    // it runs; on the namespace backend the kernel ends every member with the supervisor (--kill-child), so the periodic sweep adds nothing
    // there and only costs responsiveness. The cleanup below still takes its own snapshots.
    const sweeper = sweepMs > 0 ? setInterval(sweep, sweepMs) : null;

    const survivors = () => {
      sweep();
      return { live: [...tracked].filter(alive), group: groupAlive(pgid) };
    };

    async function terminate() {
      const t = _emptyTermination();
      const before = survivors();
      if (!before.group && before.live.length === 0) return t;
      t.signalled = 'SIGTERM';
      signalGroup(pgid, 'SIGTERM');
      for (const p of tracked) signalPid(p, 'SIGTERM');
      const deadline = Date.now() + graceMs;
      while (Date.now() < deadline) {
        const s = survivors();
        if (!s.group && s.live.length === 0) return t;
        await sleep(25);
      }
      // Grace expired: SIGKILL cannot be ignored. Repeat until nothing is left,
      // because a dying process can fork once more before it is reaped.
      t.signalled = 'SIGKILL';
      const hard = Date.now() + 3000;
      while (Date.now() < hard) {
        const s = survivors();
        if (!s.group && s.live.length === 0) break;
        signalGroup(pgid, 'SIGKILL');
        for (const p of s.live) { signalPid(p, 'SIGKILL'); if (!t.killedPids.includes(p)) t.killedPids.push(p); }
        await sleep(25);
      }
      const s = survivors();
      t.survivors = s.live.length ? s.live : (s.group ? [-pgid] : []);
      return t;
    }

    function finish() {
      if (finishing) return finishing;
      finishing = (async () => {
        if (sweeper) clearInterval(sweeper);
        clearTimeout(timer);
        const termination = await terminate();
        try { child.stdout?.destroy(); child.stderr?.destroy(); } catch { /* ignore */ }
        resolve({ spawnError, exitCode, exitSignal, stdout, stderr, timedOut, cancelled, outputCapped, termination });
      })();
      return finishing;
    }

    const collect = (which) => (d) => {
      outBytes += d.length;
      if (outBytes > maxOutputBytes) {
        if (!outputCapped) { outputCapped = true; finish(); }
        return;
      }
      if (which === 'out') stdout += d.toString('utf8'); else stderr += d.toString('utf8');
    };
    child.stdout.on('data', collect('out'));
    child.stderr.on('data', collect('err'));
    child.on('error', (e) => { spawnError = e.message; finish(); });
    child.on('exit', (code, sig) => {
      exitCode = code; exitSignal = sig;
      // Let buffered output drain, then clean up any survivors.
      setTimeout(finish, 50);
    });
    timer = setTimeout(() => { timedOut = true; finish(); }, timeoutMs);
    if (signal) {
      if (signal.aborted) { cancelled = true; finish(); }
      else signal.addEventListener('abort', () => { cancelled = true; finish(); }, { once: true });
    }
  });
}

/**
 * `runConfined`, plus a guarantee about the process tree. Same result shape as
 * every backend, with extra `cancelled`, `outputCapped`, `termination` and
 * `supervised: true`. Never throws.
 *
 * Backend coverage, stated plainly:
 *   userspace  supervised (verified by execution on macOS)
 *   namespace  supervised ONLY where the PID namespace is created with
 *              `--kill-child`: killing the unshare process then makes the
 *              kernel kill every member of the namespace, however it detached
 *              (setsid, double fork). Where the host's unshare lacks the flag
 *              the run is refused, since the sweep alone would be the whole
 *              guarantee. That it holds on a host is shown by the active probe
 *              (`linux-probes.js`), not by this comment.
 *   disabled   refused, as always
 */
export async function runConfinedSupervised(argv, opts = {}) {
  const backend = detectBackend({ force: opts.force });
  if (backend === 'disabled') return runDisabled(argv, opts);
  if (backend !== 'userspace' && backend !== 'namespace') {
    return errorResult(backend, `process-tree termination is not implemented or verified on the ${backend} backend; refusing to execute`);
  }
  const inv = backend === 'userspace' ? buildUserspaceInvocation(argv, opts) : buildNamespaceInvocation(argv, opts, opts.deps);
  if (inv.error) return inv.error;
  if (backend === 'namespace' && !inv.treeKill) {
    inv.dispose();
    return errorResult(backend, 'process-tree termination is not implemented or verified on the namespace backend (this host cannot make the kernel kill the namespace with its supervisor); refusing to execute');
  }
  const r = await superviseSpawn(inv.bin, inv.args, {
    cwd: inv.cwd, env: inv.env, timeoutMs: opts.timeoutMs ?? 10000, graceMs: opts.graceMs ?? 1000,
    signal: opts.signal, maxOutputBytes: opts.maxOutputBytes, ...(backend === 'namespace' ? { sweepMs: 0 } : {}),
  });
  let rawStderr = r.stderr;
  let unsupported = inv.unsupported;
  if (backend === 'namespace') {
    const fin = inv.finish(r.stderr, { hadError: !!r.spawnError || r.timedOut });
    if (fin.error) return fin.error;
    rawStderr = fin.stderr;
    unsupported = fin.unsupported;
  }
  const res = buildResult({
    backend,
    spawnResult: {
      status: r.exitCode,
      stdout: r.stdout,
      stderr: rawStderr,
      error: r.timedOut ? { code: 'ETIMEDOUT' } : r.spawnError ? { code: 'SPAWN', message: r.spawnError } : null,
    },
    unsupported,
  });
  let status = res.status;
  let stderr = res.stderr;
  if (r.cancelled) status = 'cancelled';
  if (r.outputCapped) { status = 'error'; stderr += '\n[sandbox] output cap exceeded; process tree terminated'; }
  if (r.termination.survivors.length) { status = 'error'; stderr += '\n[sandbox] processes survived termination'; }
  return {
    ...res, status, stderr, cancelled: r.cancelled, outputCapped: r.outputCapped,
    supervised: true, termination: r.termination,
  };
}
