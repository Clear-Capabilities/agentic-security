// owned-worker.js: run bounded work in a worker thread this module owns, with
// cooperative cancellation and a watchdog (DAG-07 R07.7).
//
// Follows the existing worker convention (pipeline/analyzer-supervisor.js:
// worker_threads, Worker.terminate() as the only preemptive tool) and adds
// the two things that module does not have:
//   - cancellation on an AbortSignal, acknowledged through a shared flag the
//     work polls (works from inside a synchronous loop);
//   - a watchdog: if the worker has not acknowledged within `ackGraceMs` of
//     the abort, it is terminated, so a worker that never polls cannot hold
//     the caller past that bound.
// The returned promise always settles with a structured result, and every
// resource this function created (worker, timers, abort listener) is released
// before it settles; `exited` resolves when the worker thread is really gone.

import { Worker } from 'node:worker_threads';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const ENTRY = path.join(path.dirname(fileURLToPath(import.meta.url)), 'owned-worker-entry.js');

export const DEFAULT_ACK_GRACE_MS = 500;

/**
 * @param {{modulePath:string, exportName:string, args?:Array}} spec
 * @param {{signal?:AbortSignal, timeoutMs?:number, ackGraceMs?:number}} [opts]
 * @returns {{done:Promise<object>, exited:Promise<void>}}
 *   done resolves to one of:
 *     {ok:true, result, cancelled:false}
 *     {ok:true, result, cancelled:true, ackMs}                 cooperative stop
 *     {ok:false, status:'cancelled', terminatedByWatchdog:true, ackMs}
 *     {ok:false, error}
 */
export function runOwnedWorker(spec, opts = {}) {
  const ackGraceMs = Number.isFinite(opts.ackGraceMs) && opts.ackGraceMs > 0 ? opts.ackGraceMs : DEFAULT_ACK_GRACE_MS;
  let resolveExited;
  const exited = new Promise((r) => { resolveExited = r; });
  const done = new Promise((resolve) => {
    if (!spec || !spec.modulePath || !spec.exportName) {
      resolveExited();
      return resolve({ ok: false, error: 'runOwnedWorker requires spec.modulePath and spec.exportName' });
    }
    const flag = new Int32Array(new SharedArrayBuffer(4));
    const worker = new Worker(ENTRY, { workerData: { modulePath: spec.modulePath, exportName: spec.exportName, args: spec.args || [], flag: flag.buffer } });
    worker.once('exit', () => resolveExited());
    let settled = false;
    let cancelAt = null;
    let reason = null;
    let watchdog = null;
    let deadlineTimer = null;

    const release = () => {
      clearTimeout(watchdog);
      clearTimeout(deadlineTimer);
      if (opts.signal) opts.signal.removeEventListener('abort', onAbort);
      worker.terminate().catch(() => {});
    };
    const settle = (value) => {
      if (settled) return;
      settled = true;
      release();
      resolve(value);
    };
    const requestCancel = (why) => {
      if (settled || cancelAt !== null) return;
      cancelAt = Date.now();
      reason = why;
      Atomics.store(flag, 0, 1);
      watchdog = setTimeout(() => {
        settle({ ok: false, status: 'cancelled', reason: why, terminatedByWatchdog: true, ackMs: Date.now() - cancelAt });
      }, ackGraceMs);
    };
    function onAbort() { requestCancel('aborted'); }

    worker.once('message', (msg) => {
      if (msg && msg.ok) {
        const wasCancelled = !!msg.cancelled || cancelAt !== null;
        settle(wasCancelled
          ? { ok: true, result: msg.result, cancelled: true, reason, ackMs: cancelAt === null ? 0 : Date.now() - cancelAt }
          : { ok: true, result: msg.result, cancelled: false });
      } else {
        settle({ ok: false, error: (msg && msg.error) || 'worker failed' });
      }
    });
    worker.once('error', (e) => settle({ ok: false, error: String((e && e.message) || e) }));

    if (opts.signal) {
      if (opts.signal.aborted) onAbort(); else opts.signal.addEventListener('abort', onAbort, { once: true });
    }
    if (Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0) {
      deadlineTimer = setTimeout(() => requestCancel('deadline'), opts.timeoutMs);
    }
  });
  return { done, exited };
}
