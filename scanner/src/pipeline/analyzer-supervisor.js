// Real, preemptive deadline enforcement via worker_threads (assurance-
// hardening PRD FR-202, D-0046 phase 1).
//
// FR-201's runDetector (detector-runner.js) catches a THROWN exception —
// it does nothing for a detector that hangs (infinite loop, catastrophic
// regex backtracking), because JavaScript is single-threaded: nothing
// running in the same event loop as a synchronous hang can preempt it. The
// existing _perFileTimeoutMs (engine.js) and AGENTIC_SECURITY_DEEP_TIMEOUT_MS
// (dataflow/engine.js) are both COOPERATIVE — they measure elapsed time
// after work already finished, or poll the clock between iterations of an
// already-bounded loop. Neither can stop a genuinely hung synchronous call.
//
// runWithDeadline is the one piece that can: it races a worker_thread
// against a real timer and calls worker.terminate() — an OS-level
// preemptive kill — if the timer wins. This is phase 1 of D-0046's 4-phase
// plan: a proven, isolated primitive, not yet wired into engine.js's real
// scan loop (phase 3). See D-0046 for the full plan and why per-file
// (not per-detector) granularity is the eventual wiring target.

import { Worker } from 'node:worker_threads';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_WORKER_SCRIPT = path.join(HERE, 'analyzer-worker.js');

// PRD FR-202: "the configured deadline plus a documented grace period."
// The grace period exists so a worker that finishes essentially on time
// (message already in flight) isn't killed by scheduler jitter.
export const DEFAULT_GRACE_MS = 500;

/**
 * Run `exportName` from `modulePath`, called with `args`, inside a worker
 * thread, with a real preemptive deadline.
 *
 * @param {object} spec
 * @param {string} spec.modulePath - absolute path to the module to import inside the worker.
 * @param {string} spec.exportName - the named export to call.
 * @param {Array} [spec.args] - plain, structured-clone-safe arguments.
 * @param {object} [opts]
 * @param {number} opts.timeoutMs - required. The configured deadline.
 * @param {number} [opts.graceMs] - documented grace period beyond timeoutMs before terminating. Default DEFAULT_GRACE_MS.
 * @param {string} [opts.workerScript] - override for testing.
 * @returns {Promise<{ok:true, result:*} | {ok:false, timedOut?:true, error?:string}>}
 */
export function runWithDeadline(spec, opts = {}) {
  const { modulePath, exportName, args = [] } = spec || {};
  const timeoutMs = opts.timeoutMs;
  const graceMs = opts.graceMs ?? DEFAULT_GRACE_MS;
  const workerScript = opts.workerScript || DEFAULT_WORKER_SCRIPT;

  if (!modulePath || !exportName) {
    return Promise.resolve({ ok: false, error: 'runWithDeadline requires spec.modulePath and spec.exportName' });
  }
  if (!(Number.isFinite(timeoutMs) && timeoutMs > 0)) {
    return Promise.resolve({ ok: false, error: 'runWithDeadline requires opts.timeoutMs > 0' });
  }

  return new Promise((resolve) => {
    let settled = false;
    const worker = new Worker(workerScript, { workerData: { modulePath, exportName, args } });

    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(killTimer);
      worker.terminate().catch(() => {});
      resolve(value);
    };

    // The one preemptive mechanism: a real OS-level Worker.terminate(),
    // triggered by a real timer, not a cooperative clock-check inside the
    // work itself. This is what makes this different from the existing
    // _perFileTimeoutMs / deadlineMs mechanisms.
    const killTimer = setTimeout(() => {
      finish({ ok: false, timedOut: true, timeoutMs, graceMs });
    }, timeoutMs + graceMs);
    killTimer.unref?.();

    worker.once('message', (msg) => {
      if (msg && msg.ok) finish({ ok: true, result: msg.result });
      else finish({ ok: false, error: (msg && msg.error) || 'unknown worker error' });
    });

    worker.once('error', (err) => {
      finish({ ok: false, error: String((err && err.message) || err) });
    });

    worker.once('exit', (code) => {
      finish({ ok: false, error: `worker exited with code ${code} before reporting a result` });
    });
  });
}
