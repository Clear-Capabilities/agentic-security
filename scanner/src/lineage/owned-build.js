// owned-build.js: run the lineage graph build under an owned worker with a
// deadline and a watchdog (DAG-07 R07.7).
//
// The in-process build (index.js buildLineageGraph) is unchanged and remains
// the default. This module is the opt-in path: it sends the file contents to a
// worker thread this module owns, which rebuilds the IR and call graph and runs
// the same buildLineageGraph with a cooperative stop signal. Two outcomes:
//   - the field analysis polls the stop flag, finishes the function it is in and
//     returns a graph whose scanHealth.status is 'cancelled' (cooperative);
//   - a worker that never polls (or is stuck in a phase that cannot be stopped,
//     such as parsing) is terminated by the watchdog `ackGraceMs` after the
//     deadline, and the result is {status:'cancelled', terminatedByWatchdog}.
// Either way the caller is released and the worker thread is gone
// (`exited` resolves when it is).
//
// Enabled by opts.deadlineMs or AGENTIC_SECURITY_LINEAGE_DEADLINE_MS. Not set
// means not used, and nothing about the default path changes.

import { fileURLToPath } from 'node:url';
import { runOwnedWorker } from './owned-worker.js';
import { buildLineageGraph } from './index.js';
import { buildProjectIR, buildProjectIRAsync } from '../ir/index.js';

const SELF = fileURLToPath(import.meta.url);

/** Resolve the configured deadline in ms, or null when the owned path is off. */
export function resolveLineageDeadlineMs(opts = {}, env = process.env) {
  const raw = opts.deadlineMs !== undefined ? opts.deadlineMs : env.AGENTIC_SECURITY_LINEAGE_DEADLINE_MS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * Worker body. Called as fn(spec, { shouldStop }) by owned-worker-entry.js.
 * `spec.opts` must be structured-cloneable (no functions).
 */
export async function lineageWorkerBody(spec, ctl) {
  const fc = spec.fileContents || {};
  const hasJava = Object.keys(fc).some((f) => /\.java$/i.test(f));
  const { perFile, callGraph } = hasJava ? await buildProjectIRAsync(fc) : buildProjectIR(fc);
  const signal = { get aborted() { return !!(ctl && ctl.shouldStop && ctl.shouldStop()); } };
  return buildLineageGraph(callGraph, { ...(spec.opts || {}), perFile, fileContents: fc, signal });
}

/**
 * @param {Object<string,string>} fileContents
 * @param {object} [opts] buildLineageGraph options that survive structured clone,
 *   plus deadlineMs, ackGraceMs, signal (AbortSignal), and the test seam `worker`
 *   ({modulePath, exportName}) which replaces the worker body.
 * @returns {{done:Promise<object>, exited:Promise<void>}} done resolves to the
 *   buildLineageGraph result shape, plus `cancelled` and, when the watchdog ended
 *   the worker, `terminatedByWatchdog` with status 'cancelled' and graph null.
 */
export function buildLineageGraphOwned(fileContents, opts = {}) {
  const t0 = Date.now();
  // onProgress and perFile cannot cross the thread boundary; the worker rebuilds the IR.
  // eslint-disable-next-line no-unused-vars
  const { deadlineMs, ackGraceMs, signal, worker, onProgress, perFile, ...rest } = opts;
  const timeoutMs = resolveLineageDeadlineMs({ deadlineMs });
  const spec = worker || { modulePath: SELF, exportName: 'lineageWorkerBody' };
  const run = runOwnedWorker(
    { ...spec, args: [{ fileContents, opts: rest }] },
    { signal, timeoutMs: timeoutMs || undefined, ackGraceMs },
  );
  const done = run.done.then((r) => {
    if (r.ok) return { ...r.result, cancelled: !!r.cancelled, elapsedMs: Date.now() - t0 };
    if (r.status === 'cancelled') {
      return {
        status: 'cancelled', graph: null, transitEvidence: new Map(),
        failure: `lineage build cancelled (${r.reason}); worker terminated by watchdog`,
        cancelled: true, terminatedByWatchdog: true, ackMs: r.ackMs, elapsedMs: Date.now() - t0,
      };
    }
    return { status: 'failed', graph: null, transitEvidence: new Map(), failure: r.error, cancelled: false, elapsedMs: Date.now() - t0 };
  });
  return { done, exited: run.exited };
}
