// FR-202 phase 3b (D-0050): a pool of long-lived workers, each running engine.js's
// _runFileCascade for many files over its lifetime, instead of the one-shot-per-call
// model runWithDeadline/analyzer-supervisor.js uses (which is correct for FR-202's
// primitive-level proof but would force whole-project setup — _buildProjectIndex,
// _buildGlobalJavaTaintedMethodIndex, _loadCustomRules — to redo per FILE, an O(n^2)
// cost across a scan). Each worker performs that setup ONCE at creation via
// _initCascadeWorkerState, then answers task messages over its lifetime.
//
// A task that exceeds its deadline+grace gets its OWN worker terminated (genuinely
// preemptive, mirroring analyzer-supervisor.js's worker.terminate() precedent) and a
// fresh replacement worker is spawned to keep the pool at full size for later files —
// one hung file costs one worker restart, not the whole scan.
import { Worker } from 'node:worker_threads';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// `new Worker()` needs a REAL file on disk -- once ncc bundles this module's code
// into a dist/ chunk, `import.meta.url` resolves to that chunk's location (dist/),
// not to src/pipeline/, so a naive path.join(HERE, 'cascade-worker.js') would look
// for a file that was never copied there. src/ always ships as a sibling of dist/
// (see package.json's "files"), in both a dev checkout and the published npm
// package, so fall back to the real, unbundled worker script in that case.
function _resolveDefaultWorkerScript() {
  const hereDir = path.dirname(fileURLToPath(import.meta.url));
  if (path.basename(hereDir) === 'pipeline') return path.join(hereDir, 'cascade-worker.js');
  return path.join(hereDir, '..', 'src', 'pipeline', 'cascade-worker.js');
}
const DEFAULT_WORKER_SCRIPT = _resolveDefaultWorkerScript();
export const DEFAULT_GRACE_MS = 500;

function spawnReadyWorker({ workerScript, modulePath, fileContents, scanRoot }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const worker = new Worker(workerScript, { workerData: { modulePath, fileContents, scanRoot } });
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      worker.off('message', onMessage);
      worker.off('error', onError);
      fn(value);
    };
    const onMessage = (msg) => {
      if (!msg) return;
      if (msg.type === 'ready') finish(resolve, worker);
      else if (msg.type === 'init-error') { worker.terminate().catch(() => {}); finish(reject, new Error(msg.error)); }
    };
    const onError = (err) => { worker.terminate().catch(() => {}); finish(reject, err); };
    worker.on('message', onMessage);
    worker.on('error', onError);
  });
}

/**
 * @param {object} opts
 * @param {Record<string,string>} opts.fileContents - broadcast once to every worker at creation.
 * @param {string|null} opts.scanRoot
 * @param {number} [opts.poolSize=4]
 * @param {string} opts.modulePath - absolute path to the engine.js each worker imports.
 * @param {string} [opts.workerScript] - defaults to cascade-worker.js next to this file.
 * @param {number} [opts.graceMs]
 */
export function createCascadePool(opts = {}) {
  const {
    fileContents = {},
    scanRoot = null,
    poolSize = 4,
    workerScript = DEFAULT_WORKER_SCRIPT,
    modulePath,
    graceMs = DEFAULT_GRACE_MS,
  } = opts;
  if (!modulePath) throw new Error('createCascadePool requires opts.modulePath');
  if (!(Number.isInteger(poolSize) && poolSize > 0)) throw new Error('createCascadePool requires opts.poolSize to be a positive integer');

  const idle = [];
  const pendingIdle = [];
  const allWorkers = new Set();
  let nextTaskId = 1;
  let closed = false;
  let spawnFailureCount = 0;
  let lastSpawnError = null;

  function spawnAndRegister() {
    return spawnReadyWorker({ workerScript, modulePath, fileContents, scanRoot }).then((w) => {
      allWorkers.add(w);
      return w;
    });
  }

  // Background respawn after a killed worker (see runFile's timeout branch)
  // is deliberately fire-and-forget -- the timed-out task has already
  // resolved and nothing is waiting on this promise -- but a swallowed
  // failure here would otherwise shrink the pool invisibly (e.g. thread
  // exhaustion making every future respawn fail silently forever). Track
  // it instead of a bare `.catch(() => {})`.
  function respawnInBackground() {
    spawnAndRegister().then(releaseWorker).catch((err) => {
      spawnFailureCount += 1;
      lastSpawnError = err;
    });
  }

  function releaseWorker(w) {
    if (closed) { allWorkers.delete(w); w.terminate().catch(() => {}); return; }
    if (pendingIdle.length) pendingIdle.shift()(w);
    else idle.push(w);
  }

  function acquireWorker() {
    if (idle.length) return Promise.resolve(idle.pop());
    return new Promise((resolve) => pendingIdle.push(resolve));
  }

  const ready = Promise.all(
    Array.from({ length: poolSize }, () => spawnAndRegister().then(releaseWorker))
  );

  /**
   * Run one file's cascade on a pooled worker. Resolves with
   * {ok:true, result} | {ok:false, error} | {ok:false, timedOut:true, timeoutMs, graceMs}.
   * Never rejects.
   */
  async function runFile(p, c, taskScanRoot, detectorErrors, taskOpts = {}) {
    await ready;
    if (closed) return { ok: false, error: 'pool is closed' };
    const timeoutMs = taskOpts.timeoutMs;
    const worker = await acquireWorker();
    const id = nextTaskId++;
    return new Promise((resolve) => {
      let settled = false;
      let killTimer = null;
      const onMessage = (msg) => {
        if (settled || !msg || msg.id !== id) return;
        settled = true;
        if (killTimer) clearTimeout(killTimer);
        worker.off('message', onMessage);
        releaseWorker(worker);
        resolve(msg.ok ? { ok: true, result: msg.result } : { ok: false, error: msg.error });
      };
      worker.on('message', onMessage);
      if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
        killTimer = setTimeout(() => {
          if (settled) return;
          settled = true;
          worker.off('message', onMessage);
          allWorkers.delete(worker);
          worker.terminate().catch(() => {});
          if (!closed) respawnInBackground();
          resolve({ ok: false, timedOut: true, timeoutMs, graceMs });
        }, timeoutMs + graceMs);
        killTimer.unref?.();
      }
      worker.postMessage({ type: 'task', id, p, c, scanRoot: taskScanRoot, detectorErrors });
    });
  }

  async function shutdown() {
    closed = true;
    await ready.catch(() => {});
    for (const w of allWorkers) await w.terminate().catch(() => {});
    allWorkers.clear();
    idle.length = 0;
  }

  return {
    runFile,
    shutdown,
    ready,
    DEFAULT_GRACE_MS: graceMs,
    getSpawnFailureCount: () => spawnFailureCount,
    getLastSpawnError: () => lastSpawnError,
  };
}
