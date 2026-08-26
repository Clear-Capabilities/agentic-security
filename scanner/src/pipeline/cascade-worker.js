// FR-202 phase 3b (D-0050): the long-lived worker thread spawned by cascade-worker-pool.js.
// Unlike analyzer-worker.js (one-shot: single call, single reply, then terminated by its
// caller), this worker performs one-time setup ONCE at startup, then services many per-file
// _runFileCascade task messages for the lifetime of the pool. See D-0050 for why per-file
// setup (rebuilding the whole-project index for every single file) would be O(N^2) and was
// rejected.
import { parentPort, workerData } from 'node:worker_threads';

const { modulePath, fileContents, scanRoot } = workerData;

let mod = null;
let initError = null;

async function init() {
  try {
    mod = await import(modulePath);
    if (typeof mod._initCascadeWorkerState !== 'function' || typeof mod._runFileCascade !== 'function') {
      throw new Error(`module at ${modulePath} does not export _initCascadeWorkerState/_runFileCascade`);
    }
    await mod._initCascadeWorkerState(fileContents, scanRoot);
    parentPort.postMessage({ type: 'ready' });
  } catch (err) {
    initError = String((err && err.stack) || err);
    parentPort.postMessage({ type: 'init-error', error: initError });
  }
}

parentPort.on('message', (msg) => {
  if (!msg || msg.type !== 'task') return;
  const { id, p, c, scanRoot: taskScanRoot, detectorErrors } = msg;
  if (!mod) {
    parentPort.postMessage({ id, ok: false, error: initError || 'worker not initialized' });
    return;
  }
  try {
    const result = mod._runFileCascade(p, c, taskScanRoot, detectorErrors || []);
    parentPort.postMessage({ id, ok: true, result });
  } catch (err) {
    parentPort.postMessage({ id, ok: false, error: String((err && err.message) || err) });
  }
});

init();
