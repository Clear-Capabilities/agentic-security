// Worker entry for owned-worker.js (DAG-07 R07.7). Same shape as
// pipeline/analyzer-worker.js, plus a shared cancellation flag the work can
// poll even from inside a synchronous loop (a posted message could not be
// delivered to a busy thread). The export is called as
// fn(...args, { shouldStop }).
import { parentPort, workerData } from 'node:worker_threads';

async function run() {
  const flag = new Int32Array(workerData.flag);
  const shouldStop = () => Atomics.load(flag, 0) === 1;
  try {
    const { modulePath, exportName, args } = workerData;
    const mod = await import(modulePath);
    const fn = mod[exportName];
    if (typeof fn !== 'function') throw new Error(`export "${exportName}" is not a function in ${modulePath}`);
    const result = await fn(...(args || []), { shouldStop });
    parentPort.postMessage({ ok: true, cancelled: shouldStop(), result });
  } catch (e) {
    parentPort.postMessage({ ok: false, error: String((e && e.message) || e) });
  }
}
run();
