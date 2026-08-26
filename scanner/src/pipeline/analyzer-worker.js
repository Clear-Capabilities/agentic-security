// Worker-thread entry point for analyzer-supervisor.js (assurance-hardening
// PRD FR-202, D-0046 phase 1).
//
// Generic by design: workerData names a module and an export to call with a
// list of plain arguments, so this file has no knowledge of what analyzer it
// is running. The supervisor is the only caller; this file is not meant to
// be imported directly.

import { parentPort, workerData } from 'node:worker_threads';

async function run() {
  try {
    const { modulePath, exportName, args } = workerData;
    const mod = await import(modulePath);
    const fn = mod[exportName];
    if (typeof fn !== 'function') {
      throw new Error(`export "${exportName}" is not a function in ${modulePath}`);
    }
    const result = await fn(...(args || []));
    parentPort.postMessage({ ok: true, result });
  } catch (e) {
    parentPort.postMessage({ ok: false, error: String((e && e.message) || e) });
  }
}

run();
