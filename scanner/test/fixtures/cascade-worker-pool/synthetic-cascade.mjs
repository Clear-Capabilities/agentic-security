// Synthetic stand-in for engine.js's _initCascadeWorkerState/_runFileCascade contract,
// used to test cascade-worker-pool.js/cascade-worker.js in isolation from the real
// (much heavier) engine.js module. Mirrors the precedent of
// test/fixtures/analyzer-supervisor/synthetic-analyzers.mjs for FR-202 phase 1.
let initCount = 0;
let fileCountAtInit = 0;
let scanRootAtInit = null;

export async function _initCascadeWorkerState(fileContents, scanRoot) {
  initCount += 1;
  fileCountAtInit = Object.keys(fileContents || {}).length;
  scanRootAtInit = scanRoot;
}

export function _runFileCascade(p, c, scanRoot, detectorErrors) {
  if (c === 'HANG') { while (true) { /* genuine busy-wait, no clock check */ } }
  if (c === 'THROW') { throw new Error('synthetic cascade failure'); }
  return {
    file: p,
    contentLength: c.length,
    scanRoot,
    detectorErrorsIsArray: Array.isArray(detectorErrors),
    initCount,
    fileCountAtInit,
    scanRootAtInit,
  };
}
