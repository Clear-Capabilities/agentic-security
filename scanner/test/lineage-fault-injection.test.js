// End-to-end fault-injection regression for Sub-project E, increment 5's
// review MUST-FIX 1: a throw from ANYTHING outside buildLineageGraph's own
// try/catch — most concretely, buildCallGraph, which
// buildProjectIR/buildProjectIRAsync do NOT guard per-file the way per-file
// PARSING is guarded — previously killed the entire scan the moment
// AGENTIC_SECURITY_LINEAGE_DEEP=1 was set. This is real and reachable: a
// scan that survives fine with AGENTIC_SECURITY_DEEP=1 alone (that flag's
// own _deepEnabled block already wraps the identical `_buildIR()` call in
// try/catch) crashed once AGENTIC_SECURITY_LINEAGE_DEEP=1 was added,
// because the lineage gate block in engine.js called `_buildIR()` with no
// handler of its own.
//
// Fixed in engine.js by wrapping the lineage gate block's body in
// try/catch, mirroring _deepEnabled's own catch exactly: on catch,
// `_lineageStatus.failure` is set and execution continues normally, no
// rethrow.
//
// WHY THIS IS ITS OWN FILE, NOT A TEST IN lineage-scan-wiring.test.js.
// Node's module-mocking (node:test's `mock.module`, gated behind
// --experimental-test-module-mocks) only intercepts a module's FIRST
// resolution in the process. lineage-scan-wiring.test.js has a top-level
// `import { runScan } from '../src/runScan.js'` — by the time any test
// body in that file runs, runScan's entire import graph (engine.js ->
// ir/index.js -> ir/callgraph.js) is already resolved, so a mock.module
// call for ir/callgraph.js inside one of that file's tests would have
// nothing left to intercept (the exact mechanism test/fault-injection.js's
// own header comment documents, and the reason that file is also its own
// isolated single-scenario file). This file deliberately has NO top-level
// import of runScan/engine.js — only a dynamic `await import(...)` inside
// the test body, AFTER mock.module() runs, so the mock is in place before
// the real module graph is ever touched.
//
// WHY THIS FILE IS NOT IN ANY test:* SCOPED SCRIPT (mirrors
// test/fault-injection.test.js's own precedent exactly): run-unit-tests.mjs
// combines every scoped test:* script into ONE `node --test` invocation,
// which does not carry --experimental-test-module-mocks, and enabling it
// globally would let mock state leak across every other file sharing that
// process. This file is invoked as its own separate step in package.json's
// top-level "test" script instead. Running it directly
// (`node --experimental-test-module-mocks --test
// test/lineage-fault-injection.test.js`) works standalone too.

import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');

test('MF-1: a thrown buildCallGraph does not crash a scan with AGENTIC_SECURITY_LINEAGE_DEEP=1 set — the failure is recorded, not swallowed and not fatal', async () => {
  const modPath = path.join(SCANNER, 'src', 'ir', 'callgraph.js');
  mock.module(modPath, {
    exports: {
      buildCallGraph: () => { throw new Error('E5 MF-1 injected fault — buildCallGraph should never actually throw in production'); },
      functionRecord: () => null,
    },
  });

  const prev = process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1';
  setStateWritesEnabled(false);
  let scan;
  try {
    const { runScan } = await import(path.join(SCANNER, 'src', 'runScan.js'));
    const fileContents = { 'app.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" };
    // A real directory is still required (runScan resolves scanRoot from
    // it), but fileContents short-circuits the tree walk — mirrors
    // lineage-scan-wiring.test.js's own established convention.
    const fs = await import('node:fs');
    const os = await import('node:os');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-lineage-fault-'));
    try {
      ({ scan } = await runScan(dir, { fileContents }));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  } finally {
    setStateWritesEnabled(true);
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
    else process.env.AGENTIC_SECURITY_LINEAGE_DEEP = prev;
  }

  // The scan must complete at all — this assertion is the whole point:
  // pre-fix, the injected throw propagated out of runFullScan and this
  // `await runScan(...)` call above would itself have rejected, failing
  // this test with the injected error instead of ever reaching here.
  assert.ok(scan, 'runScan must resolve normally even though buildCallGraph threw');
  assert.equal(scan.lineageGraph, null, 'a genuinely failed lineage build must never produce a graph');
  assert.ok(scan.lineageStatus, 'scan.lineageStatus must still be populated');
  assert.equal(scan.lineageStatus.requested, true);
  assert.equal(scan.lineageStatus.enabled, true);
  assert.ok(scan.lineageStatus.failure && /E5 MF-1 injected fault/.test(scan.lineageStatus.failure),
    `expected the injected fault to be recorded in scan.lineageStatus.failure, got: ${JSON.stringify(scan.lineageStatus)}`);
  assert.ok(scan.scanHealth && scan.scanHealth.lineageAnalysis,
    'scanHealth.lineageAnalysis must still be present');
  assert.equal(scan.scanHealth.lineageAnalysis.failure, scan.lineageStatus.failure,
    'scanHealth must surface the same recorded failure, not a swallowed/blank one');
  // The rest of the scan must be unaffected — a lineage-build fault is not
  // an excuse for the whole pipeline to degrade.
  assert.ok(Array.isArray(scan.findings), 'the ordinary SAST pipeline must still produce a findings array');
});
