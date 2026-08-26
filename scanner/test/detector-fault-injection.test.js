// End-to-end fault-injection gate (assurance-hardening PRD FR-201).
//
// test/detector-runner.test.js already proves the EXTRACTED primitive
// (runDetector) captures a synchronous throw from a synthetic callback,
// never propagating it — at the unit level. What it does NOT prove is that
// a REAL detector module, wired into a REAL runFullScan() through
// engine.js's own 128 call sites (D-0028 step (b)), actually gets the SAME
// protection — the exact same "worked in isolation but had a real, unproven
// gap at a specific call site" risk test/fault-injection.test.js's own
// header documents for FR-906/annotators.
//
// Mirrors test/fault-injection.test.js's technique exactly: node:test's
// mock.module() replaces a REAL sast module's export with a throwing stub
// BEFORE engine.js's own static import resolves it, proving the REAL
// wiring rather than a simulation of it.
//
// DELIBERATELY ITS OWN FILE, NOT ADDED TO fault-injection.test.js.
// fault-injection.test.js's own header documents why: mock.module()
// registrations bind at first resolution, and a second mock.module() call
// on a different module already pulled into the same process's import
// graph has nothing left to intercept. Wired into package.json's top-level
// "test" script as its own step, the same precedent as fault-injection.test.js
// and test/cpp-dataflow.test.js, and invokable standalone with
// `node --experimental-test-module-mocks --test test/detector-fault-injection.test.js`.

import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const FIXTURE = path.join(SCANNER, 'test', 'fixtures', 'vulnerable-js');

test('a real per-file detector that throws does not crash the scan — other detectors\' findings still land, the error is captured by analyzer', async () => {
  // scanSecretConcat runs unconditionally on every scanned file (no
  // extension guard, unlike e.g. scanGraphQL) so it is guaranteed to fire
  // on the JS fixture.
  const modPath = path.join(SCANNER, 'src', 'sast', 'secret-concat.js');
  mock.module(modPath, {
    exports: {
      scanSecretConcat: () => { throw new Error('FR-201 injected fault — this detector should never actually throw in production'); },
    },
  });

  // D-0009: a scan against a fixture directory IN PLACE writes real
  // .agentic-security/ state into it unless state writes are explicitly
  // disabled.
  setStateWritesEnabled(false);
  let scan;
  try {
    const { runScan } = await import(path.join(SCANNER, 'src', 'runScan.js'));
    ({ scan } = await runScan(FIXTURE, { network: false }));
  } finally {
    setStateWritesEnabled(true);
  }

  assert.ok((scan.findings || []).length > 0,
    'a fault in one detector must not suppress findings every OTHER independent detector already produced for the same file — this is FR-201\'s literal acceptance criterion');
  assert.ok(Array.isArray(scan.detectorErrors), 'detectorErrors must be an array even when a fault was injected');
  const captured = scan.detectorErrors.find(e => /FR-201 injected fault/.test(e.err));
  assert.ok(captured, `expected the injected fault to be captured in detectorErrors, got: ${JSON.stringify(scan.detectorErrors)}`);
  assert.equal(captured.analyzer, 'scanSecretConcat', 'the captured error must name the failing detector, not just "something failed"');
  assert.equal(typeof captured.file, 'string');
  assert.ok(captured.file.length > 0, 'the captured error must name the failing file');
});
