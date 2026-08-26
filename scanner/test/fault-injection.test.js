// End-to-end fault-injection gate (assurance-hardening PRD FR-906).
//
// test/annotator-runner.test.js already proves the EXTRACTED primitive
// (runAnnotatorAsync) captures a synchronous throw or an async rejection
// from a synthetic callback, never propagating it and never leaving an
// unhandled rejection — both directions, at the unit level. What it does
// NOT prove is that a REAL annotator module, wired into a REAL
// runFullScan() through engine.js's own ~90 call sites, actually gets the
// SAME protection — the contract could hold for the primitive and still be
// wired wrong for a specific caller (this session's own history — FR-704,
// FR-605 — is exactly that shape of bug: a mechanism that worked in
// isolation but had a real, unproven gap at a specific call site).
//
// posture/CLAUDE.md's "no throwing" convention means no ANNOTATOR naturally
// throws under a bad-but-realistic input, so there is no way to observe
// this end-to-end without actually injecting a fault. Node's built-in
// module-mocking (node:test's `mock.module`, gated behind
// --experimental-test-module-mocks) replaces a REAL posture module's
// export with a throwing stub BEFORE engine.js's own static import
// resolves it — the fault is injected at the module-registry level, not by
// modifying any production code, so this proves the REAL wiring, not a
// simulation of it.
//
// DELIBERATELY ONE SCENARIO PER FILE, NOT SEVERAL. `mock.module()`
// registrations bind at first resolution — once engine.js's own static
// import graph is resolved (which happens the moment runScan() is first
// awaited anywhere in this process), a SECOND mock.module() call on a
// different module already pulled into that graph has nothing left to
// intercept. Confirmed by direct experiment: a second test in this same
// file mocking a different posture module silently mocked nothing, and
// the first test's mock (still bound) fired instead — a real, load-bearing
// constraint of this technique, not a hypothetical one. The async-rejection
// half of FR-106's contract is already proven at the unit level in
// annotator-runner.test.js and is not re-proven here for that reason.
//
// WHY THIS FILE IS NOT IN ANY test:* SCOPED SCRIPT. run-unit-tests.mjs
// combines every scoped test:* script into ONE `node --test` invocation for
// speed — but that invocation does not carry
// --experimental-test-module-mocks, and adding it globally would let mock
// state leak across every other test file sharing that same process. This
// file is invoked as its own separate step in package.json's top-level
// "test" script instead, the exact precedent test/cpp-dataflow.test.js
// already established for AGENTIC_SECURITY_CPP_DATAFLOW=1. Running it
// directly (`node --experimental-test-module-mocks --test
// test/fault-injection.test.js`) works standalone too.

import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const FIXTURE = path.join(SCANNER, 'test', 'fixtures', 'vulnerable-js');

test('a real annotator that throws does not crash the scan — other findings still land, the error is captured by phase', async () => {
  // why-fired.js runs LAST (posture/CLAUDE.md) — a deliberate choice: a
  // fault injected here exercises every OTHER annotation stage's real
  // output surviving intact, not just an early stage that would leave most
  // of the pipeline unexercised.
  const modPath = path.join(SCANNER, 'src', 'posture', 'why-fired.js');
  mock.module(modPath, {
    exports: {
      annotateWhyFired: () => { throw new Error('FR-906 injected fault — this module should never actually throw in production'); },
    },
  });

  // D-0009 (this session's own decision log): a scan against a fixture
  // directory IN PLACE writes real .agentic-security/ state into it unless
  // state writes are explicitly disabled — the exact accumulation this
  // session spent multiple cycles diagnosing and wiping. This test scans
  // test/fixtures/vulnerable-js directly (mock.module's fault needs a real
  // runScan(), not an isolated copy), so it must not be one more source of
  // that pollution.
  setStateWritesEnabled(false);
  let scan;
  try {
    const { runScan } = await import(path.join(SCANNER, 'src', 'runScan.js'));
    ({ scan } = await runScan(FIXTURE, { network: false }));
  } finally {
    setStateWritesEnabled(true);
  }

  assert.ok((scan.findings || []).length > 0,
    'a fault in one late-stage annotator must not suppress findings every earlier stage already produced');
  assert.ok(Array.isArray(scan.annotatorErrors), 'annotatorErrors must be an array even when a fault was injected');
  const captured = scan.annotatorErrors.find(e => /FR-906 injected fault/.test(e.err));
  assert.ok(captured, `expected the injected fault to be captured in annotatorErrors, got: ${JSON.stringify(scan.annotatorErrors)}`);
  assert.equal(captured.phase, 'annotateWhyFired', 'the captured error must name the failing phase, not just "something failed"');
});
