// Sub-project E, increment 5 (E5), Task 2: end-to-end proof that
// AGENTIC_SECURITY_LINEAGE_DEEP=1 actually reaches runFullScan and produces
// scan.lineageGraph, through the real public entry point (runScan), not
// runFullScan directly.
//
// Calling convention verified against test/state-dir.test.js and
// src/runScan.js directly (NOT the plan's own literal draft, which assumed
// `runScan(null, { fileContents, scanRoot })` and a bare `scan` return
// value — both wrong):
//   - Imported from `../src/runScan.js`, matching test/state-dir.test.js's
//     own established pattern (`src/index.js` also re-exports `runScan`,
//     so either specifier resolves the same function — this file just
//     follows the existing test-suite convention).
//   - `runScan(rootDir, opts)` resolves `scanRoot` internally from the
//     POSITIONAL `rootDir` argument (`path.resolve(rootDir)`); there is no
//     `opts.scanRoot` read anywhere in runScan.js, so passing one is
//     silently ignored. `rootDir` must be a real path string —
//     `path.resolve(null)` throws `TypeError: The "paths[0]" argument must
//     be of type string`.
//   - `runScan` returns `{ scan, meta }`, not the scan object itself.
//   - `opts.fileContents` IS honored (it short-circuits the tree walk and
//     sets `completeScan = false`), exactly as the plan assumed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { validateGraph } from '../src/lineage/validate.js';

function mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-lineage-wiring-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"t","version":"1.0.0"}');
  return root;
}

test('E5/wiring-1: AGENTIC_SECURITY_LINEAGE_DEEP=1 produces a real, validateGraph()-clean scan.lineageGraph', async () => {
  const prev = process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1';
  const dir = mkTmpProject();
  try {
    const fileContents = { 'app.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" };
    const { scan } = await runScan(dir, { fileContents });
    assert.ok(scan.lineageGraph, 'scan.lineageGraph must be populated when the env var is set');
    assert.deepEqual(validateGraph(scan.lineageGraph).errors, []);
    assert.equal(scan.lineageStatus.requested, true);
    assert.equal(scan.lineageStatus.enabled, true);
    assert.equal(scan.lineageStatus.failure, null);
    assert.equal(scan.scanHealth.lineageAnalysis.requested, true);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
    else process.env.AGENTIC_SECURITY_LINEAGE_DEEP = prev;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('E5/wiring-2: without the env var, scan.lineageGraph is null and scanHealth.lineageAnalysis reports requested:false — zero behavior change for an ordinary scan', async () => {
  const prev = process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  const dir = mkTmpProject();
  try {
    const fileContents = { 'app.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" };
    const { scan } = await runScan(dir, { fileContents });
    assert.equal(scan.lineageGraph, null);
    assert.equal(scan.lineageStatus.requested, false);
    assert.equal(scan.scanHealth.lineageAnalysis.requested, false);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
    else process.env.AGENTIC_SECURITY_LINEAGE_DEEP = prev;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('E5/wiring-3: AGENTIC_SECURITY_LINEAGE_DEEP=1 alone (AGENTIC_SECURITY_DEEP unset) still produces a graph — the independent-gating ruling, proven live', async () => {
  const prevLineage = process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1';
  delete process.env.AGENTIC_SECURITY_DEEP;
  const dir = mkTmpProject();
  try {
    const fileContents = { 'app.js': "function h(res){ res.send('x'); }" };
    const { scan } = await runScan(dir, { fileContents });
    assert.ok(scan.lineageGraph, 'lineage must build even though deep mode was never requested');
  } finally {
    if (prevLineage === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP; else process.env.AGENTIC_SECURITY_LINEAGE_DEEP = prevLineage;
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Sub-project E, increment 5, final-review nitpick N-5: the lineage-timeout
// info-finding branch (engine.js, `_lr.elapsedMs > _lineageBudgetMs`) had no
// test coverage at all — this forces it live with a NEGATIVE budget, which
// any real build exceeds even when Date.now()'s millisecond resolution
// measures elapsedMs as 0 (a real, reproduced flake at budget=0: this test
// running warm, after wiring-1/2/3 already JIT-warmed the same code path in
// the same process, sometimes measures elapsedMs===0, and 0 > 0 is false —
// a negative budget makes the comparison true regardless of clock
// resolution, so this assertion no longer races the clock).
test('E5/wiring-4: AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS=-1 forces the over-budget branch, emitting an info finding — mirrors deep mode\'s own ir-taint-timeout finding shape', async () => {
  const prevLineage = process.env.AGENTIC_SECURITY_LINEAGE_DEEP;
  const prevTimeout = process.env.AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS;
  process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1';
  process.env.AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS = '-1';
  const dir = mkTmpProject();
  try {
    const fileContents = { 'app.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" };
    const { scan } = await runScan(dir, { fileContents });
    // The build must still succeed (budget is measured, not enforced by
    // interruption) — only the info finding is new.
    assert.ok(scan.lineageGraph, 'an over-budget build still completes and produces a graph');
    const timeoutFindings = (scan.findings || []).filter(f => typeof f.id === 'string' && f.id.startsWith('lineage-timeout:'));
    assert.equal(timeoutFindings.length, 1, `expected exactly one lineage-timeout finding, got: ${JSON.stringify(scan.findings?.map(f => f.id))}`);
    const f = timeoutFindings[0];
    assert.equal(f.severity, 'info');
    assert.equal(f.parser, 'LINEAGE');
  } finally {
    if (prevLineage === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_DEEP; else process.env.AGENTIC_SECURITY_LINEAGE_DEEP = prevLineage;
    if (prevTimeout === undefined) delete process.env.AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS; else process.env.AGENTIC_SECURITY_LINEAGE_TIMEOUT_MS = prevTimeout;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
