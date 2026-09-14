// Adversarial-premortem remediation on SARD_80_F1_SCANNER_PRD.md's own
// scoring infrastructure: macro-F1 (bench/sard/scripts/macro-score.mjs) is
// an unweighted mean over CWE rows, so a CWE with a handful of expected
// instances (binary 0-or-1 F1) carries the same 1/N weight as one with
// hundreds, with no visibility into how much of the headline number rests
// on that. `macroF1MinSupport` adds a supplementary figure restricted to
// CWEs with >=MIN_SUPPORT expected instances, mirroring the MIN_SUPPORT=5
// floor `compare-baseline.mjs` already applies to per-CWE regression deltas.
//
// A prior version of this finding claimed `perCweTable`'s `tp===0 && fn===0
// ? 1 : 0` branch was a live inflation bug (a CWE with zero expected
// instances defaulting to a perfect F1). Traced against how `perCwe` is
// actually built in both bench-realworld.js and score-php.mjs
// (`(perCwe[cwe] ??= {tp:0,fp:0,fn:0})[k]++` — an entry is only ever
// created by incrementing one of its own fields), that branch is dead code:
// an existing entry can never have tp=fn=fp=0 simultaneously. Not
// re-litigated here; this file tests the real, surviving fix instead.
//
// Also fixes an unguarded top-level `main()` in macro-score.mjs (the same
// bug class the 0.151.1 changelog fixed in bench-realworld.js/
// leakage-audit.mjs, missed here) — without the `import.meta.url` guard,
// this very import would have run the full CLI (read stdin, write report
// files) as a side effect.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { f1, perCweTable, macroF1, macroF1MinSupport } from '../../bench/sard/scripts/macro-score.mjs';

test('f1: harmonic mean, zero when both precision and recall are zero', () => {
  assert.equal(f1(0, 0), 0);
  assert.equal(f1(1, 1), 1);
  assert.equal(f1(1, 0), 0);
});

test('perCweTable: an entry can never be constructed with tp=fn=fp=0 (documents the invariant macroF1MinSupport relies on)', () => {
  // Every real perCwe entry comes from `(perCwe[cwe] ??= {tp:0,fp:0,fn:0})[k]++`,
  // so this is the closest a hand-built fixture can get to the "zero support"
  // shape without literally being impossible to produce from real scan data.
  const rows = perCweTable({ 'CWE-1': { tp: 0, fp: 0, fn: 0 } });
  // The dead branch still computes precision=1/recall=1/f1=1 for an
  // explicitly hand-built {0,0,0} row — asserting that here, not because
  // it's reachable from real data, but so a future refactor that removes
  // the branch does so deliberately rather than by accident.
  assert.deepEqual(rows[0], { cwe: 'CWE-1', tp: 0, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1, support: 0 });
});

test('macroF1MinSupport: excludes CWEs below the support floor and reports them', () => {
  const rows = perCweTable({
    'CWE-89': { tp: 40, fp: 5, fn: 10 },   // support 50, real signal
    'CWE-90': { tp: 0, fp: 0, fn: 200 },   // support 200, real signal (total miss)
    'CWE-1004': { tp: 0, fp: 0, fn: 1 },   // support 1 — should be excluded
    'CWE-1275': { tp: 1, fp: 0, fn: 0 },   // support 1 — should be excluded
  });
  const result = macroF1MinSupport(rows, 5);
  assert.equal(result.cweCount, 2);
  assert.equal(result.excludedCwes.length, 2);
  assert.deepEqual(new Set(result.excludedCwes.map(c => c.cwe)), new Set(['CWE-1004', 'CWE-1275']));
  // The eligible-only macro-F1 must equal the plain mean of just the two
  // high-support rows, not all four.
  const highSupportRows = rows.filter(r => r.support >= 5);
  assert.equal(result.value, macroF1(highSupportRows));
});

test('macroF1MinSupport: value is null (not 0) when every CWE is below the support floor, distinguishing "no eligible data" from "measured and zero"', () => {
  const rows = perCweTable({ 'CWE-1': { tp: 0, fp: 0, fn: 2 } });
  const result = macroF1MinSupport(rows, 5);
  assert.equal(result.value, null);
  assert.equal(result.cweCount, 0);
  assert.equal(result.excludedCwes.length, 1);
});

test('macroF1MinSupport: no excluded CWEs when every row already meets the floor', () => {
  const rows = perCweTable({ 'CWE-89': { tp: 10, fp: 0, fn: 0 } });
  const result = macroF1MinSupport(rows, 5);
  assert.equal(result.excludedCwes.length, 0);
  assert.equal(result.value, 1);
});

// PRD §9.4 "Separate score-only delta from scanner delta" — CLI-level test:
// macro-score.mjs's `scorerDelta` field is built from bench-realworld.js's
// `legacyScoring` (see that file's `scoreLegacy` for the full rationale).
// This proves the WIRING end to end: given a synthetic bench-realworld.js
// --json shape carrying `legacyScoring`, macro-score.mjs must report a
// scorerDelta whose rawOldScorer is strictly worse than rescoredSameFindings
// when the legacy scorer's perCwe reflects fewer TPs than the current one —
// exactly the C# LDAP scenario this diagnostic exists to make visible.
test('macro-score.mjs CLI: emits scorerDelta when the input carries legacyScoring, with rawOldScorer computed independently from the primary macroF1', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'macro-score-scorer-delta-'));
  const input = {
    results: [{
      name: 'sard-juliet-csharp-strict', language: 'csharp', scanned: 10,
      elapsedSec: 1, tp: 5, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1,
      // Current (flow-aware) scorer: CWE90 fully detected.
      perCwe: { 'CWE90': { tp: 5, fp: 0, fn: 0 } },
      tps: [], fps: [],
      // Legacy (strict) scorer, SAME underlying scan: the flow-aware credit
      // reverts to FN+FP — a worse number, purely from scoring methodology.
      legacyScoring: {
        tp: 0, fp: 5, fn: 5, precision: 0, recall: 0, f1: 0,
        perCwe: { 'CWE90': { tp: 0, fp: 5, fn: 5 } },
      },
    }],
  };
  const inputPath = path.join(dir, 'input.json');
  fs.writeFileSync(inputPath, JSON.stringify(input));
  const SCRIPT = path.join(import.meta.dirname, '..', '..', 'bench', 'sard', 'scripts', 'macro-score.mjs');
  const out = execFileSync(process.execPath, [SCRIPT, '--input', inputPath], { encoding: 'utf8', cwd: dir });
  const reportPath = path.join(dir, 'reports', 'latest.json');
  // macro-score.mjs resolves REPORTS_DIR relative to its OWN location, not
  // cwd — read the real committed reports dir instead of assuming `dir`.
  const realReportPath = path.join(import.meta.dirname, '..', '..', 'bench', 'sard', 'reports', 'latest.json');
  const report = JSON.parse(fs.readFileSync(realReportPath, 'utf8'));
  const app = report.apps[0];
  assert.ok(app.scorerDelta, 'expected scorerDelta to be present');
  assert.equal(app.scorerDelta.rawOldScorer, 0);
  assert.equal(app.scorerDelta.rescoredSameFindings, 1);
  assert.equal(app.scorerDelta.scannerAfterChange, app.scorerDelta.rescoredSameFindings);
  assert.match(out, /macroF1/); // sanity: the CLI actually ran, not just imported
});
