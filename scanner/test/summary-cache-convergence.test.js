// Stage 3 correctness audit (detection depth): three convergence bugs in
// the interprocedural summary-cache fixed-point machinery, all comparing
// two summaries' `mutatedParams` by SET SIZE instead of set MEMBERSHIP, so
// two same-cardinality-but-different-content sets were treated as "no
// change" — either causing a stale cached value to diverge from what was
// actually computed (summaries.js's _summaryEq), or causing the OUTER
// empty-entry pre-pass in engine.js's runTaintEngine to break one
// iteration early via an entirely separate bug: it used
// `summaryCache.size()` — a Map KEY COUNT — as its convergence signal.
// Every function gets a cache key on the FIRST iteration, so `.size()`
// jumps once and then never changes again (overwriting an existing Map
// key never changes `.size`), regardless of whether later iterations
// wrote real, different VALUES. MAX_FP_ITERS=3 promises 3 rounds of
// refinement; the bug silently delivered 2.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SummaryCache } from '../src/dataflow/summaries.js';
import { runScan } from '../src/runScan.js';

test('SummaryCache.compute(): a fixed-point iteration whose mutatedParams changes MEMBERSHIP (not size) is not mistaken for convergence', () => {
  // Simulates a recursive/depth-dependent helper whose mutated-target
  // identity flips between fixedpoint rounds (same set size throughout).
  // _summaryEq's old size-only comparison treated round 2 (fieldA) and
  // round 3 (fieldB) as equal once their sizes matched, so compute()'s
  // internal loop broke WITHOUT caching the fresher round-3 value — yet
  // still returned that fresher value to its own caller. Anyone else who
  // separately called .get() for the same qid+entry got the stale,
  // never-cached round-2 value instead — silently disagreeing with what
  // the original caller received.
  const cache = new SummaryCache();
  let call = 0;
  function analyze() {
    call++;
    if (call === 1) {
      // Trigger the recursion-detected path so compute()'s internal
      // fixed-point loop actually runs (`_hitRecursion` gets set).
      cache.compute('f', new Set(['x']), analyze);
    }
    const field = call % 2 === 0 ? 'fieldA' : 'fieldB';
    return { returnTainted: true, mutatedParams: new Set([field]), taintedGlobals: new Set(), findings: [] };
  }
  const returned = cache.compute('f', new Set(['x']), analyze);
  const cached = cache.get('f', new Set(['x']));
  assert.ok(cached, 'the summary must have been cached');
  assert.deepEqual([...returned.mutatedParams], [...cached.mutatedParams],
    `the summary returned to the original caller (${[...returned.mutatedParams]}) must match what a later ` +
    `cache.get() for the same qid+entry returns (${[...cached.mutatedParams]}) — they must never diverge`);
});

test('SummaryCache.compute(): mutatedParams with the SAME membership across rounds still converges (no infinite work, no false churn)', () => {
  const cache = new SummaryCache();
  let call = 0;
  function analyze() {
    call++;
    if (call === 1) cache.compute('g', new Set(['x']), analyze);
    return { returnTainted: true, mutatedParams: new Set(['stable']), taintedGlobals: new Set(), findings: [] };
  }
  const returned = cache.compute('g', new Set(['x']), analyze);
  assert.deepEqual([...returned.mutatedParams], ['stable']);
  // Convergence detection working correctly is what lets the loop `break`
  // early rather than always running the full FP_MAX rounds — assert it
  // didn't run more analyze() calls than the loop allows (1 initial +
  // FP_MAX=3 refinement rounds = 4 total, but the recursive re-entry from
  // call 1 adds one more nested call).
  assert.ok(call <= 5, `expected convergence to stop early, got ${call} analyze() calls`);
});

test('runTaintEngine empty-entry pre-pass: a 3-hop mutated-param propagation chain needs the full 3 fixed-point iterations, not 2', async () => {
  // Function names chosen so alphabetical qid order (aTop < bMid < cLeaf,
  // matching how fnList is sorted) is ALSO caller-before-callee at every
  // level — the worst case for this loop, since each pass processes a
  // caller before its callee has a chance to update THIS pass's summary,
  // so propagating a mutation from the leaf all the way up to the
  // outermost caller genuinely needs one pass per hop:
  //   pass 0: cLeaf computes mutatedParams={t3} (a real source, process.env).
  //   pass 1: bMid — now sees cLeaf's pass-0 summary — computes {t2}.
  //   pass 2: aTop — now sees bMid's pass-1 summary — computes {t1}.
  // The old size-only break fired after pass 1 (no NEW cache KEYS were
  // added, only an existing value changed), so pass 2 never ran and aTop's
  // cached summary stayed permanently empty.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-fp3-'));
  fs.writeFileSync(path.join(dir, 'app.js'), `
const cp = require('child_process');
const express = require('express');
const app = express();
function cLeaf(t3) { t3 = process.env.API_KEY; }
function bMid(t2) { cLeaf(t2); }
function aTop(t1) { bMid(t1); }
app.get('/run', (req, res) => {
  let obj;
  aTop(obj);
  cp.exec(obj);
});
`);
  const { scan } = await runScan(dir, { deep: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const cmdFindings = irFindings.filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    `expected the 3-hop mutation (cLeaf -> bMid -> aTop -> cp.exec(obj)) to fully propagate, got IR-TAINT findings: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});
