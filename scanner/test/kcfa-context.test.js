// FR-SEM-2 (roadmap #2) — value-context-sensitive summary cache + context cap.
//
// The cache computes a distinct summary per distinct entry-taint-state and
// bounds the number of NON-empty contexts kept per function. These tests
// pin that behavior directly (engine wiring is covered by interproc-k2 +
// the full gate).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SummaryCache } from '../src/dataflow/summaries.js';

const taintedSummary = { returnTainted: true, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [] };
const cleanSummary = { returnTainted: false, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [] };

test('distinct entry states produce distinct, independently-cached summaries', () => {
  const c = new SummaryCache();
  // empty entry → clean; tainted entry (param "x") → tainted. The cache keys
  // them separately, so the function is NOT collapsed to one result.
  const empty = c.compute('mod.js::f', new Set(), () => cleanSummary);
  const ctx = c.compute('mod.js::f', new Set(['x']), () => taintedSummary);
  assert.equal(empty.returnTainted, false);
  assert.equal(ctx.returnTainted, true);
  // Re-querying each context returns the memoized result (analyze not re-run).
  assert.equal(c.get('mod.js::f', new Set()).returnTainted, false);
  assert.equal(c.get('mod.js::f', new Set(['x'])).returnTainted, true);
});

test('context cap reuses the empty-entry summary once over budget', () => {
  const c = new SummaryCache();
  c._maxContextsPerFn = 2;
  // Seed the empty-entry base summary (the conservative fallback).
  c.compute('mod.js::g', new Set(), () => cleanSummary);
  // Two distinct non-empty contexts are allowed and computed fresh.
  assert.equal(c.compute('mod.js::g', new Set(['a']), () => taintedSummary).returnTainted, true);
  assert.equal(c.compute('mod.js::g', new Set(['b']), () => taintedSummary).returnTainted, true);
  // A third, NEW context is over budget → reuse the empty (clean) summary,
  // even though the analyze callback would have returned tainted.
  let analyzed = false;
  const third = c.compute('mod.js::g', new Set(['c']), () => { analyzed = true; return taintedSummary; });
  assert.equal(third.returnTainted, false, 'over-budget context must reuse the empty-entry summary');
  assert.equal(analyzed, false, 'analyze must not run for an over-budget context');
  assert.ok(c._contextCapHits >= 1);
  // An already-computed context is still served from cache (not capped).
  assert.equal(c.compute('mod.js::g', new Set(['a']), () => cleanSummary).returnTainted, true);
});

test('cap=0 disables context-sensitivity (pure monovariant)', () => {
  const c = new SummaryCache();
  c._maxContextsPerFn = 0;
  c.compute('mod.js::h', new Set(), () => cleanSummary);
  const ctx = c.compute('mod.js::h', new Set(['x']), () => taintedSummary);
  assert.equal(ctx.returnTainted, false, 'with cap=0 every non-empty context falls back to empty');
});

test('AGENTIC_SECURITY_KCFA_MAX_CONTEXTS env sets the cap', () => {
  const prev = process.env.AGENTIC_SECURITY_KCFA_MAX_CONTEXTS;
  process.env.AGENTIC_SECURITY_KCFA_MAX_CONTEXTS = '0';
  try {
    const c = new SummaryCache();
    assert.equal(c._maxContextsPerFn, 0);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_KCFA_MAX_CONTEXTS;
    else process.env.AGENTIC_SECURITY_KCFA_MAX_CONTEXTS = prev;
  }
});

test('clear() resets context bookkeeping', () => {
  const c = new SummaryCache();
  c._maxContextsPerFn = 1;
  c.compute('m::f', new Set(), () => cleanSummary);
  c.compute('m::f', new Set(['a']), () => taintedSummary);
  c.compute('m::f', new Set(['b']), () => taintedSummary); // over budget → cap hit
  assert.ok(c._contextCapHits >= 1);
  c.clear();
  assert.equal(c._contextCapHits, 0);
  assert.equal(c.size(), 0);
});
