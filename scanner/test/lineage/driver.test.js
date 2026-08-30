import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { FieldIdentitySummaryCache } from '../../src/lineage/summaries.js';

// Minimal hand-built callGraph fixture matching buildCallGraph's own
// output shape ({functions: Map<qid, fn>, resolveKnownCallee(name, callerFile)}) —
// isolates driver.js's own orchestration logic from real-parser/real-callgraph
// concerns (Task 3 covers those).
function fnRecord(qid, name, file, params = []) {
  return {
    qid, name, file, params,
    cfg: { entry: 'n0', exit: 'n1', nodes: {
      n0: { kind: 'entry', succ: ['n1'], pred: [] },
      n1: { kind: 'exit', succ: [], pred: ['n0'] },
    } },
  };
}

function handBuiltCallGraph(fns) {
  const functions = new Map(fns.map(fn => [fn.qid, fn]));
  const byFile = new Map();
  for (const fn of fns) {
    if (!byFile.has(fn.file)) byFile.set(fn.file, new Map());
    byFile.get(fn.file).set(fn.name, fn.qid);
  }
  return {
    functions,
    resolveKnownCallee(name, callerFile) {
      const local = byFile.get(callerFile);
      if (local && local.has(name)) return local.get(name);
      for (const m of byFile.values()) {
        if (m.has(name)) return m.get(name);
      }
      return null;
    },
  };
}

test('runFieldIdentityAnalysis produces one result per function in the call graph', () => {
  const fns = [
    fnRecord('a.js::f1@1', 'f1', 'a.js'),
    fnRecord('a.js::f2@2', 'f2', 'a.js'),
    fnRecord('b.js::f3@1', 'f3', 'b.js'),
  ];
  const callGraph = handBuiltCallGraph(fns);

  const { results, cache } = runFieldIdentityAnalysis(callGraph);

  assert.strictEqual(results.size, 3);
  assert.ok(results.has('a.js::f1@1'));
  assert.ok(results.has('a.js::f2@2'));
  assert.ok(results.has('b.js::f3@1'));
  assert.ok(cache instanceof FieldIdentitySummaryCache);
});

test('runFieldIdentityAnalysis handles an empty call graph gracefully', () => {
  const { results, cache } = runFieldIdentityAnalysis(handBuiltCallGraph([]));
  assert.strictEqual(results.size, 0);
  assert.strictEqual(cache.size(), 0);
});

test('runFieldIdentityAnalysis handles a null/undefined callGraph gracefully (no throw)', () => {
  const { results } = runFieldIdentityAnalysis(null);
  assert.strictEqual(results.size, 0);
});

test('runFieldIdentityAnalysis reuses a caller-supplied cache via opts.cache instead of creating a fresh one', () => {
  const fns = [fnRecord('a.js::f1@1', 'f1', 'a.js')];
  const callGraph = handBuiltCallGraph(fns);
  const suppliedCache = new FieldIdentitySummaryCache();

  const { cache } = runFieldIdentityAnalysis(callGraph, { cache: suppliedCache });

  assert.strictEqual(cache, suppliedCache);
});
