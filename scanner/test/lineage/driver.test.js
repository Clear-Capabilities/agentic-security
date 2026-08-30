import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { FieldIdentitySummaryCache, createCallGraphLookup, createCallSummaryResolver } from '../../src/lineage/summaries.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';

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

test('real, whole-project integration: three real files (a caller, a callee, and dead code nobody calls) all get a result, and the caller resolves the callee\'s real field identity (Sub-project B, increment 4)', () => {
  const sourceA = `
function outer(id) {
  const u = getUser(id);
  return u;
}
`;
  const sourceB = `
function getUser(userId) {
  return { email: userId, ssn: 'unrelated' };
}
`;
  const sourceC = `
function neverCalled(x) {
  return { note: x };
}
`;

  const irA = parseJsFile('/x/a.js', sourceA);
  const irB = parseJsFile('/x/b.js', sourceB);
  const irC = parseJsFile('/x/c.js', sourceC);
  assert.ok(irA && irB && irC, 'real parser must successfully parse all three files');

  const perFileIR = { '/x/a.js': irA, '/x/b.js': irB, '/x/c.js': irC };
  const callGraph = buildCallGraph(perFileIR, { '/x/a.js': sourceA, '/x/b.js': sourceB, '/x/c.js': sourceC });

  const { results, cache } = runFieldIdentityAnalysis(callGraph);

  // Every function in the project gets a result, including the one
  // nothing calls — a purely lazy, call-site-triggered scheme (B1-B3
  // alone) would never analyze `neverCalled` at all, since it's only ever
  // reached as a SIDE EFFECT of some caller's own call-site resolution.
  const outerFn = irA.functions.find(f => f.name === 'outer');
  const getUserFn = irB.functions.find(f => f.name === 'getUser');
  const neverCalledFn = irC.functions.find(f => f.name === 'neverCalled');
  assert.ok(results.has(outerFn.qid));
  assert.ok(results.has(getUserFn.qid));
  assert.ok(results.has(neverCalledFn.qid));
  // SECOND DEVIATION FROM THE PLAN'S LITERAL TEXT: the plan asserted
  // `results.size === 3`, assuming one function per file. Verified
  // empirically: `parseJsFile` emits a synthetic per-file `<module>`
  // top-level function record alongside each named function (e.g.
  // `/x/a.js::top::<module>@1` next to `/x/a.js::<module>::outer@2`), and
  // `buildCallGraph` includes those in `callGraph.functions` too — three
  // real files therefore produce SIX call-graph entries, not three. Rather
  // than hardcode that incidental count (which would silently drift if the
  // parser's synthetic-entry shape ever changes), assert against the
  // actual parsed function counts directly.
  assert.strictEqual(results.size, irA.functions.length + irB.functions.length + irC.functions.length);

  // DEVIATION FROM THE PLAN'S LITERAL TEXT (see this task's report for the
  // full writeup): the plan asserted `results.get(outerFn.qid).widenings
  // .length === 0` as the proof that the cross-file call to getUser
  // genuinely resolved, reasoning by analogy to increment B3's own fix
  // (assert on `widenings`, since a per-fact `widened` field doesn't
  // exist). That renaming fix is necessary but NOT sufficient here.
  // Verified empirically (not just by reading the code): running this
  // exact fixture through `runFieldIdentityAnalysis` against the REAL
  // callGraph, and again against a deliberately broken one
  // (`resolveKnownCallee: () => null`), produces the byte-identical
  // `{returnFacts: [], widenings: []}` for `outer` either way. The reason:
  // `runFieldIdentityAnalysis` (already-landed Task 2) analyzes every
  // function from a hardcoded `emptyState()` with no per-function
  // override, so `outer`'s own `id` parameter never carries any identity
  // in this driver run — `getUser(id)`'s argument is identity-less
  // regardless of whether the cross-file call resolves, and (per
  // engine.js's `call` case) a RESOLVED call and the UNRESOLVED-call
  // fallback both reduce to `{flat: empty, widened: false}` whenever the
  // argument itself carries no identity: the resolved branch returns
  // `widened: false` unconditionally, and the fallback branch's
  // `widened: flat.size > 0` is also false on an empty flat. So the
  // plan's literal assertion would pass identically whether or not
  // `createCallGraphLookup`/`buildCallGraph` correctly resolve the call —
  // it does not discriminate the thing this test exists to prove.
  //
  // Fixed by reusing the driver's own returned `cache` — its documented
  // contract explicitly returns it so a caller can reuse/inspect it
  // afterward — together with the SAME real `callGraph`, to re-analyze
  // `outer` one more time with a genuinely seeded identity on `id`. This
  // exercises the exact real cross-file resolution path
  // (`createCallGraphLookup` over `buildCallGraph`'s real output) the
  // driver itself used internally, now with an argument that actually
  // carries an identity, so a resolved vs. unresolved call genuinely
  // diverge. Verified empirically: swapping in a broken lookupCallee here
  // flips `widenings` from `[]` to a single `unresolved-call` entry on the
  // `u = getUser(id)` assignment, while `returnFacts` stays non-empty
  // either way (the identity still flows, just conservatively, when
  // unresolved) — confirming this assertion genuinely discriminates
  // real resolution from the widened fallback, unlike the plan's original
  // unseeded check above.
  const lookupCallee = createCallGraphLookup(callGraph, '/x/a.js');
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
  const seededEntryState = addIdentity(emptyState(), 'id', 'data:id');
  const reAnalyzedOuter = analyzeFunctionFieldIdentity(outerFn, seededEntryState, { resolveCallSummary });

  assert.strictEqual(reAnalyzedOuter.widenings.length, 0,
    'a correctly-resolved cross-file call must record no unresolved-call widening event');
  assert.strictEqual(reAnalyzedOuter.returnFacts.length, 1);
  assert.deepStrictEqual([...reAnalyzedOuter.returnFacts[0].identities], ['data:id'],
    'outer must return getUser\'s real, resolved field identity, not the generic widened unresolved-call fallback');
});

test('real, whole-project integration: two independent driver runs against the same call graph (fresh cache each time) produce identical results (determinism)', () => {
  const sourceA = `
function outer(id) {
  return getUser(id);
}
`;
  const sourceB = `
function getUser(userId) {
  return { email: userId };
}
`;
  const irA = parseJsFile('/y/a.js', sourceA);
  const irB = parseJsFile('/y/b.js', sourceB);
  const perFileIR = { '/y/a.js': irA, '/y/b.js': irB };
  const callGraph = buildCallGraph(perFileIR, { '/y/a.js': sourceA, '/y/b.js': sourceB });

  const run1 = runFieldIdentityAnalysis(callGraph);
  const run2 = runFieldIdentityAnalysis(callGraph);

  assert.strictEqual(run1.results.size, run2.results.size);
  for (const [qid, result1] of run1.results) {
    const result2 = run2.results.get(qid);
    assert.ok(result2, `expected qid ${qid} to be present in both runs`);
    assert.strictEqual(result1.widenings.length, result2.widenings.length);
    assert.strictEqual(result1.returnFacts.length, result2.returnFacts.length);
  }
});
