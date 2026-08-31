import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import {
  FieldIdentitySummaryCache, createCallGraphLookup, createCallSummaryResolver, summaryFromAnalysisResult,
} from '../../src/lineage/summaries.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';

// Counts how many times `FieldIdentitySummaryCache.compute()` invokes its
// `analyzeFn` argument, PER qid, by temporarily wrapping the class's own
// `compute` method (no source edits to summaries.js/driver.js needed — pure
// black-box instrumentation from the test file). Always restore the
// original method in a `finally`, since this class is a shared singleton
// import reused by every other test in this file (and, within the same
// `node --test` process, potentially other lineage test files too).
function instrumentComputeCallCounts() {
  const counts = new Map();
  const original = FieldIdentitySummaryCache.prototype.compute;
  FieldIdentitySummaryCache.prototype.compute = function (qid, entryState, analyzeFn) {
    const wrapped = (es) => {
      counts.set(qid, (counts.get(qid) ?? 0) + 1);
      return analyzeFn(es);
    };
    return original.call(this, qid, entryState, wrapped);
  };
  return {
    counts,
    restore() {
      FieldIdentitySummaryCache.prototype.compute = original;
    },
  };
}

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

// --- Sub-project B, increment 5, Task 2: real self-/mutually-recursive proof ---
//
// STEP 1 INVESTIGATION FINDING (empirical, via a temporary throwaway script,
// deleted before this commit — not the fixed script below): for THIS
// engine's current mechanics, a recursive function's refined vs. unrefined
// `returnFlat`/`mutatedParams` OUTPUT is byte-IDENTICAL through the real
// parser, across every shape tried — plain self-recursion (the plan's own
// literal `chain(user, depth)`-shaped suggestion), a 2-function mutual
// cycle, a 3-function cycle, and a function that self-calls TWICE within
// one return statement. Verified directly (not assumed) by temporarily
// forcing `FP_MAX` to `0` in `summaries.js` (reverted before this commit —
// `git diff` on that file is empty) and diffing the driver's real output
// against the FP_MAX=3 (committed) behavior: identical in every case.
//
// The reason, worked out by hand-tracing and confirmed by the experiment:
// `resolveCallSummary`'s calls are fully SYNCHRONOUS — a callee's own
// `compute()` (including any refinement rounds IT needed) always finishes
// completely before its result is used at the call site. So the first,
// un-refined DFS traversal of a recursive/cyclic call graph already
// incorporates every fact any deeper call could ever contribute; nothing a
// later refinement round resolves against was previously invisible to the
// union that already happened while unwinding. Combined with `returnFlat`
// being a flat, deduplicated `Set` of stable data-element id STRINGS (never
// a per-recursion-depth-distinct value, unlike Task 1's own hand-built
// mock `analyzeFn`, which fabricated a fresh string per round specifically
// to make growth observable in isolation) — union with an already-present
// identity is a no-op — round 2 of a real recursive function's own
// analysis reproduces exactly what round 1 already established. This is a
// property of the CURRENT feature set specifically: `mutatedParams` is
// never propagated from a callee back onto a caller's own state during
// analysis (`applyAtCallSite` exists but is not wired into `engine.js`'s
// `step()` — grep confirms zero call sites outside its own tests), and
// `returnByPath` is never populated (`summaryFromAnalysisResult` always
// writes `new Map()`), so neither channel can carry recursion-depth-
// dependent structure either. A future increment that changes either of
// those could reopen room for genuine, visible growth — this is not a
// claim that refinement is inherently unobservable, only that it is not
// observable in OUTPUT with what this package can express today.
//
// Per this task's own instructions, an honest negative output-level result
// does not mean "skip testing" — it means fall back to a MECHANISM-level
// assertion that genuinely discriminates refined from unrefined behavior.
// `instrumentComputeCallCounts()` (top of this file) proves that exact
// thing: wrapping `compute()`'s `analyzeFn` argument to count invocations
// per qid, run through the unmodified real driver, shows the refinement
// loop actually re-invokes `analyzeFn` a second time once recursion is
// detected — confirmed genuinely discriminating by the same temporary
// FP_MAX=0 experiment above: with refinement disabled the count is
// exactly 1 for the recursive qid (only the initial pass), with the
// committed FP_MAX=3 code it is exactly 2 (the initial pass plus one
// refinement round, which then converges and stops). An assertion that
// `analyzeFn` was invoked more than once for the recursive qid therefore
// would NOT pass if Task 1's refinement code were absent — unlike an
// output-only assertion here, which (per the finding above) would pass
// identically either way.

test('B5: self-recursion — the real driver genuinely runs the bounded refinement loop for a self-recursive JS/TS function (mechanism-level proof; see the comment above for why an output-level assertion here would be vacuous)', () => {
  const source = `
function chain(user, other, depth) {
  if (depth <= 0) return {};
  return { v: other.secret, next: chain(user, other, depth - 1) };
}
`;
  const ir = parseJsFile('/rec1/a.js', source);
  assert.ok(ir, 'real parser must successfully parse the self-recursive source');
  const callGraph = buildCallGraph({ '/rec1/a.js': ir }, { '/rec1/a.js': source });
  const chainFn = ir.functions.find(f => f.name === 'chain');
  assert.ok(chainFn, 'the real parser must produce a function record for chain');

  const { counts, restore } = instrumentComputeCallCounts();
  let results, cache;
  try {
    ({ results, cache } = runFieldIdentityAnalysis(callGraph));
  } finally {
    restore();
  }

  // Mechanism: refinement genuinely re-ran analyzeFn beyond the initial
  // pass, bounded by FP_MAX=3 (1 initial + at most 3 refinement rounds).
  const chainCallCount = counts.get(chainFn.qid) ?? 0;
  assert.ok(chainCallCount > 1,
    `analyzeFn must be re-invoked at least once beyond the initial pass for the self-recursive qid through the real driver; got ${chainCallCount} call(s)`);
  assert.ok(chainCallCount <= 4, `must stay BOUNDED (1 initial + FP_MAX=3); got ${chainCallCount} calls`);

  // Safety: the recursion guard stack is always fully unwound, and the
  // driver's whole-project pass produced a real, non-crashing, non-
  // "_recursive"-flagged final summary for the recursive function.
  assert.equal(cache._stack.size, 0, 'the recursion guard stack must be fully unwound after the driver run');
  assert.ok(results.has(chainFn.qid));
  const cachedSummary = cache.get(chainFn.qid, emptyState());
  assert.ok(cachedSummary, 'the driver must have cached a real summary for the recursive function');
  assert.ok(!cachedSummary._recursive, 'the FINAL cached summary must never carry the transient bottom-stub marker');

  // Content sanity (not the discriminating assertion — see the comment
  // above): re-analyzing with a seeded identity via the driver's own real
  // cache/lookupCallee (the established pattern this file's own increment
  // B4 test uses) confirms the recursive call genuinely resolves to real
  // facts, not a silently-empty result.
  const lookupCallee = createCallGraphLookup(callGraph, '/rec1/a.js');
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
  const seededEntryState = addIdentity(emptyState(), 'other', 'data:secret');
  const reAnalyzed = analyzeFunctionFieldIdentity(chainFn, seededEntryState, { resolveCallSummary });
  assert.deepStrictEqual([...reAnalyzed.returnFacts.flatMap(rf => [...rf.identities])].sort(), ['data:secret'],
    'the recursive function must resolve real field identity, not a silently-empty bottom stub');
});

test('B5: mutual recursion — the real driver genuinely runs the bounded refinement loop for a 2-function mutually-recursive JS/TS cycle (mechanism-level proof)', () => {
  const source = `
function ping(x, n) {
  if (n <= 0) return {};
  return { p: x.a, viaB: pong(x, n - 1) };
}
function pong(x, n) {
  if (n <= 0) return {};
  return { q: x.b, viaA: ping(x, n - 1) };
}
`;
  const ir = parseJsFile('/rec2/a.js', source);
  assert.ok(ir, 'real parser must successfully parse the mutually-recursive source');
  const callGraph = buildCallGraph({ '/rec2/a.js': ir }, { '/rec2/a.js': source });
  const pingFn = ir.functions.find(f => f.name === 'ping');
  const pongFn = ir.functions.find(f => f.name === 'pong');
  assert.ok(pingFn && pongFn, 'the real parser must produce function records for both ping and pong');

  const { counts, restore } = instrumentComputeCallCounts();
  let results, cache;
  try {
    ({ results, cache } = runFieldIdentityAnalysis(callGraph));
  } finally {
    restore();
  }

  // Mechanism: BOTH functions in the mutually-recursive pair genuinely got
  // refined beyond their initial pass, bounded by FP_MAX=3.
  const pingCallCount = counts.get(pingFn.qid) ?? 0;
  const pongCallCount = counts.get(pongFn.qid) ?? 0;
  assert.ok(pingCallCount > 1, `ping's analyzeFn must be re-invoked beyond the initial pass; got ${pingCallCount} call(s)`);
  assert.ok(pongCallCount > 1, `pong's analyzeFn must be re-invoked beyond the initial pass; got ${pongCallCount} call(s)`);
  assert.ok(pingCallCount <= 4 && pongCallCount <= 4, `must stay BOUNDED (1 initial + FP_MAX=3); got ping=${pingCallCount}, pong=${pongCallCount}`);

  // Safety: recursion guard stack fully unwound; both functions get a
  // real, non-crashing, non-"_recursive"-flagged final summary.
  assert.equal(cache._stack.size, 0, 'the recursion guard stack must be fully unwound after the driver run, even for a mutual cycle');
  assert.ok(results.has(pingFn.qid));
  assert.ok(results.has(pongFn.qid));
  const pingSummary = cache.get(pingFn.qid, emptyState());
  const pongSummary = cache.get(pongFn.qid, emptyState());
  assert.ok(pingSummary && !pingSummary._recursive, 'ping must get a real final summary, never the transient bottom-stub marker');
  assert.ok(pongSummary && !pongSummary._recursive, 'pong must get a real final summary, never the transient bottom-stub marker');

  // Content sanity: seeded re-analysis (same established pattern as above)
  // confirms both directions of the cycle resolve to real field identity.
  const lookupCallee = createCallGraphLookup(callGraph, '/rec2/a.js');
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
  let seededEntryState = addIdentity(emptyState(), 'x', 'data:a');
  seededEntryState = addIdentity(seededEntryState, 'x', 'data:b');
  const reAnalyzedPing = analyzeFunctionFieldIdentity(pingFn, seededEntryState, { resolveCallSummary });
  assert.deepStrictEqual([...reAnalyzedPing.returnFacts.flatMap(rf => [...rf.identities])].sort(), ['data:a', 'data:b'],
    'ping must resolve real field identity from both sides of the mutually-recursive cycle');
});

// --- Sub-project C, increment 3, Task 3, Step 5 (§13.7 item 17): opts.recordHop ---

// Canonicalizes a raw analyzeFunctionFieldIdentity result the same way
// engine-provenance.test.js/engine-provenance-interprocedural.test.js do
// (duplicated here rather than imported, since neither exports a
// test-support surface — matching this repo's own established precedent).
function canonicalizeStateMap(map) {
  return [...map.entries()]
    .map(([path, ids]) => [path, [...ids].sort()])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}
function canonicalizeReturnFacts(returnFacts) {
  return returnFacts
    .map((f) => ({ nodeId: f.nodeId, line: f.line, identities: [...f.identities].sort() }))
    .sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
}
function canonicalizeWidenings(widenings) {
  return widenings
    .map((w) => ({ ...w, dataElementIds: [...w.dataElementIds].sort() }))
    .map((w) => JSON.stringify(w, Object.keys(w).sort()))
    .sort();
}
function canonicalizeResult({ exitState, returnFacts, mutatedParams, widenings }) {
  return {
    exitState: canonicalizeStateMap(exitState),
    returnFacts: canonicalizeReturnFacts(returnFacts),
    mutatedParams: canonicalizeStateMap(mutatedParams),
    widenings: canonicalizeWidenings(widenings),
  };
}

test('opts.recordHop (§13.7 item 14/17): threaded into every function\'s ctx across a real multi-file project without perturbing results, and hops genuinely span more than one file once identity is seeded through the driver\'s own cache/callGraph', () => {
  const sourceA = `
function outer(id) {
  const u = getUser(id);
  return u;
}
`;
  const sourceB = `
function getUser(userId) {
  return { email: userId };
}
`;
  const irA = parseJsFile('/drv-c3/a.js', sourceA);
  const irB = parseJsFile('/drv-c3/b.js', sourceB);
  assert.ok(irA && irB, 'real parser must successfully parse both files');
  const perFileIR = { '/drv-c3/a.js': irA, '/drv-c3/b.js': irB };
  const callGraph = buildCallGraph(perFileIR, { '/drv-c3/a.js': sourceA, '/drv-c3/b.js': sourceB });
  const outerFn = irA.functions.find((f) => f.name === 'outer');
  const getUserFn = irB.functions.find((f) => f.name === 'getUser');
  assert.ok(outerFn && getUserFn, 'expected outer (file A) and getUser (file B) in the parsed IR');

  // Half 1: opts.recordHop reaches EVERY function's ctx, across both files,
  // without throwing — and does not perturb any function's own result.
  // driver.js analyzes every function from emptyState() with no seeding
  // hook (no source registry yet — driver.js's own header comment), so no
  // hop content can fire from this call alone: this half proves the WIRING
  // is safe and complete, the same property engine-provenance-
  // interprocedural.test.js's own item-14 test already pins for a single
  // hand-built call graph, now against a REAL multi-file callGraph too.
  const raw = [];
  const { results: withRecorder, cache } = runFieldIdentityAnalysis(callGraph, { recordHop: (h) => raw.push(h) });
  assert.strictEqual(withRecorder.size, irA.functions.length + irB.functions.length,
    'every function across BOTH files was analyzed with the recorder-bearing ctx');

  const { results: withoutRecorder } = runFieldIdentityAnalysis(callGraph);
  const canon = (results) => [...results.entries()]
    .map(([qid, r]) => [qid, canonicalizeResult(r)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  assert.deepEqual(
    canon(withRecorder),
    canon(withoutRecorder),
    'omitting opts.recordHop must leave every function\'s analysis result byte-identical (Decision 7.2\'s "true by construction" property, extended to the driver)',
  );

  // Half 2: hops genuinely span more than one file. Reuses the driver's
  // own returned `cache` + a real `createCallGraphLookup`/
  // `createCallSummaryResolver` (the established content-sanity pattern
  // this file's own B4/B5 tests already use above) to re-analyze `outer`
  // with a genuinely seeded identity AND a recorder attached — proving
  // that once identity actually flows, the caller's hops (file A) and the
  // resolved callee's own hops (file B) both appear in the SAME recorder.
  const lookupCallee = createCallGraphLookup(callGraph, '/drv-c3/a.js');
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
  const seededEntryState = addIdentity(emptyState(), 'id', 'data:id');
  const hops = [];
  const reAnalyzed = analyzeFunctionFieldIdentity(outerFn, seededEntryState, { resolveCallSummary, recordHop: (h) => hops.push(h) });

  assert.strictEqual(reAnalyzed.returnFacts.length, 1);
  assert.deepStrictEqual([...reAnalyzed.returnFacts[0].identities], ['data:id'],
    'outer must resolve getUser\'s real, resolved field identity');

  const scopes = new Set(hops.map((h) => h.scope));
  assert.ok(scopes.has(outerFn.qid), 'caller\'s own hops (file A) appear');
  assert.ok(scopes.has(getUserFn.qid), 'the resolved callee\'s own hops (file B) appear — hops genuinely span more than one file');
});

// --- Sub-project E, increment 1: opts.seedEntryState + the cache-key fix ---
// Binding design: src/lineage/DESIGN_GRAPH_BUILDER.md §3.
//
// The property these three tests protect is the same one `opts.recordHop`
// established for this file: the hook is ADDITIVE, and omitting it leaves
// every observable output byte-identical. The guard is a hardcoded GOLDEN
// LITERAL, not a comparison against the shipped implementation — C3's own
// §13.2a lesson (comparing the shipped code against itself degenerates to
// `assert.deepEqual(x, x)`, a vacuous, always-passing test).

const E1_FILES = {
  '/e1/a.js': `
function outer(id) { const u = getUser(id); return u; }
function alone(x) { return x.email; }
`,
  '/e1/b.js': `
function getUser(id) { return { email: id.email, name: id.name }; }
function chain(v) { return chain(v); }
`,
};

function e1CallGraph() {
  const perFile = Object.fromEntries(
    Object.entries(E1_FILES).map(([f, src]) => [f, parseJsFile(f, src)]),
  );
  return buildCallGraph(perFile, E1_FILES);
}

test('E1/driver-1: omitting opts.seedEntryState leaves results AND cache keys byte-identical to a pre-hook golden literal', () => {
  const callGraph = e1CallGraph();
  const { results, cache } = runFieldIdentityAnalysis(callGraph, {});

  const canon = [...results.entries()]
    .map(([qid, r]) => [qid, canonicalizeResult(r)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  // Captured by running the PRE-hook `driver.js` (git HEAD at the time of
  // this increment) against these exact two files. Every function is
  // analyzed from `emptyState()`, so every result is empty — that IS the
  // measured 0-hop baseline Sub-project E exists to close, pinned here so a
  // future change to the hook cannot silently perturb the unseeded path.
  const GOLDEN_RESULTS = [
    ['/e1/a.js::<module>::alone@3', { exitState: [], returnFacts: [], mutatedParams: [], widenings: [] }],
    ['/e1/a.js::<module>::outer@2', { exitState: [], returnFacts: [], mutatedParams: [], widenings: [] }],
    ['/e1/a.js::top::<module>@1', { exitState: [], returnFacts: [], mutatedParams: [], widenings: [] }],
    ['/e1/b.js::<module>::chain@3', { exitState: [], returnFacts: [], mutatedParams: [], widenings: [] }],
    ['/e1/b.js::<module>::getUser@2', { exitState: [], returnFacts: [], mutatedParams: [], widenings: [] }],
    ['/e1/b.js::top::<module>@1', { exitState: [], returnFacts: [], mutatedParams: [], widenings: [] }],
  ];
  assert.deepEqual(canon, GOLDEN_RESULTS);

  // The cache-key half. `hashState(emptyState())` is the empty string, so
  // every unseeded function is still stored under `${qid}::` — exactly what
  // the pre-hook `cache.set(fn.qid, emptyState(), ...)` line produced.
  for (const qid of results.keys()) {
    assert.ok(cache.has(qid, emptyState()), `${qid} must still be cached under the empty-entry context when no hook is supplied`);
  }

  // And the hop stream is still empty, with and without a recorder.
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h) });
  assert.equal(hops.length, 0, 'no seeding hook => zero hops, unchanged');
});

test('E1/driver-2: the hook is real, opt-in, and per-function — a falsy return means "no seed for this function", never a throw', () => {
  const callGraph = e1CallGraph();
  const outerQid = '/e1/a.js::<module>::outer@2';
  const aloneQid = '/e1/a.js::<module>::alone@3';

  const seen = [];
  const { results, cache } = runFieldIdentityAnalysis(callGraph, {
    seedEntryState: (fn) => {
      seen.push(fn.qid);
      if (fn.qid !== aloneQid) return null; // falsy for every other function
      return addIdentity(emptyState(), 'x.email', 'data:seeded-email');
    },
  });

  assert.deepEqual([...seen].sort(), [...results.keys()].sort(),
    'the hook is consulted exactly once per function in the call graph');

  // The seeded function now genuinely carries identity — the guard above is
  // not vacuous.
  const alone = canonicalizeResult(results.get(aloneQid));
  assert.deepEqual(alone.returnFacts.map((f) => f.identities), [['data:seeded-email']],
    'the seeded function returns the seeded data element');

  // Every falsy-seeded function is byte-identical to the unseeded run.
  const baseline = runFieldIdentityAnalysis(e1CallGraph(), {});
  for (const qid of results.keys()) {
    if (qid === aloneQid) continue;
    assert.deepEqual(canonicalizeResult(results.get(qid)), canonicalizeResult(baseline.results.get(qid)),
      `${qid} got no seed, so it must be byte-identical to the unseeded run`);
  }
  assert.ok(cache.has(aloneQid, addIdentity(emptyState(), 'x.email', 'data:seeded-email')),
    'the seeded function is cached under the state it was actually analyzed under');
  assert.ok(!cache.has(aloneQid, emptyState()),
    'and NOT under the empty-entry context it was never analyzed under');
});

test('E1/driver-3: the cache-key fix, proven in BOTH directions — the pre-fix keying fabricates a data element at a call site nothing tainted', () => {
  // `aaa.js` sorts before `zzz.js`, so the SEEDED helper is analyzed and
  // cached first, and the clean caller resolves it from the cache.
  const files = {
    'aaa.js': 'function helper(req) { return req.body.secret; }',
    'zzz.js': 'function caller(o) { const v = helper(o); leak(v); }',
  };
  const perFile = Object.fromEntries(Object.entries(files).map(([f, src]) => [f, parseJsFile(f, src)]));
  const callGraph = buildCallGraph(perFile, files);
  const helperQid = [...callGraph.functions.values()].find((f) => f.name === 'helper').qid;
  const callerQid = [...callGraph.functions.values()].find((f) => f.name === 'caller').qid;
  const seededState = addIdentity(emptyState(), 'req.body.secret', 'data:SEEDED');
  const seedEntryState = (fn) => (fn.qid === helperQid ? seededState : null);

  // Direction 1 — THE MUTANT. A local replica of the driver's loop that
  // differs from the shipped one in exactly ONE character-level respect:
  // `cache.set` keys on `emptyState()` instead of the state actually
  // analyzed. That was the shipped line before this increment.
  const mutantCache = new FieldIdentitySummaryCache();
  const fnList = [...callGraph.functions.values()].sort((a, b) => (a.qid < b.qid ? -1 : 1));
  const mutantResults = new Map();
  for (const fn of fnList) {
    const resolveCallSummary = createCallSummaryResolver(mutantCache, createCallGraphLookup(callGraph, fn.file));
    const entryState = seedEntryState(fn) || emptyState();
    const r = analyzeFunctionFieldIdentity(fn, entryState, { resolveCallSummary });
    mutantResults.set(fn.qid, r);
    mutantCache.set(fn.qid, emptyState(), summaryFromAnalysisResult(r)); // <- the bug
  }
  assert.deepEqual(
    [...(mutantResults.get(callerQid).exitState.get('v') ?? [])],
    ['data:SEEDED'],
    'PRE-FIX: a clean call to helper() is handed the DRIVER\'s own seed — a fabricated identity at a call site nothing tainted',
  );

  // Direction 2 — the shipped driver, same inputs.
  const { results, cache } = runFieldIdentityAnalysis(callGraph, { seedEntryState });
  assert.deepEqual(
    [...(results.get(callerQid).exitState.get('v') ?? [])],
    [],
    'POST-FIX: the clean call resolves helper under an EMPTY callee entry state and correctly gets nothing',
  );
  const emptyKeyed = cache.get(helperQid, emptyState());
  assert.ok(emptyKeyed, 'helper is still cached under the empty-entry context (written by the lazy call-site compute)');
  assert.deepEqual([...emptyKeyed.returnFlat], [],
    'and that entry honestly says "nothing flows out of helper when nothing flows in"');
  assert.deepEqual([...cache.get(helperQid, seededState).returnFlat], ['data:SEEDED'],
    'while the seeded context keeps the real answer, under its own key');
});
