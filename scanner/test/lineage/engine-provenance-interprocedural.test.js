// Sub-project C, increment C3 — INTERPROCEDURAL hop recording, permanent
// coverage against the SHIPPED implementation.
//
// See scanner/src/lineage/DESIGN_PATH_PROVENANCE.md §13 — the binding
// design this file proves against real, parsed JS/TS code, using the real
// exported functions (never local reimplementations, unlike this design's
// own PoC file, `engine-provenance-interprocedural-poc.test.js`, which
// prototyped these signatures locally because the shipped code didn't
// exist yet). §13.7 is the exact file/line/signature checklist this test
// file proves was correctly wired: `engine.js` items 1-5 (the `context`
// field, the `stepCtx` stamping, `case 'call'` forwarding the full `ctx`
// as resolveCallSummary's 4th argument, `peerScope`/`peerContext` on the
// `call-resolved` hop), `summaries.js` items 6-10 (`entryStateFromCall`'s
// recorder-only derivation, `createCallSummaryResolver`'s `call-arg-bind`
// hop emission and hole-3 fix, the return-direction `resolvedQid`/
// `resolvedContext` wrapper), and `driver.js` item 14 (`opts.recordHop`
// threading).
//
// THE SINGLE MOST IMPORTANT TEST HERE is the golden-baseline regression
// (item 15b, near the end of this file): DESIGN_PATH_PROVENANCE.md §13.2a
// documents a fix round where the design's first draft forwarded the FULL
// ctx at the hole-2 site (`entryStateFromCall`) instead of a recorder-only
// derivation, which silently changed analysis RESULTS (with no recorder
// attached anywhere) in the unsound direction under a tight B6 context
// cap. The two golden tests below pin the SHIPPED wiring's output against
// a hardcoded literal (not a comparison against "the shipped resolver" —
// once this file's own imports ARE the shipped resolver, a live
// comparison degenerates into `assert.deepEqual(result, result)`, which
// would never catch a regression here).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { analyzeFunctionFieldIdentity } from '../../src/lineage/engine.js';
import {
  FieldIdentitySummaryCache,
  createCallSummaryResolver,
  summaryFromAnalysisResult,
} from '../../src/lineage/summaries.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';

// ---------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------

function parseFns(src, file) {
  const ir = parseJsFile(file, src);
  assert.ok(ir, 'real parser must parse this fixture source');
  const byName = {};
  for (const fn of ir.functions) byName[fn.name] = fn;
  return byName;
}

function lookupCalleeFor(byName) {
  return (calleeExpr) => {
    if (!calleeExpr || calleeExpr.kind !== 'ident') return null;
    const fn = byName[calleeExpr.name];
    return fn ? { qid: fn.qid, fn } : null;
  };
}

// Decision 8: the worklist re-emits a hop once per node VISIT, not once
// per program point — duplicates are exact repeats, so tests must assert
// on the deduplicated set. Same helper `engine-provenance.test.js`/the C3
// PoC both use (JSON over sorted keys).
function dedupeHops(hops) {
  const seen = new Map();
  for (const h of hops) seen.set(JSON.stringify(h, Object.keys(h).sort()), h);
  return [...seen.values()];
}

// Canonicalizes a Map<path, Set<id>> into a sorted, iteration-order-
// independent array-of-arrays. Mirrors engine-provenance.test.js's own
// helper of the same name (duplicated here rather than imported, since
// that file exports no test-support surface of its own).
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

// Decision 1's write-only invariant, made mechanically checkable: the FULL
// analysis result — exitState, returnFacts, mutatedParams, widenings —
// canonicalized into a Map/Set-iteration-order-independent, JSON-comparable
// shape, so two runs (with/without a recorder attached) can be
// `assert.deepEqual`-ed directly.
function canonicalizeResult({ exitState, returnFacts, mutatedParams, widenings }) {
  return {
    exitState: canonicalizeStateMap(exitState),
    returnFacts: canonicalizeReturnFacts(returnFacts),
    mutatedParams: canonicalizeStateMap(mutatedParams),
    widenings: canonicalizeWidenings(widenings),
  };
}

// ---------------------------------------------------------------------
// 1. The argument -> parameter binding hop (§13.2), against shipped
//    entryStateFromCall/createCallSummaryResolver.
// ---------------------------------------------------------------------

test('argument -> parameter binding hop (§13.2): a real 2-function fixture emits write-out/call-arg-bind with the correct toPath/dataElementId, and identity resolution is unaffected whether or not a recorder is attached', () => {
  const src = `
    function callee(u) { return u.email; }
    function caller(a) { return callee(a); }
  `;
  const byName = parseFns(src, '/x/c3-bind.js');
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');

  const raw = [];
  const withRecorder = analyzeFunctionFieldIdentity(byName.caller, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(), lookupCalleeFor(byName)),
    recordHop: (h) => raw.push(h),
  });
  const hops = dedupeHops(raw);

  assert.deepEqual([...withRecorder.returnFacts[0].identities], ['data:email'], 'the resolved call really does carry the identity end to end');

  const binds = hops.filter((h) => h.kind === 'write-out' && h.subKind === 'call-arg-bind');
  assert.equal(binds.length, 1, `expected exactly one call-arg-bind hop, got shapes: ${JSON.stringify(hops.map((h) => `${h.kind}/${h.subKind}`))}`);
  const bind = binds[0];

  // Decision 4: a real, non-null dataElementId, never a Set.
  assert.equal(typeof bind.dataElementId, 'string');
  assert.equal(bind.toPath, 'u.email', 'the exact path written, never the coarse `u` (§10.2\'s granularity rule, extended to the call boundary)');
  assert.equal(bind.dataElementId, 'data:email');
  assert.equal(bind.fromPath, null, 'the argument\'s own in-halves already carry the contributing keys (Decision 6) — this out-half never re-derives them');
  assert.equal(bind.lossReason, null);
  assert.equal(bind.widenReason, null);
  assert.equal(bind.peerScope, byName.callee.qid, 'toPath lives in the CALLEE\'s namespace; without peerScope it would collide with any caller-local `u`');
  assert.equal(typeof bind.peerContext, 'string');
  assert.equal(bind.scope, byName.caller.qid, 'the bind hop is stamped with the CALLER\'s scope, which is what lets it join with the argument\'s own in-half');
  assert.equal(typeof bind.context, 'string');

  // The join, proven: the argument's own production/ident in-half shares
  // (scope, nodeId, dataElementId, context) with the bind out-half.
  const argIn = hops.find(
    (h) => h.kind === 'production' && h.subKind === 'ident'
      && h.dataElementId === 'data:email' && h.fromPath === 'a.email'
      && h.nodeId === bind.nodeId,
  );
  assert.ok(argIn, `expected the argument's own contributing-key in-half at the same node, got ${JSON.stringify(hops.filter((h) => h.nodeId === bind.nodeId))}`);
  assert.equal(argIn.scope, bind.scope);
  assert.equal(argIn.context, bind.context);

  // Identity resolution itself is unaffected by whether a recorder is
  // attached (Decision 1's zero-behaviour-change bar), for this exact
  // fixture.
  const withoutRecorder = analyzeFunctionFieldIdentity(byName.caller, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(), lookupCalleeFor(byName)),
  });
  assert.deepEqual(
    canonicalizeResult(withoutRecorder),
    canonicalizeResult(withRecorder),
    'attaching a recorder must not change the observable analysis result',
  );
});

// ---------------------------------------------------------------------
// 2. The two-hole-closure proof (§13.1 hole 1 + §13.7 hole 3): a 3-function
//    resolved chain, through a real cache + hand-built lookupCallee.
// ---------------------------------------------------------------------

test('two-hole-closure (§13.1/§13.7): hops recorded INSIDE inner\'s own analysis, two resolved hops deep, are visible in the top-level outer recorder', () => {
  const CHAIN_SRC = `
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `;
  const byName = parseFns(CHAIN_SRC, '/x/c3-closure.js');
  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCalleeFor(byName));

  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.email', 'data:email');

  const raw = [];
  const result = analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary,
    recordHop: (h) => raw.push(h),
  });
  const hops = dedupeHops(raw);

  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'the analysis result still resolves the two-hop chain, unperturbed by hop recording');

  const scopes = new Set(hops.map((h) => h.scope));
  assert.ok(scopes.has(byName.outer.qid), 'outer\'s own hops still appear');
  assert.ok(scopes.has(byName.middle.qid), 'middle\'s own hops now appear (hole 3 closed)');
  assert.ok(scopes.has(byName.inner.qid), 'inner\'s own hops now appear — two resolved hops deep (holes 1+3 closed)');

  // The specific hop the design names: inner's `u.email` selection.
  const innerHops = hops.filter((h) => h.scope === byName.inner.qid);
  const innerRead = innerHops.find(
    (h) => h.kind === 'selection' && h.subKind === 'member'
      && h.fromPath === 'u.email' && h.dataElementId === 'data:email',
  );
  assert.ok(innerRead, `expected inner's own selection/member hop from 'u.email', got ${JSON.stringify(innerHops)}`);

  // §7.2's spread-order rule, proven: the CALLEE's stamps win over the
  // caller's, even though the record physically flows out through the
  // caller's already-stamped recordHop.
  assert.equal(innerRead.scope, byName.inner.qid, 'the callee\'s scope overrides the caller\'s (§7.2 spread order)');
  assert.notEqual(innerRead.nodeId, undefined);
  assert.equal(typeof innerRead.context, 'string');
  assert.notEqual(
    innerRead.context,
    hops.find((h) => h.scope === byName.outer.qid).context,
    'inner runs under its OWN entry context, not the caller\'s',
  );

  // The stitch is complete: inner's write-out/return joins the caller side
  // via middle's own production/call-resolved hop, which now carries
  // peerScope/peerContext naming inner (§13.2c, §13.7 item 5).
  assert.ok(innerHops.some((h) => h.kind === 'write-out' && h.subKind === 'return'), 'inner\'s function-exit marker is recorded');
  const middleCallResolved = hops.filter((h) => h.scope === byName.middle.qid && h.kind === 'production' && h.subKind === 'call-resolved');
  assert.ok(middleCallResolved.length > 0, 'middle\'s own call-resolved hop for its call to inner is recorded');
  for (const h of middleCallResolved) {
    assert.equal(h.peerScope, byName.inner.qid);
    assert.equal(typeof h.peerContext, 'string');
  }

  // Outer's own call-resolved hop, for its calls to middle, carries the
  // same peerScope/peerContext augmentation.
  const outerCallResolved = hops.filter((h) => h.scope === byName.outer.qid && h.kind === 'production' && h.subKind === 'call-resolved');
  assert.ok(outerCallResolved.length > 0);
  for (const h of outerCallResolved) {
    assert.equal(h.peerScope, byName.middle.qid);
    assert.equal(typeof h.peerContext, 'string');
  }
});

// ---------------------------------------------------------------------
// 3. Context disambiguation (§13.3/§9.4's own worked example).
// ---------------------------------------------------------------------

test('context disambiguation (§13.3, §9.4\'s worked example): joining on (scope, nodeId, dataElementId, context) excludes the phantom pairs a 3-part join would include', () => {
  const src = 'function g(x) { const y = x; return y; }';
  const byName = parseFns(src, '/x/c3-ctx.js');
  const g = byName.g;

  const cache = new FieldIdentitySummaryCache();
  const raw = [];

  // Context A: the FIELD carries the identity. Context B: the CONTAINER
  // does (coarser). Both computed for real through the cache — two
  // distinct entry states, so neither suppresses the other.
  const ctxA = addIdentity(emptyState(), 'x.email', 'data:email');
  const ctxB = addIdentity(emptyState(), 'x', 'data:email');
  for (const es of [ctxA, ctxB]) {
    cache.compute(g.qid, es, (entry) => summaryFromAnalysisResult(
      analyzeFunctionFieldIdentity(g, entry, { recordHop: (h) => raw.push(h) }),
    ));
  }
  const hops = dedupeHops(raw);
  assert.equal(new Set(hops.map((h) => h.context)).size, 2, 'fixture precondition: two genuinely distinct contexts were recorded');

  // The `const y = x;` node only.
  const assignNode = Object.keys(g.cfg.nodes).find((nid) => g.cfg.nodes[nid].kind === 'assign');
  const at = hops.filter((h) => h.nodeId === assignNode && h.dataElementId === 'data:email');
  const ins = at.filter((h) => h.kind === 'production' && h.fromPath !== null);
  const outs = at.filter((h) => h.kind === 'write-out' && h.toPath !== null);

  assert.deepEqual(ins.map((h) => h.fromPath).sort(), ['x', 'x.email'], 'two in-halves, one per context');
  assert.deepEqual(outs.map((h) => h.toPath).sort(), ['y', 'y.email'], 'two out-halves, one per context');

  // The OLD join key (§2.2): every in-half pairs with every out-half.
  const oldKeyPairs = [];
  for (const i of ins) for (const o of outs) {
    if (i.scope === o.scope && i.nodeId === o.nodeId && i.dataElementId === o.dataElementId) {
      oldKeyPairs.push(`${i.fromPath}->${o.toPath}`);
    }
  }
  assert.deepEqual(oldKeyPairs.sort(), ['x->y', 'x->y.email', 'x.email->y', 'x.email->y.email'],
    '§9.4 reproduced exactly: 2 in x 2 out = 4 joinable pairs');
  assert.ok(oldKeyPairs.includes('x.email->y'), 'phantom #1 — never happened in either context');
  assert.ok(oldKeyPairs.includes('x->y.email'), 'phantom #2 — never happened in either context');

  // The NEW join key (§13.3): (scope, nodeId, dataElementId, context).
  const newKeyPairs = [];
  for (const i of ins) for (const o of outs) {
    if (i.scope === o.scope && i.nodeId === o.nodeId && i.dataElementId === o.dataElementId && i.context === o.context) {
      newKeyPairs.push(`${i.fromPath}->${o.toPath}`);
    }
  }
  assert.deepEqual(newKeyPairs.sort(), ['x->y', 'x.email->y.email'],
    'exactly the two edges that really happened — both phantoms excluded');
});

// ---------------------------------------------------------------------
// 4. Golden-baseline regression (item 15b) — the guard for the exact
//    hazard §13.2a's fix round found and closed. See this file's header.
// ---------------------------------------------------------------------

test('golden-baseline regression (item 15b): the §13.2a hazard stays closed — a call ARGUMENT that is itself a resolvable call', () => {
  const src = `
    function scrub(u) { return { safe: 1 }; }
    function sink(p) { return p; }
    function caller(user) { const out = sink(scrub(user)); return out; }
  `;
  const byName = parseFns(src, '/x/c3-golden-a.js');
  const lookup = lookupCalleeFor(byName);
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const withoutRecorder = analyzeFunctionFieldIdentity(byName.caller, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(), lookup),
  });
  const raw = [];
  const withRecorder = analyzeFunctionFieldIdentity(byName.caller, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(), lookup),
    recordHop: (h) => raw.push(h),
  });

  // Hardcoded pre-C3 golden literal (DESIGN_PATH_PROVENANCE.md §13.2a's own
  // reproduction) — NOT a comparison against any other live code path.
  // `scrub` returns a literal object, so the shipped engine never resolves
  // the nested call at this argument site: the unresolved-call fallback
  // keeps `data:email` flowing into `out`. A regression that reintroduces
  // §13.2a's original hazard (forwarding the FULL ctx into
  // entryStateFromCall's resolveExprIdentities call) would resolve
  // `scrub(user)` and silently drop this identity — this assertion would
  // then fail with `[]`.
  const golden = ['data:email'];
  assert.deepEqual([...withoutRecorder.returnFacts[0].identities], golden, 'recorder-free result must equal the hardcoded pre-C3 golden literal');
  assert.deepEqual([...withRecorder.returnFacts[0].identities], golden, 'attaching a recorder must not change the result either');

  assert.deepEqual(
    canonicalizeResult(withRecorder),
    canonicalizeResult(withoutRecorder),
    'the full canonicalized {exitState, returnFacts, mutatedParams, widenings} shape must be identical with and without a recorder',
  );

  // With a recorder attached, the argument's own in-half is recorded
  // honestly against the UNRESOLVED path the analysis actually took (§8).
  const hops = dedupeHops(raw);
  const bind = hops.find((h) => h.subKind === 'call-arg-bind' && h.dataElementId === 'data:email');
  assert.ok(bind, 'expected the argument binding to still be recorded');
  const argIn = hops.find(
    (h) => h.kind === 'production' && h.subKind === 'call'
      && h.nodeId === bind.nodeId && h.dataElementId === 'data:email',
  );
  assert.ok(argIn, 'the nested unresolved call\'s own in-half is recorded at the same node');
  assert.equal(argIn.widenReason, 'unresolved-call', 'the widening is carried honestly, not laundered into a call-resolved that never happened');
  assert.equal(bind.widenReason, null, 'not duplicated onto the bind out-half — it joins with argIn at the same (scope, nodeId, dataElementId, context) key');
});

test('golden-baseline regression (item 15b): the §13.2a hazard stays closed under a tight B6 cap — two call sites sharing a cap-1 cache', () => {
  const src = `
    function helper(x) { return { v: x.email }; }
    function pass(p) { return p; }
    function f(user, other) {
      const a = pass(helper(user));
      const b = helper(other);
      return b;
    }
  `;
  const byName = parseFns(src, '/x/c3-golden-b.js');
  const lookup = lookupCalleeFor(byName);
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'other.email', 'data:other-email');

  const withoutRecorder = analyzeFunctionFieldIdentity(byName.f, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(1), lookup),
  });
  const withRecorder = analyzeFunctionFieldIdentity(byName.f, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(1), lookup),
    recordHop: () => {},
  });

  // Hardcoded pre-C3 golden literal: `helper`'s single cap-1 context slot
  // is spent on `helper(other)` (shipped never resolves the nested
  // `helper(user)` argument to `pass`), so `helper(other)`'s own return
  // identity survives into `b`. A regression that reintroduces §13.2a's
  // hazard would consume helper's only slot on the nested resolve,
  // degrading `helper(other)` to an empty summary and losing
  // `data:other-email` — this assertion would then fail with `[]`.
  const golden = ['data:other-email'];
  assert.deepEqual([...withoutRecorder.returnFacts[0].identities], golden, 'recorder-free result must equal the hardcoded pre-C3 golden literal');
  assert.deepEqual([...withRecorder.returnFacts[0].identities], golden, 'attaching a recorder must not change the result either');

  assert.deepEqual(
    canonicalizeResult(withRecorder),
    canonicalizeResult(withoutRecorder),
    'the full canonicalized {exitState, returnFacts, mutatedParams, widenings} shape must be identical with and without a recorder',
  );
});

// ---------------------------------------------------------------------
// 5. driver.js (§13.7 item 14): opts.recordHop threading.
// ---------------------------------------------------------------------

// NOTE on what this test can and cannot observe: `runFieldIdentityAnalysis`
// analyzes every function starting from its own `emptyState()` (no source
// registry exists yet — Sub-project E, per driver.js's own header comment
// and CLAUDE.md's B6 note) and has no hook to seed a non-empty entry state
// for any function. Since this engine never invents a dataElementId from
// nothing — every hop-emitting case in engine.js loops over an identity
// set that is empty whenever nothing upstream ever called `addIdentity` —
// a driver-orchestrated run can currently never produce a single
// hop-emitting event, REGARDLESS of whether `opts.recordHop` threading is
// wired correctly. That is a pre-existing, disclosed limitation of
// `driver.js`'s current scope, not something this task's `opts.recordHop`
// change could fix or regress. What IS observable, and is exactly
// Decision 7.2's "true by construction" contract extended to the driver
// (§13.7 item 14): supplying `opts.recordHop` must not perturb any
// function's analysis result, and must not throw even though it is
// genuinely threaded into every per-function ctx.
test('driver.js (§13.7 item 14): opts.recordHop is threaded into every function\'s ctx without perturbing results; omitting it is byte-identical', () => {
  const src1 = 'function helper(u) { return u.email; }';
  const src2 = 'function caller(a) { return helper(a); }';
  const ir1 = parseJsFile('/x/c3-driver-a.js', src1);
  const ir2 = parseJsFile('/x/c3-driver-b.js', src2);
  assert.ok(ir1 && ir2);

  const functions = new Map();
  for (const fn of ir1.functions) functions.set(fn.qid, fn);
  for (const fn of ir2.functions) functions.set(fn.qid, fn);
  const byFile = new Map([
    ['/x/c3-driver-a.js', new Map([[ir1.functions[0].name, ir1.functions[0].qid]])],
    ['/x/c3-driver-b.js', new Map([[ir2.functions[0].name, ir2.functions[0].qid]])],
  ]);
  const callGraph = {
    functions,
    resolveKnownCallee(name, callerFile) {
      const local = byFile.get(callerFile);
      if (local && local.has(name)) return local.get(name);
      for (const m of byFile.values()) if (m.has(name)) return m.get(name);
      return null;
    },
  };

  // Must not throw with a recorder attached, across every function in the
  // project (mechanically exercises the `opts.recordHop ? {...} : {...}`
  // branch for each of the two functions, even though no hop content fires
  // — see the note above).
  const raw = [];
  const { results: withRecorder } = runFieldIdentityAnalysis(callGraph, { recordHop: (h) => raw.push(h) });
  assert.equal(withRecorder.size, functions.size, 'every function in the call graph was analyzed with the recorder-bearing ctx');

  const { results: withoutRecorder } = runFieldIdentityAnalysis(callGraph);

  const canon = (results) => [...results.entries()]
    .map(([qid, r]) => [qid, canonicalizeResult(r)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  assert.deepEqual(
    canon(withRecorder),
    canon(withoutRecorder),
    'omitting opts.recordHop must leave every function\'s analysis result byte-identical — Decision 7.2\'s "true by construction" property, extended to the driver',
  );
});
