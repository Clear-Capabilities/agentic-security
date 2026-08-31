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
  emptyFieldSummary,
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

// Hardcoded pre-C3 golden literals — the task review's own captured values
// for fixture A, and this task's own captured values for fixture B (both
// obtained by running the current, committed code and reading its
// canonicalized output; never guessed). Comparing the FULL canonicalized
// {exitState, returnFacts, mutatedParams, widenings} shape, not just
// returnFacts' identities alone, per item 15b's own text.
//
// `returnFacts[].nodeId` is deliberately normalized to the placeholder
// '<nodeId>' rather than pinned to a literal string — verified by running
// this exact test file: `nodeId` comes from parser-js.js's `_nodeIdSeq`,
// a MODULE-LEVEL counter that is never reset per fixture, so its value
// depends on how many CFG nodes every earlier test in this file already
// parsed (a fact about test ORDER, not about this fixture's own content).
// Measured directly: fixture A's own returnFacts[0].nodeId came out 'n13'
// parsed in isolation but 'n42' in this file's actual position (three
// prior tests' worth of parseJsFile calls ahead of it); fixture B came out
// 'n14' in isolation, 'n56' here. Pinning either literal would make this
// test fail the moment an earlier test in the file changes, which is
// exactly the "verification that doesn't hold under real execution"
// failure mode this repo's CLAUDE.md warns against — nodeId's realness is
// instead checked separately (a non-empty string), immediately below.
function normalizeNodeIdForGolden(canon) {
  return { ...canon, returnFacts: canon.returnFacts.map((f) => ({ ...f, nodeId: '<nodeId>' })) };
}

const GOLDEN_A = {
  exitState: [
    ['out', ['data:email']],
    ['user.email', ['data:email']],
  ],
  returnFacts: [
    { nodeId: '<nodeId>', line: 4, identities: ['data:email'] },
  ],
  mutatedParams: [
    ['user', ['data:email']],
  ],
  widenings: [
    '{"atPath":null,"dataElementIds":["data:email"],"line":4,"reason":"unresolved-call-arg"}',
  ],
};

const GOLDEN_B = {
  exitState: [
    ['a', ['data:email']],
    ['b', ['data:other-email']],
    ['other.email', ['data:other-email']],
    ['user.email', ['data:email']],
  ],
  returnFacts: [
    { nodeId: '<nodeId>', line: 7, identities: ['data:other-email'] },
  ],
  mutatedParams: [
    ['other', ['data:other-email']],
    ['user', ['data:email']],
  ],
  widenings: [
    '{"atPath":null,"dataElementIds":["data:email"],"line":5,"reason":"unresolved-call-arg"}',
  ],
};

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
  // `scrub(user)` and silently drop this identity — `withoutRecorder
  // .returnFacts` would become an empty array, so the guard immediately
  // below fails loudly (rather than the `deepEqual` throwing a raw
  // `TypeError` on `returnFacts[0]` being undefined).
  assert.ok(withoutRecorder.returnFacts[0], 'expected a return fact — an empty returnFacts means the §13.2a hazard is back');
  assert.ok(withRecorder.returnFacts[0], 'expected a return fact — an empty returnFacts means the §13.2a hazard is back');
  assert.equal(typeof withoutRecorder.returnFacts[0].nodeId, 'string', 'expected a real nodeId string');
  assert.deepEqual([...withoutRecorder.returnFacts[0].identities], GOLDEN_A.returnFacts[0].identities, 'recorder-free result must equal the hardcoded pre-C3 golden literal');
  assert.deepEqual([...withRecorder.returnFacts[0].identities], GOLDEN_A.returnFacts[0].identities, 'attaching a recorder must not change the result either');

  assert.deepEqual(normalizeNodeIdForGolden(canonicalizeResult(withoutRecorder)), GOLDEN_A, 'the full canonicalized {exitState, returnFacts, mutatedParams, widenings} shape must equal the hardcoded pre-C3 golden literal (nodeId normalized — see the comment above GOLDEN_A/GOLDEN_B)');
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
  // `data:other-email` — `withoutRecorder.returnFacts` would become an
  // empty array, so the guard immediately below fails loudly (rather than
  // the `deepEqual` throwing a raw `TypeError` on `returnFacts[0]` being
  // undefined).
  assert.ok(withoutRecorder.returnFacts[0], 'expected a return fact — an empty returnFacts means the §13.2a hazard is back');
  assert.ok(withRecorder.returnFacts[0], 'expected a return fact — an empty returnFacts means the §13.2a hazard is back');
  assert.equal(typeof withoutRecorder.returnFacts[0].nodeId, 'string', 'expected a real nodeId string');
  assert.deepEqual([...withoutRecorder.returnFacts[0].identities], GOLDEN_B.returnFacts[0].identities, 'recorder-free result must equal the hardcoded pre-C3 golden literal');
  assert.deepEqual([...withRecorder.returnFacts[0].identities], GOLDEN_B.returnFacts[0].identities, 'attaching a recorder must not change the result either');

  assert.deepEqual(normalizeNodeIdForGolden(canonicalizeResult(withoutRecorder)), GOLDEN_B, 'the full canonicalized {exitState, returnFacts, mutatedParams, widenings} shape must equal the hardcoded pre-C3 golden literal (nodeId normalized — see the comment above GOLDEN_A/GOLDEN_B)');
  assert.deepEqual(
    canonicalizeResult(withRecorder),
    canonicalizeResult(withoutRecorder),
    'the full canonicalized {exitState, returnFacts, mutatedParams, widenings} shape must be identical with and without a recorder',
  );
});

// ---------------------------------------------------------------------
// 4b. Item 15 absorption: the PoC's remaining non-redundant assertions,
//     re-pointed at the SHIPPED functions (never local prototypes). The
//     "this"-binding stand-in and the three "hole is real" tests have no
//     permanent equivalent by design (§13.7 item 15) — they proved a
//     now-fixed hazard, not a lasting property. Everything below DOES
//     describe a lasting property and is absorbed here before the PoC
//     file is deleted (Step 6).
// ---------------------------------------------------------------------

test('call-arg-bind (§13.2): two distinct fields carried by ONE argument each produce their own toPath-specific hop; a literal argument produces none', () => {
  const src = `
    function two(u) { return u; }
    function caller(a) {
      const lit = two('constant');
      const viaField = two(a);
      return [lit, viaField];
    }
  `;
  const byName = parseFns(src, '/x/c3-bind-literal.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'a.ssn', 'data:ssn');

  const raw = [];
  analyzeFunctionFieldIdentity(byName.caller, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(), lookupCalleeFor(byName)),
    recordHop: (h) => raw.push(h),
  });
  const hops = dedupeHops(raw);

  const binds = hops.filter((h) => h.kind === 'write-out' && h.subKind === 'call-arg-bind');
  // The literal argument (`two('constant')`) carries no identity, so
  // `entryStateFromCall`'s freshly built entryState has nothing to
  // enumerate for that call site — nothing to record, per §13.2's own
  // "arguments that are not path-shaped" rule (matching §10.1's `literal`
  // verdict). The field-carrying argument (`two(a)`) binds BOTH of its
  // fields, each at its own sub-path.
  assert.deepEqual(binds.map((h) => h.toPath).sort(), ['u.email', 'u.ssn'],
    'exactly two bind hops — one per field the field-carrying argument carries — and NONE for the literal argument');
  const bindEmail = binds.find((h) => h.toPath === 'u.email');
  const bindSsn = binds.find((h) => h.toPath === 'u.ssn');
  assert.equal(bindEmail.dataElementId, 'data:email');
  assert.equal(bindSsn.dataElementId, 'data:ssn');
  for (const h of binds) {
    assert.equal(h.fromPath, null);
    assert.equal(h.lossReason, null);
    assert.equal(h.widenReason, null);
    assert.equal(h.peerScope, byName.two.qid);
    assert.equal(typeof h.peerContext, 'string');
  }
});

test('call-arg-bind, return direction (§13.2c): the resolver hands the caller the callee\'s (qid, context) without mutating or perturbing the cached summary', () => {
  const byName = parseFns(`
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `, '/x/c3-peer-return.js');
  const cache = new FieldIdentitySummaryCache();
  const inner = createCallSummaryResolver(cache, lookupCalleeFor(byName));

  const seenReturns = [];
  const resolveCallSummary = function (...args) {
    const r = inner.apply(this, args);
    if (r) seenReturns.push({ qid: r.resolvedQid, context: r.resolvedContext });
    return r;
  };

  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.email', 'data:email');
  const withPeer = analyzeFunctionFieldIdentity(byName.outer, entryState, { resolveCallSummary });

  assert.ok(seenReturns.length > 0, 'expected at least one resolved call to have returned a peer-augmented summary');
  assert.ok(seenReturns.every((s) => typeof s.qid === 'string' && typeof s.context === 'string'),
    'every resolved call knows exactly which (callee qid, entry context) produced the summary');

  // The cached summary object itself is untouched: a second, plain run
  // through the SAME resolver (no peer-observing wrapper) produces the
  // identical analysis result.
  const cache2 = new FieldIdentitySummaryCache();
  const plain = createCallSummaryResolver(cache2, lookupCalleeFor(byName));
  const withoutPeerObserver = analyzeFunctionFieldIdentity(byName.outer, entryState, { resolveCallSummary: plain });
  assert.deepEqual(
    canonicalizeResult(withPeer),
    canonicalizeResult(withoutPeerObserver),
    'augmenting the resolver\'s RETURN value is inert to engine.js, which reads only returnFlat/returnByPath',
  );

  for (const [, summary] of cache._cache) {
    assert.equal(Object.prototype.hasOwnProperty.call(summary, 'resolvedQid'), false,
      'the resolvedQid/resolvedContext augmentation must be a fresh wrapper, never written onto the cached summary itself (item 10)');
  }
});

// ---------------------------------------------------------------------
// 4c. §13.4's disclosed cache-hit sharing property (§9.6): a cache HIT
//    records the callee's internal body once per entry CONTEXT, not once
//    per call site — measured, not assumed, and pinned here so a future
//    change can't silently regress it into either direction (orphaning a
//    call site, or the much larger cache-replay fix §13.4 explicitly
//    rejects).
// ---------------------------------------------------------------------

function countCalleeInternalHops(byName, entryState) {
  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCalleeFor(byName));
  const raw = [];
  analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary,
    recordHop: (h) => raw.push(h),
  });
  const hops = dedupeHops(raw);
  return {
    middleContexts: new Set(hops.filter((h) => h.scope === byName.middle.qid).map((h) => h.context)),
    binds: hops.filter((h) => h.subKind === 'call-arg-bind'),
  };
}

test('§13.4/§9.6: two call sites reaching the SAME (qid, entryState) get the callee\'s internal hops exactly ONCE — the cache hit shares the body, it does not orphan the call site', () => {
  const byName = parseFns(`
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `, '/x/c3-cachehit.js');

  // Both `a` and `b` carry the identical seeded identity, so
  // entryStateFromCall produces the identical entry state for BOTH call
  // sites and hashState collides -> the second compute() is a cache HIT.
  let same = addIdentity(emptyState(), 'a.email', 'data:email');
  same = addIdentity(same, 'b.email', 'data:email');
  const collided = countCalleeInternalHops(byName, same);

  const bindContexts = new Set(collided.binds.filter((h) => h.peerScope === byName.middle.qid).map((h) => h.peerContext));
  assert.equal(bindContexts.size, 1, 'fixture precondition: both call sites bind middle under ONE entry context');
  assert.equal(collided.middleContexts.size, 1, 'middle\'s own internal hops were recorded for exactly one entry context');

  for (const h of collided.binds.filter((x) => x.peerScope === byName.middle.qid)) {
    assert.ok(
      collided.middleContexts.has(h.peerContext),
      'every call site\'s bind hop points at a context whose body IS present in the record stream — nothing is orphaned',
    );
  }
});

test('§13.4/§9.6 (control): two call sites reaching DIFFERENT entry contexts each get their own copy of the callee\'s internals', () => {
  const byName = parseFns(`
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `, '/x/c3-cachemiss.js');
  let distinct = addIdentity(emptyState(), 'a.email', 'data:email');
  distinct = addIdentity(distinct, 'b.email', 'data:other');
  const r = countCalleeInternalHops(byName, distinct);
  assert.equal(r.middleContexts.size, 2, 'two distinct entry contexts -> two distinct compute()s -> two distinct sets of middle-internal hops');
});

// ---------------------------------------------------------------------
// 4d. §13.2's disclosed multi-argument cross-join (§9.1's own already-
//    disclosed phantom-pair shape, recurring at a call boundary).
// ---------------------------------------------------------------------

test('call-arg-bind (§13.2, disclosed): two arguments at one call site carrying the SAME id produce §9.1 cross-join phantoms the 4-part join key does NOT exclude', () => {
  const byName = parseFns(`
    function two(p, q) { return { p, q }; }
    function caller(m, n) { const r = two(m, n); return r; }
  `, '/x/c3-multiarg.js');

  let entryState = addIdentity(emptyState(), 'm.email', 'data:email');
  entryState = addIdentity(entryState, 'n.email', 'data:email'); // SAME id, two arguments

  const raw = [];
  analyzeFunctionFieldIdentity(byName.caller, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(), lookupCalleeFor(byName)),
    recordHop: (h) => raw.push(h),
  });
  const hops = dedupeHops(raw);

  const binds = hops.filter((h) => h.subKind === 'call-arg-bind' && h.dataElementId === 'data:email');
  assert.deepEqual(binds.map((h) => h.toPath).sort(), ['p.email', 'q.email'], 'two out-halves, one per parameter');

  const ins = hops.filter(
    (h) => h.kind === 'production' && h.subKind === 'ident'
      && h.dataElementId === 'data:email' && h.nodeId === binds[0].nodeId && h.fromPath !== null,
  );
  assert.deepEqual([...new Set(ins.map((h) => h.fromPath))].sort(), ['m.email', 'n.email'], 'two in-halves, one per argument');

  // Even with `context` in the key, all four pair — both halves share the
  // caller's single (scope, nodeId, context), so context cannot separate
  // WHICH argument bound to WHICH parameter.
  const pairs = new Set();
  for (const i of ins) {
    for (const o of binds) {
      if (i.scope === o.scope && i.nodeId === o.nodeId && i.dataElementId === o.dataElementId && i.context === o.context) {
        pairs.add(`${i.fromPath}->${o.toPath}`);
      }
    }
  }
  assert.deepEqual([...pairs].sort(), ['m.email->p.email', 'm.email->q.email', 'n.email->p.email', 'n.email->q.email'],
    '§9.1\'s cross-join, at a call site: 2 real edges plus 2 phantoms naming the WRONG parameter — a disclosed, not fixed, limitation');
});

// ---------------------------------------------------------------------
// 4e. B5/B6 degradation marking (§13.6, §13.7 items 11-12) — against
//    SHIPPED `FieldIdentitySummaryCache`/`createCallSummaryResolver`, now
//    that Steps 1-2 of this task have wired marking into compute() for
//    real (the PoC proved this only via its own `MarkingSummaryCache`
//    subclass, since shipped code did not carry it yet).
// ---------------------------------------------------------------------

test('§13.6 (B6): a cap-degraded call site\'s hop carries lossReason "context-cap-degraded"; a precisely-resolved call site does not', () => {
  const byName = parseFns(`
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `, '/x/c3-b6-marked.js');
  const cache = new FieldIdentitySummaryCache(1);
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCalleeFor(byName));

  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');

  const raw = [];
  analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary,
    recordHop: (h) => raw.push(h),
  });
  const hops = dedupeHops(raw);

  const degradedHops = hops.filter((h) => h.lossReason === 'context-cap-degraded');
  assert.ok(degradedHops.length > 0, `the degraded call site is no longer silent, got shapes ${JSON.stringify(hops.map((h) => `${h.subKind}:${h.lossReason}`))}`);
  for (const h of degradedHops) {
    assert.equal(h.kind, 'production');
    assert.equal(h.subKind, 'call-resolved');
    assert.equal(h.fromPath, null);
    assert.equal(h.toPath, null);
    assert.equal(typeof h.dataElementId, 'string');
    assert.equal(typeof h.peerScope, 'string');
    assert.equal(typeof h.peerContext, 'string');
  }

  // The marker names exactly the bound context that has no recorded body.
  const bodyContexts = new Set(hops.filter((h) => h.scope === byName.middle.qid).map((h) => h.context));
  const markedContexts = new Set(degradedHops.filter((h) => h.peerScope === byName.middle.qid).map((h) => h.peerContext));
  assert.ok(markedContexts.size > 0);
  for (const c of markedContexts) assert.equal(bodyContexts.has(c), false, 'a marked context is precisely one with no recorded body');

  // A precisely-resolved call at the OTHER call site carries no marker.
  const preciseResolved = hops.filter((h) => h.subKind === 'call-resolved' && h.lossReason === null);
  assert.ok(preciseResolved.length > 0, 'the first, precisely-resolved call site still emits an unmarked call-resolved hop');
});

test('§13.6 (B6): marking uses a SHALLOW COPY — the precise empty-entry summary it falls back to is never poisoned', () => {
  const cache = new FieldIdentitySummaryCache(1);
  const precise = { ...emptyFieldSummary(), returnFlat: new Set(['data:precise']) };
  cache.set('qid::y', emptyState(), precise);

  const other = addIdentity(emptyState(), 'p', 'data:other');
  const degraded = cache.compute('qid::y', other, () => {
    throw new Error('analyzeFn must not run past the cap');
  });

  assert.equal(degraded.degradedReason, 'context-cap', 'the degraded summary is marked');
  assert.notEqual(degraded, precise, 'and it is a COPY, not the shared fallback object');
  assert.equal(Object.prototype.hasOwnProperty.call(precise, 'degradedReason'), false,
    'the precise empty-entry summary is untouched — an in-place mark would have retroactively degraded it for every later reader');
  assert.equal(cache.get('qid::y', emptyState()), precise, 'and it is still the object cached for the empty-entry context');
  assert.deepEqual([...degraded.returnFlat], ['data:precise'], 'the copy still carries the fallback\'s real facts');
});

test('§13.6 (B6): a run with NO recorder is unaffected by marking — degradedReason is diagnostic, never a fact', () => {
  const byName = parseFns(`
    function inner(u) { return { v: u.email }; }
    function middle(u) { const r = inner(u); return r; }
    function outer(a, b) {
      const x = middle(a);
      const y = middle(b);
      return { x, y };
    }
  `, '/x/c3-b6-marked-noop.js');
  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');

  const withMarking = analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(1), lookupCalleeFor(byName)),
  });
  const withoutMarkingCtx = analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary: createCallSummaryResolver(new FieldIdentitySummaryCache(1), lookupCalleeFor(byName)),
  });

  assert.deepEqual(
    canonicalizeResult(withMarking),
    canonicalizeResult(withoutMarkingCtx),
    'the analysis result is identical run to run — degradedReason never perturbs it, and fieldSummaryEq keeps ignoring it (item 13)',
  );
});

test('§13.6 (B5): a recursion bottom stub is self-effacing — its empty returnFlat means no call-resolved hop is emitted, so there is nothing to mark there either', () => {
  const src = `
    function selfRec(u) { const n = selfRec(u); return { base: u.email, nested: n }; }
    function top(user) { return selfRec(user); }
  `;
  const byName = parseFns(src, '/x/c3-b5.js');

  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCalleeFor(byName));
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const raw = [];
  const result = analyzeFunctionFieldIdentity(byName.top, entryState, {
    resolveCallSummary,
    recordHop: (h) => raw.push(h),
  });
  const hops = dedupeHops(raw);

  assert.ok(hops.some((h) => h.scope === byName.selfRec.qid), 'the recursive callee\'s own hops are recorded (holes closed)');
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'and the recursion terminates with a sound result');

  // No call-resolved hop from the recursive self-call ever carries
  // lossReason: 'context-cap-degraded' — B5's bottom stub is a DIFFERENT
  // mechanism from B6's cap degradation, and per §13.6 Finding 3, needs no
  // marking of its own (its empty returnFlat means engine.js's own loop
  // over `flat` never fires for that round, so there is no hop to mark).
  const selfCallResolved = hops.filter((h) => h.scope === byName.selfRec.qid && h.subKind === 'call-resolved');
  for (const h of selfCallResolved) {
    assert.equal(h.lossReason, null, 'a call-resolved hop that DOES exist for the recursive call is never B6-marked — the bottom-stub round produces no hop at all, rather than an incorrectly-marked one');
    assert.ok(typeof h.dataElementId === 'string' && h.dataElementId.length > 0);
  }
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
