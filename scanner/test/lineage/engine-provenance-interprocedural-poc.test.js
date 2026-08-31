// Sub-project C, increment C3 — INTERPROCEDURAL hop recording: the
// design-task proof-of-concept.
//
// This file is deliberately named "-poc" and deliberately isolated from
// `engine-provenance.test.js`. It exists to PROVE, by running real code,
// the facts that `DESIGN_PATH_PROVENANCE.md` §13 (added by the same task
// that added this file) records as decisions. The mechanical wiring of
// those decisions into `engine.js` / `summaries.js` / `driver.js` is a
// FOLLOW-UP task; when that lands, the load-bearing assertions here should
// be re-pointed at the shipped functions and this file folded into (or
// replaced by) the main provenance suite.
//
// SHIPPED SOURCE IS NOT MODIFIED BY THIS TASK. Every "after the fix"
// assertion below runs against a LOCAL PROTOTYPE of the proposed new
// signature, defined in this file, calling the real, unmodified
// `resolveExprIdentities` / `analyzeFunctionFieldIdentity` /
// `FieldIdentitySummaryCache` underneath. Two consequences worth stating
// once, loudly:
//
//   1. Hole 1 (engine.js's `case 'call'` not passing `ctx` to
//      `ctx.resolveCallSummary`) cannot be closed from a test file. This
//      PoC works around it with a `this`-binding stand-in: engine.js calls
//      the resolver as a METHOD (`ctx.resolveCallSummary(...)`, engine.js
//      :505), so inside the resolver `this` IS the caller's stamped
//      `stepCtx`. That is enough to PROVE the caller's recorder is
//      reachable, and to prove what the hops look like once it is. It is
//      NOT the shipped fix — see §13.1 for why an explicit 4th parameter
//      is required instead.
//   2. `context` stamping belongs in `analyzeFunctionFieldIdentity`'s own
//      `stepCtx` wrapper (engine.js:864-866). This file cannot put it
//      there, so it simulates it with `contextStamping()` below, wrapping
//      each analysis entry point exactly as the shipped wrapper would.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { emptyState, addIdentity, hashState } from '../../src/lineage/field-identity.js';
import {
  analyzeFunctionFieldIdentity,
  resolveExprIdentities,
  residualFlat,
} from '../../src/lineage/engine.js';
import {
  FieldIdentitySummaryCache,
  createCallSummaryResolver,
  entryStateFromCall,
  summaryFromAnalysisResult,
  emptyFieldSummary,
} from '../../src/lineage/summaries.js';

// ---------------------------------------------------------------------
// Shared fixture — the plan's own three-function chain.
// ---------------------------------------------------------------------

const CHAIN_SRC = `
  function inner(u) { return { v: u.email }; }
  function middle(u) { const r = inner(u); return r; }
  function outer(a, b) {
    const x = middle(a);
    const y = middle(b);
    return { x, y };
  }
`;

function parseChain(file = '/x/c3-poc.js') {
  const ir = parseJsFile(file, CHAIN_SRC);
  assert.ok(ir, 'real parser must parse the C3 PoC chain fixture');
  const byName = {};
  for (const fn of ir.functions) byName[fn.name] = fn;
  assert.ok(byName.inner && byName.middle && byName.outer, 'expected inner/middle/outer in the parsed IR');
  return byName;
}

function lookupCalleeFor(byName) {
  return (calleeExpr) => {
    if (!calleeExpr || calleeExpr.kind !== 'ident') return null;
    const fn = byName[calleeExpr.name];
    return fn ? { qid: fn.qid, fn } : null;
  };
}

// Decision 8: the worklist re-emits per node VISIT. Same dedupe helper the
// main provenance suite uses (JSON over sorted keys).
function dedupeHops(hops) {
  const seen = new Map();
  for (const h of hops) seen.set(JSON.stringify(h, Object.keys(h).sort()), h);
  return [...seen.values()];
}

// ---------------------------------------------------------------------
// PROTOTYPES of the proposed C3 signatures (§13.1-§13.3). These are the
// exact bodies the follow-up implementation task should move into
// `summaries.js`, minus the `this`-binding stand-in for hole 1.
// ---------------------------------------------------------------------

// §13.3 stand-in: what `analyzeFunctionFieldIdentity`'s own `stepCtx`
// wrapper will do once C3 ships — stamp `context` (and the null defaults
// for the two new cross-scope fields) BEFORE the emitting site's own
// fields, so a site may deliberately override them (§7.2's spread-order
// rule).
function contextStamping(sink, entryState) {
  const context = hashState(entryState);
  return (h) => sink({ context, peerScope: null, peerContext: null, ...h });
}

// §13.2 prototype: `entryStateFromCall` gains `ctx` as a 4th, OPTIONAL
// parameter, forwarded to `resolveExprIdentities` so the ARGUMENT
// expressions' own in-halves are recorded at the caller's node. Body is
// otherwise byte-for-byte the shipped one.
function entryStateFromCallC3(paramNames, callArgs, callerState, ctx) {
  let entryState = emptyState();
  const n = Math.min(paramNames.length, callArgs.length);
  for (let i = 0; i < n; i++) {
    const paramName = paramNames[i];
    const resolved = resolveExprIdentities(callerState, callArgs[i], ctx);
    const residual = residualFlat(resolved.flat, resolved.byPath);
    for (const id of residual) entryState = addIdentity(entryState, paramName, id);
    for (const [subPath, ids] of resolved.byPath) {
      for (const id of ids) entryState = addIdentity(entryState, `${paramName}.${subPath}`, id);
    }
  }
  return entryState;
}

// §13.1 + §13.2 + §13.3 prototype: the resolver closure, with all three
// §7.4 ctx holes closed.
function createCallSummaryResolverC3(cache, lookupCallee) {
  return function resolveCallSummary(calleeExpr, callArgs, callerState, ctxArg) {
    // Hole 1. `ctxArg` is what the SHIPPED fix supplies (engine.js's
    // `case 'call'` passing its own `ctx` as a 4th argument). `this` is
    // this PoC's stand-in, valid only because engine.js invokes the
    // resolver as a method on `ctx`.
    const ctx = ctxArg ?? this;

    const resolved = lookupCallee(calleeExpr);
    if (!resolved) return null;
    const { qid, fn } = resolved;

    // Hole 2: ctx now reaches the argument resolution.
    const entryState = entryStateFromCallC3(fn.params, callArgs, callerState, ctx);
    const calleeContext = hashState(entryState);

    // §13.2: the argument -> parameter BINDING out-half. Emitted here (not
    // inside entryStateFromCall) because this is the only site that knows
    // the callee's identity; `entryState` is itself the complete record of
    // every (toPath, id) the binding wrote, so nothing has to be
    // re-resolved to enumerate them.
    if (ctx?.recordHop) {
      for (const [path, ids] of entryState) {
        for (const id of ids) {
          ctx.recordHop({
            kind: 'write-out', subKind: 'call-arg-bind',
            fromPath: null, toPath: path, dataElementId: id,
            syntacticPath: null, widenReason: null, lossReason: null,
            peerScope: qid, peerContext: calleeContext,
          });
        }
      }
    }

    const summary = cache.compute(qid, entryState, (es) => {
      // Hole 3: the callee's own ctx keeps the caller's recorder instead of
      // discarding it, and adds this callee-context's own `context` stamp.
      const calleeCtx = ctx?.recordHop
        ? { resolveCallSummary, recordHop: contextStamping(ctx.recordHop, es) }
        : { resolveCallSummary };
      return summaryFromAnalysisResult(analyzeFunctionFieldIdentity(fn, es, calleeCtx));
    });

    // §13.2's return-direction counterpart: hand the caller the callee's
    // identity so `case 'call'`'s existing `production/call-resolved` hop
    // can carry `peerScope`/`peerContext`. A FRESH object every time — the
    // cached summary itself is never mutated.
    return summary ? { ...summary, resolvedQid: qid, resolvedContext: calleeContext } : summary;
  };
}

// ---------------------------------------------------------------------
// Scenario 0 — the three ctx holes are real, in the SHIPPED code, today.
// ---------------------------------------------------------------------

test('C3 hole 1: engine.js\'s `case \'call\'` passes NO ctx to ctx.resolveCallSummary (but does invoke it as a method, which is what this PoC exploits)', () => {
  const byName = parseChain('/x/c3-hole1.js');
  let observed = null;
  const resolveCallSummary = function (calleeExpr, callArgs, callerState) {
    observed = {
      argc: arguments.length,
      fourth: arguments[3],
      thisHasRecordHop: !!(this && this.recordHop),
      thisKeys: this ? Object.keys(this).sort() : null,
    };
    return null;
  };
  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  analyzeFunctionFieldIdentity(byName.outer, entryState, { resolveCallSummary, recordHop: () => {} });

  assert.ok(observed, 'the resolver must have been consulted at least once');
  assert.equal(observed.argc, 3, 'shipped engine.js:505 passes exactly (calleeExpr, callArgs, callerState) — no ctx (§7.4 hole 1)');
  assert.equal(observed.fourth, undefined, 'there is no 4th argument today');
  // The stand-in this PoC relies on, pinned so it cannot silently vanish.
  assert.equal(observed.thisHasRecordHop, true, 'engine.js invokes the resolver as ctx.resolveCallSummary(...), so `this` is the caller\'s stamped stepCtx');
  assert.deepEqual(observed.thisKeys, ['recordHop', 'resolveCallSummary']);
});

test('C3 hole 2: the SHIPPED entryStateFromCall ignores any 4th argument and records nothing', () => {
  const byName = parseChain('/x/c3-hole2.js');
  const outerFn = byName.outer;
  // `const x = middle(a);` — grab that call's own argument expression.
  const callNode = Object.values(outerFn.cfg.nodes).find(
    (n) => n.kind === 'assign' && n.source && n.source.kind === 'call',
  );
  assert.ok(callNode, 'expected an assign node whose source is a call expression');

  const callerState = addIdentity(emptyState(), 'a.email', 'data:email');
  const hops = [];
  assert.equal(entryStateFromCall.length, 3, 'shipped signature is (paramNames, callArgs, callerState) — arity 3 (§7.4 hole 2)');
  const entryState = entryStateFromCall(['u'], callNode.source.args, callerState, { recordHop: (h) => hops.push(h) });

  // The binding itself works (Sub-project B) — it is only UNRECORDABLE.
  assert.deepEqual([...entryState.keys()], ['u.email'], 'the argument->parameter binding itself is correct today');
  assert.equal(hops.length, 0, 'but a 4th ctx argument is ignored entirely — zero hops, the single most important interprocedural hop is unrecordable (§7.4 hole 2)');
});

test('C3 hole 3: the SHIPPED createCallSummaryResolver discards the caller\'s recorder — a resolved chain records the caller\'s hops and NONE of the callee\'s', () => {
  const byName = parseChain('/x/c3-hole3.js');
  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolver(cache, lookupCalleeFor(byName));

  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.email', 'data:email');

  const hops = [];
  const result = analyzeFunctionFieldIdentity(byName.outer, entryState, { resolveCallSummary, recordHop: (h) => hops.push(h) });

  // The ANALYSIS genuinely resolved through both hops (outer -> middle ->
  // inner), so this is not a vacuous "nothing happened" test.
  assert.ok(result.returnFacts.length > 0, 'outer must return something');
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'the two-hop resolved chain really does carry the identity end to end');

  const scopes = new Set(hops.map((h) => h.scope));
  assert.deepEqual([...scopes], [byName.outer.qid], 'every recorded hop belongs to the CALLER; middle\'s and inner\'s own hops are lost entirely (§7.4 hole 3)');
  assert.equal(hops.some((h) => h.scope === byName.middle.qid), false);
  assert.equal(hops.some((h) => h.scope === byName.inner.qid), false);
});

// ---------------------------------------------------------------------
// Scenario 1 — the argument->parameter binding hop (§13.2).
// ---------------------------------------------------------------------

test('C3 §13.2: the call-arg-bind out-half, and the argument\'s own in-halves, are emitted at the SAME (scope, nodeId, context) join key', () => {
  const byName = parseChain('/x/c3-bind.js');
  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolverC3(cache, lookupCalleeFor(byName));

  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'a.ssn', 'data:ssn');
  entryState = addIdentity(entryState, 'b.email', 'data:other');

  const raw = [];
  analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary,
    recordHop: contextStamping((h) => raw.push(h), entryState),
  });
  const hops = dedupeHops(raw);

  const binds = hops.filter((h) => h.kind === 'write-out' && h.subKind === 'call-arg-bind');
  assert.ok(binds.length > 0, `expected call-arg-bind hops, got shapes: ${JSON.stringify([...new Set(hops.map((h) => `${h.kind}/${h.subKind}`))])}`);

  // Decision 4: one record per dataElementId, never a Set.
  for (const h of binds) assert.equal(typeof h.dataElementId, 'string');

  // `middle(a)`: a.email/a.ssn bind onto the callee's parameter `u`, at
  // their own sub-paths — `u.email` / `u.ssn`, never the coarse `u`.
  const bindEmail = binds.find((h) => h.toPath === 'u.email' && h.dataElementId === 'data:email');
  const bindSsn = binds.find((h) => h.toPath === 'u.ssn' && h.dataElementId === 'data:ssn');
  assert.ok(bindEmail, `expected a bind to 'u.email' for data:email, got ${JSON.stringify(binds)}`);
  assert.ok(bindSsn, `expected a bind to 'u.ssn' for data:ssn, got ${JSON.stringify(binds)}`);

  // §13.2's shape decisions, pinned.
  assert.equal(bindEmail.kind, 'write-out', 'the binding is the call\'s INPUT side: an outbound half at the CALLER\'s node, structurally identical to `assign` (Decision 2)');
  assert.equal(bindEmail.fromPath, null, 'fromPath stays null on every write-out — the argument expression\'s own recursion already emitted the contributing-key in-halves (Decision 6), so recomputing them here would double-emit');
  assert.equal(bindEmail.lossReason, null);
  assert.equal(bindEmail.widenReason, null);
  assert.equal(bindEmail.peerScope, byName.middle.qid, 'toPath lives in the CALLEE\'s namespace — without peerScope, `u` would collide with any caller-local named `u` (Decision 5\'s bug class)');
  assert.equal(typeof bindEmail.peerContext, 'string');
  assert.equal(bindEmail.scope, byName.outer.qid, 'the bind hop is stamped with the CALLER\'s scope, because that is what lets it join with the argument\'s own in-halves');

  // The join, proven: the argument `a`'s own production/ident in-half for
  // data:email shares (scope, nodeId, dataElementId, context) with the
  // bind out-half.
  const argIn = hops.find(
    (h) => h.kind === 'production' && h.subKind === 'ident'
      && h.dataElementId === 'data:email' && h.fromPath === 'a.email'
      && h.nodeId === bindEmail.nodeId,
  );
  assert.ok(argIn, `expected the argument's own contributing-key in-half at the same node, got ${JSON.stringify(hops.filter((h) => h.nodeId === bindEmail.nodeId))}`);
  assert.equal(argIn.scope, bindEmail.scope);
  assert.equal(argIn.context, bindEmail.context);
  // => the joined edge is  outer:a.email  ->  middle(ctx):u.email  (data:email)

  // Every id that entered the callee has a bind hop; a param bound from an
  // argument carrying NO identity produces none (nothing to record) —
  // `b.email` carries data:other, so the second call site binds it too.
  assert.ok(binds.some((h) => h.dataElementId === 'data:other'), 'the second call site (middle(b)) binds its own argument too');
});

test('C3 §13.2: a literal argument produces no bind hop; an argument that is itself an UNRESOLVED call binds with fromPath null and inherits its widening from its own in-half', () => {
  const src = `
    function sink(p) { return p; }
    function caller(user) {
      const lit = sink('constant');
      const viaCall = sink(unknownHelper(user.secret));
      return [lit, viaCall];
    }
  `;
  const ir = parseJsFile('/x/c3-bind-args.js', src);
  const byName = {};
  for (const fn of ir.functions) byName[fn.name] = fn;

  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolverC3(cache, lookupCalleeFor(byName));
  const entryState = addIdentity(emptyState(), 'user.secret', 'data:secret');

  const raw = [];
  analyzeFunctionFieldIdentity(byName.caller, entryState, {
    resolveCallSummary,
    recordHop: contextStamping((h) => raw.push(h), entryState),
  });
  const hops = dedupeHops(raw);
  const binds = hops.filter((h) => h.subKind === 'call-arg-bind');

  assert.equal(binds.length, 1, `exactly one bind hop: the literal argument carries no identity, so there is nothing to bind. got ${JSON.stringify(binds)}`);
  assert.equal(binds[0].dataElementId, 'data:secret');
  assert.equal(binds[0].toPath, 'p');
  assert.equal(binds[0].fromPath, null);
  assert.equal(binds[0].widenReason, null, 'the widening is carried by the argument\'s OWN production/call in-half, which joins with this out-half — not duplicated onto it');

  const unresolvedIn = hops.find((h) => h.kind === 'production' && h.subKind === 'call' && h.nodeId === binds[0].nodeId);
  assert.ok(unresolvedIn, 'the nested unresolved call emitted its own in-half at the same node');
  assert.equal(unresolvedIn.widenReason, 'unresolved-call');
});

// ---------------------------------------------------------------------
// Scenario 2 — the load-bearing two-hole-closure proof (§13.1/§13.3).
// ---------------------------------------------------------------------

test('C3 §13.1+§13.3: with the ctx holes closed, hops recorded INSIDE inner\'s own analysis reach a recorder attached at outer, correctly re-stamped with inner\'s own scope/nodeId/context', () => {
  const byName = parseChain('/x/c3-closure.js');
  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolverC3(cache, lookupCalleeFor(byName));

  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.email', 'data:email');

  const raw = [];
  const result = analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary,
    recordHop: contextStamping((h) => raw.push(h), entryState),
  });
  const hops = dedupeHops(raw);

  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'the analysis result is unchanged by the prototype (it still resolves the two-hop chain)');

  const scopes = new Set(hops.map((h) => h.scope));
  assert.ok(scopes.has(byName.outer.qid), 'outer\'s own hops still appear');
  assert.ok(scopes.has(byName.middle.qid), 'middle\'s own hops now appear (hole 3 closed)');
  assert.ok(scopes.has(byName.inner.qid), 'inner\'s own hops now appear — TWO resolved hops deep (holes 1+3 closed)');

  // The specific hop the plan names: inner's `u.email` selection.
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

  // And the stitch is complete: inner's write-out/return joins the caller
  // side via middle's own production/call-resolved hop.
  assert.ok(innerHops.some((h) => h.kind === 'write-out' && h.subKind === 'return'), 'inner\'s function-exit marker is recorded');
  assert.ok(
    hops.some((h) => h.scope === byName.middle.qid && h.kind === 'production' && h.subKind === 'call-resolved'),
    'middle\'s own call-resolved hop for its call to inner is recorded',
  );
});

test('C3 §13.2 (return direction): the resolver can hand the caller the callee\'s (qid, context) without mutating or perturbing the cached summary', () => {
  const byName = parseChain('/x/c3-peer-return.js');
  const cache = new FieldIdentitySummaryCache();
  const inner = createCallSummaryResolverC3(cache, lookupCalleeFor(byName));

  const seenReturns = [];
  const resolveCallSummary = function (...args) {
    const r = inner.apply(this, args);
    if (r) seenReturns.push({ qid: r.resolvedQid, context: r.resolvedContext });
    return r;
  };

  const entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  const withPeer = analyzeFunctionFieldIdentity(byName.outer, entryState, { resolveCallSummary });

  assert.ok(seenReturns.length > 0);
  assert.ok(seenReturns.every((s) => typeof s.qid === 'string' && typeof s.context === 'string'),
    'every resolved call knows exactly which (callee qid, entry context) produced the summary — the peerScope/peerContext production/call-resolved needs');

  // The cached summary object itself is untouched: a second, plain run
  // through the SHIPPED resolver produces the identical analysis result.
  const cache2 = new FieldIdentitySummaryCache();
  const shipped = createCallSummaryResolver(cache2, lookupCalleeFor(byName));
  const withoutPeer = analyzeFunctionFieldIdentity(byName.outer, entryState, { resolveCallSummary: shipped });
  assert.deepEqual(
    withPeer.returnFacts.map((f) => [...f.identities].sort()),
    withoutPeer.returnFacts.map((f) => [...f.identities].sort()),
    'augmenting the resolver\'s RETURN value is inert to engine.js, which reads only returnFlat/returnByPath',
  );

  for (const [, summary] of cache._cache) {
    assert.equal(Object.prototype.hasOwnProperty.call(summary, 'resolvedQid'), false, 'the augmentation must be a fresh wrapper, never written onto the cached summary');
  }
});

// ---------------------------------------------------------------------
// Scenario 3 — cache-hit hop suppression (§13.4). MEASURED, not predicted.
// ---------------------------------------------------------------------

function countCalleeInternalHops(byName, entryState) {
  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolverC3(cache, lookupCalleeFor(byName));
  const raw = [];
  analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary,
    recordHop: contextStamping((h) => raw.push(h), entryState),
  });
  const hops = dedupeHops(raw);
  return {
    hops,
    // "middle's OWN internal analysis" = hops whose scope is middle,
    // grouped by the entry context they ran under.
    middleContexts: new Set(hops.filter((h) => h.scope === byName.middle.qid).map((h) => h.context)),
    innerContexts: new Set(hops.filter((h) => h.scope === byName.inner.qid).map((h) => h.context)),
    binds: hops.filter((h) => h.subKind === 'call-arg-bind'),
    callResolved: hops.filter((h) => h.subKind === 'call-resolved' && h.scope === byName.outer.qid),
  };
}

test('C3 §13.4: two call sites reaching the SAME (qid, entryState) get the callee\'s internal hops exactly ONCE — the cache hit suppresses the second, per-call-site hops still fire twice', () => {
  const byName = parseChain('/x/c3-cachehit.js');

  // Both `a` and `b` carry the identical seeded identity, so
  // entryStateFromCall produces the identical entry state for BOTH call
  // sites and hashState collides -> the second compute() is a cache HIT.
  let same = addIdentity(emptyState(), 'a.email', 'data:email');
  same = addIdentity(same, 'b.email', 'data:email');
  const collided = countCalleeInternalHops(byName, same);

  // Sanity: the two call sites really did request the same context.
  const bindContexts = new Set(collided.binds.filter((h) => h.peerScope === byName.middle.qid).map((h) => h.peerContext));
  assert.equal(bindContexts.size, 1, 'fixture precondition: both call sites bind middle under ONE entry context');

  // MEASURED RESULT: one context's worth of middle-internal hops.
  assert.equal(collided.middleContexts.size, 1, 'middle\'s own internal hops were recorded for exactly one entry context');
  assert.equal(collided.innerContexts.size, 1, 'and inner\'s, transitively');

  // ... while the per-call-site hops fired for BOTH call sites.
  const bindNodes = new Set(collided.binds.filter((h) => h.peerScope === byName.middle.qid).map((h) => h.nodeId));
  assert.equal(bindNodes.size, 2, 'both call sites emitted their own call-arg-bind hop (these do not go through the cache)');
  const callResolvedNodes = new Set(collided.callResolved.map((h) => h.nodeId));
  assert.equal(callResolvedNodes.size, 2, 'both call sites emitted their own production/call-resolved hop');

  // The DISCLOSURE this measurement justifies: the callee's internals are
  // recorded once PER (qid, entryState), not once per call site — and
  // because both call sites' bind hops carry the SAME peerContext, a
  // consumer can still reach that single recorded body from either call
  // site. Nothing is unreachable; the body is SHARED, not missing.
  for (const h of collided.binds.filter((x) => x.peerScope === byName.middle.qid)) {
    assert.ok(
      collided.middleContexts.has(h.peerContext),
      'every call site\'s bind hop points at a context whose body IS present in the record stream — the cache hit shares the body, it does not orphan the call site',
    );
  }
});

test('C3 §13.4 (control): two call sites reaching DIFFERENT entry contexts each get their own copy of the callee\'s internals', () => {
  const byName = parseChain('/x/c3-cachemiss.js');
  // Same SHAPE, different identity, so both contexts resolve all the way
  // through to inner's `u.email` read. (Seeding `b.ssn` instead would
  // give middle two contexts but inner only one — inner reads `u.email`,
  // which a `u.ssn`-only entry state does not cover, so inner emits
  // nothing at all under it. Correct, but it makes a poor control.)
  let distinct = addIdentity(emptyState(), 'a.email', 'data:email');
  distinct = addIdentity(distinct, 'b.email', 'data:other');
  const r = countCalleeInternalHops(byName, distinct);

  assert.equal(r.middleContexts.size, 2, 'two distinct entry contexts -> two distinct compute()s -> two distinct sets of middle-internal hops');
  assert.equal(r.innerContexts.size, 2);
  // This is exactly why §9.4's `context` field is a PRECONDITION, not a
  // nicety: without it these two bodies collide on (scope, nodeId, id).
});

// ---------------------------------------------------------------------
// Scenario 4 — §9.4's own worked example, reconstructed and then fixed
// by folding `context` into the join key (§13.3).
// ---------------------------------------------------------------------

test('C3 §13.3: §9.4\'s worked example — joining on (scope, nodeId, dataElementId) alone yields 4 pairs, 2 of them phantom; adding `context` yields exactly the 2 real ones', () => {
  const src = 'function g(x) { const y = x; return y; }';
  const ir = parseJsFile('/x/c3-ctx.js', src);
  const g = ir.functions.find((f) => f.name === 'g');
  assert.ok(g);

  const cache = new FieldIdentitySummaryCache();
  const raw = [];

  // Context A: the FIELD carries the identity.  Context B: the CONTAINER
  // does (coarser). Both computed for real through the cache — two
  // distinct entry states, so neither suppresses the other.
  const ctxA = addIdentity(emptyState(), 'x.email', 'data:email');
  const ctxB = addIdentity(emptyState(), 'x', 'data:email');
  for (const es of [ctxA, ctxB]) {
    cache.compute(g.qid, es, (entry) => summaryFromAnalysisResult(
      analyzeFunctionFieldIdentity(g, entry, { recordHop: contextStamping((h) => raw.push(h), entry) }),
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
// Scenario 5 — B5/B6 degradation (§13.6). Two findings, both measured.
// ---------------------------------------------------------------------

test('C3 §13.6 finding 1: a B6 context-cap degradation is TODAY completely SILENT in the hop stream — the call resolves to an empty summary and emits no hop at all', () => {
  const byName = parseChain('/x/c3-b6.js');
  // cap = 1: the FIRST distinct context middle is asked for computes; the
  // second degrades to the (absent) empty-entry fallback.
  const cache = new FieldIdentitySummaryCache(1);
  const resolveCallSummary = createCallSummaryResolverC3(cache, lookupCalleeFor(byName));

  let entryState = addIdentity(emptyState(), 'a.email', 'data:email');
  entryState = addIdentity(entryState, 'b.ssn', 'data:ssn');

  const raw = [];
  analyzeFunctionFieldIdentity(byName.outer, entryState, {
    resolveCallSummary,
    recordHop: contextStamping((h) => raw.push(h), entryState),
  });
  const hops = dedupeHops(raw);

  const bindsToMiddle = hops.filter((h) => h.subKind === 'call-arg-bind' && h.peerScope === byName.middle.qid);
  const middleContexts = new Set(hops.filter((h) => h.scope === byName.middle.qid).map((h) => h.context));
  const bindContexts = new Set(bindsToMiddle.map((h) => h.peerContext));

  assert.equal(bindContexts.size, 2, 'both call sites bound middle under genuinely different contexts');
  assert.equal(middleContexts.size, 1, 'but only ONE of them was actually analyzed — the other hit the cap and degraded');

  // The silent-loss proof: one call site's bind hop points at a context
  // that has NO body anywhere in the record stream, and NOTHING in the
  // stream says why. That is §18.4's "path budget exhausted presented as
  // no path", one level up.
  const orphaned = [...bindContexts].filter((c) => !middleContexts.has(c));
  assert.equal(orphaned.length, 1, 'exactly one bound context has no recorded body');
  const orphanBind = bindsToMiddle.find((h) => h.peerContext === orphaned[0]);
  assert.equal(orphanBind.lossReason, null, 'and nothing marks it as degraded today — this is the gap §13.6 closes');
  const orphanCallResolved = hops.filter(
    (h) => h.subKind === 'call-resolved' && h.nodeId === orphanBind.nodeId,
  );
  assert.equal(orphanCallResolved.length, 0, 'the degraded call emits no production/call-resolved hop at all (its summary\'s returnFlat is empty), so there is not even a hop available to mark');
});

test('C3 §13.6 finding 2: the cap-degradation fallback is the SAME OBJECT as the empty-entry summary — marking it in place would poison a precise summary', () => {
  const cache = new FieldIdentitySummaryCache(1);
  const precise = { ...emptyFieldSummary(), returnFlat: new Set(['data:precise']) };
  cache.set('qid::x', emptyState(), precise);

  const other = addIdentity(emptyState(), 'p', 'data:other');
  const degraded = cache.compute('qid::x', other, () => {
    throw new Error('analyzeFn must not run: the cap is already consumed by the empty-entry context');
  });

  assert.equal(degraded, precise, 'the fallback returned past the cap is the very object cached for the empty-entry context — object identity, not a copy');
  assert.equal(cache.get('qid::x', emptyState()), precise);
  // => a naive `fallback.degradedReason = 'context-cap'` would retroactively
  //    mark the PRECISE empty-entry summary as degraded, for every later
  //    reader. §13.6 therefore specifies a shallow copy at this site.
});

test('C3 §13.6 finding 3: a B5 recursion bottom stub is self-effacing — its empty returnFlat means no call-resolved hop is emitted, so there is nothing to mark there either', () => {
  const src = `
    function selfRec(u) { const n = selfRec(u); return { base: u.email, nested: n }; }
    function top(user) { return selfRec(user); }
  `;
  const ir = parseJsFile('/x/c3-b5.js', src);
  const byName = {};
  for (const fn of ir.functions) byName[fn.name] = fn;

  const cache = new FieldIdentitySummaryCache();
  const resolveCallSummary = createCallSummaryResolverC3(cache, lookupCalleeFor(byName));
  const entryState = addIdentity(emptyState(), 'user.email', 'data:email');

  const raw = [];
  const result = analyzeFunctionFieldIdentity(byName.top, entryState, {
    resolveCallSummary,
    recordHop: contextStamping((h) => raw.push(h), entryState),
  });
  const hops = dedupeHops(raw);

  assert.ok(hops.some((h) => h.scope === byName.selfRec.qid), 'the recursive callee\'s own hops are recorded (holes closed)');
  assert.deepEqual([...result.returnFacts[0].identities], ['data:email'], 'and the recursion terminates with a sound result');

  // The self-call inside selfRec: on the bottom-stub round its summary's
  // returnFlat is empty, so engine.js's `for (const id of flat)` loop
  // emits nothing. No hop exists at that moment to carry a marker.
  const selfCallResolved = hops.filter((h) => h.scope === byName.selfRec.qid && h.subKind === 'call-resolved');
  for (const h of selfCallResolved) {
    assert.ok(typeof h.dataElementId === 'string' && h.dataElementId.length > 0,
      'every call-resolved hop that DOES exist carries a real id — a bottom-stub round produces none, rather than an id-less one');
  }
});

// ---------------------------------------------------------------------
// Scenario 6 — §13.3's additivity claim, checked mechanically.
// ---------------------------------------------------------------------

test('C3 §13.3: adding `context`/`peerScope`/`peerContext` to every hop is ADDITIVE — the existing suite\'s presence-based field checks and per-run dedupe counts are unaffected', () => {
  // The §6 worked example, exactly as engine-provenance.test.js pins it at
  // 14 deduplicated records — re-run here with the new fields stamped on.
  const src = `
function f(user) {
  const u = user;
  const o = { email: u.email, ssn: u.ssn };
  return o;
}
`;
  const ir = parseJsFile('/x/c3-additive.js', src);
  const fn = ir.functions.find((f2) => f2.name === 'f');
  let entryState = addIdentity(emptyState(), 'user.email', 'data:email');
  entryState = addIdentity(entryState, 'user.ssn', 'data:ssn');

  const raw = [];
  analyzeFunctionFieldIdentity(fn, entryState, { recordHop: contextStamping((h) => raw.push(h), entryState) });
  const hops = dedupeHops(raw);

  // The existing suite's own guard, verbatim: presence + never-undefined.
  // It is a REQUIRED-fields check, not a closed-set check, so extra fields
  // pass it unchanged.
  const REQUIRED_FIELDS = [
    'kind', 'subKind', 'scope', 'dataElementId', 'fromPath', 'toPath',
    'syntacticPath', 'nodeId', 'line', 'widenReason', 'lossReason',
  ];
  for (const h of hops) {
    for (const field of REQUIRED_FIELDS) {
      assert.ok(Object.prototype.hasOwnProperty.call(h, field), `hop missing "${field}"`);
      assert.notEqual(h[field], undefined);
    }
    // ... and the three new ones are always present too (§3's stable-shape
    // contract: never undefined, never an omitted key).
    for (const field of ['context', 'peerScope', 'peerContext']) {
      assert.ok(Object.prototype.hasOwnProperty.call(h, field), `hop missing new field "${field}"`);
      assert.notEqual(h[field], undefined);
    }
  }

  // Within ONE analysis run `context` is constant, so it cannot split a
  // dedupe group: the count engine-provenance.test.js pins is unchanged.
  assert.equal(new Set(hops.map((h) => h.context)).size, 1);
  assert.equal(hops.length, 14, 'the §6 fixture still deduplicates to exactly 14 records with the new fields stamped on');
});
