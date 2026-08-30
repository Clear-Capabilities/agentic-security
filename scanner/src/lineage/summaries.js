import { hashState, emptyState, addIdentity } from './field-identity.js';
import { resolveExprIdentities, residualFlat, analyzeFunctionFieldIdentity } from './engine.js';
import { accessPathOf } from '../dataflow/access-paths.js';
import { functionRecord } from '../ir/callgraph.js';

export function emptyFieldSummary() {
  return { returnFlat: new Set(), returnByPath: new Map(), mutatedParams: new Map(), widenings: [] };
}

const DEFAULT_MAX_CONTEXTS = 16; // matches dataflow/summaries.js's own default, chosen independently for this
                                  // package (a lineage-specific cap, not shared config, per the isolation
                                  // principle — see the constructor param below for how a caller can override it)

export class FieldIdentitySummaryCache {
  constructor(maxContextsPerFn = DEFAULT_MAX_CONTEXTS) {
    this._cache = new Map();
    this._stack = new Set();
    this._contextsByQid = new Map();
    this._maxContextsPerFn = maxContextsPerFn;
  }

  _key(qid, entryState) {
    return `${qid}::${hashState(entryState)}`;
  }

  has(qid, entryState) {
    return this._cache.has(this._key(qid, entryState));
  }

  get(qid, entryState) {
    return this._cache.get(this._key(qid, entryState));
  }

  set(qid, entryState, summary) {
    this._cache.set(this._key(qid, entryState), summary);
    const hash = hashState(entryState);
    const seen = this._contextsByQid.get(qid) ?? new Set();
    seen.add(hash);
    this._contextsByQid.set(qid, seen);
  }

  compute(qid, entryState, analyzeFn) {
    if (this.has(qid, entryState)) return this.get(qid, entryState);

    const hash = hashState(entryState);
    const seen = this._contextsByQid.get(qid) ?? new Set();
    if (!seen.has(hash) && seen.size >= this._maxContextsPerFn) {
      // Past this function's distinct-context cap: degrade to the
      // empty-entry summary (if one exists) rather than computing an
      // unbounded number of contexts. Mirrors
      // dataflow/summaries.js's own graceful degradation past its own cap.
      const fallback = this._cache.get(this._key(qid, emptyState())) ?? emptyFieldSummary();
      this.set(qid, entryState, fallback);
      return fallback;
    }

    if (this._stack.has(qid)) {
      // Recursion guard, THIS INCREMENT'S SCOPE: return a bottom stub
      // immediately, never recurse further, and do NOT attempt any
      // fixed-point refinement here — that precision improvement is
      // increment B5's job. This guard's only job in B1 is safety (never
      // infinite-loop on a hand-built recursive call graph), not
      // precision. A caller receiving `_recursive: true` knows this
      // summary may under-approximate the function's real behavior.
      return { ...emptyFieldSummary(), _recursive: true };
    }

    this._stack.add(qid);
    try {
      // A final whole-branch review found this method previously had no
      // try/finally around analyzeFn — if it threw, qid stayed on _stack
      // forever, and every LATER compute() call for that qid would fall
      // into the recursion guard above and silently return a bottom stub,
      // permanently. Not reachable at this increment's own hand-built-test
      // scope, but live the moment a real driver (B4) runs
      // analyzeFunctionFieldIdentity over real parsed IR — that function
      // throws a plain TypeError on a malformed `fn`, and a sensible
      // driver catching-and-continuing would otherwise silently spread
      // "one function failed" into "this function under-reports for the
      // rest of the run," the exact silent-under-approximation class the
      // intraprocedural engine spent six rounds closing. Mirrors
      // dataflow/summaries.js's own try/finally around the identical
      // stack-push/pop pattern.
      const summary = analyzeFn(entryState);
      this.set(qid, entryState, summary);
      return summary;
    } finally {
      this._stack.delete(qid);
    }
  }

  size() {
    return this._cache.size;
  }

  clear() {
    this._cache.clear();
    this._stack.clear();
    this._contextsByQid.clear();
  }
}

// Maps a call site's argument expressions onto a fresh entry state for the
// callee, keyed by the callee's own parameter names — the interprocedural
// analog of `engine.js`'s `assign` transfer function: each argument is
// resolved against the CALLER's current state via `resolveExprIdentities`,
// and its residual (root-level) identities plus its byPath (field-level)
// structure are both written into the callee's entry state at the
// corresponding parameter name, using the exact same residual+byPath split
// `assign` already uses — this is a direct, deliberate reuse of Sub-project
// A's already-hardened write pattern, not a new mechanism.
export function entryStateFromCall(paramNames, callArgs, callerState) {
  let entryState = emptyState();
  const n = Math.min(paramNames.length, callArgs.length);
  for (let i = 0; i < n; i++) {
    const paramName = paramNames[i];
    const resolved = resolveExprIdentities(callerState, callArgs[i]);
    const residual = residualFlat(resolved.flat, resolved.byPath);
    for (const id of residual) entryState = addIdentity(entryState, paramName, id);
    for (const [subPath, ids] of resolved.byPath) {
      for (const id of ids) entryState = addIdentity(entryState, `${paramName}.${subPath}`, id);
    }
  }
  return entryState;
}

// Maps a callee's summary back onto the CALLER's own state at the call
// site — the interprocedural analog of reading a function's return value
// and observing its side effects. Unlike dataflow/summaries.js's
// applyAtCallSite (which only propagates a mutation back for a bare
// `ident` argument, silently dropping a `member`-expression argument like
// `f(obj.field)`), this version also resolves a member-expression argument
// via `accessPathOf` — a deliberate, scoped improvement: field mutations
// plausibly target `obj.field`-shaped arguments often enough that
// dropping them silently would be a real, avoidable under-approximation.
export function applyAtCallSite(summary, paramNames, callArgs) {
  const mutations = [];
  for (const [paramPath, ids] of summary.mutatedParams) {
    const [rootParamName, ...rest] = paramPath.split('.');
    const idx = paramNames.indexOf(rootParamName);
    if (idx === -1) continue;
    const arg = callArgs[idx];
    const argPath = accessPathOf(arg);
    if (!argPath) continue;
    const fullPath = rest.length > 0 ? `${argPath}.${rest.join('.')}` : argPath;
    mutations.push({ path: fullPath, dataElementIds: [...ids] });
  }
  return { returnFlat: summary.returnFlat, returnByPath: summary.returnByPath, mutations };
}

// Builds a `resolveCallSummary` closure — the shape `resolveExprIdentities`'s
// `call` case now consults (see engine.js) — wired to a real
// FieldIdentitySummaryCache. `lookupCallee` is itself injected and
// deliberately opaque to this function: this increment's own tests pass a
// simple hand-built name-to-function map; increment B3's real call-graph
// integration will pass a resolver backed by `scanner/src/ir/callgraph.js`
// instead, without this function (or `resolveExprIdentities`) needing to
// change at all.
export function createCallSummaryResolver(cache, lookupCallee) {
  return function resolveCallSummary(calleeExpr, callArgs, callerState) {
    const resolved = lookupCallee(calleeExpr);
    if (!resolved) return null;
    const { qid, fn } = resolved;
    const entryState = entryStateFromCall(fn.params, callArgs, callerState);
    return cache.compute(qid, entryState, (es) => {
      // Pass THIS SAME resolver down as the callee's own ctx — without
      // this, a chain of resolved calls (outer resolves to middle, middle
      // itself calls inner) would silently stop resolving after one hop:
      // middle's own analysis would run with no ctx, so its call to inner
      // would take the unresolved fallback, and outer would receive a
      // coarsely-widened summary reported as `widened: false` (since
      // resolveExprIdentities's call case only reads summary.returnFlat/
      // returnByPath, never summary.widenings) — a confident-looking
      // answer that's silently wrong one level down. A final whole-branch
      // review found and proved this exact gap via a real three-function
      // chain. Passing the resolver down makes resolution recurse through
      // as many resolved hops as `lookupCallee` can cover, with the
      // existing recursion guard (field-identity summary cache's `_stack`
      // bottom-stub) already sufficient to keep a self- or mutually-
      // recursive chain safe (verified: both terminate immediately,
      // returning an empty, honestly-unrefined result — precision there
      // is increment B5's job, not this fix's).
      const result = analyzeFunctionFieldIdentity(fn, es, { resolveCallSummary });
      // Union across EVERY return site, not just the first — a function
      // with multiple return statements (e.g. an early-return branch) must
      // have all of them reflected, not just whichever happened to be
      // recorded first. This is a genuine correctness improvement over
      // increment B1's own round-trip test's `returnFacts[0]` shortcut
      // (that test only ever exercised a single-return-site function, so
      // the shortcut was harmless there — this shared, reusable resolver is
      // the right place to do it correctly going forward).
      const returnFlat = new Set();
      for (const rf of result.returnFacts) {
        for (const id of rf.identities) returnFlat.add(id);
      }
      return {
        returnFlat,
        returnByPath: new Map(), // still flat-only — see B1's disclosed limitation in CLAUDE.md; not closed by this increment either
        mutatedParams: result.mutatedParams,
        widenings: result.widenings,
      };
    });
  };
}

// Resolves a call expression's callee to a bare, resolvable name — the
// lineage-engine analog of dataflow/engine.js's own `_resolvableCalleeName`
// BASE CASE (before that file's later, CHA-gated member-expression
// extension) for the `calleeExpr.kind === 'ident'` branch specifically.
// Deliberately narrow: only a bare identifier callee (`helper(x)`) resolves
// to a name at all. A member-expression callee (`obj.helper(x)`) returns
// null here, on purpose — resolving THAT safely needs class-hierarchy
// analysis (which method does the object concretely carry), a separate,
// much larger mechanism dataflow built specifically for its own R11
// requirement (`_resolveMemberCalleeViaCHA`, gated on a `_cha` object this
// package has no equivalent of and is not in scope to build here).
// Guessing from the property name alone would fabricate a call edge that
// may not exist — worse than leaving the call unresolved, matching this
// whole codebase's own stated doctrine (see callgraph.js's comments on
// `resolveKnownCallee` vs. the guessing `resolve()`).
//
// UNLIKE dataflow's version, this one does NOT also accept a plain string
// callee (`typeof calleeExpr === 'string'`). Per the IR shape contract
// (scanner/src/ir/CLAUDE.md), `callee` is `string|expr` — the seven
// hand-rolled parsers (Python/Ruby/PHP/Go/Java/C#/Kotlin) emit a flat,
// dot-joined STRING callee, never a structured `{kind:'ident'}` node. This
// means `createCallGraphLookup` below resolves NOTHING for those
// languages' IR today — every call in a non-JS/TS file silently takes the
// unresolved-call fallback (flat + widened:true), the same fail-safe
// direction as an unresolvable JS/TS call, just unconditionally so. This
// is not an oversight: naively accepting a dotted string (e.g. Java's
// class-qualified `"App.getUser"`) and handing it to `resolveKnownCallee`
// would resolve it via that function's project-wide bare-name index —
// which is member-call resolution in disguise, exactly what this
// increment's CHA-free scope forbids. Whether/how to extend real
// interprocedural resolution to the hand-rolled-parser languages is
// undecided and out of scope for Sub-project B's current B1-B6 breakdown.
function _resolvableCalleeName(calleeExpr) {
  if (!calleeExpr) return null;
  if (calleeExpr.kind === 'ident') return calleeExpr.name || null;
  return null;
}

// Builds a real `lookupCallee` closure — the shape `createCallSummaryResolver`
// expects as its second argument — backed by a real call graph from
// `scanner/src/ir/callgraph.js#buildCallGraph`. `callerFile` is fixed at
// construction time: one `lookupCallee` closure is built per analyzed
// function/file (mirroring how `dataflow/engine.js`'s own
// `_resolveCalleeForSummary` derives `_callerFile` fresh per call context),
// so `createCallSummaryResolver`'s existing single-argument `lookupCallee`
// shape (no caller-file parameter) does not need to change.
//
// Uses `resolveKnownCallee` — never `resolve()` — matching `callgraph.js`'s
// own documented distinction: `resolveKnownCallee` is "safe-by-default,"
// refusing the bare-name-tail guess `resolve()` is willing to make. This
// package's own doctrine (see FR-301, never silently merge/drop distinct
// identities) treats a fabricated call edge as strictly worse than a missed
// one, same as dataflow's own precedent.
export function createCallGraphLookup(callGraph, callerFile) {
  return function lookupCallee(calleeExpr) {
    if (!callGraph || typeof callGraph.resolveKnownCallee !== 'function') return null;
    const name = _resolvableCalleeName(calleeExpr);
    if (!name) return null;
    const resolved = callGraph.resolveKnownCallee(name, callerFile);
    if (!resolved) return null;
    const fn = functionRecord(callGraph, resolved);
    if (!fn) return null;
    return { qid: resolved, fn };
  };
}
