// Function-summary cache for context-sensitive interprocedural taint.
//
// PRD §6.2: "k-CFA configurable per analysis." This module is VALUE-context
// sensitive (FR-SEM-2): a function gets a distinct summary PER distinct
// entry-taint-state, cached by hash and computed lazily at the call sites
// that need it (see engine.js). So a helper that is pure when called with
// clean args but vulnerable when called with tainted args is modelled
// correctly at each call site, not collapsed to one empty-entry result.
//
// To bound the blowup that per-context computation invites, the number of
// distinct NON-empty contexts kept per function is capped
// (`_maxContextsPerFn`, env `AGENTIC_SECURITY_KCFA_MAX_CONTEXTS`, default 16;
// 0 = pure monovariant). Over the cap we reuse the empty-entry summary.
// Call-string (k>1) sensitivity is still not modelled — context is the
// value-abstraction (which params are tainted), not the call stack.
//
// A summary captures, given a set of tainted parameter names at function
// entry, what the function does:
//   - which return value(s) are tainted
//   - which call-site arguments get mutated to tainted (by-reference)
//   - which global / module variables get tainted
//   - which findings emit
//
// The taint engine (engine.js) consults the summary cache before re-analyzing
// a callee. Cache key = `${qid}::${sorted-taint-state}`. Cache hits are O(1).
//
// Limitations:
//   - Field sensitivity is at the parameter granularity only (not arbitrary
//     access paths). `f(obj)` with obj.foo tainted is treated the same as
//     obj.bar tainted.
//   - No higher-order tracking — callbacks passed as args aren't analyzed.
//   - Recursion: when we'd recurse into a function already on the analysis
//     stack, we return the bottom summary (no-taint) and rely on fixed-point
//     iteration. With k=1 this converges in ≤2 iterations for typical code.

import * as crypto from 'node:crypto';
import { canonicalize as canonicalizeAccessSet } from './access-paths.js';
import { hashReceiverType } from './receiver-context.js';

function _hashState(taintedParams) {
  if (!taintedParams || taintedParams.size === 0) return 'empty';
  // P1.1: canonicalize the access-path lattice before hashing so equivalent
  // states (e.g. {"x", "x.y"} and {"x"}) produce the same cache key.
  const canon = canonicalizeAccessSet(taintedParams);
  const sorted = [...canon].sort().join('|');
  return crypto.createHash('sha256').update(sorted).digest('hex').slice(0, 12);
}

export class SummaryCache {
  constructor() {
    this._cache = new Map(); // qid::hash → summary
    this._stack = new Set(); // qids currently being analyzed (recursion guard)
    this._iter = 0;
    this._maxIter = 5000;
    // FR-SEM-2 (roadmap #2): the engine computes a distinct summary per
    // entry-taint-state (value-context sensitivity), computed lazily at call
    // sites. To stop that from blowing up when a hot helper is reached under
    // many distinct tainted-arg combinations, cap the number of NON-empty
    // entry contexts kept per function. Over the cap we reuse the empty-entry
    // (monovariant) summary — the conservative base the pre-pass computed.
    //   AGENTIC_SECURITY_KCFA_MAX_CONTEXTS=N  (default 16)
    //   ...=0  disables context-sensitivity (pure monovariant).
    this._contextsByQid = new Map(); // qid → Set<stateHash> of computed contexts
    const envCap = Number(process.env.AGENTIC_SECURITY_KCFA_MAX_CONTEXTS);
    this._maxContextsPerFn = Number.isFinite(envCap) && envCap >= 0 ? envCap : 16;
    this._contextCapHits = 0;
    // R2 (PRD §5): bounded k=1 call-string sensitivity. OPT-IN (default OFF).
    // When on, the cache key is extended with the immediate caller's qid, so two
    // call paths reaching a helper with the SAME tainted-arg shape get DISTINCT
    // summaries instead of sharing one (removes the over-merge that the pure
    // value-context cache produces). Off by default → keys are byte-identical to
    // before, so no behavior change for the shipped engine.
    this._callString = process.env.AGENTIC_SECURITY_KCFA_CALLSTRING === '1';
    this._callerCtx = null;
  }

  // Set the immediate-caller qid for call-string keying; returns the previous
  // value so the engine can save/restore it around nested callee analysis.
  setCallerContext(callerQid) {
    const prev = this._callerCtx;
    this._callerCtx = callerQid || null;
    return prev;
  }

  _key(qid, taintedParams, receiverType) {
    // P1.2: when a receiver type is provided, extend the cache key with
    // its hash. Backward-compatible: no receiverType → same key as before.
    let base = `${qid}::${_hashState(taintedParams)}`;
    // R2: append the caller qid when call-string sensitivity is enabled.
    if (this._callString && this._callerCtx) base = `${base}@${this._callerCtx}`;
    if (!receiverType) return base;
    return `${base}::${hashReceiverType(receiverType)}`;
  }

  get(qid, taintedParams, receiverType) {
    return this._cache.get(this._key(qid, taintedParams, receiverType));
  }

  set(qid, taintedParams, summary, receiverType) {
    this._cache.set(this._key(qid, taintedParams, receiverType), summary);
  }

  has(qid, taintedParams, receiverType) {
    return this._cache.has(this._key(qid, taintedParams, receiverType));
  }

  // Compute the summary for a function (or return cached). The `analyze`
  // callback is the per-function walker that returns
  //   { returnTainted, mutatedParams: Set, taintedGlobals: Set, findings: [] }
  //
  // Fixed-point iteration: when a recursive call returns a bottom stub,
  // re-analyze up to FP_MAX times until the summary stabilizes.
  compute(qid, taintedParams, analyze) {
    const k = this._key(qid, taintedParams);
    if (this._cache.has(k)) {
      const cached = this._cache.get(k);
      if (!cached._recursive) return cached;
    }
    // Context cap (FR-SEM-2). Empty entry is always allowed — it's the base
    // summary the pre-pass computes for every function. For a NON-empty
    // context that's new and over budget, reuse the empty-entry summary
    // instead of computing a fresh one.
    const stateHash = _hashState(taintedParams);
    if (stateHash !== 'empty') {
      let ctxs = this._contextsByQid.get(qid);
      if (!ctxs) { ctxs = new Set(); this._contextsByQid.set(qid, ctxs); }
      if (!ctxs.has(stateHash) && ctxs.size >= this._maxContextsPerFn) {
        this._contextCapHits++;
        const base = this._cache.get(this._key(qid, new Set()));
        if (base && !base._recursive) return base;
        // No base summary yet → fall through and compute this one (we need a
        // result), but don't grow the context set.
      } else {
        ctxs.add(stateHash);
      }
    }
    if (this._stack.has(qid)) {
      this._hitRecursion = true;
      return { returnTainted: false, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [], _recursive: true };
    }
    if (++this._iter > this._maxIter) {
      return { returnTainted: false, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [], _budgetExceeded: true };
    }
    this._stack.add(qid);
    this._hitRecursion = false;
    try {
      let summary = analyze(qid, taintedParams);
      this._cache.set(k, summary);
      if (this._hitRecursion) {
        const FP_MAX = 3;
        for (let fp = 0; fp < FP_MAX; fp++) {
          if (++this._iter > this._maxIter) break;
          const prev = summary;
          summary = analyze(qid, taintedParams);
          if (_summaryEq(prev, summary)) break;
          this._cache.set(k, summary);
        }
      }
      if (summary._recursive) delete summary._recursive;
      return summary;
    } finally {
      this._stack.delete(qid);
    }
  }

  // Helper: apply a summary to a caller's taint state given the call site's
  // argument bindings. Returns { calleeReturnTainted, mutated: Set of caller-side
  // var names that should become tainted because the callee mutated them }.
  applyAtCallSite(summary, paramNames, callArgs, callerTaintedVars) {
    if (!summary) return { returnTainted: false, mutated: new Set() };
    const mutated = new Set();
    if (summary.mutatedParams && summary.mutatedParams.size) {
      // Map each mutated parameter position back to the caller-side argument name.
      for (const paramName of summary.mutatedParams) {
        const idx = paramNames.indexOf(paramName);
        if (idx < 0) continue;
        const arg = callArgs[idx];
        if (arg && arg.kind === 'ident') mutated.add(arg.name);
      }
    }
    return { returnTainted: !!summary.returnTainted, mutated };
  }

  size() { return this._cache.size; }
  clear() { this._cache.clear(); this._iter = 0; this._contextsByQid.clear(); this._contextCapHits = 0; }
}

function _summaryEq(a, b) {
  if (!a || !b) return a === b;
  if (!!a.returnTainted !== !!b.returnTainted) return false;
  if ((a.mutatedParams?.size || 0) !== (b.mutatedParams?.size || 0)) return false;
  return true;
}

// Build the entry-taint-state for a callee from a call site:
//   given the callee's param names + the caller's tainted-var set + the
//   call args, return a Set of param names that are tainted at entry.
export function entryStateFromCall(paramNames, callArgs, callerTaintedVars) {
  const out = new Set();
  if (!Array.isArray(paramNames) || !Array.isArray(callArgs)) return out;
  for (let i = 0; i < paramNames.length && i < callArgs.length; i++) {
    const arg = callArgs[i];
    if (!arg) continue;
    if (arg.kind === 'ident' && callerTaintedVars.has(arg.name)) {
      out.add(paramNames[i]);
    } else if (arg.kind === 'member' && arg.object?.kind === 'ident') {
      const base = arg.object.name;
      if (callerTaintedVars.has(base) || callerTaintedVars.has(`${base}.${arg.prop}`)) {
        out.add(paramNames[i]);
      }
    }
  }
  return out;
}
