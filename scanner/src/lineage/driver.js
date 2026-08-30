import { emptyState } from './field-identity.js';
import { analyzeFunctionFieldIdentity } from './engine.js';
import {
  FieldIdentitySummaryCache,
  createCallGraphLookup,
  createCallSummaryResolver,
  summaryFromAnalysisResult,
} from './summaries.js';

// Project-wide driver (Sub-project B, increment 4) — mirrors
// dataflow/engine.js's runTaintEngine Phase A/B structure, adapted to this
// package's own machinery: B1-B3 already built a fully lazy, on-demand
// interprocedural resolution mechanism, but nothing yet DRIVES it across
// an entire project — every prior increment's test only ever analyzed ONE
// caller function, hand-picking which callee to resolve. This is the
// "producing summaries for a whole small project's worth of functions,
// not just one call site at a time" piece the scoping doc calls out.
//
// Unlike dataflow's own 3-sub-pass Phase A (empty-entry pre-pass plus two
// SPECULATIVE precompute passes, justified by that engine's need to
// pre-seed conservative summaries so a non-computing cache LOOKUP
// mid-expression-walk doesn't have to guess), this driver needs none of
// that: this package's one call-consultation point (`resolveCallSummary`,
// built in B1/B2) already lazily `cache.compute()`s on every miss — see
// `createCallSummaryResolver`. A single pass over every function, each
// analyzed with its own empty entry state and a ctx wired for
// interprocedural resolution, is therefore sufficient: whichever order
// functions are visited in, a call to an as-yet-unvisited callee still
// resolves correctly (lazily, on demand) rather than falling back to a
// conservative default. No fixed-point loop here — recursive/cyclic
// convergence refinement is increment B5's job; this driver relies
// entirely on B1's existing `_stack`-based bottom-stub for safety on a
// recursive/cyclic call graph, exactly as B1-B3 already did.
//
// `callGraph` must be a real object from
// `scanner/src/ir/callgraph.js#buildCallGraph` (`{functions,
// resolveKnownCallee, ...}`) or an equivalent hand-built fixture exposing
// the same shape (see this file's own tests). `opts.maxContextsPerFn` is
// forwarded to a fresh `FieldIdentitySummaryCache` unless `opts.cache` is
// supplied directly, letting a caller reuse/inspect the cache afterward or
// seed it before calling — mirrors dataflow's own `opts.summaryCache`
// escape hatch in `runTaintEngine`.
//
// Returns `{results, cache}`: `results` is a `Map<qid, rawAnalysisResult>`
// — the raw `{exitState, returnFacts, mutatedParams, widenings}` shape
// `analyzeFunctionFieldIdentity` itself returns, one entry per function in
// `callGraph.functions` — and `cache` is the `FieldIdentitySummaryCache`
// instance used throughout, seeded with every function's own empty-entry
// summary (converted via `summaryFromAnalysisResult`) plus whatever
// additional real-context entries were computed lazily along the way as
// call sites were resolved.
export function runFieldIdentityAnalysis(callGraph, opts = {}) {
  const cache = opts.cache instanceof FieldIdentitySummaryCache
    ? opts.cache
    : new FieldIdentitySummaryCache(opts.maxContextsPerFn);

  const fnList = callGraph && callGraph.functions
    ? [...callGraph.functions.values()].sort((a, b) => (a.qid < b.qid ? -1 : a.qid > b.qid ? 1 : 0))
    : [];

  const results = new Map();
  for (const fn of fnList) {
    const lookupCallee = createCallGraphLookup(callGraph, fn.file);
    const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
    const result = analyzeFunctionFieldIdentity(fn, emptyState(), { resolveCallSummary });
    results.set(fn.qid, result);
    // Seed the cache with this function's OWN empty-entry summary directly
    // (not via cache.compute, which is reserved for a CALL SITE resolving
    // an as-yet-uncomputed callee) — this is what lets a LATER function in
    // fnList that calls this one reuse the driver's own result instead of
    // silently recomputing it a second time. Safe to overwrite an entry a
    // callee-triggered lazy compute() may have already written for the
    // SAME (qid, emptyState()) key earlier in this loop — deterministic
    // analysis means both would agree; this is redundant work in that
    // case, never a correctness issue.
    cache.set(fn.qid, emptyState(), summaryFromAnalysisResult(result));
  }

  return { results, cache };
}
