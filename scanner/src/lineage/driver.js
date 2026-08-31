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
// `opts.seedEntryState(fn) -> state | falsy` (Sub-project E, increment 1)
// is the SOURCE-SEEDING hook: it supplies the per-function entry state a
// source registry derived from real matched call sites inside `fn`. It is
// additive and opt-in — omit it and every observable output of this
// function is byte-identical to what it produced before the hook existed
// (`test/lineage/driver.test.js`'s E1 regression tests pin this in both
// directions, against a golden literal). `opts.recordHop` established
// exactly this contract for this file; see DESIGN_GRAPH_BUILDER.md §3.
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
    // Path provenance (Sub-project C, increment 3, §13.7 item 14): thread
    // opts.recordHop into the per-function ctx CONDITIONALLY, so a caller
    // that supplies none gets a byte-identical `{ resolveCallSummary }`
    // object to what this function constructed before this change —
    // Decision 7.2's "true by construction" property, extended to the
    // driver.
    const ctx = opts.recordHop ? { resolveCallSummary, recordHop: opts.recordHop } : { resolveCallSummary };
    // Sub-project E, increment 1 (DESIGN_GRAPH_BUILDER.md §3): the seeding
    // hook. `opts.seedEntryState(fn)` returns the entry state this function
    // should be analyzed under — a `field-identity.js` state carrying the
    // data-element identities a source registry matched at real call sites
    // INSIDE `fn`. Additive and opt-in, exactly like `opts.recordHop`
    // above: with no hook supplied, `entryState` is `emptyState()` and both
    // this call and the `cache.set` below are byte-identical to what this
    // loop did before the hook existed (Decision 7.2's "true by
    // construction" property, extended once more). A hook returning a
    // falsy value is treated as "no seed for this function", so a caller
    // can seed a subset without special-casing the rest.
    const entryState = opts.seedEntryState ? (opts.seedEntryState(fn) || emptyState()) : emptyState();
    const result = analyzeFunctionFieldIdentity(fn, entryState, ctx);
    results.set(fn.qid, result);
    // Seed the cache with this function's OWN empty-entry summary directly
    // (not via cache.compute, which is reserved for a CALL SITE resolving
    // an as-yet-uncomputed callee) — this is what lets a LATER function in
    // fnList that calls this one reuse the driver's own result instead of
    // silently recomputing it a second time.
    //
    // This CAN overwrite an entry a callee-triggered lazy compute() already
    // wrote for the SAME (qid, emptyState()) key earlier in this loop — and
    // a final whole-branch review proved by direct construction that the
    // two computations are NOT guaranteed to agree: createCallGraphLookup's
    // `callerFile` is fixed to the CALLING function's file, so when fn was
    // first analyzed lazily (as someone else's callee), any bare-identifier
    // call fn itself makes was resolved preferring THAT CALLER's file, not
    // fn's own. This loop's own direct call above uses fn.file, the
    // correct scope, so the overwrite here always uses the more precise of
    // the two answers, never a worse one — but it is a real overwrite of a
    // possibly-different prior value, not merely redundant re-computation
    // of an identical one. Today every entry state is emptyState() (no
    // source registry yet), so no identity can actually differ between the
    // two computations and this is unobservable; it becomes load-bearing
    // the moment entry states carry real identities.
    //
    // Sub-project E, increment 1 CLOSED THE SECOND, WORSE HALF of that
    // hazard, which the paragraph above did not name: the KEY. This line
    // used to write the summary under `emptyState()` unconditionally, i.e.
    // under a key that claims "this is what `fn` does when nothing flows
    // in". Once a seed puts real identities into `entryState`, that claim
    // is FALSE — a later call site resolving `fn` with clean arguments
    // builds an empty callee entry state, hits this key, and is handed
    // return facts that exist only because the DRIVER seeded them. That is
    // a fabricated identity at a call site nothing tainted, and it is
    // measurable (see DESIGN_GRAPH_BUILDER.md §3.6: a real two-function
    // fixture, plus a 27% swing in accepted hops on a 33-file project).
    // Keying by the state actually analyzed is both the fix and a no-op
    // when no hook is supplied — `entryState` IS `emptyState()` then, so
    // this line stays byte-identical for every pre-existing caller.
    cache.set(fn.qid, entryState, summaryFromAnalysisResult(result));
  }

  return { results, cache };
}
