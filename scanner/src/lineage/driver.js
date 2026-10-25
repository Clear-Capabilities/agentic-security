import { emptyState, hashState } from './field-identity.js';
import { computeScc } from '../graph/scc.js';
import { solveRecursiveComponent } from './scc-solver.js';
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
// DAG-01 UPDATE (SCC scheduling). Functions are now scheduled over the
// condensation of the call graph (`graph/scc.js`), callees before callers,
// ties broken by qid. Call edges come from `callGraph.edges` (caller ->
// callee qids, as `buildCallGraph` emits) or `opts.calleesOf(fn) -> qid[]`;
// a hand-built graph with neither has no edges, so every function is its own
// component and the order is exactly the old sorted-qid order. A component
// that is a single function with no self-call runs the legacy single-pass
// step unchanged. A RECURSIVE component (two or more functions, or a
// self-call) is solved by `scc-solver.js`: re-analyze each member until a
// full round changes no member summary (see that file for the bounded fact
// domain, the join/widening policy and what "converged" does and does not
// mean). Every analysis in a round re-reads the previous round's summaries.
// The return value gains `convergence`; `results` keeps ascending-qid order.
//
// Budgets (all optional, deterministic where possible): `opts.maxRounds`,
// `opts.maxPathDepth`, `opts.maxFunctionAnalyses` (a work count),
// `opts.deadlineMs` with `opts.now()` (default Date.now), `opts.signal`.
// When any of them stops the run, `convergence.converged` is false,
// `status` is 'partial', and `remainingFrontier` lists the qids that were
// not finished. A partial result must never be read as a safety proof.
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
  // Live progress, additive/opt-in. Each function is reported once, the first
  // time it is analyzed (recursive re-rounds are not re-reported).
  const onProgress = typeof opts.onProgress === 'function' ? opts.onProgress : null;
  let _progressN = 0;
  const reported = new Set();
  const progress = (fn) => {
    if (!onProgress || reported.has(fn.qid)) return;
    reported.add(fn.qid);
    onProgress({ current: ++_progressN, total: fnList.length });
  };

  const results = new Map();
  const fnByQid = new Map(fnList.map(f => [f.qid, f]));

  // --- Schedule: SCC condensation of the call graph, callees first. -------
  const edges = [];
  const edgeSeen = new Set();
  const addEdge = (caller, callee) => {
    if (!fnByQid.has(caller) || !fnByQid.has(callee)) return;
    const k = `${caller}\u0000${callee}`;
    if (edgeSeen.has(k)) return;
    edgeSeen.add(k);
    // Dependency direction: the callee must come before the caller.
    edges.push([callee, caller]);
  };
  if (callGraph && Array.isArray(callGraph.edges)) {
    for (const e of callGraph.edges) if (e && typeof e.callee === 'string') addEdge(e.caller, e.callee);
  }
  if (typeof opts.calleesOf === 'function') {
    for (const fn of fnList) for (const c of (opts.calleesOf(fn) || [])) addEdge(fn.qid, c);
  }
  const scc = computeScc({ nodes: fnList.map(f => f.qid), edges });

  // --- Budget. ------------------------------------------------------------
  const now = typeof opts.now === 'function' ? opts.now : Date.now;
  let work = 0;
  let stopReason = null;
  const shouldStop = () => {
    if (stopReason) return stopReason;
    if (opts.signal && opts.signal.aborted) stopReason = 'aborted';
    else if (typeof opts.deadlineMs === 'number' && now() >= opts.deadlineMs) stopReason = 'deadline';
    else if (Number.isFinite(opts.deadline) && Date.now() > opts.deadline) stopReason = 'deadline';
    else if (typeof opts.maxFunctionAnalyses === 'number' && work >= opts.maxFunctionAnalyses) stopReason = 'work-limit';
    return stopReason;
  };

  // Sub-project E, increment 1 (DESIGN_GRAPH_BUILDER.md section 3): the
  // seeding hook. `opts.seedEntryState(fn)` returns the entry state `fn` is
  // analyzed under; a falsy return means "no seed". With no hook, this IS
  // `emptyState()` and every output is byte-identical to the pre-hook driver.
  const entryStateOf = (fn) => (opts.seedEntryState ? (opts.seedEntryState(fn) || emptyState()) : emptyState());
  const ctxFor = (fn) => {
    const lookupCallee = createCallGraphLookup(callGraph, fn.file);
    const resolveCallSummary = createCallSummaryResolver(cache, lookupCallee);
    // Path provenance (Sub-project C, increment 3, section 13.7 item 14):
    // thread opts.recordHop CONDITIONALLY so a caller that supplies none gets
    // a byte-identical `{ resolveCallSummary }` object (Decision 7.2).
    const ctx = opts.recordHop ? { resolveCallSummary, recordHop: opts.recordHop } : { resolveCallSummary };
    // DAG-07: optional per-function iteration ceiling and cooperative stop
    // (engine.js ignores a non-positive-integer ceiling, so this cannot loosen it).
    if (opts.maxIterations !== undefined) ctx.maxIterations = opts.maxIterations;
    if (opts.signal || opts.deadline !== undefined || opts.deadlineMs !== undefined) ctx.shouldStop = () => { const r = shouldStop(); return r === 'aborted' || r === 'deadline'; };
    return ctx;
  };
  const notesFrom = cache.completionNotes().length;

  const convergence = {
    converged: true,
    status: 'complete',
    rounds: 0,
    changedFacts: [],
    changedFactsTotal: 0,
    wideningReasons: [],
    remainingFrontier: [],
    stoppedBy: null,
    components: [],
  };
  const wideningReasons = new Set();
  const frontier = new Set();

  const orderedComponents = scc.order.map(id => scc.components[id]);
  for (const comp of orderedComponents) {
    if (!comp.recursive) {
      const fn = fnByQid.get(comp.members[0]);
      if (shouldStop()) { frontier.add(fn.qid); continue; }
      work++;
      progress(fn);
      const entryState = entryStateOf(fn);
      const result = analyzeFunctionFieldIdentity(fn, entryState, ctxFor(fn));
      results.set(fn.qid, result);
      // Seed the cache with this function's OWN summary, keyed by the state
      // actually analyzed. This can overwrite an entry a callee-triggered
      // lazy compute() wrote for the same key; the overwrite is the more
      // precise answer (it resolves bare-identifier calls against fn.file).
      // With the E1 key fix this is a no-op difference when no seed hook is
      // supplied. See DESIGN_GRAPH_BUILDER.md section 3.6.
      cache.set(fn.qid, entryState, summaryFromAnalysisResult(result));
      continue;
    }

    // Recursive component: solve to a fixed point or report partial.
    const entryStates = new Map(comp.members.map(q => [q, entryStateOf(fnByQid.get(q))]));
    const keepHashes = new Map(comp.members.map(q => [q, new Set([hashState(entryStates.get(q))])]));
    const solved = solveRecursiveComponent({
      members: comp.members,
      maxRounds: opts.maxRounds,
      maxPathDepth: opts.maxPathDepth,
      maxChangedFacts: opts.maxChangedFacts,
      shouldStop,
      beforeRound() {
        // Contexts reached through call-site argument states were computed
        // against an earlier round's summaries. Forget them; the seeded
        // entry context stays and is overwritten by `publish`.
        for (const q of comp.members) cache.dropContexts(q, keepHashes.get(q));
      },
      publish(q, summary) {
        cache.set(q, entryStates.get(q), summary);
      },
      analyze(q) {
        const fn = fnByQid.get(q);
        work++;
        progress(fn);
        let result;
        const raw = cache.refreshing(q, entryStates.get(q), () => cache.compute(q, entryStates.get(q), (es) => {
          result = analyzeFunctionFieldIdentity(fn, es, ctxFor(fn));
          return summaryFromAnalysisResult(result);
        }));
        results.set(q, result);
        return raw;
      },
    });
    for (const r of solved.wideningReasons) wideningReasons.add(r);
    convergence.rounds = Math.max(convergence.rounds, solved.rounds);
    convergence.changedFactsTotal += solved.changedFactsTotal;
    for (const f of solved.changedFacts) convergence.changedFacts.push({ component: comp.id, ...f });
    convergence.components.push({
      id: comp.id,
      members: comp.members,
      rounds: solved.rounds,
      converged: solved.converged,
      stoppedBy: solved.stoppedBy,
      changedFacts: solved.changedFactsTotal,
    });
    if (!solved.converged) {
      for (const q of solved.remainingFrontier) frontier.add(q);
      if (solved.stoppedBy && !convergence.stoppedBy) convergence.stoppedBy = solved.stoppedBy;
    }
  }
  if (stopReason) convergence.stoppedBy = stopReason;

  // Anything never reached because a budget stopped the run is frontier too.
  if (stopReason) for (const fn of fnList) if (!results.has(fn.qid)) frontier.add(fn.qid);
  convergence.remainingFrontier = [...frontier].sort();
  convergence.wideningReasons = [...wideningReasons].sort();
  if (convergence.stoppedBy || convergence.remainingFrontier.length > 0) {
    convergence.converged = false;
    convergence.status = 'partial';
  }

  // Keep `results` in ascending-qid order regardless of schedule order.
  const ordered = new Map();
  for (const fn of fnList) if (results.has(fn.qid)) ordered.set(fn.qid, results.get(fn.qid));

  // DAG-07 completion roll-up: per-function budget stops, degraded
  // contexts and cancellation, so a cut-short unit is visible even when it
  // emitted nothing.
  const incomplete = [];
  let cancelled = false;
  for (const fn of fnList) {
    const r = ordered.get(fn.qid);
    if (!r || !r.completion || r.completion.status === 'complete') continue;
    if (r.completion.status === 'cancelled') cancelled = true;
    incomplete.push({
      qid: fn.qid,
      context: hashState(entryStateOf(fn)),
      reasons: r.completion.reasons,
      iterations: r.completion.iterations,
      maxIterations: r.completion.maxIterations,
      unfinishedWork: r.completion.unfinishedWork,
    });
  }
  if (stopReason === 'aborted' || stopReason === 'deadline') cancelled = true;
  const notAnalyzed = fnList.length - ordered.size;
  const seen = new Set();
  const degraded = cache.completionNotes().slice(notesFrom).filter((n) => {
    const k = `${n.qid}:${n.reason}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const completion = {
    status: cancelled ? 'cancelled'
      : (incomplete.length === 0 && degraded.length === 0 && convergence.status === 'complete') ? 'complete' : 'partial',
    functionsAnalyzed: ordered.size,
    functionsNotAnalyzed: notAnalyzed,
    incomplete,
    degraded,
  };

  return { results: ordered, cache, convergence, completion };
}
