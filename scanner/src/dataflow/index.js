// Layer 2 entry point.
import { runTaintEngine } from './engine.js';
import { CATALOG, matchSource, matchSinkOrSanitizer, _catalogSize } from './catalog.js';
import { applyPathFeasibility } from './path-feasibility.js';
import { SummaryCache, entryStateFromCall } from './summaries.js';
import { rhsReachableFunctions, shouldAnalyzeUnderRhs } from './tabulation.js';
import { annotateBackwardSlices } from './backward.js';
import {
  readIncrementalState, validateIncrementalState, diffFileHashes,
  hashFileContent, pickReusableSummaries, seedSummaryCache,
  serializeSummaries, commitIncrementalState,
} from './incremental.js';
import { buildPointsTo } from './points-to.js';
import { annotateSoftTaint } from './soft-taint.js';

export function runDeepAnalysis(perFileIR, callGraph, opts = {}) {
  // Path-feasibility pass over every function before the taint walk.
  let totalPruned = 0;
  for (const fn of callGraph.functions.values()) {
    const r = applyPathFeasibility(fn);
    totalPruned += r.pruned;
  }
  // P2.1 — RHS-lite reachability slice. When AGENTIC_SECURITY_RHS=1 the
  // engine narrows analysis to sink-reachable functions. Default OFF
  // because it changes the finding-set composition.
  if (process.env.AGENTIC_SECURITY_RHS === '1') {
    const ctx = rhsReachableFunctions(perFileIR, callGraph);
    if (ctx.reachable) {
      opts = { ...opts, _rhsReachable: ctx.reachable, _rhsCheck: shouldAnalyzeUnderRhs };
    }
  }
  // v0.69 — cross-scan incremental cache (AGENTIC_SECURITY_INCREMENTAL=1).
  // Read persisted state, seed the SummaryCache with summaries from files
  // whose content hasn't changed, then hand it to runTaintEngine. After,
  // serialize the cache and commit to disk.
  const incrementalEnabled = process.env.AGENTIC_SECURITY_INCREMENTAL === '1';
  let preSeededCache = null;
  let priorState = null;
  let currentFileHashes = null;
  if (incrementalEnabled && opts.scanRoot && opts.fileContents) {
    priorState = readIncrementalState(opts.scanRoot);
    const currentVersion = {
      scanner: opts.scannerVersion || 'unknown',
      rules: opts.rulesDigest || `catalog:${_catalogSize()}`,
    };
    const valid = validateIncrementalState(priorState, currentVersion);
    if (valid.valid) {
      currentFileHashes = {};
      for (const [fp, content] of Object.entries(opts.fileContents)) {
        currentFileHashes[fp] = hashFileContent(content);
      }
      const diff = diffFileHashes(priorState.files || {}, currentFileHashes);
      const changedQids = new Set();
      // Map a changed file to the qids it owns. perFileIR exposes file→fns.
      for (const fp of [...diff.changed, ...diff.added, ...diff.removed]) {
        const ir = perFileIR[fp];
        if (!ir) continue;
        for (const fn of (ir.functions || [])) changedQids.add(fn.qid);
      }
      const persistedPayload = (priorState.summaries && priorState.summaries.summaries) || priorState.summaries || {};
      const callerOfQid = (priorState.summaries && priorState.summaries.callers) || {};
      const { reusable } = pickReusableSummaries(persistedPayload, callerOfQid, changedQids);
      preSeededCache = new SummaryCache();
      const seededN = seedSummaryCache(preSeededCache, persistedPayload, reusable);
      preSeededCache._incrementalSeeded = seededN;
      preSeededCache._incrementalReusable = reusable.size;
    } else {
      // Stale → caller should drop; we just don't seed.
      priorState = null;
    }
  }
  // v0.70 #2 — Steensgaard points-to / alias analysis. Built once before
  // the worklist, passed via opts so the engine can resolve aliased
  // mutations (`let a = obj; a.x = tainted; sink(obj.x)`).
  let pointsToGraph = null;
  if (process.env.AGENTIC_SECURITY_POINTS_TO === '1') {
    try { pointsToGraph = buildPointsTo(perFileIR, callGraph); }
    catch { pointsToGraph = null; }
  }
  let findings = runTaintEngine(perFileIR, callGraph, {
    ...opts,
    summaryCache: preSeededCache || undefined,
    _pointsTo: pointsToGraph || undefined,
  });
  for (const f of findings) f._pathFeasibilityPruned = totalPruned;
  if (preSeededCache) {
    Object.defineProperty(findings, '_incrementalStats', {
      value: {
        seeded: preSeededCache._incrementalSeeded || 0,
        reusable: preSeededCache._incrementalReusable || 0,
      },
      enumerable: false,
    });
  }
  // P1.4 — backward slice (opt-in via AGENTIC_SECURITY_BACKWARD_SLICE=1).
  if (process.env.AGENTIC_SECURITY_BACKWARD_SLICE === '1') {
    findings = annotateBackwardSlices(findings, perFileIR, callGraph);
  }
  // v0.70 #6 — probabilistic / soft taint. Walks each finding's trace +
  // chain, multiplies (1 - effectiveness) across sanitizers, demotes
  // below-threshold findings to lower severity (never drops).
  if (process.env.AGENTIC_SECURITY_SOFT_TAINT === '1') {
    findings = annotateSoftTaint(findings);
  }
  // v0.69 — commit incremental state after a successful scan.
  if (incrementalEnabled && opts.scanRoot && currentFileHashes) {
    const cache = findings._summaryCache;
    const summaries = cache ? serializeSummaries(cache) : {};
    // Reverse call-graph (qid → callers) — derive from callGraph.
    const callers = {};
    if (callGraph && callGraph.functions) {
      for (const fn of callGraph.functions.values()) {
        if (!Array.isArray(fn.calls)) continue;
        for (const callee of fn.calls) {
          if (!callers[callee]) callers[callee] = [];
          callers[callee].push(fn.qid);
        }
      }
    }
    commitIncrementalState(opts.scanRoot, {
      files: currentFileHashes,
      summaries,
      callers,
    }, {
      scanner: opts.scannerVersion || 'unknown',
      rules: opts.rulesDigest || `catalog:${_catalogSize()}`,
    });
  }
  return findings;
}

export { runTaintEngine, CATALOG, matchSource, matchSinkOrSanitizer, _catalogSize, applyPathFeasibility, SummaryCache, entryStateFromCall, rhsReachableFunctions, shouldAnalyzeUnderRhs, annotateBackwardSlices };
