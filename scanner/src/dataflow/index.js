// Layer 2 entry point.
import { runTaintEngine } from './engine.js';
import { annotateProvenClean } from './proven-clean.js';
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
import { runIfdsTaintEngine } from './ifds.js';
import { proveExploits } from './exploit-prover.js';
import { applyStubAwareFilter } from './stub-aware-filter.js';
import { loadProjectStubs } from '../ir/type-stubs.js';

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
    // Compute current file hashes UNCONDITIONALLY — the first scan (and any
    // scan after a version/rule invalidation) must persist a baseline so the
    // NEXT scan has something to reuse. This previously lived inside the
    // valid-state branch, so a cold cache never committed and incremental was
    // a permanent no-op (the commit guard at the bottom keys on currentFileHashes).
    currentFileHashes = {};
    for (const [fp, content] of Object.entries(opts.fileContents)) {
      currentFileHashes[fp] = hashFileContent(content);
    }
    const valid = validateIncrementalState(priorState, currentVersion);
    if (valid.valid) {
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
  // v0.71 #3 — IFDS alternative analyzer (AGENTIC_SECURITY_IFDS=1).
  // Runs the formal Reps-Horwitz-Sagiv tabulation in parallel with the
  // worklist engine. We MERGE findings — the IFDS solver may catch
  // context-sensitive flows the k=2 cache joined out. Deduped by sink+line.
  let findings = runTaintEngine(perFileIR, callGraph, {
    ...opts,
    summaryCache: preSeededCache || undefined,
    _pointsTo: pointsToGraph || undefined,
  });
  if (process.env.AGENTIC_SECURITY_IFDS === '1') {
    try {
      const ifdsFindings = runIfdsTaintEngine(perFileIR, callGraph, opts);
      const existing = new Set(findings.map(f => `${f.file}:${f.line}:${f.sink?.label || ''}`));
      for (const f of ifdsFindings) {
        const key = `${f.file}:${f.line}:${f.sink?.label || ''}`;
        if (!existing.has(key)) findings.push(f);
      }
    } catch { /* IFDS failure should not fail the scan */ }
  }
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
  // Roadmap #6 — flow-proof: prove SQL sinks reached only through a
  // parameterizer (`provenClean`). Runs by default in the deep pass; it only
  // touches IR-TAINT SQL findings and never drops anything. The proof-gate
  // annotator (engine.js) consolidates this into the demotion verdict.
  if (process.env.AGENTIC_SECURITY_NO_PROOF_GATE !== '1') {
    try { findings = annotateProvenClean(findings, perFileIR); } catch { /* proof failure must not fail the scan */ }
  }
  // v0.70 #6 — probabilistic / soft taint. Walks each finding's trace +
  // chain, multiplies (1 - effectiveness) across sanitizers, demotes
  // below-threshold findings to lower severity (never drops).
  if (process.env.AGENTIC_SECURITY_SOFT_TAINT === '1') {
    findings = annotateSoftTaint(findings);
  }
  // v0.73 — type-stub-aware filter. Consults the project's TS/.pyi/JAR
  // stub signatures (loaded by ir/type-stubs.js when AGENTIC_SECURITY_TYPE_STUBS=1).
  // If a finding's source type is provably non-stringy (number, boolean,
  // Date, RegExp) AND the sink class can't be triggered by that type,
  // demote the finding's severity.
  if (process.env.AGENTIC_SECURITY_TYPE_STUBS === '1' && opts.scanRoot) {
    try {
      const stubs = loadProjectStubs(opts.scanRoot);
      findings = applyStubAwareFilter(findings, stubs);
    } catch { /* stub load failure must not fail the scan */ }
  }
  // v0.71 #9 — symbolic exploit proof. For each finding, run the SMT-lite
  // infeasibility check (and optionally Z3 when AGENTIC_SECURITY_SYMEXEC_Z3=1
  // AND z3-solver is installed). Attach _exploitInput / _provenUnreachable.
  if (process.env.AGENTIC_SECURITY_SYMEXEC === '1') {
    try {
      const useZ3 = process.env.AGENTIC_SECURITY_SYMEXEC_Z3 === '1';
      // proveExploits returns a Promise; we keep the deep pass synchronous
      // by not awaiting — the prover runs eagerly with z3=null (sync path).
      // For Z3 path, callers should use the async runDeepAnalysisAsync (TBD).
      if (!useZ3) {
        // Synchronous SMT-lite branch.
        // proveExploits awaits z3 only when opts.useZ3=true; otherwise it
        // returns synchronously through the same async function (Promise of
        // sync result). We tolerate the Promise here since findings are
        // mutated in place.
        const p = proveExploits(findings, { useZ3: false });
        if (p && typeof p.then === 'function') p.catch(() => {});
      }
    } catch { /* prover failure should not fail the scan */ }
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
