// Layer 2 entry point.
import { runTaintEngine } from './engine.js';
import { annotateProvenClean } from './proven-clean.js';
import { CATALOG, matchSource, matchSinkOrSanitizer, _catalogSize } from './catalog.js';
import { applyPathFeasibility, buildConstantFnMap } from './path-feasibility.js';
import { SummaryCache, entryStateFromCall } from './summaries.js';
import { rhsReachableFunctions, shouldAnalyzeUnderRhs } from './tabulation.js';
import { annotateBackwardSlices } from './backward.js';
// DAG-05: dependency-complete incremental analysis (see incremental-session.js).
import { beginIncrementalSession, engineOptionsFor, finishIncrementalSession } from './incremental-session.js';
import { buildPointsTo } from './points-to.js';
import { buildClassHierarchy, annotateRTA } from '../ir/class-hierarchy.js';
import { annotateSoftTaint } from './soft-taint.js';
import { runIfdsTaintEngine } from './ifds.js';
import { proveExploits } from './exploit-prover.js';
import { applyStubAwareFilter } from './stub-aware-filter.js';
import { loadProjectStubs } from '../ir/type-stubs.js';
import { runPrivacyTaintEngine } from './privacy-deep-walker.js';

export function runDeepAnalysis(perFileIR, callGraph, opts = {}) {
  // Path-feasibility pass over every function before the taint walk.
  // W2.1: build the trivially-constant-helper map ONCE, from every function
  // in the scan, before folding any single function's conditions — a
  // constant helper in file A must resolve when called from file B.
  const constFns = buildConstantFnMap(callGraph.functions.values());
  let totalPruned = 0;
  for (const fn of callGraph.functions.values()) {
    const r = applyPathFeasibility(fn, constFns);
    totalPruned += r.pruned;
  }
  // P2.1 — RHS-lite reachability slice. When AGENTIC_SECURITY_RHS=1 the
  // engine narrows analysis to sink-reachable functions. Default OFF
  // because it changes the finding-set composition.
  let rhsCompletion = null;
  if (process.env.AGENTIC_SECURITY_RHS === '1') {
    const ctx = rhsReachableFunctions(perFileIR, callGraph);
    rhsCompletion = ctx.completion || null;
    if (ctx.reachable) {
      opts = { ...opts, _rhsReachable: ctx.reachable, _rhsCheck: shouldAnalyzeUnderRhs };
    }
  }
  const incrementalEnabled = process.env.AGENTIC_SECURITY_INCREMENTAL === '1';
  // PRD R6/R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md): Class Hierarchy
  // Analysis. Built once per scan (mirrors the points-to graph immediately
  // below) and threaded through opts so the taint engine can (a) narrow
  // catalog sink matches to the receiver's inferred type (R6) and (b) safely
  // resolve a member call to a concrete callee when the receiver resolves to
  // exactly one known class (R11). Unlike points-to, this is NOT gated behind
  // an env flag — receiver-context.js and class-hierarchy.js were both
  // already built, unit-tested, and left completely unreachable from the
  // production pipeline (see PRD R6's evidence); building it always is cheap
  // (a single walk of the already-parsed IR, no fixed-point iteration) and
  // every consumer degrades to today's behavior when it finds no useful type.
  let classHierarchy = null;
  try {
    classHierarchy = buildClassHierarchy(perFileIR, callGraph);
    // PRD W2.5 (SARD_80_F1_EXECUTION_PRD.md) — RTA-annotate so
    // `engine.js`'s `_resolveMemberCalleeViaCHA` can resolve a
    // parameter-typed (or otherwise non-`new`-tracked) receiver against
    // whichever subclasses are ACTUALLY instantiated somewhere in this
    // scan, not just the receiver's own declared/abstract type (which
    // typically has no method BODY of its own to resolve to at all).
    if (classHierarchy) annotateRTA(classHierarchy, perFileIR);
  } catch { classHierarchy = null; }
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
  // DAG-05: the session decides warm or cold from content fingerprints (it needs the
  // call graph and class hierarchy built above) and restores typed contexts.
  const incrementalSession = beginIncrementalSession({ enabled: incrementalEnabled, opts, perFileIR, callGraph, cha: classHierarchy });
  let findings = runTaintEngine(perFileIR, callGraph, {
    ...opts,
    ...engineOptionsFor(incrementalSession),
    _pointsTo: pointsToGraph || undefined,
    _cha: classHierarchy || undefined,
  });
  const engineOutput = findings;
  // DAG-05: provenance + persistence happen right after the engine, on the engine's own array.
  const incrementalStats = finishIncrementalSession(incrementalSession, engineOutput);
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
  // FR-403 step 3 (assurance-hardening PRD, D-0047): opt-in, isolated
  // privacy-taint walker. OFF by default. Mirrors the IFDS wiring above
  // exactly -- an additional pass whose findings are merged in, never
  // replacing the primary engine's output, and whose failure must never
  // fail the scan. See dataflow/privacy-deep-walker.js's own header for why
  // this is a wholly separate module rather than a change to runTaintEngine/
  // step/exprTaint above.
  if (process.env.AGENTIC_SECURITY_PRIVACY_DEEP === '1') {
    try {
      const privacyFindings = runPrivacyTaintEngine(callGraph, opts);
      const existing = new Set(findings.map(f => `${f.file}:${f.line}:${f.sink?.label || f.cwe || ''}`));
      for (const f of privacyFindings) {
        const key = `${f.file}:${f.line}:${f.sink?.label || f.cwe || ''}`;
        if (!existing.has(key)) findings.push(f);
      }
    } catch { /* privacy-deep failure should not fail the scan */ }
  }
  for (const f of findings) f._pathFeasibilityPruned = totalPruned;
  if (incrementalStats) {
    Object.defineProperty(findings, '_incrementalStats', { value: incrementalStats, enumerable: false });
    if (findings !== engineOutput) Object.defineProperty(engineOutput, '_incrementalStats', { value: incrementalStats, enumerable: false });
  }
  if (rhsCompletion) Object.defineProperty(findings, '_rhsCompletion', { value: rhsCompletion, enumerable: false });
  // P1.4 — backward slice (opt-in via AGENTIC_SECURITY_BACKWARD_SLICE=1).
  // Next-gen taint capability #5 (SMT path-feasibility rebuild): ALSO run
  // this when AGENTIC_SECURITY_SYMEXEC=1 is set, even if the operator never
  // separately set AGENTIC_SECURITY_BACKWARD_SLICE — `proveExploits`'s own
  // infeasibility check now depends on `finding.backwardSlice` for a sound
  // verdict (see exploit-prover.js's own header), and requiring an operator
  // to know to independently set a SECOND, differently-named flag just to
  // get a real answer out of the first is exactly the kind of silent,
  // undiscoverable degradation this codebase's own verification discipline
  // warns against — SYMEXEC's own soundness must not be a hidden function
  // of an unrelated flag.
  if (process.env.AGENTIC_SECURITY_BACKWARD_SLICE === '1' || process.env.AGENTIC_SECURITY_SYMEXEC === '1') {
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
  // demote the finding's confidence/tier (recall-preserving — severity
  // is never touched).
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
  return findings;
}

export { runTaintEngine, CATALOG, matchSource, matchSinkOrSanitizer, _catalogSize, applyPathFeasibility, buildConstantFnMap, SummaryCache, entryStateFromCall, rhsReachableFunctions, shouldAnalyzeUnderRhs, annotateBackwardSlices };
