// IFDS — Interprocedural Finite Distributive Subset (v0.71 #3).
//
// Reps, Horwitz, and Sagiv. "Precise interprocedural dataflow analysis
// via graph reachability." POPL 1995.
//
// The classical formal framework for context-sensitive, flow-sensitive
// interprocedural dataflow analysis. Polynomial in the size of the
// exploded supergraph (|nodes| × |facts|). Each fact is a single domain
// element (here: one access path or the special bottom fact `0̂`). The
// solver maintains path edges (`(d1, d2)` pairs at each statement) and
// summary edges (`(d1, d2)` pairs at each callee).
//
// What this v1 supports:
//   - Intraprocedural fact propagation via per-node flow functions
//   - Interprocedural call → start → return → after-call edges
//   - Summary cache (per-function `Map<entryFact, Set<exitFact>>`)
//   - Sink detection driven by the same catalog as the worklist engine
//
// What we DON'T do yet (left for v2):
//   - The "may-must" extension (IDE)
//   - Demand-driven querying (we still solve from every start node)
//   - Field-sensitive facts (facts are full access paths today; for
//     field-sensitivity we'd partition the fact set by path-prefix)
//
// Out-of-scope: we don't replace the existing k=2 worklist engine here.
// `runIfdsTaintEngine` is an ALTERNATIVE analyzer the operator opts
// into via AGENTIC_SECURITY_IFDS=1; the equivalence vs. the worklist
// engine is gated on the CVE-replay regression corpus.

import { matchSource, matchSinkOrSanitizer } from './catalog.js';

// Special bottom fact: "no taint yet, but reachable." Every node propagates
// 0̂ → 0̂ to mark reachability, then layers domain facts on top.
export const ZERO = '0';

// ─── Flow functions ──────────────────────────────────────────────────────
//
// Each function takes (node, fact) → Set<fact'>. The semantics are
// distributive: f(d1 ⊔ d2) = f(d1) ⊔ f(d2). For taint analysis where the
// domain is sets of access paths and the transfer is "propagate or
// generate," the distributivity holds.

function _flowAssign(node, fact) {
  const out = new Set([fact]);
  if (!node || node.kind !== 'assign') return out;
  const target = typeof node.target === 'string' ? node.target : null;
  if (!target) return out;
  // Source generation: an assign whose source matches a catalog source
  // generates a new fact (target is tainted from now on).
  const src = node.source ? matchSource(node.source) : null;
  if (src && fact === ZERO) {
    out.add(target);
    return out;
  }
  // Kill: assign to `target` from a clean expression kills `target`.
  if (fact === target || (typeof fact === 'string' && fact.startsWith(target + '.'))) {
    // Check if RHS reads `fact` (in which case we propagate, don't kill).
    const sourcePath = _exprAccessPath(node.source);
    if (sourcePath === fact) return out;       // copy, fact survives
    // Otherwise the LHS clobbers; remove the fact.
    out.delete(fact);
  }
  // Propagation via copy: `x = y` and `fact == y` → out adds `x`.
  if (typeof fact === 'string' && fact !== ZERO) {
    const sourcePath = _exprAccessPath(node.source);
    if (sourcePath === fact || (sourcePath && fact.startsWith(sourcePath + '.'))) {
      out.add(target + (fact === sourcePath ? '' : fact.slice(sourcePath.length)));
    }
  }
  return out;
}

/**
 * v0.73 — derive the callee's entry fact from a call site + caller fact.
 *
 *   - If the caller's currentFact is ZERO (no taint), the callee's entry
 *     is ZERO too (reachability propagation).
 *   - If the caller has a tainted access path that matches one of the
 *     call's arguments, the corresponding callee parameter becomes the
 *     callee's entry fact.
 *   - Otherwise the callee starts clean (ZERO) — the caller's taint
 *     doesn't flow into this call.
 */
function _entryFactForCall(callNode, currentFact, callee) {
  if (currentFact === ZERO) return ZERO;
  const args = callNode.args || [];
  const params = callee.params || [];
  for (let i = 0; i < args.length && i < params.length; i++) {
    const argPath = _exprAccessPath(args[i]);
    if (argPath === currentFact || (argPath && currentFact.startsWith(argPath + '.'))) {
      // The caller's tainted path arrives via this argument; bind it to
      // the parameter name in the callee's scope.
      const tail = currentFact === argPath ? '' : currentFact.slice(argPath.length);
      return params[i] + tail;
    }
  }
  return ZERO;
}

/**
 * v0.73 — when a callee's summary says it returns with exit fact F,
 * translate that back into the caller's variable namespace. For now:
 *   - ZERO stays ZERO (reachability)
 *   - If the exit fact is a callee-local var (assign target inside the
 *     callee body) it doesn't escape the call — return ZERO.
 *   - If the exit fact corresponds to a parameter the caller bound to a
 *     specific arg, map it back to that arg's access path. This is the
 *     interprocedural mutation-through-param case.
 * v1 is conservative: returns ZERO unless we can map back precisely.
 */
function _mapReturnFact(callNode, exitFact, callerCurrent) {
  if (exitFact === ZERO) return ZERO;
  // For v1, we don't try to map callee param mutations back to caller
  // args without alias info — that's covered by the worklist engine's
  // _addPathAliasAware path. Here we conservatively propagate the
  // caller's current fact (which is already correct if the callee was
  // pure w.r.t. the caller's tainted vars).
  return callerCurrent;
}

function _exprAccessPath(expr) {
  if (!expr) return null;
  if (expr.kind === 'ident') return expr.name;
  if (expr.kind === 'member' && expr.object && expr.object.kind === 'ident' && typeof expr.prop === 'string') {
    return `${expr.object.name}.${expr.prop}`;
  }
  return null;
}

// Sink detection at call nodes. Returns a list of sink-finding records
// {sinkId, vuln, severity, cwe, line} when `fact` reaches a sink arg.
function _detectSinkAtCall(node, fact) {
  if (!node || node.kind !== 'call') return [];
  if (fact === ZERO) return [];
  const cat = matchSinkOrSanitizer(node.callee);
  if (!cat) return [];
  const findings = [];
  const args = node.args || [];
  for (const e of cat) {
    if (e.kind !== 'sink') continue;
    const argTaintedIdx = args.findIndex(a => {
      const p = _exprAccessPath(a);
      return p === fact || (p && fact.startsWith(p + '.'));
    });
    if (e.argIndex === 'all' || (typeof e.argIndex === 'number' && argTaintedIdx === e.argIndex)) {
      findings.push({
        sinkId: e.id,
        vuln: e.vuln?.name || 'Tainted Sink',
        severity: e.vuln?.severity || 'high',
        cwe: e.vuln?.cwe || null,
        remediation: e.vuln?.remediation || null,
        line: node.line,
        argIndex: argTaintedIdx,
        callee: node.callee,
      });
    }
  }
  return findings;
}

// ─── Solver ──────────────────────────────────────────────────────────────

export class IFDSSolver {
  constructor(perFileIR, callGraph, opts = {}) {
    this.perFileIR = perFileIR;
    this.callGraph = callGraph;
    this.opts = opts;
    // Path edges: for each node id, Set<"entryFact|currentFact">
    this.pathEdges = new Map();
    // Summary edges: per qid, Map<entryFact, Set<exitFact>>
    // This is the v0.73 lift: real summaries replace the v0.71 bottom
    // placeholder. When a callee has been solved under `entryFact` and
    // we already know the resulting `exitFacts`, the caller jumps over
    // the call site by applying those facts directly.
    this.summaries = new Map();
    // Pending-callsite registry: per (callee qid + entry fact), the list
    // of return sites waiting on more summaries to materialize. When a
    // new exit fact is added, we re-propagate at each return site.
    this.pendingReturns = new Map();
    // Findings: emitted whenever a sink call fires.
    this.findings = [];
    // Worklist: array of { fn, nodeId, entryFact, currentFact }
    this.work = [];
    // Budget — IFDS can blow up; cap path-edge count.
    this.maxEdges = Number(opts.budgetFacts) || Number(process.env.AGENTIC_SECURITY_IFDS_BUDGET_FACTS) || 10_000;
    this.edgeCount = 0;
  }

  _summaryKey(qid, entryFact) { return `${qid}|${entryFact}`; }

  _addSummary(qid, entryFact, exitFact) {
    const key = this._summaryKey(qid, entryFact);
    if (!this.summaries.has(key)) this.summaries.set(key, new Set());
    const set = this.summaries.get(key);
    if (set.has(exitFact)) return false;
    set.add(exitFact);
    // Replay pending return sites: any caller that asked for this
    // (callee, entryFact) gets the new exit fact propagated.
    const pending = this.pendingReturns.get(key);
    if (pending) {
      for (const { fn, returnNodeId, callerEntry } of pending) {
        this._propagate(fn, returnNodeId, callerEntry, exitFact);
      }
    }
    return true;
  }

  _getSummaries(qid, entryFact) {
    const set = this.summaries.get(this._summaryKey(qid, entryFact));
    return set ? [...set] : [];
  }

  _registerPendingReturn(qid, entryFact, fn, returnNodeId, callerEntry) {
    const key = this._summaryKey(qid, entryFact);
    if (!this.pendingReturns.has(key)) this.pendingReturns.set(key, []);
    this.pendingReturns.get(key).push({ fn, returnNodeId, callerEntry });
  }

  run() {
    if (!this.callGraph || !this.callGraph.functions) return [];
    // Seed: for every function, add ZERO → ZERO at its entry. This is
    // the main-procedure seed in IFDS; with no main, every function is
    // potentially the entry point for the analysis.
    for (const fn of this.callGraph.functions.values()) {
      if (!fn.cfg) continue;
      this._propagate(fn, fn.cfg.entry, ZERO, ZERO);
    }
    // Drain the worklist.
    while (this.work.length) {
      if (this.edgeCount >= this.maxEdges) break;
      const item = this.work.shift();
      this._processNode(item);
    }
    return this.findings;
  }

  _propagate(fn, nodeId, entryFact, currentFact) {
    if (this.edgeCount >= this.maxEdges) return;
    const key = `${fn.qid}|${nodeId}`;
    if (!this.pathEdges.has(key)) this.pathEdges.set(key, new Set());
    const edge = `${entryFact}|${currentFact}`;
    const set = this.pathEdges.get(key);
    if (set.has(edge)) return;
    set.add(edge);
    this.edgeCount++;
    this.work.push({ fn, nodeId, entryFact, currentFact });
  }

  _processNode({ fn, nodeId, entryFact, currentFact }) {
    const node = fn.cfg.nodes[nodeId];
    if (!node) return;
    // Emit findings if this is a sink.
    if (node.kind === 'call') {
      for (const f of _detectSinkAtCall(node, currentFact)) {
        this.findings.push({ ...f, _fnQid: fn.qid, _entryFact: entryFact });
      }
      // v0.73 — interprocedural call: if the callee is resolved AND we
      // can derive an entry fact for it, look up (or queue) its summary
      // and apply the resulting exit facts at the return site.
      const resolved = this.callGraph.resolve ? this.callGraph.resolve(node.callee) : null;
      const callee = resolved && resolved.qid ? resolved : null;
      if (callee && callee.cfg) {
        const calleeEntryFact = _entryFactForCall(node, currentFact, callee);
        // Seed the callee at its entry with the derived fact.
        this._propagate(callee, callee.cfg.entry, calleeEntryFact, calleeEntryFact);
        // Apply any already-known summaries to OUR return site.
        const existing = this._getSummaries(callee.qid, calleeEntryFact);
        for (const succ of (node.succ || [])) {
          for (const exitFact of existing) {
            this._propagate(fn, succ, entryFact, _mapReturnFact(node, exitFact, currentFact));
          }
          // Register the return site so when more summaries arrive, we
          // re-propagate at it.
          this._registerPendingReturn(callee.qid, calleeEntryFact, fn, succ, entryFact);
        }
      }
    }
    // v0.73 — at the function exit, record a summary edge
    // (entryFact, currentFact) for this function. Callers use it.
    if (node.kind === 'exit' || (node.succ || []).length === 0) {
      this._addSummary(fn.qid, entryFact, currentFact);
    }
    // Compute next facts.
    let nextFacts;
    if (node.kind === 'assign') {
      nextFacts = _flowAssign(node, currentFact);
    } else {
      // Identity transfer for non-modeled kinds.
      nextFacts = new Set([currentFact]);
    }
    // Propagate to successors.
    for (const succ of (node.succ || [])) {
      for (const nf of nextFacts) {
        this._propagate(fn, succ, entryFact, nf);
      }
    }
  }

  // Diagnostics
  stats() {
    return {
      pathEdges: this.edgeCount,
      summaries: this.summaries.size,
      findings: this.findings.length,
      capped: this.edgeCount >= this.maxEdges,
    };
  }
}

/**
 * Top-level entry mirroring runTaintEngine's shape. Returns a flat array
 * of findings. The IFDS solver runs only when AGENTIC_SECURITY_IFDS=1
 * (gated by runDeepAnalysis).
 */
export function runIfdsTaintEngine(perFileIR, callGraph, opts = {}) {
  const solver = new IFDSSolver(perFileIR, callGraph, opts);
  const raw = solver.run();
  // Shape to match runTaintEngine's output.
  const out = [];
  const seen = new Set();
  for (const f of raw) {
    const fn = callGraph.functions.get(f._fnQid);
    if (!fn) continue;
    const key = `${f.sinkId}:${fn.file}:${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      id: `ir-taint-ifds:${fn.file}:${f.line}:${f.sinkId}`,
      file: fn.file,
      line: f.line,
      vuln: f.vuln,
      severity: f.severity,
      cwe: f.cwe,
      remediation: f.remediation,
      parser: 'IR-TAINT-IFDS',
      confidence: 0.8,
      sink: { file: fn.file, line: f.line, label: f.sinkId },
    });
  }
  Object.defineProperty(out, '_ifdsStats', {
    value: solver.stats(),
    enumerable: false,
  });
  return out;
}

export const _internal = { _flowAssign, _exprAccessPath, _detectSinkAtCall };
