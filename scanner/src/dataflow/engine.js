// Interprocedural taint engine — IFDS-lite tabulation over the IR.
//
// Algorithm (simplified):
//
//   For each function F:
//     We compute a SUMMARY of the form
//        (entry: Set<TaintFact>) → { returnTaint: bool, paramMutations: { paramName: bool }, sideEffectFindings: Finding[] }
//     where TaintFact is currently a variable name (string).
//
//   To handle inter-procedural flow:
//     When the engine encounters a call site `f(...args)`:
//       1. Look up the resolved callee qid in the call graph.
//       2. Compute an entry-taint-state for that callee: which of the callee's
//          parameters bind to tainted caller-side expressions?
//       3. If a summary already exists for that callee + entry-state, use it.
//          Otherwise, recursively analyze the callee with that entry state,
//          cache the summary, and use it.
//       4. The callee's `returnTaint` determines whether the call expression's
//          value is tainted on return.
//       5. The callee's `paramMutations` taint specific caller-side variables
//          (param-by-reference, e.g. `Object.assign(target, tainted)`).
//
//   Recursion: We use the standard fixed-point trick — when a function is
//   already on the analysis stack, return a conservative summary (no
//   tainting). The cache then re-iterates.
//
// Sources: anywhere a CFG node reads a catalog-registered source pattern,
// the resulting variable becomes tainted.
//
// Sinks: anywhere a CFG node calls a catalog-registered sink with a tainted
// argument, we emit a finding.
//
// Sanitizers: a call to a catalog-registered sanitizer kills the taint on its
// argument (the call's return value is treated as clean).

import { matchSource, matchSinkOrSanitizer } from './catalog.js';
import { accessPathOf, isCoveredBy, addPath, removePathAndDescendants, joinSets as joinAccessSets, setsEqual as accessSetsEqual } from './access-paths.js';
import { aliasesForVar } from './points-to.js';
import { higherOrderTaintFlow } from './higher-order.js';
import { SummaryCache, entryStateFromCall } from './summaries.js';
import { lookupBuiltinSummary } from './builtin-summaries.js';

// v0.70 #2 — addPath that also taints every alias of the variable.
// When `target` is a dotted path like "a.x" and the root `a` has aliases
// {a, obj}, we taint both `a.x` and `obj.x`. The points-to graph is read
// from callContext._pointsTo (built by runDeepAnalysis when
// AGENTIC_SECURITY_POINTS_TO=1).
function _addPathAliasAware(state, path, callContext) {
  let s = addPath(state, path);
  const pt = callContext && callContext._pointsTo;
  const fnQid = callContext && callContext._currentFnQid;
  if (!pt || !fnQid || typeof path !== 'string') return s;
  // Determine the variable root + remainder of the path.
  const dot = path.indexOf('.');
  const root = dot >= 0 ? path.slice(0, dot) : path;
  const rest = dot >= 0 ? path.slice(dot) : '';
  const aliases = aliasesForVar(pt, fnQid, root);
  for (const a of aliases) {
    if (a === root) continue;
    s = addPath(s, a + rest);
  }
  return s;
}

let _activeConstantVars = null;

function exprTaint(expr, state) {
  if (expr && expr.kind === 'member' && exprIsSource(expr)) return true;
  if (!expr) return false;
  // Constant propagation: variables assigned from literals are never tainted
  if (expr.kind === 'ident' && _activeConstantVars && _activeConstantVars.has(expr.name)) return false;
  // P1.1 — field-sensitive access path: if the expression is a pure
  // ident/member chain ("x.y.z"), ask the access-path lattice whether any
  // shorter prefix in the state covers it. This is what makes
  // `user.password` distinguishable from `user.email`.
  const ap = accessPathOf(expr);
  if (ap !== null) return isCoveredBy(state, ap);
  switch (expr.kind) {
    case 'literal':           return false;
    case 'binary':
    case 'logical':           return exprTaint(expr.left, state) || exprTaint(expr.right, state);
    case 'tpl':               return (expr.parts || []).some(p => exprTaint(p, state));
    case 'union':             return (expr.branches || []).some(b => exprTaint(b, state));
    case 'object':            return (expr.props || []).some(p => exprTaint(p.value, state));
    case 'array':             return (expr.elements || []).some(e => exprTaint(e, state));
    case 'call': {
      // Calls are handled at the CFG level (the call has already been processed).
      // For an inline call expression, conservatively return whether any arg is tainted.
      // This loses the sanitizer effect but is safe.
      return (expr.args || []).some(a => exprTaint(a, state));
    }
    case 'unknown':           return false;
    default:                  return false;
  }
}

// Premortem #10: which recorded sources actually reach this expression?
// Collects the variable / access-path roots referenced by `expr` and returns
// the _taintSources entries whose varName matches one of those roots. This
// replaces "first source we ever saw" with "sources tied to this argument."
function _collectExprVars(expr, out) {
  if (!expr) return;
  if (typeof expr === 'string') { out.add(expr); return; }
  if (expr.kind === 'ident' && expr.name) { out.add(expr.name); return; }
  if (expr.kind === 'member') {
    // Capture the access path (e.g. `user.email`) AND its root (`user`).
    const ap = accessPathOf(expr);
    if (ap) out.add(ap);
    if (expr.object) _collectExprVars(expr.object, out);
    return;
  }
  if (expr.kind === 'binary' || expr.kind === 'logical') {
    _collectExprVars(expr.left, out); _collectExprVars(expr.right, out); return;
  }
  if (expr.kind === 'tpl' && Array.isArray(expr.parts)) {
    for (const p of expr.parts) _collectExprVars(p, out); return;
  }
  if (expr.kind === 'union' && Array.isArray(expr.branches)) {
    for (const b of expr.branches) _collectExprVars(b, out); return;
  }
  if (expr.kind === 'object' && Array.isArray(expr.props)) {
    for (const p of expr.props) _collectExprVars(p.value, out); return;
  }
  if (expr.kind === 'array' && Array.isArray(expr.elements)) {
    for (const e of expr.elements) _collectExprVars(e, out); return;
  }
  if (expr.kind === 'call' && Array.isArray(expr.args)) {
    for (const a of expr.args) _collectExprVars(a, out); return;
  }
}
function _sourcesReachingExpr(expr, _state, taintSources) {
  if (!Array.isArray(taintSources) || taintSources.length === 0) return [];
  const vars = new Set();
  _collectExprVars(expr, vars);
  if (vars.size === 0) return [];
  // Match by exact varName OR by access-path prefix (a source recorded for
  // `user` covers `user.email`, and a source recorded for `user.email`
  // covers the literal expression `user.email`).
  const matched = [];
  for (const s of taintSources) {
    const v = s.varName;
    if (!v) continue;
    if (vars.has(v)) { matched.push(s); continue; }
    for (const candidate of vars) {
      if (typeof candidate === 'string' && (candidate === v || candidate.startsWith(v + '.'))) {
        matched.push(s); break;
      }
    }
  }
  return matched;
}

// Heuristic: does this expression read a registered source?
function exprIsSource(expr) {
  if (!expr) return null;
  if (expr.kind === 'member') {
    const hit = matchSource(expr);
    if (hit) return hit;
  }
  if (expr.kind === 'member' && expr.object) {
    return exprIsSource(expr.object);
  }
  return null;
}

const _SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|WHERE|FROM|JOIN|INTO|VALUES|SET|EXEC|EXECUTE)\b/i;
const _HTML_META = /[<>'"&]|innerHTML|outerHTML|document\.write/;
const _SHELL_META = /[;|`$(){}]|&&|\|\|/;

function _literalPartsOfExpr(expr) {
  if (!expr) return [];
  if (expr.kind === 'literal') return [String(expr.value || '')];
  if (expr.kind === 'tpl') return (expr.parts || []).filter(p => p.kind === 'literal').map(p => String(p.value || ''));
  if (expr.kind === 'binary') return [..._literalPartsOfExpr(expr.left), ..._literalPartsOfExpr(expr.right)];
  return [];
}

function literalSkeletonMatchesFamily(expr, cwe) {
  const literals = _literalPartsOfExpr(expr);
  if (!literals.length) return true;
  const joined = literals.join(' ');
  if (!joined.trim()) return true;
  if (cwe === 'CWE-89' || cwe === 'CWE-943') return _SQL_KEYWORDS.test(joined);
  if (cwe === 'CWE-79') return _HTML_META.test(joined);
  if (cwe === 'CWE-78') return _SHELL_META.test(joined);
  return true;
}

// Apply a CFG node to a taint-state. Returns the new state + any finding emitted.
function step(node, stateIn, callContext) {
  const state = new Set(stateIn);
  const findings = [];

  switch (node.kind) {
    case 'entry':
    case 'exit':
    case 'noop':
    case 'loop-header':
      return { state, findings };

    case 'assign': {
      const src = exprIsSource(node.source);
      const target = typeof node.target === 'string' ? node.target : null;
      // Constant propagation: track variables assigned from literals
      if (target && _activeConstantVars) {
        if (node.source && node.source.kind === 'literal') _activeConstantVars.set(target, node.source.value);
        else _activeConstantVars.delete(target);
      }
      let newState = state;
      // Premortem #7: interprocedural return-taint via SummaryCache. If the
      // RHS is a call to a known callee whose empty-entry-state summary says
      // the return is tainted, taint the assignment target. This makes the
      // simplest cross-function flow (helper reads req.body and returns it)
      // visible to the engine — the case the cache was built for.
      const calleeName = node.source && node.source.kind === 'call' && typeof node.source.callee === 'string'
        ? node.source.callee : null;
      if (target && calleeName && callContext._summaryCache && callContext._callGraph) {
        const resolved = callContext._callGraph.resolve ? callContext._callGraph.resolve(calleeName) : null;
        const fn  = resolved && resolved.qid ? resolved : null;
        const qid = resolved && (resolved.qid || resolved);
        if (typeof qid === 'string') {
          // v0.66 — context-sensitive lookup. Build the entry-state from
          // the call args + current taint; look up (and lazily compute) the
          // summary for THAT state, not just empty. This is what closes the
          // "helper is pure when called clean but tainted when called with
          // user input" FN class.
          const callerTainted = newState;
          const callArgs = (node.source.args || []);
          const paramNames = (fn && Array.isArray(fn.params)) ? fn.params : [];
          const entry = paramNames.length
            ? entryStateFromCall(paramNames, callArgs, callerTainted)
            : new Set();
          let sum = callContext._summaryCache.get(qid, entry);
          if (!sum && fn && fn.cfg) {
            // Lazy compute under this entry state. Use a fresh ctx so we
            // don't pollute the outer caller's _taintSources with the
            // callee's internal noise.
            sum = callContext._summaryCache.compute(qid, entry, () => {
              const inner = {
                _findings: [], _taintSources: [], _returnTainted: false,
                _stack: new Set(), deadlineMs: callContext.deadlineMs,
                _summaryCache: callContext._summaryCache,
                _callGraph: callContext._callGraph,
                _mutatedParamsOut: new Set(),
              };
              try { analyzeFunction(fn, entry, inner); } catch {}
              return {
                returnTainted: !!inner._returnTainted,
                mutatedParams: inner._mutatedParamsOut || new Set(),
                taintedGlobals: new Set(),
                findings: [],
              };
            });
          }
          if (sum && sum.returnTainted) {
            newState = _addPathAliasAware(newState, target, callContext);
            callContext._taintSources.push({
              varName: target,
              sourceId: `interproc:${qid}`,
              sourceLabel: `interproc-return:${calleeName}`,
              provenance: 'interproc',
              line: node.line,
            });
          }
          // applyAtCallSite — mutated params propagate to caller arg-vars.
          if (sum && sum.mutatedParams && sum.mutatedParams.size && paramNames.length) {
            const mutated = callContext._summaryCache.applyAtCallSite(
              sum, paramNames, callArgs, callerTainted);
            for (const v of mutated.mutated) newState = addPath(newState, v);
          }
          if (sum && sum.returnTainted) return { state: newState, findings: [] };
        } else if (target && calleeName) {
          // Fallback: check builtin summaries for unresolved external calls
          const builtin = lookupBuiltinSummary(calleeName);
          if (builtin) {
            if (builtin.returnTainted && (node.source.args || []).some(a => exprTaint(a, newState))) {
              newState = _addPathAliasAware(newState, target, callContext);
            } else if (!builtin.returnTainted) {
              newState = removePathAndDescendants(newState, target);
              return { state: newState, findings: [] };
            }
            if (builtin.mutatedParams && builtin.mutatedParams.size) {
              for (const idx of builtin.mutatedParams) {
                const argExpr = (node.source.args || [])[parseInt(idx)];
                if (argExpr && argExpr.kind === 'ident' && (node.source.args || []).some(a => exprTaint(a, newState))) {
                  newState = _addPathAliasAware(newState, argExpr.name, callContext);
                }
              }
            }
          }
        }
      }
      if (src && target) {
        newState = _addPathAliasAware(newState, target, callContext);
        const sourcePath = accessPathOf(node.source);
        if (sourcePath) newState = addPath(newState, sourcePath);
        callContext._taintSources.push({ varName: target, sourceId: src.id, sourceLabel: src.label, provenance: src.provenance || null, line: node.line });
      } else if (exprTaint(node.source, newState)) {
        // P1.1: when the source IS a pure access path (e.g., RHS is `obj.foo.bar`),
        // taint the TARGET as well as transitively propagate the source path so
        // later uses of the same source remain tainted. The target path
        // becomes the new tainted location.
        if (target) {
          newState = _addPathAliasAware(newState, target, callContext);
          const sourcePath = accessPathOf(node.source);
          if (sourcePath && !isCoveredBy(newState, sourcePath)) newState = addPath(newState, sourcePath);
        }
      } else {
        // Re-assigning a previously-tainted var to a clean value clears it
        // AND its descendants — P1.1 semantics: assigning `x = clean` kills
        // `x.foo`, `x.foo.bar`, etc. Sanitization at root level.
        if (target) newState = removePathAndDescendants(newState, target);
      }
      return { state: newState, findings };
    }

    case 'call': {
      // 1. Catalog match: sanitizer, sink, or just an external/unresolved call.
      const cat = matchSinkOrSanitizer(node.callee);
      const argTaints = (node.args || []).map(a => exprTaint(a, state));
      // v0.66 — apply mutated-param taint at plain (non-assign) call sites.
      // Object.assign(target, tainted) → target becomes tainted in caller.
      if (callContext._summaryCache && callContext._callGraph
          && typeof node.callee === 'string') {
        const resolved = callContext._callGraph.resolve
          ? callContext._callGraph.resolve(node.callee) : null;
        const fn  = resolved && resolved.qid ? resolved : null;
        const qid = resolved && (resolved.qid || resolved);
        if (typeof qid === 'string' && fn && Array.isArray(fn.params)) {
          const paramNames = fn.params;
          const entry = paramNames.length
            ? entryStateFromCall(paramNames, node.args || [], state)
            : new Set();
          const sum = callContext._summaryCache.get(qid, entry);
          if (sum && sum.mutatedParams && sum.mutatedParams.size) {
            const mutated = callContext._summaryCache.applyAtCallSite(
              sum, paramNames, node.args || [], state);
            for (const v of mutated.mutated) state = addPath(state, v);
          }
        }
      }
      // Built-in mutation functions: Object.assign(target, ...sources),
      // _.merge(target, ...sources), etc. When any source arg is tainted,
      // taint the target in the caller's scope.
      const calleeName = typeof node.callee === 'string' ? node.callee : null;
      if (calleeName && /^(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep|_\.defaults|Object\.defineProperties?)$/.test(calleeName)) {
        const targetArg = (node.args || [])[0];
        const sourceArgsTainted = argTaints.slice(1).some(Boolean);
        if (targetArg && targetArg.kind === 'ident' && sourceArgsTainted) {
          state = _addPathAliasAware(state, targetArg.name, callContext);
          callContext._taintSources.push({
            varName: targetArg.name,
            sourceId: `builtin-mutation:${calleeName}`,
            sourceLabel: `${calleeName} mutation`,
            provenance: 'mutation',
            line: node.line,
          });
        }
      }
      if (cat) {
        for (const e of cat) {
          if (e.kind === 'sink' && (
            e.argIndex === 'all' ? argTaints.some(Boolean) :
            (typeof e.argIndex === 'number' && argTaints[e.argIndex])
          )) {
            const taintedArgIdx = e.argIndex === 'all'
              ? argTaints.findIndex(Boolean) : e.argIndex;
            const taintedArgExpr = (node.args || [])[taintedArgIdx];
            // String content analysis: skip if literal skeleton doesn't match injection family
            if (e.vuln && taintedArgExpr && !literalSkeletonMatchesFamily(taintedArgExpr, e.vuln.cwe)) continue;
            // Premortem #10: attribute the source for THIS sink to the
            // source(s) that taint the actual argument expression — not the
            // first source the worklist happened to record. We walk the
            // expression's free vars / access paths against the recorded
            // _taintSources and keep entries whose root variable still
            // covers something in the expression.
            const reachingSources = _sourcesReachingExpr(taintedArgExpr, state, callContext._taintSources);
            const traceForThisFinding = reachingSources.length
              ? reachingSources.slice(0, 5)
              // Fallback: better to surface "no precise source" than the wrong source.
              : [];
            findings.push({
              kind: 'taint',
              sinkId: e.id,
              vuln: e.vuln?.name || 'Tainted Sink',
              severity: e.vuln?.severity || 'high',
              cwe: e.vuln?.cwe || null,
              remediation: e.vuln?.remediation || null,
              line: node.line,
              argIndex: taintedArgIdx,
              callee: node.callee,
              sourceProvenance: (traceForThisFinding[0]?.provenance) || null,
              trace: traceForThisFinding,
            });
          }
        }
      }
      // 2. P1.3 — higher-order taint flow. When the call is `arr.map(fn)` or
      //    `promise.then(fn)` and the receiver is tainted, propagate taint
      //    into the callback's first parameter. v1: we propagate AT THE
      //    CALLBACK INVOCATION LEVEL by adding the callback's first-arg
      //    name (when resolvable as a plain ident or function-value) into
      //    the taint state.
      const hoFlow = (() => {
        // Heuristic receiver-tainted check: if the callee string is
        // "<recv>.<method>", check whether <recv> is in state.
        const callee = typeof node.callee === 'string' ? node.callee : null;
        if (!callee) return null;
        const dot = callee.lastIndexOf('.');
        if (dot <= 0) return null;
        const recv = callee.slice(0, dot);
        const recvTainted = isCoveredBy(state, recv);
        return higherOrderTaintFlow(node, recvTainted);
      })();
      if (hoFlow && hoFlow.taintsCallbackParam === 0) {
        // The first arg should be the callback. If it's a plain ident or
        // function-value, the engine's per-callee summary path will pick it
        // up when the callee is independently analyzed. We don't model the
        // callback inline here; instead we record on callContext that the
        // callback was invoked with a tainted first param, so the engine's
        // call-graph pass can re-run the callback with that entry state.
        const cb = (node.args || [])[0];
        if (cb && (cb.kind === 'ident' || cb.kind === 'function-value')) {
          callContext._higherOrderInvocations = callContext._higherOrderInvocations || [];
          callContext._higherOrderInvocations.push({
            callee: cb.kind === 'ident' ? cb.name : (cb.qid || null),
            paramIndex: 0,
            taintedParam: true,
            line: node.line,
            via: hoFlow.kind,
          });
        }
      }
      return { state, findings };
    }

    case 'if': {
      // Path-feasibility lite: if the condition is a literal false / unreachable,
      // mark the node so the CFG walker can skip the consequent edge.
      // For now we simply propagate state to both branches.
      return { state, findings };
    }

    case 'return': {
      if (exprTaint(node.value, state)) {
        callContext._returnTainted = true;
      }
      return { state, findings };
    }

    case 'throw': {
      // Thrown values don't taint subsequent code in the same fn — exit.
      return { state, findings };
    }

    default:
      return { state, findings };
  }
}

// Worklist traversal of one function's CFG with a given entry-taint-state.
// Returns the merged exit state + the union of findings on every path + the
// taint sources observed (for evidence trails).
//
// Premortem 2R4.4 / 2R-9: also honors callContext.deadlineMs by checking
// every 100 iterations. A pathological CFG (large generated file with dense
// control flow) can otherwise hold past the global timeout.
function analyzeFunction(fn, entryState, callContext) {
  const nodes = fn.cfg.nodes;
  const work = [];
  const inStates = new Map();
  const outStates = new Map();
  inStates.set(fn.cfg.entry, new Set(entryState));
  work.push(fn.cfg.entry);
  _activeConstantVars = new Map();
  // v0.70 #2 — points-to context for the step() transfer. Setting it here
  // (instead of plumbing through step's signature) keeps the worklist loop
  // unchanged and lets `step` consult `aliasesForVar` when callContext._pointsTo
  // is present.
  if (callContext) callContext._currentFnQid = fn.qid;
  const deadlineMs = (callContext && typeof callContext.deadlineMs === 'number') ? callContext.deadlineMs : Infinity;
  const visited = 0;
  let iterations = 0;
  const ITER_BUDGET = 5000;

  while (work.length) {
    if (++iterations > ITER_BUDGET) break;
    // Check the global deadline every 100 iterations — Date.now() is cheap
    // but not free; this keeps overhead negligible on small functions.
    if ((iterations & 0x7f) === 0 && Date.now() > deadlineMs) break;
    const nid = work.shift();
    const node = nodes[nid];
    if (!node) continue;
    const incoming = inStates.get(nid) || new Set();
    const { state: out, findings } = step(node, incoming, callContext);
    callContext._findings.push(...findings.map(f => ({ ...f, _funcQid: fn.qid })));
    const prevOut = outStates.get(nid);
    const merged = mergeStates(prevOut, out);
    if (!prevOut || !stateEq(prevOut, merged)) {
      outStates.set(nid, merged);
      for (const s of (node.succ || [])) {
        const succIn = inStates.get(s);
        const newIn = mergeStates(succIn, merged);
        if (!succIn || !stateEq(succIn, newIn)) {
          inStates.set(s, newIn);
          work.push(s);
        }
      }
    }
  }

  const exit = outStates.get(fn.cfg.exit) || new Set();
  // v0.66 — record which params are tainted at function exit so the
  // caller's applyAtCallSite can propagate that mutated taint back. We
  // intersect the exit-state with the function's declared params (only
  // param vars count as "mutated by reference"; locals are caller-invisible).
  if (callContext && Array.isArray(fn.params) && fn.params.length) {
    if (!callContext._mutatedParamsOut) callContext._mutatedParamsOut = new Set();
    for (const p of fn.params) {
      if (isCoveredBy(exit, p)) callContext._mutatedParamsOut.add(p);
    }
  }
  return exit;
}

function mergeStates(a, b) {
  // P1.1: use access-path-aware union that collapses longer descendants
  // under their shorter-prefix parents.
  return joinAccessSets(a, b);
}
function stateEq(a, b) {
  // P1.1: use access-path-aware set equality (canonicalized).
  return accessSetsEqual(a, b);
}

// ── Top-level entry ─────────────────────────────────────────────────────────
//
// Iterate each function with an EMPTY entry-taint-state. The function's
// internal sources will populate the state as we walk. (Future work: when the
// caller of F passes tainted args, re-analyze F with those params marked.
// The infra for it is in callContext.)
//
// Returns a flat array of findings, each enriched with file/line/etc.
export function runTaintEngine(perFileIR, callGraph, opts = {}) {
  const all = [];
  const seen = new Set();
  const fnLimit = opts.fnLimit || 5000;
  const deadlineMs = typeof opts.deadlineMs === 'number' ? opts.deadlineMs : Infinity;
  let n = 0;

  // Premortem #7: instantiate the k=1 SummaryCache and seed it with each
  // function's empty-entry-state summary (returnTainted bit). The cache is
  // available to call sites through callContext so the worklist can ask
  // "does callee F return tainted under this entry state?" before
  // conservatively assuming it doesn't. This wires the cache that was
  // exported-but-unused for several releases.
  //
  // v0.69 — opts.summaryCache lets the caller (runDeepAnalysis with
  // incremental mode) hand in a pre-seeded cache from persisted state.
  const summaryCache = opts.summaryCache || new SummaryCache();

  // Deterministic ordering (Sentinel-parity §9.2): sort functions by qid so
  // cache-cold runs produce the same finding sequence run-over-run.
  const fnList = [...callGraph.functions.values()].sort((a, b) =>
    a.qid < b.qid ? -1 : a.qid > b.qid ? 1 : 0
  );
  // Pre-pass + fixed-point: compute empty-entry-state summaries for every
  // function, then re-run the pre-pass until the summary cache stabilizes
  // (capped at MAX_FP_ITERS so recursion and chains converge without
  // unbounded blowup). v0.66 — the inner ctx now records mutatedParams
  // via _mutatedParamsOut so cross-function param mutation propagates.
  const MAX_FP_ITERS = 3;
  let prevCacheSize = -1;
  for (let it = 0; it < MAX_FP_ITERS; it++) {
    if (Date.now() > deadlineMs) break;
    for (const fn of fnList) {
      if (Date.now() > deadlineMs) break;
      const entry = new Set();
      const key = fn.qid + '::empty';
      const existing = summaryCache.get(fn.qid, entry);
      // On re-iterations, recompute even if cached so refined summaries
      // (from now-known callee summaries) can lift returnTainted/mutated.
      const ctx = {
        _findings: [], _taintSources: [], _returnTainted: false,
        _stack: new Set(), deadlineMs,
        _summaryCache: summaryCache, _callGraph: callGraph,
        _mutatedParamsOut: new Set(),
      };
      try { analyzeFunction(fn, entry, ctx); } catch {}
      const next = {
        returnTainted: !!ctx._returnTainted,
        mutatedParams: ctx._mutatedParamsOut || new Set(),
        taintedGlobals: new Set(),
        findings: [],
      };
      if (!existing
          || existing.returnTainted !== next.returnTainted
          || (existing.mutatedParams?.size || 0) !== next.mutatedParams.size) {
        summaryCache.set(fn.qid, entry, next);
      }
    }
    if (summaryCache.size() === prevCacheSize) break;
    prevCacheSize = summaryCache.size();
  }
  // Class-field cross-taint pass: when a method writes tainted data to _this_.field,
  // re-analyze other methods of the same class with those fields in the entry state.
  const classTaintedFields = new Map();
  for (const fn of fnList) {
    if (Date.now() > deadlineMs) break;
    const sum = summaryCache.get(fn.qid, new Set());
    if (!sum || !sum.mutatedParams) continue;
    for (const p of sum.mutatedParams) {
      if (typeof p === 'string' && p.startsWith('_this_.')) {
        const classPrefix = fn.qid.split('::')[0] + '::';
        if (!classTaintedFields.has(classPrefix)) classTaintedFields.set(classPrefix, new Set());
        classTaintedFields.get(classPrefix).add(p);
      }
    }
  }
  for (const [classPrefix, fields] of classTaintedFields) {
    if (Date.now() > deadlineMs) break;
    for (const fn of fnList) {
      if (!fn.qid.startsWith(classPrefix)) continue;
      if (summaryCache.has(fn.qid, fields)) continue;
      const ctx = {
        _findings: [], _taintSources: [], _returnTainted: false,
        _stack: new Set(), deadlineMs,
        _summaryCache: summaryCache, _callGraph: callGraph,
        _mutatedParamsOut: new Set(),
      };
      try { analyzeFunction(fn, fields, ctx); } catch {}
      summaryCache.set(fn.qid, fields, {
        returnTainted: !!ctx._returnTainted,
        mutatedParams: ctx._mutatedParamsOut || new Set(),
        taintedGlobals: new Set(),
        findings: [],
      });
    }
  }

  // k=2 pass: compute tainted-entry-state summaries for functions with params
  // AND at least one caller in the call graph. This catches "safe when called
  // clean, dangerous when called with tainted input" wrapper patterns.
  for (const fn of fnList) {
    if (Date.now() > deadlineMs) break;
    if (!fn.params || !fn.params.length) continue;
    const taintedEntry = new Set(fn.params);
    if (summaryCache.has(fn.qid, taintedEntry)) continue;
    const ctx = {
      _findings: [], _taintSources: [], _returnTainted: false,
      _stack: new Set(), deadlineMs,
      _summaryCache: summaryCache, _callGraph: callGraph,
      _mutatedParamsOut: new Set(),
    };
    try { analyzeFunction(fn, taintedEntry, ctx); } catch {}
    summaryCache.set(fn.qid, taintedEntry, {
      returnTainted: !!ctx._returnTainted,
      mutatedParams: ctx._mutatedParamsOut || new Set(),
      taintedGlobals: new Set(),
      findings: [],
    });
  }
  for (const fn of fnList) {
    if (++n > fnLimit) break;
    if (Date.now() > deadlineMs) break;  // global timeout
    // Module-level functions: analyze with an empty entry state. The function
    // discovers its own sources from req.body/process.env/etc. as it walks.
    const callContext = {
      _findings: [],
      _taintSources: [],
      _returnTainted: false,
      _stack: new Set(),
      deadlineMs,   // honored by the worklist inside analyzeFunction
      _summaryCache: summaryCache,
      _callGraph: callGraph,
    };
    try {
      analyzeFunction(fn, new Set(), callContext);
    } catch { continue; }
    // Process higher-order invocations: resolve callbacks and analyze with
    // tainted first-param. Feed findings back into the caller's finding set.
    const hoInvocations = callContext._higherOrderInvocations || [];
    const HO_CAP = 50;
    for (let hi = 0; hi < Math.min(hoInvocations.length, HO_CAP); hi++) {
      if (Date.now() > deadlineMs) break;
      const inv = hoInvocations[hi];
      if (!inv.callee || !inv.taintedParam) continue;
      const resolved = callGraph.resolve ? callGraph.resolve(inv.callee) : null;
      const cbFn = resolved && resolved.qid ? resolved : null;
      if (!cbFn || !cbFn.params || !cbFn.params.length) continue;
      const cbEntry = new Set([cbFn.params[inv.paramIndex || 0]]);
      let cbSummary = summaryCache.get(cbFn.qid, cbEntry);
      if (!cbSummary) {
        cbSummary = summaryCache.compute(cbFn.qid, cbEntry, () => {
          const inner = {
            _findings: [], _taintSources: [], _returnTainted: false,
            _stack: new Set(), deadlineMs,
            _summaryCache: summaryCache, _callGraph: callGraph,
            _mutatedParamsOut: new Set(),
          };
          try { analyzeFunction(cbFn, cbEntry, inner); } catch {}
          // Merge any findings from the callback analysis into the caller.
          callContext._findings.push(...inner._findings.map(f => ({ ...f, _funcQid: fn.qid, _via: 'higher-order' })));
          return {
            returnTainted: !!inner._returnTainted,
            mutatedParams: inner._mutatedParamsOut || new Set(),
            taintedGlobals: new Set(),
            findings: [],
          };
        });
      }
    }
    for (const f of callContext._findings) {
      const key = `${f.sinkId}:${fn.file}:${f.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      all.push({
        id: `ir-taint:${fn.file}:${f.line}:${f.sinkId}`,
        file: fn.file,
        line: f.line,
        vuln: f.vuln,
        severity: f.severity,
        cwe: f.cwe,
        remediation: f.remediation,
        parser: 'IR-TAINT',
        confidence: 0.75,
        source: f.trace && f.trace.length ? {
          file: fn.file,
          line: f.trace[0].line,
          label: f.trace[0].sourceLabel,
        } : null,
        sink: {
          file: fn.file,
          line: f.line,
          label: f.sinkId,
        },
        chain: (f.trace || []).map(t => ({
          file: fn.file, line: t.line, label: t.sourceLabel,
        })),
      });
    }
  }
  // v0.69 — expose cache to caller (runDeepAnalysis) for incremental persistence.
  // Dead code suppression: demote findings in functions with zero callers
  // (except route handlers which are entry points)
  const calledQids = new Set();
  if (callGraph.edges) for (const e of callGraph.edges) calledQids.add(typeof e.to === 'string' ? e.to : e.to?.qid);
  if (callGraph.callersOf) for (const [qid, callers] of callGraph.callersOf) { if (callers && callers.size) calledQids.add(qid); }
  for (const f of all) {
    if (!f._funcQid) continue;
    const fn = callGraph.functions?.get(f._funcQid);
    if (!fn) continue;
    if (calledQids.has(f._funcQid)) continue;
    if (/handler|route|controller|middleware|endpoint/i.test(fn.name || '')) continue;
    f._inDeadCode = true;
    const dg = { critical: 'high', high: 'medium', medium: 'low', low: 'info' };
    if (dg[f.severity]) f.severity = dg[f.severity];
  }
  Object.defineProperty(all, '_summaryCache', { value: summaryCache, enumerable: false });
  return all;
}
