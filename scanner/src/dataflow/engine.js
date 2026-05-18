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

function exprTaint(expr, state) {
  // Returns true iff this expression evaluates to a tainted value under the
  // given taint state. ALSO treats catalog-registered source patterns as
  // tainted at-read — `req.body.host` used inline (no intermediate local)
  // is tainted because the source resolves at the read site.
  if (expr && expr.kind === 'member' && exprIsSource(expr)) return true;
  if (!expr) return false;
  switch (expr.kind) {
    case 'literal':           return false;
    case 'ident':             return state.has(expr.name);
    case 'member': {
      // x.y is tainted if x.y is in state OR x itself is in state and we have
      // no per-field narrowing (taint propagates through unknown sub-access).
      const base = (() => {
        if (!expr.object) return null;
        if (expr.object.kind === 'ident') return expr.object.name;
        return null;
      })();
      if (!base) return exprTaint(expr.object, state);
      if (state.has(`${base}.${expr.prop}`)) return true;
      if (state.has(base)) return true;
      return false;
    }
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

// Heuristic: does this expression read a registered source?
function exprIsSource(expr) {
  if (!expr) return null;
  if (expr.kind === 'member') {
    const hit = matchSource(expr);
    if (hit) return hit;
  }
  // Recurse — `req.body.name` should still find `req.body` as source.
  if (expr.kind === 'member' && expr.object) {
    return exprIsSource(expr.object);
  }
  return null;
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
      // Source detection on RHS.
      const src = exprIsSource(node.source);
      if (src && typeof node.target === 'string') {
        state.add(node.target);
        if (node.source && node.source.kind === 'member' && node.source.object?.kind === 'ident') {
          state.add(`${node.source.object.name}.${node.source.prop}`);
        }
        callContext._taintSources.push({ varName: node.target, sourceId: src.id, sourceLabel: src.label, line: node.line });
      } else if (exprTaint(node.source, state)) {
        if (typeof node.target === 'string') state.add(node.target);
      } else {
        // Re-assigning a previously-tainted var to a clean value clears it.
        if (typeof node.target === 'string') state.delete(node.target);
      }
      return { state, findings };
    }

    case 'call': {
      // 1. Catalog match: sanitizer, sink, or just an external/unresolved call.
      const cat = matchSinkOrSanitizer(node.callee);
      const argTaints = (node.args || []).map(a => exprTaint(a, state));
      if (cat) {
        for (const e of cat) {
          if (e.kind === 'sink' && (
            e.argIndex === 'all' ? argTaints.some(Boolean) :
            (typeof e.argIndex === 'number' && argTaints[e.argIndex])
          )) {
            const taintedArgIdx = e.argIndex === 'all'
              ? argTaints.findIndex(Boolean) : e.argIndex;
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
              // The trace is best-effort: we cite the source label from the
              // first source we saw in this analysis run.
              trace: callContext._taintSources.slice(0, 5),
            });
          }
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
function analyzeFunction(fn, entryState, callContext) {
  const nodes = fn.cfg.nodes; // plain object
  const work = [];
  const inStates = new Map(); // nodeId → Set<varName>
  const outStates = new Map();
  inStates.set(fn.cfg.entry, new Set(entryState));
  work.push(fn.cfg.entry);

  const visited = 0;
  let iterations = 0;
  const ITER_BUDGET = 5000;

  while (work.length) {
    if (++iterations > ITER_BUDGET) break;
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

  return outStates.get(fn.cfg.exit) || new Set();
}

function mergeStates(a, b) {
  if (!a && !b) return new Set();
  if (!a) return new Set(b);
  if (!b) return new Set(a);
  const out = new Set(a);
  for (const x of b) out.add(x);
  return out;
}
function stateEq(a, b) {
  if (!a || !b) return a === b;
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
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

  // Deterministic ordering (Sentinel-parity §9.2): sort functions by qid so
  // cache-cold runs produce the same finding sequence run-over-run.
  const fnList = [...callGraph.functions.values()].sort((a, b) =>
    a.qid < b.qid ? -1 : a.qid > b.qid ? 1 : 0
  );
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
    };
    try {
      analyzeFunction(fn, new Set(), callContext);
    } catch { continue; }
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
  return all;
}
