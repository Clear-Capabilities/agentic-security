// Backward taint slicing (P1.4).
//
// Forward analysis answers: "given these sources, what flows reach the sinks?"
// Backward slicing answers: "given this sink, walk back along def-use to
// find the source(s)." The two combined give precise source→sink paths for
// every emitted finding — the "show me the work" explainability layer.
//
// Algorithm (intraprocedural for v1):
//
//   slice(fn, sinkNode, sinkArgPath):
//     work = [{ node: sinkNode, path: sinkArgPath }]
//     visited = set
//     trail = []
//     while work non-empty:
//       n = work.pop()
//       if visited.has(n.node + ':' + n.path): continue
//       visited.add(...)
//       if n.node is 'assign' and target subsumes n.path:
//         trail.push(n)
//         enqueue every read in n.node.source as a new query
//       follow CFG predecessor edges and continue
//     return trail (oldest first)
//
// We use the IR CFG's `succ` arrays — predecessors are not directly stored
// but we precompute the reverse edges for each function on demand.
//
// Interprocedural: when the sink's argument is bound to a function parameter,
// we ascend to caller(s) by consulting the call graph. v1 visits up to 5
// callers (BFS-bounded) to keep the slicer fast.

import { accessPathOf, pathIsCoveredByPrefix } from './access-paths.js';
import { matchSinkOrSanitizer } from './catalog.js';
import { safeSanitizerOutputRegex as _safeSanitizerOutputRegex } from './string-domain.js';
import { _collectExprVars } from './engine.js';

const SLICE_BUDGET_NODES = 200;
const SLICE_BUDGET_CALLERS = 5;

function _reverseEdges(cfg) {
  const rev = new Map();
  if (!cfg || !cfg.nodes) return rev;
  for (const id of Object.keys(cfg.nodes)) {
    const node = cfg.nodes[id];
    for (const s of (node?.succ || [])) {
      if (!rev.has(s)) rev.set(s, []);
      rev.get(s).push(id);
    }
  }
  return rev;
}

/**
 * Build a backward slice from a finding's sink site to its source(s).
 *
 *   fn:        the function the sink lives in
 *   sinkNode:  the IR node where the sink fires
 *   sinkArgPath: the access path of the tainted argument (string)
 *
 * Returns an ordered list of trace steps (source-first):
 *   [
 *     { line, kind: 'source',   label, varName, path },
 *     { line, kind: 'assign',   from, to, path },
 *     { line, kind: 'sanitize', callee, sanitizerId, path },  // a RECOGNIZED
 *                                                              // catalog sanitizer
 *                                                              // applied on the path
 *     { line, kind: 'call',     callee, sanitizerId: null, path },  // any OTHER
 *                                                                    // call — best-effort
 *                                                                    // continuity only;
 *                                                                    // a sound consumer
 *                                                                    // (e.g. the SMT
 *                                                                    // encoder) must NOT
 *                                                                    // treat this as a
 *                                                                    // known transform
 *     { line, kind: 'sink',     callee, argIndex, path },
 *   ]
 */
export function sliceBackward(fn, sinkNode, sinkArgPath) {
  const out = [];
  if (!fn || !sinkNode) return out;
  const cfg = fn.cfg;
  if (!cfg || !cfg.nodes) return out;
  const rev = _reverseEdges(cfg);

  // Map node-id to itself lookup for nodes in this CFG.
  const nodes = cfg.nodes;

  // We don't directly know the node-id of `sinkNode`; the caller passes
  // a reference. Recover it by linear search (CFGs are small per fn).
  let sinkNid = null;
  for (const id of Object.keys(nodes)) {
    if (nodes[id] === sinkNode) { sinkNid = id; break; }
  }
  if (!sinkNid) return out;

  out.push({
    line: sinkNode.line || 0,
    kind: 'sink',
    callee: sinkNode.callee || null,
    path: sinkArgPath,
  });

  const work = [{ nid: sinkNid, queryPath: sinkArgPath }];
  const visited = new Set();
  let visitedCount = 0;

  while (work.length) {
    if (++visitedCount > SLICE_BUDGET_NODES) break;
    const { nid, queryPath } = work.shift();
    const key = `${nid}::${queryPath}`;
    if (visited.has(key)) continue;
    visited.add(key);

    const node = nodes[nid];
    if (!node) continue;

    // The query path matches an assignment target? Record the def + chase RHS.
    if (node.kind === 'assign' && typeof node.target === 'string' && pathIsCoveredByPrefix(queryPath, node.target)) {
      const srcAp = accessPathOf(node.source);
      out.push({
        line: node.line || 0,
        kind: 'assign',
        to: node.target,
        from: srcAp,
        path: queryPath,
      });
      // Switch the query to the RHS access path (if any). If the source
      // itself is a catalog source (req.body, etc.), mark it as the
      // origin step.
      if (srcAp) {
        // Heuristic source detection without re-importing catalog —
        // anything that starts with a common source prefix.
        if (/^req\.(?:body|query|params|headers|cookies)|process\.env|window\.location|document\.URL/.test(srcAp)) {
          out.push({
            line: node.line || 0,
            kind: 'source',
            label: srcAp,
            path: queryPath,
          });
          continue;
        }
        // Otherwise, follow the def of the new query path upstream.
        work.push({ nid, queryPath: srcAp });
      } else if (node.source && node.source.kind === 'call') {
        // Next-gen taint capability #5 (SMT path feasibility rebuild):
        // `accessPathOf` returns null for a CALL expression by design (it
        // only handles pure ident/member chains), so `const clean =
        // sanitize(x); sink(clean);` — arguably the single most common
        // real-world sanitizer idiom — previously dead-ended the slice
        // right here with no 'source' step ever appended: `srcAp` is null,
        // so neither branch above fires, and the bare "walk predecessors
        // regardless" loop below can only ever find a DIFFERENT def of the
        // SAME queryPath, never continue into the call's own argument.
        // Fixed by treating a call-shaped RHS as a real, tracked step: a
        // recognized CATALOG SANITIZER gets its own 'sanitize' kind (the
        // SMT encoder below trusts ONLY this shape, via the sanitizer's
        // proven output-regex, to constrain a value); anything else gets a
        // generic 'call' kind, for explainability continuity only — the
        // SMT encoder must refuse to build a sound proof across an opaque
        // call it cannot reason about, never treat it as either a
        // transparent passthrough or an implicit sanitizer. Deliberately
        // single-argument, intraprocedural only, matching this whole
        // module's own documented v1 scope: continues into the FIRST
        // argument carrying a resolvable access path, not every argument
        // (a sanitizer/helper's OTHER arguments are typically
        // configuration, e.g. `escape(x, {mode: 'html'})`, not additional
        // taint sources).
        const callee = node.source.callee;
        const args = Array.isArray(node.source.args) ? node.source.args : [];
        let argPath = null;
        for (const a of args) { const p = accessPathOf(a); if (p) { argPath = p; break; } }
        const hits = matchSinkOrSanitizer(callee, fn.file);
        const sanitizerHit = Array.isArray(hits) ? hits.find(h => h.kind === 'sanitizer') : null;
        const calleeName = typeof callee === 'string' ? callee
          : callee && callee.kind === 'ident' ? callee.name
          : callee && callee.kind === 'member' && typeof callee.prop === 'string' ? callee.prop
          : null;
        // `outputRegexSource` is a SEPARATE, narrower signal than
        // `sanitizerId` above: the broad 706-entry catalog match is fine
        // for EXPLAINABILITY (labelling a step "this looks like a
        // sanitizer call" for a human reading the trace), but it matches
        // by bare callee NAME — a project-local function that merely
        // happens to be named the same as a cataloged sanitizer (e.g. a
        // local `sanitize()` helper that does something unrelated) would
        // match it too. A soundness-critical consumer (the SMT
        // infeasibility check) must never treat that broad match as
        // license to assume a specific, provable output shape — only
        // `safeSanitizerOutputRegex`'s own small, hand-vetted set of
        // unambiguous global builtins earns that trust.
        const outputRegexSource = calleeName ? _safeSanitizerOutputRegex(calleeName) : null;
        out.push({
          line: node.line || 0,
          kind: sanitizerHit ? 'sanitize' : 'call',
          callee: calleeName,
          sanitizerId: sanitizerHit ? sanitizerHit.id : null,
          outputRegexSource: outputRegexSource ? outputRegexSource.source : null,
          outputRegexFlags: outputRegexSource ? outputRegexSource.flags : null,
          path: queryPath,
        });
        if (argPath) work.push({ nid, queryPath: argPath });
      }
    }

    // Walk predecessors regardless — defs can be on prior nodes.
    for (const p of (rev.get(nid) || [])) {
      work.push({ nid: p, queryPath });
    }
  }

  // Reverse so the trace reads source-first.
  return out.reverse();
}

/**
 * Helper: annotate every finding in a list with its backward slice.
 *
 *   findings: produced by the engine, expected to carry `_funcQid` and `line`.
 *   perFileIR / callGraph: same shape the dataflow engine consumes.
 *
 * Walltime-bounded: total annotation work is capped by
 * AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS (default 30_000). When the
 * budget is exhausted, remaining findings are left without slices —
 * earlier findings keep their annotations.
 *
 * Returns the (mutated) findings array, with an `_annotateBackwardSlicesStats`
 * scratch property on the array containing { annotated, skipped, exhausted }.
 */
export function annotateBackwardSlices(findings, perFileIR, callGraph) {
  if (!Array.isArray(findings)) return findings;
  const budgetMs = Number(process.env.AGENTIC_SECURITY_BACKWARD_SLICE_BUDGET_MS) || 30_000;
  const deadline = Date.now() + budgetMs;
  // Build a qid → fn map for O(1) lookup.
  const fnByQid = new Map();
  if (callGraph && callGraph.functions) {
    for (const fn of callGraph.functions.values()) fnByQid.set(fn.qid, fn);
  }
  let annotated = 0, skipped = 0, exhausted = false;
  for (const f of findings) {
    if (Date.now() > deadline) { exhausted = true; skipped++; continue; }
    if (!f || !f._funcQid) { skipped++; continue; }
    const fn = fnByQid.get(f._funcQid);
    if (!fn) { skipped++; continue; }
    // Find the sink node in fn by line + callee match.
    let sinkNode = null;
    for (const nid of Object.keys(fn.cfg?.nodes || {})) {
      const n = fn.cfg.nodes[nid];
      if (!n || n.kind !== 'call') continue;
      if (n.line === f.line && n.callee === f.callee) { sinkNode = n; break; }
    }
    if (!sinkNode) { skipped++; continue; }
    // The tainted arg path — derive from the tainted argument's expression.
    // `f.argIndex` can be a real number, the string 'all' (any arg tainted —
    // no single index to point at) or 'rhs' (a member-write sink) — only a
    // plain numeric index names one real argument to slice from.
    const argExprs = sinkNode.args || [];
    const taintedArg = typeof f.argIndex === 'number' ? argExprs[f.argIndex] : undefined;
    let argPath = accessPathOf(taintedArg);
    let slice = argPath ? sliceBackward(fn, sinkNode, argPath) : null;
    // Next-gen taint capability #5 (SMT path-feasibility rebuild):
    // `accessPathOf` only ever succeeds for a BARE ident/member chain — the
    // single most common real shape, a sink argument built by string
    // concatenation (`'SELECT ...' + id`, a template literal, string.format
    // args, …), is a `binary`/`tpl`/`call` expression, so `accessPathOf`
    // returns null and the slice used to fall back to the unmatchable
    // placeholder string `arg[${f.argIndex}]` — no real variable is ever
    // named that, so `sliceBackward` could only ever return the bare sink
    // node, structurally regardless of AGENTIC_SECURITY_BACKWARD_SLICE.
    // Fixed by extracting every free variable/access-path referenced
    // ANYWHERE in the tainted argument expression (the same tree-walker
    // `engine.js`'s own `_sourcesReachingExpr` uses to attribute a finding
    // to its real source) and trying each one in turn, keeping the first
    // that yields a genuine (more-than-just-the-sink) slice.
    if ((!slice || slice.length <= 1) && taintedArg) {
      const vars = new Set();
      _collectExprVars(taintedArg, vars);
      for (const candidate of vars) {
        const candidateSlice = sliceBackward(fn, sinkNode, candidate);
        if (candidateSlice && candidateSlice.length > 1) { slice = candidateSlice; break; }
        if (!slice) slice = candidateSlice;
      }
    }
    if (slice && slice.length) {
      f.backwardSlice = slice;
      f.pathSteps = (f.pathSteps || []).concat(slice.map(s => ({
        type: s.kind,
        label: s.label || s.callee || s.path || '',
        line: s.line,
      })));
      annotated++;
    } else {
      skipped++;
    }
  }
  Object.defineProperty(findings, '_annotateBackwardSlicesStats', {
    value: { annotated, skipped, exhausted, budgetMs },
    enumerable: false,
  });
  return findings;
}
