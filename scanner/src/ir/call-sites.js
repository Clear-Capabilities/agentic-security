// Shared call-site extraction.
//
// Reads only the IR contract documented in ./CLAUDE.md — it walks cfg.nodes and
// collects call expressions from `call`, `assign`, `return`, `throw` and `if`
// nodes — so nothing here is language-specific.
//
// It lives in one place deliberately. Phase 1 put a resolver guard at a single
// call site; the next task re-broke it and it had to be moved into callgraph.js.
// Five copies of this would recreate that exactly.

// Recursively collect every 'call' subexpression inside a lowered expr tree
// (a call's own args can themselves contain calls, e.g. `foo(bar(x))`).
// `elements` (array literals) and `props` (object literals) are walked too —
// added when parser-py-cst.js's own copy of this walker was folded in here,
// so that e.g. `xs = [foo(x), bar(y)]` still surfaces both call sites for
// Python. Harmless for other languages: those fields are simply absent from
// their expr shapes.
function _collectCallExprs(expr, out) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.kind === 'call') {
    out.push(expr);
    for (const a of expr.args || []) _collectCallExprs(a, out);
    return;
  }
  if (Array.isArray(expr.parts)) for (const p of expr.parts) _collectCallExprs(p, out);
  if (Array.isArray(expr.branches)) for (const b of expr.branches) _collectCallExprs(b, out);
  if (Array.isArray(expr.elements)) for (const e of expr.elements) _collectCallExprs(e, out);
  if (Array.isArray(expr.props)) for (const p of expr.props) _collectCallExprs(p && p.value, out);
  if (expr.left) _collectCallExprs(expr.left, out);
  if (expr.right) _collectCallExprs(expr.right, out);
  if (expr.object) _collectCallExprs(expr.object, out);
}

// Build the `fn.calls` list documented at parser-js.js:19 —
// `[{ site, callee, args, line }]` — from the CFG. A call can appear at
// statement position (its own 'call' node) or embedded in another node's
// expression (an assignment's RHS, a return/throw value, an if condition —
// `char* p = getenv("CMD")` is exactly the source-introducing shape the
// taint engine needs to see and must not be missed just because it isn't a
// bare statement).
//
// Known boundaries (not modeled): a call in a `for`-loop's step expression
// (`for (;; advance(p))`) is not surfaced — the CFG only lowers the loop's
// test into the `if` node's `cond`; a call as an assignment's LHS/target
// (not a real C++ shape but a malformed one a fuzz input could produce) is
// never inspected, only `source`; and a `kind: 'unknown'` statement (a
// construct `_lowerStmt` couldn't classify) contributes no call sites even
// if it textually contains one.
export function callSitesFromCfg(cfg) {
  const sites = [];
  for (const [nodeId, node] of Object.entries((cfg && cfg.nodes) || {})) {
    if (!node) continue;
    let root = null;
    if (node.kind === 'call') root = { kind: 'call', callee: node.callee, args: node.args };
    else if (node.kind === 'assign') root = node.source;
    else if (node.kind === 'return' || node.kind === 'throw') root = node.value;
    else if (node.kind === 'if') root = node.cond;
    if (!root) continue;
    const found = [];
    _collectCallExprs(root, found);
    for (const c of found) {
      sites.push({ site: nodeId, callee: c.callee, args: c.args, line: node.line });
    }
  }
  return sites;
}
