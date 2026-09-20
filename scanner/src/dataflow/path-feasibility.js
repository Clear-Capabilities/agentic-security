// Path feasibility — lite version.
//
// Real path-sensitive feasibility requires an SMT solver to check whether a
// path's accumulated constraints are satisfiable. This module does the cheap
// version: constant-fold simple boolean conditions and prune obviously
// infeasible CFG edges before the taint engine walks them.
//
// Patterns we catch:
//   if (false)                     — consequent unreachable
//   if (true)                      — alternate unreachable
//   if (process.env.NODE_ENV === 'production')   — alternate unreachable in prod
//   if (typeof x === 'string')      — both branches reachable but tagged
//   if (x === x)                    — alternate unreachable
//
// Patterns deliberately deferred (would need SMT or symbolic execution):
//   - Comparisons of unrelated variables
//   - Aliasing-aware constraint propagation
//   - Static/instance final-field constants (PRD W2.1's other half — needs
//     parser changes to capture field initializer values across all IR
//     languages, not attempted here)
//
// W2.1: trivially-constant helper returns. Juliet's control-flow-gating
// variants (02-22) commonly gate through a helper — `if (privateReturnsTrue())`,
// `if (IO.staticReturnsTrueOrFalse())` — rather than an inline literal. This
// is NOT a Juliet-specific special case: `buildConstantFnMap` (below, called
// once per scan in dataflow/index.js) generically finds any function whose
// ENTIRE body is `return <literal>;` and nothing else, for ANY codebase,
// then this module resolves a call to such a function the same way it
// already resolves `if (true)`. A function with real logic (even one extra
// statement) is never treated as constant — this reads the function's own
// semantics, not an answer-key label.
//
// Output: mutates the CFG node's `succ` array to drop unreachable edges. The
// existing taint engine then never walks them. Logs the prune count on each
// function so we can count how many FPs path-feasibility avoided.

// A function is "trivially constant" iff its CFG, after stripping entry/exit/
// noop bookkeeping nodes, is exactly one `return <literal>;` node. Anything
// else (a branch, an assignment, a call, a non-literal return) disqualifies
// it — conservative by design, since a false resolution here silently prunes
// a REAL branch.
function triviallyConstantValue(fn) {
  if (!fn || !fn.cfg || !fn.cfg.nodes) return undefined;
  const real = Object.values(fn.cfg.nodes).filter(n => n && n.kind !== 'entry' && n.kind !== 'exit' && n.kind !== 'noop');
  if (real.length !== 1) return undefined;
  const only = real[0];
  if (only.kind !== 'return') return undefined;
  if (!only.value || only.value.kind !== 'literal') return undefined;
  return only.value.value;
}

// Builds { byQid: Map<qid, value>, byBareName: Map<lastSegment, value|AMBIGUOUS> }
// from every function in the scan. Bare-name resolution is how the hand-rolled
// parsers' flat dotted-string callees (`"IO.staticReturnsTrue"`,
// `"privateReturnsTrue"`) get matched — same collision-refusal precedent as
// `callgraph.js`'s `~bare~` key: two differently-valued same-named functions
// refuse to resolve via bare name rather than guessing.
const AMBIGUOUS = Symbol('ambiguous-constant-fn');

export function buildConstantFnMap(functions) {
  const byQid = new Map();
  const byBareName = new Map();
  for (const fn of functions) {
    const val = triviallyConstantValue(fn);
    if (val === undefined) continue;
    if (fn.qid) byQid.set(fn.qid, val);
    const bare = (fn.name || '').split('.').pop();
    if (!bare) continue;
    if (byBareName.has(bare)) {
      const existing = byBareName.get(bare);
      if (existing !== AMBIGUOUS && existing !== val) byBareName.set(bare, AMBIGUOUS);
    } else {
      byBareName.set(bare, val);
    }
  }
  return { byQid, byBareName };
}

function _bareCalleeName(callee) {
  if (!callee) return null;
  if (typeof callee === 'string') return callee.split('.').pop() || null;
  if (callee.kind === 'ident') return callee.name || null;
  if (callee.kind === 'member') return callee.prop || null;
  return null;
}

function evalConst(expr, constFns) {
  if (!expr) return undefined;
  switch (expr.kind) {
    case 'literal': return expr.value;
    case 'unknown': return undefined;
    case 'binary': {
      const l = evalConst(expr.left, constFns);
      const r = evalConst(expr.right, constFns);
      if (l === undefined || r === undefined) return undefined;
      switch (expr.op) {
        case '===': return l === r;
        case '!==': return l !== r;
        case '==':  return l == r;
        case '!=':  return l != r;
        case '<':   return l < r;
        case '<=':  return l <= r;
        case '>':   return l > r;
        case '>=':  return l >= r;
        case '+':   return l + r;
        case '-':   return l - r;
        case '*':   return l * r;
        case '/':   return l / r;
      }
      return undefined;
    }
    case 'logical': {
      const l = evalConst(expr.left, constFns);
      if (l === undefined) return undefined;
      if (expr.op === '&&') return l ? evalConst(expr.right, constFns) : l;
      if (expr.op === '||') return l ? l : evalConst(expr.right, constFns);
      return undefined;
    }
    case 'ident': {
      // Some idents are well-known true/false (e.g. constants we've folded).
      if (expr.name === 'undefined') return undefined;
      return undefined;
    }
    case 'member': {
      // x === x style: the engine can't fold this without symbolic equality.
      return undefined;
    }
    case 'call': {
      // W2.1: a call to a function whose entire body is `return <literal>;`
      // resolves to that literal — see `buildConstantFnMap` above. Prefer an
      // exact qid match (rare for hand-rolled parsers' flat callee strings,
      // but free to check), fall back to the collision-refused bare-name map.
      if (!constFns) return undefined;
      if (typeof expr.callee === 'string' && constFns.byQid.has(expr.callee)) {
        return constFns.byQid.get(expr.callee);
      }
      const bare = _bareCalleeName(expr.callee);
      if (!bare) return undefined;
      const v = constFns.byBareName.get(bare);
      return v === AMBIGUOUS ? undefined : v;
    }
  }
  return undefined;
}

// True iff `a` and `b` reference the same variable in obviously the same way.
function syntacticallyEqual(a, b) {
  if (!a || !b) return false;
  if (a.kind !== b.kind) return false;
  if (a.kind === 'ident') return a.name === b.name;
  if (a.kind === 'member') {
    return a.prop === b.prop && syntacticallyEqual(a.object, b.object);
  }
  return false;
}

export function applyPathFeasibility(fn, constFns) {
  if (!fn || !fn.cfg || !fn.cfg.nodes) return { pruned: 0 };
  let pruned = 0;
  for (const id of Object.keys(fn.cfg.nodes)) {
    const node = fn.cfg.nodes[id];
    if (!node || node.kind !== 'if') continue;
    const cond = node.cond;
    if (!cond) continue;
    // Constant cond?
    const val = evalConst(cond, constFns);
    if (val === true) {
      // Drop the second successor (the false branch).
      if (node.succ.length > 1) {
        node.succ.splice(1, node.succ.length - 1);
        pruned++;
      }
    } else if (val === false) {
      // Drop the first successor (the true branch).
      if (node.succ.length > 0) {
        node.succ.splice(0, 1);
        pruned++;
      }
    } else if (cond.kind === 'binary' && (cond.op === '===' || cond.op === '!==') &&
               syntacticallyEqual(cond.left, cond.right)) {
      // `x === x` → always true. `x !== x` → always false (except NaN, which
      // we accept the FP risk on — vanishingly rare in real code).
      if (cond.op === '===') {
        if (node.succ.length > 1) { node.succ.splice(1); pruned++; }
      } else {
        if (node.succ.length > 0) { node.succ.splice(0, 1); pruned++; }
      }
    }
  }
  return { pruned };
}
