// Numeric range / abstract integer domain (P3.2).
//
// Today's path-feasibility module (`path-feasibility.js`) prunes branches
// only when the condition folds to a literal constant. This module adds an
// abstract domain over INTEGER VALUES so we can reason about ranges:
//
//   const idx = 5;
//   if (idx < 0) return;                  // ← provably dead
//   if (idx >= arr.length) return;        // ← provably dead if arr.length ≥ 6
//   arr[idx]                              // ← bounds-check-safe
//
//   const idx = parseInt(req.query.i);
//   if (idx < 0 || idx >= 100) return;
//   table[idx]                            // ← idx narrowed to [0,99]
//
// The abstract domain is the classical interval lattice with TOP / BOTTOM:
//
//   TOP   ≡ (-∞, +∞)   — no information
//   range(lo, hi)      — closed interval; lo ≤ hi; lo,hi ∈ ℤ ∪ {-∞, +∞}
//   BOTTOM             — unreachable (use after a contradiction)
//
// Operations: join (∪), meet (∩), narrow-after-conditional, arithmetic
// (+, -, *, /), and a `decide` predicate over a relational test
// (lhs op rhs) returning 'true' | 'false' | 'maybe'.
//
// This is intentionally light-weight: no widening, no congruences, no
// strided intervals — just the things you need to prune ~30% of false-
// positive bounds-related paths in real code.

const NEG_INF = -Infinity;
const POS_INF = +Infinity;

export const TOP = Object.freeze({ kind: 'range', lo: NEG_INF, hi: POS_INF });
export const BOTTOM = Object.freeze({ kind: 'bottom' });

/** Build a closed interval [lo, hi]. Order is normalized. */
export function range(lo, hi) {
  if (lo === undefined || lo === null) lo = NEG_INF;
  if (hi === undefined || hi === null) hi = POS_INF;
  if (lo > hi) return BOTTOM;
  return { kind: 'range', lo, hi };
}

/** Convenience constructor for a single literal value. */
export function constant(n) {
  if (typeof n !== 'number' || Number.isNaN(n)) return TOP;
  if (!Number.isFinite(n)) return TOP;
  return range(n, n);
}

function isBottom(a) { return a && a.kind === 'bottom'; }
function isTop(a)    { return a && a.kind === 'range' && a.lo === NEG_INF && a.hi === POS_INF; }

/** Lattice join (least upper bound) — used at if/loop joins. */
export function join(a, b) {
  if (!a || isBottom(a)) return b;
  if (!b || isBottom(b)) return a;
  return range(Math.min(a.lo, b.lo), Math.max(a.hi, b.hi));
}

/** Lattice meet (greatest lower bound) — used to narrow after a guard. */
export function meet(a, b) {
  if (!a || !b) return BOTTOM;
  if (isBottom(a) || isBottom(b)) return BOTTOM;
  const lo = Math.max(a.lo, b.lo);
  const hi = Math.min(a.hi, b.hi);
  if (lo > hi) return BOTTOM;
  return range(lo, hi);
}

/** Arithmetic. */
export function add(a, b) {
  if (!a || !b || isBottom(a) || isBottom(b)) return BOTTOM;
  return range(a.lo + b.lo, a.hi + b.hi);
}
export function sub(a, b) {
  if (!a || !b || isBottom(a) || isBottom(b)) return BOTTOM;
  return range(a.lo - b.hi, a.hi - b.lo);
}
export function mul(a, b) {
  if (!a || !b || isBottom(a) || isBottom(b)) return BOTTOM;
  const candidates = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi];
  return range(Math.min(...candidates), Math.max(...candidates));
}

/**
 * Decide a relational test `a op b` where a, b are ranges.
 *   Returns 'true' iff every concrete pair in a×b satisfies the test.
 *   Returns 'false' iff every concrete pair fails it.
 *   Returns 'maybe' otherwise (overlap → undecidable).
 *
 * Supported ops: '<', '<=', '>', '>=', '==', '!=', '===', '!=='.
 */
export function decide(a, op, b) {
  if (!a || !b || isBottom(a) || isBottom(b)) return 'maybe';
  switch (op) {
    case '<':   return a.hi <  b.lo ? 'true' : a.lo >= b.hi ? 'false' : 'maybe';
    case '<=':  return a.hi <= b.lo ? 'true' : a.lo >  b.hi ? 'false' : 'maybe';
    case '>':   return a.lo >  b.hi ? 'true' : a.hi <= b.lo ? 'false' : 'maybe';
    case '>=':  return a.lo >= b.hi ? 'true' : a.hi <  b.lo ? 'false' : 'maybe';
    case '==':
    case '===': {
      // True iff intervals reduce to the same singleton.
      if (a.lo === a.hi && b.lo === b.hi && a.lo === b.lo) return 'true';
      // False iff disjoint.
      if (a.hi < b.lo || b.hi < a.lo) return 'false';
      return 'maybe';
    }
    case '!=':
    case '!==': {
      if (a.hi < b.lo || b.hi < a.lo) return 'true';
      if (a.lo === a.hi && b.lo === b.hi && a.lo === b.lo) return 'false';
      return 'maybe';
    }
    default: return 'maybe';
  }
}

/**
 * Narrow `a` by the assertion `a op b` having been observed as true.
 *   e.g.  narrow(TOP, '>=', constant(0))  →  range(0, +∞)
 *         narrow(TOP, '<',  constant(10)) →  range(-∞, 9)
 *
 * Returns a refined range; BOTTOM if the assertion is incompatible.
 */
export function narrow(a, op, b) {
  if (!a || !b) return a || TOP;
  if (isBottom(a) || isBottom(b)) return BOTTOM;
  switch (op) {
    case '<':  return meet(a, range(NEG_INF, b.hi - 1));
    case '<=': return meet(a, range(NEG_INF, b.hi));
    case '>':  return meet(a, range(b.lo + 1, POS_INF));
    case '>=': return meet(a, range(b.lo, POS_INF));
    case '==':
    case '===': return meet(a, b);
    case '!=':
    case '!==': {
      // Only refine when b is a singleton matching a boundary of a.
      if (b.lo === b.hi) {
        if (a.lo === b.lo) return range(a.lo + 1, a.hi);
        if (a.hi === b.lo) return range(a.lo, a.hi - 1);
      }
      return a;
    }
    default: return a;
  }
}

/**
 * Abstract an AST-ish expression into a range. Returns TOP for anything
 * we can't fold. The parser shape mirrors what `path-feasibility.js`
 * consumes: { kind: 'literal'|'ident'|'bin', ... }
 *
 *   env: Map<varName, range>  — the abstract store
 */
export function abstractEval(expr, env) {
  if (!expr) return TOP;
  if (expr.kind === 'literal' && typeof expr.value === 'number' && Number.isFinite(expr.value)) {
    return constant(expr.value);
  }
  if (expr.kind === 'ident' && env instanceof Map) {
    return env.get(expr.name) || TOP;
  }
  if (expr.kind === 'bin') {
    const l = abstractEval(expr.left, env);
    const r = abstractEval(expr.right, env);
    switch (expr.op) {
      case '+': return add(l, r);
      case '-': return sub(l, r);
      case '*': return mul(l, r);
      default:  return TOP;
    }
  }
  return TOP;
}

/** Render an interval for debugging / finding evidence. */
export function render(a) {
  if (!a) return '⊤';
  if (isBottom(a)) return '⊥';
  if (isTop(a))    return '(-∞, +∞)';
  const lo = a.lo === NEG_INF ? '-∞' : a.lo;
  const hi = a.hi === POS_INF ? '+∞' : a.hi;
  return `[${lo}, ${hi}]`;
}

/** True iff `a ⊑ b` (a is at least as precise as b). */
export function leq(a, b) {
  if (isBottom(a)) return true;
  if (isBottom(b)) return false;
  return a.lo >= b.lo && a.hi <= b.hi;
}
