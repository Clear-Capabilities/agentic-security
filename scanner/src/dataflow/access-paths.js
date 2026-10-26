// Field-sensitive access-path lattice (P1.1).
//
// Replaces the engine's flat Set<varName> with Set<accessPath>, where an
// access path is a string of the shape "base.prop.prop.prop" (any depth).
// The lattice operations are:
//
//   - prefixCovers(haveSet, query)
//       True iff some path in haveSet is a prefix of `query` (e.g. "x" covers
//       "x.y.z"). Models the "if x is tainted, x.y and x.y.z are tainted too"
//       contamination rule we already use today.
//
//   - longestCommonPrefixJoin(a, b)
//       At a branch-join point, given two access-path sets, compute the LCP
//       of every pair (a_path, b_path) that share a common prefix. The join
//       keeps:
//         (i)  paths present in BOTH a and b unchanged
//         (ii) for paths present in only ONE branch, KEEP them (over-
//              approximate — the path may have been mutated in that branch
//              and stayed clean in the other; we treat the union as the
//              conservative state).
//       This is the canonical lattice for forward dataflow over a powerset.
//
// The path string format is intentionally simple — dot-separated, with no
// support for [i] / [*] / function-call notation. Index sensitivity is a
// follow-on (P3 work).
//
// Public API:
//   accessPathOf(expr)             → string | null
//   isCoveredBy(set, path)         → bool — is `path` covered by some path in `set`?
//   joinSets(a, b)                 → new Set
//   addPath(set, path)             → new Set (returns a new set with `path` added,
//                                            collapsing redundant longer paths)
//   removePathAndDescendants(set, path) → new Set
//   canonicalize(set)              → new Set (removes paths covered by shorter prefixes)

/**
 * Convert an exprDesc (member / ident) into a dot-separated access path.
 * Returns null when the expression is not a pure ident/member chain (e.g.
 * has a call, binary, etc. — those are not access paths).
 */
export function accessPathOf(expr) {
  if (!expr) return null;
  if (expr.kind === 'ident') return expr.name;
  if (expr.kind === 'member') {
    if (!expr.object || typeof expr.prop !== 'string') return null;
    const base = accessPathOf(expr.object);
    if (!base) return null;
    return `${base}.${expr.prop}`;
  }
  return null;
}

/**
 * Returns true iff `path` is `prefix` or starts with `prefix + '.'`.
 */
export function pathIsCoveredByPrefix(path, prefix) {
  if (typeof path !== 'string' || typeof prefix !== 'string') return false;
  if (path === prefix) return true;
  return path.length > prefix.length && path[prefix.length] === '.' && path.startsWith(prefix);
}

/**
 * Returns true iff some entry in `set` is a prefix of `path` (or equals it).
 * This is the "covers" relation that determines whether `path` is tainted:
 * - `set = {"x"}` covers "x.y.z"  ✓
 * - `set = {"x.y"}` covers "x.y.z"  ✓
 * - `set = {"x.z"}` does NOT cover "x.y"  ✗
 * - `set = {"x.y.z"}` does NOT cover "x.y"  ✗ (we don't propagate UP)
 */
/**
 * True iff some path in `set` lies STRICTLY BELOW `path` (`o.cmd` is below `o`). Reading `o` as a whole value (passing it to a function, serialising
 * it) reads every field, so a tainted field taints the whole read; reading `o.safe` does not, because `o.cmd` is not below `o.safe`.
 */
export function hasTaintedDescendant(set, path) {
  if (!set || typeof path !== 'string') return false;
  const prefix = `${path}.`;
  for (const p of set) if (typeof p === 'string' && p.startsWith(prefix)) return true;
  return false;
}

export function isCoveredBy(set, path) {
  if (!set || typeof path !== 'string') return false;
  if (set.has(path)) return true;
  let idx = path.lastIndexOf('.');
  while (idx > 0) {
    const prefix = path.slice(0, idx);
    if (set.has(prefix)) return true;
    idx = prefix.lastIndexOf('.');
  }
  return false;
}

/**
 * Add `path` to the set. If a strictly-shorter prefix already covers `path`,
 * the set is unchanged. If `path` covers existing longer descendants, they
 * are removed (they're now redundant — taint at the shorter prefix subsumes
 * taint at the longer descendant).
 */
export function addPath(set, path) {
  if (typeof path !== 'string' || !path) return set;
  const out = new Set(set);
  // Strict-prefix already in set? Nothing to add.
  let idx = path.lastIndexOf('.');
  while (idx > 0) {
    const prefix = path.slice(0, idx);
    if (out.has(prefix)) return out;
    idx = prefix.lastIndexOf('.');
  }
  // Remove redundant longer descendants.
  for (const existing of [...out]) {
    if (existing !== path && pathIsCoveredByPrefix(existing, path)) out.delete(existing);
  }
  out.add(path);
  return out;
}

/**
 * Remove `path` AND every descendant from the set (re-assignment of `x`
 * clears `x.y`, `x.y.z`, etc.).
 */
export function removePathAndDescendants(set, path) {
  if (!set || typeof path !== 'string' || !path) return set;
  const out = new Set();
  for (const existing of set) {
    if (existing === path) continue;
    if (pathIsCoveredByPrefix(existing, path)) continue;
    out.add(existing);
  }
  return out;
}

/**
 * Branch-join: the conservative union of two access-path sets, with
 * redundant longer paths collapsed under their shorter-prefix parents.
 */
export function joinSets(a, b) {
  if (!a && !b) return new Set();
  if (!a) return canonicalize(b);
  if (!b) return canonicalize(a);
  // Union both, then canonicalize.
  const all = new Set();
  for (const p of a) all.add(p);
  for (const p of b) all.add(p);
  return canonicalize(all);
}

/**
 * Remove any path that is covered by some strictly-shorter prefix in the
 * same set. Idempotent.
 */
export function canonicalize(set) {
  if (!set || set.size <= 1) return new Set(set || []);
  const sorted = [...set].sort((a, b) => a.length - b.length || (a < b ? -1 : 1));
  const out = new Set();
  for (const path of sorted) {
    // A kept path covers `path` exactly when it is one of the dot-delimited prefixes of it, so look those up
    // (a handful per path) instead of testing every kept path (the set can hold hundreds in a large function).
    let covered = false;
    if (typeof path === 'string') {
      for (let i = path.indexOf('.'); i >= 0; i = path.indexOf('.', i + 1)) {
        if (out.has(path.slice(0, i))) { covered = true; break; }
      }
    }
    if (!covered) out.add(path);
  }
  return out;
}

/**
 * Hash a set for cache keying — sorted canonical paths joined by '|'.
 */
export function hashSet(set) {
  if (!set || set.size === 0) return 'empty';
  return [...canonicalize(set)].sort().join('|');
}

/**
 * Two access-path sets equal under canonicalization?
 */
export function setsEqual(a, b) {
  if (a === b) return true;
  if (!a || !b) return false;
  // Identical members are equal under any canonicalization; only a difference needs the canonical forms.
  if (a.size === b.size) {
    let same = true;
    for (const x of a) if (!b.has(x)) { same = false; break; }
    if (same) return true;
  }
  const ca = canonicalize(a), cb = canonicalize(b);
  if (ca.size !== cb.size) return false;
  for (const x of ca) if (!cb.has(x)) return false;
  return true;
}
