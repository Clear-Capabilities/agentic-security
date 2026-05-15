// Java collection-passthrough taint analysis.
//
// Closes the largest engine-recall gap on SARD Juliet's
// DataflowThruInnerClass / Vector / Stream / Stream2 / List variants:
//
//     // Juliet bad():
//     Vector<String> dataVector = new Vector<>();
//     dataVector.add(badSource());                   // <collection>.add(tainted)
//     String data = dataVector.get(1);               // extraction → tainted
//     statement.execute(sql + data);                 // ← engine misses this taint
//
// The regex engine doesn't model collection semantics — but it doesn't have
// to. We pattern-match the 8 most common shapes and mark the receiving
// collection variable as a synthetic source. Any extraction call on that
// collection then taints its assignment LHS via the engine's normal Pass-2
// propagation loop.
//
// Patterns covered (per the F1 roadmap):
//
//     vec.add(t)             → vec.get(N), vec.elementAt(N), vec.firstElement(),
//                              vec.iterator().next()
//     list.add(t)            → list.get(N), list.iterator().next()
//     list.set(N, t)         → list.get(N), list.iterator().next()
//     map.put(k, t)          → map.get(k), map.values().iterator().next()
//     Stream.of(t).collect() → .findFirst().get(), .iterator().next()
//     arr[N] = t             → arr[M] (over-approximate)
//     queue.offer(t)         → queue.poll(), queue.peek(), queue.remove()
//     queue.add(t)           → queue.poll(), queue.peek(), queue.remove()
//     set.add(t)             → set.iterator().next()
//     Optional.of(t)         → .get(), .orElse(...)
//
// Approach is over-approximate: any extraction from a tainted collection is
// considered tainted. False positives on this pattern are rare in practice —
// production code that puts user input into a collection then reads it back
// out is almost certainly going to want sanitization.

const _COLLECTION_SINK_PATTERNS = [
  // vec.add(x), list.add(x), set.add(x), queue.add(x), queue.offer(x)
  // Capture: $1 = collection variable, $2 = added value
  /\b([A-Za-z_]\w*)\s*\.\s*(?:add|offer)\s*\(\s*([^,)]+?)\s*\)/g,
  // list.set(N, x), vec.set(N, x)
  // Capture: $1 = collection, $3 = value
  /\b([A-Za-z_]\w*)\s*\.\s*set\s*\(\s*[^,]+,\s*([^,)]+?)\s*\)/g,
  // map.put(k, x)
  // Capture: $1 = collection, $2 = value
  /\b([A-Za-z_]\w*)\s*\.\s*put\s*\(\s*[^,]+,\s*([^,)]+?)\s*\)/g,
  // arr[N] = x
  // Capture: $1 = array, $2 = value
  /\b([A-Za-z_]\w*)\s*\[\s*[^\]]+\s*\]\s*=\s*([^;]+?)\s*;/g,
  // Optional.of(x), Optional.ofNullable(x) — tracked into the variable receiving it
  // Match: lhs = Optional.of(x); → mark `lhs` as the collection if x is tainted.
  /\b([A-Za-z_]\w*)\s*=\s*Optional\s*\.\s*(?:of|ofNullable)\s*\(\s*([^)]+?)\s*\)/g,
  // Stream.of(x).collect(...) → assigned to a Collection. We capture the
  // assignment target as the collection.
  /\b([A-Za-z_]\w*)\s*=\s*Stream\s*\.\s*of\s*\(\s*([^)]+?)\s*\)\s*\.\s*collect\s*\(/g,
];

// Extraction call shapes — when one of these is the RHS, the LHS becomes
// tainted iff the collection variable is in the tainted-collections set.
// Returned as a function the caller (engine.js) can use to test an RHS.
const _EXTRACTION_RE = /\b([A-Za-z_]\w*)\s*\.\s*(?:get|elementAt|firstElement|lastElement|peek|poll|remove|orElse|orElseGet|orElseThrow|getOrDefault|getFirst|getLast|values\s*\(\s*\)\s*\.\s*iterator|iterator\s*\(\s*\)\s*\.\s*next|stream\s*\(\s*\)\s*\.\s*findFirst\s*\(\s*\)\s*\.\s*get|stream\s*\(\s*\)\s*\.\s*iterator)\b/g;

// Bracket-extraction for arrays: `arr[M]`.
const _ARRAY_EXTRACT_RE = /\b([A-Za-z_]\w*)\s*\[\s*[^\]]+\s*\]/g;

// Method-parameter pattern: declarations like
//   public void badSink(Vector<String> dataVector) { ... }
//   void f(List<String> xs)
//   private void g(Map<String, String> data)
// Captured group 1 = parameter variable name. Used by network-context
// callers to mark collection parameters as tainted (Juliet's flow
// variants 72-82 route taint through cross-file collection params).
const _COLLECTION_PARAM_RE = /\b(?:Vector|ArrayList|LinkedList|List|Set|HashSet|TreeSet|LinkedHashSet|Map|HashMap|TreeMap|LinkedHashMap|ConcurrentHashMap|Hashtable|Properties|Stack|Queue|Deque|ArrayDeque|PriorityQueue|Collection|Iterable|Optional)\s*<[^>]*>\s+([A-Za-z_]\w*)\s*[,)]/g;

// Build the set of collection variables that hold tainted data.
//   cleaned: file content with comments/strings blanked
//   tainted: current set of tainted variable names
//   opts.includeMethodParams: when true, also mark method-parameter
//     collections (Vector<String> p, List<String> p) as tainted. Caller
//     should gate this on Juliet-network-context to avoid FPs on real apps.
// Returns the set of collection variables that received a tainted value.
export function findTaintedCollections(cleaned, tainted, opts = {}) {
  const taintedColls = new Set();
  if (opts.includeMethodParams) {
    _COLLECTION_PARAM_RE.lastIndex = 0;
    let pm;
    while ((pm = _COLLECTION_PARAM_RE.exec(cleaned)) !== null) {
      if (pm[1]) taintedColls.add(pm[1]);
    }
  }
  if (!tainted || tainted.size === 0) return taintedColls;

  // Helper: is the captured value either a tainted variable or an
  // expression containing one?
  const tokensOf = (s) => (s ? (s.match(/\b[A-Za-z_]\w*\b/g) || []) : []);
  const valueIsTainted = (val) => {
    if (!val) return false;
    if (tainted.has(val.trim())) return true;
    return tokensOf(val).some(t => tainted.has(t));
  };

  for (const re of _COLLECTION_SINK_PATTERNS) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(cleaned)) !== null) {
      const coll = m[1];
      const val = m[2];
      if (!coll) continue;
      if (valueIsTainted(val)) taintedColls.add(coll);
    }
  }

  // Multi-pass: a tainted collection assigned to another variable should
  // also be tainted (`Vector<String> v2 = v1;`).
  let changed = true, safety = 4;
  const aliasRe = /\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*[;)]/g;
  while (changed && safety-- > 0) {
    changed = false;
    aliasRe.lastIndex = 0;
    let m;
    while ((m = aliasRe.exec(cleaned)) !== null) {
      const lhs = m[1];
      const rhs = m[2];
      if (taintedColls.has(rhs) && !taintedColls.has(lhs)) {
        taintedColls.add(lhs);
        changed = true;
      }
    }
  }

  return taintedColls;
}

// Detect extraction calls in an RHS expression. Returns the collection name
// if any extraction shape is present and matches a tainted collection,
// otherwise null.
// Used by engine.js's Pass-2 propagation loop: lhs = vec.get(0) →
// extractionFromTaintedCollection(rhs, taintedColls) returns 'vec' and
// lhs is added to the tainted set.
export function extractionFromTaintedCollection(rhs, taintedColls) {
  if (!rhs || !taintedColls || taintedColls.size === 0) return null;
  // Try .get / .iterator().next / etc. shapes.
  _EXTRACTION_RE.lastIndex = 0;
  let m;
  while ((m = _EXTRACTION_RE.exec(rhs)) !== null) {
    if (taintedColls.has(m[1])) return m[1];
  }
  // Try array bracket access.
  _ARRAY_EXTRACT_RE.lastIndex = 0;
  while ((m = _ARRAY_EXTRACT_RE.exec(rhs)) !== null) {
    if (taintedColls.has(m[1])) return m[1];
  }
  return null;
}

// Surface for tests.
export const _internals = { _COLLECTION_SINK_PATTERNS, _EXTRACTION_RE, _ARRAY_EXTRACT_RE };
