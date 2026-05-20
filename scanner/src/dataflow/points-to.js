// Steensgaard points-to / alias analysis (v0.70 #2).
//
// Unification-based, near-linear pointer analysis. The classical reference
// is Steensgaard, "Points-to analysis in almost linear time" (POPL'96).
//
// The idea: every program variable belongs to an equivalence class. Two
// variables in the same class point to the same set of abstract heap
// locations. When the analysis sees:
//
//   a = b        → unify class(a) with class(b)
//   a.f = c      → for the abstract object class(a) points to, its `f`-slot
//                  is unified with class(c)
//   x = a.f      → reverse: class(x) unifies with the `f`-slot of what a
//                  points to
//   a = new T()  → fresh abstract location L; class(a) points to L
//
// In Steensgaard, every step is a UNION, never a copy. This gives O(n α(n))
// time but loses some precision: `a = b; a = c` unifies class(b) and class(c)
// even though they were never directly compared. Worth the speed; the
// alternative (Andersen, inclusion-based) is cubic.
//
// We use it for ONE specific purpose: at taint-time, when checking whether
// a variable name `x` is in the tainted state, also check every alias of
// `x` per the points-to graph. A taint propagated through one alias is
// visible through all of them.
//
// Out of scope for v1:
//   - Heap snapshots (we don't model allocation freshness)
//   - Context-sensitivity (one graph per function; merged at call sites
//     via parameter unification)
//   - Containers (arrays, maps) — modelled as single abstract objects
//   - Reflection / dynamic dispatch
//
// Wiring: AGENTIC_SECURITY_POINTS_TO=1 in dataflow/index.js builds the
// graph before runTaintEngine. The engine reads `opts._pointsTo` and
// consults `aliasesOf(x)` inside exprTaint and the assign transfer.

// ─── Union-Find ──────────────────────────────────────────────────────────

class UnionFind {
  constructor() {
    this.parent = new Map();   // name → name (canonical rep)
    this.rank = new Map();     // canonical rep → tree depth
  }
  // Ensure `x` has a node. Idempotent.
  add(x) {
    if (!this.parent.has(x)) {
      this.parent.set(x, x);
      this.rank.set(x, 0);
    }
  }
  // Find canonical rep of `x` with path compression.
  find(x) {
    this.add(x);
    let cur = x;
    while (this.parent.get(cur) !== cur) cur = this.parent.get(cur);
    // Path compression — point every visited node directly to the root.
    let next = x;
    while (this.parent.get(next) !== cur) {
      const p = this.parent.get(next);
      this.parent.set(next, cur);
      next = p;
    }
    return cur;
  }
  // Union the classes of `a` and `b`. Returns the new canonical rep.
  union(a, b) {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra === rb) return ra;
    const ranka = this.rank.get(ra);
    const rankb = this.rank.get(rb);
    let winner, loser;
    if (ranka < rankb) { winner = rb; loser = ra; }
    else if (ranka > rankb) { winner = ra; loser = rb; }
    else { winner = ra; loser = rb; this.rank.set(winner, ranka + 1); }
    this.parent.set(loser, winner);
    return winner;
  }
  // Every name registered with the union-find.
  members() { return [...this.parent.keys()]; }
  // Map of canonical-rep → list of members.
  classes() {
    const out = new Map();
    for (const x of this.parent.keys()) {
      const r = this.find(x);
      if (!out.has(r)) out.set(r, []);
      out.get(r).push(x);
    }
    return out;
  }
}

// ─── PointsToGraph ───────────────────────────────────────────────────────

export class PointsToGraph {
  constructor() {
    this.uf = new UnionFind();
    // For each class, the abstract object it points to (also a class id).
    // Steensgaard's "pending" / lazy-unify trick: when two classes both have
    // distinct pointees, those pointees must themselves be unified.
    this.pointee = new Map();    // classId → classId (its pointee)
    // For each pointee-class, a per-field map of field-pointees.
    this.fields = new Map();     // pointeeId → Map<fieldName, classId>
  }

  _ensure(name) {
    this.uf.add(name);
    return this.uf.find(name);
  }

  // a = b  (or a = b's value flows into a)
  unify(a, b) {
    const ra = this._ensure(a);
    const rb = this._ensure(b);
    this._unifyClasses(ra, rb);
  }

  _unifyClasses(ra, rb) {
    if (ra === rb) return ra;
    const merged = this.uf.union(ra, rb);
    const other = merged === ra ? rb : ra;
    // If both classes had a pointee, unify the pointees.
    const pa = this.pointee.get(ra);
    const pb = this.pointee.get(rb);
    this.pointee.delete(other);
    if (pa && pb) {
      this.pointee.set(merged, this._unifyClasses(pa, pb));
    } else if (pa || pb) {
      this.pointee.set(merged, pa || pb);
    }
    // Same for field maps.
    const fa = this.fields.get(ra);
    const fb = this.fields.get(rb);
    this.fields.delete(other);
    if (fa && fb) {
      const merged_f = new Map(fa);
      for (const [k, v] of fb) {
        if (merged_f.has(k)) merged_f.set(k, this._unifyClasses(merged_f.get(k), v));
        else merged_f.set(k, v);
      }
      this.fields.set(merged, merged_f);
    } else if (fa || fb) {
      this.fields.set(merged, fa || fb);
    }
    return merged;
  }

  // a = new ... → bind `a` to a fresh pointee class
  alloc(a, locationId) {
    const ra = this._ensure(a);
    const loc = `__loc:${locationId}`;
    this._ensure(loc);
    const existing = this.pointee.get(ra);
    if (existing) this._unifyClasses(existing, this.uf.find(loc));
    else this.pointee.set(ra, this.uf.find(loc));
  }

  // a.f = c
  fieldStore(a, field, c) {
    const ra = this._ensure(a);
    const rc = this._ensure(c);
    // Get the pointee class of `a`; if absent, create a virtual one.
    let pa = this.pointee.get(ra);
    if (!pa) {
      pa = `__virt:${ra}`;
      this._ensure(pa);
      this.pointee.set(ra, this.uf.find(pa));
      pa = this.uf.find(pa);
    }
    if (!this.fields.has(pa)) this.fields.set(pa, new Map());
    const fmap = this.fields.get(pa);
    if (fmap.has(field)) {
      // Unify the existing field-pointee with rc.
      this._unifyClasses(fmap.get(field), rc);
    } else {
      fmap.set(field, rc);
    }
  }

  // x = a.f
  fieldLoad(x, a, field) {
    const rx = this._ensure(x);
    const ra = this._ensure(a);
    // Get or create pointee of `a`.
    let pa = this.pointee.get(ra);
    if (!pa) {
      pa = `__virt:${ra}`;
      this._ensure(pa);
      this.pointee.set(ra, this.uf.find(pa));
      pa = this.uf.find(pa);
    }
    // Get or create the field-pointee.
    if (!this.fields.has(pa)) this.fields.set(pa, new Map());
    const fmap = this.fields.get(pa);
    if (fmap.has(field)) {
      this._unifyClasses(fmap.get(field), rx);
    } else {
      fmap.set(field, rx);
    }
  }

  // Return all variable names in the same equivalence class as `name`,
  // INCLUDING `name` itself.
  aliasesOf(name) {
    if (!this.uf.parent.has(name)) return [name];
    const root = this.uf.find(name);
    // O(n) scan — for v1, fine; v2 would index class→members on each union.
    const out = [];
    for (const v of this.uf.parent.keys()) {
      if (this.uf.find(v) === root) out.push(v);
    }
    return out;
  }

  // Diagnostic snapshot.
  snapshot() {
    return {
      classes: [...this.uf.classes()].map(([root, members]) => ({ root, members })),
      pointees: [...this.pointee].map(([k, v]) => ({ class: k, points: v })),
      fields: [...this.fields].map(([k, m]) => ({ class: k, fields: [...m] })),
    };
  }
}

// ─── Build the graph from an IR universe ─────────────────────────────────

/**
 * Walk every function in the call graph and feed assign/call nodes into
 * the PointsToGraph. Returns the populated graph.
 *
 * Naming convention for the union-find:
 *   - Local variable `x` in function `qid` is named `qid::x`.
 *   - Global / unresolved references are named `::<name>`.
 *   - Allocation sites are named `__loc:<qid>:<line>`.
 */
export function buildPointsTo(perFileIR, callGraph) {
  const g = new PointsToGraph();
  if (!callGraph || !callGraph.functions) return g;
  for (const fn of callGraph.functions.values()) {
    _processFunction(fn, g);
  }
  // Interprocedural step: at every resolved call site, unify caller-arg
  // names with callee-param names. This makes parameter aliasing visible.
  for (const fn of callGraph.functions.values()) {
    if (!fn.cfg || !fn.cfg.nodes) continue;
    for (const nid of Object.keys(fn.cfg.nodes)) {
      const node = fn.cfg.nodes[nid];
      if (!node || node.kind !== 'call') continue;
      const resolved = callGraph.resolve ? callGraph.resolve(node.callee) : null;
      const target = resolved && resolved.qid ? resolved : null;
      if (!target || !Array.isArray(target.params)) continue;
      const args = node.args || [];
      for (let i = 0; i < target.params.length && i < args.length; i++) {
        const argName = _nameForExpr(fn.qid, args[i]);
        if (!argName) continue;
        g.unify(argName, `${target.qid}::${target.params[i]}`);
      }
    }
  }
  return g;
}

function _processFunction(fn, g) {
  if (!fn || !fn.cfg || !fn.cfg.nodes) return;
  for (const nid of Object.keys(fn.cfg.nodes)) {
    const node = fn.cfg.nodes[nid];
    if (!node) continue;
    if (node.kind === 'assign') _processAssign(fn, node, g);
  }
}

function _processAssign(fn, node, g) {
  const target = typeof node.target === 'string' ? node.target : null;
  if (!target) return;
  const tgtName = `${fn.qid}::${target}`;
  const src = node.source;
  if (!src) return;
  // x = y
  if (src.kind === 'ident' && typeof src.name === 'string') {
    g.unify(tgtName, `${fn.qid}::${src.name}`);
    return;
  }
  // x = y.f
  if (src.kind === 'member' && src.object && src.object.kind === 'ident' && typeof src.prop === 'string') {
    g.fieldLoad(tgtName, `${fn.qid}::${src.object.name}`, src.prop);
    return;
  }
  // x = new T()  / x = {} / x = []
  if (src.kind === 'object' || src.kind === 'array') {
    g.alloc(tgtName, `${fn.qid}:${node.line || 0}`);
    return;
  }
  if (src.kind === 'call' && typeof src.callee === 'string' && /^new\s+/.test(src.callee)) {
    g.alloc(tgtName, `${fn.qid}:${node.line || 0}`);
    return;
  }
  // Member-store: x.f = y handled by the `assign` whose TARGET is a string
  // path like "x.f". Our IR may emit `target: 'x.f'`; handle that.
  if (target.includes('.') && src.kind === 'ident') {
    const [recv, ...rest] = target.split('.');
    if (recv && rest.length === 1) {
      g.fieldStore(`${fn.qid}::${recv}`, rest[0], `${fn.qid}::${src.name}`);
      return;
    }
  }
}

function _nameForExpr(qid, expr) {
  if (!expr) return null;
  if (expr.kind === 'ident' && typeof expr.name === 'string') return `${qid}::${expr.name}`;
  return null;
}

// ─── Engine consumption helpers ──────────────────────────────────────────

/**
 * Given a points-to graph and a function qid + variable name, return all
 * known aliases (full qid-prefixed names) that the engine should also
 * check against the taint state.
 */
export function aliasesForVar(pointsTo, qid, varName) {
  if (!pointsTo || !pointsTo.aliasesOf) return [varName];
  const fullName = `${qid}::${varName}`;
  const aliases = pointsTo.aliasesOf(fullName);
  const out = new Set([varName]);
  for (const a of aliases) {
    // Strip the qid prefix for engine-state lookups (engine state is per-fn).
    const idx = a.indexOf('::');
    if (idx > 0) {
      const local = a.slice(idx + 2);
      // Skip __loc: / __virt: synthetic names.
      if (local && !local.startsWith('__')) out.add(local);
    }
  }
  return [...out];
}
