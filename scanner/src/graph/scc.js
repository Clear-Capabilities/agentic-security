// Strongly connected components and condensation for typed directed graphs.
//
// Pure and iterative: no recursion anywhere (a 100,000-node chain must not
// overflow the JavaScript stack), no I/O, no dependence on any analysis
// engine. The raw graph is never modified; the condensation is a derived
// view. It is a DAG, the raw graph is a provenance graph that may be cyclic.
//
// Input: `{ nodes: string[], edges: Array<[from, to] | {from, to}> }`.
// Node ids are strings. Duplicate nodes and duplicate edges are collapsed.
// An edge whose endpoint is not in `nodes` throws a TypeError rather than
// being silently dropped (the caller decides how to filter).
//
// Output is independent of the order of `nodes` and `edges`:
//   components    Array<{ id, members, internalEdges, recursive }>
//                 ids are 0..n-1 assigned by ascending smallest member, so
//                 they are stable. `members` is sorted. `internalEdges` is the
//                 sorted, de-duplicated list of [from, to] inside the
//                 component (self-loops included). `recursive` is true when
//                 the component has more than one member or a self-loop.
//   componentOf   Map<node, componentId>
//   condensationEdges  sorted unique [fromId, toId] across components
//   order         component ids in a deterministic topological order: for
//                 every cross-component edge u -> v, comp(u) appears before
//                 comp(v). Ties are broken by smallest component id.
//
// To schedule callees before callers, pass edges as callee -> caller (or
// reverse `order`). SCC membership says nodes can reach each other; it is
// not evidence that every pair has a feasible data path in any context.

function cmp(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

function edgeEnds(e) {
  if (Array.isArray(e)) return [e[0], e[1]];
  return [e.from, e.to];
}

// Minimal binary min-heap of non-negative integers.
class IntHeap {
  constructor() { this.a = []; }
  get size() { return this.a.length; }
  push(v) {
    const a = this.a;
    let i = a.length;
    a.push(v);
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (a[p] <= v) break;
      a[i] = a[p];
      i = p;
    }
    a[i] = v;
  }
  pop() {
    const a = this.a;
    const top = a[0];
    const last = a.pop();
    if (a.length > 0) {
      let i = 0;
      const n = a.length;
      for (;;) {
        let c = 2 * i + 1;
        if (c >= n) break;
        if (c + 1 < n && a[c + 1] < a[c]) c++;
        if (a[c] >= last) break;
        a[i] = a[c];
        i = c;
      }
      a[i] = last;
    }
    return top;
  }
}

export function computeScc(graph) {
  const rawNodes = (graph && graph.nodes) || [];
  const rawEdges = (graph && graph.edges) || [];
  const names = [...new Set(rawNodes)].sort(cmp);
  const n = names.length;
  const index = new Map();
  for (let i = 0; i < n; i++) index.set(names[i], i);

  // Adjacency over integer indexes, de-duplicated and sorted.
  const adjSets = new Array(n).fill(null);
  for (const e of rawEdges) {
    const [f, t] = edgeEnds(e);
    const fi = index.get(f);
    const ti = index.get(t);
    if (fi === undefined || ti === undefined) {
      throw new TypeError(`scc: edge endpoint not in nodes: ${String(f)} -> ${String(t)}`);
    }
    (adjSets[fi] ||= new Set()).add(ti);
  }
  const adj = adjSets.map(s => (s ? [...s].sort((a, b) => a - b) : []));

  // Iterative Tarjan with explicit call stack.
  const idx = new Int32Array(n).fill(-1);
  const low = new Int32Array(n);
  const onStack = new Uint8Array(n);
  const comp = new Int32Array(n).fill(-1);
  const sccStack = [];
  const callNode = [];
  const callPos = [];
  let counter = 0;
  const rawComps = [];
  for (let root = 0; root < n; root++) {
    if (idx[root] !== -1) continue;
    callNode.push(root); callPos.push(0);
    idx[root] = low[root] = counter++;
    sccStack.push(root); onStack[root] = 1;
    while (callNode.length > 0) {
      const top = callNode.length - 1;
      const v = callNode[top];
      const pos = callPos[top];
      const out = adj[v];
      if (pos < out.length) {
        callPos[top] = pos + 1;
        const w = out[pos];
        if (idx[w] === -1) {
          idx[w] = low[w] = counter++;
          sccStack.push(w); onStack[w] = 1;
          callNode.push(w); callPos.push(0);
        } else if (onStack[w] && idx[w] < low[v]) {
          low[v] = idx[w];
        }
      } else {
        if (low[v] === idx[v]) {
          const members = [];
          let w;
          do {
            w = sccStack.pop();
            onStack[w] = 0;
            members.push(w);
          } while (w !== v);
          rawComps.push(members);
        }
        callNode.pop(); callPos.pop();
        if (callNode.length > 0) {
          const parent = callNode[callNode.length - 1];
          if (low[v] < low[parent]) low[parent] = low[v];
        }
      }
    }
  }

  // Canonical component ids: ascending smallest member index (indexes follow
  // the sorted names, so this is order-independent).
  for (const m of rawComps) m.sort((a, b) => a - b);
  rawComps.sort((a, b) => a[0] - b[0]);
  for (let c = 0; c < rawComps.length; c++) for (const v of rawComps[c]) comp[v] = c;

  const k = rawComps.length;
  const internal = Array.from({ length: k }, () => []);
  const condSets = new Array(k).fill(null);
  for (let v = 0; v < n; v++) {
    const cv = comp[v];
    for (const w of adj[v]) {
      const cw = comp[w];
      if (cv === cw) internal[cv].push([v, w]);
      else (condSets[cv] ||= new Set()).add(cw);
    }
  }
  const condAdj = condSets.map(s => (s ? [...s].sort((a, b) => a - b) : []));

  // Kahn's algorithm with a min-heap on component id.
  const indeg = new Int32Array(k);
  for (let c = 0; c < k; c++) for (const d of condAdj[c]) indeg[d]++;
  const heap = new IntHeap();
  for (let c = 0; c < k; c++) if (indeg[c] === 0) heap.push(c);
  const order = [];
  while (heap.size > 0) {
    const c = heap.pop();
    order.push(c);
    for (const d of condAdj[c]) if (--indeg[d] === 0) heap.push(d);
  }

  const components = new Array(k);
  for (let c = 0; c < k; c++) {
    const members = rawComps[c].map(i => names[i]);
    const internalEdges = internal[c].map(([a, b]) => [names[a], names[b]]);
    internalEdges.sort((x, y) => cmp(x[0], y[0]) || cmp(x[1], y[1]));
    components[c] = {
      id: c,
      members,
      internalEdges,
      recursive: members.length > 1 || internalEdges.length > 0,
    };
  }
  const componentOf = new Map();
  for (let v = 0; v < n; v++) componentOf.set(names[v], comp[v]);
  const condensationEdges = [];
  for (let c = 0; c < k; c++) for (const d of condAdj[c]) condensationEdges.push([c, d]);

  return { components, componentOf, condensationEdges, order };
}

// Checks a result against its input graph. Returns `{ ok, problems }`; every
// problem is a human-readable string. Verifies: each node is in exactly one
// component, members are sorted, every edge is either internal to a
// component or goes forward in `order`, internal edges match, and the
// condensation edges are exactly the cross-component edges.
export function verifyScc(graph, result) {
  const problems = [];
  const nodes = [...new Set((graph && graph.nodes) || [])];
  const pos = new Map();
  result.order.forEach((c, i) => pos.set(c, i));
  if (result.order.length !== result.components.length || pos.size !== result.components.length) {
    problems.push('order is not a permutation of the components');
  }
  const seen = new Set();
  for (const c of result.components) {
    for (let i = 0; i < c.members.length; i++) {
      if (i > 0 && !(c.members[i - 1] < c.members[i])) problems.push(`component ${c.id} members not strictly sorted`);
      if (seen.has(c.members[i])) problems.push(`node ${c.members[i]} in more than one component`);
      seen.add(c.members[i]);
      if (result.componentOf.get(c.members[i]) !== c.id) problems.push(`componentOf disagrees for ${c.members[i]}`);
    }
  }
  for (const nd of nodes) if (!seen.has(nd)) problems.push(`node ${nd} missing from components`);
  const cross = new Set();
  const internalCount = new Map();
  const edgeSeen = new Set();
  for (const e of (graph && graph.edges) || []) {
    const [f, t] = edgeEnds(e);
    const key = `${f}\u0000${t}`;
    if (edgeSeen.has(key)) continue;
    edgeSeen.add(key);
    const cf = result.componentOf.get(f);
    const ct = result.componentOf.get(t);
    if (cf === undefined || ct === undefined) { problems.push(`edge ${f} -> ${t} has an unknown endpoint`); continue; }
    if (cf === ct) { internalCount.set(cf, (internalCount.get(cf) || 0) + 1); continue; }
    cross.add(`${cf}\u0000${ct}`);
    if (!(pos.get(cf) < pos.get(ct))) problems.push(`cross edge ${f} -> ${t} violates topological order`);
  }
  for (const c of result.components) {
    if (c.internalEdges.length !== (internalCount.get(c.id) || 0)) problems.push(`component ${c.id} internal edge count mismatch`);
    if (c.recursive !== (c.members.length > 1 || c.internalEdges.length > 0)) problems.push(`component ${c.id} recursive flag wrong`);
  }
  const condKeys = new Set(result.condensationEdges.map(([a, b]) => `${a}\u0000${b}`));
  if (condKeys.size !== cross.size || [...cross].some(x => !condKeys.has(x))) problems.push('condensation edges differ from the cross-component edges');
  return { ok: problems.length === 0, problems };
}
