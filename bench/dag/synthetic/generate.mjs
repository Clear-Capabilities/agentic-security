// Seeded generators for large synthetic call-graph families with KNOWN
// properties. Every family is a pure function of (family, n, seed): the same
// triple always yields the same graph, and `digest` is a hash of the edge list
// so a run can prove it measured the graph the baseline recorded.
//
// Known properties are derived from the construction, not from running any
// analysis, so they can be compared against what the SCC computation reports.
//
//   chain      n nodes, n-1 edges i -> i+1.       n SCCs of size 1, 0 recursive.
//   ring       n nodes, n edges i -> (i+1) % n.   1 SCC of size n, recursive.
//   fanin      n-1 callers -> one hub.            n SCCs, hub in-degree n-1.
//   fanout     one root -> n-1 callees.           n SCCs, root out-degree n-1.
//   scc-rich   k = n/s blocks of s nodes; each block is a ring plus seeded
//              chords inside the block; blocks are linked forward only (block
//              j to a later block), so the condensation is a DAG.
//              k SCCs of size s (s >= 2), k recursive.
import * as crypto from 'node:crypto';

export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const FAMILIES = ['chain', 'ring', 'fanin', 'fanout', 'scc-rich'];
export const SCC_BLOCK_SIZE = 8;

export function nodeName(i) { return `f${String(i).padStart(8, '0')}`; }

/** Returns { family, n, seed, nodes: string[], edges: [string,string][], expected, digest }. */
export function generate(family, n, seed = 1) {
  if (!FAMILIES.includes(family)) throw new Error(`unknown family ${family}`);
  if (!Number.isInteger(n) || n < 2) throw new Error('n must be an integer >= 2');
  const rnd = mulberry32(seed);
  const idx = []; // edges as index pairs first (cheaper to hash)
  let expected;
  if (family === 'chain') {
    for (let i = 0; i + 1 < n; i++) idx.push([i, i + 1]);
    expected = { sccCount: n, largestScc: 1, recursiveComponents: 0, edgeCount: n - 1 };
  } else if (family === 'ring') {
    for (let i = 0; i < n; i++) idx.push([i, (i + 1) % n]);
    expected = { sccCount: 1, largestScc: n, recursiveComponents: 1, edgeCount: n };
  } else if (family === 'fanin') {
    for (let i = 0; i < n - 1; i++) idx.push([i, n - 1]);
    expected = { sccCount: n, largestScc: 1, recursiveComponents: 0, edgeCount: n - 1 };
  } else if (family === 'fanout') {
    for (let i = 1; i < n; i++) idx.push([0, i]);
    expected = { sccCount: n, largestScc: 1, recursiveComponents: 0, edgeCount: n - 1 };
  } else {
    const s = SCC_BLOCK_SIZE;
    const k = Math.floor(n / s);
    if (k < 1) throw new Error(`scc-rich needs n >= ${s}`);
    const seen = new Set();
    const push = (a, b) => { const key = a * n + b; if (!seen.has(key)) { seen.add(key); idx.push([a, b]); } };
    for (let b = 0; b < k; b++) {
      const base = b * s;
      for (let j = 0; j < s; j++) push(base + j, base + ((j + 1) % s));
      for (let c = 0; c < s; c++) push(base + Math.floor(rnd() * s), base + Math.floor(rnd() * s));
      if (b + 1 < k) {
        const span = Math.min(3, k - b - 1);
        push(base + Math.floor(rnd() * s), (b + 1 + Math.floor(rnd() * span)) * s + Math.floor(rnd() * s));
      }
    }
    // Nodes beyond k*s (when s does not divide n) are singleton callees of block 0.
    for (let i = k * s; i < n; i++) push(0, i);
    const tail = n - k * s;
    expected = { sccCount: k + tail, largestScc: s, recursiveComponents: k, edgeCount: idx.length };
  }
  const h = crypto.createHash('sha256');
  h.update(`${family}:${n}:${seed}:`);
  const buf = Buffer.alloc(8);
  for (const [a, b] of idx) { buf.writeUInt32LE(a, 0); buf.writeUInt32LE(b, 4); h.update(buf); }
  const nodes = new Array(n);
  for (let i = 0; i < n; i++) nodes[i] = nodeName(i);
  const edges = idx.map(([a, b]) => [nodeName(a), nodeName(b)]);
  return { family, n, seed, nodes, edges, expected, digest: h.digest('hex') };
}
