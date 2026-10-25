//
// value-versions.js: SSA-like definition identities for the lineage engine
// (DAG-03, R03.3).
//
// A reaching-definitions pass over one function's CFG that answers: "which
// definitions of this state path can reach the entry of this CFG node?" The
// answer is a SET, so a merge keeps both alternatives (a phi) instead of
// pretending they co-occur or picking one, and a later strong write kills the
// earlier definition of that path and everything under it, whether or not
// the written value carried any identity (a clean literal is still a kill).
//
// Definition ids are the CFG node ids of the writing `assign`, plus the
// reserved id 'entry' for a value that was live on function entry (a
// parameter, a seeded source, anything no assignment has overwritten).
//
// The pass is purely structural. It does not read or change the field
// identity state, so it cannot alter an analysis result; it only labels the
// provenance halves the engine emits when correlation version 2 is on.
//
export const ENTRY_VERSION = 'entry';

function nodeEntries(nodes) {
  if (nodes instanceof Map) return [...nodes.entries()];
  return Object.entries(nodes ?? {});
}

function pathHasWildcard(path) {
  return path.split('.').includes('*');
}

function definitePrefix(path) {
  const segs = path.split('.');
  const idx = segs.indexOf('*');
  if (idx <= 0) return null;
  return segs.slice(0, idx).join('.');
}

/** The definitions recorded for the longest self-or-ancestor key of `path` in `st`, or {entry}. */
function lookup(st, path) {
  let p = path;
  for (;;) {
    const hit = st.get(p);
    if (hit) return hit;
    const i = p.lastIndexOf('.');
    if (i === -1) return null;
    p = p.slice(0, i);
  }
}

function join(a, b) {
  const out = new Map();
  const keys = new Set([...a.keys(), ...b.keys()]);
  for (const k of keys) {
    const sa = a.get(k) ?? lookup(a, k) ?? new Set([ENTRY_VERSION]);
    const sb = b.get(k) ?? lookup(b, k) ?? new Set([ENTRY_VERSION]);
    out.set(k, new Set([...sa, ...sb]));
  }
  return out;
}

function equal(a, b) {
  if (a.size !== b.size) return false;
  for (const [k, sa] of a) {
    const sb = b.get(k);
    if (!sb || sb.size !== sa.size) return false;
    for (const d of sa) if (!sb.has(d)) return false;
  }
  return true;
}

function transfer(nid, node, st) {
  if (node.kind !== 'assign' || typeof node.target !== 'string') return st;
  const out = new Map(st);
  if (pathHasWildcard(node.target)) {
    // A computed-key write is a WEAK update: it adds a definition to the
    // container and kills nothing.
    const container = definitePrefix(node.target);
    if (container) {
      const prior = out.get(container) ?? lookup(st, container) ?? new Set([ENTRY_VERSION]);
      out.set(container, new Set([...prior, nid]));
    }
    return out;
  }
  const t = node.target;
  for (const k of [...out.keys()]) {
    if (k === t || k.startsWith(`${t}.`)) out.delete(k);
  }
  out.set(t, new Set([nid]));
  return out;
}

/**
 * @param {{cfg:{entry:string, nodes:Map|object}, params?:string[]}} fn
 * @returns {{versionsAt:(nodeId:string, path:string)=>string[]}}
 */
export function computeReachingDefinitions(fn) {
  const nodes = new Map(nodeEntries(fn.cfg?.nodes));
  const inStates = new Map();
  const entry = new Map();
  for (const p of fn.params ?? []) entry.set(p, new Set([ENTRY_VERSION]));
  inStates.set(fn.cfg.entry, entry);
  const work = [fn.cfg.entry];
  const outStates = new Map();
  let guard = 0;
  const cap = Math.max(10000, nodes.size * 64);
  while (work.length && guard++ < cap) {
    const nid = work.shift();
    const node = nodes.get(nid);
    if (!node) continue;
    const out = transfer(nid, node, inStates.get(nid) ?? new Map());
    const prev = outStates.get(nid);
    if (prev && equal(prev, out)) continue;
    outStates.set(nid, out);
    for (const s of node.succ ?? []) {
      const pi = inStates.get(s);
      const ni = pi ? join(pi, out) : out;
      if (!pi || !equal(pi, ni)) {
        inStates.set(s, ni);
        work.push(s);
      }
    }
  }
  return {
    versionsAt(nodeId, path) {
      const st = inStates.get(nodeId);
      const hit = st ? lookup(st, path) : null;
      return hit ? [...hit].sort() : [ENTRY_VERSION];
    },
  };
}
