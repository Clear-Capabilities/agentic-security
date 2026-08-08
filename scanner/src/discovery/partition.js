//
// Split the codebase into disjoint focus areas so parallel hunters cannot
// converge on the same code.
//
// WHY THE CALL GRAPH AND NOT DIRECTORIES: a directory split hands one
// subsystem to several hunters whenever a feature spans folders, and hands
// unrelated code to one hunter whenever a folder is a grab bag. Weakly-
// connected components over call edges group code that actually talks to
// itself, which is the unit a hunter can reason about end to end.
//
// FILES, NOT FUNCTIONS, ARE THE ATOM. A hunter reads whole files. If two
// components share a file they are merged, otherwise the same source lands in
// two hunters' context and the convergence this module exists to prevent
// comes straight back.
import * as crypto from 'node:crypto';

export function focusAreaId(files) {
  const canon = [...new Set(files || [])].sort().join('\n');
  return crypto.createHash('sha256').update(canon).digest('hex').slice(0, 12);
}

// Union-find over file paths.
function makeDSU() {
  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r);
    while (parent.get(x) !== r) { const n = parent.get(x); parent.set(x, r); x = n; }
    return r;
  };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra, rb); };
  return { find, union };
}

function labelFor(files) {
  if (files.length === 1) return files[0];
  const parts = files[0].split('/');
  for (let i = parts.length - 1; i > 0; i--) {
    const prefix = parts.slice(0, i).join('/') + '/';
    if (files.every(f => f.startsWith(prefix))) return prefix;
  }
  return files[0] + ` (+${files.length - 1})`;
}

export function partitionCallGraph(callGraph, opts = {}) {
  const fns = callGraph?.functions;
  if (!fns || typeof fns.get !== 'function' || fns.size === 0) return [];
  const maxAreas = Number.isInteger(opts.maxAreas) && opts.maxAreas > 0 ? opts.maxAreas : 8;

  const dsu = makeDSU();
  for (const fn of fns.values()) if (fn?.file) dsu.find(fn.file);
  for (const e of callGraph.edges || []) {
    const a = fns.get(e?.caller)?.file;
    const b = fns.get(e?.callee)?.file;
    if (a && b) dsu.union(a, b);
  }

  const filesByRoot = new Map();
  for (const fn of fns.values()) {
    if (!fn?.file) continue;
    const root = dsu.find(fn.file);
    if (!filesByRoot.has(root)) filesByRoot.set(root, new Set());
    filesByRoot.get(root).add(fn.file);
  }

  const fnsByFile = new Map();
  for (const fn of fns.values()) {
    if (!fn?.file) continue;
    if (!fnsByFile.has(fn.file)) fnsByFile.set(fn.file, []);
    fnsByFile.get(fn.file).push(fn.qid);
  }

  const build = (files, label) => {
    const sorted = [...files].sort();
    const functions = sorted.flatMap(f => (fnsByFile.get(f) || [])).sort();
    return { id: focusAreaId(sorted), label: label ?? labelFor(sorted), files: sorted, functions, size: functions.length };
  };

  let areas = [...filesByRoot.values()].map(s => build(s));
  // Deterministic ranking: biggest first, ties broken by id so two runs on the
  // same graph produce the same order.
  areas.sort((a, b) => b.size - a.size || (a.id < b.id ? -1 : 1));

  if (areas.length > maxAreas) {
    const kept = areas.slice(0, maxAreas - 1);
    const tail = areas.slice(maxAreas - 1);
    kept.push(build(tail.flatMap(a => a.files), 'misc'));
    areas = kept;
  }
  return areas;
}
