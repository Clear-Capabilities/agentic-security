// DAG-05: dependency fingerprints for cross-scan incremental analysis.
//
// What a cached result may be reused for is decided here, from CONTENT:
//
//   * a per-function OWN fingerprint: the canonical body (node ids renamed, they
//     come from a process-global counter), the resolution of every name the body
//     calls or passes along (so a callee that appeared, vanished or moved changes
//     the caller even when the caller's text did not), the file-level facts the
//     engine shares between functions of one file, and the class hierarchy;
//   * a dependency graph over those functions: calls, callbacks, class-field
//     coupling between methods and the request-object seeding of one file;
//   * the strongly connected components of that graph (graph/scc.js), so a
//     function in a cycle is only ever reused together with its whole cycle;
//   * a CLOSURE fingerprint per component: its members' own fingerprints plus
//     the closure fingerprints of everything it depends on;
//   * GLOBAL components (analysis options, build and language configuration,
//     graph schema, catalog / sanitizer / analyzer content digests, stubs,
//     policies, boundary contracts). They are digests of CONTENT, never entry
//     counts: a sanitizer whose behaviour changed keeps the catalog size.
//
// `planIncremental` compares a prior persisted model with the current one and
// answers, per function, clean or dirty and why. A removed or renamed symbol is
// found through the PRIOR graph (persisted file-to-symbol mapping and prior
// callees), because the current IR no longer contains it.
//
// Everything here is pure except `globalComponents`, which reads build and
// policy files under the scan root and the analyzer sources next to this file.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeScc } from '../graph/scc.js';
import { CATALOG } from './catalog.js';
import { classOfVar } from '../ir/class-hierarchy.js';
import { isLanguageManifest, isExplicitExport, readExplicitExports } from '../language/discovery.js';
import { stateDir } from '../posture/state-dir.js';

export const DEP_GRAPH_SCHEMA = 'dep-graph/1';
const MODEL_VERSION = 1;
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ── stable serialisation ────────────────────────────────────────────────────

/**
 * Deterministic text for any value: object keys sorted, Map / Set / RegExp /
 * function handled, cycles marked. Returns null when the value is too deep to
 * serialise safely (the caller treats that as "cannot fingerprint").
 */
export function stableSerialize(value, maxDepth = 1500) {
  const seen = new WeakSet();
  const out = [];
  let tooDeep = false;
  const walk = (v, depth) => {
    if (tooDeep) return;
    if (depth > maxDepth) { tooDeep = true; return; }
    if (v === null) { out.push('null'); return; }
    switch (typeof v) {
      case 'undefined': out.push('undefined'); return;
      case 'number': out.push(Number.isFinite(v) ? String(v) : `"n:${v}"`); return;
      case 'boolean': out.push(v ? 'true' : 'false'); return;
      case 'bigint': out.push(`"b:${v}"`); return;
      case 'string': out.push(JSON.stringify(v)); return;
      case 'symbol': out.push(JSON.stringify(String(v))); return;
      case 'function': out.push(JSON.stringify(`fn:${Function.prototype.toString.call(v)}`)); return;
      default: break;
    }
    if (v instanceof RegExp) { out.push(JSON.stringify(`re:${v.source}/${v.flags}`)); return; }
    if (seen.has(v)) { out.push('"[cycle]"'); return; }
    seen.add(v);
    if (Array.isArray(v)) {
      out.push('[');
      for (let i = 0; i < v.length; i++) { if (i) out.push(','); walk(v[i], depth + 1); }
      out.push(']');
    } else if (v instanceof Set) {
      const parts = [...v].map((x) => stableSerialize(x, maxDepth - depth)).sort();
      out.push(`{"$set":[${parts.join(',')}]}`);
    } else if (v instanceof Map) {
      const parts = [...v].map(([k, x]) => `[${stableSerialize(k, maxDepth - depth)},${stableSerialize(x, maxDepth - depth)}]`).sort();
      out.push(`{"$map":[${parts.join(',')}]}`);
    } else {
      const keys = Object.keys(v).sort();
      out.push('{');
      let first = true;
      for (const k of keys) {
        if (v[k] === undefined) continue;
        if (!first) out.push(',');
        first = false;
        out.push(JSON.stringify(k), ':');
        walk(v[k], depth + 1);
      }
      out.push('}');
    }
    seen.delete(v);
  };
  try { walk(value, 0); } catch { return null; }
  if (tooDeep) return null;
  return out.join('');
}

// ── canonical function body ─────────────────────────────────────────────────

const ID_VALUE_KEYS = new Set(['id', 'entry', 'exit', 'site', 'node']);
const ID_ARRAY_KEYS = new Set(['succ', 'pred', 'returns']);

/**
 * Native JSON text with Map / Set / RegExp / function made representable. Key
 * order is the producer's own, which is deterministic for a given source and
 * analyzer version (the analyzer digest is a global component), so it is not
 * re-sorted: a reorder can only cause an unneeded invalidation, never a stale
 * reuse. Returns null when the value cannot be serialised (cycle, too deep).
 */
function fastSerialize(value, extra = null) {
  try {
    return JSON.stringify(value, function replacer(k, v) {
      if (v instanceof Set) return { $set: [...v] };
      if (v instanceof Map) return { $map: [...v] };
      if (v instanceof RegExp) return `re:${v.source}/${v.flags}`;
      if (typeof v === 'function') return `fn:${Function.prototype.toString.call(v)}`;
      return extra ? extra(k, v) : v;
    });
  } catch { return null; }
}

/**
 * The function as text with its CFG node ids renamed to their position. The IR
 * assigns ids from a process-global counter, so two builds of identical source
 * differ in ids; everything else (kinds, expressions, lines, spans) is kept
 * verbatim. Null when the function cannot be serialised.
 */
export function canonicalFunctionText(fn) {
  const nodes = (fn && fn.cfg && fn.cfg.nodes) || {};
  const ids = Object.keys(nodes);
  const rename = new Map(ids.map((id, i) => [id, `#${i}`]));
  const shell = {};
  for (const k of Object.keys(fn || {})) if (k !== 'cfg') shell[k] = fn[k];
  shell.cfg = fn && fn.cfg ? {
    entry: rename.get(fn.cfg.entry) ?? fn.cfg.entry,
    exit: rename.get(fn.cfg.exit) ?? fn.cfg.exit,
    nodes: ids.map((id) => nodes[id]),
  } : null;
  return fastSerialize(shell, (k, v) => {
    if (typeof v === 'string') return ID_VALUE_KEYS.has(k) && rename.has(v) ? rename.get(v) : v;
    if (Array.isArray(v) && ID_ARRAY_KEYS.has(k)) return v.map((x) => (typeof x === 'string' && rename.has(x) ? rename.get(x) : x));
    return v;
  });
}

// ── names a function resolves ───────────────────────────────────────────────

function flattenCallee(c) {
  if (typeof c === 'string') return c;
  if (!c || typeof c !== 'object') return null;
  // the Babel frontend spells `this` as `_this_`; the engine converts it before resolving (engine.js _flattenCalleeName)
  if (c.kind === 'ident') return c.name === '_this_' ? 'this' : (c.name || null);
  if (c.kind === 'member') {
    const o = flattenCallee(c.object);
    return o && c.prop ? `${o}.${c.prop}` : (c.prop || null);
  }
  return null;
}

const MAX_NAMES_PER_FN = 600;

/** Names a function calls, passes as a callback argument, or references by qid. */
function referencedNames(fn, functionsByQid) {
  const names = new Set();
  const qids = new Set();
  const visit = (v, depth) => {
    if (!v || typeof v !== 'object' || depth > 60) return;
    if (Array.isArray(v)) { for (const x of v) visit(x, depth + 1); return; }
    if (v.kind === 'call') {
      const nm = flattenCallee(v.callee);
      if (nm) names.add(nm);
      if (Array.isArray(v.args)) for (const a of v.args) if (a && a.kind === 'ident' && a.name) names.add(a.name);
    }
    for (const k of Object.keys(v)) {
      const x = v[k];
      if (typeof x === 'string') { if ((k === 'calleeQid' || k === 'qid') && functionsByQid.has(x)) qids.add(x); }
      else visit(x, depth + 1);
    }
  };
  const nodes = (fn.cfg && fn.cfg.nodes) || {};
  for (const id of Object.keys(nodes)) {
    const n = nodes[id];
    if (!n) continue;
    if (n.kind === 'call' && n.callee != null) {
      const nm = flattenCallee(n.callee);
      if (nm) names.add(nm);
    }
    visit(n, 0);
    if (names.size > MAX_NAMES_PER_FN) break;
  }
  for (const c of fn.calls || []) {
    const nm = typeof c === 'string' ? c : flattenCallee(c && c.callee);
    if (nm) names.add(nm);
  }
  return { names: [...names].sort().slice(0, MAX_NAMES_PER_FN), qids: [...qids].sort() };
}

// ── class hierarchy digest ──────────────────────────────────────────────────

function classHierarchyDigest(cha) {
  if (!cha || !cha.classes || !cha.classes.size) return 'no-classes';
  const classes = [...cha.classes.values()].map((c) => ({
    name: c.name, extends: c.extends || null,
    bases: [...(c.bases || [])].sort(),
    fields: [...(c.fields || [])].sort(),
    methods: [...(c.methods || [])].sort(),
  })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const live = cha.liveClasses ? [...cha.liveClasses].sort() : [];
  return sha(stableSerialize({ classes, live }) || 'unserialisable');
}

// ── file-level context the engine shares between functions of one file ──────

const REQ_PARAM = /^(?:req|request|ctx)$/;
// Languages whose IR for a file is built from that file's text alone (no include or module merging across files).
const PER_FILE_IR = /\.(?:m?js|cjs|jsx|tsx?|py|java|go|rs|cs|kt|rb)$/i;

function isRegexInit(src) {
  if (!src || typeof src !== 'object') return false;
  if (src.kind === 'literal' && src.isRegex) return true;
  return src.kind === 'call' && !!src.callee && src.callee.kind === 'ident' && src.callee.name === 'RegExp';
}

/** Per file: the provably-RegExp names and the functions that seed request fields (mirrors engine.js). */
function fileContexts(fns) {
  const byFile = new Map();
  for (const fn of fns) {
    if (!fn || !fn.file) continue;
    let rec = byFile.get(fn.file);
    if (!rec) { rec = { names: new Map(), seeders: [] }; byFile.set(fn.file, rec); }
    if (fn.cfg && fn.cfg.nodes) {
      for (const p of fn.params || []) if (typeof p === 'string') rec.names.set(p, false);
      for (const n of Object.values(fn.cfg.nodes)) {
        if (!n || n.kind !== 'assign' || typeof n.target !== 'string' || n.target.includes('.')) continue;
        const prev = rec.names.get(n.target);
        rec.names.set(n.target, (prev === undefined || prev === true) && isRegexInit(n.source));
      }
      if (Array.isArray(fn.params) && REQ_PARAM.test(fn.params[0] || '')) {
        const p0 = fn.params[0];
        for (const n of Object.values(fn.cfg.nodes)) {
          if (n && n.kind === 'assign' && typeof n.target === 'string' && n.target.startsWith(`${p0}.`)) { rec.seeders.push(fn.qid); break; }
        }
      }
    }
  }
  const out = new Map();
  for (const [file, rec] of byFile) {
    const regex = [...rec.names].filter(([, ok]) => ok).map(([n]) => n).sort();
    out.set(file, { regexDigest: sha(regex.join('|')), seeders: rec.seeders.slice().sort() });
  }
  return out;
}

// ── the dependency model ────────────────────────────────────────────────────

/**
 * name -> qid exactly as the engine resolves a call (`resolveKnownCallee`; the engine never
 * uses the guessing `resolve`), memoised per (file, name), with a pre-filter: a call can only
 * resolve to a function if the name, its last segment, its `this.`-stripped form or its
 * qualified-name spelling is something some function is called, or the file imports the head
 * of the name, or the project re-exports under that alias. Anything else cannot resolve, and the
 * O(files) global scan inside the resolver is skipped for it.
 */
function makeResolver(callGraph, fns, fileContents) {
  const memo = new Map();
  const exact = new Set();        // fn.name as written
  const tails = new Set();        // last segment of a dotted fn.name (bare-tail resolution)
  const classKeys = new Set();    // Class.method
  const qnameFiles = new Set();   // C/C++ files: qualified-name resolution applies
  for (const fn of fns) {
    if (fn.name) { exact.add(fn.name); if (fn.name.includes('.')) tails.add(fn.name.split('.').pop()); }
    if (fn.qname) qnameFiles.add(fn.file);
    const m = /::(\w+)::(\w+)@/.exec(fn.qid);
    if (m) classKeys.add(`${m[1]}.${m[2]}`);
  }
  // Names a re-export can make resolvable under a different spelling (`export { a as b } from`).
  const aliases = new Set();
  for (const src of Object.values(fileContents || {})) {
    if (typeof src !== 'string' || !src.includes(' from ')) continue;
    for (const m of src.matchAll(/export\s*\{\s*([^}]+)\s*\}\s*from\s*['"][^'"]+['"]/g)) {
      for (const part of m[1].split(',')) { const [orig, alias] = part.trim().split(/\s+as\s+/); aliases.add((alias || orig || '').trim()); }
    }
  }
  const mi = callGraph && callGraph.moduleIndex;
  const real = (name, file) => { try { return callGraph.resolveKnownCallee ? (callGraph.resolveKnownCallee(name, file) || null) : null; } catch { return null; } };
  return (name, file) => {
    const k = `${file}\0${name}`;
    let r = memo.get(k);
    if (r !== undefined) return r;
    let viaImport = false;
    if (mi && typeof mi.resolveCall === 'function' && file) {
      try { const imp = mi.resolveCall(file, name); viaImport = !!(imp && (imp.status === 'resolved' || imp.status === 'external')); } catch { viaImport = true; }
    }
    const bare = name.startsWith('this.') ? name.slice(5) : null;
    const possible = viaImport || aliases.has(name) || qnameFiles.has(file) || exact.has(name) || classKeys.has(name)
      || (!name.includes('.') && tails.has(name))
      || (bare !== null && (exact.has(bare) || tails.has(bare)));
    r = possible ? real(name, file) : null;
    memo.set(k, r);
    return r;
  };
}

/**
 * Build the dependency model for one scan.
 *
 *   functions[qid] = { file, name, own, closure, scc, callees:[qid], unfingerprintable? }
 *   fileSymbols[file] = [qid]
 *   sccs[sccId] = [qid]            (recursive or coupled components only)
 */
export function buildDependencyModel({ perFileIR, callGraph, cha, fileContents, reuse = null }) {
  const fnMap = (callGraph && callGraph.functions) || new Map();
  const fns = [...fnMap.values()].filter((f) => f && f.qid);
  const phase = {}; let _t = Date.now();
  const lap = (name) => { const n = Date.now(); phase[name] = n - _t; _t = n; };
  const chaDigest = classHierarchyDigest(cha);
  lap('cha-digest');
  const hasClasses = chaDigest !== 'no-classes';
  const ctxByFile = fileContexts(fns);
  lap('file-contexts');
  const resolveKnown = makeResolver(callGraph, fns, fileContents);

  const methodOwner = (cha && cha.methodOwners) || new Map();
  // Classes related to `cls` by inheritance (itself, ancestors, descendants): the candidates the engine's
  // class-hierarchy and instantiated-class dispatch can pick a method from for a receiver typed `cls`.
  const children = new Map();
  if (hasClasses) {
    for (const c of cha.classes.values()) {
      for (const b of new Set([c.extends, ...(c.bases || [])].filter(Boolean))) {
        if (!children.has(b)) children.set(b, []);
        children.get(b).push(c.name);
      }
    }
  }
  const relatedMemo = new Map();
  const related = (cls) => {
    let r = relatedMemo.get(cls);
    if (r) return r;
    r = new Set([cls]);
    const stack = [cls];
    while (stack.length) {
      const c = stack.pop();
      const info = cha.classes.get(c);
      for (const b of new Set([info && info.extends, ...((info && info.bases) || [])].filter(Boolean))) if (!r.has(b)) { r.add(b); stack.push(b); }
      for (const d of children.get(c) || []) if (!r.has(d)) { r.add(d); stack.push(d); }
    }
    relatedMemo.set(cls, r);
    return r;
  };
  const methodsOfClass = new Map();
  for (const [qid, cls] of methodOwner) {
    if (!methodsOfClass.has(cls)) methodsOfClass.set(cls, []);
    methodsOfClass.get(cls).push(qid);
  }

  lap('indexes');
  const ownInfo = new Map();
  const edges = new Map(); // caller -> Set(callee)
  const addEdge = (a, b) => { if (a === b) return; let s = edges.get(a); if (!s) { s = new Set(); edges.set(a, s); } s.add(b); };

  // A function of an unchanged file, in a language whose IR is built from that one file alone, has
  // the body digest and name list it had last time (same analyzer, same source): they are carried
  // forward instead of re-serialising its IR. Resolution is never carried, it depends on other files.
  const bodyOf = new Map();
  const carried = (fn) => {
    if (!reuse || !PER_FILE_IR.test(fn.file)) return null;
    if (!reuse.priorFiles || reuse.priorFiles[fn.file] === undefined || reuse.priorFiles[fn.file] !== reuse.curFiles[fn.file]) return null;
    const p = reuse.functions && reuse.functions[fn.qid];
    return p && typeof p.body === 'string' && p.refs ? p : null;
  };
  for (const fn of fns) {
    const prev = carried(fn);
    let canon; let refs; let body;
    if (prev) { body = prev.body; refs = prev.refs; canon = body; }
    else {
      canon = canonicalFunctionText(fn);
      body = canon === null ? null : sha(canon);
      refs = referencedNames(fn, fnMap);
    }
    bodyOf.set(fn.qid, { body, refs });
    const res = [];
    for (const name of refs.names) {
      const known = resolveKnown(name, fn.file);
      res.push([name, known]);
      if (known) addEdge(fn.qid, known);
      // A member call the engine resolves through the class hierarchy: `recv.method` where recv is a bare local
      // whose class the hierarchy knows (engine.js _resolveMemberCalleeViaCHA). The candidates are the methods of
      // every related class (inheritance and instantiated-class dispatch); nothing else can be picked.
      if (hasClasses) {
        const dot = name.indexOf('.');
        if (dot > 0 && name.indexOf('.', dot + 1) === -1) {
          const recv = name.slice(0, dot); const method = name.slice(dot + 1);
          if (recv !== 'this' && recv !== '_this_') {
            let cls = null;
            try { cls = classOfVar(cha, fn.file, fn.qid, recv); } catch { cls = null; }
            if (cls) for (const c of related(cls)) {
              const info = cha.classes.get(c);
              if (info && info.methods && info.methods.has(method)) { const q = resolveKnown(`${c}.${method}`, fn.file); if (q) addEdge(fn.qid, q); }
            }
          }
        }
      }
    }
    for (const q of refs.qids) addEdge(fn.qid, q);
    const ctx = ctxByFile.get(fn.file);
    // Request-object seeding: every request-taking function of a file reads what
    // the file's seeding functions leave tainted.
    if (ctx && ctx.seeders.length && Array.isArray(fn.params) && REQ_PARAM.test(fn.params[0] || '')) {
      for (const s of ctx.seeders) addEdge(fn.qid, s);
    }
    ownInfo.set(fn.qid, { canon: body === null ? null : canon, body, res, ctx });
  }

  lap('names-and-resolution');
  // Class-field coupling (engine.js class-field and cross-class passes): a method
  // reads what its sibling methods leave tainted, and the seeds it gets depend on
  // who calls it. Same-class methods are mutually dependent; a method also depends
  // on its callers; a function whose file text names a class with declared fields
  // depends on that class's methods.
  // Only a class with DECLARED fields can take part (the engine's class-field passes start from
  // `cha.classes[c].fields`), so a class without any couples nothing.
  const fieldClassNames = new Set();
  if (hasClasses) for (const [name, c] of cha.classes) if (c.fields && c.fields.size) fieldClassNames.add(name);
  if (fieldClassNames.size) {
    for (const [cls, qids] of methodsOfClass) {
      if (!fieldClassNames.has(cls) || qids.length < 2) continue;
      for (const a of qids) for (const b of qids) addEdge(a, b);
    }
    const callersOf = new Map();
    for (const [a, set] of edges) for (const b of set) { if (!callersOf.has(b)) callersOf.set(b, new Set()); callersOf.get(b).add(a); }
    for (const [qid, cls] of methodOwner) {
      if (!fieldClassNames.has(cls)) continue;
      for (const c of callersOf.get(qid) || []) addEdge(qid, c);
    }
    if (fileContents) {
      const fnsByFile = new Map();
      for (const fn of fns) { if (!fnsByFile.has(fn.file)) fnsByFile.set(fn.file, []); fnsByFile.get(fn.file).push(fn.qid); }
      for (const [file, qids] of fnsByFile) {
        const src = fileContents[file];
        if (typeof src !== 'string') continue;
        for (const cname of fieldClassNames) {
          if (!src.includes(`${cname}.`)) continue;
          for (const m of methodsOfClass.get(cname) || []) for (const q of qids) { addEdge(q, m); addEdge(m, q); }
        }
      }
    }
  }
  lap('class-coupling');
  // Own fingerprints (after edges: nothing below feeds back into them).
  const own = new Map();
  const unfingerprintable = new Set();
  for (const fn of fns) {
    const info = ownInfo.get(fn.qid);
    if (info.canon === null) { unfingerprintable.add(fn.qid); own.set(fn.qid, `unfingerprintable:${fn.qid}`); continue; }
    const body = info.body;
    own.set(fn.qid, sha(stableSerialize({
      v: MODEL_VERSION, qid: fn.qid, body, res: info.res,
      regex: info.ctx ? info.ctx.regexDigest : null,
      cha: hasClasses ? chaDigest : null,
    })));
  }

  lap('own-fingerprints');
  // SCCs over callee -> caller, so `order` lists dependencies first.
  const nodes = fns.map((f) => f.qid);
  const sccEdges = [];
  for (const [a, set] of edges) for (const b of set) if (fnMap.has(b)) sccEdges.push([b, a]);
  const scc = computeScc({ nodes, edges: sccEdges });
  const closureOfComp = new Map();
  for (const cid of scc.order) {
    const comp = scc.components[cid];
    const memberOwn = comp.members.map((q) => `${q}=${own.get(q)}`).sort();
    const dep = new Set();
    for (const m of comp.members) for (const b of edges.get(m) || []) {
      if (!fnMap.has(b)) continue;
      const bc = scc.componentOf.get(b);
      if (bc !== cid) dep.add(closureOfComp.get(bc));
    }
    closureOfComp.set(cid, sha(stableSerialize({ own: memberOwn, deps: [...dep].sort() })));
  }

  lap('scc-and-closure');
  const functions = {};
  const fileSymbols = {};
  const sccs = {};
  const sccKeyOf = new Map();
  for (const fn of fns) {
    const cid = scc.componentOf.get(fn.qid);
    const comp = scc.components[cid];
    let sccKey = null;
    if (comp.members.length > 1) {
      sccKey = sccKeyOf.get(cid);
      if (!sccKey) { sccKey = sha(comp.members.join('\n')).slice(0, 16); sccKeyOf.set(cid, sccKey); sccs[sccKey] = comp.members.slice(); }
    }
    functions[fn.qid] = {
      file: fn.file, name: fn.name || null,
      own: own.get(fn.qid), closure: closureOfComp.get(cid), scc: sccKey,
      body: bodyOf.get(fn.qid).body, refs: bodyOf.get(fn.qid).refs,
      callees: [...(edges.get(fn.qid) || [])].filter((b) => fnMap.has(b)).sort(),
      ...(unfingerprintable.has(fn.qid) ? { unfingerprintable: true } : {}),
    };
    (fileSymbols[fn.file] ||= []).push(fn.qid);
  }
  for (const f of Object.keys(fileSymbols)) fileSymbols[f].sort();
  lap('assemble');
  return {
    schema: DEP_GRAPH_SCHEMA, modelVersion: MODEL_VERSION, chaDigest,
    functions, fileSymbols, sccs,
    stats: { functions: fns.length, edges: sccEdges.length, components: scc.components.length, coupled: Object.keys(sccs).length, phaseMs: phase },
  };
}

// ── global components ───────────────────────────────────────────────────────

const VOLATILE_ENV = /^AGENTIC_SECURITY_(?:INCREMENTAL(?:_.*)?|HMAC_KEY|DEBUG|NO_GATE_WARM|NO_PRECOMMIT|GATE_.*|NO_STATE|DEEP_TIMEOUT_MS|RESUME|NO_COLOR|QUIET|PROGRESS.*|LLM_.*|OFFLINE|HOME|TMPDIR)$/;

function analyzerRoots() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const src = path.resolve(here, '..');
  return { here, src, isSource: path.basename(here) === 'dataflow' && fs.existsSync(path.join(src, 'ir')) };
}

let _analyzerMemo = null;
/** Digest of the analyzer and parser sources (or the bundle when running from one). */
function analyzerDigest() {
  if (_analyzerMemo) return _analyzerMemo;
  const { here, src, isSource } = analyzerRoots();
  const h = crypto.createHash('sha256');
  try {
    if (isSource) {
      for (const dir of ['dataflow', 'ir', 'graph', 'language']) {
        const d = path.join(src, dir);
        let names = [];
        try { names = fs.readdirSync(d).filter((n) => /\.(?:m?js|py)$/.test(n)).sort(); } catch { /* absent */ }
        for (const n of names) { h.update(`${dir}/${n}\0`); h.update(fs.readFileSync(path.join(d, n))); h.update('\n'); }
      }
    } else {
      const self = fileURLToPath(import.meta.url);
      h.update(path.basename(self)); h.update(fs.readFileSync(self));
    }
  } catch { h.update(`unreadable:${here}`); }
  _analyzerMemo = h.digest('hex');
  return _analyzerMemo;
}

function readIf(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }

const BUILD_FILE = /^(?:package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|tsconfig[\w.-]*\.json|jsconfig\.json|pyproject\.toml|setup\.cfg|setup\.py|requirements[\w.-]*\.txt|pom\.xml|build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|composer\.json|Gemfile(?:\.lock)?|[\w.-]+\.csproj|[\w.-]+\.cabal|cabal\.project[\w.]*|stack\.yaml(?:\.lock)?|package\.yaml|hie\.yaml|flake\.(?:nix|lock)|default\.nix|shell\.nix|configuration\.nix|CMakeLists\.txt|Makefile)$/;
const STATE_POLICY = /^(?:rules|policy|policies|stubs?|boundar(?:y|ies)[\w-]*|sanitizers?[\w-]*|assurance)\.(?:ya?ml|json)$/;

/**
 * The global inputs, one digest each, so a mismatch can say WHICH one moved.
 * Every digest is over content.
 */
export function globalComponents({ scanRoot, fileContents, opts = {}, env = process.env, stubsProvider = null }) {
  const comp = {};
  // options: the semantically relevant environment plus engine options.
  const envEntries = Object.keys(env).filter((k) => /^AGENTIC_SECURITY_/.test(k) && !VOLATILE_ENV.test(k)).sort().map((k) => [k, env[k]]);
  comp.options = sha(stableSerialize({ env: envEntries, fnLimit: opts.fnLimit ?? null }));
  // build / language configuration: manifests found at the root, in the scanned set, and explicit exports.
  const build = {};
  if (scanRoot) {
    let names = [];
    try { names = fs.readdirSync(scanRoot); } catch { names = []; }
    for (const n of names) if (BUILD_FILE.test(n)) { const t = readIf(path.join(scanRoot, n)); if (t !== null) build[n] = sha(t); }
  }
  const manifestRels = [];
  for (const k of Object.keys(fileContents || {})) {
    const rel = k.replace(/\\/g, '/');
    if (isLanguageManifest(rel) || isExplicitExport(rel) || BUILD_FILE.test(path.posix.basename(rel))) {
      build[rel] = sha(String(fileContents[k] ?? ''));
      if (isLanguageManifest(rel)) manifestRels.push(rel);
    }
  }
  if (scanRoot) {
    try {
      const { contents } = readExplicitExports(scanRoot, manifestRels);
      for (const [rel, text] of Object.entries(contents)) build[rel] = sha(text);
    } catch { /* unreadable export: absent from the digest, which differs from present */ }
  }
  comp.build = sha(stableSerialize(build));
  comp.graphSchema = sha(`${DEP_GRAPH_SCHEMA}/${MODEL_VERSION}`);
  // rule / model content, not counts.
  comp.catalog = sha(fastSerialize(CATALOG.filter((e) => e && e.kind !== 'sanitizer')) || 'unserialisable');
  comp.sanitizers = sha(fastSerialize(CATALOG.filter((e) => e && e.kind === 'sanitizer')) || 'unserialisable');
  comp.analyzers = analyzerDigest();
  // stubs
  let stubs = 'off';
  if (env.AGENTIC_SECURITY_TYPE_STUBS === '1') {
    try { stubs = sha(stableSerialize(stubsProvider ? stubsProvider(scanRoot) : null) || 'unserialisable'); } catch { stubs = 'unreadable'; }
  }
  comp.stubs = stubs;
  // policies and boundary contracts under the state directory (operator-authored inputs).
  const policy = {}; const boundary = {};
  if (scanRoot) {
    let names = [];
    const stateRoot = stateDir(scanRoot);
    try { names = fs.readdirSync(stateRoot); } catch { names = []; }
    for (const n of names.sort()) {
      if (!STATE_POLICY.test(n)) continue;
      const t = readIf(path.join(stateRoot, n));
      if (t === null) continue;
      (/^boundar/.test(n) ? boundary : policy)[n] = sha(t);
    }
  }
  comp.policies = sha(stableSerialize(policy));
  comp.boundary = sha(stableSerialize(boundary));
  return comp;
}

function digestOfComponents(comp) {
  return sha(stableSerialize(Object.fromEntries(Object.entries(comp).sort())));
}

/** Names of the components that differ (both directions). */
export function diffComponents(prior, current) {
  const names = new Set([...Object.keys(prior || {}), ...Object.keys(current || {})]);
  return [...names].filter((n) => (prior || {})[n] !== (current || {})[n]).sort();
}

// ── the plan ────────────────────────────────────────────────────────────────

/**
 * Compare a prior persisted model with the current one.
 * `prior` is { global, deps (model), hasRecord(qid) }, `current` is { global, model }.
 * Returns { mode, reason?, changedComponents?, clean:Set, dirty:Map(qid->reason), removed:[...], ... }.
 */
export function planIncremental(prior, current) {
  const changedComponents = diffComponents(prior.global, current.global);
  if (changedComponents.length) {
    return { mode: 'cold', reason: `global input changed: ${changedComponents.join(', ')}`, changedComponents, clean: new Set(), dirty: new Map(), removed: [], renamed: [] };
  }
  const pf = prior.deps.functions || {};
  const cf = current.model.functions;
  const dirty = new Map();
  const mark = (q, r) => { if (!dirty.has(q)) dirty.set(q, r); };

  // direct changes
  for (const [q, f] of Object.entries(cf)) {
    const p = pf[q];
    if (!p) mark(q, 'new');
    else if (f.unfingerprintable || p.unfingerprintable) mark(q, 'unfingerprintable');
    else if (p.own !== f.own) mark(q, 'changed-body-or-resolution');
  }
  // removals and renames: found through the PRIOR graph, the current IR has no trace of them
  const removed = Object.keys(pf).filter((q) => !(q in cf)).sort();
  const priorCallers = new Map();
  for (const [q, p] of Object.entries(pf)) for (const c of p.callees || []) { if (!priorCallers.has(c)) priorCallers.set(c, []); priorCallers.get(c).push(q); }
  const currentFileSet = new Set(Object.keys(current.model.fileSymbols));
  const renamed = [];
  for (const q of removed) {
    const p = pf[q];
    if (p && currentFileSet.has(p.file)) renamed.push({ qid: q, file: p.file, name: p.name }); // file still exists: moved, renamed or deleted inside it
    for (const caller of priorCallers.get(q) || []) if (caller in cf) mark(caller, 'callee-removed-or-renamed');
  }
  // current callers (reverse of the current edges) for the closure
  const currentCallers = new Map();
  for (const [q, f] of Object.entries(cf)) for (const c of f.callees) { if (!currentCallers.has(c)) currentCallers.set(c, []); currentCallers.get(c).push(q); }
  const seeds = [...dirty.keys()];
  const stack = seeds.slice();
  while (stack.length) {
    const q = stack.pop();
    for (const caller of currentCallers.get(q) || []) {
      if (!dirty.has(caller)) { dirty.set(caller, 'depends-on-changed'); stack.push(caller); }
    }
    for (const caller of priorCallers.get(q) || []) {
      if (caller in cf && !dirty.has(caller)) { dirty.set(caller, 'depends-on-changed'); stack.push(caller); }
    }
  }
  // whole SCCs: current coupled components, and the prior component of anything dirty
  const priorScc = new Map();
  for (const [key, members] of Object.entries(prior.deps.sccs || {})) priorScc.set(key, members);
  const curScc = current.model.sccs || {};
  let widened = 0;
  let again = true;
  while (again) {
    again = false;
    for (const q of [...dirty.keys()]) {
      const f = cf[q]; const p = pf[q];
      const groups = [];
      if (f && f.scc && curScc[f.scc]) groups.push(curScc[f.scc]);
      if (p && p.scc && priorScc.has(p.scc)) groups.push(priorScc.get(p.scc));
      for (const g of groups) for (const m of g) if (m in cf && !dirty.has(m)) { dirty.set(m, 'scc-member'); widened++; again = true; }
    }
    if (again) {
      // newly dirty members have callers too
      const st = [...dirty.keys()];
      while (st.length) {
        const q = st.pop();
        for (const caller of currentCallers.get(q) || []) if (!dirty.has(caller)) { dirty.set(caller, 'depends-on-changed'); st.push(caller); }
      }
    }
  }
  // belt and braces: the closure fingerprint must agree with the explicit walk
  for (const [q, f] of Object.entries(cf)) {
    const p = pf[q];
    if (p && !dirty.has(q) && p.closure !== f.closure) dirty.set(q, 'closure-fingerprint');
  }
  const clean = new Set();
  for (const q of Object.keys(cf)) {
    if (dirty.has(q)) continue;
    if (!prior.hasRecord(q)) { dirty.set(q, 'no-cached-record'); continue; }
    clean.add(q);
  }
  // files that held symbols last time and are gone (their symbols are in `removed`)
  const removedFiles = Object.keys(prior.deps.fileSymbols || {}).filter((f) => !(f in current.model.fileSymbols)).sort();
  return { mode: 'warm', clean, dirty, removed, removedFiles, renamed, widened, changedComponents: [] };
}

export function countByReason(dirty) {
  const o = {};
  for (const r of dirty.values()) o[r] = (o[r] || 0) + 1;
  return Object.fromEntries(Object.entries(o).sort());
}
