// Functional semantic IR and call graph for Haskell (HS-002).
//
// Lowers the expression AST from haskell-syntax.js into the EXISTING dataflow IR
// contract (src/ir/CLAUDE.md): `{file, functions[{qid, name, line, params, file,
// cfg, calls}], topLevel}`. No node or expression kind is added, so every IR
// consumer (SSA, path feasibility, the taint engine, buildCallGraph) keeps
// working unchanged. Haskell specifics ride in an optional `hs` side object on
// functions, nodes and call expressions.
//
// Semantics that cannot be faked with mutable assignments:
//   * Immutable, lazy bindings. A `let`/`where` binding that is never referenced
//     produces NO executed node (it is recorded under `fn.hs.deferred`). One that
//     is demanded only conditionally keeps its flow but is marked
//     `demand: 'potential'` with `uncertainty: 'potentially-demanded'`.
//   * Effects. IO actions are executed where they are sequenced (do statements),
//     not where they are bound. `hs.effect` is `io` / `pure` / `unknown`.
//   * Partial application and composition are values, not calls.
//   * `$`, `.`, `&`, `>>=`, `=<<`, `fmap`, `<$>`, `<*>` normalise to ordinary
//     applications; map/traverse/mapM_/forM_/foldr/filter/sequence are bounded
//     summaries over an element placeholder.
//
// Honest boundaries: no type checking and no typeclass resolution beyond the
// instances visible in the analysed files. An unresolved target is recorded as
// `status: 'unknown'` and is NEVER treated as unreachable (see `reachability`).

import { createHash } from 'node:crypto';
import { parseSyntax, groupDecls, patternVars } from './haskell-syntax.js';
import { preprocessForSyntax } from './haskell-parser.js';
import { deriveCppContext } from './haskell-cpp.js';
import { isKnownApi, isSourceApi, qualifyAmbiguous } from './haskell-models.js';

export const HS_IR_LIMITS = Object.freeze({
  maxExprDepth: 200,
  maxResolveDepth: 16,
  maxFunctionsPerFile: 5000,
  maxSummaryIterations: 64,
});

const PRELUDE = new Set(['map', 'fmap', 'filter', 'foldr', 'foldl', 'mapM', 'mapM_', 'sequence', 'sequence_', 'concatMap', 'return', 'pure', 'lookup', 'putStrLn', 'putStr', 'print', 'getLine', 'getContents', 'readFile', 'writeFile', 'appendFile', 'interact', 'show', 'read', 'id', 'const', 'flip', 'length', 'head', 'tail', 'null', 'not', 'fst', 'snd', 'otherwise', 'div', 'mod', 'elem', 'concat', 'zip', 'unwords', 'words', 'lines', 'unlines', 'reverse', 'take', 'drop', 'error', 'maybe', 'either', 'traverse', 'sequenceA', 'readLn', 'sum', 'product', 'and', 'or', 'any', 'all', 'replicate', 'lookup', 'curry', 'uncurry', 'seq']);

const IO_NAMES = new Set(['putStr', 'putStrLn', 'print', 'getLine', 'getContents', 'readFile', 'writeFile', 'appendFile', 'readLn', 'interact', 'callCommand', 'callProcess', 'system', 'rawSystem', 'readProcess', 'readProcessWithExitCode', 'readCreateProcess', 'createProcess', 'spawnCommand', 'spawnProcess', 'getArgs', 'getEnv', 'lookupEnv', 'hPutStrLn', 'hPutStr', 'hGetLine', 'hGetContents', 'execute', 'execute_', 'query', 'query_', 'httpLBS', 'httpBS', 'unsafePerformIO']);

// name -> positions of the function, the collection and (folds) the seed.
const BODY_SETTER = /^Network\.HTTP\.(?:Simple|Conduit|Client)\.setRequestBody(?:JSON|LBS|BS|URLEncoded|File)$/;
const HOF = {
  map: { fn: 0, coll: 1, kind: 'map' }, fmap: { fn: 0, coll: 1, kind: 'map' }, concatMap: { fn: 0, coll: 1, kind: 'map' },
  traverse: { fn: 0, coll: 1, kind: 'traverse' }, mapM: { fn: 0, coll: 1, kind: 'traverse' },
  forM: { fn: 1, coll: 0, kind: 'traverse' }, for: { fn: 1, coll: 0, kind: 'traverse' },
  traverse_: { fn: 0, coll: 1, kind: 'traverse_' }, mapM_: { fn: 0, coll: 1, kind: 'traverse_' },
  forM_: { fn: 1, coll: 0, kind: 'traverse_' }, for_: { fn: 1, coll: 0, kind: 'traverse_' },
  filter: { fn: 0, coll: 1, kind: 'filter' },
  foldr: { fn: 0, seed: 1, coll: 2, kind: 'fold' }, foldl: { fn: 0, seed: 1, coll: 2, kind: 'fold' }, "foldl'": { fn: 0, seed: 1, coll: 2, kind: 'fold' },
  sequence: { coll: 0, kind: 'sequence' }, sequenceA: { coll: 0, kind: 'sequence' }, sequence_: { coll: 0, kind: 'sequence' },
};

const ARITH = new Set(['+', '-', '*', '/', '^', '**', '==', '/=', '<', '<=', '>', '>=', '!!', '%']);

const unknownExpr = (hs) => (hs ? { kind: 'unknown', hs } : { kind: 'unknown' });
const mkUnion = (a, b) => (!a ? b : !b ? a : { kind: 'union', branches: [a, b] });

// ── signatures ───────────────────────────────────────────────────────────────
function sigInfo(tokens, sig) {
  let depth = 0;
  let arity = 0;
  let resStart = sig.ta;
  for (let i = sig.ta; i < sig.tb; i++) {
    const t = tokens[i];
    if (t.t === 'sp') {
      if (t.v === '(' || t.v === '[' || t.v === '{') depth++;
      else if (t.v === ')' || t.v === ']' || t.v === '}') depth--;
    } else if (depth === 0 && t.t === 'rop' && t.v === '->') { arity++; resStart = i + 1; }
    else if (depth === 0 && t.t === 'rop' && t.v === '=>') { arity = 0; resStart = i + 1; }
  }
  const first = tokens[resStart];
  // The text of each argument type, in order (the part before the final result): used to decide which parameters carry
  // caller-supplied text.
  const argTypes = [];
  if (arity > 0) {
    let start = sig.ta; depth = 0;
    for (let i = sig.ta; i < resStart; i++) {
      const t = tokens[i];
      if (t.t === 'sp') { if (t.v === '(' || t.v === '[' || t.v === '{') depth++; else if (t.v === ')' || t.v === ']' || t.v === '}') depth--; }
      else if (depth === 0 && t.t === 'rop' && t.v === '=>') start = i + 1;
      else if (depth === 0 && t.t === 'rop' && t.v === '->') { argTypes.push(tokens.slice(start, i).map((x) => x.v).join(' ')); start = i + 1; }
    }
  }
  return { arity, returnsIO: !!first && first.t === 'con' && first.v === 'IO', text: tokens.slice(sig.ta, sig.tb).map((t) => t.v).join(' '), argTypes };
}

// Parameters of an EXPORTED function whose declared type is text-like: the caller supplies that text, and nothing in the
// module proves it trusted. They are modelled as a source of kind "caller-controlled parameter" (a weaker claim than a
// request or stdin read: the finding says so). A function without a signature, a non-exported function and a parameter
// of any other type (a connection, a number, a record) are never sources.
const TEXT_LIKE = /^\(?\s*(?:Maybe\s+)?(?:String|Text|ByteString|FilePath|URI|Url|URL|\[\s*Char\s*\]|\[\s*(?:String|Text)\s*\])\s*\)?$/;
function callerControlledParams(fn, sig, exported) {
  if (!exported || !sig || !Array.isArray(sig.argTypes) || !Array.isArray(fn.params)) return [];
  const out = [];
  sig.argTypes.forEach((t, i) => { const name = fn.params[i]; if (name && TEXT_LIKE.test(t)) out.push({ index: i, name, decorator: 'hs:caller-controlled' }); });
  return out;
}

// ── module table ─────────────────────────────────────────────────────────────
function buildModuleInfo(file, src, cpp) {
  const parse = parseSyntax(preprocessForSyntax(src, { file, cpp }));
  const groups = groupDecls(parse.decls);
  const name = parse.module && parse.module.name ? parse.module.name : 'Main';
  const mod = {
    name, file, parse, groups, exports: parse.module ? parse.module.exports : null, imports: parse.imports,
    defs: new Map(), cons: new Map(), classes: new Map(), sigs: new Map(),
  };
  for (const [n, s] of groups.sigs) mod.sigs.set(n, sigInfo(parse.tokens, s));
  const addDef = (n, def) => { if (!mod.defs.has(n)) mod.defs.set(n, def); };
  for (const f of groups.funs) {
    const arity = Math.max(0, ...f.clauses.map((c) => c.pats.length));
    addDef(f.name, { kind: 'fun', qid: `${file}::${name}.${f.name}@${f.line}`, name: f.name, arity, line: f.line, sig: mod.sigs.get(f.name) || null });
  }
  for (const pb of groups.patbinds) {
    for (const v of patternVars(pb.pat)) addDef(v, { kind: 'fun', qid: `${file}::${name}.${v}@${pb.line}`, name: v, arity: 0, line: pb.line, sig: mod.sigs.get(v) || null, patbind: true });
  }
  for (const d of parse.data) {
    for (const c of d.constructors) {
      mod.cons.set(c.name, { fields: c.fields, arity: c.arity, type: d.name });
      for (const fld of c.fields || []) addDef(fld, { kind: 'field', qid: `${file}::${name}.${fld}@${d.line}`, name: fld, con: c.name, line: d.line });
    }
  }
  for (const bnd of parse.boundaries || []) {
    if (bnd.kind === 'ffi' && bnd.name) addDef(bnd.name, { kind: 'ffi', qid: `${file}::${name}.${bnd.name}@${bnd.line}`, name: bnd.name, line: bnd.line });
  }
  for (const c of parse.classes) {
    const methods = new Set();
    for (const d of c.decls) if (d.t === 'sig') for (const m of d.names) { methods.add(m); addDef(m, { kind: 'method', cls: c.name, qid: `${file}::${name}.${m}@${d.line}`, name: m, arity: 0, line: d.line }); }
    mod.classes.set(c.name, methods);
  }
  return mod;
}

// ── name resolution ──────────────────────────────────────────────────────────
function visibleImports(mod, name, qual) {
  return mod.imports.filter((imp) => {
    if (qual) return imp.as ? imp.as === qual : imp.module === qual;
    if (imp.qualified) return false;
    if (imp.items) return imp.hiding ? !imp.items.includes(name) : (imp.items.includes(name) || (imp.typeAll && imp.typeAll.length > 0));
    return true;
  });
}

function defResult(mod, name) {
  const def = mod.defs.get(name);
  return { kind: 'def', qid: def.qid, mod: mod.name, name, def };
}

function exportedLookup(proj, target, name, depth, seen) {
  const key = `${target.name}.${name}`;
  if (seen.has(key)) return { kind: 'unknown', reason: 'reexport-cycle' };
  if (depth > HS_IR_LIMITS.maxResolveDepth) return { kind: 'unknown', reason: 'resolution-depth-cap' };
  const next = new Set(seen); next.add(key);
  if (!target.exports) return target.defs.has(name) ? defResult(target, name) : null;
  for (const ex of target.exports) {
    if (ex.kind === 'var' && ex.name === name) return resolveGlobal(proj, target, name, ex.qual || null, depth + 1, next);
    if (ex.kind === 'type' && ex.all) {
      const d = target.defs.get(name);
      if (d && d.kind === 'field') return defResult(target, name);
    }
    if (ex.kind === 'module') {
      if (ex.name === target.name) { if (target.defs.has(name)) return defResult(target, name); continue; }
      for (const imp of target.imports) {
        if (imp.qualified || (imp.as !== ex.name && imp.module !== ex.name)) continue;
        if (imp.items && (imp.hiding ? imp.items.includes(name) : !imp.items.includes(name))) continue;
        const t2 = proj.modules.get(imp.module);
        const r = t2 ? exportedLookup(proj, t2, name, depth + 1, next) : { kind: 'external', module: imp.module, name, certain: !!(imp.items && !imp.hiding && imp.items.includes(name)) };
        if (r) return r;
      }
    }
  }
  return null;
}

// A top-level resolution (depth 0, nothing seen yet) is a pure function of the module table, which is complete before any function
// is lowered, so its answer is kept per module: the same name is resolved again at every use site, and each resolution walks the
// module's imports and the re-export chains of every module it imports (hub modules re-export hundreds of names). Resolutions
// made inside a re-export chain (depth > 0) depend on the path taken, so they are never kept. Callers treat the result as
// read-only.
const RESOLVE_MEMO = new WeakMap();   // module info -> (qualifier, name) -> resolution; a module's memo dies with the module
function resolveGlobal(proj, mod, name, qual, depth = 0, seen = null) {
  if (depth !== 0 || seen) return resolveGlobalUncached(proj, mod, name, qual, depth, seen || new Set());
  let memo = RESOLVE_MEMO.get(mod);
  if (!memo) { memo = new Map(); RESOLVE_MEMO.set(mod, memo); }
  const key = qual ? `${qual}\0${name}` : name;
  let r = memo.get(key);
  if (r === undefined) { r = resolveGlobalUncached(proj, mod, name, qual, 0, new Set()); memo.set(key, r); }
  return r;
}

function resolveGlobalUncached(proj, mod, name, qual, depth, seen) {
  if ((!qual || qual === mod.name) && mod.defs.has(name)) return defResult(mod, name);
  if (depth > HS_IR_LIMITS.maxResolveDepth) return { kind: 'unknown', reason: 'resolution-depth-cap' };
  const hits = [];
  const wildcard = [];
  let unknownReason = null;
  for (const imp of visibleImports(mod, name, qual)) {
    const target = proj.modules.get(imp.module);
    if (target) {
      const r = exportedLookup(proj, target, name, depth + 1, seen);
      if (!r) continue;
      if (!qual && !imp.hiding && imp.items && !imp.items.includes(name)) {
        // Visible only through `T(..)`: it must really be a field/method of one of those types.
        const owner = r.kind === 'def' ? (r.def.kind === 'field' ? (proj.modules.get(r.mod)?.cons.get(r.def.con)?.type) : r.def.kind === 'method' ? r.def.cls : null) : null;
        if (!owner || !(imp.typeAll || []).includes(owner)) continue;
      }
      if (r.kind === 'unknown') unknownReason = r.reason; else hits.push(r);
    } else if (qual || (imp.items && !imp.hiding && imp.items.includes(name))) hits.push({ kind: 'external', module: imp.module, name, certain: true });
    else wildcard.push(imp.module);   // includes `import M (T(..))` of a module we cannot read: possible, never certain
  }
  const keyOf = (r) => (r.kind === 'def' ? r.qid : `${r.module}.${r.name}`);
  const distinct = [...new Map(hits.map((r) => [keyOf(r), r])).values()];
  if (distinct.length === 1) return distinct[0];
  if (distinct.length > 1) return { kind: 'unknown', reason: 'ambiguous-import', candidates: distinct.map(keyOf) };
  if (unknownReason) return { kind: 'unknown', reason: unknownReason };
  if (!qual && PRELUDE.has(name)) return { kind: 'builtin', module: 'Prelude', name };
  if (wildcard.length) return { kind: 'external', module: wildcard.length === 1 ? wildcard[0] : null, candidates: wildcard, name, certain: false };
  return { kind: 'unknown', reason: qual ? 'unknown-qualifier' : 'unbound-name' };
}

// The import-qualified name of a library reference. External: its module (or, when several wildcard
// imports compete, the one module the model registry knows for that name). Builtin: `Prelude.<name>`
// only for names the registry models, so user-visible names of unmodelled Prelude functions are unchanged.
function libraryName(r, name, qual) {
  if (r.kind === 'external') {
    if (r.module) return { name: `${r.module}.${name}` };
    const qa = qualifyAmbiguous(name, r.candidates);
    if (qa) return { name: `${qa.module}.${name}`, viaRegistry: true };
    return { name: qual ? `${qual}.${name}` : name };
  }
  if (r.kind === 'builtin' && isKnownApi('Prelude', name)) return { name: `Prelude.${name}` };
  return { name: qual ? `${qual}.${name}` : name };
}

// An IO action named in an executing position (`x <- getLine`, a statement) runs when sequenced: it is a call.
function asExecutedAction(v, ln) {
  if (v && v.kind === 'ident' && v.hs && (v.hs.resolution === 'builtin' || v.hs.resolution === 'external')) {
    return { kind: 'call', callee: v.name, args: [], line: ln, hs: { status: v.hs.resolution, effect: 'io', action: true, ...(v.hs.viaRegistry ? { viaRegistry: true, certain: false } : {}) } };
  }
  return v;
}

// ── CFG builder ──────────────────────────────────────────────────────────────
class Cfg {
  constructor(line) {
    this.nodes = {};
    this.n = 0;
    this.entry = this.mk('entry', line);
    this.exit = null;
    this.front = [this.entry];
  }

  mk(kind, line, extra) {
    const id = `n${this.n++}`;
    this.nodes[id] = { kind, line: line || 0, succ: [], pred: [], ...(extra || {}) };
    return id;
  }

  link(a, b) {
    if (!this.nodes[a].succ.includes(b)) { this.nodes[a].succ.push(b); this.nodes[b].pred.push(a); }
  }

  add(kind, line, extra) {
    const id = this.mk(kind, line, extra);
    for (const f of this.front) this.link(f, id);
    this.front = [id];
    return id;
  }

  finish(line) {
    this.exit = this.mk('exit', line);
    for (const f of this.front) this.link(f, this.exit);
    this.front = [];
    return { entry: this.entry, exit: this.exit, nodes: this.nodes };
  }
}

// ── AST helpers ──────────────────────────────────────────────────────────────
function countOcc(name, ast) {
  let n = 0;
  const seen = new WeakSet();
  const walk = (x) => {
    if (!x || typeof x !== 'object' || seen.has(x)) return;
    seen.add(x);
    if (Array.isArray(x)) { for (const y of x) walk(y); return; }
    if (x.t === 'var' && !x.qual && x.name === name) n++;
    for (const k of Object.keys(x)) { const v = x[k]; if (v && typeof v === 'object') walk(v); }
  };
  walk(ast);
  return n;
}

const unparen = (e) => { let x = e; while (x && x.t === 'paren') x = x.e; return x; };

function headVar(e) {
  const x = unparen(e);
  if (!x) return null;
  if (x.t === 'var' && !x.qual) return x.name;
  if (x.t === 'app') return headVar(x.f);
  if (x.t === 'op' && ['$', '>>=', '>>', '<$>', '*>', '<*', '<*>', '$!'].includes(x.op)) return headVar(x.l);
  return null;
}

// Names the body demands unconditionally: an executed statement head, or the
// scrutinee/condition of the top-level branch. Anything else is "potential".
function strictNames(items, out = new Set()) {
  for (const it of items) {
    if (!it) continue;
    if (it.t === 'sexpr' || it.t === 'sbind') { const h = headVar(it.e); if (h) out.add(h); continue; }
    if (it.t === 'slet') continue;
    const x = unparen(it);
    if (!x) continue;
    if (x.t === 'do') strictNames(x.stmts, out);
    else if (x.t === 'let') strictNames([x.body], out);
    else if (x.t === 'if') { const h = headVar(x.c); if (h) out.add(h); }
    else if (x.t === 'case') { const h = headVar(x.scrut); if (h) out.add(h); }
    else { const h = headVar(x); if (h) out.add(h); }
  }
  return out;
}

// ── bounded inlining of small pure helpers ───────────────────────────────────
// A call to a user function whose whole body is a small pure expression (a record builder, a wrapper,
// an operator chain) is lowered by substituting the already-lowered arguments into that body. That is
// what keeps record fields apart across a function return (`mkCfg l` builds {cmd: l, label: "fixed"},
// so `label c` stays clean) and what analyses the helper once per call context. The helper is still
// lowered and analysed on its own; the call is kept as a reference edge in the call graph.
const INLINE_MAX_NODES = 60;
const INLINE_MAX_DEPTH = 4;
const INLINE_KINDS = new Set(['var', 'con', 'lit', 'app', 'op', 'paren', 'tuple', 'list', 'rec', 'neg', 'lowered']);

function inlineScan(node, params, selfName, acc = { size: 0, ok: true }, headPos = false) {
  if (!acc.ok || !node || typeof node !== 'object') return acc;
  if (Array.isArray(node)) { for (const x of node) inlineScan(x, params, selfName, acc, false); return acc; }
  if (typeof node.t === 'string') {
    if (!INLINE_KINDS.has(node.t)) { acc.ok = false; return acc; }
    if (++acc.size > INLINE_MAX_NODES) { acc.ok = false; return acc; }
    if (node.t === 'var' && !node.qual) {
      if (node.name === selfName) { acc.ok = false; return acc; }          // recursion
      if (headPos && params.has(node.name)) { acc.ok = false; return acc; } // a parameter applied as a function
    }
    if (node.t === 'app') { inlineScan(node.f, params, selfName, acc, true); inlineScan(node.args, params, selfName, acc, false); return acc; }
    if (node.t === 'op') { inlineScan(node.l, params, selfName, acc, false); inlineScan(node.r, params, selfName, acc, false); return acc; }
  }
  for (const k of Object.keys(node)) {
    if (k === 't' || k === 'line') continue;
    const v = node[k];
    if (v && typeof v === 'object') inlineScan(v, params, selfName, acc, false);
  }
  return acc;
}

function inlinableBody(fnAst) {
  if (!fnAst || fnAst.clauses.length !== 1) return null;
  const c = fnAst.clauses[0];
  if (!c.pats.every((p) => p && p.t === 'pvar')) return null;
  if (!c.rhs || (c.rhs.guards && c.rhs.guards.length) || (c.rhs.where && c.rhs.where.length) || !c.rhs.body) return null;
  const params = new Set(c.pats.map((p) => p.name));
  const acc = inlineScan(c.rhs.body, params, fnAst.name);
  return acc.ok ? { params: c.pats.map((p) => p.name), body: c.rhs.body } : null;
}

// ── per-function lowering ────────────────────────────────────────────────────
class FnLowerer {
  constructor(proj, mod, fnInfo, scopes) {
    this.proj = proj;
    this.mod = mod;
    this.info = fnInfo; // {qid, name, line, parentName}
    this.scopes = scopes ? [...scopes] : [];
    this.base = this.scopes.length;
    this.cfg = new Cfg(fnInfo.line);
    this.depth = 0;
    this.tmp = 0;
    this.lam = 0;
    this.refs = [];
    this.deferred = [];
    this.captures = new Set();
    this.diagnostics = [];
    this.params = [];
    this.sawIO = false;
  }

  // scope handling
  push() { const m = new Map(); this.scopes.push(m); return m; }
  pop() { this.scopes.pop(); }
  declare(name, entry) { this.scopes[this.scopes.length - 1].set(name, entry); }
  lookupLocal(name) {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      if (!this.scopes[i].has(name)) continue;
      const entry = this.scopes[i].get(name);
      // A parameter of an enclosing function is a captured variable here, not
      // one of this function's own positional parameters.
      if (i < this.base && entry.kind === 'param') { this.captures.add(name); return { kind: 'local', captured: true }; }
      return entry;
    }
    return null;
  }

  resolve(name, qual) {
    if (!qual) {
      const l = this.lookupLocal(name);
      if (l) return { kind: l.kind, ...l, name };
    }
    return resolveGlobal(this.proj, this.mod, name, qual || null);
  }

  noteRef(qid, via, line) { if (qid) this.refs.push({ target: qid, via, line }); }

  // ── expression lowering ────────────────────────────────────────────────────
  lowerExpr(e, line) {
    if (++this.depth > HS_IR_LIMITS.maxExprDepth) { this.depth--; return unknownExpr({ capped: 'expression-depth' }); }
    try { return this.lowerInner(e, line || 0); } finally { this.depth--; }
  }

  lowerInner(e, line) {
    if (!e) return unknownExpr();
    // While an inlined body is lowered, every node reports the CALL SITE's line: the callee's own line
    // belongs to a different place (often a different file).
    const ln = this.lineOverride || e.line || line;
    switch (e.t) {
      case 'lowered': return e.expr;
      case 'paren': return this.lowerExpr(e.e, ln);
      case 'lit': return { kind: 'literal', value: e.kind === 'int' || e.kind === 'float' ? Number(String(e.v).replace(/_/g, '')) : e.v };
      case 'con': return { kind: 'literal', value: e.name, hs: { con: e.name } };
      case 'var': return this.lowerVarValue(e, ln);
      case 'app': return this.lowerApp(e.f, e.args, ln);
      case 'op': return this.lowerOp(e, ln);
      case 'neg': return { kind: 'binary', op: '-', left: { kind: 'literal', value: 0 }, right: this.lowerExpr(e.e, ln) };
      case 'tuple': return { kind: 'array', elements: e.items.map((x) => this.lowerExpr(x, ln)), hs: { tuple: true } };
      case 'list': return { kind: 'array', elements: e.items.map((x) => this.lowerExpr(x, ln)) };
      case 'range': return { kind: 'array', elements: e.items.map((x) => this.lowerExpr(x, ln)), hs: { range: true } };
      case 'listcomp': return this.lowerListComp(e, ln);
      case 'rec': return this.lowerRecord(e, ln);
      case 'recupd': {
        const base = this.lowerExpr(e.base, ln);
        return mkUnion(base, { kind: 'object', props: e.fields.map((f) => ({ key: f.name, value: this.lowerExpr(f.e, ln) })), hs: { update: true } });
      }
      case 'if': {
        const c = this.lowerExpr(e.c, ln);
        return this.branch(c, ln, () => this.lowerExpr(e.a, ln), () => this.lowerExpr(e.b, ln));
      }
      case 'multiif': return this.lowerGuards(e.guards, ln);
      case 'case': return this.lowerCase(e, ln);
      case 'lamcase': return this.liftClosure({ params: [{ t: 'pvar', name: '$lc' }], body: { t: 'case', scrut: { t: 'var', name: '$lc', qual: null }, alts: e.alts, line: ln }, line: ln }, ln);
      case 'lam': return this.liftClosure(e, ln);
      case 'let': {
        this.push();
        try {
          this.processDecls(e.decls, [e.body], ln);
          return this.lowerExpr(e.body, ln);
        } finally { this.pop(); }
      }
      case 'do': return this.lowerDo(e.stmts, ln);
      case 'lsec': case 'rsec': {
        const refs = this.sectionTargets(e);
        for (const r of refs) this.noteRef(r, 'section', ln);
        return { kind: 'array', elements: [this.lowerExpr(e.e, ln)], hs: { section: e.op, partial: { remaining: 1 } } };
      }
      default: return unknownExpr({ ast: e.t || 'unknown' });
    }
  }

  sectionTargets() { return []; }

  lowerRecord(e, ln) {
    const props = [];
    const cons = this.mod.cons.get(e.con.name) || this.proj.findCon(e.con.name);
    for (const f of e.fields) {
      if (f.wildcard) {
        for (const fld of (cons && cons.fields) || []) if (!e.fields.some((g) => g.name === fld)) props.push({ key: fld, value: { kind: 'ident', name: fld } });
      } else props.push({ key: f.name, value: this.lowerExpr(f.e, ln) });
    }
    return { kind: 'object', props, hs: { con: e.con.name } };
  }

  lowerListComp(e, ln) {
    for (const q of e.quals) {
      if (q.t === 'qbind') this.bindPattern(q.pat, { kind: 'member', object: this.lowerExpr(q.e, ln), prop: '[]' }, ln);
      else if (q.t === 'qlet') this.processDecls(q.decls, [e.head], ln);
    }
    return { kind: 'array', elements: [this.lowerExpr(e.head, ln)], hs: { comprehension: true } };
  }

  // A function name used as a value (not applied).
  lowerVarValue(e, ln) {
    const r = this.resolve(e.name, e.qual);
    if (r.kind === 'alias') return r.expr;
    if (r.kind === 'def' && r.def.kind === 'field') return { kind: 'ident', name: e.name, hs: { fieldSelector: r.name } };
    if (r.kind === 'def' || r.kind === 'localfn') {
      this.noteRef(r.qid, 'reference', ln);
      return { kind: 'ident', name: this.canonical(r), hs: { functionRef: r.qid } };
    }
    if (r.kind === 'param' || r.kind === 'local') return { kind: 'ident', name: e.name };
    const lib = libraryName(r, e.name, e.qual);
    const viaReg = lib.viaRegistry ? { viaRegistry: true, certain: false } : {};
    // A modelled SOURCE action named as a value (`getLine >>= f`, `fmap g getLine`) yields untrusted data
    // wherever it is bound, so it lowers to the call that produces it.
    if ((r.kind === 'external' || r.kind === 'builtin') && isSourceApi(lib.name)) {
      return this.sourceValue({ kind: 'call', callee: lib.name, args: [], line: ln, hs: { status: r.kind, effect: 'io', action: true, ...viaReg } }, ln);
    }
    return { kind: 'ident', name: lib.name, hs: { resolution: r.kind, ...viaReg } };
  }

  canonical(r) {
    if (r.kind === 'def') return `${r.mod}.${r.name}`;
    if (r.kind === 'localfn') return r.canonical;
    return r.name;
  }

  // ── application ────────────────────────────────────────────────────────────
  lowerApp(fAst, argAsts, ln, via) {
    const f = unparen(fAst);
    if (!f) return unknownExpr();
    if (f.t === 'app') return this.lowerApp(f.f, [...f.args, ...argAsts], ln, via);
    if (!argAsts.length) return this.lowerExpr(f, ln);
    if (f.t === 'op') {
      if (f.op === '.') {
        const [a0, ...rest] = argAsts;
        return this.lowerApp(f.l, [{ t: 'app', f: f.r, args: [a0], line: ln }, ...rest], ln, via);
      }
      if (f.op === '$' || f.op === '$!') return this.lowerApp(f.l, [f.r, ...argAsts], ln, via);
      if (f.op === '&') return this.lowerApp(f.r, [f.l, ...argAsts], ln, via);
    }
    if (f.t === 'rsec') return this.lowerOp({ t: 'op', op: f.op, qual: f.qual, l: argAsts[0], r: f.e, line: ln }, ln);
    if (f.t === 'lsec') return this.lowerOp({ t: 'op', op: f.op, qual: f.qual, l: f.e, r: argAsts[0], line: ln }, ln);
    if (f.t === 'lam') return this.betaReduce(f, argAsts, ln);
    if (f.t === 'var') return this.applyVar(f, argAsts, ln, via);
    if (f.t === 'con') {
      const cons = this.mod.cons.get(f.name) || this.proj.findCon(f.name);
      const elements = argAsts.map((a) => this.lowerExpr(a, ln));
      if (cons && cons.fields) return { kind: 'object', props: cons.fields.map((k, i) => ({ key: k, value: elements[i] || unknownExpr() })), hs: { con: f.name } };
      return { kind: 'array', elements, hs: { con: f.name } };
    }
    // Function-valued conditional/let/case etc.: the target is not statically known.
    const fv = this.lowerExpr(f, ln);
    return { kind: 'call', callee: '<indirect>', args: [fv, ...argAsts.map((a) => this.lowerExpr(a, ln))], hs: { status: 'unknown', reason: 'computed-function', via } };
  }

  betaReduce(lam, argAsts, ln) {
    const n = Math.min(lam.params.length, argAsts.length);
    this.push();
    try {
      for (let i = 0; i < n; i++) this.bindPattern(lam.params[i], this.lowerExpr(argAsts[i], ln), ln);
      if (lam.params.length > argAsts.length) return { kind: 'array', elements: argAsts.map((a) => this.lowerExpr(a, ln)), hs: { partial: { remaining: lam.params.length - argAsts.length }, closure: true } };
      const body = this.lowerExpr(lam.body, ln);
      if (argAsts.length > n) return { kind: 'call', callee: '<indirect>', args: [body, ...argAsts.slice(n).map((a) => this.lowerExpr(a, ln))], hs: { status: 'unknown', reason: 'result-applied' } };
      return body;
    } finally { this.pop(); }
  }

  applyVar(f, argAsts, ln, via) {
    const r = this.resolve(f.name, f.qual);
    // Bounded collection summaries only apply to library names, never a user definition.
    if (HOF[f.name] && (r.kind === 'builtin' || r.kind === 'external')) {
      const out = this.lowerHof(f.name, argAsts, ln);
      if (out) return out;
    }
    if (r.kind === 'def' && r.def.kind === 'field' && argAsts.length >= 1) {
      const obj = this.lowerExpr(argAsts[0], ln);
      const mem = { kind: 'member', object: obj, prop: r.name };
      return argAsts.length === 1 ? mem : { kind: 'call', callee: '<indirect>', args: [mem, ...argAsts.slice(1).map((a) => this.lowerExpr(a, ln))], hs: { status: 'unknown', reason: 'field-applied' } };
    }
    let args = argAsts.map((a) => this.lowerExpr(a, ln));
    // `lookup key table` returns an element OF the table: the key chooses which, it is not where the value comes from. Only the table
    // flows to the result, so a constant table gives a constant result however tainted the key is.
    let selector = null;
    if (f.name === 'lookup' && args.length === 2 && (r.kind === 'builtin' || r.kind === 'external')) { selector = args[0]; args = [args[1]]; }
    const hs = { via };
    // The key stays on the call as `hs.selector`: taint ignores it (it only chooses), but a rule asking "does caller text decide whether
    // this fails" (fromJust (lookup key t)) still sees it.
    if (selector) hs.selector = selector;
    let callee = f.qual ? `${f.qual}.${f.name}` : f.name;
    const arity = (r.kind === 'def' && r.def.kind === 'fun') ? r.def.arity : (r.kind === 'localfn' ? r.arity : -1);
    if ((r.kind === 'def' && r.def.kind === 'fun') || r.kind === 'localfn') {
      callee = this.canonical(r);
      hs.status = 'resolved'; hs.target = r.qid;
      if (r.kind === 'def' && arity === args.length && arity > 0 && (this.inlineDepth || 0) < INLINE_MAX_DEPTH) {
        const inl = this.tryInline(r, args, ln, via);
        if (inl) return inl;
      }
      if (arity > args.length) {
        this.noteRef(r.qid, 'partial', ln);
        return { kind: 'array', elements: args, hs: { partial: { target: r.qid, name: callee, remaining: arity - args.length } } };
      }
      const sig = r.kind === 'def' ? r.def.sig : null;
      hs.effect = sig ? (sig.returnsIO ? 'io' : 'pure') : 'unknown';
    } else if (r.kind === 'def' && r.def.kind === 'ffi') {
      // A foreign function: the code behind it is not analysed, so the call is an opaque boundary.
      callee = `${r.mod}.${r.name}`;
      hs.status = 'ffi'; hs.reason = 'foreign-function'; hs.effect = 'io';
    } else if (r.kind === 'def' && r.def.kind === 'method') {
      callee = `${r.mod}.${r.name}`;
      hs.status = 'typeclass'; hs.cls = r.def.cls; hs.method = r.name; hs.target = r.qid;
      hs.candidates = this.proj.instancesOf(r.def.cls, r.name);
      hs.effect = 'unknown';
    } else if (r.kind === 'param') {
      hs.status = 'param'; hs.paramIndex = r.index; hs.effect = 'unknown';
    } else if (r.kind === 'local') {
      hs.status = 'unknown'; hs.reason = 'local-function-value'; hs.effect = 'unknown';
    } else if (r.kind === 'external') {
      const lib = libraryName(r, f.name, f.qual);
      callee = lib.name;
      hs.status = 'external'; hs.certain = lib.viaRegistry ? false : r.certain; if (lib.viaRegistry) hs.viaRegistry = true; hs.effect = IO_NAMES.has(f.name) ? 'io' : 'unknown';
      if (IO_NAMES.has(f.name)) this.sawIO = true;
    } else if (r.kind === 'builtin') {
      callee = libraryName(r, f.name, f.qual).name;
      hs.status = 'builtin'; hs.effect = IO_NAMES.has(f.name) ? 'io' : 'pure';
      if (IO_NAMES.has(f.name)) this.sawIO = true;
    } else {
      hs.status = 'unknown'; hs.reason = r.reason || 'unresolved'; hs.effect = 'unknown';
    }
    if (hs.status === 'resolved' || hs.status === 'typeclass') {
      const ctxTargets = args.map((a) => argTargets(a));
      if (ctxTargets.some((t) => t.length)) hs.argTargets = ctxTargets;
    }
    const call = { kind: 'call', callee, args, line: ln, hs };
    // `setRequestBodyJSON body req` returns the REQUEST with a body: the body's taint is a property of the body, and
    // must not make the request's URL tainted. The call still gets its own node so a sink on the body argument fires.
    if ((hs.status === 'external' || hs.status === 'builtin') && BODY_SETTER.test(callee) && args.length >= 2) {
      const t = `$body${this.tmp++}`;
      this.cfg.add('assign', ln, { target: t, source: call, hs: { demand: 'executed', bodySetter: true } });
      return args[args.length - 1];
    }
    return (hs.status === 'external' || hs.status === 'builtin') && isSourceApi(callee) ? this.sourceValue(call, ln) : call;
  }

  // A modelled source read gets its own assignment node, so the evidence chain names the exact line the
  // untrusted data entered, even when the read sits inside a larger expression (`f =<< getLine`).
  sourceValue(call, ln) {
    const t = `$src${this.tmp++}`;
    this.cfg.add('assign', call.line || ln, { target: t, source: call, hs: { demand: 'executed', source: true } });
    return { kind: 'ident', name: t, hs: { sourceTemp: call.callee } };
  }

  // Substitute lowered arguments into a small pure callee body. Returns null when the callee is not inlinable.
  tryInline(r, loweredArgs, ln, via) {
    const calleeMod = this.proj.modules.get(r.mod);
    if (!calleeMod) return null;
    const fnAst = calleeMod.groups.funs.find((f) => f.name === r.name);
    const inl = inlinableBody(fnAst);
    if (!inl || inl.params.length !== loweredArgs.length) return null;
    const savedMod = this.mod;
    const savedOverride = this.lineOverride;
    this.lineOverride = this.lineOverride || ln;
    this.inlineDepth = (this.inlineDepth || 0) + 1;
    this.push();
    try {
      inl.params.forEach((name, i) => this.declare(name, { kind: 'alias', expr: loweredArgs[i] }));
      this.mod = calleeMod;
      (this.inlinedCalls ||= []).push({ site: null, callee: this.canonical(r), args: [], line: ln, hs: { status: 'resolved', target: r.qid, effect: 'unknown', inlined: true, ...(via ? { via } : {}) } });
      const out = this.lowerExpr(inl.body, ln);
      return out && typeof out === 'object' ? { ...out, hs: { ...(out.hs || {}), inlinedFrom: r.qid } } : out;
    } finally {
      this.mod = savedMod;
      this.lineOverride = savedOverride;
      this.pop();
      this.inlineDepth -= 1;
    }
  }

  // A project-defined zero-argument action executed by a bind or a statement (`u <- requireUser`) is a
  // call to it, not a mere reference: it runs when sequenced.
  executeRef(v, ln) {
    if (!v || v.kind !== 'ident' || !v.hs || !v.hs.functionRef || v.hs.closure) return v;
    const def = this.proj.defByQid(v.hs.functionRef);
    if (!def || def.kind !== 'fun' || def.arity !== 0) return v;
    return { kind: 'call', callee: v.name, args: [], line: ln, hs: { status: 'resolved', target: v.hs.functionRef, effect: 'io', action: true } };
  }

  // Bounded collection/traversal summaries. Returns null to fall back to a plain call.
  lowerHof(name, argAsts, ln) {
    const spec = HOF[name];
    const need = Math.max(spec.fn === undefined ? 0 : spec.fn, spec.coll) + 1;
    if (argAsts.length < need || (spec.seed !== undefined && argAsts.length < 3)) return null;
    const coll = this.lowerExpr(argAsts[spec.coll], ln);
    const elem = { kind: 'member', object: coll, prop: '[]' };
    if (spec.kind === 'sequence') { this.sawIO = true; return coll; }
    const fnAst = argAsts[spec.fn];
    const el = { t: 'lowered', expr: elem };
    if (spec.kind === 'fold') {
      const seed = this.lowerExpr(argAsts[spec.seed], ln);
      const step = this.lowerApp(fnAst, [spec.fn === 0 && (name === 'foldr') ? el : { t: 'lowered', expr: seed }, name === 'foldr' ? { t: 'lowered', expr: seed } : el], ln, name);
      return mkUnion(seed, step);
    }
    const res = this.lowerApp(fnAst, [el], ln, name);
    if (spec.kind === 'filter') {
      this.cfg.add('if', ln, { cond: res, hs: { via: 'filter' } });
      return coll;
    }
    if (spec.kind === 'traverse_') {
      this.addCallNode(res, ln);
      return { kind: 'literal', value: '()' };
    }
    return { kind: 'array', elements: [res], hs: { via: name, effect: spec.kind === 'traverse' ? 'unknown' : 'pure' } };
  }

  // ── operators ──────────────────────────────────────────────────────────────
  lowerOp(e, ln) {
    const op = e.op;
    switch (op) {
      case '$': case '$!': return this.lowerApp(e.l, [e.r], ln);
      case '&': return this.lowerApp(e.r, [e.l], ln);
      case '<&>': return this.lowerApp(e.r, [e.l], ln, 'fmap');
      case '>>=': return this.lowerApp(e.r, [e.l], ln, 'bind');
      case '=<<': return this.lowerApp(e.l, [e.r], ln, 'bind');
      case '<$>': case '<$!>': return this.lowerApp(e.l, [e.r], ln, 'fmap');
      case '<$': { const v = this.lowerExpr(e.l, ln); this.addCallNode(this.lowerExpr(e.r, ln), ln); return v; }
      case '>>': case '*>': { this.addCallNode(this.lowerExpr(e.l, ln), ln); return this.lowerExpr(e.r, ln); }
      case '<*': { const v = this.lowerExpr(e.l, ln); this.addCallNode(this.lowerExpr(e.r, ln), ln); return v; }
      case '<*>': return this.lowerApplicative(e, ln);
      case '<|>': return mkUnion(this.lowerExpr(e.l, ln), this.lowerExpr(e.r, ln));
      case '.': case '>=>': case '<=<': {
        const l = this.lowerExpr(e.l, ln);
        const r = this.lowerExpr(e.r, ln);
        return { kind: 'array', elements: [l, r], hs: { compose: true, targets: [...argTargets(l), ...argTargets(r)] } };
      }
      case '++': case '<>': return { kind: 'binary', op: '+', left: this.lowerExpr(e.l, ln), right: this.lowerExpr(e.r, ln), hs: { concat: op } };
      case '&&': return { kind: 'logical', op: 'and', left: this.lowerExpr(e.l, ln), right: this.lowerExpr(e.r, ln) };
      case '||': return { kind: 'logical', op: 'or', left: this.lowerExpr(e.l, ln), right: this.lowerExpr(e.r, ln) };
      case ':': return { kind: 'array', elements: [this.lowerExpr(e.l, ln), this.lowerExpr(e.r, ln)], hs: { cons: true } };
      default: break;
    }
    if (ARITH.has(op)) return { kind: 'binary', op, left: this.lowerExpr(e.l, ln), right: this.lowerExpr(e.r, ln) };
    if (op[0] === ':') return { kind: 'array', elements: [this.lowerExpr(e.l, ln), this.lowerExpr(e.r, ln)], hs: { con: op } };
    return this.lowerApp({ t: 'var', name: op, qual: e.qual || null, line: ln }, [e.l, e.r], ln);
  }

  // f <$> a <*> b <*> c  ==> f a b c ; `pure f <*> a` likewise.
  lowerApplicative(e, ln) {
    const rest = [];
    let cur = e;
    while (cur.t === 'op' && cur.op === '<*>') { rest.unshift(cur.r); cur = unparen(cur.l); if (!cur) break; }
    if (cur && cur.t === 'op' && (cur.op === '<$>' || cur.op === '<$!>')) return this.lowerApp(cur.l, [cur.r, ...rest], ln, 'applicative');
    const pure = cur && cur.t === 'app' && unparen(cur.f) && unparen(cur.f).t === 'var' && ['pure', 'return'].includes(unparen(cur.f).name) && cur.args.length === 1;
    if (pure) return this.lowerApp(cur.args[0], rest, ln, 'applicative');
    const base = cur ? this.lowerExpr(cur, ln) : unknownExpr();
    return { kind: 'call', callee: '<ap>', args: [base, ...rest.map((a) => this.lowerExpr(a, ln))], hs: { status: 'unknown', reason: 'applicative-function-unknown', via: 'applicative' } };
  }

  // ── closures ───────────────────────────────────────────────────────────────
  liftClosure(lam, ln) {
    this.lam++;
    const name = `${this.info.name}.\\lambda${this.lam}`;
    const qid = `${this.mod.file}::${this.info.parentName || this.info.name}.\\lambda${this.lam}@${ln}`;
    const sub = new FnLowerer(this.proj, this.mod, { qid, name, line: ln, parentName: this.info.parentName || this.info.name }, this.scopes);
    sub.push();
    const params = lam.params.map((p, i) => (p.t === 'pvar' ? p.name : `$arg${i}`));
    params.forEach((p, i) => sub.declare(p, { kind: 'param', index: i }));
    sub.params = params;
    lam.params.forEach((p, i) => { if (p.t !== 'pvar') sub.bindPattern(p, { kind: 'ident', name: `$arg${i}` }, ln); });
    const body = sub.lowerExpr(lam.body, ln);
    sub.cfg.add('return', (body && body.kind === 'call' && body.line) || ln, { value: body });
    this.proj.addFn(sub.finishFn({ kind: 'closure', arity: params.length, parent: this.info.qid, captures: [...sub.captures] }));
    this.noteRef(qid, 'closure', ln);
    return { kind: 'ident', name: qid, hs: { functionRef: qid, closure: true } };
  }

  // ── statements / control flow ──────────────────────────────────────────────
  addCallNode(expr, ln) {
    if (!expr) return;
    if (expr.kind === 'call') this.cfg.add('call', ln, { callee: expr.callee, args: expr.args, hs: expr.hs });
    else if (expr.kind !== 'literal' && expr.kind !== 'ident') this.cfg.add('assign', ln, { target: `$e${this.tmp++}`, source: expr, hs: { demand: 'executed' } });
  }

  branch(cond, ln, thenF, elseF) {
    const c = this.cfg;
    const ifId = c.add('if', ln, { cond });
    c.front = [ifId];
    const a = thenF();
    const fa = c.front;
    const thenEdgesAfterThen = [...c.nodes[ifId].succ];
    c.front = [ifId];
    const b = elseF();
    const fb = c.front;
    const join = c.mk('noop', ln);
    // Which successor is which: a branch that adds no node falls straight through to the join, so the
    // order of `succ` is NOT then/else. Record the real entries for guard analysis.
    const thenEdges = thenEdgesAfterThen;
    const elseEdges = c.nodes[ifId].succ.filter((x) => !thenEdges.includes(x));
    c.nodes[ifId].thenEntry = thenEdges[0] || join;
    c.nodes[ifId].elseEntry = elseEdges[0] || join;
    for (const f of [...fa, ...fb]) c.link(f, join);
    c.front = [join];
    const u = mkUnion(a, b);
    // Record which condition selects which branch, so a guard can be judged structurally: branch 0 runs
    // when the condition holds, branch 1 when it does not. (A branch that yields nothing collapses the
    // union and the fact is simply not recorded: fewer guards are recognised, never more.)
    if (u && u.kind === 'union' && u.branches.length === 2 && u.branches[0] === a && u.branches[1] === b) {
      u.hs = { ...(u.hs || {}), branchConds: [{ cond, when: true }, { cond, when: false }] };
    }
    return u;
  }

  // items: [{test():expr|null, body():expr|null}], chained as nested branches.
  alternatives(items, i, ln) {
    if (i >= items.length) return null;
    const it = items[i];
    const test = it.test();
    if (test === null) return it.body();
    return this.branch(test, ln, () => it.body(), () => this.alternatives(items, i + 1, ln));
  }

  lowerGuards(guards, ln) {
    const items = guards.map((g) => ({
      test: () => this.guardCond(g.quals, ln),
      body: () => this.lowerExpr(g.body, ln),
    }));
    return this.alternatives(items, 0, ln);
  }

  guardCond(quals, ln) {
    let cond = null;
    for (const q of quals) {
      let c = null;
      if (q.t === 'qbool') {
        const x = unparen(q.e);
        if (x && x.t === 'var' && (x.name === 'otherwise' || x.name === 'True')) continue;
        c = this.lowerExpr(q.e, ln);
      } else if (q.t === 'qbind') {
        const scrut = this.lowerExpr(q.e, ln);
        this.bindPattern(q.pat, scrut, ln);
        c = { kind: 'call', callee: '<match>', args: [scrut], hs: { status: 'builtin', effect: 'pure', pattern: true } };
      } else if (q.t === 'qlet') this.processDecls(q.decls, [], ln);
      if (c) cond = cond ? { kind: 'logical', op: 'and', left: cond, right: c } : c;
    }
    return cond;
  }

  lowerRhs(rhs, ln) {
    this.push();
    try {
      this.processDecls(rhs.where || [], [rhs.body, ...(rhs.guards || []).flatMap((g) => [g.body, ...g.quals])], ln);
      if (rhs.guards) return this.lowerGuards(rhs.guards, ln);
      return this.lowerExpr(rhs.body, ln);
    } finally { this.pop(); }
  }

  lowerCase(e, ln) {
    const scrut = this.lowerExpr(e.scrut, ln);
    const s = `$s${this.tmp++}`;
    this.cfg.add('assign', ln, { target: s, source: scrut, hs: { demand: 'demanded' } });
    const sv = { kind: 'ident', name: s };
    const items = e.alts.map((alt) => ({
      test: () => (isRefutable(alt.pat) ? { kind: 'call', callee: '<match>', args: [sv], hs: { status: 'builtin', effect: 'pure', pattern: true } } : null),
      body: () => { this.push(); try { this.bindPattern(alt.pat, sv, ln); return this.lowerRhs(alt.rhs, alt.line || ln); } finally { this.pop(); } },
    }));
    return this.alternatives(items, 0, ln);
  }

  lowerDo(stmts, ln) {
    this.push();
    try {
      let last = null;
      for (let i = 0; i < stmts.length; i++) {
        const st = stmts[i];
        const isLast = i === stmts.length - 1;
        const sl = st.line || ln;
        if (st.t === 'sbind') {
          const v = this.executeRef(asExecutedAction(this.lowerExpr(st.e, sl), sl), sl);
          this.bindPattern(st.pat, v, sl, { executed: true });
        } else if (st.t === 'slet') {
          this.processDecls(st.decls, stmts.slice(i + 1), sl);
        } else if (st.t === 'sexpr') {
          const v = this.executeRef(asExecutedAction(this.lowerExpr(st.e, sl), sl), sl);
          if (isLast) last = v; else this.addCallNode(v, sl);
        }
      }
      return last || { kind: 'literal', value: '()' };
    } finally { this.pop(); }
  }

  // ── patterns ───────────────────────────────────────────────────────────────
  bindPattern(p, src, ln, opts) {
    if (p && p.t !== 'pvar' && src && src.kind !== 'ident') {
      // Evaluate the scrutinee once; every component then reads the temporary.
      if (!patternVars(p).length) { if (opts && opts.executed) this.addCallNode(src, ln); return; }
      const t = `$p${this.tmp++}`;
      this.cfg.add('assign', ln, { target: t, source: src, hs: { demand: opts && opts.executed ? 'executed' : 'demanded', pattern: true } });
      src = { kind: 'ident', name: t };
    } else if (p && p.t === 'pwild' && opts && opts.executed) { this.addCallNode(src, ln); return; }
    const emit = (name, source) => {
      this.declare(name, { kind: 'local' });
      // `x <- getLine`: bind the read DIRECTLY to `x` (retarget the temp assignment just emitted) so the
      // evidence chain stays attached to the variable the program actually uses.
      if (source && source.kind === 'ident' && source.hs && source.hs.sourceTemp && this.cfg.front.length === 1) {
        const last = this.cfg.nodes[this.cfg.front[0]];
        if (last && last.kind === 'assign' && last.target === source.name) { last.target = name; last.hs = { ...last.hs, pattern: true }; return; }
      }
      this.addAssign(ln, name, source, { demand: opts && opts.executed ? 'executed' : 'demanded', pattern: true });
    };
    const walk = (pat, s) => {
      if (!pat) return;
      switch (pat.t) {
        case 'pvar': emit(pat.name, s); break;
        case 'pas': emit(pat.name, s); walk(pat.p, s); break;
        case 'ptuple': pat.items.forEach((x, i) => walk(x, { kind: 'member', object: s, prop: `[${i}]` })); break;
        case 'plist': pat.items.forEach((x) => walk(x, { kind: 'member', object: s, prop: '[]' })); break;
        case 'pcon': {
          if (pat.con === ':' && pat.args.length === 2) { walk(pat.args[0], { kind: 'member', object: s, prop: '[0]' }); walk(pat.args[1], { kind: 'member', object: s, prop: '[]' }); break; }
          const info = this.mod.cons.get(pat.con) || this.proj.findCon(pat.con);
          pat.args.forEach((x, i) => walk(x, { kind: 'member', object: s, prop: info && info.fields && info.fields[i] ? info.fields[i] : `${pat.con}.${i}` }));
          for (const f of pat.fields) {
            if (f.wildcard) { for (const fld of (info && info.fields) || []) if (!pat.fields.some((g) => g.name === fld)) emit(fld, { kind: 'member', object: s, prop: fld }); }
            else walk(f.pat, { kind: 'member', object: s, prop: f.name });
          }
          break;
        }
        default: break;
      }
    };
    walk(p, src);
  }

  // ── let / where declarations: lazy, immutable bindings ─────────────────────
  processDecls(decls, bodyAsts, ln) {
    if (!decls.length) return;
    const g = groupDecls(decls);
    const scope = this.scopes[this.scopes.length - 1];
    const parent = this.info.parentName || this.info.name;
    for (const f of g.funs) {
      const arity = Math.max(0, ...f.clauses.map((c) => c.pats.length));
      if (arity > 0) {
        const canonical = `${this.info.name}.${f.name}`;
        scope.set(f.name, { kind: 'localfn', qid: `${this.mod.file}::${parent}.${f.name}@${f.line}`, arity, canonical });
      } else scope.set(f.name, { kind: 'local' });
    }
    for (const pb of g.patbinds) for (const v of patternVars(pb.pat)) scope.set(v, { kind: 'local' });
    const strict = strictNames(bodyAsts.map((b) => b));
    const siblingAsts = decls.map((d) => (d.t === 'clause' ? d.clause.rhs : d.t === 'patbind' ? d.rhs : null));

    for (const f of g.funs) {
      const arity = Math.max(0, ...f.clauses.map((c) => c.pats.length));
      const entry = scope.get(f.name);
      if (arity > 0) { this.liftLocalFunction(f, entry); continue; }
      const rhsAsts = f.clauses.map((c) => c.rhs);
      const others = siblingAsts.filter((a) => a && !rhsAsts.includes(a));
      this.bindLazy([f.name], () => this.lowerRhs(f.clauses[0].rhs, f.line || ln), bodyAsts, others, strict, f.line || ln);
    }
    for (const pb of g.patbinds) {
      const names = patternVars(pb.pat);
      const others = siblingAsts.filter((a) => a && a !== pb.rhs);
      this.bindLazy(names, () => this.lowerRhs(pb.rhs, pb.line || ln), bodyAsts, others, strict, pb.line || ln, pb.pat);
    }
  }

  // Assign `source` to `target`. A record construction is stored FIELD BY FIELD (`c.cmd = ..`,
  // `c.label = ..`), so the engine's access-path lattice keeps a clean sibling field clean. A record
  // update (`r { f = v }`) is not split: it also carries the base record, which must stay whole.
  addAssign(ln, target, source, hs) {
    const rv = (this.recordVars ||= new Map());
    const emptyRecord = () => this.cfg.add('assign', ln, { target, source: { kind: 'object', props: [], hs: { record: true } }, hs: { ...hs, record: true } });
    // a fresh record: one assignment per field
    if (source && source.kind === 'object' && Array.isArray(source.props) && source.props.length && !(source.hs && source.hs.update)) {
      emptyRecord();
      const keys = [];
      for (const pr of source.props) {
        if (!pr || typeof pr.key !== 'string') continue;
        keys.push(pr.key);
        this.addAssign(ln, `${target}.${pr.key}`, pr.value, { ...hs, recordField: pr.key });
      }
      if (!target.includes('.')) rv.set(target, keys);
      return;
    }
    // a copy of a known record: copy it field by field, so one field's taint does not become the whole record's
    if (source && source.kind === 'ident' && rv.has(source.name) && !target.includes('.')) {
      const keys = rv.get(source.name);
      emptyRecord();
      for (const k of keys) this.addAssign(ln, `${target}.${k}`, { kind: 'member', object: { kind: 'ident', name: source.name }, prop: k }, { ...hs, recordField: k });
      rv.set(target, keys);
      return;
    }
    // an update of a known record: the base's fields, with the updated ones replaced
    if (source && source.kind === 'union' && source.branches.length === 2 && source.branches[1] && source.branches[1].hs && source.branches[1].hs.update
      && source.branches[0] && source.branches[0].kind === 'ident' && rv.has(source.branches[0].name) && !target.includes('.')) {
      const base = source.branches[0].name;
      const upd = new Map((source.branches[1].props || []).filter((p) => p && typeof p.key === 'string').map((p) => [p.key, p.value]));
      const keys = [...new Set([...rv.get(base), ...upd.keys()])];
      emptyRecord();
      for (const k of keys) this.addAssign(ln, `${target}.${k}`, upd.has(k) ? upd.get(k) : { kind: 'member', object: { kind: 'ident', name: base }, prop: k }, { ...hs, recordField: k });
      rv.set(target, keys);
      return;
    }
    if (!target.includes('.')) rv.delete(target);
    this.cfg.add('assign', ln, { target, source, hs });
  }

  bindLazy(names, lowerRhsFn, bodyAsts, otherAsts, strict, ln, pat) {
    const used = names.reduce((n, nm) => n + bodyAsts.reduce((s, b) => s + countOcc(nm, b), 0) + otherAsts.reduce((s, b) => s + countOcc(nm, b), 0), 0);
    if (used === 0) {
      // Never demanded: lower into a scratch graph so it is disclosed but not executed.
      const keep = this.cfg;
      this.cfg = new Cfg(ln);
      let src;
      try { src = lowerRhsFn(); } finally { this.cfg = keep; }
      const callees = [];
      collectCallsInExpr(src, callees);
      this.deferred.push({ names, line: ln, demand: 'unused', reason: 'binding is never referenced; lazy evaluation never demands it', callees: callees.map((c) => c.callee) });
      this.cfg.add('noop', ln, { hs: { deferred: { names, demand: 'unused' } } });
      return;
    }
    const demanded = names.some((n) => strict.has(n));
    const hs = demanded ? { demand: 'demanded', lazy: true } : { demand: 'potential', uncertainty: 'potentially-demanded', lazy: true };
    const src = lowerRhsFn();
    if (pat && pat.t !== 'pvar') this.bindPattern(pat, src, ln);
    else this.addAssign(ln, names[0], src, hs);
    if (!pat || pat.t === 'pvar') for (const n of names) this.declare(n, { kind: 'local' });
  }

  liftLocalFunction(f, entry) {
    const name = entry.canonical;
    const sub = new FnLowerer(this.proj, this.mod, { qid: entry.qid, name, line: f.line, parentName: this.info.parentName || this.info.name }, this.scopes);
    sub.lowerClauses(f.clauses, f.line);
    this.proj.addFn(sub.finishFn({ kind: 'local-function', arity: entry.arity, parent: this.info.qid }));
  }

  // Multi-clause function body: pattern clauses chained as alternatives.
  lowerClauses(clauses, ln) {
    this.push();
    const arity = Math.max(0, ...clauses.map((c) => c.pats.length));
    const params = [];
    for (let i = 0; i < arity; i++) {
      const names = clauses.map((c) => (c.pats[i] && c.pats[i].t === 'pvar' ? c.pats[i].name : null));
      params.push(names[0] && names.every((n) => n === names[0]) ? names[0] : `$arg${i}`);
    }
    this.params = params;
    params.forEach((p, i) => this.declare(p, { kind: 'param', index: i }));
    const items = clauses.map((c) => ({
      test: () => (c.pats.some((p) => isRefutable(p)) ? { kind: 'call', callee: '<match>', args: params.map((p) => ({ kind: 'ident', name: p })), hs: { status: 'builtin', effect: 'pure', pattern: true } } : null),
      body: () => {
        this.push();
        try {
          c.pats.forEach((p, i) => { if (!(p.t === 'pvar' && p.name === params[i])) this.bindPattern(p, { kind: 'ident', name: params[i] }, c.line || ln); });
          return this.lowerRhs(c.rhs, c.line || ln);
        } finally { this.pop(); }
      },
    }));
    const value = this.alternatives(items, 0, ln);
    this.cfg.add('return', (value && value.kind === 'call' && value.line) || ln, { value: value || unknownExpr({ reason: 'non-exhaustive' }) });
    this.pop();
  }

  finishFn(hs) {
    const cfg = this.cfg.finish(this.info.line);
    const fn = {
      qid: this.info.qid, name: this.info.name, line: this.info.line, params: this.params, file: this.mod.file, cfg,
      calls: [],
      hs: { module: this.mod.name, ...hs, refs: this.refs, deferred: this.deferred, diagnostics: this.diagnostics, effect: hs.effect || (this.sawIO ? 'io' : 'unknown') },
    };
    fn.calls = collectCalls(cfg);
    // Inlining substitutes a callee's body at the call site, but the call itself still happened:
    // keep it as a resolved edge so the call graph and reachability see it.
    if (this.inlinedCalls) fn.calls.push(...this.inlinedCalls);
    return fn;
  }
}

function isRefutable(p) {
  if (!p) return false;
  if (p.t === 'pcon' || p.t === 'plit' || p.t === 'plist') return true;
  if (p.t === 'pas') return isRefutable(p.p);
  if (p.t === 'ptuple') return p.items.some(isRefutable);
  return false;
}

// Targets an argument expression may call when applied later.
function argTargets(expr) {
  if (!expr || !expr.hs) return [];
  const out = [];
  if (expr.hs.functionRef) out.push(expr.hs.functionRef);
  if (expr.hs.partial && expr.hs.partial.target) out.push(expr.hs.partial.target);
  if (expr.hs.compose && expr.hs.targets) out.push(...expr.hs.targets);
  return out;
}

function collectCallsInExpr(expr, out) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.kind === 'call') out.push(expr);
  for (const k of ['args', 'parts', 'branches', 'elements']) if (Array.isArray(expr[k])) for (const x of expr[k]) collectCallsInExpr(x, out);
  if (Array.isArray(expr.props)) for (const p of expr.props) collectCallsInExpr(p && p.value, out);
  for (const k of ['left', 'right', 'object']) if (expr[k]) collectCallsInExpr(expr[k], out);
}

// `fn.calls` in the shared contract shape, plus the Haskell resolution facts.
function collectCalls(cfg) {
  const sites = [];
  for (const [id, node] of Object.entries(cfg.nodes)) {
    const found = [];
    if (node.kind === 'call') {
      found.push({ kind: 'call', callee: node.callee, args: node.args, hs: node.hs });
      for (const a of node.args || []) collectCallsInExpr(a, found);
    } else if (node.kind === 'assign') collectCallsInExpr(node.source, found);
    else if (node.kind === 'return') collectCallsInExpr(node.value, found);
    else if (node.kind === 'if') collectCallsInExpr(node.cond, found);
    for (const c of found) {
      if (c.callee === '<match>') continue;
      sites.push({ site: id, callee: c.callee, args: c.args, line: node.line, hs: c.hs || {} });
    }
  }
  return sites;
}

// ── project ──────────────────────────────────────────────────────────────────
class Project {
  constructor() {
    this.modules = new Map();
    this.fns = [];
    this.byFile = new Map();
    this.instanceIndex = new Map(); // `${cls}.${method}` -> qids
    this.diagnostics = [];
  }

  addFn(fn) {
    this.fns.push(fn);
    if (!this.byFile.has(fn.file)) this.byFile.set(fn.file, []);
    this.byFile.get(fn.file).push(fn);
  }

  // The three lookups below used to walk every module on every call (a constructor, a record type, a def by qid), which is
  // quadratic in project size. They are built once, lazily, on first use: the module table is complete before any function
  // is lowered, and nothing adds a module, a constructor or a definition afterwards. First-wins / last-wins orders match the
  // original scans exactly.
  findCon(name) {
    if (!this._conIndex) {
      this._conIndex = new Map();
      for (const m of this.modules.values()) for (const [n, c] of m.cons) if (!this._conIndex.has(n)) this._conIndex.set(n, c);
    }
    return this._conIndex.get(name) || null;
  }

  // Record types declared in the project: type name -> field names (a later declaration of the same type name wins).
  recordTypes() {
    if (!this._recTypes) {
      const recTypes = new Map();
      for (const m of this.modules.values()) for (const d of (m.parse && m.parse.data) || []) if (d.constructors && d.constructors.some((c) => c.fields && c.fields.length)) recTypes.set(d.name, d.constructors.flatMap((c) => c.fields || []));
      this._recTypes = recTypes;
    }
    return this._recTypes;
  }

  // A definition by its qid (the last one in module order wins, as the linear scan it replaces did).
  defByQid(qid) {
    if (!this._defIndex) {
      this._defIndex = new Map();
      for (const m of this.modules.values()) for (const d of m.defs.values()) this._defIndex.set(d.qid, d);
    }
    return this._defIndex.get(qid) || null;
  }

  instancesOf(cls, method) { return [...(this.instanceIndex.get(`${cls}.${method}`) || [])]; }
}

function lowerTopFunction(proj, mod, fun, def) {
  const info = { qid: def.qid, name: `${mod.name}.${fun.name}`, line: fun.line, parentName: `${mod.name}.${fun.name}` };
  const L = new FnLowerer(proj, mod, info, []);
  L.lowerClauses(fun.clauses, fun.line);
  const sig = def.sig;
  const kind = def.arity > 0 ? 'function' : (sig && sig.returnsIO) || fun.name === 'main' ? 'io-action' : 'value';
  const exported = !mod.exports || mod.exports.some((x) => x.kind === 'var' && x.name === fun.name || x.kind === 'module' && x.name === mod.name);
  const fn = L.finishFn({ kind, arity: def.arity, effect: sig ? (sig.returnsIO ? 'io' : 'pure') : (L.sawIO ? 'io' : 'unknown'), sig: sig ? sig.text : null, exported });
  const ann = callerControlledParams(fn, sig, exported);
  fn.hs.textParams = ann.map((a) => a.name);
  // Parameters of an exported function whose type is a record DECLARED IN THE PROJECT: the lineage view treats each such
  // parameter as a source of that record's fields (a customer record handed to an entry point), field by field.
  const recTypes = proj.recordTypes();
  fn.hs.recordParams = [];
  if (exported && sig && Array.isArray(sig.argTypes) && Array.isArray(fn.params)) {
    sig.argTypes.forEach((t, i) => { const m = /^\(?\s*([A-Z][A-Za-z0-9_']*)\s*\)?$/.exec(t); if (m && recTypes.has(m[1]) && fn.params[i]) fn.hs.recordParams.push({ name: fn.params[i], type: m[1], fields: [...new Set(recTypes.get(m[1]))] }); });
  }
  if (ann.length) fn.paramAnnotations = ann;
  return fn;
}

function lowerPatbind(proj, mod, pb) {
  const names = patternVars(pb.pat);
  const first = names[0] || '_';
  const def = mod.defs.get(first);
  const info = { qid: def ? def.qid : `${mod.file}::${mod.name}.${first}@${pb.line}`, name: `${mod.name}.${first}`, line: pb.line, parentName: `${mod.name}.${first}` };
  const L = new FnLowerer(proj, mod, info, []);
  L.push();
  const v = L.lowerRhs(pb.rhs, pb.line);
  L.cfg.add('return', pb.line, { value: v || unknownExpr() });
  L.pop();
  return L.finishFn({ kind: 'value', arity: 0, patbind: names });
}

/**
 * Build the Haskell IR and call graph for a set of files.
 * @param {Record<string,string>} fileContents path -> source (only `.hs` files are read)
 * @returns {{perFile:object, callGraph:object, modules:Map, diagnostics:object[]}}
 */
// One scan asks for the Haskell IR from several passes (rules, web analysis, supply chain, AI inventory, the deep taint engine).
// Building it is the dominant allocation, so identical input returns the SAME build: the last two distinct file sets are kept,
// keyed by path and content hash. A consumer must treat the result as read-only.
const IR_CACHE = [];
function irKey(files) {
  const h = createHash('sha256');
  for (const f of files) { h.update(f); h.update('\0'); h.update(createHash('sha256').update(String(files.__src ? files.__src[f] : '')).digest()); }
  return h.digest('hex');
}

export function buildHaskellIR(fileContents) {
  const names = Object.keys(fileContents || {}).filter((f) => /\.hs$/i.test(f)).sort();
  const keyed = Object.assign(names.slice(), { __src: fileContents });
  const key = irKey(keyed);
  const hit = IR_CACHE.find((e) => e.key === key);
  if (hit) return hit.ir;
  const ir = buildHaskellIRUncached(fileContents);
  IR_CACHE.unshift({ key, ir });
  if (IR_CACHE.length > 2) IR_CACHE.length = 2;
  return ir;
}

function buildHaskellIRUncached(fileContents) {
  const proj = new Project();
  const files = Object.keys(fileContents || {}).filter((f) => /\.hs$/i.test(f)).sort();
  const cppCtx = deriveCppContext(fileContents || {});
  for (const file of files) {
    try {
      const mod = buildModuleInfo(file, fileContents[file], cppCtx);
      proj.modules.set(mod.name === 'Main' && proj.modules.has('Main') ? `Main@${file}` : mod.name, mod);
      for (const e of mod.parse.errors) proj.diagnostics.push({ file, line: e.line, kind: e.kind, detail: e.detail });
    } catch (err) {
      proj.diagnostics.push({ file, line: 1, kind: 'ir-parse-failure', detail: String(err && err.message) });
    }
  }
  const instQids = [];
  for (const mod of proj.modules.values()) {
    for (const inst of mod.parse.instances) {
      const g = groupDecls(inst.decls);
      for (const f of g.funs) {
        const qid = `${mod.file}::${mod.name}.$inst.${inst.name}.${f.name}@${f.line}`;
        const key = `${inst.name}.${f.name}`;
        if (!proj.instanceIndex.has(key)) proj.instanceIndex.set(key, []);
        proj.instanceIndex.get(key).push(qid);
        instQids.push({ mod, inst, f, qid });
      }
    }
  }
  for (const mod of proj.modules.values()) {
    let count = 0;
    for (const f of mod.groups.funs) {
      if (++count > HS_IR_LIMITS.maxFunctionsPerFile) { proj.diagnostics.push({ file: mod.file, kind: 'function-cap', detail: 'function cap reached; remaining functions are unknown' }); break; }
      try { proj.addFn(lowerTopFunction(proj, mod, f, mod.defs.get(f.name))); } catch (err) { incomplete(proj, mod, f, err); }
    }
    for (const pb of mod.groups.patbinds) {
      try { proj.addFn(lowerPatbind(proj, mod, pb)); } catch (err) { proj.diagnostics.push({ file: mod.file, line: pb.line, kind: 'ir-lowering-failure', detail: String(err && err.message) }); }
    }
  }
  for (const { mod, inst, f, qid } of instQids) {
    const info = { qid, name: `${mod.name}.$inst.${inst.name}.${f.name}`, line: f.line, parentName: `${mod.name}.$inst.${inst.name}.${f.name}` };
    try {
      const L = new FnLowerer(proj, mod, info, []);
      L.lowerClauses(f.clauses, f.line);
      proj.addFn(L.finishFn({ kind: 'instance-method', cls: inst.name, arity: Math.max(0, ...f.clauses.map((c) => c.pats.length)) }));
    } catch (err) { proj.diagnostics.push({ file: mod.file, line: f.line, kind: 'ir-lowering-failure', detail: String(err && err.message) }); }
  }

  const perFile = {};
  for (const mod of proj.modules.values()) {
    const functions = [...(proj.byFile.get(mod.file) || [])];
    const modQid = `${mod.file}::<module>@1`;
    const cfg = new Cfg(1);
    for (const fn of functions.filter((x) => ['value', 'io-action'].includes(x.hs.kind))) {
      cfg.add('noop', fn.line, { hs: { init: { name: fn.name, kind: fn.hs.kind, demand: 'lazy-once', executedAtLoad: false } } });
    }
    functions.push({ qid: modQid, name: `${mod.name}.<module>`, line: 1, params: [], file: mod.file, cfg: cfg.finish(1), calls: [], hs: { module: mod.name, kind: 'module-init', effect: 'pure' } });
    perFile[mod.file] = {
      file: mod.file, language: 'haskell', functions, topLevel: modQid, classes: [],
      imports: mod.imports.map((i) => ({ kind: 'static', module: i.module, names: i.items || [], isDefault: false, line: i.line })),
      hs: { module: mod.name, exports: mod.exports, errors: mod.parse.errors.length },
    };
  }
  const callGraph = buildHaskellCallGraph(perFile, proj);
  // A function the analysed code itself calls or references takes its parameters from THOSE callers, which the taint engine
  // follows per call context; treating the parameter as caller-controlled as well would flag a helper that is only ever
  // called with constants. Only a function nothing in the project reaches is an entry point whose callers are external.
  const reached = new Set();
  for (const e of callGraph.edges || []) if (e && e.callee) reached.add(e.callee);
  for (const fn of callGraph.functions.values()) for (const r of (fn.hs && fn.hs.refs) || []) if (r && r.target) reached.add(r.target);
  for (const fn of callGraph.functions.values()) if (reached.has(fn.qid)) { if (fn.paramAnnotations) delete fn.paramAnnotations; if (fn.hs && fn.hs.recordParams) fn.hs.recordParams = []; }
  return { perFile, callGraph, modules: proj.modules, diagnostics: proj.diagnostics, project: proj };
}

function incomplete(proj, mod, f, err) {
  const def = mod.defs.get(f.name);
  const cfg = new Cfg(f.line);
  proj.addFn({
    qid: def.qid, name: `${mod.name}.${f.name}`, line: f.line, params: [], file: mod.file, cfg: cfg.finish(f.line), calls: [],
    hs: { module: mod.name, kind: 'function', incomplete: true, reason: String(err && err.message), refs: [], deferred: [], diagnostics: [] },
  });
  proj.diagnostics.push({ file: mod.file, line: f.line, kind: 'ir-lowering-failure', detail: String(err && err.message) });
}

// ── call graph ───────────────────────────────────────────────────────────────
function buildHaskellCallGraph(perFile, proj) {
  const functions = new Map();
  const byName = new Map();
  for (const ir of Object.values(perFile)) for (const fn of ir.functions) { functions.set(fn.qid, fn); byName.set(fn.name, fn.qid); }

  const edges = [];
  const contexts = new Map(); // callee-with-HO-params qid -> [{caller, site, targets}]
  const push = (e) => edges.push(e);

  for (const fn of functions.values()) {
    if (fn.hs && fn.hs.incomplete) push({ caller: fn.qid, site: null, callee: null, calleeName: null, line: fn.line, kind: 'direct', status: 'unknown', reason: 'incomplete-lowering' });
    for (const c of fn.calls) {
      const hs = c.hs || {};
      const base = { caller: fn.qid, site: c.site, calleeName: c.callee, line: c.line };
      const kind = hs.via ? 'higher-order' : 'direct';
      switch (hs.status) {
        case 'resolved':
          push({ ...base, callee: hs.target, kind, status: 'resolved', via: hs.via || null });
          if (hs.argTargets) {
            if (!contexts.has(hs.target)) contexts.set(hs.target, []);
            contexts.get(hs.target).push({ caller: fn.qid, site: c.site, argTargets: hs.argTargets });
          }
          break;
        case 'typeclass': {
          const cands = hs.candidates || [];
          if (!cands.length) push({ ...base, callee: null, kind, status: 'unknown', reason: 'no-visible-instance' });
          for (const q of cands) push({ ...base, callee: q, kind, status: 'candidate', ambiguous: true, via: hs.via || null });
          if (hs.argTargets) {
            for (const q of cands) { if (!contexts.has(q)) contexts.set(q, []); contexts.get(q).push({ caller: fn.qid, site: c.site, argTargets: hs.argTargets }); }
          }
          break;
        }
        case 'external': case 'builtin':
          push({ ...base, callee: null, kind, status: hs.status, certain: hs.certain });
          break;
        default:
          push({ ...base, callee: null, kind, status: 'unknown', reason: hs.reason || (hs.status === 'param' ? 'higher-order-parameter' : 'unresolved'), paramIndex: hs.paramIndex });
      }
    }
    for (const r of (fn.hs && fn.hs.refs) || []) {
      if (functions.has(r.target)) push({ caller: fn.qid, site: null, callee: r.target, calleeName: functions.get(r.target).name, line: r.line, kind: 'reference', status: 'potential', via: r.via, ambiguous: true });
    }
  }

  // Context-specific higher-order edges: a parameter call inside F, bound to the
  // function each caller actually passes.
  for (const e of [...edges]) {
    if (e.status !== 'unknown' || e.paramIndex === undefined) continue;
    for (const ctx of contexts.get(e.caller) || []) {
      for (const t of ctx.argTargets[e.paramIndex] || []) {
        push({ caller: e.caller, site: e.site, callee: t, calleeName: functions.get(t) ? functions.get(t).name : null, line: e.line, kind: 'higher-order', status: 'resolved-in-context', context: `${e.caller}<-${ctx.caller}@${ctx.site}`, ambiguous: true });
      }
    }
  }

  const callersOf = new Map();
  for (const e of edges) {
    if (!e.callee) continue;
    if (!callersOf.has(e.callee)) callersOf.set(e.callee, []);
    callersOf.get(e.callee).push(e);
  }
  const out = new Map();
  for (const e of edges) { if (e.callee) { if (!out.has(e.caller)) out.set(e.caller, new Set()); out.get(e.caller).add(e.callee); } }
  const unknownOf = new Set(edges.filter((e) => e.status === 'unknown').map((e) => e.caller));

  const resolve = (name) => byName.get(name) || null;

  // Reachability that never concludes "unreachable" while an unknown call exists
  // on a reached path (that call could target anything).
  function reachability(roots) {
    const reached = new Set();
    const queue = [...roots].filter((r) => functions.has(r));
    let sawUnknown = false;
    while (queue.length) {
      const q = queue.pop();
      if (reached.has(q)) continue;
      reached.add(q);
      if (unknownOf.has(q)) sawUnknown = true;
      for (const t of out.get(q) || []) if (!reached.has(t)) queue.push(t);
    }
    const status = new Map();
    for (const q of functions.keys()) status.set(q, reached.has(q) ? 'reachable' : sawUnknown ? 'unknown' : 'unreachable');
    return { reached, status, sawUnknown };
  }

  // Transitive-callee summaries to a fixpoint, bounded. A hit on the cap marks
  // every summary unknown rather than returning a partial answer as complete.
  function summarize(opts = {}) {
    const cap = opts.maxIterations || HS_IR_LIMITS.maxSummaryIterations;
    const sum = new Map();
    for (const q of functions.keys()) sum.set(q, { callees: new Set(out.get(q) || []), unknown: unknownOf.has(q) });
    let iterations = 0;
    let converged = false;
    while (iterations < cap) {
      iterations++;
      let changed = false;
      for (const [q, s] of sum) {
        for (const c of [...s.callees]) {
          const cs = sum.get(c);
          if (!cs) continue;
          for (const x of cs.callees) if (!s.callees.has(x)) { s.callees.add(x); changed = true; }
          if (cs.unknown && !s.unknown) { s.unknown = true; changed = true; }
        }
      }
      if (!changed) { converged = true; break; }
    }
    if (!converged) for (const s of sum.values()) s.unknown = true;
    return { summaries: sum, converged, iterations, capped: !converged };
  }

  return { functions, edges, callersOf, resolve, resolveKnownCallee: resolve, contexts, reachability, summarize, unresolved: edges.filter((e) => e.status === 'unknown') };
}

/**
 * Lower an arbitrary handler expression (a route's `do` block or lambda) as its own synthetic function, in
 * the context of `mod`, so it can be analysed per route. Returns the function IR (`cfg`, `calls`, ...).
 */
export function lowerHandlerExpr(project, mod, exprAst, label, line = 1) {
  const qid = `${mod.file}::${mod.name}.$handler.${label}@${line}`;
  const L = new FnLowerer(project, mod, { qid, name: `${mod.name}.$handler.${label}`, line, parentName: `${mod.name}.$handler.${label}` }, []);
  L.push();
  const v = L.lowerExpr(exprAst, line);
  L.cfg.add('return', (v && v.kind === 'call' && v.line) || line, { value: v || unknownExpr() });
  L.pop();
  return L.finishFn({ kind: 'handler', arity: 0 });
}

export { resolveGlobal as resolveName };
export { buildHaskellCallGraph };
export const _internals = { sigInfo, resolveGlobal, argTargets, strictNames };
