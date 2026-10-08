// Nix expression/config IR (NIX-001).
//
// Normalizes a parsed Nix file (nix-parser.js) into a bounded configuration IR:
// flattened attribute assignments with full attribute paths and original spans,
// an attribute tree that merges `a = { x = 1; }; a.y = 2;` style definitions,
// import / callPackage edges, flake inputs and outputs, overlays, functions and
// string/path interpolations.
//
// What it will not do is evaluate. Whatever it cannot know statically is exposed
// in `unresolved` instead of being guessed: dynamic attribute names, dynamic or
// non-literal imports, import cycles and missing import targets (graph level),
// lazy recursion (`rec` / `let` cycles and fixed-point helpers), syntax errors
// and parser/IR budget hits. A literal string is `{literal}`; anything with an
// interpolation is `{literal:null, interpolated:true}`, so interpolated text is
// never mistaken for a constant.
//
// Comments and string contents are not nodes, so an option name appearing in
// either can never produce an assignment.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseNix, childrenOf } from './nix-parser.js';

export const DEFAULT_IR_BUDGETS = Object.freeze({
  maxBindings: 20_000,
  maxImports: 5_000,
  maxFunctions: 2_000,
  maxInterpolations: 5_000,
  maxIrDepth: 400,
  maxSiblings: 500,
});

export const DEFAULT_GRAPH_BUDGETS = Object.freeze({
  maxFiles: 200,
  maxImportDepth: 50,
});

const PRIORITY_WRAPPERS = new Set(['mkDefault', 'mkForce', 'mkOverride', 'mkBefore', 'mkAfter', 'mkOptionDefault', 'mkVMOverride', 'mkAfter']);
const COND_WRAPPERS = new Set(['mkIf', 'optionalAttrs']);
const BUILDER_CALLEE = /^(mkDerivation|buildPythonPackage|buildPythonApplication|buildGoModule|buildRustPackage|buildNpmPackage|mkShell|buildFHSEnv|runCommand|writeShellScriptBin)$/;
const FIXPOINT_FUNCS = new Set(['fix', 'fix\'', 'extends', 'makeExtensible', 'makeScope', 'makeScopeWithSplicing']);

const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };

/** Splits `f a b` into its callee and arguments. */
function appChain(node) {
  const args = [];
  let fn = node;
  while (fn && fn.type === 'app') { args.unshift(fn.arg); fn = fn.fn; }
  return { fn, args };
}

/** `foo` or `lib.foo` or `pkgs.lib.foo` -> 'foo'; anything else null. */
function calleeName(fn) {
  const f = unparen(fn);
  if (!f) return null;
  if (f.type === 'ident') return f.name;
  if (f.type === 'select' && f.attrpath.length) {
    const last = f.attrpath[f.attrpath.length - 1];
    if (last.kind === 'static') return last.name;
  }
  return null;
}

function staticPath(segs) {
  const out = [];
  let dynamic = false;
  for (const s of segs) {
    if (s.kind === 'static') out.push(s.name); else { out.push(null); dynamic = true; }
  }
  return { path: out, dynamic };
}

export function foldLiteralPath(node) {
  const n = unparen(node);
  if (!n) return null;
  if (n.type === 'path' && !n.interpolated) return n.literal;
  if (n.type === 'string' && !n.interpolated) return n.literal;
  if (n.type === 'binop' && n.op === '+') {
    const l = foldLiteralPath(n.left);
    const r = foldLiteralPath(n.right);
    if (l !== null && r !== null && unparen(n.left).type === 'path') return l.replace(/\/$/, '') + (r.startsWith('/') ? '' : '/') + r.replace(/^\//, '');
  }
  return null;
}

export function resolveImportPath(fromFile, literal) {
  if (typeof literal !== 'string' || !literal) return null;
  if (literal.startsWith('/')) return path.posix.normalize(literal);
  if (literal.startsWith('~')) return null;
  const dir = path.posix.dirname(String(fromFile || 'default.nix').split(path.sep).join('/'));
  return path.posix.normalize(path.posix.join(dir, literal));
}

class IrBuilder {
  constructor(parse, opts) {
    this.parse = parse;
    this.file = opts.file || parse.file || null;
    this.source = typeof opts.source === 'string' ? opts.source : null;
    this.b = { ...DEFAULT_IR_BUDGETS, ...(opts.budgets || {}) };
    this.bindings = [];
    this.imports = [];
    this.overlays = [];
    this.functions = [];
    this.interpolations = [];
    this.unresolved = [];
    this.truncated = new Set();
    this.seen = new Set();
  }

  snippet(node) {
    if (!this.source) return null;
    const t = this.source.slice(node.start, Math.min(node.end, node.start + 120));
    return t.length < node.end - node.start ? `${t}...` : t;
  }

  gap(kind, detail, span, extra = {}) {
    const key = `${kind}:${span ? span.startOffset : ''}:${detail}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.unresolved.push({ kind, detail, span: span || null, ...extra });
  }

  budget(name) {
    if (!this.truncated.has(name)) {
      this.truncated.add(name);
      this.gap('ir-budget', `IR budget "${name}" reached (limit ${this.b[name]}); the rest of the file is not in the IR`, null);
    }
  }

  summarize(node) {
    const n = unparen(node);
    if (!n) return { type: 'none' };
    switch (n.type) {
      case 'string':
        return {
          type: 'string', literal: n.literal, interpolated: n.interpolated, indented: n.indented,
          interpolations: n.parts.filter((p) => p.kind === 'interp').map((p) => ({ span: p.span, exprKind: unparen(p.expr).type, text: this.snippet(p.expr) })),
        };
      case 'path': return { type: 'path', literal: n.literal, interpolated: n.interpolated, pathKind: n.pathKind };
      case 'spath': return { type: 'search-path', literal: n.value, interpolated: false };
      case 'uri': return { type: 'uri', literal: n.value, interpolated: false };
      case 'int': case 'float': return { type: 'number', value: n.value };
      case 'ident':
        if (n.name === 'true' || n.name === 'false') return { type: 'bool', value: n.name === 'true' };
        if (n.name === 'null') return { type: 'null', value: null };
        return { type: 'reference', name: n.name };
      case 'list': return { type: 'list', length: n.items.length, items: n.items.slice(0, 64).map((x) => this.summarize(x)) };
      case 'attrset': return { type: 'attrset', rec: n.rec };
      case 'lambda': return { type: 'function', params: n.param.kind === 'ident' ? [n.param.name] : n.param.formals.map((f) => f.name) };
      default: return { type: 'expression', kind: n.type, text: this.snippet(n) };
    }
  }

  addBinding(rec) {
    if (this.bindings.length >= this.b.maxBindings) { this.budget('maxBindings'); return null; }
    this.bindings.push(rec);
    return rec;
  }

  /** Returns the assignments a value node contributes under `ctx.prefix`. */
  flatten(node, ctx, depth) {
    const n = unparen(node);
    if (!n) return [];
    if (depth > this.b.maxIrDepth) { this.budget('maxIrDepth'); return []; }
    switch (n.type) {
      case 'attrset': return this.flattenAttrs(n, ctx, depth);
      // `evalWrap` remembers the OUTERMOST let/with that wraps a leaf value (through nothing but let, with, assert and parentheses), so
      // the module resolver can evaluate the whole wrapper with correct scoping instead of the bare body. Any other combinator clears it.
      case 'let': {
        const out = this.recordScoped(n, 'let', ctx);
        return out.concat(this.flatten(n.body, { ...ctx, evalWrap: ctx.evalWrap || { span: n.span, withs: ctx.withs } }, depth + 1));
      }
      case 'with': return this.flatten(n.body, { ...ctx, withs: [...ctx.withs, this.snippet(n.env)], evalWrap: ctx.evalWrap || { span: n.span, withs: ctx.withs } }, depth + 1);
      case 'assert': return this.flatten(n.body, { ...ctx, evalWrap: ctx.evalWrap || { span: n.span, withs: ctx.withs } }, depth + 1);
      case 'if': {
        const c = { kind: 'if', span: n.cond.span, text: this.snippet(n.cond) };
        return this.flatten(n.then, { ...ctx, evalWrap: null, conditions: [...ctx.conditions, { ...c, branch: 'then' }] }, depth + 1)
          .concat(this.flatten(n.else, { ...ctx, evalWrap: null, conditions: [...ctx.conditions, { ...c, branch: 'else' }] }, depth + 1));
      }
      case 'binop':
        if (n.op === '//') {
          const left = this.flatten(n.left, { ...ctx, evalWrap: null }, depth + 1);
          const right = this.flatten(n.right, { ...ctx, evalWrap: null }, depth + 1);
          const over = new Set();
          for (const r of right) if (r.path.length > ctx.prefix.length && r.path[ctx.prefix.length] !== null) over.add(r.path[ctx.prefix.length]);
          const kept = [];
          for (const l of left) {
            if (over.has(l.path[ctx.prefix.length])) l.overridden = true;
            else kept.push(l);
          }
          for (const r of right) r.update = true;
          return kept.concat(right);
        }
        return this.leaf(n, ctx);
      case 'app': {
        const { fn, args } = appChain(n);
        const name = calleeName(fn);
        if (name === 'mkMerge' && args.length === 1 && unparen(args[0]).type === 'list') {
          let out = [];
          for (const it of unparen(args[0]).items) out = out.concat(this.flatten(it, { ...ctx, evalWrap: null, merge: 'mkMerge' }, depth + 1));
          return out;
        }
        if (COND_WRAPPERS.has(name) && args.length === 2) {
          const cond = { kind: name, span: args[0].span, text: this.snippet(args[0]), branch: 'then' };
          return this.flatten(args[1], { ...ctx, evalWrap: null, conditions: [...ctx.conditions, cond] }, depth + 1);
        }
        if (PRIORITY_WRAPPERS.has(name) && args.length >= 1) {
          // mkOverride carries its numeric priority as the first argument; keep it so the module resolver can rank it
          const priorityArg = name === 'mkOverride' && args.length >= 2 ? this.summarize(args[0]) : null;
          return this.flatten(args[args.length - 1], { ...ctx, evalWrap: null, priority: name, priorityArg }, depth + 1);
        }
        // a file that is just `mkDerivation { ... }` / `callPackage ./x.nix { ... }`: the last attrset argument is the configuration
        if (!ctx.prefix.length && args.length) {
          const last = unparen(args[args.length - 1]);
          if (last && last.type === 'attrset') return this.flattenAttrs(last, { ...ctx, callee: name }, depth + 1);
        }
        return this.leaf(n, ctx);
      }
      default: return this.leaf(n, ctx);
    }
  }

  leaf(n, ctx) {
    if (!ctx.prefix.length) return [];
    const rec = this.addBinding({
      path: ctx.prefix, pathText: ctx.prefix.map((p) => (p === null ? '${...}' : p)).join('.'),
      value: this.summarize(n), span: ctx.span || n.span, valueSpan: n.span,
      origin: ctx.origin || 'attr', scope: ctx.scope, dynamic: ctx.prefix.includes(null),
      conditions: ctx.conditions, priority: ctx.priority || null, merge: ctx.merge || null,
      withs: ctx.withs, overridden: false, update: false, callee: ctx.callee || null,
    });
    if (rec && ctx.priorityArg) rec.priorityArg = ctx.priorityArg;
    if (rec && ctx.evalWrap) { rec.evalSpan = ctx.evalWrap.span; rec.evalWiths = ctx.evalWrap.withs; }
    if (rec && ctx.inRec) rec.inRec = true;
    if (rec && n.type === 'lambda') this.noteBoundaryLambda(n, ctx);
    return rec ? [rec] : [];
  }

  /** The `outputs` function of a flake is analyzed as its own root. */
  noteBoundaryLambda(n, ctx) {
    if (ctx.scope === 'file' && ctx.prefix.length === 1 && ctx.prefix[0] === 'outputs') {
      let body = n;
      while (body && body.type === 'lambda') body = body.body;
      this.flatten(body, { prefix: [], scope: 'outputs', conditions: [], withs: [], priority: null, merge: null }, 1);
    }
  }

  flattenAttrs(n, ctx, depth) {
    let out = [];
    for (const b of n.bindings) {
      if (b.kind === 'inherit') {
        for (const nm of b.names) {
          if (nm.kind !== 'static') { this.gap('dynamic-attribute', 'dynamic name in inherit', nm.span); continue; }
          const rec = this.addBinding({
            path: [...ctx.prefix, nm.name], pathText: [...ctx.prefix, nm.name].join('.'),
            value: { type: 'inherit', from: b.from ? this.snippet(b.from) : null, name: nm.name }, span: b.span, valueSpan: nm.span,
            origin: 'inherit', scope: ctx.scope, dynamic: false, conditions: ctx.conditions, priority: null, merge: ctx.merge || null,
            withs: ctx.withs, overridden: false, update: false,
          });
          if (rec) out.push(rec);
        }
        continue;
      }
      const { path: segs, dynamic } = staticPath(b.path);
      if (dynamic) {
        for (const s of b.path) if (s.kind !== 'static') this.gap('dynamic-attribute', `attribute name computed at evaluation time (${this.snippet({ start: s.span.startOffset, end: s.span.endOffset }) || 'interpolated'})`, s.span);
      }
      const sub = { ...ctx, prefix: [...ctx.prefix, ...segs], span: b.span, origin: 'attr', evalWrap: null, inRec: ctx.inRec || !!n.rec };
      out = out.concat(this.flatten(b.value, sub, depth + 1));
    }
    return out;
  }

  /** let bindings, recorded under scope `let` so they never read as option assignments. */
  recordScoped(n, scope, ctx) {
    const out = [];
    for (const b of n.bindings) {
      if (b.kind === 'inherit') {
        for (const nm of b.names) if (nm.kind === 'static') {
          const r = this.addBinding({ path: [nm.name], pathText: nm.name, value: { type: 'inherit', from: b.from ? this.snippet(b.from) : null, name: nm.name }, span: b.span, valueSpan: nm.span, origin: 'inherit', scope, dynamic: false, conditions: ctx.conditions, priority: null, merge: null, withs: ctx.withs, overridden: false, update: false });
          if (r) out.push(r);
        }
        continue;
      }
      const { path: segs, dynamic } = staticPath(b.path);
      const r = this.addBinding({ letSpan: n.span, path: segs, pathText: segs.map((p) => (p === null ? '${...}' : p)).join('.'), value: this.summarize(b.value), span: b.span, valueSpan: b.value.span, origin: 'let', scope, dynamic, conditions: ctx.conditions, priority: null, merge: null, withs: ctx.withs, overridden: false, update: false });
      if (r) out.push(r);
      if (dynamic) this.gap('dynamic-attribute', 'dynamic attribute name in let binding', b.span);
    }
    return out;
  }

  // ── whole-tree pass: imports, functions, interpolations, laziness ──

  walkAll(root) {
    const stack = [root];
    while (stack.length) {
      const n = stack.pop();
      this.visit(n);
      const kids = childrenOf(n);
      for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
    }
  }

  visit(n) {
    switch (n.type) {
      case 'lambda': {
        if (this.functions.length < this.b.maxFunctions) {
          this.functions.push({
            kind: n.param.kind, params: n.param.kind === 'ident' ? [n.param.name] : n.param.formals.map((f) => f.name),
            ellipsis: n.param.ellipsis, atName: n.param.atName, span: n.span,
          });
        } else this.budget('maxFunctions');
        break;
      }
      case 'string': case 'path': {
        for (const p of n.parts) if (p.kind === 'interp') this.noteInterp(n, p);
        break;
      }
      case 'app': {
        const { fn, args } = appChain(n);
        const name = calleeName(fn);
        const f = unparen(fn);
        if (f && f.type === 'ident' && f.name === 'import' && args.length >= 1 && !this.chainSeen(n)) this.noteImport('import', args[0], n);
        else if ((name === 'callPackage' || name === 'callPackages') && args.length >= 1 && !this.chainSeen(n)) this.noteImport('call-package', args[0], n);
        else if (name && FIXPOINT_FUNCS.has(name) && !this.chainSeen(n)) this.gap('lazy-recursion', `fixed-point helper "${name}" builds a lazily recursive value that is not evaluated`, n.span, { name });
        break;
      }
      case 'attrset': case 'let': {
        if (n.type === 'attrset') for (const b of n.bindings) {
          if (b.kind !== 'attr') continue;
          const last = b.path[b.path.length - 1];
          if (last && last.kind === 'static' && last.name === 'imports') this.noteImportsList(b);
          if (last && last.kind === 'static' && last.name === 'overlays') this.noteOverlays(b);
        }
        if (n.type === 'attrset' && n.rec) this.checkRecursion(n, 'rec attribute set');
        else if (n.type === 'let') this.checkRecursion(n, 'let');
        break;
      }
      default: break;
    }
  }

  chainSeen(n) {
    // an app chain `f a b` is nested as app(app(f,a),b); report once, from the outermost node
    this.chains = this.chains || new Set();
    const { fn } = appChain(n);
    const key = `${fn.start}:${fn.end}`;
    if (this.chains.has(key)) return true;
    this.chains.add(key);
    return false;
  }

  noteInterp(owner, part) {
    if (this.interpolations.length >= this.b.maxInterpolations) { this.budget('maxInterpolations'); return; }
    this.interpolations.push({
      span: part.span, exprKind: unparen(part.expr).type, text: this.snippet(part.expr),
      context: owner.type === 'path' ? 'path' : owner.indented ? 'indented-string' : 'string', ownerSpan: owner.span,
    });
  }

  noteImportsList(b) {
    const v = unparen(b.value);
    if (!v) return;
    if (v.type === 'list') { for (const it of v.items) this.addImport('module-import', it, b.span); return; }
    this.addImport('module-import', v, b.span);
  }

  noteImport(kind, target, call) {
    this.addImport(kind, target, call.span);
  }

  addImport(kind, target, viaSpan) {
    if (this.imports.length >= this.b.maxImports) { this.budget('maxImports'); return; }
    const t = unparen(target);
    const folded = foldLiteralPath(t);
    let rec;
    if (t.type === 'path' || (folded !== null && t.type !== 'string') || (t.type === 'string' && folded !== null && folded.startsWith('/'))) {
      if (folded !== null) {
        rec = { kind, target: { type: 'path', literal: folded }, literal: true, resolved: resolveImportPath(this.file, folded), span: t.span, viaSpan };
      } else {
        rec = { kind, target: { type: 'path', literal: null, interpolated: true }, literal: false, resolved: null, span: t.span, viaSpan };
        this.gap('dynamic-import', `import target contains an interpolation and cannot be resolved statically (${this.snippet(t)})`, t.span, { importKind: kind });
      }
    } else if (t.type === 'spath') {
      rec = { kind, target: { type: 'search-path', literal: t.value }, literal: true, external: true, resolved: null, span: t.span, viaSpan };
    } else {
      rec = { kind, target: { type: t.type === 'string' ? 'string' : 'expression', literal: t.type === 'string' ? t.literal : null, text: this.snippet(t) }, literal: false, resolved: null, span: t.span, viaSpan };
      this.gap('dynamic-import', `import target is not a literal path (${t.type}: ${this.snippet(t)})`, t.span, { importKind: kind });
    }
    this.imports.push(rec);
  }

  noteOverlays(b) {
    const v = unparen(b.value);
    if (!v || v.type !== 'list') return;
    for (const it of v.items) {
      const l = unparen(it);
      if (l.type === 'lambda') this.addOverlay(l);
      else this.overlays.push({ kind: 'reference', span: l.span, text: this.snippet(l), bindings: 0 });
    }
  }

  addOverlay(l) {
    const params = [];
    let body = l;
    while (body && body.type === 'lambda' && params.length < 2) { params.push(body.param.kind === 'ident' ? body.param.name : '{pattern}'); body = body.body; }
    const before = this.bindings.length;
    this.flatten(body, { prefix: [], scope: 'overlay', conditions: [], withs: [], priority: null, merge: null }, 1);
    this.overlays.push({ kind: 'function', params, span: l.span, bindings: this.bindings.length - before });
  }

  /** Reports bindings that sit on a reference cycle among their siblings. */
  checkRecursion(n, what) {
    const names = new Map();
    for (const b of n.bindings) {
      if (b.kind === 'attr' && b.path[0] && b.path[0].kind === 'static') names.set(b.path[0].name, b);
      else if (b.kind === 'inherit') for (const nm of b.names) if (nm.kind === 'static') names.set(nm.name, null);
    }
    if (names.size === 0 || names.size > this.b.maxSiblings) { if (names.size > this.b.maxSiblings) this.budget('maxSiblings'); return; }
    const refs = new Map();
    for (const [name, b] of names) {
      const set = new Set();
      if (b) {
        const stack = [b.value];
        let guard = 0;
        while (stack.length && guard++ < 20_000) {
          const x = stack.pop();
          if (!x) continue;
          if (x.type === 'ident' && names.has(x.name)) set.add(x.name);
          for (const k of childrenOf(x)) stack.push(k);
        }
      }
      refs.set(name, set);
    }
    const reaches = (from, to) => {
      const seen = new Set();
      const st = [...refs.get(from)];
      while (st.length) {
        const c = st.pop();
        if (c === to) return true;
        if (seen.has(c)) continue;
        seen.add(c);
        for (const nx of refs.get(c) || []) st.push(nx);
      }
      return false;
    };
    for (const [name, b] of names) {
      if (b && reaches(name, name)) this.gap('lazy-recursion', `"${name}" refers back to itself through ${what} siblings (${[...refs.get(name)].join(', ')}); its value is only defined lazily and is not evaluated`, b.span, { name });
    }
  }
}

function classify(ast, bindings, file) {
  let root = unparen(ast);
  if (!root) return 'expression';
  const base = String(file || '').split('/').pop();
  let lam = null;
  while (root && root.type === 'lambda') { lam = lam || root; root = unparen(root.body); }
  while (root && (root.type === 'let' || root.type === 'with' || root.type === 'assert')) root = unparen(root.body);
  const top = new Set(bindings.filter((b) => b.scope === 'file' && b.path.length >= 1).map((b) => b.path[0]));
  if (!lam && root && root.type === 'attrset' && top.has('outputs') && (top.has('inputs') || top.has('description') || base === 'flake.nix')) return 'flake';
  if (lam && lam.param.kind === 'ident' && lam.body && unparen(lam.body).type === 'lambda' && unparen(unparen(lam.body).body) && ['attrset', 'let', 'with'].includes(unparen(unparen(lam.body).body).type)) return 'overlay';
  const formals = lam && lam.param.kind === 'pattern' ? new Set(lam.param.formals.map((f) => f.name)) : new Set();
  if (formals.has('config') || formals.has('options') || formals.has('modulesPath') || top.has('imports') || top.has('options') || top.has('config')) return 'module';
  if (bindings.some((b) => b.callee && BUILDER_CALLEE.test(b.callee))) return 'package';
  if (formals.has('stdenv') || formals.has('mkDerivation') || formals.has('callPackage') || formals.has('fetchurl') || formals.has('fetchFromGitHub')) return 'package';
  return 'expression';
}

/**
 * Builds the config IR from a parseNix() result.
 * @param {object} parse
 * @param {{file?:string, source?:string, budgets?:object}} [opts]
 */
export function buildNixIR(parse, opts = {}) {
  const ib = new IrBuilder(parse, opts);
  const ir = {
    kind: 'nix-config-ir', version: 1, file: ib.file, status: parse.status, fileKind: 'expression',
    bindings: ib.bindings, imports: ib.imports, overlays: ib.overlays, functions: ib.functions, interpolations: ib.interpolations,
    unresolved: ib.unresolved, conflicts: [], flake: null, attrTree: null, truncated: [], usedNixBinary: false,
  };
  for (const e of parse.errors || []) ib.gap('syntax-error', e.detail, e.span);
  if (parse.status === 'budget_exceeded') ib.gap('budget-exceeded', `parser budget "${parse.budget.name}" exceeded (limit ${parse.budget.limit}); the file was not analyzed`, null, { budget: parse.budget.name });
  if (parse.status === 'missing_grammar') ib.gap('missing-grammar', parse.gap ? parse.gap.detail : 'Nix grammar unavailable', null);
  if (parse.status === 'failed' && !(parse.errors || []).length) ib.gap('parse-failed', 'file could not be parsed', null);
  if (!parse.ast) { ir.truncated = [...ib.truncated]; return ir; }

  // peel root lambdas so their bodies are the module/flake body
  let body = unparen(parse.ast);
  let rootFn = null;
  while (body && body.type === 'lambda') { rootFn = rootFn || body; body = unparen(body.body); }
  const ctx = { prefix: [], scope: 'file', conditions: [], withs: [], priority: null, merge: null };
  ib.flatten(body, ctx, 1);
  ib.walkAll(parse.ast);
  ir.fileKind = classify(parse.ast, ib.bindings, ib.file);
  if (rootFn) ir.rootFunction = { kind: rootFn.param.kind, params: rootFn.param.kind === 'ident' ? [rootFn.param.name] : rootFn.param.formals.map((f) => f.name), ellipsis: rootFn.param.ellipsis, span: rootFn.span };
  if (ir.fileKind === 'overlay') {
    const l = unparen(parse.ast);
    if (!ib.overlays.some((o) => o.span.startOffset === l.span.startOffset)) ib.addOverlay(l);
  }
  ir.attrTree = buildAttrTree(ib.bindings, ir.conflicts);
  if (ir.fileKind === 'flake') ir.flake = flakeInfo(ib.bindings);
  ir.truncated = [...ib.truncated];
  if (parse.status === 'partial') ir.status = 'partial';
  else if (ib.unresolved.length) ir.status = 'partial';
  return ir;
}

function flakeInfo(bindings) {
  const flake = { description: null, inputs: [], outputs: null };
  const inputs = new Map();
  for (const b of bindings) {
    if (b.scope !== 'file' || b.origin === 'let') continue;
    if (b.path[0] === 'description' && b.path.length === 1) flake.description = b.value.literal === undefined ? null : b.value.literal;
    if (b.path[0] === 'outputs' && b.path.length === 1) {
      flake.outputs = { span: b.valueSpan, params: b.value.type === 'function' ? b.value.params : [] };
    }
    if (b.path[0] === 'inputs' && b.path.length >= 2 && b.path[1] !== null) {
      const name = b.path[1];
      if (!inputs.has(name)) inputs.set(name, { name, url: null, follows: null, flake: true, nestedFollows: [], span: b.span, dynamic: false });
      const inp = inputs.get(name);
      if (b.path.length === 2 && b.value.type === 'string') inp.url = b.value.literal;
      else if (b.path[2] === 'url' && b.path.length === 3) { inp.url = b.value.literal === undefined ? null : b.value.literal; if (b.value.interpolated) inp.dynamic = true; }
      else if (b.path[2] === 'follows' && b.path.length === 3) inp.follows = b.value.literal === undefined ? null : b.value.literal;
      else if (b.path[2] === 'flake' && b.path.length === 3) inp.flake = b.value.type === 'bool' ? b.value.value : true;
      else if (b.path[2] === 'inputs' && b.path[b.path.length - 1] === 'follows') inp.nestedFollows.push({ path: b.path.slice(3, -1), follows: b.value.literal === undefined ? null : b.value.literal });
    }
  }
  flake.inputs = [...inputs.values()];
  return flake;
}

function buildAttrTree(bindings, conflicts) {
  const root = { children: new Map(), bindings: [] };
  for (const b of bindings) {
    if (b.scope === 'let' || b.dynamic || b.overridden || !b.path.length) continue;
    let node = root;
    for (const seg of b.path) {
      if (!node.children.has(seg)) node.children.set(seg, { children: new Map(), bindings: [] });
      node = node.children.get(seg);
    }
    node.bindings.push(b);
  }
  const walk = (node, p) => {
    const plain = node.bindings.filter((b) => !b.merge && !b.conditions.length && !b.priority);
    if (plain.length > 1) conflicts.push({ kind: 'duplicate-definition', path: p, spans: plain.map((b) => b.span) });
    if (node.bindings.length && node.children.size && node.bindings.some((b) => b.value.type !== 'attrset' && b.value.type !== 'expression')) conflicts.push({ kind: 'value-and-subattributes', path: p, spans: node.bindings.map((b) => b.span) });
    for (const [k, c] of node.children) walk(c, [...p, k]);
  };
  walk(root, []);
  return root;
}

/** Definitions at exactly `attrPath` (array or dotted string). */
export function lookupAttr(ir, attrPath) {
  const segs = Array.isArray(attrPath) ? attrPath : String(attrPath).split('.');
  let node = ir.attrTree;
  for (const s of segs) {
    if (!node) return [];
    node = node.children.get(s);
  }
  return node ? node.bindings : [];
}

/**
 * Parses and builds the IR in one call. Never throws.
 */
export function analyzeNix(source, opts = {}) {
  const parse = parseNix(source, opts);
  const ir = buildNixIR(parse, { file: opts.file, source: typeof source === 'string' ? source : null, budgets: opts.irBudgets });
  return { parse, ir };
}

/**
 * Bounded static import graph. Follows only literal local path imports; reads files
 * through `readFile` (default: confined to `root`), never runs nix.
 * @param {string} entry entry file path, relative to root
 * @param {{root?:string, readFile?:(p:string)=>string|null, budgets?:object, parseBudgets?:object}} [opts]
 */
export function buildNixImportGraph(entry, opts = {}) {
  const budgets = { ...DEFAULT_GRAPH_BUDGETS, ...(opts.budgets || {}) };
  const root = opts.root ? path.resolve(opts.root) : null;
  const read = opts.readFile || ((p) => {
    if (!root) return null;
    const abs = path.resolve(root, p);
    if (abs !== root && !abs.startsWith(root + path.sep)) return null;
    try {
      const st = fs.statSync(abs);
      if (!st.isFile()) return null;
      return fs.readFileSync(abs, 'utf8');
    } catch { return null; }
  });
  const graph = { entry, files: [], edges: [], unresolved: [], truncated: false, usedNixBinary: false };
  const done = new Map();
  const cycles = new Set();
  const norm = (p) => path.posix.normalize(String(p).split(path.sep).join('/'));

  const visit = (file, chain) => {
    if (chain.length > budgets.maxImportDepth) {
      graph.truncated = true;
      graph.unresolved.push({ kind: 'import-depth', detail: `import chain deeper than ${budgets.maxImportDepth}`, file, span: null });
      return;
    }
    if (done.has(file)) return;
    if (done.size >= budgets.maxFiles) {
      if (!graph.truncated) graph.unresolved.push({ kind: 'import-budget', detail: `more than ${budgets.maxFiles} files in the import graph`, file, span: null });
      graph.truncated = true;
      return;
    }
    const text = read(file);
    if (text === null || text === undefined) { done.set(file, { file, status: 'missing' }); return; }
    const { parse, ir } = analyzeNix(text, { file, budgets: opts.parseBudgets });
    done.set(file, { file, status: ir.status, fileKind: ir.fileKind });
    for (const u of ir.unresolved) graph.unresolved.push({ ...u, file });
    for (const imp of ir.imports) {
      if (!imp.literal || imp.external || !imp.resolved) continue;
      const cands = /\.nix$/.test(imp.resolved) ? [imp.resolved] : [`${imp.resolved}/default.nix`, imp.resolved];
      let target = null;
      for (const c of cands) {
        const k = norm(c);
        if (chain.includes(k) || k === file || done.has(k) || (read(k) !== null && read(k) !== undefined)) { target = k; break; }
      }
      if (!target) {
        graph.unresolved.push({ kind: 'missing-import', detail: `imported file ${imp.resolved} does not exist or is outside the scanned root`, file, span: imp.span });
        continue;
      }
      graph.edges.push({ from: file, to: target, kind: imp.kind, span: imp.span });
      if (target === file || chain.includes(target)) {
        const cyc = [...chain.slice(chain.indexOf(target) >= 0 ? chain.indexOf(target) : chain.length), file, target];
        const key = [...new Set(cyc)].sort().join('|');
        if (!cycles.has(key)) {
          cycles.add(key);
          graph.unresolved.push({ kind: 'import-cycle', detail: `import cycle: ${cyc.join(' -> ')}`, file, span: imp.span, cycle: cyc });
        }
        continue;
      }
      visit(target, [...chain, file]);
    }
    void parse;
  };
  visit(norm(entry), []);
  graph.files = [...done.values()];
  return graph;
}
