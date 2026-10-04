// Bounded effective NixOS / Home Manager configuration reasoning (NIX-002).
//
// Documented static subset. Given entry module file(s) it follows LITERAL local
// imports (nix-ir's bounded import graph, never `nix`), collects every assignment of
// each option, and decides the effective value by the module system's own rules:
//
//   * priorities: mkForce 50, plain 100, mkDefault 1000, mkOptionDefault 1500,
//     mkOverride N (literal N only), lower number wins; mkMerge/mkBefore/mkAfter do
//     not change priority;
//   * conditions: `mkIf`, `optionalAttrs`, `if/else`, judged by a small evaluator
//     (booleans, strings, ints, `!`, `&&`, `||`, `->`, `==`, `!=`, references to
//     `config.<option>` and let-aliases of them, `pkgs.stdenv.isLinux`-style platform
//     flags from `target.system`, and function arguments supplied in `target.args`).
//     Anything else is UNKNOWN, and an unknown condition keeps its definition
//     "conditional", it is never assumed true or false;
//   * list options merge; scalar options with equal-priority different values are a
//     `conflict`; an option whose type is not cataloged with such a disagreement is
//     `unresolved-precedence`. A winner is never guessed.
//
// A missing setting gets a default only when the catalog PROVES it for the release in
// force (or for every cataloged release). The release comes from `target.release` or a
// flake `nixpkgs` input, NEVER from `system.stateVersion`, which is a state
// compatibility marker and is reported separately.
//
// Home Manager options live in their own namespace, scoped per user
// (`home-manager.users.<u>` or a module imported from it), and never merge with NixOS
// options of the same spelling.
//
// Evaluation is capped (`DEFAULT_RESOLVE_BUDGETS`); a cap reports `truncated` and the
// affected option is `unknown`. Cyclic references converge to `unknown` the same way.

import * as path from 'node:path';
import { parseNix, spanText } from './nix-parser.js';
import { analyzeNix, buildNixImportGraph } from './nix-ir.js';
import { defaultCatalog, normalizeRelease } from './nixos-option-catalog.js';

export const DEFAULT_RESOLVE_BUDGETS = Object.freeze({
  maxEvaluations: 20_000,
  maxEvalDepth: 24,
  maxDefinitionsPerOption: 500,
  maxFiles: 200,
});

const PRIORITY = { mkForce: 50, mkVMOverride: 10, mkDefault: 1000, mkOptionDefault: 1500, mkBefore: 100, mkAfter: 100 };
const SKIP_TOP = new Set(['options', 'meta', 'imports', '_module', 'inputs', 'outputs', 'description', 'disabledModules']);
const BLOCKER_KINDS = new Set(['dynamic-import', 'missing-import', 'import-cycle', 'syntax-error', 'budget-exceeded', 'import-budget', 'import-depth', 'ir-budget', 'missing-grammar', 'parse-failed', 'opaque-config', 'flake-modules-not-followed']);
const UNK = Object.freeze({ known: false });
const known = (value) => ({ known: true, value });

class Cap extends Error {
  constructor(budget, limit) { super(`budget ${budget}`); this.budget = budget; this.limit = limit; }
}

const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };
const sameValue = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const within = (outer, inner) => outer && inner && outer.startOffset <= inner.startOffset && inner.endOffset <= outer.endOffset;

function platformFlags(system) {
  if (typeof system !== 'string' || !system.includes('-')) return null;
  const [cpu, os] = system.split('-');
  return { isLinux: os === 'linux', isDarwin: os === 'darwin', isx86_64: cpu === 'x86_64', isAarch64: cpu === 'aarch64' };
}

class Resolver {
  constructor(opts) {
    this.opts = opts;
    this.b = { ...DEFAULT_RESOLVE_BUDGETS, ...(opts.budgets || {}) };
    this.catalog = opts.catalog || defaultCatalog();
    this.target = opts.target || {};
    this.irs = new Map();
    this.sources = new Map();
    this.fileNs = new Map();
    this.unresolved = [];
    this.truncated = [];
    this.defs = new Map();
    this.opaque = [];
    this.dynamicPrefixes = [];
    this.overlays = [];
    this.unknownOptions = new Map();
    this.renamed = new Map();
    this.memo = new Map();
    this.stack = new Set();
    this.parseCache = new Map();
    this.steps = 0;
  }

  gap(g) { this.unresolved.push(g); }

  cap(name, limit, detail) {
    if (!this.truncated.some((t) => t.budget === name)) this.truncated.push({ budget: name, limit, detail });
    return new Cap(name, limit);
  }

  // ── loading ──

  read(file) {
    const { readFile, files } = this.opts;
    if (files) return Object.prototype.hasOwnProperty.call(files, file) ? files[file] : null;
    return readFile ? readFile(file) : null;
  }

  load() {
    const entries = [].concat(this.opts.entry || []).map((e) => path.posix.normalize(String(e).split(path.sep).join('/')));
    const edges = [];
    const order = [];
    for (const entry of entries) {
      const graph = buildNixImportGraph(entry, { root: this.opts.root, readFile: (p) => this.read(p), budgets: { maxFiles: this.b.maxFiles } });
      for (const u of graph.unresolved) this.gap({ ...u });
      if (graph.truncated) this.truncated.push({ budget: 'maxFiles', limit: this.b.maxFiles, detail: 'import graph truncated' });
      for (const e of graph.edges) edges.push(e);
      for (const f of graph.files) if (!order.includes(f.file)) order.push(f.file);
    }
    for (const file of order) {
      const text = this.read(file);
      if (text === null || text === undefined) continue;
      const { ir } = analyzeNix(text, { file });
      this.irs.set(file, ir);
      this.sources.set(file, text);
      if (ir.fileKind === 'flake') this.gap({ kind: 'flake-modules-not-followed', detail: `${file} is a flake; its module lists are not followed, pass the module files as entries`, file, span: null });
    }
    // namespace per file: entries are NixOS unless declared otherwise; imports from a home-manager user binding are that user's
    const entryNs = this.target.namespace === 'home-manager' ? { namespace: 'home-manager', scope: this.target.user || 'standalone' } : { namespace: 'nixos', scope: null };
    for (const e of entries) if (this.irs.has(e)) this.fileNs.set(e, entryNs);
    const queue = entries.filter((e) => this.irs.has(e));
    while (queue.length) {
      const from = queue.shift();
      const base = this.fileNs.get(from);
      for (const e of edges.filter((x) => x.from === from)) {
        if (this.fileNs.has(e.to) || !this.irs.has(e.to)) continue;
        const scope = base.namespace === 'nixos' ? this.homeScopeOf(this.irs.get(from), e.span) : null;
        this.fileNs.set(e.to, scope ? { namespace: 'home-manager', scope } : base);
        queue.push(e.to);
      }
    }
    this.graphEdges = edges.map((e) => ({ from: e.from, to: e.to, kind: e.kind }));
    this.order = order.filter((f) => this.fileNs.has(f));
  }

  homeScopeOf(ir, span) {
    let best = null;
    for (const b of ir.bindings) {
      if (b.scope !== 'file' || b.origin === 'let' || b.path[0] !== 'home-manager' || b.path[1] !== 'users' || typeof b.path[2] !== 'string') continue;
      if (!within(b.span, span)) continue;
      if (!best || (b.span.endOffset - b.span.startOffset) < (best.span.endOffset - best.span.startOffset)) best = b;
    }
    return best ? best.path[2] : null;
  }

  // ── definitions ──

  collect() {
    let id = 0;
    for (const file of this.order) {
      const ir = this.irs.get(file);
      const base = this.fileNs.get(file);
      for (const o of ir.overlays) this.overlays.push({ file, kind: o.kind, span: o.span, params: o.params || [], bindings: o.bindings });
      for (const b of ir.bindings) {
        if (b.scope !== 'file' || b.origin === 'let' || b.overridden || !b.path.length) continue;
        if (b.dynamic) {
          const cut = b.path.indexOf(null);
          this.dynamicPrefixes.push({ prefix: b.path.slice(0, cut), file, span: b.span, namespace: base.namespace });
          continue;
        }
        let p = b.path;
        if (p[0] === 'config' && p.length > 1) p = p.slice(1);
        else if (p[0] === 'config') {
          if (b.value.type !== 'attrset') { this.opaque.push({ prefix: [], namespace: base.namespace, scope: base.scope, file, span: b.span }); this.gap({ kind: 'opaque-config', detail: 'the module `config` is not an attribute set literal and is not followed', file, span: b.span }); }
          continue;
        }
        if (SKIP_TOP.has(p[0])) continue;
        let ns = base.namespace;
        let scope = base.scope;
        if (ns === 'nixos' && p[0] === 'home-manager' && p[1] === 'users' && typeof p[2] === 'string') {
          if (p.length === 3) {
            if (b.value.type === 'function') this.gap({ kind: 'home-manager-function-module', detail: `home-manager.users.${p[2]} is a function module whose body is not followed`, file, span: b.span });
            continue;
          }
          ns = 'home-manager'; scope = p[2]; p = p.slice(3);
          if (SKIP_TOP.has(p[0])) continue;
          if (p[0] === 'config' && p.length > 1) p = p.slice(1);
        }
        let pathText = p.join('.');
        let viaRename = null;
        const cat = ns === 'nixos' ? this.catalog.nixos : this.catalog.homeManager;
        if (cat.renames[pathText]) { viaRename = { from: pathText, to: cat.renames[pathText] }; pathText = cat.renames[pathText]; p = pathText.split('.'); }
        const def = {
          id: id++, namespace: ns, scope, path: p, pathText, file, span: b.span, valueSpan: b.valueSpan, summary: b.value,
          priorityName: b.priority || 'plain', priorityArg: b.priorityArg || null, conditions: b.conditions || [], merge: b.merge || null, viaRename,
        };
        const key = this.key(ns, scope, pathText);
        if (!this.defs.has(key)) this.defs.set(key, []);
        this.defs.get(key).push(def);
        if (b.value.type !== 'attrset' && !['bool', 'string', 'number', 'null', 'list', 'path', 'uri', 'inherit'].includes(b.value.type)) {
          this.opaque.push({ prefix: p, namespace: ns, scope, file, span: b.span, selfDef: true });
        }
        const info = this.catalogInfo(ns, pathText);
        if (viaRename) { const k = `${ns}:${viaRename.from}`; if (!this.renamed.has(k)) this.renamed.set(k, { from: viaRename.from, to: viaRename.to, namespace: ns, sources: [] }); this.renamed.get(k).sources.push({ file, span: b.span }); }
        if (info.status === 'unknown') { const k = `${ns}:${pathText}`; if (!this.unknownOptions.has(k)) this.unknownOptions.set(k, { path: pathText, namespace: ns, authoritativePrefix: info.prefix, sources: [] }); this.unknownOptions.get(k).sources.push({ file, span: b.span }); }
      }
    }
  }

  key(ns, scope, pathText) { return `${ns}|${scope || ''}|${pathText}`; }

  catalogInfo(ns, pathText) {
    const cat = ns === 'nixos' ? this.catalog.nixos : this.catalog.homeManager;
    const entry = cat.options[pathText];
    if (entry) return { status: 'known', entry };
    if (cat.renames[pathText]) return { status: 'renamed', entry: cat.options[cat.renames[pathText]] || null };
    if (cat.freeform.some((f) => pathText.startsWith(`${f}.`))) return { status: 'freeform', entry: null };
    const prefix = cat.authoritative.find((a) => pathText === a || pathText.startsWith(`${a}.`));
    if (prefix) return { status: 'unknown', entry: null, prefix };
    return { status: 'uncataloged', entry: null };
  }

  // ── release / defaults ──

  determineRelease() {
    if (this.target.release) {
      const r = normalizeRelease(this.target.release);
      return r ? { release: r, source: 'target.release' } : { release: null, source: 'unparseable-target-release' };
    }
    if (this.opts.flake && this.read(this.opts.flake) != null) {
      const { ir } = analyzeNix(this.read(this.opts.flake), { file: this.opts.flake });
      for (const inp of (ir.flake && ir.flake.inputs) || []) {
        if (!/nixpkgs/i.test(inp.name) || !inp.url) continue;
        const r = normalizeRelease(inp.url.replace(/^.*nixpkgs\//i, '/'));
        if (r) return { release: r, source: `flake-input:${inp.name}` };
      }
    }
    return { release: null, source: 'unknown' };
  }

  defaultFor(info) {
    const d = info.entry && info.entry.default;
    if (!d) return { known: false, reason: 'no-cataloged-default' };
    const rel = this.release.release;
    if (rel) {
      if (!this.catalog.releases.includes(rel)) return { known: false, reason: `release-${rel}-not-in-catalog` };
      if (!(rel in d)) return { known: false, reason: `no-default-recorded-for-${rel}` };
      return { known: true, value: d[rel], proof: `catalog default for NixOS ${rel}` };
    }
    const vals = this.catalog.releases.map((r) => d[r]);
    if (vals.every((v) => v !== undefined && sameValue(v, vals[0]))) return { known: true, value: vals[0], proof: 'identical default in every cataloged release (release not determined)' };
    return { known: false, reason: 'default-differs-by-release-and-release-unknown' };
  }

  // ── expression evaluation ──

  tick() {
    if (++this.steps > this.b.maxEvaluations) throw this.cap('maxEvaluations', this.b.maxEvaluations, 'static evaluation step budget exhausted');
  }

  parseAt(file, span) {
    if (!span) return null;
    const k = `${file}:${span.startOffset}:${span.endOffset}`;
    if (this.parseCache.has(k)) return this.parseCache.get(k);
    const src = this.sources.get(file);
    const text = src ? spanText(src, span) : null;
    const r = text ? parseNix(text, { file }) : null;
    const ast = r && r.ast && r.status === 'ok' ? r.ast : null;
    this.parseCache.set(k, ast);
    return ast;
  }

  alias(file, name, guard) {
    const ir = this.irs.get(file);
    const hits = ir ? ir.bindings.filter((b) => b.origin === 'let' && b.path.length === 1 && b.path[0] === name) : [];
    if (hits.length !== 1 || guard.has(`${file}:${name}`)) return null;
    guard.add(`${file}:${name}`);
    return this.parseAt(file, hits[0].valueSpan);
  }

  /** `config.a.b`, or `cfg.b` where `cfg = config.a`, as ['a','b']; otherwise null. */
  configPathOf(node, env, guard = new Set()) {
    const n = unparen(node);
    if (!n) return null;
    let base; let segs = [];
    if (n.type === 'select') {
      if (n.default || n.attrpath.some((s) => s.kind !== 'static')) return null;
      base = unparen(n.base); segs = n.attrpath.map((s) => s.name);
    } else base = n;
    if (!base || base.type !== 'ident') return null;
    if (base.name === 'config') return segs.length ? segs : null;
    const al = this.alias(env.file, base.name, guard);
    const head = al ? this.configPathOf(al, env, guard) : null;
    return head ? head.concat(segs) : null;
  }

  evalExpr(node, env) {
    this.tick();
    const n = unparen(node);
    if (!n) return UNK;
    switch (n.type) {
      case 'ident':
        if (n.name === 'true') return known(true);
        if (n.name === 'false') return known(false);
        if (n.name === 'null') return known(null);
        if (this.target.args && Object.prototype.hasOwnProperty.call(this.target.args, n.name)) return known(this.target.args[n.name]);
        return UNK;
      case 'int': case 'float': return known(n.value);
      case 'string': return n.interpolated ? UNK : known(n.literal);
      case 'unop': {
        if (n.op !== '!') return UNK;
        const v = this.evalExpr(n.operand, env);
        return v.known && typeof v.value === 'boolean' ? known(!v.value) : UNK;
      }
      case 'binop': return this.evalBinop(n, env);
      case 'select': {
        const flags = platformFlags(this.target.system);
        const b = unparen(n.base);
        if (flags && b && b.type === 'ident' && b.name === 'pkgs' && n.attrpath.length === 2 && n.attrpath[0].name === 'stdenv' && n.attrpath[1].name in flags) return known(flags[n.attrpath[1].name]);
        const p = this.configPathOf(n, env);
        return p ? this.optionValue(env, p) : UNK;
      }
      default: return UNK;
    }
  }

  evalBinop(n, env) {
    const bool = (r) => (r.known && typeof r.value === 'boolean' ? r.value : null);
    if (['&&', '||', '->'].includes(n.op)) {
      const l = bool(this.evalExpr(n.left, env));
      const r = bool(this.evalExpr(n.right, env));
      if (n.op === '&&') return l === false || r === false ? known(false) : l === true && r === true ? known(true) : UNK;
      if (n.op === '||') return l === true || r === true ? known(true) : l === false && r === false ? known(false) : UNK;
      return l === false || r === true ? known(true) : l === true && r === false ? known(false) : UNK;
    }
    if (n.op === '==' || n.op === '!=') {
      const l = this.evalExpr(n.left, env);
      const r = this.evalExpr(n.right, env);
      if (!l.known || !r.known) return UNK;
      const eq = sameValue(l.value, r.value);
      return known(n.op === '==' ? eq : !eq);
    }
    return UNK;
  }

  optionValue(env, segs) {
    const res = this.resolve(env.namespace, env.scope, segs.join('.'));
    return (res.status === 'set' || res.status === 'default') && res.valueKnown ? known(res.value) : UNK;
  }

  condOutcome(def, c) {
    const ast = this.parseAt(def.file, c.span);
    if (!ast) return 'unknown';
    const r = this.evalExpr(ast, { file: def.file, namespace: def.namespace, scope: def.scope });
    if (!r.known || typeof r.value !== 'boolean') return 'unknown';
    const truth = c.branch === 'else' ? !r.value : r.value;
    return truth ? 'true' : 'false';
  }

  defValue(def) {
    const s = def.summary;
    switch (s.type) {
      case 'bool': case 'number': case 'null': return known(s.value);
      case 'string': return s.interpolated ? UNK : known(s.literal);
      case 'list': {
        if (s.items.length < s.length) return UNK;
        const out = [];
        for (const it of s.items) {
          const v = it.type === 'string' && !it.interpolated ? known(it.literal) : it.type === 'number' || it.type === 'bool' ? known(it.value) : UNK;
          if (!v.known) return UNK;
          out.push(v.value);
        }
        return known(out);
      }
      case 'expression': case 'reference': {
        const ast = this.parseAt(def.file, def.valueSpan);
        return ast ? this.evalExpr(ast, { file: def.file, namespace: def.namespace, scope: def.scope }) : UNK;
      }
      default: return UNK;
    }
  }

  priorityOf(def) {
    if (def.priorityName === 'plain') return 100;
    if (def.priorityName === 'mkOverride') return def.priorityArg && def.priorityArg.type === 'number' ? def.priorityArg.value : null;
    return def.priorityName in PRIORITY ? PRIORITY[def.priorityName] : null;
  }

  // ── option resolution ──

  resolve(ns, scope, pathText) {
    const cat = ns === 'nixos' ? this.catalog.nixos : this.catalog.homeManager;
    const canonical = cat.renames[pathText] || pathText;
    const key = this.key(ns, scope, canonical);
    if (this.memo.has(key)) return this.memo.get(key);
    if (this.stack.has(key)) {
      this.gap({ kind: 'cyclic-config-reference', detail: `${canonical} depends on itself through config references`, file: null, span: null });
      return this.shell(ns, scope, canonical, 'unknown', { reason: 'cyclic-reference' });
    }
    if (this.stack.size >= this.b.maxEvalDepth) throw this.cap('maxEvalDepth', this.b.maxEvalDepth, `reference chain deeper than ${this.b.maxEvalDepth}`);
    this.stack.add(key);
    let res;
    try { res = this.compute(ns, scope, canonical, key); } finally { this.stack.delete(key); }
    this.memo.set(key, res);
    return res;
  }

  /** Top-level entry: caps surface as an `unknown` result plus `truncated`, never as a throw. */
  resolveTop(ns, scope, pathText) {
    this.steps = 0;
    try { return this.resolve(ns, scope, pathText); } catch (e) {
      if (!(e instanceof Cap)) throw e;
      this.stack.clear();
      return this.finish(this.shell(ns, scope, pathText, 'unknown', { reason: 'evaluation-budget', budget: { name: e.budget, limit: e.limit } }));
    }
  }

  shell(ns, scope, pathText, status, extra = {}) {
    const info = this.catalogInfo(ns, pathText);
    return {
      namespace: ns, scope, path: pathText, status, value: undefined, valueKnown: false, definite: false,
      sources: [], precedence: { rule: null, winnerPriority: null }, caveats: [],
      catalog: { revision: this.catalog.revision, release: this.release.release, releaseSource: this.release.source, optionStatus: info.status, type: info.entry ? info.entry.type : null },
      ...extra,
    };
  }

  compute(ns, scope, pathText, key) {
    const info = this.catalogInfo(ns, pathText);
    const defs = this.defs.get(key) || [];
    if (defs.length > this.b.maxDefinitionsPerOption) throw this.cap('maxDefinitionsPerOption', this.b.maxDefinitionsPerOption, `${pathText} has more than ${this.b.maxDefinitionsPerOption} definitions`);
    const rows = defs.map((d) => {
      const conditions = d.conditions.map((c) => ({ kind: c.kind, text: c.text, branch: c.branch, outcome: this.condOutcome(d, c) }));
      const active = conditions.some((c) => c.outcome === 'false') ? 'inactive' : conditions.some((c) => c.outcome === 'unknown') ? 'conditional' : 'certain';
      return { d, conditions, active, priority: this.priorityOf(d), value: this.defValue(d) };
    });
    const live = rows.filter((r) => r.active !== 'inactive');
    const certain = live.filter((r) => r.active === 'certain');
    const isList = info.entry && info.entry.type === 'listOf';
    const typed = !!(info.entry && info.entry.type);
    const out = this.shell(ns, scope, pathText, 'unknown');
    const def = this.defaultFor(info);
    const mark = (r, role) => out.sources.push({
      file: r.d.file, span: r.d.span, namespace: r.d.namespace, scope: r.d.scope, priority: r.priority, priorityLabel: r.d.priorityName,
      conditions: r.conditions, role, viaRename: r.d.viaRename, orderSensitive: r.d.priorityName === 'mkBefore' || r.d.priorityName === 'mkAfter' || undefined,
    });
    const finishWith = (patch, roles) => {
      Object.assign(out, patch);
      for (const r of rows) mark(r, roles.get(r) || (r.active === 'inactive' ? 'inactive-condition-false' : 'shadowed'));
      return out;
    };
    const roles = new Map();
    for (const r of rows) if (r.active === 'conditional') roles.set(r, 'conditional');

    if (!live.length) {
      out.precedence = { rule: 'no-active-definition', winnerPriority: null };
      if (def.known) return finishWith({ status: 'default', value: def.value, valueKnown: true, defaultProof: def.proof }, roles);
      return finishWith({ status: 'unknown', reason: `no-definition-and-no-proven-default (${def.reason})` }, roles);
    }
    const certainBest = certain.length && certain.every((r) => r.priority !== null) ? Math.min(...certain.map((r) => r.priority)) : null;
    const nullCertain = certain.some((r) => r.priority === null);
    const winners = live.filter((r) => r.priority === null || certainBest === null || r.priority <= certainBest);
    const condWinners = winners.filter((r) => r.active === 'conditional');
    const certWinners = winners.filter((r) => r.active === 'certain');
    const prio = { rule: 'lowest priority number wins (mkForce 50 < plain 100 < mkDefault 1000)', winnerPriority: certainBest };
    out.precedence = prio;

    const vals = (rs) => rs.map((r) => (r.value.known ? JSON.stringify(r.value.value) : `?${r.d.id}`));
    const allSame = (rs) => new Set(vals(rs)).size === 1;

    if (nullCertain && !allSame(live)) {
      out.precedence = { ...prio, rule: 'priority is not a literal (mkOverride argument)' };
      return finishWith({ status: 'unresolved-precedence', reason: 'a definition has a non-literal priority' }, roles);
    }

    if (isList && !condWinners.length && !nullCertain) {
      const group = certWinners.filter((r) => r.priority === certainBest);
      group.forEach((r) => roles.set(r, 'winner'));
      const values = group.map((r) => r.value);
      const ok = values.every((v) => v.known && Array.isArray(v.value));
      return finishWith({ status: 'set', value: ok ? values.flatMap((v) => v.value) : undefined, valueKnown: ok, merged: group.length > 1, precedence: { ...prio, rule: 'list option: definitions at the winning priority are concatenated' } }, roles);
    }
    if (isList) {
      certWinners.forEach((r) => roles.set(r, 'winner'));
      const base = certWinners.filter((r) => r.priority === certainBest).map((r) => r.value);
      const everyLive = winners.map((r) => r.value);
      return finishWith({
        status: 'conditional', reason: 'a list definition depends on a condition that could not be decided',
        definiteItems: base.every((v) => v.known) ? base.flatMap((v) => v.value) : undefined,
        possibleItems: everyLive.every((v) => v.known && Array.isArray(v.value)) ? everyLive.flatMap((v) => v.value) : undefined,
      }, roles);
    }

    if (!condWinners.length) {
      const group = certWinners.filter((r) => r.priority === certainBest || certainBest === null);
      group.forEach((r) => roles.set(r, 'winner'));
      if (group.length === 1 || allSame(group)) {
        const w = group[0];
        return finishWith({ status: 'set', value: w.value.known ? w.value.value : undefined, valueKnown: w.value.known }, roles);
      }
      const differ = group.every((r) => r.value.known);
      if (differ && typed) return finishWith({ status: 'conflict', reason: `${group.length} definitions at priority ${certainBest} disagree; the module system rejects this`, candidates: group.map((r) => r.value.value) }, roles);
      return finishWith({ status: 'unresolved-precedence', reason: differ ? 'option type is not cataloged, so whether the definitions merge is unknown' : 'definition values are not statically evaluable' }, roles);
    }

    // some winner depends on an undecided condition
    const cands = winners.map((r) => r);
    const candVals = vals(cands);
    const needDefault = !certWinners.length;
    if (needDefault) candVals.push(def.known ? JSON.stringify(def.value) : '?default');
    if (new Set(candVals).size === 1 && !candVals[0].startsWith('?')) {
      const w = cands[0];
      certWinners.forEach((r) => roles.set(r, 'winner'));
      return finishWith({ status: 'set', value: w.value.value, valueKnown: true, note: 'every undecided condition leads to the same value' }, roles);
    }
    certWinners.forEach((r) => roles.set(r, 'winner'));
    const possible = cands.filter((r) => r.value.known).map((r) => r.value.value);
    if (needDefault && def.known) possible.push(def.value);
    return finishWith({
      status: 'conditional', reason: 'the effective value depends on a condition that could not be decided statically',
      possibleValues: possible, allPossibleValuesKnown: cands.every((r) => r.value.known) && (!needDefault || def.known),
    }, roles);
  }

  /** Adds caveats and the `definite` flag. */
  finish(res) {
    const segs = res.path.split('.');
    const caveats = [];
    for (const dp of this.dynamicPrefixes) {
      if (dp.namespace === res.namespace && dp.prefix.every((s, i) => segs[i] === s)) caveats.push({ kind: 'dynamic-attribute', detail: `an attribute name under ${dp.prefix.join('.') || '(root)'} is computed at evaluation time`, file: dp.file, span: dp.span });
    }
    for (const o of this.opaque) {
      if (o.namespace !== res.namespace || (o.scope || null) !== (res.scope || null)) continue;
      const proper = o.selfDef ? o.prefix.length < segs.length : true;
      if (proper && o.prefix.every((s, i) => segs[i] === s)) caveats.push({ kind: 'opaque-definition', detail: `${o.prefix.join('.') || 'config'} is assigned a non-literal value that may define this option`, file: o.file, span: o.span });
    }
    if (res.status === 'default' || res.status === 'unknown') {
      const ns = res.namespace === 'nixos' ? this.catalog.nixos : this.catalog.homeManager;
      const prefix = ns.authoritative.find((a) => res.path === a || res.path.startsWith(`${a}.`));
      if (prefix) for (const u of this.unknownOptions.values()) if (u.namespace === res.namespace && u.authoritativePrefix === prefix) caveats.push({ kind: 'unknown-option-in-namespace', detail: `${u.path} is not a known option; if it is a misspelling or a removed option the default here may not be in force`, file: u.sources[0].file, span: u.sources[0].span });
    }
    if (segs[segs.length - 1] === 'package' && this.overlays.length) caveats.push({ kind: 'overlay-may-change-package', detail: 'an overlay is applied; the package this option selects may differ from nixpkgs', file: this.overlays[0].file, span: this.overlays[0].span });
    const blockers = this.unresolved.filter((g) => BLOCKER_KINDS.has(g.kind));
    if (blockers.length) caveats.push({ kind: 'incomplete-module-graph', detail: `module graph is partial (${[...new Set(blockers.map((g) => g.kind))].join(', ')}); an unread module could override this`, file: null, span: null });
    res.caveats = caveats;
    res.definite = (res.status === 'set' || res.status === 'default') && res.valueKnown && caveats.length === 0;
    return res;
  }
}

/**
 * @param {{entry:string|string[], root?:string, files?:Record<string,string>, readFile?:(p:string)=>string|null,
 *   target?:{name?:string, release?:string, system?:string, args?:object, namespace?:'nixos'|'home-manager', user?:string},
 *   flake?:string, catalog?:object, budgets?:object}} opts
 */
export function resolveNixosConfig(opts) {
  const r = new Resolver(opts);
  r.release = r.determineRelease();
  r.load();
  r.collect();
  const keys = [...r.defs.keys()].sort();
  const options = [];
  for (const k of keys) {
    const [ns, scope, ...rest] = k.split('|');
    const pathText = rest.join('|');
    options.push(r.finish(r.resolveTop(ns, scope || null, pathText)));
  }
  const sv = r.defs.get(r.key('nixos', null, 'system.stateVersion'));
  const stateVersion = sv && sv[0] && sv[0].summary.type === 'string'
    ? { value: sv[0].summary.literal, file: sv[0].file, span: sv[0].span, role: 'state-compatibility-marker', usedForRelease: false }
    : null;
  const blockers = r.unresolved.filter((g) => BLOCKER_KINDS.has(g.kind));
  const report = {
    kind: 'nixos-effective-config', version: 1,
    target: { name: (opts.target && opts.target.name) || null, entries: [].concat(opts.entry || []), system: (opts.target && opts.target.system) || null, release: r.release.release, releaseSource: r.release.source },
    catalog: { revision: r.catalog.revision, schema: r.catalog.schema, releases: r.catalog.releases, matchedRelease: r.release.release && r.catalog.releases.includes(r.release.release) ? r.release.release : null },
    stateVersion,
    namespaces: [...new Set([...r.fileNs.values()].map((v) => v.namespace).concat([...r.defs.keys()].map((k) => k.split('|')[0])))].sort(),
    files: r.order.map((f) => ({ file: f, ...r.fileNs.get(f), status: r.irs.get(f).status })),
    graph: { edges: r.graphEdges },
    options,
    unknownOptions: [...r.unknownOptions.values()],
    renamedOptions: [...r.renamed.values()],
    overlays: r.overlays,
    unresolved: r.unresolved,
    truncated: r.truncated,
    completeness: blockers.length || r.truncated.length ? 'partial' : 'complete',
  };
  Object.defineProperty(report, 'lookup', {
    enumerable: false,
    value: (path, { namespace = 'nixos', scope = null } = {}) => {
      const cat = namespace === 'nixos' ? r.catalog.nixos : r.catalog.homeManager;
      const canonical = cat.renames[path] || path;
      const hit = options.find((o) => o.namespace === namespace && (o.scope || null) === scope && o.path === canonical);
      if (hit) return hit;
      const res = r.finish(r.resolveTop(namespace, scope, canonical));
      report.truncated = r.truncated;
      return res;
    },
  });
  return report;
}
