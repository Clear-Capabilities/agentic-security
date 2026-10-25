// Demand-driven reverse taint (DAG-02): a sink query answered by a finite
// backward demand frontier plus the EXISTING forward engine run on the
// selected region only.
//
// Roles (R02.5, no existing implementation is removed):
//   tabulation.js   coarse caller-only function selector (reachabilitySliceFromSinks)
//   backward.js     intraprocedural explanation trace of a finding
//   ifds-precise.js depth-capped predecessor chain
//   this module     sink-keyed selector that follows definitions, parameter and
//                   return mappings, receiver fields, aliases, producer helpers
//                   and callbacks, then lets runTaintEngine corroborate.
//
// Soundness rules this module is built around:
//   1. The frontier only SELECTS functions. A backward/forward intersection is a
//      candidate filter and is reported as one; the only witness is a finding the
//      forward engine produced over the selected region.
//   2. A construct the selector cannot follow (instance fields, an exhausted
//      depth or work budget, an unresolved higher-order shape) never silently
//      drops a function. Default policy expands to the full function set
//      (`onLimit` / `onUnsupported` = 'full'); the 'partial' policy instead
//      reports partial scope with negativeClaimAllowed false.
//   3. A limited reverse walk never authorizes a negative verdict. The verdict
//      vocabulary has no "safe": `flow-found`, `no-flow-in-modeled-scope`
//      (only when the completion envelope allows a negative claim) and
//      `unknown`.
//
// Opt-in: AGENTIC_SECURITY_DEMAND=1 (see demandEnabled) plus the API below. The
// default scan never calls this module.

import * as crypto from 'node:crypto';
import { accessPathOf } from './access-paths.js';
import { matchSource, matchSinkOrSanitizer, matchMemberWriteSink, _catalogSize } from './catalog.js';
import { lookupBuiltinSummary } from './builtin-summaries.js';
import { runTaintEngine } from './engine.js';
import { buildCallerQidIndex, reachabilitySliceWithCompletion } from './tabulation.js';
import { makeCompletion } from '../lineage/completion.js';

const DEMAND_SCHEMA_VERSION = '1.0.0';
const DEMAND_CONTEXTS = Object.freeze(['whole-program']);
const DEFAULT_MAX_CALLER_DEPTH = 64;
const DEFAULT_MAX_WORK = 50000;
const MAX_PATH_SEGMENTS = 6;

/** Demand mode is opt-in: this env flag AND an explicit API/query list. */
export function demandEnabled(env = process.env) {
  return env.AGENTIC_SECURITY_DEMAND === '1';
}

// ---------------------------------------------------------------------------
// R02.1 query contract
// ---------------------------------------------------------------------------

/**
 * Normalize a sink query. Keys: exact sink site (file + line, optionally
 * nodeId / callee / sinkId to narrow), argument index, field/access path within
 * the sink argument, analysis context, rule family (CWE id or family name), and
 * the graph/configuration digests the answer is valid for.
 */
export function normalizeSinkQuery(q = {}) {
  const num = (v) => (Number.isInteger(v) && v >= 0 ? v : null);
  const str = (v) => (typeof v === 'string' && v.length ? v : null);
  return {
    file: str(q.file),
    line: num(q.line),
    nodeId: str(q.nodeId),
    fnQid: str(q.fnQid),
    callee: str(q.callee),
    sinkId: str(q.sinkId),
    argIndex: num(q.argIndex),
    accessPath: str(q.accessPath),
    context: str(q.context) || 'whole-program',
    ruleFamily: str(q.ruleFamily),
    graphDigest: str(q.graphDigest),
    configDigest: str(q.configDigest),
  };
}

const _digestCache = new WeakMap();

/** Stable digest of the call graph content the query was answered over. */
export function graphDigest(callGraph) {
  if (!callGraph || !callGraph.functions) return null;
  if (_digestCache.has(callGraph)) return _digestCache.get(callGraph);
  const h = crypto.createHash('sha256');
  for (const qid of [...callGraph.functions.keys()].sort()) {
    const fn = callGraph.functions.get(qid);
    h.update(qid); h.update('\0');
    h.update(JSON.stringify(fn.params || [])); h.update('\0');
    h.update(JSON.stringify(fn.cfg ? fn.cfg.nodes : null)); h.update('\n');
  }
  const d = h.digest('hex').slice(0, 32);
  _digestCache.set(callGraph, d);
  return d;
}

/** Digest of everything besides the graph that can change an answer. */
export function configDigest(opts = {}) {
  const h = crypto.createHash('sha256');
  h.update(JSON.stringify({
    catalog: _catalogSize(),
    kcfa: process.env.AGENTIC_SECURITY_KCFA_MAX_CONTEXTS || null,
    callstring: process.env.AGENTIC_SECURITY_KCFA_CALLSTRING || null,
    fnLimit: opts.fnLimit || null,
    maxCallerDepth: opts.maxCallerDepth || DEFAULT_MAX_CALLER_DEPTH,
    maxWork: opts.maxWork || DEFAULT_MAX_WORK,
    onLimit: opts.onLimit || 'full',
    onUnsupported: opts.onUnsupported || 'full',
  }));
  return h.digest('hex').slice(0, 16);
}

/** Stable key of a normalized query bound to its digests. */
export function sinkQueryKey(query, digests = {}) {
  const q = normalizeSinkQuery(query);
  q.graphDigest = digests.graphDigest ?? q.graphDigest;
  q.configDigest = digests.configDigest ?? q.configDigest;
  return crypto.createHash('sha256').update(JSON.stringify(q)).digest('hex').slice(0, 24);
}

// ---------------------------------------------------------------------------
// Expression helpers
// ---------------------------------------------------------------------------

const SELF_ROOTS = new Set(['this', '_this_', 'self', 'cls']);
const REQ_PARAM = /^(?:req|request|ctx)$/;
// Roots that are language builtins or ambient globals, so a call on them is
// modeled by the engine's own summaries rather than being an unresolved callee.
const BUILTIN_ROOTS = new Set(['console', 'JSON', 'Math', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Promise', 'Buffer', 'process', 'Date', 'RegExp', 'Set', 'Map', 'Symbol', 'Error', 'parseInt', 'parseFloat', 'encodeURIComponent', 'decodeURIComponent', 'require']);

const HIGHER_ORDER_METHODS = new Set(['map', 'forEach', 'filter', 'flatMap', 'find', 'findIndex', 'some', 'every', 'reduce', 'reduceRight', 'sort', 'then', 'catch', 'finally', 'all', 'allSettled', 'race', 'any']);

function isExpr(v) { return v && typeof v === 'object' && typeof v.kind === 'string'; }

function visitVal(v, f) {
  if (!v || typeof v !== 'object') return;
  if (isExpr(v)) { f(v); return; }
  if (Array.isArray(v)) { for (const x of v) visitVal(x, f); return; }
  for (const x of Object.values(v)) visitVal(x, f);
}

function forEachChild(e, f) {
  for (const k of Object.keys(e)) {
    if (k === 'kind') continue;
    visitVal(e[k], f);
  }
}

const rootOf = (p) => { const i = p.indexOf('.'); return i < 0 ? p : p.slice(0, i); };

/** Segment-wise overlap; a `*` segment (computed key) matches any segment. */
const _segs = new Map();
function segsOf(s) { let v = _segs.get(s); if (!v) { v = s.split('.'); if (_segs.size > 200000) _segs.clear(); _segs.set(s, v); } return v; }
function segOverlap(a, b) {
  if (a === b) return true;
  const x = segsOf(a); const y = segsOf(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i] && x[i] !== '*' && y[i] !== '*') return false;
  return true;
}

function exprOfPath(path) {
  const segs = path.split('.');
  let e = { kind: 'ident', name: segs[0] };
  for (let i = 1; i < segs.length; i++) e = { kind: 'member', object: e, prop: segs[i] };
  return e;
}

function calleeName(callee) {
  if (typeof callee === 'string') return callee;
  if (!callee) return null;
  if (callee.kind === 'ident') return callee.name;
  if (callee.kind === 'member') return accessPathOf(callee);
  return null;
}

// ---------------------------------------------------------------------------
// Function facts and the extended incoming-call index (R02.2)
// ---------------------------------------------------------------------------

const _infoCache = new WeakMap();

function fnInfo(fn) {
  if (_infoCache.has(fn)) return _infoCache.get(fn);
  const info = { params: Array.isArray(fn.params) ? fn.params.filter((p) => typeof p === 'string') : [], assigns: [], calls: [], returns: [], fnValues: new Set(), assignedRoots: new Set(), hasOpaqueAssign: false };
  const walk = (e, nid, line) => {
    if (!e || typeof e !== 'object') return;
    if (e.kind === 'function-value') { if (e.qid) info.fnValues.add(e.qid); return; }
    if (e.kind === 'call') info.calls.push({ expr: e, nid, line: e.line || line });
    if (isExpr(e)) forEachChild(e, (c) => walk(c, nid, line));
  };
  const nodes = (fn.cfg && fn.cfg.nodes) || {};
  for (const nid of Object.keys(nodes)) {
    const n = nodes[nid];
    if (!n) continue;
    if (n.kind === 'assign') {
      if (typeof n.target === 'string') { info.assigns.push({ nid, target: n.target, source: n.source, line: n.line }); info.assignedRoots.add(rootOf(n.target)); }
      else { info.assigns.push({ nid, target: null, source: n.source, line: n.line, opaque: true }); info.hasOpaqueAssign = true; }
      walk(n.source, nid, n.line);
    } else if (n.kind === 'call') {
      info.calls.push({ expr: n, nid, line: n.line, top: true });
      for (const a of (n.args || [])) walk(a, nid, n.line);
      if (n.callee && typeof n.callee === 'object') walk(n.callee, nid, n.line);
    } else if (n.kind === 'return') {
      if (n.value) { info.returns.push(n.value); walk(n.value, nid, n.line); }
    } else {
      for (const k of Object.keys(n)) {
        if (['id', 'kind', 'succ', 'pred', 'line'].includes(k)) continue;
        visitVal(n[k], (c) => walk(c, nid, n.line));
      }
    }
  }
  _infoCache.set(fn, info);
  return info;
}

const _indexCache = new WeakMap();

/**
 * Incoming-call index over the WHOLE call graph: callee qid -> sites, each
 * {caller, nid, call, kind: 'call'|'callback'|'callback-ref'}. Starts from the
 * canonical buildCallerQidIndex (statement-level calls) and adds embedded call
 * sites that `fn.calls` omits, plus callback registrations. Also indexes
 * functions by bare name for method-name candidate expansion.
 */
export function buildIncomingIndex(callGraph) {
  if (_indexCache.has(callGraph)) return _indexCache.get(callGraph);
  const incoming = new Map();
  const byTail = new Map();
  const modules = new Map(); const byFile = new Map();
  const add = (qid, site) => { if (!incoming.has(qid)) incoming.set(qid, []); incoming.get(qid).push(site); };
  const resolveName = (name, file) => (name && callGraph.resolveKnownCallee ? callGraph.resolveKnownCallee(name, file) : null);
  for (const fn of callGraph.functions.values()) {
    const tail = String(fn.name || '').split('.').pop();
    if (tail) { if (!byTail.has(tail)) byTail.set(tail, []); byTail.get(tail).push(fn.qid); }
    if (!byFile.has(fn.file)) byFile.set(fn.file, []); byFile.get(fn.file).push(fn);
    if (fn.name === '<module>' && String(fn.qid).includes('::top::')) { if (!modules.has(fn.file)) modules.set(fn.file, []); modules.get(fn.file).push(fn.qid); }
  }
  const base = buildCallerQidIndex(callGraph); // canonical statement-level edges, retained for parity checks
  for (const fn of callGraph.functions.values()) {
    const info = fnInfo(fn);
    for (const occ of info.calls) {
      const name = calleeName(occ.expr.callee);
      const g = resolveName(name, fn.file);
      if (g) add(g, { caller: fn.qid, nid: occ.nid, call: occ.expr, kind: 'call' });
      for (const a of (occ.expr.args || [])) {
        if (a && a.kind === 'function-value' && a.qid) add(a.qid, { caller: fn.qid, nid: occ.nid, call: occ.expr, kind: 'callback' });
        else if (a && a.kind === 'ident') {
          const r = resolveName(a.name, fn.file);
          if (r && r !== fn.qid) add(r, { caller: fn.qid, nid: occ.nid, call: occ.expr, kind: 'callback-ref' });
        }
      }
    }
  }
  const idx = { incoming, byTail, modules, byFile, base };
  _indexCache.set(callGraph, idx);
  return idx;
}

// ---------------------------------------------------------------------------
// Sink-site discovery (nested sinks in assignment and return expressions)
// ---------------------------------------------------------------------------

function matchesFamily(entry, family) {
  if (!family) return true;
  const v = entry.vuln || {};
  return v.cwe === family || entry.id === family || (v.name && v.name === family) || (entry.family && entry.family === family);
}

/** Enumerate sink sites in the graph that satisfy the query's site keys. */
export function findSinkSites(callGraph, query) {
  const q = normalizeSinkQuery(query);
  const sites = [];
  for (const fn of callGraph.functions.values()) {
    if (q.file && fn.file !== q.file) continue;
    if (q.fnQid && fn.qid !== q.fnQid) continue;
    const info = fnInfo(fn);
    for (const occ of info.calls) {
      if (q.line != null && occ.line !== q.line) continue;
      if (q.nodeId && occ.nid !== q.nodeId) continue;
      const hits = matchSinkOrSanitizer(occ.expr.callee, fn.file) || [];
      for (const e of hits) {
        if (e.kind !== 'sink' || !matchesFamily(e, q.ruleFamily)) continue;
        if (q.sinkId && e.id !== q.sinkId) continue;
        if (q.callee && calleeName(occ.expr.callee) !== q.callee) continue;
        sites.push({ file: fn.file, fnQid: fn.qid, nodeId: occ.nid, line: occ.line, entry: e, sinkId: e.id, argExprs: occ.expr.args || [], callee: calleeName(occ.expr.callee), kind: 'call' });
      }
    }
    for (const a of info.assigns) {
      if (!a.target || (q.line != null && a.line !== q.line)) continue;
      if (q.nodeId && a.nid !== q.nodeId) continue;
      const hits = matchMemberWriteSink(a.target, fn.file) || [];
      for (const e of hits) {
        if (!matchesFamily(e, q.ruleFamily) || (q.sinkId && e.id !== q.sinkId)) continue;
        if (q.callee && a.target !== q.callee) continue;
        sites.push({ file: fn.file, fnQid: fn.qid, nodeId: a.nid, line: a.line, entry: e, sinkId: e.id, argExprs: [a.source], callee: a.target, kind: 'member-write' });
      }
    }
  }
  // The IR can carry one call both as a statement node and as the value of a
  // return node; both name the same source site.
  const seenSite = new Set();
  for (let i = sites.length - 1; i >= 0; i--) {
    const s = sites[i];
    const k = `${s.fnQid}|${s.line}|${s.sinkId}|${s.callee}`;
    if (seenSite.has(k)) sites.splice(i, 1); else seenSite.add(k);
  }
  sites.sort((x, y) => (x.fnQid < y.fnQid ? -1 : x.fnQid > y.fnQid ? 1 : x.nodeId < y.nodeId ? -1 : x.nodeId > y.nodeId ? 1 : x.sinkId < y.sinkId ? -1 : 1));
  return sites;
}

// ---------------------------------------------------------------------------
// R02.2 / R02.4: the backward demand frontier
// ---------------------------------------------------------------------------

class Frontier {
  constructor(callGraph, opts) {
    this.cg = callGraph;
    this.idx = buildIncomingIndex(callGraph);
    this.maxDepth = opts.maxCallerDepth ?? DEFAULT_MAX_CALLER_DEPTH;
    this.maxWork = opts.maxWork ?? DEFAULT_MAX_WORK;
    this.hasCha = !!(opts.engineOpts && opts.engineOpts._cha);
    this.region = new Map(); // qid -> Set(reason)
    this.work = [];
    this.seen = new Set();
    this.cbDone = new Set();
    this.reqDone = new Set();
    this.steps = 0;
    this.maxDepthReached = 0;
    this.limits = []; // {kind, count}
    this.unsupported = []; // {kind, qid, detail}
    this.unresolved = new Map(); // name@qid -> record
    this.terminals = new Set(); // 'source' | 'param' | 'call' | 'free' | 'callback'
    this.followed = { callers: 0, producers: 0, callbacks: 0, mutators: 0 };
    this.depthCut = 0;
    this.workLeft = 0;
    this.sinkCalls = new Set();
    this.touchCache = new WeakMap();
    this.expanded = new Set();
  }

  addRegion(qid, reason) {
    if (!this.cg.functions.has(qid)) return;
    if (!this.region.has(qid)) this.region.set(qid, new Set());
    this.region.get(qid).add(reason);
  }

  push(qid, path, ep, depth, reason) {
    // recursive field growth (`x = x.next` in a loop) would otherwise generate
    // an unbounded family of paths; fold to a capped prefix, which selects
    // more, never less
    if (path.length > 24 && path.charCodeAt(0) !== 36) {
      const segs = segsOf(path);
      if (segs.length > MAX_PATH_SEGMENTS) path = segs.slice(0, MAX_PATH_SEGMENTS).join('.');
    }
    const k = `${qid}|${path}|${ep ? 1 : 0}`;
    if (this.seen.has(k)) return;
    this.seen.add(k);
    this.work.push({ qid, path, ep, depth, reason });
    if (depth > this.maxDepthReached) this.maxDepthReached = depth;
  }

  run() {
    while (this.work.length) {
      if (++this.steps > this.maxWork) {
        this.limits.push({ kind: 'work-limit', count: this.work.length });
        this.workLeft = this.work.length;
        this.work = [];
        break;
      }
      const item = this.work.pop();
      this.process(item);
    }
  }

  markUnsupported(kind, qid, detail) {
    if (!this.unsupported.some((u) => u.kind === kind && u.qid === qid)) this.unsupported.push({ kind, qid, detail });
  }

  /** Walk an expression in `fn` and register every path/call it depends on. */
  reads(fn, expr, item) {
    const rd = (e) => {
      if (!e || typeof e !== 'object') return;
      if (e.kind === 'literal') return;
      if (e.kind === 'function-value') { this.callbackValue(e.qid, item.depth); return; }
      const p = accessPathOf(e);
      if (p) { this.push(fn.qid, p, item.ep, item.depth, item.reason); this.checkSourceExpr(fn, e, p); return; }
      if (e.kind === 'call') { this.callExpr(fn, e, item); return; }
      if (matchSource(e, fn.file)) this.terminals.add('source');
      forEachChild(e, rd);
    };
    rd(expr);
  }

  callbackValue(qid, depth) {
    if (!qid || !this.cg.functions.has(qid)) return;
    this.followed.callbacks += 1;
    this.addRegion(qid, 'callback');
    this.push(qid, '$ret', false, depth, 'callback');
    this.push(qid, '$params', false, depth, 'callback');
  }

  callExpr(fn, e, item) {
    if (matchSource(e, fn.file)) this.terminals.add('source');
    const callee = e.callee;
    // receiver: taint on the receiver flows through the call (`tainted.trim()`)
    if (callee && typeof callee === 'object' && callee.kind === 'member') {
      const rp = accessPathOf(callee.object);
      if (rp) this.push(fn.qid, rp, item.ep, item.depth, item.reason);
      else this.reads(fn, callee.object, item);
    } else if (typeof callee === 'string' && callee.includes('.')) {
      this.push(fn.qid, callee.slice(0, callee.lastIndexOf('.')), item.ep, item.depth, item.reason);
    }
    for (const a of (e.args || [])) this.reads(fn, a, item);
    const name = calleeName(callee);
    const g = name && this.cg.resolveKnownCallee ? this.cg.resolveKnownCallee(name, fn.file) : null;
    if (g) {
      this.followed.producers += 1;
      this.addRegion(g, 'producer');
      this.push(g, '$ret', false, item.depth, 'producer');
      this.terminals.add('call');
      return;
    }
    // member call on an unresolved receiver: the engine may resolve it through
    // class-hierarchy analysis, so every project function with that bare name
    // is a candidate producer (conservative expansion, never a drop).
    const tail = name ? name.split('.').pop() : null;
    // Only the engine's class-hierarchy resolution (opts._cha) can reach such a
    // callee, so without it there is nothing to over-select; with it, only
    // class methods are candidates.
    const cands = tail && this.hasCha && callee && typeof callee === 'object' && callee.kind === 'member'
      ? (this.idx.byTail.get(tail) || []).filter((q) => /::[A-Za-z_$][\w$]*::[\w$]+@/.test(q) && !q.includes('::<module>::'))
      : null;
    if (cands && cands.length) {
      for (const c of cands) { this.followed.producers += 1; this.addRegion(c, 'method-candidate'); this.push(c, '$ret', false, item.depth, 'method-candidate'); this.push(c, '$params', false, item.depth, 'method-candidate'); }
      this.terminals.add('call');
      return;
    }
    const info = fnInfo(fn);
    const prop = callee && typeof callee === 'object' && callee.kind === 'member' && typeof callee.prop === 'string' ? callee.prop : (name ? name.split('.').pop() : null);
    // A call through a parameter is a callback invocation (the registration
    // site is followed by expandCallers); an array or promise combinator is
    // modeled by the engine's higher-order handling.
    const viaParam = callee && typeof callee === 'object' && callee.kind === 'ident' && info.params.includes(callee.name);
    const modeled = viaParam || (prop && HIGHER_ORDER_METHODS.has(prop)) || (callee && matchSinkOrSanitizer(callee, fn.file)) || (name && lookupBuiltinSummary(name)) || (name && BUILTIN_ROOTS.has(rootOf(name)));
    if (!modeled) {
      const key = `${name || '<dynamic>'}@${fn.qid}`;
      if (!this.unresolved.has(key)) this.unresolved.set(key, { callee: name || '<dynamic>', fnQid: fn.qid, line: e.line || null });
    }
    this.terminals.add('call');
  }

  checkSource(fn, path) {
    const segs = path.split('.');
    for (let i = 1; i <= segs.length; i++) {
      if (matchSource(exprOfPath(segs.slice(0, i).join('.')), fn.file)) { this.terminals.add('source'); return; }
    }
  }

  checkSourceExpr(fn, e, p) {
    if (matchSource(e, fn.file)) this.terminals.add('source');
    else this.checkSource(fn, p);
  }

  process(item) {
    const fn = this.cg.functions.get(item.qid);
    if (!fn || !fn.cfg || !fn.cfg.nodes) { this.markUnsupported('missing-function-body', item.qid, item.path); return; }
    this.addRegion(item.qid, item.reason || 'sink');
    const info = fnInfo(fn);
    const p = item.path;

    if (!this.cbDone.has(fn.qid)) {
      this.cbDone.add(fn.qid);
      // callbacks defined inside a selected function run under its taint
      for (const q of info.fnValues) this.callbackValue(q, item.depth);
      this.requestFieldWriters(fn, info, item);
    }
    if (p === '$ret') { for (const r of info.returns) this.reads(fn, r, item); return; }
    if (p === '$params') { for (const prm of info.params) this.push(fn.qid, prm, false, item.depth, item.reason); this.push(fn.qid, '$ret', false, item.depth, item.reason); return; }

    const root = rootOf(p);
    if (SELF_ROOTS.has(root)) { this.markUnsupported('instance-field', fn.qid, p); return; }
    this.checkSource(fn, p);

    for (const a of info.assigns) {
      if (a.opaque) { this.reads(fn, a.source, item); continue; }
      if (!segOverlap(a.target, p)) continue;
      // target covers the needed path (equal or a prefix): the value of the
      // needed path comes from the matching part of the source. Otherwise the
      // write is to a sub-field of the needed path (a partial write): the whole
      // source matters.
      const tl = a.target.split('.').length; const pl = p.split('.').length;
      if (tl <= pl) this.assignSource(fn, a, p.split('.').slice(tl).join('.'), item);
      else this.reads(fn, a.source, item);
    }

    for (const occ of info.calls) {
      // the queried sink call itself runs after its argument is formed, so it
      // cannot change what the argument holds
      if (this.sinkCalls.has(`${fn.qid}|${occ.line}|${calleeName(occ.expr.callee)}`)) continue;
      if (!this.callTouches(occ.expr, p)) continue;
      this.followed.mutators += 1;
      this.reads(fn, occ.expr, item);
      const name = calleeName(occ.expr.callee);
      const g = name && this.cg.resolveKnownCallee ? this.cg.resolveKnownCallee(name, fn.file) : null;
      if (g && g !== fn.qid) { this.addRegion(g, 'mutator'); this.push(g, '$params', false, item.depth, 'mutator'); }
    }

    const pi = info.params.indexOf(root);
    if (pi >= 0) {
      this.terminals.add('param');
      if (item.ep) this.expandCallers(fn, pi, item);
    } else if (!info.assignedRoots.has(root) && !info.hasOpaqueAssign && !info.params.includes(root)) {
      this.freeVariable(fn, root, p, item);
    }
  }

  assignSource(fn, a, suffix, item) {
    const src = a.source;
    if (!src) return;
    if (src.kind === 'object' && Array.isArray(src.props)) {
      if (!suffix) { for (const pr of src.props) this.reads(fn, pr.value, item); return; }
      const segs = suffix.split('.');
      const key = segs[0];
      let found = false;
      for (const pr of src.props) {
        if (pr.key === key || pr.key === '*' || key === '*') {
          found = true;
          const rest = segs.slice(1).join('.');
          const vp = accessPathOf(pr.value);
          if (rest && vp) this.push(fn.qid, `${vp}.${rest}`, item.ep, item.depth, item.reason);
          else this.reads(fn, pr.value, item);
        }
      }
      // a spread entry (`...other`) can supply any key
      if (!found || src.props.some((pr) => pr.key === '...' || pr.spread)) this.reads(fn, src, item);
      return;
    }
    const sp = accessPathOf(src);
    if (sp) { this.push(fn.qid, suffix ? `${sp}.${suffix}` : sp, item.ep, item.depth, item.reason); this.checkSource(fn, sp); return; }
    this.reads(fn, src, item);
  }

  callTouches(call, p) {
    let paths = this.touchCache.get(call);
    if (paths) return paths.some((q) => segOverlap(q, p));
    paths = [];
    this.touchCache.set(call, paths);
    const collect = (e) => {
      if (!e || typeof e !== 'object') return;
      if (e.kind === 'function-value') return;
      const ap = accessPathOf(e);
      if (ap) { paths.push(ap); return; }
      if (isExpr(e)) forEachChild(e, collect);
    };
    const callee = call.callee;
    if (callee && typeof callee === 'object' && callee.kind === 'member') collect(callee.object);
    else if (typeof callee === 'string' && callee.includes('.')) paths.push(callee.slice(0, callee.lastIndexOf('.')));
    for (const a of (call.args || [])) collect(a);
    return paths.some((q) => segOverlap(q, p));
  }

  expandCallers(fn, paramIdx, item) {
    // the caller-side argument is read whole, so one expansion per parameter
    // covers every access path rooted at it
    const ek = `${fn.qid}|${paramIdx}`;
    if (this.expanded.has(ek)) return;
    this.expanded.add(ek);
    const sites = this.idx.incoming.get(fn.qid) || [];
    if (!sites.length) return;
    if (item.depth + 1 > this.maxDepth) { this.depthCut += sites.length; this.limits.push({ kind: 'depth-limit', count: sites.length }); return; }
    for (const s of sites) {
      const caller = this.cg.functions.get(s.caller);
      if (!caller) continue;
      this.followed.callers += 1;
      this.addRegion(s.caller, s.kind === 'call' ? 'caller' : 'callback-registrar');
      const ni = { ...item, qid: s.caller, depth: item.depth + 1, ep: true, reason: 'caller' };
      if (s.kind === 'call') {
        const arg = (s.call.args || [])[paramIdx];
        if (arg) this.reads(caller, arg, ni);
        const callee = s.call.callee;
        if (callee && typeof callee === 'object' && callee.kind === 'member') this.reads(caller, callee.object, ni);
      } else {
        for (const a of (s.call.args || [])) if (!(a && a.kind === 'function-value' && a.qid === fn.qid)) this.reads(caller, a, ni);
        const callee = s.call.callee;
        if (callee && typeof callee === 'object' && callee.kind === 'member') this.reads(caller, callee.object, ni);
      }
    }
  }

  requestFieldWriters(fn, info, item) {
    if (!item.ep && item.reason !== 'sink') return;
    const p0 = info.params[0];
    if (!p0 || !REQ_PARAM.test(p0) || this.reqDone.has(fn.file)) return;
    this.reqDone.add(fn.file);
    for (const other of (this.idx.byFile.get(fn.file) || [])) {
      if (other.file !== fn.file) continue;
      const oi = fnInfo(other);
      const q0 = oi.params[0];
      if (!q0 || !REQ_PARAM.test(q0)) continue;
      for (const a of oi.assigns) {
        if (a.target && a.target.startsWith(`${q0}.`)) {
          this.addRegion(other.qid, 'request-field-writer');
          this.push(other.qid, a.target, true, item.depth, 'request-field-writer');
        }
      }
    }
  }

  freeVariable(fn, root, p, item) {
    const definers = [];
    for (const other of (this.idx.byFile.get(fn.file) || [])) {
      if (other.file !== fn.file || other.qid === fn.qid) continue;
      const oi = fnInfo(other);
      if (oi.assignedRoots.has(root) || oi.params.includes(root)) definers.push(other);
    }
    // import bindings (`const x = require(...)`) carry no data of their own
    const importOnly = definers.length > 0 && definers.every((d) => fnInfo(d).assigns.filter((a) => a.target && rootOf(a.target) === root).every((a) => a.source && a.source.kind === 'call' && calleeName(a.source.callee) === 'require'));
    if (!definers.length) return; // ambient global; the engine models it by name only
    this.terminals.add('free');
    if (importOnly) return;
    for (const d of definers) {
      if (d.qid === fn.qid) continue;
      this.addRegion(d.qid, 'free-variable-definer');
      this.push(d.qid, p, item.ep, item.depth, 'free-variable-definer');
    }
  }
}

// ---------------------------------------------------------------------------
// Seeds from a sink site
// ---------------------------------------------------------------------------

function seedExprs(site, q) {
  let args;
  if (q.argIndex != null) args = site.argExprs[q.argIndex] ? [site.argExprs[q.argIndex]] : [];
  else if (site.entry.argIndex === 'all') args = site.argExprs;
  else if (typeof site.entry.argIndex === 'number') args = site.argExprs[site.entry.argIndex] ? [site.argExprs[site.entry.argIndex]] : [];
  else args = site.argExprs; // 'rhs' and member-write
  return args;
}

function seedFrontier(frontier, fn, site, q) {
  const item = { qid: site.fnQid, path: '', ep: true, depth: 0, reason: 'sink' };
  frontier.addRegion(site.fnQid, 'sink');
  if (site.kind === 'call') frontier.sinkCalls.add(`${site.fnQid}|${site.line}|${site.callee}`);
  for (const a of seedExprs(site, q)) {
    if (!q.accessPath) { frontier.reads(fn, a, item); continue; }
    const ap = accessPathOf(a);
    if (ap) { frontier.push(site.fnQid, `${ap}.${q.accessPath}`, true, 0, 'sink'); continue; }
    if (a && a.kind === 'object' && Array.isArray(a.props)) {
      const segs = q.accessPath.split('.');
      for (const pr of a.props) {
        if (pr.key !== segs[0] && pr.key !== '*') continue;
        const vp = accessPathOf(pr.value);
        if (segs.length > 1 && vp) frontier.push(site.fnQid, `${vp}.${segs.slice(1).join('.')}`, true, 0, 'sink');
        else frontier.reads(fn, pr.value, item);
      }
      continue;
    }
    // not a path or literal: no field refinement is possible, read the whole expression
    frontier.reads(fn, a, item);
  }
}

// ---------------------------------------------------------------------------
// Normalization, running, comparing
// ---------------------------------------------------------------------------

export function normalizeFinding(f) {
  const sources = new Set();
  if (f.source && f.source.label) sources.add(`${f.source.label}@${f.source.line ?? ''}`);
  for (const c of (f.chain || [])) if (c && c.label) sources.add(`${c.label}@${c.line ?? ''}`);
  return {
    file: f.file,
    line: f.line,
    sinkId: f.sink ? f.sink.label : null,
    argIndex: f.argIndex ?? null,
    cwe: f.cwe ?? null,
    sources: [...sources].sort(),
  };
}

const findingKey = (n) => JSON.stringify([n.file, n.line, n.sinkId, n.argIndex, n.cwe, n.sources]);

function pickFindings(raw, sites, q) {
  const out = [];
  const want = new Set(sites.map((s) => `${s.file}|${s.line}|${s.sinkId}`));
  for (const f of raw) {
    if (!f.sink || !want.has(`${f.file}|${f.line}|${f.sink.label}`)) continue;
    if (q.argIndex != null && f.argIndex !== q.argIndex) continue;
    out.push(normalizeFinding(f));
  }
  const byKey = new Map();
  for (const n of out) byKey.set(findingKey(n), n);
  return [...byKey.values()].sort((a, b) => (findingKey(a) < findingKey(b) ? -1 : 1));
}

function sourceBearing(fn) {
  const info = fnInfo(fn);
  let found = Array.isArray(fn.paramAnnotations) && fn.paramAnnotations.length > 0;
  const rd = (e) => { if (found || !e || typeof e !== 'object') return; if (e.kind === 'function-value') return; if (matchSource(e, fn.file)) { found = true; return; } if (isExpr(e)) forEachChild(e, rd); };
  for (const a of info.assigns) rd(a.source);
  for (const c of info.calls) rd(c.expr);
  for (const r of info.returns) rd(r);
  return found;
}

const _lru = new Map();
const LRU_MAX = 64;

function resultCacheGet(key) { if (!_lru.has(key)) return null; const v = _lru.get(key); _lru.delete(key); _lru.set(key, v); return v; }
function resultCachePut(key, v) { _lru.set(key, v); while (_lru.size > LRU_MAX) _lru.delete(_lru.keys().next().value); }
export function clearDemandCache() { _lru.clear(); }

function engineOptsOf(opts) {
  const o = { ...(opts.engineOpts || {}) };
  if (opts.fnLimit) o.fnLimit = opts.fnLimit;
  if (typeof opts.deadlineMs === 'number') o.deadlineMs = opts.deadlineMs;
  return o;
}

function engineIncomplete(raw) {
  const list = raw && raw.analysisIncomplete;
  return Array.isArray(list) ? list.map((x) => x.reason).filter(Boolean) : [];
}

function fieldAttributable(frontier) {
  return frontier.terminals.size > 0;
}

function baseResult(q, key, digests) {
  return { schemaVersion: DEMAND_SCHEMA_VERSION, queryKey: key, query: q, digests };
}

/**
 * Run one sink query in demand mode. Returns the result record described in
 * the module header. Never throws for an unanswerable query: it returns an
 * `unavailable` completion instead.
 */
export function runDemandSinkQuery(perFileIR, callGraph, query, opts = {}) {
  const q = normalizeSinkQuery(query);
  const digests = { graphDigest: opts.graphDigest ?? graphDigest(callGraph), configDigest: opts.configDigest ?? configDigest(opts) };
  const key = sinkQueryKey(q, digests);
  const useCache = opts.cache !== false && !opts.engine;
  if (useCache) { const hit = resultCacheGet(key); if (hit) return { ...hit, cached: true }; }
  const res = baseResult(q, key, digests);
  res.mode = 'demand';
  const total = callGraph && callGraph.functions ? callGraph.functions.size : 0;

  if (!callGraph || !callGraph.functions) return unavailable(res, 'no-call-graph', total);
  if (!DEMAND_CONTEXTS.includes(q.context)) return unavailable(res, 'unsupported-context', total);
  const sites = findSinkSites(callGraph, q);
  if (!sites.length) return unavailable(res, 'sink-site-not-found', total);

  const frontier = new Frontier(callGraph, opts);
  for (const s of sites) seedFrontier(frontier, callGraph.functions.get(s.fnQid), s, q);
  frontier.run();

  const onLimit = opts.onLimit || 'full';
  const onUnsupported = opts.onUnsupported || 'full';
  const reasons = [];
  let fallback = null;
  if (frontier.limits.length) {
    if (onLimit === 'full') fallback = { reason: frontier.limits.map((l) => l.kind).sort()[0], expandedToFull: true };
    else for (const l of frontier.limits) reasons.push(l.kind);
  }
  if (frontier.unsupported.length) {
    const kinds = frontier.unsupported.map((u) => u.kind).sort();
    if (onUnsupported === 'full') fallback = fallback || { reason: `unsupported:${kinds[0]}`, expandedToFull: true };
    else for (const k of new Set(kinds)) reasons.push(`unsupported-construct:${k}`);
  }
  if (frontier.unresolved.size) reasons.push('unresolved-callee');

  let regionIds = [...frontier.region.keys()].sort();
  if (fallback) regionIds = [...callGraph.functions.keys()].sort();
  const regionGraph = { ...callGraph, functions: new Map(regionIds.map((id) => [id, callGraph.functions.get(id)])) };

  const run = opts.engine || runTaintEngine;
  const raw = run(perFileIR, regionGraph, engineOptsOf(opts));
  for (const r of engineIncomplete(raw)) reasons.push(`engine:${r}`);

  let findings = pickFindings(raw, sites, q);
  let siblingSuppressed = 0;
  if (q.accessPath && !fieldAttributable(frontier)) { siblingSuppressed = findings.length; findings = []; }

  const sbIn = regionIds.filter((id) => sourceBearing(callGraph.functions.get(id)));
  res.sites = sites.map((s) => ({ file: s.file, line: s.line, fnQid: s.fnQid, nodeId: s.nodeId, sinkId: s.sinkId, kind: s.kind }));
  res.findings = findings;
  res.siblingFieldSuppressed = siblingSuppressed;
  res.witness = findings.length ? 'forward-engine-corroborated' : 'none';
  res.candidateFilter = { role: 'candidate-filter-only', sourceBearingFunctionsInRegion: sbIn.length, candidate: sbIn.length > 0 || frontier.terminals.has('param') || frontier.terminals.has('free') };
  res.selectorCoverage = {
    totalFunctions: total,
    selectedFunctions: frontier.region.size,
    selectedFraction: total ? frontier.region.size / total : 0,
    byReason: countReasons(frontier.region),
    followed: { ...frontier.followed },
    maxDepthReached: frontier.maxDepthReached,
    workSteps: frontier.steps,
    limits: { maxCallerDepth: frontier.maxDepth, maxWork: frontier.maxWork },
    limitHits: frontier.limits.map((l) => ({ ...l })),
    unsupported: frontier.unsupported.map((u) => ({ ...u })),
    unresolvedCallees: [...frontier.unresolved.values()],
    terminals: [...frontier.terminals].sort(),
  };
  res.analyzedFunctions = regionIds.length;
  res.fallback = fallback;
  res.completion = completionOf(reasons, frontier, fallback);
  res.negativeClaimAllowed = res.completion.negativeClaimAllowed;
  res.verdict = findings.length ? 'flow-found' : (res.negativeClaimAllowed ? 'no-flow-in-modeled-scope' : 'unknown');
  if (useCache) resultCachePut(key, res);
  return res;
}

function countReasons(region) {
  const out = {};
  for (const set of region.values()) for (const r of set) out[r] = (out[r] || 0) + 1;
  return out;
}

function completionOf(reasons, frontier, fallback) {
  const unexplored = frontier.depthCut + frontier.workLeft;
  const partial = reasons.length > 0;
  return makeCompletion({
    status: partial ? 'partial' : 'complete',
    modelCoverage: partial ? 'partial' : 'complete',
    reasons,
    unexploredFrontierCount: partial ? Math.max(unexplored, 0) : 0,
    limits: { maxCallerDepth: frontier.maxDepth, maxWork: frontier.maxWork, expandedToFull: !!fallback },
    unit: 'demand-query',
  });
}

function unavailable(res, reason, total) {
  res.sites = [];
  res.findings = [];
  res.siblingFieldSuppressed = 0;
  res.witness = 'none';
  res.candidateFilter = { role: 'candidate-filter-only', sourceBearingFunctionsInRegion: 0, candidate: false };
  res.selectorCoverage = { totalFunctions: total, selectedFunctions: 0, selectedFraction: 0, byReason: {}, followed: {}, maxDepthReached: 0, workSteps: 0, limits: {}, limitHits: [], unsupported: [], unresolvedCallees: [], terminals: [] };
  res.analyzedFunctions = 0;
  res.fallback = null;
  res.completion = makeCompletion({ status: 'unavailable', reasons: [reason], unit: 'demand-query' });
  res.negativeClaimAllowed = false;
  res.verdict = 'unknown';
  return res;
}

/** Reference answer: the same query over the FULL function set. */
export function runFullSinkQuery(perFileIR, callGraph, query, opts = {}) {
  const q = normalizeSinkQuery(query);
  const digests = { graphDigest: opts.graphDigest ?? graphDigest(callGraph), configDigest: opts.configDigest ?? configDigest(opts) };
  const res = baseResult(q, sinkQueryKey(q, digests), digests);
  res.mode = 'full';
  const total = callGraph.functions.size;
  const sites = findSinkSites(callGraph, q);
  if (!sites.length) return unavailable(res, 'sink-site-not-found', total);
  const run = opts.engine || runTaintEngine;
  const raw = run(perFileIR, callGraph, engineOptsOf(opts));
  let findings = pickFindings(raw, sites, q);
  let suppressed = 0;
  if (q.accessPath) {
    const frontier = new Frontier(callGraph, opts);
    for (const s of sites) seedFrontier(frontier, callGraph.functions.get(s.fnQid), s, q);
    frontier.run();
    if (!fieldAttributable(frontier)) { suppressed = findings.length; findings = []; }
  }
  res.sites = sites.map((s) => ({ file: s.file, line: s.line, fnQid: s.fnQid, nodeId: s.nodeId, sinkId: s.sinkId, kind: s.kind }));
  res.findings = findings;
  res.siblingFieldSuppressed = suppressed;
  res.analyzedFunctions = total;
  res.engineIncomplete = engineIncomplete(raw);
  return res;
}

/** Compare a demand result with the full reference for the same query. */
export function compareToFull(demand, full) {
  const a = demand.findings.map(findingKey);
  const b = full.findings.map(findingKey);
  const missing = b.filter((k) => !a.includes(k));
  const extra = a.filter((k) => !b.includes(k));
  return { equal: missing.length === 0 && extra.length === 0, missing, extra };
}

/** Run a batch of queries (the shape the optional dataflow/index.js hook uses). */
export function runDemandQueries(perFileIR, callGraph, queries, opts = {}) {
  return (queries || []).map((q) => runDemandSinkQuery(perFileIR, callGraph, q, opts));
}

/** Enumerate every sink site in the graph as a query (used by parity checks and the benchmark). */
export function enumerateSinkQueries(callGraph) {
  return findSinkSites(callGraph, {}).map((s) => ({ file: s.file, line: s.line, nodeId: s.nodeId, fnQid: s.fnQid, sinkId: s.sinkId }));
}

// ---------------------------------------------------------------------------
// R02.5: adapters over the existing reverse implementations
// ---------------------------------------------------------------------------

/**
 * Compare the demand region of a query result with the coarse tabulation slice
 * for the same sink functions, using the shared completion metadata. Nothing is
 * replaced: the report states which role each selector keeps.
 */
export function reconcileSelectors(callGraph, demandResult) {
  const sinkFns = [...new Set((demandResult.sites || []).map((s) => s.fnQid))];
  const tab = reachabilitySliceWithCompletion(sinkFns.map((fnQid) => ({ fnQid })), callGraph);
  const demandIds = new Set();
  const frontier = new Frontier(callGraph, {});
  for (const s of findSinkSites(callGraph, demandResult.query)) seedFrontier(frontier, callGraph.functions.get(s.fnQid), s, demandResult.query);
  frontier.run();
  for (const id of frontier.region.keys()) demandIds.add(id);
  const onlyDemand = [...demandIds].filter((x) => !tab.reachable.has(x)).sort();
  const onlyTabulation = [...tab.reachable].filter((x) => !demandIds.has(x)).sort();
  return {
    roles: {
      tabulation: 'coarse caller-only selector; kept, cannot see producer helpers or callback registrars',
      backward: 'explanation trace of an emitted finding; kept, not a selector',
      ifdsPrecise: 'depth-capped predecessor chain; kept, now reports a completion record',
      demand: 'sink-keyed selector with forward corroboration',
    },
    tabulationCompletion: makeCompletion({ status: tab.completion.status, reasons: tab.completion.reasons, unexploredFrontierCount: tab.completion.unexploredFrontierCount, limits: tab.completion.limits, unit: 'tabulation-slice' }),
    demandCompletion: demandResult.completion,
    onlyDemand,
    onlyTabulation,
    tabulationMissedDemandFunctions: onlyDemand.length,
  };
}

export const _internals = { Frontier, fnInfo, segOverlap, calleeName, sourceBearing };
