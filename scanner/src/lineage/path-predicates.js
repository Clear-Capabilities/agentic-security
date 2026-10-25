//
// path-predicates.js: branch conditions carried with a witness (DAG-04, R04.1 to R04.4).
//
// A reconstructed witness is a chain of provenance edges. Each edge was emitted at one CFG node of one
// function (`edge.scope`, `edge.siteNodeId`). This module answers, for every edge on a witness:
//   * which branch conditions MUST hold for that node to execute (predicate references, with branch
//     polarity and the value versions of the variables the condition reads), and
//   * whether the conjunction of those conditions along the whole witness can hold at all.
//
// Rules this module keeps:
//   * A node is guarded by (branch, polarity) only when that arm's first node DOMINATES it and has the
//     branch as its only predecessor. A node after a join is guarded by neither arm. So alternatives are
//     never conjoined by construction: the two arms of one branch cannot both guard the same node.
//   * One witness is one execution path. If it needs both arms of one branch in one frame, that is a
//     reported contradiction (`mutually-exclusive-branches`), not a silent conjunction. In a loop the
//     two arms may belong to different iterations, so the answer there is `unknown`.
//   * Different witnesses are never merged: each carries its own conjunction (alternatives stay distinct).
//   * A disjunction inside one condition (`a || b`) is kept as distinct alternatives (DNF, bounded).
//   * Every variable is identified by (call frame, name, reaching-definition versions), so a reassigned
//     variable is a different value, and a callee parameter is tied to the caller's argument only through
//     an explicit call binding.
//   * Existing bounded abstract domains first: `numeric-domain.js` intervals narrowed through
//     `symbolic-exec.js` `assume`, plus equality on constants and boolean atoms. No solver is needed.
//
// Result vocabulary (R04.4): feasible-model, infeasible-under-model, unknown, unsupported, timeout. Every
// result carries the semantics version and its limitations. SATISFIABILITY UNDER THIS MODEL DOES NOT IMPLY
// A WORKING EXPLOIT, and `infeasible-under-model` is relative to the model's stated limits, not a proof
// about the running program.
//
// Pure: no filesystem, no engine imports.

import crypto from 'node:crypto';
import { computeDominators } from '../ir/ssa.js';
import { accessPathOf } from '../dataflow/access-paths.js';
import * as N from '../dataflow/numeric-domain.js';
import { assume, newState } from '../dataflow/symbolic-exec.js';
import { computeReachingDefinitions, ENTRY_VERSION } from './value-versions.js';
import { exprRoots, walkExpr } from './source-seeding.js';

export const PATH_PREDICATE_VERSION = 'path-predicates/1';
export const FEASIBILITY_RESULTS = Object.freeze(['feasible-model', 'infeasible-under-model', 'unknown', 'unsupported', 'timeout']);
export const SATISFIABILITY_NOTE = 'Satisfiability under this model does not imply a working exploit.';

export const PREDICATE_LIMITS = Object.freeze({ maxAlternativesPerClause: 16, maxCombinations: 256, maxClauses: 256 });

const BASE_LIMITATIONS = Object.freeze([
  'Bounded abstract domains only: numeric intervals, equality against constants and boolean atoms.',
  'A condition outside those domains is recorded as an unmodeled predicate and never decides feasibility.',
  'Mutation of a variable through a callee, an alias or a closure is not modeled.',
  'infeasible-under-model is relative to this model, not a proof about the running program.',
]);

const REFLECTIVE_CALLEES = new Set([
  'eval', 'Function', 'Reflect.apply', 'Reflect.get', 'Reflect.set', 'Reflect.construct', 'getattr', 'setattr', '__import__',
  'importlib.import_module', 'Class.forName', 'invoke', 'instance_eval', 'class_eval', 'public_send', 'constantize', 'vm.runInContext', 'vm.runInNewContext',
]);

const NUM_OPS = new Set(['<', '<=', '>', '>=', '==', '===', '!=', '!==']);
const NEG_OP = { '<': '>=', '<=': '>', '>': '<=', '>=': '<', '==': '!=', '===': '!==', '!=': '==', '!==': '===' };

const sha12 = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);
const arr = (v) => (Array.isArray(v) ? v : []);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

// ---- CFG helpers -------------------------------------------------------------------------------------

const _cfgCache = new WeakMap();

function cfgInfo(fn) {
  const cfg = fn?.cfg;
  if (!cfg || !cfg.nodes) return null;
  let info = _cfgCache.get(cfg);
  if (info) return info;
  const nodesObj = cfg.nodes instanceof Map ? Object.fromEntries(cfg.nodes) : cfg.nodes;
  const normalized = { entry: cfg.entry, nodes: nodesObj };
  const preds = new Map(Object.keys(nodesObj).map((k) => [k, []]));
  for (const [id, n] of Object.entries(nodesObj)) for (const s of arr(n.succ)) if (preds.has(s)) preds.get(s).push(id);
  info = { nodes: nodesObj, entry: cfg.entry, preds, dom: computeDominators(normalized), rd: null, reach: new Map() };
  _cfgCache.set(cfg, info);
  return info;
}

function reachingDefs(fn, info) {
  if (!info.rd) info.rd = computeReachingDefinitions({ cfg: { entry: info.entry, nodes: info.nodes }, params: fn.params ?? [] });
  return info.rd;
}

/** Can `to` be reached from `from` by following successors (used to detect "this branch is inside a loop"). */
function reachableFrom(info, from, to) {
  const key = `${from}>${to}`;
  if (info.reach.has(key)) return info.reach.get(key);
  const seen = new Set(); const stack = [...arr(info.nodes[from]?.succ)]; let found = false;
  while (stack.length && !found) {
    const n = stack.pop();
    if (n === to) { found = true; break; }
    if (seen.has(n)) continue;
    seen.add(n);
    for (const s of arr(info.nodes[n]?.succ)) stack.push(s);
  }
  info.reach.set(key, found);
  return found;
}

/**
 * Branch arms guarding a CFG node: [{ branchNodeId, polarity: true|false }]. Sound for "must hold": an arm
 * guards only when it dominates the node and has the branch as its only predecessor.
 */
export function guardsFor(fn, nodeId) {
  const info = cfgInfo(fn);
  if (!info || !info.nodes[nodeId]) return [];
  const dom = info.dom.get(nodeId);
  if (!dom) return [];
  const out = [];
  for (const [bid, b] of Object.entries(info.nodes)) {
    if (b.kind !== 'if' || bid === nodeId) continue;
    const succ = arr(b.succ);
    if (succ.length !== 2 || succ[0] === succ[1]) continue;
    for (const [idx, polarity] of [[0, true], [1, false]]) {
      const arm = succ[idx];
      if (!dom.has(arm)) continue;
      const armPreds = info.preds.get(arm) ?? [];
      if (armPreds.length === 1 && armPreds[0] === bid) out.push({ branchNodeId: bid, polarity });
    }
  }
  return out.sort((a, b) => (a.branchNodeId < b.branchNodeId ? -1 : a.branchNodeId > b.branchNodeId ? 1 : a.polarity ? -1 : 1));
}

// ---- conditions ----------------------------------------------------------------------------------------

function renderExpr(e) {
  if (!e || typeof e !== 'object') return '?';
  switch (e.kind) {
    case 'ident': return e.name;
    case 'literal': return typeof e.value === 'string' ? JSON.stringify(e.value) : String(e.value);
    case 'member': { const o = renderExpr(e.object); return `${o}.${e.prop}`; }
    case 'binary': case 'logical': return `(${renderExpr(e.left)} ${e.op} ${renderExpr(e.right)})`;
    case 'unary': case 'unary-not': return `!${renderExpr(e.operand ?? e.argument)}`;
    default: return e.kind ?? '?';
  }
}

/** The variable a leaf expression reads, or null. `scopeCtx.versionsOf(path)` gives its reaching definitions. */
function varOf(e, scopeCtx) {
  if (!e) return null;
  if (e.kind === 'ident' || e.kind === 'member') {
    const p = e.kind === 'ident' ? e.name : accessPathOf(e);
    if (typeof p !== 'string' || !p) return null;
    return { frame: scopeCtx.frame, name: p, ver: scopeCtx.versionsOf(p).join(',') };
  }
  return null;
}

export const varKey = (v) => `${v.frame}|${v.name}@${v.ver}`;

const TRUE_ALTS = [[]];
const FALSE_ALTS = [];

/**
 * Condition to disjunctive normal form: an array of alternatives, each a conjunction (array) of literals.
 * `[[]]` is true, `[]` is false. Bounded: an expansion beyond the cap collapses to one unmodeled literal.
 */
export function condToDnf(expr, polarity, scopeCtx) {
  const tooBig = (alts) => alts.length > PREDICATE_LIMITS.maxAlternativesPerClause;
  const opaque = () => [[{ t: 'opaque', text: renderExpr(expr).slice(0, 120), polarity }]];
  if (!expr) return opaque();
  if (expr.kind === 'logical' && (expr.op === '&&' || expr.op === '||')) {
    const conj = (expr.op === '&&') === polarity; // && true, or || false: both operands must hold (in their polarity)
    const l = condToDnf(expr.left, polarity, scopeCtx);
    const r = condToDnf(expr.right, polarity, scopeCtx);
    if (conj) {
      const out = [];
      for (const a of l) for (const b of r) out.push([...a, ...b]);
      return tooBig(out) ? opaque() : out;
    }
    const out = [...l, ...r];
    return tooBig(out) ? opaque() : out;
  }
  if (expr.kind === 'unary' || expr.kind === 'unary-not') {
    if (expr.kind === 'unary-not' || expr.op === '!') return condToDnf(expr.operand ?? expr.argument, !polarity, scopeCtx);
    return opaque();
  }
  if (expr.kind === 'literal') {
    const truthy = Boolean(expr.value);
    return truthy === polarity ? TRUE_ALTS.map((a) => a.slice()) : FALSE_ALTS.slice();
  }
  if ((expr.kind === 'binary' || expr.kind === 'bin') && NUM_OPS.has(expr.op)) {
    const op = polarity ? expr.op : NEG_OP[expr.op];
    const lv = varOf(expr.left, scopeCtx); const rv = varOf(expr.right, scopeCtx);
    const lc = expr.left?.kind === 'literal' ? expr.left.value : undefined;
    const rc = expr.right?.kind === 'literal' ? expr.right.value : undefined;
    const isNum = (x) => typeof x === 'number' && Number.isFinite(x);
    if ((lv || isNum(lc)) && (rv || isNum(rc)) && (lv || rv)) {
      return [[{ t: 'num', op, left: lv ? { v: lv } : { c: lc }, right: rv ? { v: rv } : { c: rc }, text: renderExpr(expr).slice(0, 120) }]];
    }
    const strEq = ['==', '===', '!=', '!=='].includes(expr.op);
    if (strEq && ((lv && typeof rc === 'string') || (rv && typeof lc === 'string'))) {
      const v = lv ?? rv; const value = typeof rc === 'string' ? rc : lc;
      const equal = expr.op === '==' || expr.op === '===';
      return [[{ t: 'eq', v, value, equal: polarity ? equal : !equal, text: renderExpr(expr).slice(0, 120) }]];
    }
    return opaque();
  }
  const v = varOf(expr, scopeCtx);
  if (v) return [[{ t: 'bool', v, truth: polarity, text: renderExpr(expr).slice(0, 120) }]];
  return opaque();
}

// ---- collection ----------------------------------------------------------------------------------------

function calleeName(callee) {
  if (typeof callee === 'string') return callee;
  if (!callee) return null;
  if (callee.kind === 'ident') return callee.name;
  if (callee.kind === 'member') { const o = calleeName(callee.object); return o ? `${o}.${callee.prop}` : callee.prop; }
  return null;
}

function callsAt(node) {
  const calls = [];
  if (!node) return calls;
  for (const root of exprRoots(node)) walkExpr(root, (e) => { if (e.kind === 'call') calls.push(e); });
  if (node.kind === 'call' && node.callee) calls.unshift({ kind: 'call', callee: node.callee, args: node.args ?? [] });
  return calls;
}

/**
 * Collect the conditions a witness requires.
 *
 * @param {object[]} hops   `path.hops` of a reconstructed path (source first)
 * @param {{fnOf:(qid:string)=>object|null}} o
 * @returns {object} { semanticsVersion, frames, clauses, edgeGuards, bindings, unsupported, limitations }
 */
export function collectWitnessConditions(hops, { fnOf } = {}) {
  const frames = []; // { id, scope, context }
  const stack = [];  // indices into frames (the active call stack)
  const clauses = new Map();
  const edgeGuards = {};
  const bindings = [];
  const unsupported = [];
  const limitations = [...BASE_LIMITATIONS];
  const lookup = typeof fnOf === 'function' ? fnOf : () => null;
  let pendingCall = null; // call-arg-bind seen on the previous hop

  const hopList = arr(hops);
  for (let i = 0; i < hopList.length; i++) {
    const h = hopList[i];
    const scope = h.scope;
    // ---- frame tracking: a scope change is a call (push) or a return to an open frame (pop) ----
    const cur = stack.length ? frames[stack[stack.length - 1]] : null;
    if (!cur || cur.scope !== scope) {
      const parentIdx = stack.length >= 2 ? stack[stack.length - 2] : -1;
      if (parentIdx >= 0 && frames[parentIdx].scope === scope) stack.pop();
      else { frames.push({ id: `f${frames.length}`, scope, context: h.context ?? null }); stack.push(frames.length - 1); }
    }
    const frame = frames[stack[stack.length - 1]];
    const fn = lookup(scope);
    const info = fn ? cfgInfo(fn) : null;
    if (!info) {
      unsupported.push({ reason: 'no-cfg', scope, edgeId: h.edgeId ?? null });
      continue;
    }
    const node = info.nodes[h.siteNodeId];

    // ---- pending call binding: the previous hop bound arguments and this hop is in the callee ----
    if (pendingCall && pendingCall.callerFrameId !== frame.id && pendingCall.calleeScope === scope) {
      const callee = fn;
      const callerFrame = frames.find((f) => f.id === pendingCall.callerFrameId);
      for (const [idx, p] of arr(callee.params).entries()) {
        const a = pendingCall.args[idx];
        if (!a) continue;
        if (a.kind === 'literal' && (typeof a.value === 'number' || typeof a.value === 'string')) {
          bindings.push({ calleeFrame: frame.id, param: p, const: a.value });
        } else {
          const ap = a.kind === 'ident' ? a.name : a.kind === 'member' ? accessPathOf(a) : null;
          if (ap && callerFrame) {
            bindings.push({ calleeFrame: frame.id, param: p, callerFrame: callerFrame.id, arg: ap, argVer: pendingCall.argVersions(ap) });
          }
        }
      }
      pendingCall = null;
    }
    if ((h.outSubKind === 'call-arg-bind' || h.inSubKind === 'call-arg-bind') && node) {
      const calls = callsAt(node);
      const rd = reachingDefs(fn, info);
      pendingCall = {
        callerFrameId: frame.id,
        calleeScope: null,
        calls,
        args: [],
        argVersions: (p) => rd.versionsAt(h.siteNodeId, p).join(','),
      };
      // The callee scope is the next hop whose scope differs; resolve it lazily by looking ahead.
      const next = hopList.slice(i + 1).find((x) => x.scope !== scope);
      if (next) {
        pendingCall.calleeScope = next.scope;
        const calleeFn = lookup(next.scope);
        const nm = calleeFn?.name;
        const match = calls.find((c) => {
          const n = calleeName(c.callee);
          return n && nm && (n === nm || n.endsWith(`.${nm}`));
        }) ?? (calls.length === 1 ? calls[0] : null);
        pendingCall.args = match ? arr(match.args) : [];
      } else pendingCall = null;
    }

    // ---- reflective dispatch anywhere in this frame's function could rewrite any local: not assessable ----
    if (!frame.reflectiveChecked) {
      frame.reflectiveChecked = true;
      for (const [nid, n] of Object.entries(info.nodes)) {
        for (const c of callsAt(n)) {
          const nm = calleeName(c.callee);
          if (nm && REFLECTIVE_CALLEES.has(nm)) unsupported.push({ reason: 'reflective-dispatch', callee: nm, scope, nodeId: nid, edgeId: h.edgeId ?? null });
        }
      }
    }

    // ---- guards for this site ----
    const rd = reachingDefs(fn, info);
    const refsHere = [];
    for (const g of guardsFor(fn, h.siteNodeId)) {
      const bnode = info.nodes[g.branchNodeId];
      const key = `${frame.id}|${g.branchNodeId}|${g.polarity}`;
      let clause = clauses.get(key);
      if (!clause) {
        const scopeCtx = { frame: frame.id, versionsOf: (p) => rd.versionsAt(g.branchNodeId, p) };
        const alts = condToDnf(bnode.cond ?? bnode.condition, g.polarity, scopeCtx);
        clause = {
          ref: `pred:${sha12(`${frame.id}|${scope}|${g.branchNodeId}|${g.polarity}`)}`,
          frame: frame.id, scope, branchNodeId: g.branchNodeId, polarity: g.polarity,
          text: renderExpr(bnode.cond ?? bnode.condition).slice(0, 160),
          line: bnode.line ?? null,
          alts, inLoop: reachableFrom(info, g.branchNodeId, g.branchNodeId),
          atEdgeIds: [],
          versions: [...new Set(alts.flat().flatMap((l) => (l.t === 'num' ? [l.left.v, l.right.v] : l.v ? [l.v] : [])).filter(Boolean).map((v) => `${v.name}@${v.ver}`))].sort(),
          consts: {},
        };
        // A definition inside the loop that also feeds this branch produces a NEW value every iteration, so the
        // same definition id does not mean the same value across iterations. Make such variables clause-local.
        if (clause.inLoop) {
          for (const l of clause.alts.flat()) {
            for (const v of (l.t === 'num' ? [l.left.v, l.right.v] : l.v ? [l.v] : [])) {
              if (!v) continue;
              const vers = rd.versionsAt(g.branchNodeId, v.name);
              if (vers.some((x) => x !== ENTRY_VERSION && info.nodes[x] && reachableFrom(info, x, g.branchNodeId) && reachableFrom(info, g.branchNodeId, x))) v.ver = `${v.ver}#iter:${clause.ref}`;
            }
          }
          clause.versions = [...new Set(clause.alts.flat().flatMap((l) => (l.t === 'num' ? [l.left.v, l.right.v] : l.v ? [l.v] : [])).filter(Boolean).map((v) => `${v.name}@${v.ver}`))].sort();
        }
        // Constants established by a single reaching assignment of a literal.
        for (const l of clause.alts.flat()) {
          for (const v of (l.t === 'num' ? [l.left.v, l.right.v] : l.v ? [l.v] : [])) {
            if (!v) continue;
            const vers = rd.versionsAt(g.branchNodeId, v.name);
            if (vers.length === 1 && vers[0] !== ENTRY_VERSION) {
              const def = info.nodes[vers[0]];
              if (def?.kind === 'assign' && def.source?.kind === 'literal' && (typeof def.source.value === 'number' || typeof def.source.value === 'string')) clause.consts[varKey(v)] = def.source.value;
            }
          }
        }
        clauses.set(key, clause);
      }
      if (h.edgeId && !clause.atEdgeIds.includes(h.edgeId)) clause.atEdgeIds.push(h.edgeId);
      refsHere.push({ ref: clause.ref, polarity: g.polarity, branchNodeId: g.branchNodeId, versions: clause.versions });
    }
    if (h.edgeId) edgeGuards[h.edgeId] = refsHere;
  }
  if (clauses.size > PREDICATE_LIMITS.maxClauses) limitations.push(`more than ${PREDICATE_LIMITS.maxClauses} guarding branches; evaluation is bounded`);
  return {
    semanticsVersion: PATH_PREDICATE_VERSION,
    frames, clauses: [...clauses.values()], edgeGuards, bindings, unsupported, limitations,
  };
}

// ---- evaluation ----------------------------------------------------------------------------------------

class Aliases {
  constructor() { this.p = new Map(); }
  find(k) { let r = k; while (this.p.has(r) && this.p.get(r) !== r) r = this.p.get(r); return r; }
  union(a, b) { const ra = this.find(a); const rb = this.find(b); if (ra !== rb) this.p.set(ra, rb); }
}

function aliasesOf(collected) {
  const al = new Aliases();
  const consts = new Map();
  for (const b of arr(collected.bindings)) {
    const pk = `${b.calleeFrame}|${b.param}@${ENTRY_VERSION}`;
    if (b.const !== undefined) consts.set(pk, b.const);
    else al.union(pk, `${b.callerFrame}|${b.arg}@${b.argVer}`);
  }
  for (const c of arr(collected.clauses)) for (const [k, v] of Object.entries(c.consts ?? {})) consts.set(k, v);
  return { al, consts };
}

function checkCombo(literals, collected) {
  const { al, consts } = aliasesOf(collected);
  const canon = (v) => al.find(varKey(v));
  const constOf = (v) => consts.get(canon(v)) ?? consts.get(varKey(v));
  const state = newState();
  for (const [k, v] of consts) if (typeof v === 'number') state.vars.set(al.find(k), N.constant(v));
  const bools = new Map(); const eqs = new Map();
  let unmodeled = 0; let bottom = false; const core = new Set();
  for (const lit of literals) {
    if (bottom) break;
    if (lit.t === 'opaque') { unmodeled += 1; continue; }
    if (lit.t === 'bool') {
      const k = canon(lit.v);
      if (bools.has(k) && bools.get(k).truth !== lit.truth) { bottom = true; core.add(lit.ref); core.add(bools.get(k).ref); } else bools.set(k, { truth: lit.truth, ref: lit.ref });
      continue;
    }
    if (lit.t === 'eq') {
      const k = canon(lit.v); const known = constOf(lit.v);
      if (known !== undefined) {
        if ((known === lit.value) !== lit.equal) { bottom = true; core.add(lit.ref); }
        continue;
      }
      const e = eqs.get(k) ?? { eq: new Map(), ne: new Map() };
      if (lit.equal) {
        if ([...e.eq.keys()].some((x) => x !== lit.value) || e.ne.has(lit.value)) { bottom = true; core.add(lit.ref); for (const r of [...e.eq.values(), ...e.ne.values()]) core.add(r); }
        e.eq.set(lit.value, lit.ref);
      } else {
        if (e.eq.has(lit.value)) { bottom = true; core.add(lit.ref); core.add(e.eq.get(lit.value)); }
        e.ne.set(lit.value, lit.ref);
      }
      eqs.set(k, e);
      continue;
    }
    if (lit.t === 'num') {
      const side = (s) => (s.v ? { kind: 'ident', name: canon(s.v) } : { kind: 'literal', value: s.c });
      const next = assume(state, { kind: 'bin', op: lit.op, left: side(lit.left), right: side(lit.right) });
      if (next.bottom) { bottom = true; core.add(lit.ref); for (const l of literals) if (l.ref && l.t === 'num') core.add(l.ref); break; }
      state.vars = next.vars;
    }
  }
  return { bottom, unmodeled, core: [...core] };
}

/**
 * Decide the conjunction of a witness's conditions under the bounded abstract model.
 *
 * @param {object} collected `collectWitnessConditions` result
 * @param {object} [o] { maxCombinations, deadlineMs, now }
 */
export function evaluateWitnessConditions(collected, o = {}) {
  const now = o.now ?? Date.now;
  const started = now();
  const base = { semanticsVersion: PATH_PREDICATE_VERSION, satisfiabilityNote: SATISFIABILITY_NOTE, limitations: [...arr(collected.limitations)] };
  const clauses = arr(collected.clauses);
  const unmodeledRefs = [];

  if (arr(collected.unsupported).length) {
    const reasons = [...new Set(collected.unsupported.map((u) => u.reason))].sort();
    return { ...base, status: 'unsupported', reasons, unsupported: collected.unsupported, contradiction: null, unmodeledPredicates: [], clauseRefs: clauses.map((c) => c.ref) };
  }
  if (!clauses.length) return { ...base, status: 'feasible-model', reasons: ['no-guarding-branches'], contradiction: null, unmodeledPredicates: [], clauseRefs: [] };

  // One witness, one execution path: both arms of one branch in one frame cannot both hold.
  const byBranch = new Map();
  for (const c of clauses) {
    const k = `${c.frame}|${c.branchNodeId}`;
    if (!byBranch.has(k)) byBranch.set(k, []);
    byBranch.get(k).push(c);
  }
  const looped = [];
  for (const list of byBranch.values()) {
    if (list.length === 2 && list[0].polarity !== list[1].polarity) {
      if (list.some((c) => c.inLoop)) looped.push(...list.map((c) => c.ref));
      else {
        return { ...base, status: 'infeasible-under-model', reasons: ['mutually-exclusive-branches'], contradiction: { kind: 'mutually-exclusive-branches', refs: list.map((c) => c.ref).sort() }, unmodeledPredicates: [], clauseRefs: clauses.map((c) => c.ref) };
      }
    }
  }

  // Expand alternatives (distinct, bounded) into combinations; a witness is feasible when ANY combination holds.
  let combos = [[]];
  const maxCombos = o.maxCombinations ?? PREDICATE_LIMITS.maxCombinations;
  for (const c of clauses) {
    const tagged = c.alts.map((alt) => alt.map((l) => ({ ...l, ref: c.ref })));
    const next = [];
    for (const base0 of combos) for (const alt of tagged) { next.push([...base0, ...alt]); if (next.length > maxCombos) break; }
    combos = next;
    if (combos.length > maxCombos) {
      return { ...base, status: 'unknown', reasons: ['alternative-explosion'], contradiction: null, unmodeledPredicates: [], clauseRefs: clauses.map((cl) => cl.ref), limitHit: 'maxCombinations' };
    }
  }
  if (!combos.length) {
    return { ...base, status: 'infeasible-under-model', reasons: ['constant-false-condition'], contradiction: { kind: 'constant-false-condition', refs: clauses.filter((c) => c.alts.length === 0).map((c) => c.ref).sort() }, unmodeledPredicates: [], clauseRefs: clauses.map((c) => c.ref) };
  }
  let best = null; const cores = [];
  for (const combo of combos) {
    if (o.deadlineMs !== undefined && now() - started > o.deadlineMs) {
      return { ...base, status: 'timeout', reasons: ['deadline'], contradiction: null, unmodeledPredicates: [], clauseRefs: clauses.map((c) => c.ref) };
    }
    const r = checkCombo(combo, collected);
    if (r.bottom) { cores.push(r.core); continue; }
    if (!best || r.unmodeled < best.unmodeled) best = { ...r, combo };
  }
  if (!best) {
    return { ...base, status: 'infeasible-under-model', reasons: ['contradictory-conditions'], contradiction: { kind: 'contradictory-conditions', refs: [...new Set(cores.flat())].sort() }, unmodeledPredicates: [], clauseRefs: clauses.map((c) => c.ref) };
  }
  for (const l of best.combo) if (l.t === 'opaque') unmodeledRefs.push(l.ref);
  if (best.unmodeled > 0 || looped.length) {
    const reasons = [];
    if (best.unmodeled > 0) reasons.push('unmodeled-predicates');
    if (looped.length) reasons.push('branch-arms-in-loop');
    return { ...base, status: 'unknown', reasons, contradiction: null, unmodeledPredicates: [...new Set(unmodeledRefs)].sort(), clauseRefs: clauses.map((c) => c.ref) };
  }
  return { ...base, status: 'feasible-model', reasons: ['consistent-under-model'], contradiction: null, unmodeledPredicates: [], clauseRefs: clauses.map((c) => c.ref) };
}

/** A solver-neutral view of the collected conditions (see smt-orchestrator.js). Pure data. */
export function toSolverProblem(collected) {
  const { al, consts } = aliasesOf(collected);
  const canon = (v) => al.find(varKey(v));
  const vars = new Set(); const assertions = [];
  const nameOf = (v) => canon(v);
  for (const c of arr(collected.clauses)) {
    const alts = c.alts.map((alt) => alt.map((l) => {
      if (l.t === 'num') {
        for (const s of [l.left, l.right]) if (s.v) vars.add(nameOf(s.v));
        return { t: 'num', op: l.op, left: l.left.v ? { var: nameOf(l.left.v) } : { const: l.left.c }, right: l.right.v ? { var: nameOf(l.right.v) } : { const: l.right.c } };
      }
      if (l.t === 'eq') { vars.add(nameOf(l.v)); return { t: 'eq', var: nameOf(l.v), value: l.value, equal: l.equal }; }
      if (l.t === 'bool') { vars.add(nameOf(l.v)); return { t: 'bool', var: nameOf(l.v), truth: l.truth }; }
      return { t: 'opaque', text: l.text };
    }));
    assertions.push({ ref: c.ref, alternatives: alts });
  }
  return { semanticsVersion: PATH_PREDICATE_VERSION, logic: 'QF_LIA+EUF', vars: [...vars].sort(), constants: Object.fromEntries([...consts].map(([k, v]) => [al.find(k), v])), assertions };
}
