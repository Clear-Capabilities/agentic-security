// A lineage VIEW of the Haskell call graph (X-004).
//
// The field-identity engine behind the Data Flow Explorer seeds identities at a function's ENTRY from
// matched member reads (`req.body.email`), and enumerates privacy sinks only at call-STATEMENT sites. The
// Haskell IR is JS-shaped but differs in exactly the ways that matter to that machinery:
//
//   * a source is a monadic call bound to a variable (`s <- jsonData`), and its fields are read later
//     (`email s`), so there is no member read to seed;
//   * a sink is wrapped (`liftIO (execute conn q row)`) or bound to a discarded variable, so it is never a
//     statement-level call;
//   * a request body setter was lowered to an assignment (to keep the URL clean of body taint).
//
// This module rewrites a CLONE of each Haskell function so the same machinery sees what the code means,
// and nothing else: sources become member reads on a synthetic root (`$hs.<Module.name>[.<field>]`) with
// one property per FIELD the program actually reads, lifts are unwrapped, and body-setter assignments become
// call statements. The original call graph (shared with the taint engine) is never mutated.
//
// What it does not do is also part of the contract: a field the program never reads on a source value is not
// invented, and a source whose fields cannot be enumerated (it is only passed whole to code outside the
// project) is seeded at container level and disclosed as such, never as a set of made-up fields.

import { matchSource } from '../dataflow/catalog.js';

export const HS_LINEAGE_ROOT = '$hs';
// the label of a record parameter handed to an exported function (see language/haskell-ir.js `recordParams`)
export const HS_PARAM_SOURCE = 'hs:record-parameter';
const isHsFile = (f) => typeof f === 'string' && /\.l?hs$/i.test(f);
const LIFT = /(?:^|\.)(?:liftIO|lift)$/;
const MAX_DEPTH = 3;

const clone = (o) => { try { return structuredClone(o); } catch { return JSON.parse(JSON.stringify(o)); } };

function walk(e, visit, depth = 0) {
  if (!e || typeof e !== 'object' || depth > 60) return;
  visit(e);
  switch (e.kind) {
    case 'member': walk(e.object, visit, depth + 1); break;
    case 'call': walk(e.callee, visit, depth + 1); for (const a of e.args || []) walk(a, visit, depth + 1); break;
    case 'binary': case 'logical': walk(e.left, visit, depth + 1); walk(e.right, visit, depth + 1); break;
    case 'tpl': for (const p of e.parts || []) walk(p, visit, depth + 1); break;
    case 'union': for (const p of e.options || []) walk(p, visit, depth + 1); break;
    case 'array': for (const p of e.elements || []) walk(p, visit, depth + 1); break;
    case 'object': for (const p of e.props || []) walk(p && p.value, visit, depth + 1); break;
    default: break;
  }
}
const nodesOf = (fn) => Object.values(fn.cfg.nodes);
const roots = (n) => { const r = []; if (n.kind === 'assign' && n.source) r.push(n.source); if (n.kind === 'call') { if (n.callee && typeof n.callee === 'object') r.push(n.callee); for (const a of n.args || []) r.push(a); } if (n.kind === 'return' && n.value) r.push(n.value); return r; };

/** unwrap `liftIO (x)` / `lift (x)` wrappers around a call expression (transparent for data flow). */
function unwrapLift(e) {
  let cur = e;
  while (cur && cur.kind === 'call' && typeof cur.callee === 'string' && LIFT.test(cur.callee) && (cur.args || []).length === 1 && cur.args[0] && cur.args[0].kind === 'call') cur = cur.args[0];
  return cur;
}

/** property names read off variable `name` across a function body. */
function fieldsRead(fn, name) {
  const props = new Set();
  let whole = false;
  for (const n of nodesOf(fn)) for (const r of roots(n)) {
    const parents = new Map();
    walk(r, (e) => {
      if (e.kind === 'member' && e.object && e.object.kind === 'ident' && e.object.name === name && typeof e.prop === 'string') props.add(e.prop);
      for (const k of ['object', 'left', 'right']) if (e[k] && typeof e[k] === 'object') parents.set(e[k], e);
      for (const k of ['args', 'elements', 'parts', 'options']) if (Array.isArray(e[k])) for (const c of e[k]) if (c) parents.set(c, e);
      if (Array.isArray(e.props)) for (const p of e.props) if (p && p.value) parents.set(p.value, e);
    });
    walk(r, (e) => { if (e.kind === 'ident' && e.name === name) { const p = parents.get(e); if (!(p && p.kind === 'member' && p.object === e)) whole = true; } });
  }
  return { props, whole };
}

/** fields read through a resolved callee's parameter when the variable is passed whole. */
function fieldsViaCallees(fn, name, fnByQid, depth, seen) {
  const out = new Set();
  if (depth > MAX_DEPTH) return out;
  for (const n of nodesOf(fn)) for (const r of roots(n)) walk(r, (e) => {
    if (e.kind !== 'call' || !e.hs || !e.hs.target) return;
    (e.args || []).forEach((a, i) => {
      if (!(a && a.kind === 'ident' && a.name === name)) return;
      const callee = fnByQid.get(e.hs.target);
      if (!callee || seen.has(`${callee.qid}#${i}`)) return;
      seen.add(`${callee.qid}#${i}`);
      const p = (callee.params || [])[i];
      const pname = typeof p === 'string' ? p : (p && p.name);
      if (!pname) return;
      for (const f of fieldsRead(callee, pname).props) out.add(f);
      for (const f of fieldsViaCallees(callee, pname, fnByQid, depth + 1, seen)) out.add(f);
    });
  });
  return out;
}

const memberOf = (obj, prop) => ({ kind: 'member', object: obj, prop });
const rootMember = (label) => memberOf({ kind: 'ident', name: HS_LINEAGE_ROOT }, label);

export function sourceLabelOf(call) { return typeof call.callee === 'string' ? call.callee : null; }

function transformFunction(fn, fnByQid) {
  const stats = { sources: 0, containerOnly: 0, unwrapped: 0, bodySetters: 0 };
  for (const [id, n] of Object.entries(fn.cfg.nodes)) {
    // lifts and body setters at statement level
    if (n.kind === 'call' && typeof n.callee === 'string' && LIFT.test(n.callee) && (n.args || []).length === 1 && n.args[0] && n.args[0].kind === 'call') {
      const inner = unwrapLift(n);
      n.callee = inner.callee; n.args = inner.args; n.hs = inner.hs || n.hs; stats.unwrapped++;
    }
    if (n.kind === 'assign' && n.source && n.source.kind === 'call') {
      const inner = unwrapLift(n.source);
      if (inner !== n.source) { n.source = inner; stats.unwrapped++; }
      if (n.hs && n.hs.bodySetter && n.source.kind === 'call') {
        // `$bodyN = setRequestBodyJSON body req` -> a call statement, so the sink is enumerable
        n.kind = 'call'; n.callee = n.source.callee; n.args = n.source.args; n.line = n.line ?? n.source.line; delete n.source; delete n.target; stats.bodySetters++;
        continue;
      }
      // a discarded or unused bind of a call: `_ <- execute ...` is a statement-level call
      if ((n.target === '_' || /^_\w*$/.test(n.target || '')) && !matchSource(n.source, fn.file)) { n.kind = 'call'; n.callee = n.source.callee; n.args = n.source.args; delete n.source; delete n.target; continue; }
    }
  }
  // The last expression of a function body is a `return` of a call (`handle acct = putStrLn (email acct)`). A sink is only
  // enumerated at a call STATEMENT, so the call is also placed before the return as a statement of its own; the return stays
  // (a caller still needs what the function returns).
  for (const [id, n] of Object.entries({ ...fn.cfg.nodes })) {
    if (n.kind !== 'return' || !n.value) continue;
    const v = unwrapLift(n.value);
    if (!v || v.kind !== 'call' || typeof v.callee !== 'string') continue;
    const sid = `${id}_stmt`;
    const stmt = { kind: 'call', line: v.line ?? n.line, callee: v.callee, args: v.args || [], hs: v.hs, succ: [id], pred: [...(n.pred || [])] };
    for (const pid of n.pred || []) {
      const pn = fn.cfg.nodes[pid];
      if (!pn) continue;
      pn.succ = (pn.succ || []).map((x) => (x === id ? sid : x));
      if (pn.thenEntry === id) pn.thenEntry = sid;
      if (pn.elseEntry === id) pn.elseEntry = sid;
    }
    n.pred = [sid];
    fn.cfg.nodes[sid] = stmt;
    stats.returnSinks = (stats.returnSinks || 0) + 1;
  }
  // sources
  for (const [id, n] of Object.entries(fn.cfg.nodes)) {
    if (n.kind !== 'assign' || !n.source || n.source.kind !== 'call' || typeof n.target !== 'string' || n.target.includes('.')) continue;
    const entry = matchSource(n.source, fn.file);
    if (!entry || !String(entry.id).startsWith('hs-src-')) continue;
    const label = sourceLabelOf(n.source);
    if (!label) continue;
    const lit = (n.source.args || []).find((a) => a && a.kind === 'literal' && typeof a.value === 'string' && /^[A-Za-z_][\w.-]*$/.test(a.value));
    const target = n.target;
    if (lit) {
      // `param "email"`: the argument names the field
      n.source = memberOf(rootMember(label), lit.value);
      n.hs = { ...(n.hs || {}), lineageSource: { label, fields: [lit.value], form: 'named-parameter' } };
      stats.sources++;
      continue;
    }
    const { props } = fieldsRead(fn, target);
    for (const f of fieldsViaCallees(fn, target, fnByQid, 1, new Set())) props.add(f);
    if (props.size) {
      n.source = { kind: 'object', props: [...props].sort().map((p) => ({ key: p, value: memberOf(rootMember(label), p) })) };
      n.hs = { ...(n.hs || {}), lineageSource: { label, fields: [...props].sort(), form: 'record-fields' } };
    } else {
      n.source = rootMember(label);
      n.hs = { ...(n.hs || {}), lineageSource: { label, fields: [], form: 'container' } };
      stats.containerOnly++;
    }
    stats.sources++;
  }
  // record-typed parameters of an entry point: a source of the record's fields, one per field the body (and its callees) reads
  for (const rp of (fn.hs && fn.hs.recordParams) || []) {
    const { props } = fieldsRead(fn, rp.name);
    for (const f of fieldsViaCallees(fn, rp.name, fnByQid, 1, new Set())) props.add(f);
    const fields = [...props].filter((f) => (rp.fields || []).includes(f)).sort();
    if (!fields.length) continue;
    const entry = Object.entries(fn.cfg.nodes).find(([, c]) => c.kind === 'entry');
    if (!entry) continue;
    const id = `n_param_${rp.name}`;
    const next = [...(entry[1].succ || [])];
    const node = { kind: 'assign', line: fn.line, target: rp.name, source: { kind: 'object', props: fields.map((p) => ({ key: p, value: memberOf(rootMember(HS_PARAM_SOURCE), p) })) }, succ: next, pred: [entry[0]], hs: { lineageSource: { label: HS_PARAM_SOURCE, fields, form: 'record-parameter', type: rp.type } } };
    fn.cfg.nodes[id] = node;
    for (const nid of next) { const nn = fn.cfg.nodes[nid]; if (nn) nn.pred = [...new Set([...(nn.pred || []).filter((x) => x !== entry[0]), id])]; }
    entry[1].succ = [id];
    stats.sources++; stats.paramSources = (stats.paramSources || 0) + 1;
  }
  cutNonContent(fn, stats);
  fn.hs = { ...(fn.hs || {}), lineageView: stats };
  return fn;
}

// A size or emptiness test carries none of the value's content: `length`/`null` of a field is a number or a boolean. In the lineage
// clone the call is replaced by a literal, so the field identity ends there; the original call graph is untouched, and the
// replacement is counted on the function (`lineageView.nonContentCuts`).
const NON_CONTENT = /^(?:(?:Prelude|Data\.List|Data\.Foldable|Data\.Text|Data\.Text\.Lazy|Data\.ByteString|Data\.ByteString\.Char8|Data\.ByteString\.Lazy|Data\.ByteString\.Lazy\.Char8|Data\.Map|Data\.Set)\.)?(?:length|null)$|^(?:length|null)$/;
function cutNonContent(fn, stats) {
  const rewrite = (e, depth = 0) => {
    if (!e || typeof e !== 'object' || depth > 60) return e;
    if (Array.isArray(e)) return e.map((x) => rewrite(x, depth + 1));
    if (e.kind === 'call' && typeof e.callee === 'string' && NON_CONTENT.test(e.callee)) {
      stats.nonContentCuts = (stats.nonContentCuts || 0) + 1;
      return { kind: 'literal', value: '<size>', hs: { derived: 'non-content', callee: e.callee } };
    }
    const out = { ...e };
    for (const k of ['object', 'callee', 'left', 'right', 'value', 'source']) if (e[k] && typeof e[k] === 'object') out[k] = rewrite(e[k], depth + 1);
    for (const k of ['args', 'elements', 'parts', 'options', 'branches']) if (Array.isArray(e[k])) out[k] = e[k].map((x) => rewrite(x, depth + 1));
    if (Array.isArray(e.props)) out.props = e.props.map((p) => (p && p.value ? { ...p, value: rewrite(p.value, depth + 1) } : p));
    if (e.hs && Array.isArray(e.hs.branchConds)) out.hs = { ...e.hs, branchConds: e.hs.branchConds.map((b) => (b && b.cond ? { ...b, cond: rewrite(b.cond, depth + 1) } : b)) };
    return out;
  };
  for (const n of Object.values(fn.cfg.nodes)) {
    if (n.source) n.source = rewrite(n.source);
    if (n.value) n.value = rewrite(n.value);
    if (n.cond) n.cond = rewrite(n.cond);
    if (Array.isArray(n.args)) n.args = rewrite(n.args);
  }
}

// ── callee inlining ──────────────────────────────────────────────────────────
// The field-identity engine analyses one function at a time and does not carry a caller's parameter identities
// into a callee's sink sites. For Haskell, whose handlers delegate to other modules, that would drop every
// cross-module flow, so each statement-level call to a project function is replaced by a renamed COPY of the
// callee's CFG (bounded depth and size; recursion is not inlined). Parameters become assignments from the call's
// arguments, locals are prefixed so two inlined copies never collide, and a `return` becomes an assignment to the
// call's result variable. Branch structure is preserved: nothing is flattened.
const INLINE_MAX_DEPTH = 3;
const INLINE_MAX_NODES = 600;

const paramName = (p) => (typeof p === 'string' ? p : p && p.name);

function renameExpr(e, map) {
  if (!e || typeof e !== 'object') return e;
  if (Array.isArray(e)) return e.map((x) => renameExpr(x, map));
  const out = { ...e };
  if (e.kind === 'ident' && typeof e.name === 'string' && map.has(e.name)) out.name = map.get(e.name);
  for (const k of ['object', 'callee', 'left', 'right', 'value', 'source']) if (e[k] && typeof e[k] === 'object') out[k] = renameExpr(e[k], map);
  for (const k of ['args', 'elements', 'parts', 'options']) if (Array.isArray(e[k])) out[k] = e[k].map((x) => renameExpr(x, map));
  if (Array.isArray(e.props)) out.props = e.props.map((p) => (p && p.value ? { ...p, value: renameExpr(p.value, map) } : p));
  return out;
}
const renameTarget = (t, map) => { if (typeof t !== 'string') return t; const head = t.split('.')[0]; return map.has(head) ? map.get(head) + t.slice(head.length) : t; };

let inlineSeq = 0;
function inlineCalls(fn, ctx, stack = []) {
  if (fn.hs && fn.hs.lineageInlined) return;
  fn.hs = { ...(fn.hs || {}), lineageInlined: true };
  let total = Object.keys(fn.cfg.nodes).length;
  const skipped = [];
  for (const [id, n] of Object.entries({ ...fn.cfg.nodes })) {
    const isCall = n.kind === 'call' && typeof n.callee === 'string';
    const isAssignCall = n.kind === 'assign' && n.source && n.source.kind === 'call' && typeof n.source.callee === 'string';
    if (!isCall && !isAssignCall) continue;
    const call = isCall ? n : n.source;
    const target = (call.hs && call.hs.target) || (ctx.resolve ? ctx.resolve(call.callee, fn.file) : null);
    if (!target) continue;
    const callee = ctx.clones.get(target);
    if (!callee) continue;
    if (stack.includes(target) || stack.length >= INLINE_MAX_DEPTH) { skipped.push({ callee: call.callee, reason: stack.includes(target) ? 'recursion' : 'depth' }); continue; }
    inlineCalls(callee, ctx, [...stack, fn.qid]);
    const body = Object.entries(callee.cfg.nodes).filter(([, c]) => c.kind !== 'entry' && c.kind !== 'exit');
    if (!body.length || total + body.length > INLINE_MAX_NODES) { if (body.length) skipped.push({ callee: call.callee, reason: 'size' }); continue; }
    const tag = `__i${++inlineSeq}_`;
    const params = (callee.params || []).map(paramName).filter(Boolean);
    const map = new Map();
    for (const p of params) map.set(p, `${tag}${p}`);
    for (const [, c] of body) if (c.kind === 'assign' && typeof c.target === 'string') { const head = c.target.split('.')[0]; if (!map.has(head)) map.set(head, `${tag}${head}`); }
    const idMap = new Map(body.map(([cid]) => [cid, `${id}~${tag}${cid}`]));
    const newNodes = new Map();
    // parameter binding nodes
    const binds = params.map((p, i) => ({ id: `${id}~${tag}bind${i}`, node: { kind: 'assign', line: n.line, target: map.get(p), source: (call.args || [])[i] || { kind: 'literal', value: null } } }));
    for (const [cid, c] of body) {
      const nn = { ...c, succ: (c.succ || []).map((x) => idMap.get(x) || null).filter(Boolean), pred: (c.pred || []).map((x) => idMap.get(x) || null).filter(Boolean) };
      if (nn.kind === 'assign') { nn.target = renameTarget(nn.target, map); nn.source = renameExpr(nn.source, map); }
      else if (nn.kind === 'call') { nn.args = renameExpr(nn.args, map); if (nn.callee && typeof nn.callee === 'object') nn.callee = renameExpr(nn.callee, map); }
      else if (nn.kind === 'return') {
        const value = renameExpr(nn.value, map);
        if (isAssignCall && value) { nn.kind = 'assign'; nn.target = n.target; nn.source = value; delete nn.value; } else if (value && value.kind === 'call') { nn.kind = 'call'; nn.callee = value.callee; nn.args = value.args; nn.hs = value.hs || nn.hs; delete nn.value; } else { nn.kind = 'noop'; delete nn.value; }
      } else if (nn.kind === 'if' || nn.kind === 'branch') { if (nn.cond) nn.cond = renameExpr(nn.cond, map); if (nn.thenEntry) nn.thenEntry = idMap.get(nn.thenEntry) || nn.thenEntry; if (nn.elseEntry) nn.elseEntry = idMap.get(nn.elseEntry) || nn.elseEntry; }
      newNodes.set(idMap.get(cid), nn);
    }
    // wire: pred(X) -> binds -> callee entry successors ; callee returns/exit predecessors -> succ(X)
    const entry = Object.entries(callee.cfg.nodes).find(([, c]) => c.kind === 'entry');
    const exit = Object.entries(callee.cfg.nodes).find(([, c]) => c.kind === 'exit');
    const entryNext = ((entry && entry[1].succ) || []).map((x) => idMap.get(x)).filter(Boolean);
    const exitPreds = ((exit && exit[1].pred) || []).map((x) => idMap.get(x)).filter(Boolean);
    const chain = binds.map((b) => b.id);
    const first = chain.length ? chain[0] : null;
    for (let i = 0; i < binds.length; i++) newNodes.set(binds[i].id, { ...binds[i].node, succ: i + 1 < binds.length ? [binds[i + 1].id] : entryNext, pred: i === 0 ? [...(n.pred || [])] : [binds[i - 1].id] });
    const startIds = first ? [first] : entryNext;
    for (const nid of entryNext) { const nn = newNodes.get(nid); if (nn) nn.pred = binds.length ? [binds[binds.length - 1].id] : [...(n.pred || [])]; }
    for (const xid of exitPreds) { const nn = newNodes.get(xid); if (nn) nn.succ = [...(n.succ || [])]; }
    for (const pid of n.pred || []) { const pn = fn.cfg.nodes[pid]; if (pn) pn.succ = [...new Set([...(pn.succ || []).filter((x) => x !== id), ...startIds])]; if (pn && pn.thenEntry === id) pn.thenEntry = startIds[0]; if (pn && pn.elseEntry === id) pn.elseEntry = startIds[0]; }
    for (const sid of n.succ || []) { const sn = fn.cfg.nodes[sid]; if (sn) sn.pred = [...new Set([...(sn.pred || []).filter((x) => x !== id), ...exitPreds])]; }
    delete fn.cfg.nodes[id];
    for (const [nid, nn] of newNodes) fn.cfg.nodes[nid] = nn;
    total += newNodes.size;
    fn.hs.lineageInlinedCalls = (fn.hs.lineageInlinedCalls || 0) + 1;
  }
  if (skipped.length) fn.hs.lineageNotInlined = skipped;
}

/**
 * @param {object} callGraph the shared call graph (never mutated)
 * @returns {object} a call graph whose Haskell functions are lineage-view clones; the input itself when there is no Haskell
 */
export function adaptCallGraphForLineage(callGraph) {
  if (!callGraph || !callGraph.haskell || typeof callGraph.functions?.values !== 'function') return callGraph;
  const hsOriginals = [...callGraph.functions.values()].filter((f) => isHsFile(f.file));
  if (!hsOriginals.length) return callGraph;
  const originalsByQid = new Map(hsOriginals.map((f) => [f.qid, f]));
  const clones = new Map();
  for (const f of hsOriginals) clones.set(f.qid, clone(f));
  for (const c of clones.values()) transformFunction(c, originalsByQid);
  const ctx = { clones, resolve: callGraph.resolveKnownCallee ? (name, file) => { const r = callGraph.resolveKnownCallee(name, file); return typeof r === 'string' ? r : (r && r.qid) || null; } : null };
  for (const c of clones.values()) inlineCalls(c, ctx);
  const functions = new Map();
  for (const [k, f] of callGraph.functions) functions.set(k, isHsFile(f.file) && clones.has(f.qid) ? clones.get(f.qid) : f);
  const swap = (f) => (f && isHsFile(f.file) && clones.has(f.qid) ? clones.get(f.qid) : f);
  const resolve = callGraph.resolve ? (...a) => swap(callGraph.resolve(...a)) : undefined;
  const resolveKnownCallee = callGraph.resolveKnownCallee ? (...a) => swap(callGraph.resolveKnownCallee(...a)) : undefined;
  return { ...callGraph, functions, ...(resolve ? { resolve } : {}), ...(resolveKnownCallee ? { resolveKnownCallee } : {}), lineageView: { haskell: true, functions: clones.size } };
}
