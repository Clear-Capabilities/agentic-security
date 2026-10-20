//
// Deterministic, bounded reachability from an entry point's handler.
//
// Breadth-first, with a stable tie-break (call line, then callee name, then target id), so the same graph always
// yields the same visit order and therefore the same bundle bytes. Three things this module refuses to do:
//
//   * claim exhaustiveness. A call that could not be resolved to a declaration is recorded as an explicit unknown.
//     Only the ones that COULD hide first-party code (the callee's name matches a first-party declaration, or the
//     callee is dynamic) are `material`; a call into a library or a response helper is a boundary, listed but not
//     blocking, because nothing first-party can be hiding behind it.
//   * hide a limit. Hitting the symbol or depth cap marks the walk `capped` and lists what was left unvisited.
//   * lose a control. Middleware and every callee are walked, and each visited symbol's controls are collected by the
//     same classifier the packer uses to refuse pruning.
import { analyzeSymbolText, blankComments } from './controls.js';
import { cmpCodeUnit } from './canonical.js';
import { MATERIAL_REASONS } from './graph-schema.js';

export const DEFAULT_LIMITS = Object.freeze({ maxSymbols: 60, maxDepth: 12 });

function indexGraph(graph) {
  const byId = new Map();
  const edgesFrom = new Map();
  for (const s of graph.symbols) byId.set(s.id, s);
  for (const e of graph.edges) {
    if (!edgesFrom.has(e.from)) edgesFrom.set(e.from, []);
    edgesFrom.get(e.from).push(e);
  }
  return { byId, edgesFrom };
}

/**
 * Walk the graph from an entry point.
 * Returns { root, visited, facts, unknowns, boundaries, capped, unvisited, cycles, limits }.
 */
export function reachFrom({ graph, fileContents, entrypoint, limits = {} }) {
  const lim = { ...DEFAULT_LIMITS, ...limits };
  const { byId, edgesFrom } = indexGraph(graph);
  const linesCache = new Map();
  const linesOf = (f) => { if (!linesCache.has(f)) linesCache.set(f, blankComments(fileContents[f] || '', f).split('\n')); return linesCache.get(f); };

  const visited = [];
  const seen = new Set();
  const unknowns = [];
  const boundaryMap = new Map();
  let cycles = 0;
  let capped = false;
  const queue = [];

  const inlineRoot = entrypoint.handlerKind === 'inline' && entrypoint.rootSpan && entrypoint.language === 'haskell';
  const rootSymbol = entrypoint.handlerSymbol ? byId.get(entrypoint.handlerSymbol) : null;

  // the "root view": either the handler declaration or, for an inline handler inside a larger declaration, only the
  // registration block's lines
  let root = null;
  if (inlineRoot && rootSymbol) {
    root = { kind: 'inline-block', symbolId: rootSymbol.id, file: entrypoint.rootSpan.file, startLine: entrypoint.rootSpan.startLine, endLine: entrypoint.rootSpan.endLine, declLine: entrypoint.rootSpan.startLine, spanPrecision: entrypoint.rootSpan.precision };
  } else if (rootSymbol) {
    root = { kind: 'declaration', symbolId: rootSymbol.id, file: rootSymbol.file, startLine: rootSymbol.startLine, endLine: rootSymbol.endLine, declLine: rootSymbol.declLine, spanPrecision: rootSymbol.spanPrecision };
  } else if (entrypoint.rootSpan) {
    root = { kind: 'registration-only', symbolId: null, file: entrypoint.rootSpan.file, startLine: entrypoint.rootSpan.startLine, endLine: entrypoint.rootSpan.endLine, declLine: entrypoint.rootSpan.startLine, spanPrecision: entrypoint.rootSpan.precision };
  }

  const enqueue = (symbolId, depth, reason, viaLine, path, confidence) => {
    if (seen.has(symbolId)) { cycles++; return; }
    seen.add(symbolId);
    queue.push({ symbolId, depth, reason, viaLine, path, confidence });
  };

  if (!root) {
    return { root: null, visited: [], facts: [], unknowns: [{ type: 'no-handler', site: `${entrypoint.registrationSite.file}:${entrypoint.registrationSite.line}`, reason: 'entry point has no resolvable handler or registration block', material: true }], boundaries: [], capped: false, unvisited: [], cycles: 0, limits: lim };
  }

  // middleware runs before the handler: it is enqueued first and ordered at line -1
  for (const mw of [...entrypoint.middleware].sort((a, b) => (a.line - b.line) || cmpCodeUnit(a.name, b.name))) {
    if (mw.symbolId && byId.has(mw.symbolId)) enqueue(mw.symbolId, 0, mw.inherited ? 'inherited-middleware' : 'middleware', -1, [mw.symbolId], mw.resolution === 'resolved' ? 'exact' : 'name-match');
  }
  if (root.symbolId) {
    if (!seen.has(root.symbolId)) { seen.add(root.symbolId); }
    queue.unshift({ symbolId: root.symbolId, depth: 0, reason: 'handler', viaLine: null, path: [root.symbolId], confidence: entrypoint.handlerConfidence, isRoot: true });
  }

  const emitted = [];
  while (queue.length) {
    const cur = queue.shift();
    const sym = byId.get(cur.symbolId);
    if (!sym) continue;
    if (emitted.length >= lim.maxSymbols) { capped = true; queue.unshift(cur); break; }
    emitted.push(cur);
    visited.push({ symbolId: cur.symbolId, depth: cur.depth, reason: cur.reason, viaLine: cur.viaLine, path: cur.path, confidence: cur.confidence });

    const restrictTo = cur.isRoot && root.kind === 'inline-block' ? [root.startLine, root.endLine] : null;
    const out = (edgesFrom.get(cur.symbolId) || [])
      .filter(e => !e.superseded)
      .filter(e => !restrictTo || (e.line >= restrictTo[0] && e.line <= restrictTo[1]))
      .sort((a, b) => (a.line - b.line) || (a.calleeName < b.calleeName ? -1 : a.calleeName > b.calleeName ? 1 : 0) || ((a.to || '') < (b.to || '') ? -1 : 1));
    for (const e of out) {
      // The root-level line a chain started on: callees of the handler are ordered by the line of the call that led to them.
      const via = cur.isRoot ? e.line : cur.viaLine;
      if (e.conflict) {
        // the compiler and the static pass disagree about this call: follow both, and say the bundle is not settled
        unknowns.push({ type: 'compiler-static-conflict', site: `${sym.file}:${e.line}`, from: cur.symbolId, calleeName: e.calleeName, reason: 'compiler-and-static-analysis-disagree', material: true, candidates: [] });
      }
      if (e.to) {
        if (cur.depth + 1 > lim.maxDepth) { capped = true; continue; }
        enqueue(e.to, cur.depth + 1, 'callee', via, [...cur.path, e.to], 'exact');
      } else if (MATERIAL_REASONS.has(e.unresolvedReason)) {
        unknowns.push({ type: e.kind, site: `${sym.file}:${e.line}`, from: cur.symbolId, calleeName: e.calleeName, reason: e.unresolvedReason, material: true, candidates: e.candidates });
        // Candidates are shown to the model as CANDIDATES (low confidence); the unknown stays material regardless.
        if (e.candidates.length && e.candidates.length <= 3 && cur.depth + 1 <= lim.maxDepth) {
          for (const c of e.candidates) enqueue(c, cur.depth + 1, 'name-match-candidate', via, [...cur.path, c], 'name-match');
        }
      } else {
        const key = `${e.calleeName}|${e.unresolvedReason}`;
        const b = boundaryMap.get(key) || { calleeName: e.calleeName, reason: e.unresolvedReason, count: 0, firstSite: `${sym.file}:${e.line}` };
        b.count++;
        boundaryMap.set(key, b);
      }
    }
  }
  const unvisited = queue.map(q => q.symbolId).sort();

  // facts: classified once per visited symbol, with the effective ordering line attached
  const facts = [];
  for (const v of visited) {
    const sym = byId.get(v.symbolId);
    const isInlineRoot = v.reason === 'handler' && root.kind === 'inline-block';
    const view = isInlineRoot ? { ...sym, startLine: root.startLine, endLine: root.endLine, declLine: root.startLine } : sym;
    const hs = /\.l?hs$/i.test(sym.file);
    for (const f of analyzeSymbolText(view, linesOf(sym.file), { haskell: hs })) {
      let effLine;
      if (v.reason === 'handler') effLine = f.line;
      else if (v.reason === 'middleware' || v.reason === 'inherited-middleware') effLine = -1;
      else effLine = v.viaLine === null || v.viaLine === undefined ? f.line : v.viaLine;
      facts.push({ ...f, file: sym.file, effLine, via: v.reason });
    }
  }
  // registration-only roots have no symbol: still classify the registration block itself
  if (!root.symbolId) {
    const view = { id: `${root.file}::<registration>@${root.startLine}`, file: root.file, startLine: root.startLine, endLine: root.endLine, declLine: root.startLine };
    for (const f of analyzeSymbolText(view, linesOf(root.file), { haskell: /\.l?hs$/i.test(root.file) })) facts.push({ ...f, file: root.file, effLine: f.line, via: 'handler' });
  }

  unknowns.sort((a, b) => (a.site < b.site ? -1 : a.site > b.site ? 1 : 0) || (a.calleeName < b.calleeName ? -1 : 1));
  const boundaries = [...boundaryMap.values()].sort((a, b) => (a.calleeName < b.calleeName ? -1 : a.calleeName > b.calleeName ? 1 : 0));
  return { root, visited, facts, unknowns, boundaries, capped, unvisited, cycles, limits: lim };
}

/**
 * Protection state per dimension. The five non-present states are deliberately distinct, because collapsing them is
 * how "I did not see a check" turns into "there is no check":
 *   present                     an observed or named control precedes the first sensitive operation
 *   evaluated_and_ineffective   a control exists but runs AFTER the first sensitive operation (a late guard)
 *   not_present                 the context is complete and no control of this kind is in it
 *   not_resolved                a material unknown edge could hide one
 *   omitted_due_to_budget       a symbol that holds a control was left out for size
 *   not_seen                    no sensitive operation was seen, so there was nothing for a control to protect
 */
export const PROTECTION_DIMENSIONS = Object.freeze(['authentication', 'authorization-role', 'ownership']);

export function evaluateProtection({ facts, unknowns, omittedWithControls = false, capped = false }) {
  const sens = facts.filter(f => f.category === 'sensitive');
  const firstSens = sens.length ? Math.min(...sens.map(f => f.effLine)) : null;
  const dims = {};
  for (const dim of PROTECTION_DIMENSIONS) {
    const kinds = dim === 'ownership' ? ['ownership', 'tenant-scope'] : [dim];
    const ctl = facts.filter(f => f.category === 'control' && kinds.includes(f.kind));
    // A control whose answer is visibly thrown away (a predicate called as a bare statement) guards nothing.
    const effective = (f) => f.rejectionSeen !== false;
    // Ownership is the one dimension where reading before checking is the ordinary safe shape: load the record by id, refuse unless the
    // principal owns it, and only then act on it. What an unchecked read can do is bounded by the check that follows before anything is
    // written, so for ownership and tenant scope the line that must be preceded is the first WRITE. With no write in view the first
    // sensitive operation of any kind still applies, so a read returned without a check is not excused.
    const writes = sens.filter(f => f.subkind === 'write' || f.kind === 'filesystem' || f.kind === 'process');
    const gate = dim === 'ownership' && writes.length ? Math.min(...writes.map(f => f.effLine)) : firstSens;
    const before = ctl.filter(f => effective(f) && (gate === null || f.effLine < gate || (f.basis === 'query-filter' && f.effLine <= gate)));
    const after = ctl.filter(f => gate !== null && f.effLine > gate);
    let state; let why;
    if (before.length) { state = 'present'; why = 'a control precedes the first sensitive operation'; }
    else if (after.length) { state = 'evaluated_and_ineffective'; why = 'every control of this kind runs after the first sensitive operation'; }
    else if (ctl.length && ctl.every(f => !effective(f))) { state = 'evaluated_and_ineffective'; why = 'a check is called but nothing in view acts on its answer'; }
    else if (ctl.length) { state = 'evaluated_and_ineffective'; why = 'a control is present but is not ordered before the sensitive operation'; }
    else if (omittedWithControls) { state = 'omitted_due_to_budget'; why = 'a symbol holding a control was left out for size'; }
    else if (unknowns.some(u => u.material) || capped) { state = 'not_resolved'; why = 'an unresolved call or a traversal limit could hide a control'; }
    else if (firstSens === null) { state = 'not_seen'; why = 'no sensitive operation was seen in the resolved context'; }
    else { state = 'not_present'; why = 'the resolved context is complete and contains no control of this kind'; }
    dims[dim] = {
      state, why, firstSensitiveLine: firstSens,
      // How the control was established: 'observed' = the text shows it, 'inferred' = only a name suggests it. Only meaningful for `present`.
      strength: state === 'present' ? (before.some(f => f.evidence === 'observed') ? 'observed' : 'inferred') : null,
      evidence: ctl.slice(0, 6).map(f => ({ file: f.file, line: f.line, kind: f.kind, evidence: f.evidence, basis: f.basis, order: firstSens === null ? 'no-sensitive-op' : f.effLine < firstSens ? 'before-sensitive' : f.effLine > firstSens ? 'after-sensitive' : 'same-step', rejectionSeen: f.rejectionSeen })),
    };
  }
  return dims;
}
