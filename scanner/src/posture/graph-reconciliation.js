// Static / runtime graph reconciliation (E5-04).
//
// The static graph says which calls, routes and service edges the CODE contains. A runtime trace says which ones a RUNNING BUILD exercised. This
// module lines the two up edge by edge and states, for each edge, what is actually known:
//
//   statically_inferred  the static graph has the edge; no usable runtime evidence about it
//   runtime_observed     a runtime record shows the edge; the static graph does not contain it (a gap in the static graph, or dynamic dispatch)
//   both                 the static graph has it AND a record from a build matched to this snapshot shows it
//   conflicted           the two disagree: the same route reached a different handler, or the same call site's caller reached a callee the static
//                        graph never resolved it to while a matched build was running
//   unknown              evidence exists but cannot be tied to this snapshot (runtime records with no comparable build identity), so the edge is
//                        neither confirmed nor refuted
//
// `both` REQUIRES a matched build (deployment-identity.js). A record from a different build never confirms an edge: it is counted against the edge
// as `mismatchedRecords` and decays its confidence. Records with no build identity make the edge `unknown`, not `both`.
//
// CONFIDENCE is a number in [0,1] with the factors listed in `factors`, so a reader can see why it is what it is:
//   base           static edge 0.6; resolved call 0.7; runtime-only 0.5; both 0.95; conflicted 0.3; unknown 0.4
//   x0.5           for each edge that also has records from a mismatched build (the evidence is about different code), once
//   x0.85          when the trace's coverage is partial: sampled below 1 or sampling undeclared
// Matching is by NORMALIZED KEY: symbols lose a trailing @line and, per `opts.normalize`, a configured prefix and case; routes become their path
// with every `:param` and id-like segment collapsed to `:id`.
//
// NOT USED: spans. Static symbols carry a start line and no end line, so line-range matching is not attempted; matching is by qualified symbol.
import * as fs from 'node:fs';
import * as readline from 'node:readline';
import { linkObservationToSnapshot, normalizeIdentity } from '../lineage/deployment-identity.js';
import { normalizeRoute } from './runtime-trace-ingest.js';

export const EDGE_STATES = Object.freeze(['statically_inferred', 'runtime_observed', 'both', 'conflicted', 'unknown']);
const BASE = Object.freeze({ statically_inferred: 0.6, runtime_observed: 0.5, both: 0.95, conflicted: 0.3, unknown: 0.4 });

/** Normalise a symbol per the configurable rules. */
export function normalizeSymbol(q, norm = {}) {
  if (typeof q !== 'string') return null;
  let s = q.replace(/@\d+$/, '').replace(/\(\)$/, '');
  // `rewrite` is [[pattern, replacement], ...]: how this project's collector spells a symbol versus how the IR does (the IR writes `app.js::<module>::run`)
  for (const [pat, rep] of norm.rewrite || []) s = s.replace(new RegExp(pat), rep);
  for (const pre of norm.stripPrefixes || []) if (s.startsWith(pre)) { s = s.slice(pre.length); break; }
  if (norm.caseInsensitive) s = s.toLowerCase();
  return s || null;
}
/** Normalise a route path: query dropped, ids and `:param` collapsed to `:id`. */
export function normalizeRouteKey(r) {
  const n = normalizeRoute(typeof r === 'string' ? r.replace(/\{[^}/]+\}/g, ':id') : r);
  return n ? n.split('/').map((seg) => (seg.startsWith(':') ? ':id' : seg)).join('/') : null;
}

const keyOf = (kind, a, b) => `${kind}|${a}|${b}`;

/**
 * Static edges from a SemanticGraph.
 * @param {object} graph a SemanticGraph v1
 * @param {{routes?:{path:string, handler:string}[]}} extra route -> handler pairs the caller knows (the IR has no route entity)
 */
export function staticEdgesFromGraph(graph, extra = {}, norm = {}) {
  const byId = new Map((graph.symbols || []).map((s) => [s.id, s]));
  const edges = new Map();
  const add = (kind, a, b, over = {}) => { if (a && b) edges.set(keyOf(kind, a, b), { kind, from: a, to: b, resolved: true, ...over }); };
  for (const c of graph.callSites || []) {
    if (c.resolution !== 'resolved') continue;
    add('call', normalizeSymbol(byId.get(c.caller)?.qid, norm), normalizeSymbol(byId.get(c.callee)?.qid, norm), { file: c.file ?? null, line: c.line ?? null });
  }
  for (const r of extra.routes || []) add('route', normalizeRouteKey(r.path), normalizeSymbol(r.handler, norm));
  for (const b of graph.serviceBoundaries || []) if (b.from && b.to && b.from.service && b.to.service) add('service', b.from.service, b.to.service);
  return edges;
}

/** Read the trace file and collect runtime edges with their build links. Never throws on a bad line. */
export async function readRuntimeEdges(tracePath, opts = {}) {
  const snap = opts.snapshotIdentity ? normalizeIdentity(opts.snapshotIdentity) : null;
  const norm = opts.normalize || {};
  const windowMs = (opts.windowDays || 30) * 86400_000; const now = opts.now ?? Date.now();
  const edges = new Map(); let records = 0;
  const touch = (key, kind, from, to, link) => {
    const e = edges.get(key) || { kind, from, to, matched: 0, unattested: 0, mismatched: 0 };
    e[link === 'matched' ? 'matched' : link === 'mismatched' ? 'mismatched' : 'unattested']++;
    edges.set(key, e);
  };
  const rl = readline.createInterface({ input: fs.createReadStream(tracePath, { encoding: 'utf8' }), crlfDelay: Infinity });
  for await (const line of rl) {
    let r; try { r = JSON.parse(line); } catch { continue; }
    if (!r || typeof r !== 'object') continue;
    const t = r.ts ? Date.parse(r.ts) : NaN;
    if (Number.isFinite(t) && now - t > windowMs) continue;
    records++;
    const link = snap ? linkObservationToSnapshot({ commit: r.commit, buildHash: r.buildHash, imageDigest: r.imageDigest, sbomRef: r.sbomRef, environment: r.environment }, snap).state : 'unknown';
    if (r.kind === 'function-call' && r.caller && r.qid) { const a = normalizeSymbol(r.caller, norm); const b = normalizeSymbol(r.qid, norm); if (a && b) touch(keyOf('call', a, b), 'call', a, b, link); }
    else if (r.kind === 'route-hit' && r.route && r.qid) { const a = normalizeRouteKey(r.route); const b = normalizeSymbol(r.qid, norm); if (a && b) touch(keyOf('route', a, b), 'route', a, b, link); }
    else if (r.kind === 'service-call' && r.service && r.peer) touch(keyOf('service', r.service, r.peer), 'service', r.service, r.peer, link);
  }
  return { edges, records };
}

/**
 * @param {Map} staticEdges  from staticEdgesFromGraph
 * @param {{edges:Map, records:number}} runtime from readRuntimeEdges
 * @param {{sampling?:{state:string}}} opts sampling from runtime-correlation.js samplingOf(trace)
 * @returns {{edges:object[], counts:Object<string,number>, limitations:string[]}}
 */
export function reconcileGraphs(staticEdges, runtime, opts = {}) {
  const partial = !opts.sampling || opts.sampling.state !== 'complete';
  const out = new Map();
  const finish = (key, state, base, extra) => {
    const factors = [{ name: 'base', value: BASE[state] ?? base }];
    let c = BASE[state] ?? base;
    if (base !== undefined && state === 'statically_inferred') { c = base; factors[0].value = base; }
    if (extra.mismatchedRecords > 0) { c *= 0.5; factors.push({ name: 'records-from-a-different-build', value: 0.5 }); }
    if (partial) { c *= 0.85; factors.push({ name: 'partial-or-undeclared-coverage', value: 0.85 }); }
    out.set(key, { key, state, confidence: Math.round(c * 1000) / 1000, factors, ...extra });
  };
  const rt = runtime ? runtime.edges : new Map();
  for (const [key, s] of staticEdges) {
    const r = rt.get(key);
    const base = s.kind === 'call' ? 0.7 : 0.6;
    const common = { kind: s.kind, from: s.from, to: s.to, mismatchedRecords: r ? r.mismatched : 0, matchedRecords: r ? r.matched : 0, unattestedRecords: r ? r.unattested : 0 };
    if (r && r.matched > 0) finish(key, 'both', base, common);
    else if (r && r.unattested > 0) finish(key, 'unknown', base, { ...common, reason: 'runtime records show this edge but carry no build identity comparable to the snapshot' });
    else finish(key, 'statically_inferred', base, { ...common, ...(r && r.mismatched ? { reason: 'only a different build was observed using this edge' } : {}) });
  }
  // runtime-only edges, and conflicts
  const staticByFrom = new Map();
  for (const s of staticEdges.values()) { const k = `${s.kind}|${s.from}`; (staticByFrom.get(k) || staticByFrom.set(k, []).get(k)).push(s); }
  for (const [key, r] of rt) {
    if (out.has(key)) continue;
    const common = { kind: r.kind, from: r.from, to: r.to, mismatchedRecords: r.mismatched, matchedRecords: r.matched, unattestedRecords: r.unattested };
    if (r.matched === 0 && r.unattested === 0) { finish(key, 'unknown', undefined, { ...common, reason: 'seen only in a different build: not evidence about this snapshot' }); continue; }
    const rivals = (r.kind === 'route' || r.kind === 'call') ? (staticByFrom.get(`${r.kind}|${r.from}`) || []) : [];
    const conflicting = r.matched > 0 && r.kind === 'route' && rivals.length > 0;
    if (conflicting) {
      finish(key, 'conflicted', undefined, { ...common, conflictsWith: rivals.map((x) => keyOf(x.kind, x.from, x.to)), reason: 'the same route reached a different handler than the static graph names' });
      for (const x of rivals) { const k = keyOf(x.kind, x.from, x.to); const cur = out.get(k); if (cur && cur.state !== 'both') finish(k, 'conflicted', undefined, { kind: cur.kind, from: cur.from, to: cur.to, mismatchedRecords: cur.mismatchedRecords, matchedRecords: cur.matchedRecords, unattestedRecords: cur.unattestedRecords, conflictsWith: [key], reason: 'a matched build routed this path to a different handler' }); }
    } else finish(key, 'runtime_observed', undefined, { ...common, ...(r.matched === 0 ? { reason: 'build identity not comparable: observed, not corroborating' } : {}) });
  }
  const edges = [...out.values()].sort((a, b) => (a.key < b.key ? -1 : 1));
  const counts = Object.fromEntries(EDGE_STATES.map((s) => [s, edges.filter((e) => e.state === s).length]));
  return { edges, counts, partialCoverage: partial, limitations: ['Spans are not used: static symbols carry no end line, so matching is by qualified symbol.', 'Route-to-handler static edges exist only when the caller supplies them; the IR has no route entity.', 'Conflicts are detected for routes only; a call edge to a callee the static graph did not resolve is runtime_observed.'] };
}

/**
 * Can an exploit path be called runtime-corroborated? Only when EVERY edge of it is `both`. A conflicted edge makes the path conflicted; an edge
 * the reconciliation has no entry for counts as uncorroborated.
 * @param {string[]} pathKeys edge keys along the path
 */
export function pathCorroboration(reconciled, pathKeys) {
  const byKey = new Map(reconciled.edges.map((e) => [e.key, e]));
  const states = pathKeys.map((k) => (byKey.get(k) || { state: 'statically_inferred' }).state);
  if (!states.length) return { state: 'uncorroborated', reason: 'the path has no edges' };
  if (states.includes('conflicted')) return { state: 'conflicted' };
  if (states.every((s) => s === 'both')) return { state: 'corroborated' };
  return { state: states.some((s) => s === 'both') ? 'partial' : 'uncorroborated', missing: pathKeys.filter((k, i) => states[i] !== 'both') };
}

export { keyOf as edgeKey };
