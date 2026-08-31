//
// handling-analyzer.js — Milestone 2, Sub-project D ("handling analyzer +
// FR-307 control-credit"), increment 1.
//
// FR-403's single-path handling TAXONOMY classifier — see
// DESIGN_HANDLING_ANALYZER.md for the full design record: the exact
// `transform-catalog.js` `kind` -> `schema.js` `HANDLING_VALUES` mapping
// table, the load-bearing naming note distinguishing `flow.handling` (this
// module's output) from `protection.js`'s own `PROTECTION_DIMENSIONS`
// `handling` dimension (a different field, a different vocabulary, a
// different question), and everything explicitly deferred (FR-307's
// multi-path control-credit rule, `aggregate`'s own `'aggregated'` verdict,
// any UI/display concern).
//
// Reuse boundary: imports ONLY `recognizeTransformation` from
// `./transform-catalog.js` and `exprRoots`/`walkExpr` from
// `./source-seeding.js` — both already-shipped, read-only consumers, per
// this package's established isolation convention. Never
// `dataflow/engine.js`, never `dataflow/summaries.js`, never
// `dataflow/catalog.js`/`dataflow/privacy-catalog.js` directly.
//
// A pure, one-path-at-a-time classifier. `classifyHandling(path, callGraph)`
// takes ONE `path-query.js#reconstructPaths` result path — the caller picks
// which; this module never iterates multiple paths to one sink, that is
// FR-307's job, explicitly deferred to D2 — and never throws on malformed
// input.

import { recognizeTransformation } from './transform-catalog.js';
import { exprRoots, walkExpr } from './source-seeding.js';

/**
 * The `transform-catalog.js` `kind` -> FR-403 `HANDLING_VALUES` mapping
 * (DESIGN_HANDLING_ANALYZER.md §2). Five kinds map to their own protective
 * handling state (`mask`/`redact`/`hash`/`tokenize`/`encrypt`); five more
 * (`decrypt`/`encode`/`decode`/`truncate`/`normalize`) map to `'unknown'`
 * because none of them is itself a PROTECTIVE handling state for FR-403's
 * purposes — decoding/truncating/normalizing doesn't protect a field, and
 * a `decrypt` immediately before a sink is actively the OPPOSITE of
 * protection. `aggregate` ALSO maps to `'unknown'` here, for a different,
 * disclosed reason: `HANDLING_VALUES` carries its own `'aggregated'`
 * value, but awarding it needs shape-level reasoning about a WHOLE
 * collection that a single-hop, single-path classifier cannot do soundly —
 * deferred to D2/later, never faked from a hop-level recognition alone.
 * `custom`/`unknown` never appear as keys here because
 * `recognizeTransformation` never emits them as a `kind`
 * (`transform-catalog.js`'s own documented, load-time-enforced contract).
 */
const KIND_TO_HANDLING = Object.freeze({
  mask: 'masked',
  redact: 'redacted',
  hash: 'hashed',
  tokenize: 'tokenized',
  encrypt: 'encrypted',
  decrypt: 'unknown',
  encode: 'unknown',
  decode: 'unknown',
  truncate: 'unknown',
  normalize: 'unknown',
  aggregate: 'unknown',
});

/** The honest empty answer: no hop on this path yielded a recognized
 * transform. Frozen and shared — this module never mutates its own
 * return values. */
const RAW_RESULT = Object.freeze({ handling: 'raw', recognizedTransform: null, hopIndex: null });

/**
 * Mirrors `graph-builder.js`'s own private (unexported) `calleeDescriptor`
 * helper. Deliberately NOT imported from there — see
 * DESIGN_HANDLING_ANALYZER.md §3 for why a third copy of this ~10-line
 * shape was chosen over introducing a `graph-builder.js` <->
 * `handling-analyzer.js` module cycle (this module is wired INTO
 * `graph-builder.js`, the reverse direction). Never throws; returns `null`
 * for anything that cannot become a `transform-catalog.js` descriptor.
 */
function calleeDescriptorOf(calleeExpr) {
  if (typeof calleeExpr === 'string') return { type: 'call', callee: calleeExpr };
  if (!calleeExpr || typeof calleeExpr !== 'object') return null;
  if (calleeExpr.kind === 'ident' && typeof calleeExpr.name === 'string') return { type: 'call', callee: calleeExpr.name };
  if (calleeExpr.kind === 'member' && typeof calleeExpr.prop === 'string') {
    const obj = calleeExpr.object && calleeExpr.object.kind === 'ident' ? calleeExpr.object.name : null;
    return obj ? { type: 'member-call', object: obj, method: calleeExpr.prop } : { type: 'call', callee: calleeExpr.prop };
  }
  return null;
}

/**
 * Every `{kind: 'call', ...}` expression reachable from one CFG node, in
 * expression-tree order — mirrors `graph-builder.js`'s own per-hop
 * transformation-extraction loop exactly (`exprRoots`/`walkExpr` over the
 * node, plus the node's OWN call when the node itself is `kind: 'call'` —
 * `exprRoots` only ever yields a call NODE's `callee`/`args`, never a
 * `{kind:'call'}` shape for the node itself, so that case needs the same
 * explicit unshift `graph-builder.js` already uses). This is what makes an
 * `assign`-kind CFG node whose `.source` IS a call (`const maskedPan =
 * maskCard(cardNumber);`) resolvable too, not just a bare call statement —
 * see DESIGN_HANDLING_ANALYZER.md §3 item 2 for why that distinction is
 * load-bearing for this increment's own required AC-02 fixture. Defensive:
 * a malformed `node` yields `[]`, never throws.
 */
function callsAt(node) {
  if (!node || typeof node !== 'object') return [];
  const calls = [];
  for (const root of exprRoots(node)) walkExpr(root, (e) => { if (e && typeof e === 'object' && e.kind === 'call') calls.push(e); });
  if (node.kind === 'call' && node.callee) calls.unshift({ kind: 'call', callee: node.callee, args: node.args ?? [] });
  return calls;
}

/**
 * FR-403's single-path handling classifier. `path` is one
 * `path-query.js#reconstructPaths` result path (the caller picks which —
 * this module never iterates multiple paths to one sink, per FR-307's own
 * deferred multi-path control-credit rule). `callGraph` is the same
 * `scanner/src/ir/callgraph.js#buildCallGraph`-shaped object (a real
 * `Map` at `.functions`) `graph-builder.js` already consumes, or an
 * equivalent hand-built fixture exposing the same shape.
 *
 * Walks `path.hops` in the SOURCE-TO-SINK order `path-query.js` already
 * materializes paths in. For each hop, resolves
 * `callGraph.functions.get(hop.scope)?.cfg?.nodes?.[hop.siteNodeId]`
 * defensively — never throws on a missing/malformed lookup, mirroring
 * every other lineage module's defensiveness — and, when that CFG node
 * yields one or more call expressions (via `callsAt`, above), tries
 * `recognizeTransformation` on each in expression order. Returns the FIRST
 * recognized transform found walking from source to sink.
 *
 * @param {object} path a `reconstructPaths` result path
 * @param {object} callGraph `{functions: Map<qid, {cfg: {nodes}}>, ...}`
 * @returns {{handling: string, recognizedTransform: object|null, hopIndex: number|null}}
 *   `handling` is always a `schema.js` `HANDLING_VALUES` member.
 *   `recognizedTransform` is `recognizeTransformation`'s own decision
 *   object (kind/reversibility/algorithm/confidence/evidence), unmodified,
 *   when one was found — else `null`. `hopIndex` is the index into
 *   `path.hops` the transform was found at, else `null`. When no hop
 *   yields a recognized transform, returns
 *   `{handling: 'raw', recognizedTransform: null, hopIndex: null}` —
 *   never a guess.
 */
export function classifyHandling(path, callGraph) {
  const hops = Array.isArray(path?.hops) ? path.hops : [];
  const fns = callGraph && callGraph.functions && typeof callGraph.functions.get === 'function' ? callGraph.functions : null;
  if (!fns) return RAW_RESULT;

  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i];
    if (!hop || typeof hop !== 'object') continue;
    const fn = fns.get(hop.scope);
    const node = fn?.cfg?.nodes?.[hop.siteNodeId];
    if (!node) continue;
    for (const call of callsAt(node)) {
      const descriptor = calleeDescriptorOf(call.callee);
      if (!descriptor) continue;
      const rec = recognizeTransformation(descriptor);
      if (!rec) continue;
      // Defensive fallback only — every non-fallback `TRANSFORM_KINDS`
      // value `recognizeTransformation` can actually emit is a key in
      // `KIND_TO_HANDLING` above (11 kinds, both tables measured against
      // the same live `transform-catalog.js`), so `?? 'unknown'` is never
      // exercised by real catalog output today. Kept rather than omitted
      // so a future catalog kind this table hasn't been updated for fails
      // safe (an honest `'unknown'`) instead of writing `undefined` onto
      // `flow.handling`.
      const handling = KIND_TO_HANDLING[rec.kind] ?? 'unknown';
      return { handling, recognizedTransform: rec, hopIndex: i };
    }
  }
  return RAW_RESULT;
}
