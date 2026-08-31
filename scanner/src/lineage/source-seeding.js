//
// source-seeding.js — Sub-project E, increment 2 (E2).
//
// Extracts the already-designed-and-proven source-seeding mechanism out of
// `DESIGN_GRAPH_BUILDER.md` §3 (binding ADR) and its throwaway
// proof-of-concept (`test/lineage/graph-builder-poc.test.js`'s
// `exprRoots`/`exprChildren`/`walkExpr`/`seedPathFor`/`planSeeds`/
// `seedEntryStateFactory`, `E1/1`-`E1/5`, `E1/14`) into a real, permanent,
// shipped module. This closes the measured "0 hops on real code" gap: the
// shipped `driver.js` (Sub-project E, increment 1) hardcodes `emptyState()`
// and produces exactly zero hops on real code with no seeding hook — see
// `DESIGN_GRAPH_BUILDER.md` §2.1. This module is that hook's first real
// consumer.
//
// This is mechanical porting of an already-reviewed design, not a redesign
// — see `DESIGN_GRAPH_BUILDER.md` §3 in full for the binding rules this
// file implements, and its own header for why the PoC (not this document)
// is authoritative if the two ever disagree.
//
// Reuse boundary (§12, confirmed against the source): imports ONLY
// `matchSource` from `../dataflow/catalog.js` and `accessPathOf` from
// `../dataflow/access-paths.js` — never `dataflow/engine.js`'s live taint
// state, never `dataflow/summaries.js`'s SummaryCache, never
// `dataflow/index.js`'s `runDeepAnalysis` (PRD §18.1). Everything else this
// module needs comes from already-shipped `src/lineage/` modules.

import { matchSource } from '../dataflow/catalog.js';
import { accessPathOf } from '../dataflow/access-paths.js';
import { emptyState, addIdentity } from './field-identity.js';
import { reclassifySource } from './source-registry.js';
import { classifyDataElementName } from './classification.js';
import { dataElementId } from './ids.js';

// ── §3.1: where the matched expressions come from ──────────────────────────
//
// Walk `fn.cfg.nodes` and, per node, the SAME expression roots `engine.js`'s
// own `step()` switch reads: `assign` → `source`, `call` → `callee` + `args`,
// `return` → `value`. Then recurse into every sub-expression. Deliberately
// NOT `fn.reads`/`fn.calls`: Sub-project D5 already measured that a call
// used as an assignment RHS never reaches `fn.calls[]` at all, so those
// side-channels are incomplete for this purpose. `fn.cfg.nodes` is a plain
// `Object` at runtime, not a `Map` (also D5's finding).

/**
 * The expression roots a single CFG node carries, mirroring `engine.js`'s
 * own `step()` switch exactly. Exported: this walking primitive is not
 * seeding-specific — E3's projection (sink enumeration, transformation
 * attribution) needs the identical CFG-node → expression-roots traversal,
 * and a second, independently-drifting copy is exactly the duplication
 * this package avoids everywhere else (see `DESIGN_REGISTRIES.md` §1).
 */
export function exprRoots(node) {
  const r = [];
  if (node.kind === 'assign' && node.source) r.push(node.source);
  if (node.kind === 'call') {
    if (node.callee) r.push(node.callee);
    for (const a of node.args ?? []) r.push(a);
  }
  if (node.kind === 'return' && node.value) r.push(node.value);
  return r;
}

/** The sub-expressions of `e`, for recursive descent during the walk. */
function exprChildren(e) {
  switch (e.kind) {
    case 'member': return [e.object];
    case 'call': return [e.callee, ...(e.args ?? [])];
    case 'tpl': return e.parts ?? [];
    case 'binary': case 'logical': return [e.left, e.right];
    case 'union': return e.options ?? [];
    case 'array': return e.elements ?? [];
    case 'object': return (e.props ?? []).map((p) => p.value);
    case 'assign-expr': return [e.source ?? e.value];
    default: return [];
  }
}

/**
 * Depth-first walk over an expression tree, visiting every node once.
 * Exported for the same reuse reason as `exprRoots` above.
 */
export function walkExpr(e, visit, parent = null) {
  if (!e || typeof e !== 'object') return;
  visit(e, parent);
  for (const c of exprChildren(e)) walkExpr(c, visit, e);
}

// ── §3.2: the seed-path rule — seed the FIELD, not the container ───────────
//
// `matchSource` matches the CONTAINER (`req.body`), but the thing that has
// a field identity is the FIELD (`req.body.card_number`). Extend the
// matched expression outward through every enclosing pure-member access,
// then take `accessPathOf` of the outermost node. Falls back to the matched
// expression's own path when it is not the object of a member access
// (`User.create(req.body)`) — that container-level seed is the honest
// answer for that shape. §3.2's own text: "Classification is impossible
// without this rule." This must be ported EXACTLY as the PoC implements it
// — the single most consequential rule in the whole design.

/**
 * Extend `expr` outward through every enclosing pure-member access (using
 * `parentOf`, a map from expression node to its immediate parent expression
 * within the same CFG-node walk), then return `accessPathOf` of the
 * outermost such node — the FIELD path, not the container path.
 */
function seedPathFor(expr, parentOf) {
  let cur = expr;
  for (;;) {
    const p = parentOf.get(cur);
    if (p && p.kind === 'member' && p.object === cur && typeof p.prop === 'string') { cur = p; continue; }
    break;
  }
  return accessPathOf(cur);
}

// ── §3.3/§3.4: planSeeds ────────────────────────────────────────────────────

/**
 * Plan the seeds for a whole project. Pure: runs no field-identity analysis
 * itself, only walks IR expressions and consults the source registry.
 *
 * `callGraph` must be a real object from
 * `scanner/src/ir/callgraph.js#buildCallGraph` (`{functions, ...}`) or an
 * equivalent hand-built fixture exposing the same shape.
 *
 * Returns `{seeds, unseedable}`. Each seed record carries exactly the
 * §3.3 shape:
 *   { file, qid, nodeId, line, entryId, seedPath, canonicalName,
 *     category, coverageStatus, externality, reason,   // <- reclassifySource(entry)
 *     dataElementId, dataClasses }                      // <- ids.js + classification.js
 *
 * A matched expression with NO access path (`accessPathOf` → `null`) is
 * recorded in `unseedable[]` — never silently dropped (§3.3).
 */
export function planSeeds(callGraph, { repository } = {}) {
  const seeds = [];
  const unseedable = [];
  for (const fn of callGraph.functions.values()) {
    for (const [nid, node] of Object.entries(fn.cfg?.nodes ?? {})) {
      const parentOf = new Map();
      for (const root of exprRoots(node)) walkExpr(root, (e, p) => { if (p) parentOf.set(e, p); });
      for (const root of exprRoots(node)) {
        walkExpr(root, (e) => {
          const entry = matchSource(e, fn.file);
          if (!entry) return;
          const decision = reclassifySource(entry);
          const seedPath = seedPathFor(e, parentOf);
          if (!seedPath) {
            unseedable.push({
              file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null,
              entryId: entry.id, reason: 'accessPathOf returned null for the matched expression',
            });
            return;
          }
          const canonicalName = seedPath.slice(seedPath.lastIndexOf('.') + 1);
          seeds.push({
            file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null,
            entryId: entry.id, seedPath, canonicalName,
            category: decision.category, coverageStatus: decision.coverageStatus,
            externality: decision.externality, reason: decision.reason,
            // §3.4's minting rule. `canonicalName` alone is forbidden by
            // PRD §10.4; the discriminator carries the system proxy
            // (repository + file), the access path, and the category.
            // Function scope (`qid`) is deliberately NOT in the
            // discriminator (§3.4).
            dataElementId: dataElementId(canonicalName, [repository, fn.file, seedPath, decision.category ?? '']),
            dataClasses: classifyDataElementName(canonicalName).classes,
          });
        });
      }
    }
  }
  return { seeds, unseedable };
}

// ── §3.5: seedEntryStateFactory — the driver.js opts.seedEntryState hook ──

/**
 * Builds the `opts.seedEntryState(fn) -> state | undefined` function
 * `driver.js`'s `runFieldIdentityAnalysis` expects (Sub-project E,
 * increment 1's additive hook). Groups `seeds` by function (`qid`) and
 * returns, for a given function, a `field-identity.js` state carrying every
 * data-element identity seeded at a matched call site inside that function
 * — or `undefined` for a function with no seeds, so `driver.js`'s own
 * `opts.seedEntryState(fn) || emptyState()` fallback applies unchanged.
 */
export function seedEntryStateFactory(seeds) {
  const byQid = new Map();
  for (const s of seeds) {
    if (!byQid.has(s.qid)) byQid.set(s.qid, []);
    byQid.get(s.qid).push(s);
  }
  return (fn) => {
    const list = byQid.get(fn.qid);
    if (!list) return undefined;
    let st = emptyState();
    for (const s of list) st = addIdentity(st, s.seedPath, s.dataElementId);
    return st;
  };
}
