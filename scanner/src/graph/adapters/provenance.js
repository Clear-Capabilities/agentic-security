//
// adapters/provenance.js: read-only view over a PathStore provenance DAG
// (pnode / pedge). Duck-typed on the store's read API (`nodes()`, `edges()`,
// `limitStatus()`, `diagnostics()`); it does not import path-store.js or any
// analysis engine.
//
// Entities: `pnode` (a point in the DAG) and `pedge` (one witness: a join of an
// in-half and an out-half at one program site). A pedge is BOTH an entity, so a
// crosswalk can name it as a witness, and a relation edge between two pnodes.
//
// Relation choice, from the store's own fields (nothing is guessed):
//   widenReason 'control-dependence'        -> control_dependence
//   target path '<return>'                  -> returns
//   crossScope (argument into a callee)     -> calls
//   otherwise                               -> data_flow
// Evidence grade reuses the flow-grade vocabulary: severed (loss reason),
// ambiguous (correlation ambiguity), widened, implicit, else explicit.

import { digestOf } from '../refs.js';
import { IndexedGraphView, local } from '../view.js';

export const PROVENANCE_ADAPTER_VERSION = '1.0.0';

function relationOf(e, toNode) {
  if ((e.widenReasons || []).includes('control-dependence')) return 'control_dependence';
  if (toNode && toNode.path === '<return>') return 'returns';
  if (e.crossScope) return 'calls';
  return 'data_flow';
}

function gradeOf(e) {
  if ((e.lossReasons || []).length) return 'severed';
  if (e.ambiguousCorrelation) return 'ambiguous';
  if ((e.widenReasons || []).includes('control-dependence')) return 'implicit';
  if ((e.widenReasons || []).length) return 'widened';
  return 'explicit';
}

/**
 * @param {{nodes:()=>object[], edges:()=>object[], limitStatus?:()=>object, diagnostics?:()=>object}} store
 * @param {{repository:string, completion?:object}} opts
 *        `completion` may carry the driver's analysisCompletion record; it is
 *        folded into the view's completion() so an unfinished analysis never
 *        reads as complete.
 */
export function provenanceView(store, opts) {
  if (!store || typeof store.nodes !== 'function' || typeof store.edges !== 'function') {
    throw new TypeError('provenanceView requires a store with nodes() and edges()');
  }
  const repository = opts?.repository;
  const pnodes = store.nodes();
  const pedges = store.edges();
  const byId = new Map(pnodes.map((n) => [n.id, n]));
  const graphDigest = digestOf({ nodes: pnodes, edges: pedges });

  const nodes = [
    ...pnodes.map((n) => ({ entityKind: 'pnode', localId: n.id, native: n, summary: { kind: n.kind, scope: n.scope, path: n.path, truncated: !!n.truncated } })),
    ...pedges.map((e) => ({ entityKind: 'pedge', localId: e.id, native: e, summary: { scope: e.scope, line: e.line ?? null, siteNodeId: e.siteNodeId ?? null, dataElementId: e.dataElementId } })),
  ];
  const edges = pedges.map((e) => {
    const unknowns = [
      ...(e.widenReasons || []).map((r) => ({ kind: 'widen', reason: r })),
      ...(e.lossReasons || []).map((r) => ({ kind: 'loss', reason: r })),
    ];
    if (e.truncated) unknowns.push({ kind: 'truncated', reason: 'analysis-incomplete' });
    return {
      id: e.id, relation: relationOf(e, byId.get(e.toNodeId)), origin: 'code',
      from: local('pnode', e.fromNodeId), to: local('pnode', e.toNodeId),
      evidence: { grade: gradeOf(e), source: 'path-store' },
      unknowns, attrs: { line: e.line ?? null, scope: e.scope, dataElementId: e.dataElementId }, native: e,
    };
  });

  const reasons = [];
  const lim = typeof store.limitStatus === 'function' ? store.limitStatus() : null;
  if (lim?.hit) reasons.push('store-limit-hit');
  const diag = typeof store.diagnostics === 'function' ? store.diagnostics() : null;
  if (diag?.truncations?.length) reasons.push(`truncated-units:${diag.truncations.length}`);
  if (diag?.orphanedPeerSources?.length) reasons.push(`orphaned-peer-sources:${diag.orphanedPeerSources.length}`);
  if (diag?.malformed?.length) reasons.push(`malformed-hops:${diag.malformed.length}`);
  const ac = opts?.completion ?? null;
  if (ac && ac.status && ac.status !== 'complete') reasons.push(`analysis-${ac.status}`);
  const status = reasons.length ? 'partial' : (lim || ac) ? 'complete' : 'unknown';

  return new IndexedGraphView({
    graphKind: 'provenance', adapterVersion: PROVENANCE_ADAPTER_VERSION, repository, graphDigest,
    metadata: { source: 'PathStore', pnodes: pnodes.length, pedges: pedges.length, relationEdges: edges.length },
    completion: { status, reasons, coverage: { limits: lim, analysis: ac } },
    nodes, edges,
    reconstruct: () => ({ nodes: pnodes, edges: pedges }),
  });
}
