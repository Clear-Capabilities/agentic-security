//
// correlation.js: provenance correlation version 2 (DAG-03).
//
// Version 1 pairs the production and consumption halves of a hop at a join
// key (scope, nodeId, dataElementId, context) and marks the pairings it
// cannot tell apart as `ambiguousCorrelation`. Version 2 adds evidence the
// engine had at the moment it emitted each half, so that halves pair only
// when that evidence proves them compatible:
//
//   derivationId     where inside the CFG node's expression tree an in-half
//                    was produced (a segment path such as `/src/p:left/a0`)
//   derivationScope  the part of that tree an out-half consumes
//   relPath          the field path of an in-half relative to the value it
//                    is selected from, and of an out-half relative to the
//                    value it writes
//   fromVersions     the definitions of the read path that reach the read
//   toVersion        the definition a write creates
//   invocationId     one id per call expression instance
//   callRole         'arg' | 'bind' | 'return'
//   argPosition / formalPosition   actual and formal argument positions
//
// Version 2 is OFF by default. It is enabled per call site by the
// `correlationVersion: 2` option or process-wide by
// AGENTIC_SECURITY_LINEAGE_CORRELATION=2. With it off no module in this
// package emits, reads or hashes any of the fields above, so version 1
// output, ids and digests are byte-identical to the pre-DAG-03 behavior.
//
// A hop that lacks the evidence (a hand-built stream, an older recorder, an
// expression kind that carries no derivation) is never pruned: it pairs the
// way version 1 paired it and the edge says so (`correlation:
// 'legacy-unknown'`). Evidence only ever removes pairings that are proven
// incompatible; it never removes a marked edge to make a metric look better.
//
import * as crypto from 'node:crypto';
import { provenanceNodeId, provenanceEdgeId } from './ids.js';

export const CORRELATION_VERSION_1 = 1;
export const CORRELATION_VERSION_2 = 2;

/** Additive hop fields version 2 adds to the 14 version 1 fields. */
export const V2_HOP_FIELDS = [
  'derivationId', 'derivationScope', 'relPath', 'fromVersions', 'toVersion',
  'invocationId', 'callRole', 'argPosition', 'formalPosition', 'allocKind', 'receiver',
];

/** Default bound on the call-context stack a balanced traversal tracks. */
export const DEFAULT_MAX_CALL_DEPTH = 8;

/**
 * Resolves the effective correlation version. An explicit option wins over
 * the environment; anything other than 2 (or '2') is version 1.
 */
export function resolveCorrelationVersion(option) {
  if (option !== undefined && option !== null) {
    return Number(option) === CORRELATION_VERSION_2 ? CORRELATION_VERSION_2 : CORRELATION_VERSION_1;
  }
  return process.env.AGENTIC_SECURITY_LINEAGE_CORRELATION === '2' ? CORRELATION_VERSION_2 : CORRELATION_VERSION_1;
}

// --- derivation ids ---------------------------------------------------

/** Appends one segment to a derivation path. */
export function deriveChild(parent, seg) {
  return `${parent ?? ''}/${seg}`;
}

/**
 * Is `scope` a segment-aligned prefix of (or equal to) `id`? An out-half
 * whose scope is `/src/p:left` consumes `/src/p:left` and everything under
 * it, but not `/src/p:leftover`.
 */
export function derivationCovers(scope, id) {
  if (scope === '' || scope === null || scope === undefined) return true;
  return id === scope || id.startsWith(`${scope}/`);
}

/**
 * For an out-half that writes the byPath entry `subPath` of a value built by
 * `expr`, returns the derivation scope that entry was produced under and the
 * part of `subPath` left over below that scope. Only an object literal names
 * its properties; every other expression kind keeps the root scope, which
 * is the version 1 behavior (all in-halves of the node are candidates).
 */
export function scopeForSubPath(expr, subPath, rootDerivation) {
  let scope = rootDerivation ?? '';
  let rest = subPath ?? '';
  let cur = expr;
  while (cur && cur.kind === 'object' && rest !== '') {
    const dot = rest.indexOf('.');
    const head = dot === -1 ? rest : rest.slice(0, dot);
    const tail = dot === -1 ? '' : rest.slice(dot + 1);
    const props = (cur.props ?? []).filter((p) => !p.spread && p.key === head);
    if (props.length !== 1) break; // absent, duplicated or computed: keep the wider scope
    scope = deriveChild(scope, `p:${head}`);
    rest = tail;
    cur = props[0].value;
  }
  return { scope, rest };
}

/** The field path of `key` relative to the queried path (empty when the key is the path or an ancestor). */
export function relPathOf(key, path) {
  if (typeof key !== 'string' || typeof path !== 'string') return null;
  return key.length > path.length && key.startsWith(`${path}.`) ? key.slice(path.length + 1) : '';
}

/** One id per call expression instance in a function context. */
export function invocationIdOf({ scope, nodeId, context, derivation }) {
  const h = crypto.createHash('sha256')
    .update([scope, nodeId, context, derivation].map((p) => (p === null || p === undefined ? '' : String(p))).join('|'))
    .digest('hex').slice(0, 12);
  return `inv:${h}`;
}

// Two relative field paths disagree only when BOTH name a field and the names
// differ. An empty path is a container-level fact, which applies to every
// field of the container, so it never disagrees: pruning on it would drop a
// real edge.
function fieldsDisagree(a, b) {
  return typeof a === 'string' && typeof b === 'string' && a !== '' && b !== '' && a !== b;
}

// --- pairing -----------------------------------------------------------

/**
 * Are an in-half `s` and an out-half `o` of one group compatible under
 * version 2? Both arguments are `{hop}` wrappers. `true` means "pair them";
 * `evidence` says whether the pairing is proven by ids on both sides.
 */
export function pairCompatibility(sHop, oHop) {
  // A call argument feeds exactly the parameter binding of the same
  // invocation and position. It never reaches the assignment that receives
  // the call's result, because the value goes through the callee.
  if (sHop.callRole === 'arg') {
    const ok = oHop.callRole === 'bind'
      && oHop.invocationId === sHop.invocationId
      && oHop.formalPosition === sHop.argPosition
      && !fieldsDisagree(sHop.relPath, oHop.relPath);
    return { compatible: ok, proven: true };
  }
  if (oHop.callRole === 'bind') return { compatible: false, proven: true };
  if (sHop.derivationId != null && oHop.derivationScope != null) {
    if (!derivationCovers(oHop.derivationScope, sHop.derivationId)) return { compatible: false, proven: true };
    if (fieldsDisagree(sHop.relPath, oHop.relPath)) return { compatible: false, proven: true };
    return { compatible: true, proven: true };
  }
  return { compatible: true, proven: false };
}

// --- crosswalk ---------------------------------------------------------

/**
 * Version 1 to version 2 crosswalk for a built version 2 store. A version 1
 * id names a (scope, context, path, data element) location; the version 2
 * ids under it are the value versions of that location. An edge crosswalks
 * the same way through its endpoints.
 *
 *   { version: 2, nodes: [{ v1, v2: [ids] }], edges: [{ v1, v2: [ids] }],
 *     unmapped: { nodes: [...], edges: [...] } }
 *
 * Every version 2 id appears under exactly one version 1 id, so the
 * crosswalk is total over the store; `unmapped` is always empty for a
 * correct store and exists so a test can assert that.
 */
export function buildCrosswalk(store) {
  const nodes = store.nodes();
  const edges = store.edges();
  const v1OfNode = new Map();
  const nodeGroups = new Map();
  for (const n of nodes) {
    const v1 = provenanceNodeId({
      kind: n.kind, scope: n.scope, context: n.context, path: n.path,
      siteNodeId: n.siteNodeId, dataElementId: n.dataElementId,
    });
    v1OfNode.set(n.id, v1);
    if (!nodeGroups.has(v1)) nodeGroups.set(v1, []);
    nodeGroups.get(v1).push(n.id);
  }
  const edgeGroups = new Map();
  for (const e of edges) {
    const v1 = provenanceEdgeId({
      fromNodeId: v1OfNode.get(e.fromNodeId), toNodeId: v1OfNode.get(e.toNodeId),
      dataElementId: e.dataElementId, scope: e.scope, context: e.context, siteNodeId: e.siteNodeId,
      inKind: e.inKind, inSubKind: e.inSubKind, outKind: e.outKind, outSubKind: e.outSubKind,
      widenReasons: e.widenReasons, lossReasons: e.lossReasons,
    });
    if (!edgeGroups.has(v1)) edgeGroups.set(v1, []);
    edgeGroups.get(v1).push(e.id);
  }
  const toRows = (m) => [...m.entries()]
    .map(([v1, v2]) => ({ v1, v2: [...new Set(v2)].sort() }))
    .sort((a, b) => (a.v1 < b.v1 ? -1 : a.v1 > b.v1 ? 1 : 0));
  return {
    version: CORRELATION_VERSION_2,
    nodes: toRows(nodeGroups),
    edges: toRows(edgeGroups),
    unmapped: { nodes: [], edges: [] },
  };
}
