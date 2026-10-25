//
// refs.js: the graph reference format (DAG-06 R06.2).
//
// A reference names ONE entity in ONE immutable graph:
//   { v, graphKind, repository, graphDigest, entityKind, localId }
//
// The local id is only unique inside its graph, so it is never used alone as
// a key. The repository identity and the graph digest are part of the
// reference, which is what keeps two repositories with identical local ids
// distinct and stops a stale reference from silently resolving against a
// different version of the graph.
//
// Pure functions, no I/O.

import { createHash } from 'node:crypto';

export const REF_VERSION = 1;

/** The graph layers that have an adapter. Every one keeps its own native schema. */
export const GRAPH_KINDS = Object.freeze([
  'provenance',        // PathStore pnode/pedge DAG
  'dataflow',          // DataFlowGraph v1
  'semantic',          // SemanticGraph v1
  'artifact',          // artifact provenance graph
  'cross-repo-links',  // declared CrossRepoLink records
  'findings',          // scanner findings, as referenceable entities
]);

export class GraphViewError extends Error {
  constructor(code, message, detail = {}) {
    super(`${code}: ${message}`);
    this.name = 'GraphViewError';
    this.code = code;
    this.detail = detail;
  }
}

const isNonEmpty = (v) => typeof v === 'string' && v.length > 0;

/** Deterministic key-sorted JSON, the canonical form every digest here hashes. */
export function canonicalJson(value) {
  const canon = (v) => {
    if (Array.isArray(v)) return v.map(canon);
    if (v && typeof v === 'object') {
      const o = {};
      for (const k of Object.keys(v).sort()) if (v[k] !== undefined) o[k] = canon(v[k]);
      return o;
    }
    return v;
  };
  return JSON.stringify(canon(value));
}

export function digestOf(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

/**
 * Build a reference object. Throws GraphViewError('BAD_REF') on a missing
 * component: a reference with a blank part is never constructed.
 */
export function makeRef({ graphKind, repository, graphDigest, entityKind, localId }) {
  const ref = { v: REF_VERSION, graphKind, repository, graphDigest, entityKind, localId };
  const bad = validateRef(ref);
  if (bad) throw new GraphViewError('BAD_REF', bad, { ref });
  return Object.freeze(ref);
}

/** @returns {string|null} a problem description, or null when the reference is well formed */
export function validateRef(ref) {
  if (!ref || typeof ref !== 'object' || Array.isArray(ref)) return 'a reference is an object';
  if (ref.v !== REF_VERSION) return `unsupported reference version ${JSON.stringify(ref.v)} (supported: ${REF_VERSION})`;
  if (!GRAPH_KINDS.includes(ref.graphKind)) return `unknown graph kind ${JSON.stringify(ref.graphKind)}`;
  for (const f of ['repository', 'graphDigest', 'entityKind', 'localId']) {
    if (!isNonEmpty(ref[f])) return `${f} is required`;
  }
  return null;
}

/** The identity of the graph a reference points into (no entity part). */
export function graphIdentityKey(ref) {
  return [ref.graphKind, ref.repository, ref.graphDigest].map(encodeURIComponent).join('|');
}

/** Stable string form; also the map key used by every index. */
export function refKey(ref) {
  const bad = validateRef(ref);
  if (bad) throw new GraphViewError('BAD_REF', bad, { ref });
  return `gref${ref.v}|${[ref.graphKind, ref.repository, ref.graphDigest, ref.entityKind, ref.localId].map(encodeURIComponent).join('|')}`;
}

export function parseRef(text) {
  if (typeof text !== 'string') throw new GraphViewError('BAD_REF', 'a reference string is required');
  const parts = text.split('|');
  const m = /^gref(\d+)$/.exec(parts[0] || '');
  if (!m || parts.length !== 6) throw new GraphViewError('BAD_REF', 'malformed reference string');
  let decoded;
  try { decoded = parts.slice(1).map(decodeURIComponent); } catch { throw new GraphViewError('BAD_REF', 'malformed escape in reference string'); }
  const [graphKind, repository, graphDigest, entityKind, localId] = decoded;
  return makeRef({ graphKind, repository, graphDigest, entityKind, localId, v: Number(m[1]) });
}

export function sameRef(a, b) {
  return refKey(a) === refKey(b);
}
