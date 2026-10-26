//
// view.js: the read-only typed graph view contract (DAG-06 R06.1) and the
// shared adjacency-index cache (R06.6).
//
// A GraphView is a READ-ONLY lens over one existing graph. It never replaces
// the graph's own schema: every node and edge keeps its original object in
// `native`, every original id is preserved, and `reconstruct()` hands back the
// source graph so an adapter round trip loses nothing.
//
// The contract (every adapter exposes exactly this):
//   identity            { graphKind, repository, graphDigest, adapterVersion }
//   metadata()          adapter/graph facts: counts, schema versions, sources
//   completion()        { status: 'complete'|'partial'|'unknown', reasons[], coverage }
//   has(ref)            boolean, never throws on a well-formed ref
//   node(ref)           the entity, or throws DANGLING_REF / WRONG_GRAPH
//   incoming(ref, f)    edges ending at ref, restricted by the relation filter
//   outgoing(ref, f)    edges starting at ref, restricted by the relation filter
//   reconstruct()       the original source graph (round trip)
//
// Adjacency indexes are built once per immutable (graphKind, digest, adapter
// version) and shared by every view over the same content. The index is
// keyed by LOCAL ids and references are rebuilt per view, so two repositories
// that happen to share content never share each other's identity.

import { createHash } from 'node:crypto';
import {
  GraphViewError, GRAPH_KINDS, makeRef, refKey, validateRef, REF_VERSION,
} from './refs.js';
import { normalizeFilter, edgeMatches, RELATION_KINDS, EDGE_ORIGINS } from './relations.js';

const localKey = (entityKind, localId) => `${entityKind}\u0000${localId}`;

// ---- adjacency cache -------------------------------------------------------------------------------------------------------

const CACHE_LIMIT = 64;
const _cache = new Map(); // cacheKey -> { fingerprint, index }
const _stats = { builds: 0, hits: 0, evictions: 0 };

export function adjacencyCacheStats() { return { ..._stats, size: _cache.size }; }
export function clearAdjacencyCache() { _cache.clear(); _stats.builds = 0; _stats.hits = 0; _stats.evictions = 0; }

function buildIndex(templates) {
  const out = new Map();
  const inn = new Map();
  const push = (m, k, e) => { const a = m.get(k); if (a) a.push(e); else m.set(k, [e]); };
  const endKey = (end) => (end.local ? localKey(end.entityKind, end.localId) : refKey(end.ref));
  for (const t of templates) {
    push(out, endKey(t.from), t);
    push(inn, endKey(t.to), t);
  }
  return { out, in: inn };
}

function sharedIndex({ graphKind, graphDigest, adapterVersion }, templates, fingerprint) {
  const key = `${graphKind}|${graphDigest}|${adapterVersion}`;
  const hit = _cache.get(key);
  if (hit) {
    if (hit.fingerprint !== fingerprint) {
      // The digest is the cache key because a graph with that digest is immutable.
      // Different content under the same digest means the digest was not computed
      // from the content, and serving the cached index would be a silent wrong answer.
      throw new GraphViewError('DIGEST_CONFLICT', `graph digest ${graphDigest} was seen with different content`, { key });
    }
    _stats.hits += 1;
    _cache.delete(key); _cache.set(key, hit); // LRU touch
    return hit.index;
  }
  const index = buildIndex(templates);
  _stats.builds += 1;
  _cache.set(key, { fingerprint, index });
  if (_cache.size > CACHE_LIMIT) {
    _cache.delete(_cache.keys().next().value);
    _stats.evictions += 1;
  }
  return index;
}

// ---- edge templates --------------------------------------------------------------------------------------------------------

/**
 * Adapters describe edges with `local(entityKind, localId)` endpoints for
 * entities of their own graph, or `foreign(ref)` for an endpoint that lives in
 * another graph (cross-repository declarations).
 */
export const local = (entityKind, localId) => ({ local: true, entityKind, localId });
export const foreign = (ref) => {
  const bad = validateRef(ref);
  if (bad) throw new GraphViewError('BAD_REF', bad);
  return { local: false, ref };
};

function checkTemplate(t) {
  if (!t || typeof t.id !== 'string' || !t.id) throw new GraphViewError('BAD_EDGE', 'an edge needs an id');
  if (!RELATION_KINDS.includes(t.relation)) throw new GraphViewError('BAD_EDGE', `edge ${t.id}: unknown relation ${JSON.stringify(t.relation)}`);
  if (!EDGE_ORIGINS.includes(t.origin)) throw new GraphViewError('BAD_EDGE', `edge ${t.id}: unknown origin ${JSON.stringify(t.origin)}`);
  if (!t.from || !t.to) throw new GraphViewError('BAD_EDGE', `edge ${t.id}: both endpoints are required`);
}

// ---- the view --------------------------------------------------------------------------------------------------------------

export class IndexedGraphView {
  /**
   * @param {object} spec
   * @param {string} spec.graphKind
   * @param {string} spec.adapterVersion  semver of the adapter, not of the graph schema
   * @param {string} spec.repository
   * @param {string} spec.graphDigest     digest of the SOURCE graph, preserved as given
   * @param {object} spec.metadata
   * @param {object} spec.completion      { status, reasons, coverage }
   * @param {{entityKind:string, localId:string, native:any, summary?:object}[]} spec.nodes
   * @param {object[]} spec.edges         edge templates (see local()/foreign())
   * @param {() => any} spec.reconstruct  returns the original source graph
   * @param {boolean} [spec.allowForeign] endpoints may live in other graphs
   */
  constructor(spec) {
    if (!GRAPH_KINDS.includes(spec.graphKind)) throw new GraphViewError('BAD_REF', `unknown graph kind ${spec.graphKind}`);
    if (!/^\d+\.\d+\.\d+$/.test(spec.adapterVersion || '')) throw new GraphViewError('BAD_VERSION', 'adapterVersion must be a semantic version');
    for (const f of ['repository', 'graphDigest']) {
      if (typeof spec[f] !== 'string' || !spec[f]) throw new GraphViewError('BAD_REF', `${f} is required`);
    }
    this.graphKind = spec.graphKind;
    this.adapterVersion = spec.adapterVersion;
    this.repository = spec.repository;
    this.graphDigest = spec.graphDigest;
    this._metadata = spec.metadata ?? {};
    this._completion = spec.completion ?? { status: 'unknown', reasons: ['adapter supplied no completion record'], coverage: null };
    this._reconstruct = spec.reconstruct;
    this._allowForeign = !!spec.allowForeign;

    this._nodes = new Map();
    for (const n of spec.nodes) {
      const k = localKey(n.entityKind, n.localId);
      if (this._nodes.has(k)) throw new GraphViewError('DUPLICATE_ID', `${this.graphKind} graph has two ${n.entityKind} entities with id ${n.localId}`, { entityKind: n.entityKind, localId: n.localId });
      this._nodes.set(k, n);
    }
    this._templates = [];
    const seen = new Set();
    for (const t of spec.edges) {
      checkTemplate(t);
      if (seen.has(t.id)) throw new GraphViewError('DUPLICATE_ID', `${this.graphKind} graph has two edges with id ${t.id}`, { edgeId: t.id });
      seen.add(t.id);
      for (const end of [t.from, t.to]) {
        if (end.local && !this._nodes.has(localKey(end.entityKind, end.localId))) {
          throw new GraphViewError('DANGLING_REF', `edge ${t.id} points at ${end.entityKind} ${end.localId}, which is not in the graph`, { edgeId: t.id });
        }
        if (!end.local && !this._allowForeign) throw new GraphViewError('BAD_EDGE', `edge ${t.id}: foreign endpoints are only allowed in declaration views`);
      }
      this._templates.push(t);
    }
    // Content fingerprint over every entity key and edge id (order-insensitive). A
    // digest names one immutable graph; the fingerprint is how a digest that does
    // NOT match its content is caught instead of served from the shared index.
    const h = createHash('sha256');
    for (const k of [...this._nodes.keys()].sort()) h.update(k).update('\u0001');
    h.update('\u0002');
    for (const t of [...this._templates].map((x) => x.id).sort()) h.update(t).update('\u0001');
    this.fingerprint = h.digest('hex');
    this._index = sharedIndex(this.identity, this._templates, this.fingerprint);
  }

  get identity() {
    return { graphKind: this.graphKind, repository: this.repository, graphDigest: this.graphDigest, adapterVersion: this.adapterVersion };
  }

  /** Reference to one of this graph's own entities. Throws DANGLING_REF if it is not there. */
  ref(entityKind, localId) {
    if (!this._nodes.has(localKey(entityKind, localId))) {
      throw new GraphViewError('DANGLING_REF', `no ${entityKind} ${localId} in this ${this.graphKind} graph`, { entityKind, localId });
    }
    return makeRef({ graphKind: this.graphKind, repository: this.repository, graphDigest: this.graphDigest, entityKind, localId });
  }

  owns(ref) {
    return ref.graphKind === this.graphKind && ref.repository === this.repository && ref.graphDigest === this.graphDigest;
  }

  _checkRef(ref) {
    const bad = validateRef(ref);
    if (bad) {
      throw new GraphViewError(ref && ref.v !== undefined && ref.v !== REF_VERSION ? 'VERSION_INCOMPATIBLE' : 'BAD_REF', bad, { ref });
    }
  }

  has(ref) {
    this._checkRef(ref);
    return this.owns(ref) && this._nodes.has(localKey(ref.entityKind, ref.localId));
  }

  node(ref) {
    this._checkRef(ref);
    if (!this.owns(ref)) {
      throw new GraphViewError('WRONG_GRAPH', `reference points into ${ref.graphKind}/${ref.repository}/${ref.graphDigest.slice(0, 12)}, not this view`, { ref });
    }
    const n = this._nodes.get(localKey(ref.entityKind, ref.localId));
    if (!n) throw new GraphViewError('DANGLING_REF', `no ${ref.entityKind} ${ref.localId} in this ${this.graphKind} graph`, { ref });
    return { ref, entityKind: n.entityKind, localId: n.localId, summary: n.summary ?? null, native: n.native };
  }

  _lookup(map, ref) {
    this._checkRef(ref);
    let key;
    if (this.owns(ref)) {
      key = localKey(ref.entityKind, ref.localId);
      if (!this._nodes.has(key)) throw new GraphViewError('DANGLING_REF', `no ${ref.entityKind} ${ref.localId} in this ${this.graphKind} graph`, { ref });
    } else if (this._allowForeign) {
      key = refKey(ref);
    } else {
      throw new GraphViewError('WRONG_GRAPH', 'reference points into a different graph', { ref });
    }
    return map.get(key) ?? [];
  }

  _materialize(t) {
    const end = (e) => (e.local ? this.ref(e.entityKind, e.localId) : e.ref);
    return {
      id: t.id, relation: t.relation, origin: t.origin,
      from: end(t.from), to: end(t.to),
      evidence: t.evidence ?? { grade: 'none', source: null },
      unknowns: t.unknowns ?? [],
      attrs: t.attrs ?? {},
      native: t.native,
    };
  }

  outgoing(ref, filter) {
    const nf = normalizeFilter(filter);
    return this._lookup(this._index.out, ref).filter((t) => edgeMatches(t, nf)).map((t) => this._materialize(t));
  }

  incoming(ref, filter) {
    const nf = normalizeFilter(filter);
    return this._lookup(this._index.in, ref).filter((t) => edgeMatches(t, nf)).map((t) => this._materialize(t));
  }

  /** Entities in insertion order, optionally of one kind. */
  entities(entityKind) {
    const out = [];
    for (const n of this._nodes.values()) if (!entityKind || n.entityKind === entityKind) out.push(this.node(this.ref(n.entityKind, n.localId)));
    return out;
  }

  edges() { return this._templates.map((t) => this._materialize(t)); }

  metadata() {
    return { ...this._metadata, graphKind: this.graphKind, repository: this.repository, graphDigest: this.graphDigest, adapterVersion: this.adapterVersion, nodeCount: this._nodes.size, edgeCount: this._templates.length };
  }

  completion() {
    const c = this._completion;
    return { status: c.status, reasons: [...(c.reasons ?? [])], coverage: c.coverage ?? null };
  }

  reconstruct() { return this._reconstruct(); }
}
