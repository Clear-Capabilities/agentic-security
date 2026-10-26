export const id = 8158;
export const ids = [8158];
export const modules = {

/***/ 88158:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  GraphViewError: () => (/* reexport */ refs_GraphViewError),
  dataflowView: () => (/* reexport */ dataflowView)
});

// UNUSED EXPORTS: ARTIFACT_ADAPTER_VERSION, CROSSREPO_ADAPTER_VERSION, CROSSWALK_VERSION, DATAFLOW_ADAPTER_VERSION, DEFAULT_TRUSTED_ORIGINS, EDGE_ORIGINS, FINDINGS_ADAPTER_VERSION, GRAPH_KINDS, IndexedGraphView, MAPPING_TYPES, PROVENANCE_ADAPTER_VERSION, REF_VERSION, RELATION_KINDS, SEMANTIC_ADAPTER_VERSION, SUPPORTED_ADAPTER_MAJORS, adjacencyCacheStats, artifactView, attributeObservation, canonicalJson, clearAdjacencyCache, createCrosswalk, createGraphRegistry, crossRepoLinkView, digestOf, edgeMatches, findingsView, foreign, graphIdentityKey, local, makeRef, mapCallSitesToWitnesses, mapFindingsToCallSites, mapProjectedNodesToSites, mapWitnessesToFlows, normalizeFilter, parseRef, provenanceView, refKey, sameRef, semanticView, validateRef

// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
;// CONCATENATED MODULE: ./src/graph/refs.js
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



const refs_REF_VERSION = 1;

/** The graph layers that have an adapter. Every one keeps its own native schema. */
const GRAPH_KINDS = Object.freeze([
  'provenance',        // PathStore pnode/pedge DAG
  'dataflow',          // DataFlowGraph v1
  'semantic',          // SemanticGraph v1
  'artifact',          // artifact provenance graph
  'cross-repo-links',  // declared CrossRepoLink records
  'findings',          // scanner findings, as referenceable entities
]);

class refs_GraphViewError extends Error {
  constructor(code, message, detail = {}) {
    super(`${code}: ${message}`);
    this.name = 'GraphViewError';
    this.code = code;
    this.detail = detail;
  }
}

const isNonEmpty = (v) => typeof v === 'string' && v.length > 0;

/** Deterministic key-sorted JSON, the canonical form every digest here hashes. */
function refs_canonicalJson(value) {
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

function refs_digestOf(value) {
  return createHash('sha256').update(refs_canonicalJson(value)).digest('hex');
}

/**
 * Build a reference object. Throws GraphViewError('BAD_REF') on a missing
 * component: a reference with a blank part is never constructed.
 */
function refs_makeRef({ graphKind, repository, graphDigest, entityKind, localId }) {
  const ref = { v: refs_REF_VERSION, graphKind, repository, graphDigest, entityKind, localId };
  const bad = refs_validateRef(ref);
  if (bad) throw new refs_GraphViewError('BAD_REF', bad, { ref });
  return Object.freeze(ref);
}

/** @returns {string|null} a problem description, or null when the reference is well formed */
function refs_validateRef(ref) {
  if (!ref || typeof ref !== 'object' || Array.isArray(ref)) return 'a reference is an object';
  if (ref.v !== refs_REF_VERSION) return `unsupported reference version ${JSON.stringify(ref.v)} (supported: ${refs_REF_VERSION})`;
  if (!GRAPH_KINDS.includes(ref.graphKind)) return `unknown graph kind ${JSON.stringify(ref.graphKind)}`;
  for (const f of ['repository', 'graphDigest', 'entityKind', 'localId']) {
    if (!isNonEmpty(ref[f])) return `${f} is required`;
  }
  return null;
}

/** The identity of the graph a reference points into (no entity part). */
function refs_graphIdentityKey(ref) {
  return [ref.graphKind, ref.repository, ref.graphDigest].map(encodeURIComponent).join('|');
}

/** Stable string form; also the map key used by every index. */
function refs_refKey(ref) {
  const bad = refs_validateRef(ref);
  if (bad) throw new refs_GraphViewError('BAD_REF', bad, { ref });
  return `gref${ref.v}|${[ref.graphKind, ref.repository, ref.graphDigest, ref.entityKind, ref.localId].map(encodeURIComponent).join('|')}`;
}

function parseRef(text) {
  if (typeof text !== 'string') throw new refs_GraphViewError('BAD_REF', 'a reference string is required');
  const parts = text.split('|');
  const m = /^gref(\d+)$/.exec(parts[0] || '');
  if (!m || parts.length !== 6) throw new refs_GraphViewError('BAD_REF', 'malformed reference string');
  let decoded;
  try { decoded = parts.slice(1).map(decodeURIComponent); } catch { throw new refs_GraphViewError('BAD_REF', 'malformed escape in reference string'); }
  const [graphKind, repository, graphDigest, entityKind, localId] = decoded;
  return refs_makeRef({ graphKind, repository, graphDigest, entityKind, localId, v: Number(m[1]) });
}

function sameRef(a, b) {
  return refs_refKey(a) === refs_refKey(b);
}

;// CONCATENATED MODULE: ./src/graph/relations.js
//
// relations.js: relation kinds and the traversal filter (DAG-06 R06.3, R06.4).
//
// Two independent axes, never collapsed into one:
//   - RELATION: what the edge means (data flow, calls, ...).
//   - ORIGIN: how the edge came to exist (derived from code, declared by an
//     operator, observed at runtime, ...).
//
// A query chooses the relations it may traverse AND the origins it trusts.
// The default filter traverses code-derived and derived edges only, so an
// operator declaration or a runtime observation is never silently walked as
// if it were a code-derived data flow (R06.4).



const RELATION_KINDS = Object.freeze([
  'data_flow',            // a value moves from one place to another
  'control_dependence',   // execution of B depends on a decision at A
  'calls',                // a call site invokes a callee
  'returns',              // a callee result comes back to a caller
  'dependency',           // A needs B (package, module, component)
  'declaration',          // A declares/contains B (symbol -> call site, origin)
  'observation',          // a runtime observation attached to an entity
  'artifact_derivation',  // A was built into / produced B
]);

const EDGE_ORIGINS = Object.freeze([
  'code',      // read directly from analyzed source
  'derived',   // computed from code-derived facts by a projection or index
  'declared',  // asserted by an operator (cross-repo links, deployments)
  'observed',  // seen at runtime (telemetry)
  'schema',    // taken from a schema or manifest
]);

/** Origins a default query trusts as "the program's own structure". */
const DEFAULT_TRUSTED_ORIGINS = Object.freeze(['code', 'derived', 'schema']);

/**
 * Normalize a relation filter. Accepted forms:
 *   undefined / null          -> every relation, trusted origins only
 *   'calls' | ['calls', ...]  -> those relations, trusted origins only
 *   { relations, origins }    -> explicit on both axes
 * Unknown relation or origin names throw, so a typo never silently widens
 * or empties a query.
 */
function normalizeFilter(filter) {
  let relations = null;
  let origins = DEFAULT_TRUSTED_ORIGINS;
  if (filter === undefined || filter === null) {
    // defaults
  } else if (typeof filter === 'string') {
    relations = [filter];
  } else if (Array.isArray(filter)) {
    relations = filter;
  } else if (typeof filter === 'object') {
    if (filter.relations !== undefined && filter.relations !== null) {
      relations = typeof filter.relations === 'string' ? [filter.relations] : filter.relations;
    }
    if (filter.origins !== undefined && filter.origins !== null) {
      origins = typeof filter.origins === 'string' ? [filter.origins] : filter.origins;
    }
  } else {
    throw new refs_GraphViewError('BAD_FILTER', 'a relation filter is a name, a list of names or { relations, origins }');
  }
  if (relations !== null) {
    if (!Array.isArray(relations)) throw new refs_GraphViewError('BAD_FILTER', 'relations must be a list');
    for (const r of relations) {
      if (!RELATION_KINDS.includes(r)) throw new refs_GraphViewError('BAD_FILTER', `unknown relation kind ${JSON.stringify(r)}`);
    }
  }
  if (!Array.isArray(origins)) throw new refs_GraphViewError('BAD_FILTER', 'origins must be a list');
  for (const o of origins) {
    if (!EDGE_ORIGINS.includes(o)) throw new refs_GraphViewError('BAD_FILTER', `unknown edge origin ${JSON.stringify(o)}`);
  }
  return { relations: relations ? new Set(relations) : null, origins: new Set(origins) };
}

function edgeMatches(edge, nf) {
  if (nf.relations && !nf.relations.has(edge.relation)) return false;
  return nf.origins.has(edge.origin);
}

;// CONCATENATED MODULE: ./src/graph/view.js
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





const localKey = (entityKind, localId) => `${entityKind}\u0000${localId}`;

// ---- adjacency cache -------------------------------------------------------------------------------------------------------

const CACHE_LIMIT = 64;
const _cache = new Map(); // cacheKey -> { fingerprint, index }
const _stats = { builds: 0, hits: 0, evictions: 0 };

function adjacencyCacheStats() { return { ..._stats, size: _cache.size }; }
function clearAdjacencyCache() { _cache.clear(); _stats.builds = 0; _stats.hits = 0; _stats.evictions = 0; }

function buildIndex(templates) {
  const out = new Map();
  const inn = new Map();
  const push = (m, k, e) => { const a = m.get(k); if (a) a.push(e); else m.set(k, [e]); };
  const endKey = (end) => (end.local ? localKey(end.entityKind, end.localId) : refs_refKey(end.ref));
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
      throw new refs_GraphViewError('DIGEST_CONFLICT', `graph digest ${graphDigest} was seen with different content`, { key });
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
const view_local = (entityKind, localId) => ({ local: true, entityKind, localId });
const view_foreign = (ref) => {
  const bad = validateRef(ref);
  if (bad) throw new GraphViewError('BAD_REF', bad);
  return { local: false, ref };
};

function checkTemplate(t) {
  if (!t || typeof t.id !== 'string' || !t.id) throw new refs_GraphViewError('BAD_EDGE', 'an edge needs an id');
  if (!RELATION_KINDS.includes(t.relation)) throw new refs_GraphViewError('BAD_EDGE', `edge ${t.id}: unknown relation ${JSON.stringify(t.relation)}`);
  if (!EDGE_ORIGINS.includes(t.origin)) throw new refs_GraphViewError('BAD_EDGE', `edge ${t.id}: unknown origin ${JSON.stringify(t.origin)}`);
  if (!t.from || !t.to) throw new refs_GraphViewError('BAD_EDGE', `edge ${t.id}: both endpoints are required`);
}

// ---- the view --------------------------------------------------------------------------------------------------------------

class view_IndexedGraphView {
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
    if (!GRAPH_KINDS.includes(spec.graphKind)) throw new refs_GraphViewError('BAD_REF', `unknown graph kind ${spec.graphKind}`);
    if (!/^\d+\.\d+\.\d+$/.test(spec.adapterVersion || '')) throw new refs_GraphViewError('BAD_VERSION', 'adapterVersion must be a semantic version');
    for (const f of ['repository', 'graphDigest']) {
      if (typeof spec[f] !== 'string' || !spec[f]) throw new refs_GraphViewError('BAD_REF', `${f} is required`);
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
      if (this._nodes.has(k)) throw new refs_GraphViewError('DUPLICATE_ID', `${this.graphKind} graph has two ${n.entityKind} entities with id ${n.localId}`, { entityKind: n.entityKind, localId: n.localId });
      this._nodes.set(k, n);
    }
    this._templates = [];
    const seen = new Set();
    for (const t of spec.edges) {
      checkTemplate(t);
      if (seen.has(t.id)) throw new refs_GraphViewError('DUPLICATE_ID', `${this.graphKind} graph has two edges with id ${t.id}`, { edgeId: t.id });
      seen.add(t.id);
      for (const end of [t.from, t.to]) {
        if (end.local && !this._nodes.has(localKey(end.entityKind, end.localId))) {
          throw new refs_GraphViewError('DANGLING_REF', `edge ${t.id} points at ${end.entityKind} ${end.localId}, which is not in the graph`, { edgeId: t.id });
        }
        if (!end.local && !this._allowForeign) throw new refs_GraphViewError('BAD_EDGE', `edge ${t.id}: foreign endpoints are only allowed in declaration views`);
      }
      this._templates.push(t);
    }
    // Content fingerprint over every entity key and edge id (order-insensitive). A
    // digest names one immutable graph; the fingerprint is how a digest that does
    // NOT match its content is caught instead of served from the shared index.
    const h = (0,external_node_crypto_.createHash)('sha256');
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
      throw new refs_GraphViewError('DANGLING_REF', `no ${entityKind} ${localId} in this ${this.graphKind} graph`, { entityKind, localId });
    }
    return refs_makeRef({ graphKind: this.graphKind, repository: this.repository, graphDigest: this.graphDigest, entityKind, localId });
  }

  owns(ref) {
    return ref.graphKind === this.graphKind && ref.repository === this.repository && ref.graphDigest === this.graphDigest;
  }

  _checkRef(ref) {
    const bad = refs_validateRef(ref);
    if (bad) {
      throw new refs_GraphViewError(ref && ref.v !== undefined && ref.v !== refs_REF_VERSION ? 'VERSION_INCOMPATIBLE' : 'BAD_REF', bad, { ref });
    }
  }

  has(ref) {
    this._checkRef(ref);
    return this.owns(ref) && this._nodes.has(localKey(ref.entityKind, ref.localId));
  }

  node(ref) {
    this._checkRef(ref);
    if (!this.owns(ref)) {
      throw new refs_GraphViewError('WRONG_GRAPH', `reference points into ${ref.graphKind}/${ref.repository}/${ref.graphDigest.slice(0, 12)}, not this view`, { ref });
    }
    const n = this._nodes.get(localKey(ref.entityKind, ref.localId));
    if (!n) throw new refs_GraphViewError('DANGLING_REF', `no ${ref.entityKind} ${ref.localId} in this ${this.graphKind} graph`, { ref });
    return { ref, entityKind: n.entityKind, localId: n.localId, summary: n.summary ?? null, native: n.native };
  }

  _lookup(map, ref) {
    this._checkRef(ref);
    let key;
    if (this.owns(ref)) {
      key = localKey(ref.entityKind, ref.localId);
      if (!this._nodes.has(key)) throw new refs_GraphViewError('DANGLING_REF', `no ${ref.entityKind} ${ref.localId} in this ${this.graphKind} graph`, { ref });
    } else if (this._allowForeign) {
      key = refs_refKey(ref);
    } else {
      throw new refs_GraphViewError('WRONG_GRAPH', 'reference points into a different graph', { ref });
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

;// CONCATENATED MODULE: ./src/graph/adapters/provenance.js
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




const PROVENANCE_ADAPTER_VERSION = '1.0.0';

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
function provenanceView(store, opts) {
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

// EXTERNAL MODULE: ./src/lineage/export-json.js
var export_json = __webpack_require__(40859);
;// CONCATENATED MODULE: ./src/graph/adapters/dataflow.js
//
// adapters/dataflow.js: read-only view over a DataFlowGraph v1 document (the
// graph-builder output / signed export body).
//
// The graph keeps its own schema, validator and digest. This view:
//   - uses the existing `computeGraphDigest` as the graph digest, so the
//     digest in every reference equals the digest the export already signs;
//   - exposes node, edge, flow, dataElement, evidence and transformation
//     entities under their original ids;
//   - maps `edge.provenance` to the origin axis (code -> code, schema ->
//     schema, manual -> declared, runtime -> observed), so a runtime-observed
//     or manually declared edge is never traversed as a code-derived one by a
//     default query;
//   - reports completion from `scanHealth`, `coverage` and `limitations`.
//
// Projected nodes are category-granular: one node can stand for many source
// sites. That coarsening is not hidden here; it is recorded by crosswalks
// (one-to-many) built in crosswalk-builders.js.




const DATAFLOW_ADAPTER_VERSION = '1.0.0';

const ORIGIN_OF_PROVENANCE = { code: 'code', schema: 'schema', manual: 'declared', runtime: 'observed' };

const ENTITY_SECTIONS = [
  ['node', 'nodes'], ['edge', 'edges'], ['flow', 'flows'],
  ['dataElement', 'dataElements'], ['evidence', 'evidence'], ['transformation', 'transformations'],
];

/**
 * @param {object} graph  DataFlowGraph v1 (e.g. buildDataFlowGraph(...).graph)
 * @param {{repository?:string}} [opts]
 */
function dataflowView(graph, opts = {}) {
  if (!graph || typeof graph !== 'object' || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new TypeError('dataflowView requires a DataFlowGraph v1 object with nodes[] and edges[]');
  }
  const repository = opts.repository ?? graph.scope?.repository;
  const graphDigest = (0,export_json.computeGraphDigest)(graph);

  const nodes = [];
  for (const [kind, section] of ENTITY_SECTIONS) {
    for (const e of graph[section] || []) {
      nodes.push({ entityKind: kind, localId: e.id, native: e, summary: kind === 'node' ? { kind: e.kind, subtype: e.subtype ?? null, label: e.label ?? null, coverageStatus: e.coverageStatus ?? null } : null });
    }
  }
  const edges = graph.edges.map((e) => {
    const unknowns = [];
    if (e.protocol?.destinationResolution && e.protocol.destinationResolution !== 'literal') unknowns.push({ kind: 'destination-resolution', reason: e.protocol.destinationResolution });
    if (e.coverageStatus && e.coverageStatus !== 'modeled') unknowns.push({ kind: 'coverage', reason: e.coverageStatus });
    return {
      id: e.id, relation: 'data_flow', origin: ORIGIN_OF_PROVENANCE[e.provenance] ?? 'schema',
      from: view_local('node', e.from), to: view_local('node', e.to),
      evidence: { grade: e.evidenceGrade ?? e.coverageStatus ?? 'none', source: 'dataflow-graph', evidenceRefs: e.evidenceRefs ?? [] },
      unknowns, attrs: { provenance: e.provenance, relationship: e.relationship }, native: e,
    };
  });

  const health = graph.scanHealth || {};
  const reasons = [];
  const status = health.status === 'complete' ? 'complete' : health.status ? 'partial' : 'unknown';
  if (health.status && health.status !== 'complete') reasons.push(`scan-health:${health.status}${health.reason ? `:${health.reason}` : ''}`);
  if (graph.coverage?.pathBudgetTruncation) reasons.push('path-budget-truncation');
  if (health.analysisCompletion && health.analysisCompletion.status && health.analysisCompletion.status !== 'complete') reasons.push(`analysis-${health.analysisCompletion.status}`);
  if ((graph.limitations || []).length) reasons.push(`limitations:${graph.limitations.length}`);

  return new view_IndexedGraphView({
    graphKind: 'dataflow', adapterVersion: DATAFLOW_ADAPTER_VERSION, repository, graphDigest,
    metadata: { schemaVersion: graph.schemaVersion ?? null, graphId: graph.graphId ?? null, scope: graph.scope ?? null, counts: Object.fromEntries(ENTITY_SECTIONS.map(([k, s]) => [k, (graph[s] || []).length])) },
    completion: { status: reasons.length && status === 'complete' ? 'partial' : status, reasons, coverage: graph.coverage ?? null },
    nodes, edges,
    reconstruct: () => graph,
  });
}

;// CONCATENATED MODULE: ./src/dataflow/analysis-limits.js
// Dynamic features the static analysis cannot resolve, reported instead of silently approximated (E2-03).
//
// Where the engine meets one of these it takes the sound direction (a write through an unknown key taints the whole container, a read through
// an unknown key reads the whole container) and loses precision. That is the right trade, but it must be visible: a result that depended on it is
// less precise than one that did not, and a reviewer should be able to see which functions contain such constructs.
//
// Pure: reads the Layer-1 IR only.
const LIMIT_KINDS = Object.freeze({
  'computed-write': 'a write through a key that is not a literal (`o[k] = v`): the engine taints the whole container `o`, so clean sibling fields read afterwards are over-approximated as tainted',
  'computed-read': 'a read through a key that is not a literal (`o[k]`): the engine cannot tell which field is read, so any tainted field of `o` reaches it',
  'eval-like': 'code built at run time (`eval`, `new Function`, `setTimeout` with a string): its content is not analysed',
  'dynamic-require': 'a module name computed at run time (`require(name)`, `import(name)`): the callee is unknown, so the call stays unresolved',
  'reflective-call': 'a call through reflection (`Reflect.apply`, `fn.call/apply` on a computed target, `obj[name]()`): the callee is unknown',
  'getter-or-proxy': 'property access that may run user code (`Proxy`, `Object.defineProperty` accessors): reads and writes may have effects the engine does not model',
});

const expressions = (e, acc = []) => {
  if (!e || typeof e !== 'object') return acc;
  acc.push(e);
  for (const k of ['object', 'callee', 'left', 'right', 'value']) if (e[k] && typeof e[k] === 'object') expressions(e[k], acc);
  for (const k of ['args', 'parts', 'elements', 'props', 'branches']) if (Array.isArray(e[k])) for (const x of e[k]) expressions(x && x.value && !x.kind ? x.value : x, acc);
  return acc;
};
const nameOf = (c) => (typeof c === 'string' ? c : c && c.kind === 'ident' ? c.name : c && c.kind === 'member' ? `${nameOf(c.object)}.${c.prop}` : '');

/** @returns {{kind:string, line:number, detail:string, effect:string}[]} */
function limitsOfFunction(fn) {
  const out = [];
  const add = (kind, line, detail) => out.push({ kind, line: Number.isInteger(line) ? line : (fn.line || 0), detail, effect: LIMIT_KINDS[kind] });
  for (const n of Object.values(fn.cfg?.nodes || {})) {
    if (n.kind === 'assign') {
      if (typeof n.target === 'string' && /\.\*$/.test(n.target)) add('computed-write', n.line, n.target);
      for (const x of expressions(n.source)) inspect(x, n.line, add);
    } else if (n.kind === 'call') {
      inspect({ kind: 'call', callee: n.callee, args: n.args }, n.line, add);
      for (const a of n.args || []) for (const x of expressions(a)) inspect(x, n.line, add);
    } else if (n.kind === 'return' && n.value) for (const x of expressions(n.value)) inspect(x, n.line, add);
  }
  return out;
}

function inspect(x, line, add) {
  if (x.kind === 'member' && x.prop === '*') add('computed-read', line, `${nameOf(x.object)}[…]`);
  if (x.kind === 'call') {
    const c = nameOf(x.callee);
    if (/^(?:eval|Function|new Function|setTimeout|setInterval)$/.test(c)) { if (c === 'eval' || c === 'Function' || c === 'new Function' || (x.args && x.args[0] && x.args[0].kind !== 'function-value' && x.args[0].kind !== 'ident' && x.args[0].kind !== 'literal')) add('eval-like', line, c); else if ((c === 'setTimeout' || c === 'setInterval') && x.args && x.args[0] && x.args[0].kind === 'literal' && typeof x.args[0].value === 'string') add('eval-like', line, `${c}(string)`); }
    if (c === 'require' && x.args && x.args[0] && x.args[0].kind !== 'literal') add('dynamic-require', line, 'require(<expression>)');
    if (/^Reflect\.(?:apply|construct|get|set)$/.test(c)) add('reflective-call', line, c);
    if (x.callee && x.callee.kind === 'member' && x.callee.prop === '*') add('reflective-call', line, `${nameOf(x.callee.object)}[…](…)`);
    if (/^(?:Object\.defineProperty|Object\.defineProperties|Object\.setPrototypeOf)$/.test(c) || c === 'Proxy' || c === 'new Proxy') add('getter-or-proxy', line, c);
  }
}

/**
 * @param {{perFile:Record<string,{functions:object[]}>}} projectIR
 * @returns {{file:string, qid:string, function:string, kind:string, line:number, detail:string, effect:string}[]} sorted, stable
 */
function analysis_limits_analysisLimits(projectIR) {
  const out = [];
  for (const file of Object.keys(projectIR?.perFile || {}).sort()) {
    for (const fn of projectIR.perFile[file].functions || []) {
      for (const l of limitsOfFunction(fn)) out.push({ file, qid: String(fn.qid).replace(/@\d+$/, ''), function: fn.name, ...l });
    }
  }
  return out.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.kind < b.kind ? -1 : 1)));
}

;// CONCATENATED MODULE: ./src/ir/semantic-graph.js
// SemanticGraph v1: a typed, versioned, additive view over the Layer-1 IR (E2-01).
//
// WHY. The IR (`buildProjectIR`) is a bag of per-function records consumed by the taint engine. It has no stable identifiers, no shared
// entity types and no serialization contract, so every analysis that needs "the call at this place" or "where did this value come from"
// re-derives it with its own conventions, and nothing can be compared across runs. This module names the entities once, gives each a
// STABLE id, and fixes a versioned wire format.
//
// ADDITIVE. Building the graph reads the IR and never modifies it; it is not wired into findings, `chain[]` or last-scan.json. Existing
// output is unchanged by construction (a test pins that). A consumer opts in by calling `buildSemanticGraph`.
//
// HONEST. An entity type the IR cannot yet supply (Sanitizer, Guard, ServiceBoundary, StorageEdge) is declared in the schema, emitted as an
// empty list, and reported `schema-only` in `coverage` with the reason. A location the IR does not carry (column) is `null` and the entity
// says `locationPrecision: 'line'`. Nothing is guessed to fill a field.
//
// STABLE IDS. An id is the first 16 hex of SHA-256 over the entity's kind and its identity fields, which never include a line number: adding
// a blank line above a function does not change any id in it. Ties between otherwise identical entities (two `exec(x)` in one function) are
// broken by their order of appearance in that function.



const semantic_graph_SEMANTIC_GRAPH_SCHEMA = 'agentic-security/semantic-graph';
const SEMANTIC_GRAPH_VERSION = '1.0.0';
const semantic_graph_SUPPORTED_MAJOR = 1;

const semantic_graph_ENTITY_LISTS = Object.freeze(['symbols', 'callSites', 'allocations', 'fieldAccesses', 'valueOrigins', 'serviceBoundaries', 'storageEdges', 'sanitizers', 'guards']);
const CONFIDENCE_TIERS = Object.freeze(['observed', 'inferred', 'unresolved']);
const SYMBOL_KINDS = Object.freeze(['module', 'function', 'class', 'variable', 'parameter']);
const ORIGIN_KINDS = Object.freeze(['parameter', 'call-result', 'literal', 'member', 'concat', 'object', 'array', 'function', 'identifier', 'unknown']);

const ID_PREFIX = Object.freeze({ symbols: 'sym', callSites: 'call', allocations: 'alloc', fieldAccesses: 'field', valueOrigins: 'orig', serviceBoundaries: 'svc', storageEdges: 'store', sanitizers: 'san', guards: 'guard' });

const h16 = (parts) => createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 16);
const stripLine = (qid) => String(qid).replace(/@\d+$/, '');

// ---- canonical serialization ------------------------------------------------------------------------------------------------

function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]));
  return v;
}
function serializeGraph(graph) {
  const g = { ...graph };
  for (const k of semantic_graph_ENTITY_LISTS) g[k] = [...(graph[k] || [])].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return JSON.stringify(canon(g));
}

// ---- validation -------------------------------------------------------------------------------------------------------------

/** @returns {{ok:boolean, errors:{code:string,path:string,message:string}[]}} Never throws on hostile input. */
function semantic_graph_validateGraph(g) {
  const errors = [];
  const err = (code, path, message) => errors.push({ code, path, message });
  if (!g || typeof g !== 'object' || Array.isArray(g)) return { ok: false, errors: [{ code: 'NOT_AN_OBJECT', path: '', message: 'a graph is an object' }] };
  if (g.schema !== semantic_graph_SEMANTIC_GRAPH_SCHEMA) { err('SCHEMA_MISMATCH', 'schema', `expected ${semantic_graph_SEMANTIC_GRAPH_SCHEMA}`); return { ok: false, errors }; }
  const m = typeof g.schemaVersion === 'string' ? /^(\d+)\.(\d+)\.(\d+)$/.exec(g.schemaVersion) : null;
  if (!m) { err('BAD_VERSION', 'schemaVersion', 'must be a semantic version'); return { ok: false, errors }; }
  if (Number(m[1]) !== semantic_graph_SUPPORTED_MAJOR) { err('UNSUPPORTED_MAJOR', 'schemaVersion', `major ${m[1]} is not supported (supported: ${semantic_graph_SUPPORTED_MAJOR}); migrate it first`); return { ok: false, errors }; }
  const ids = new Map();
  for (const list of semantic_graph_ENTITY_LISTS) {
    if (!Array.isArray(g[list])) { err('MISSING_FIELD', list, 'must be a list (empty when none)'); continue; }
    g[list].forEach((e, i) => {
      const p = `${list}[${i}]`;
      if (!e || typeof e !== 'object' || Array.isArray(e)) { err('BAD_TYPE', p, 'must be an object'); return; }
      if (typeof e.id !== 'string' || !new RegExp(`^${ID_PREFIX[list]}:[0-9a-f]{16}$`).test(e.id)) err('BAD_ID', `${p}.id`, `must look like ${ID_PREFIX[list]}:<16 hex>`);
      else if (ids.has(e.id)) err('DUPLICATE_ID', `${p}.id`, `duplicate id ${e.id}`); else ids.set(e.id, list);
      if (typeof e.file !== 'string' || !e.file || e.file.startsWith('/') || e.file.split('/').includes('..')) err('BAD_TYPE', `${p}.file`, 'must be a repository-relative path');
      if (!(Number.isInteger(e.line) && e.line >= 0)) err('BAD_TYPE', `${p}.line`, 'line must be a non-negative integer');
      if (!(e.column === null || (Number.isInteger(e.column) && e.column >= 0))) err('BAD_TYPE', `${p}.column`, 'column must be null or a non-negative integer');
      if (e.column === null && e.locationPrecision !== 'line') err('RULE_VIOLATION', `${p}.locationPrecision`, "a null column requires locationPrecision 'line'");
      const c = e.confidence;
      if (!c || typeof c !== 'object' || !CONFIDENCE_TIERS.includes(c.tier) || typeof c.basis !== 'string' || !c.basis) err('BAD_TYPE', `${p}.confidence`, 'needs { tier, basis }');
    });
  }
  if (errors.length) return { ok: false, errors };
  const need = (e, p, field, list) => { if (e[field] !== null && e[field] !== undefined && ids.get(e[field]) !== list) err('DANGLING_REF', `${p}.${field}`, `${e[field]} is not a ${list} id`); };
  g.symbols.forEach((e, i) => { if (!SYMBOL_KINDS.includes(e.kind)) err('UNKNOWN_ENUM', `symbols[${i}].kind`, `unknown symbol kind ${e.kind}`); need(e, `symbols[${i}]`, 'parent', 'symbols'); });
  g.callSites.forEach((e, i) => { need(e, `callSites[${i}]`, 'caller', 'symbols'); need(e, `callSites[${i}]`, 'callee', 'symbols'); if (e.callee && e.resolution !== 'resolved') err('RULE_VIOLATION', `callSites[${i}].resolution`, 'a call with a callee must be resolved'); if (!e.callee && e.resolution === 'resolved') err('RULE_VIOLATION', `callSites[${i}].resolution`, 'a resolved call needs a callee'); (e.args || []).forEach((a, j) => need(a, `callSites[${i}].args[${j}]`, 'origin', 'valueOrigins')); });
  g.valueOrigins.forEach((e, i) => { if (!ORIGIN_KINDS.includes(e.kind)) err('UNKNOWN_ENUM', `valueOrigins[${i}].kind`, `unknown origin kind ${e.kind}`); need(e, `valueOrigins[${i}]`, 'symbol', 'symbols'); });
  g.fieldAccesses.forEach((e, i) => { need(e, `fieldAccesses[${i}]`, 'symbol', 'symbols'); if (!['read', 'write'].includes(e.mode)) err('UNKNOWN_ENUM', `fieldAccesses[${i}].mode`, 'mode must be read or write'); });
  g.allocations.forEach((e, i) => need(e, `allocations[${i}]`, 'symbol', 'symbols'));
  if (!g.coverage || typeof g.coverage !== 'object') err('MISSING_FIELD', 'coverage', 'coverage is required');
  else for (const list of semantic_graph_ENTITY_LISTS) { const c = g.coverage[list]; if (!c || !['populated', 'schema-only'].includes(c.state) || !c.reason) err('BAD_TYPE', `coverage.${list}`, 'needs { state, reason }'); else if (c.state === 'schema-only' && g[list].length) err('RULE_VIOLATION', `coverage.${list}`, 'schema-only but not empty'); else if (c.state === 'populated' && !g[list].length) err('RULE_VIOLATION', `coverage.${list}`, 'populated but empty'); }
  return { ok: errors.length === 0, errors };
}

/** Parse and validate a serialized graph. Returns { ok, graph?, errors }. */
function parseGraph(text) {
  let g; try { g = JSON.parse(text); } catch (e) { return { ok: false, errors: [{ code: 'BAD_JSON', path: '', message: e.message }] }; }
  const v = semantic_graph_validateGraph(g);
  return v.ok ? { ok: true, graph: g, errors: [] } : { ok: false, errors: v.errors };
}

/** Bring an older-minor graph to this version. A different major is refused: there is no silent best-effort. */
function migrateGraph(g) {
  const m = typeof g?.schemaVersion === 'string' ? /^(\d+)\.(\d+)\.(\d+)$/.exec(g.schemaVersion) : null;
  if (!m || g.schema !== semantic_graph_SEMANTIC_GRAPH_SCHEMA) return { ok: false, reason: 'not a semantic graph' };
  if (Number(m[1]) !== semantic_graph_SUPPORTED_MAJOR) return { ok: false, reason: `major ${m[1]} has no migration path to ${SEMANTIC_GRAPH_VERSION}` };
  return { ok: true, graph: { ...g, schemaVersion: SEMANTIC_GRAPH_VERSION }, migrated: g.schemaVersion !== SEMANTIC_GRAPH_VERSION };
}

// ---- builder ----------------------------------------------------------------------------------------------------------------

const exprText = (e) => {
  if (!e || typeof e !== 'object') return '';
  switch (e.kind) {
    case 'ident': return e.name;
    case 'member': return `${exprText(e.object)}.${e.prop ?? '[]'}`;
    case 'call': return `${exprText(e.callee)}(...)`;
    case 'literal': return JSON.stringify(e.value);
    default: return `<${e.kind || 'unknown'}>`;
  }
};
const originKindOf = (e, params) => {
  if (!e) return 'unknown';
  if (e.kind === 'ident') return params.includes(e.name) ? 'parameter' : 'identifier';
  if (e.kind === 'call') return 'call-result';
  if (e.kind === 'literal') return 'literal';
  if (e.kind === 'member') return 'member';
  if (e.kind === 'binary' || e.kind === 'tpl') return 'concat';
  if (e.kind === 'object') return 'object';
  if (e.kind === 'array') return 'array';
  if (e.kind === 'function-value') return 'function';
  return 'unknown';
};
const loc = (file, line) => ({ file, line: Number.isInteger(line) ? line : 0, column: null, locationPrecision: 'line' });
const OBSERVED = { tier: 'observed', basis: 'read directly from the Layer-1 IR' };
const UNRESOLVED = { tier: 'unresolved', basis: 'the IR holds no resolved target for this call' };

function memberChain(e) {
  const path = [];
  let cur = e;
  while (cur && cur.kind === 'member') { path.unshift(cur.prop ?? '[]'); cur = cur.object; }
  return cur && cur.kind === 'ident' ? { base: cur.name, path } : null;
}
function walkExprs(e, visit) {
  if (!e || typeof e !== 'object') return;
  visit(e);
  for (const k of ['object', 'callee', 'left', 'right', 'test', 'cons', 'alt']) if (e[k]) walkExprs(e[k], visit);
  for (const k of ['args', 'parts', 'elements', 'values']) if (Array.isArray(e[k])) e[k].forEach((x) => walkExprs(x, visit));
  if (Array.isArray(e.props)) e.props.forEach((p) => walkExprs(p?.value ?? p, visit));
}

/**
 * @param {{perFile:object, callGraph?:object}} projectIR the object `buildProjectIR` returns
 * @param {{engineVersion?:string}} [meta]
 */
function buildSemanticGraph(projectIR, meta = {}) {
  const g = Object.fromEntries(semantic_graph_ENTITY_LISTS.map((k) => [k, []]));
  const ordinal = new Map();
  const next = (key) => { const n = ordinal.get(key) ?? 0; ordinal.set(key, n + 1); return n; };
  const symByQid = new Map();
  const files = Object.keys(projectIR?.perFile || {}).sort();

  // pass 1: symbols
  for (const file of files) {
    const pf = projectIR.perFile[file];
    for (const fn of pf.functions || []) {
      const isModule = fn.name === '<module>';
      const key = `${file}|${stripLine(fn.qid)}`;
      const id = `sym:${h16(['symbol', file, stripLine(fn.qid), next(`sym|${key}`)])}`;
      symByQid.set(fn.qid, id);
      g.symbols.push({ id, kind: isModule ? 'module' : 'function', name: fn.name, qid: stripLine(fn.qid), parent: null, params: [...(fn.params || [])], ...loc(file, fn.line), confidence: OBSERVED });
    }
  }
  // function-by-name index for DIRECT same-file resolution only; anything else stays unresolved (cross-file resolution is E2-02)
  const byFileName = new Map();
  for (const file of files) for (const fn of projectIR.perFile[file].functions || []) if (fn.name !== '<module>') { const k = `${file}|${fn.name}`; byFileName.set(k, byFileName.has(k) ? null : symByQid.get(fn.qid)); }

  // pass 2: call sites, origins, field accesses, allocations
  for (const file of files) {
    for (const fn of projectIR.perFile[file].functions || []) {
      const symId = symByQid.get(fn.qid);
      const params = fn.params || [];
      const originFor = (expr, variable, line) => {
        const kind = originKindOf(expr, params);
        const o = { id: `orig:${h16(['origin', symId, variable, kind, exprText(expr), next(`orig|${symId}|${variable}|${kind}|${exprText(expr)}`)])}`, symbol: symId, variable, kind, text: exprText(expr), ...loc(file, line), confidence: kind === 'unknown' ? { tier: 'unresolved', basis: 'the IR could not model this expression' } : OBSERVED };
        g.valueOrigins.push(o);
        return o.id;
      };
      const field = (expr, mode, line) => {
        const mc = memberChain(expr);
        if (!mc || !mc.path.length) return;
        g.fieldAccesses.push({ id: `field:${h16(['field', symId, mc.base, mc.path, mode, next(`field|${symId}|${mc.base}|${mc.path.join('.')}|${mode}`)])}`, symbol: symId, base: mc.base, path: mc.path, mode, ...loc(file, line), confidence: OBSERVED });
      };
      const alloc = (expr, line) => {
        const kind = expr.kind === 'object' ? 'object' : expr.kind === 'array' ? 'array' : expr.kind === 'function-value' ? 'function' : null;
        if (!kind) return;
        g.allocations.push({ id: `alloc:${h16(['alloc', symId, kind, next(`alloc|${symId}|${kind}`)])}`, symbol: symId, kind, ...loc(file, line), confidence: OBSERVED });
      };
      for (const c of fn.calls || []) {
        const calleeText = c.callee;
        const direct = byFileName.get(`${file}|${calleeText}`) || null;
        const args = (c.args || []).map((a, index) => { walkExprs(a, (x) => { if (x.kind === 'member') field(x, 'read', c.line); alloc(x, c.line); }); return { index, origin: originFor(a, `arg:${calleeText}:${index}`, c.line) }; });
        g.callSites.push({ id: `call:${h16(['call', symId, calleeText, next(`call|${symId}|${calleeText}`)])}`, caller: symId, calleeText, callee: direct, resolution: direct ? 'resolved' : 'unresolved', args, ...loc(file, c.line), confidence: direct ? { tier: 'inferred', basis: 'a function of this name exists in the same file' } : UNRESOLVED });
      }
      const callFromExpr = (x, line) => {
        const calleeText = exprText(x.callee).replace(/\(\.\.\.\)$/, '');
        const direct = x.callee?.kind === 'ident' ? (byFileName.get(`${file}|${calleeText}`) || null) : null;
        const args = (x.args || []).map((a, index) => ({ index, origin: originFor(a, `arg:${calleeText}:${index}`, line) }));
        g.callSites.push({ id: `call:${h16(['call', symId, calleeText, next(`call|${symId}|${calleeText}`)])}`, caller: symId, calleeText, callee: direct, resolution: direct ? 'resolved' : 'unresolved', args, ...loc(file, line), confidence: direct ? { tier: 'inferred', basis: 'a function of this name exists in the same file' } : UNRESOLVED });
      };
      // The CFG is the one structure every language's IR shares (`writes` exists for JavaScript only): assignment nodes carry { target, source, line }.
      const assigns = Object.values(fn.cfg?.nodes || {}).filter((n) => n.kind === 'assign' && n.target).sort((x, y) => (x.line ?? 0) - (y.line ?? 0) || String(x.id ?? '').localeCompare(String(y.id ?? '')));
      for (const d of assigns) {
        const variable = String(d.target);
        const line = d.line ?? fn.line;
        originFor(d.source, variable, line);
        // calls that appear INSIDE an assignment source (`const cmd = h.build(x)`) are not in fn.calls; they are call sites all the same
        walkExprs(d.source, (x) => { if (x.kind === 'member') field(x, 'read', line); alloc(x, line); if (x.kind === 'call' && x.callee) callFromExpr(x, line); });
        const mc = variable.includes('.') ? variable.split('.') : null;
        if (mc) g.fieldAccesses.push({ id: `field:${h16(['field', symId, mc[0], mc.slice(1), 'write', next(`field|${symId}|${mc[0]}|${mc.slice(1).join('.')}|write`)])}`, symbol: symId, base: mc[0], path: mc.slice(1), mode: 'write', ...loc(file, line), confidence: OBSERVED });
      }
    }
  }

  // E2-07: service relationships are opt-in. A caller that ran dataflow/service-edges.js passes the result as `meta.serviceEdges`; HTTP and
  // messaging relationships become `serviceBoundaries`, persistence relationships become `storageEdges`, and relationships with no counterpart
  // are kept as boundaries with `to: null` and unresolved confidence. Without it both lists stay schema-only, as before.
  const se = meta.serviceEdges && meta.serviceEdges.optedIn ? meta.serviceEdges : null;
  if (se) {
    const tier = (e) => (e === 'observed' ? 'observed' : e === 'inferred' ? 'inferred' : 'unresolved');
    for (const e of se.edges) {
      const list = e.kind === 'persistence' ? g.storageEdges : g.serviceBoundaries;
      list.push({ id: `${e.kind === 'persistence' ? 'store' : 'svc'}:${e.id.slice('svcedge:'.length)}`, kind: e.kind, from: e.from, to: e.to, via: e.via, ...loc(e.from.file, e.from.line), evidence: e.evidence, confidence: { tier: tier(e.evidence), basis: e.basis } });
    }
    for (const u of se.unknown) g.serviceBoundaries.push({ id: `svc:${h16(['unknown', u.service, u.file, u.kind, u.reason])}`, kind: u.kind, from: { service: u.service, file: u.file, line: u.line }, to: null, via: null, ...loc(u.file, u.line), evidence: 'unknown', confidence: { tier: 'unresolved', basis: u.reason } });
  }
  const SCHEMA_ONLY = {
    ...(se ? {} : { serviceBoundaries: 'opt-in: pass meta.serviceEdges (dataflow/service-edges.js) with two or more declared services; the IR itself carries no service-boundary facts', storageEdges: 'opt-in: pass meta.serviceEdges (dataflow/service-edges.js); the IR itself carries no persistence facts' }),
    sanitizers: 'sanitizer decisions are made by the dataflow layer (sanitizer-gate.js), not recorded in the IR; they are folded in by E2-08',
    guards: 'guard dominance is computed by dataflow/guard-dominance.js, not recorded in the IR; it is folded in by E2-08',
  };
  const REASON_POP = { serviceBoundaries: 'HTTP and messaging relationships between declared services, and the ones with no counterpart', storageEdges: 'tables one declared service writes and another reads', symbols: 'one per IR function and per file top level', callSites: 'every call recorded in an IR function, plus calls nested inside assignment sources', allocations: 'object, array and function-valued expressions in call arguments and assignments', fieldAccesses: 'member reads in arguments and assignments, and dotted writes', valueOrigins: 'every call argument and every assignment node in the CFG of a function' };
  const coverage = {};
  for (const k of semantic_graph_ENTITY_LISTS) coverage[k] = SCHEMA_ONLY[k] ? { state: 'schema-only', reason: SCHEMA_ONLY[k] } : g[k].length ? { state: 'populated', reason: REASON_POP[k] } : { state: 'schema-only', reason: `no ${k} in this input` };
  const limits = [
    'columns are null: the IR carries line numbers only',
    'a call resolves only to a same-file function of the same name; imports, re-exports and methods are unresolved until E2-02',
    'heap, alias and closure facts are not in the IR, so field accesses are syntactic, not points-to results',
  ];
  // Dynamic constructs the analysis cannot resolve, per function (E2-03): the graph says where precision was given up, instead of leaving it implicit.
  const dynamicFeatures = analysisLimits(projectIR).map((l) => ({ symbol: symByQid.get(`${l.qid}@${(projectIR.perFile[l.file].functions.find((f) => stripLine(f.qid) === l.qid) || {}).line}`) ?? null, file: l.file, line: l.line, kind: l.kind, detail: l.detail, effect: l.effect }));
  return { schema: semantic_graph_SEMANTIC_GRAPH_SCHEMA, schemaVersion: SEMANTIC_GRAPH_VERSION, producer: { layer: 'ir-v1', engineVersion: meta.engineVersion ?? null }, ...g, coverage, limits, dynamicFeatures };
}

;// CONCATENATED MODULE: ./src/graph/adapters/semantic.js
//
// adapters/semantic.js: read-only view over a SemanticGraph v1
// (ir/semantic-graph.js). Imports only the schema constants and validator; it
// never builds or mutates a graph.
//
// A graph that fails `validateGraph`, or whose major version is not the
// supported one, is REJECTED (INCOMPATIBLE_VERSION / INVALID_GRAPH) rather than
// partially adapted.
//
// Entities: symbol, callSite, allocation, fieldAccess, valueOrigin,
// serviceBoundary, storageEdge, sanitizer, guard (singular names of the
// graph's own lists). The semantic graph stores references as id fields, not
// an edge list, so the relation edges here are DERIVED (origin 'derived') and
// get deterministic ids; the underlying confidence tier becomes the evidence
// grade, and an unresolved call is carried as an `unknowns` entry, never as a
// fabricated callee edge.
//
//   symbol --declaration--> callSite      (the caller declares/contains it)
//   symbol --declaration--> valueOrigin / fieldAccess / allocation
//   callSite --calls--> symbol            (resolved calls only)
//   valueOrigin --data_flow--> callSite   (an argument origin feeds the call)





const SEMANTIC_ADAPTER_VERSION = '1.0.0';

const SINGULAR = {
  symbols: 'symbol', callSites: 'callSite', allocations: 'allocation', fieldAccesses: 'fieldAccess',
  valueOrigins: 'valueOrigin', serviceBoundaries: 'serviceBoundary', storageEdges: 'storageEdge',
  sanitizers: 'sanitizer', guards: 'guard',
};

/**
 * @param {object} graph  SemanticGraph v1 (buildSemanticGraph output)
 * @param {{repository:string}} opts
 */
function semanticView(graph, opts) {
  const m = typeof graph?.schemaVersion === 'string' ? /^(\d+)\./.exec(graph.schemaVersion) : null;
  if (graph?.schema === SEMANTIC_GRAPH_SCHEMA && m && Number(m[1]) !== SUPPORTED_MAJOR) {
    throw new GraphViewError('INCOMPATIBLE_VERSION', `semantic graph major ${m[1]} is not supported (supported: ${SUPPORTED_MAJOR})`, { schemaVersion: graph.schemaVersion });
  }
  const v = validateGraph(graph);
  if (!v.ok) throw new GraphViewError('INVALID_GRAPH', `semantic graph failed validation: ${v.errors[0].code} at ${v.errors[0].path}`, { errors: v.errors.slice(0, 5) });

  const graphDigest = digestOf(graph);
  const nodes = [];
  for (const list of ENTITY_LISTS) {
    for (const e of graph[list]) {
      nodes.push({ entityKind: SINGULAR[list], localId: e.id, native: e, summary: { file: e.file, line: e.line, tier: e.confidence?.tier ?? null } });
    }
  }
  const edges = [];
  const edge = (relation, from, to, grade, extra = {}) => {
    edges.push({
      id: `sgedge:${relation}:${from.localId}:${to.localId}`, relation, origin: 'derived',
      from, to, evidence: { grade, source: 'semantic-graph' }, unknowns: extra.unknowns ?? [], attrs: extra.attrs ?? {}, native: null,
    });
  };
  for (const c of graph.callSites) {
    edge('declaration', local('symbol', c.caller), local('callSite', c.id), c.confidence.tier);
    if (c.callee) edge('calls', local('callSite', c.id), local('symbol', c.callee), c.confidence.tier, { attrs: { resolution: c.resolution } });
    for (const a of c.args || []) {
      if (a.origin) edge('data_flow', local('valueOrigin', a.origin), local('callSite', c.id), c.confidence.tier, { attrs: { argIndex: a.index } });
    }
  }
  for (const o of graph.valueOrigins) if (o.symbol) edge('declaration', local('symbol', o.symbol), local('valueOrigin', o.id), o.confidence.tier);
  for (const f of graph.fieldAccesses) if (f.symbol) edge('declaration', local('symbol', f.symbol), local('fieldAccess', f.id), f.confidence.tier);
  for (const a of graph.allocations) if (a.symbol) edge('declaration', local('symbol', a.symbol), local('allocation', a.id), a.confidence.tier);

  // Unresolved calls are unknowns on the view, not edges.
  const unresolvedCalls = graph.callSites.filter((c) => !c.callee).length;
  const reasons = [];
  const schemaOnly = ENTITY_LISTS.filter((k) => graph.coverage[k].state === 'schema-only');
  if (schemaOnly.length) reasons.push(`schema-only:${schemaOnly.join(',')}`);
  if (unresolvedCalls) reasons.push(`unresolved-calls:${unresolvedCalls}`);
  if ((graph.dynamicFeatures || []).length) reasons.push(`dynamic-features:${graph.dynamicFeatures.length}`);

  return new IndexedGraphView({
    graphKind: 'semantic', adapterVersion: SEMANTIC_ADAPTER_VERSION, repository: opts?.repository, graphDigest,
    metadata: { schema: graph.schema, schemaVersion: graph.schemaVersion, producer: graph.producer ?? null, limits: graph.limits ?? [], unresolvedCalls },
    completion: { status: reasons.length ? 'partial' : 'complete', reasons, coverage: graph.coverage },
    nodes, edges,
    reconstruct: () => graph,
  });
}

;// CONCATENATED MODULE: ./src/graph/adapters/artifact.js
//
// adapters/artifact.js: read-only view over the artifact provenance graph
// (artifact/provenance-graph.js: commit -> build -> OCI digest -> SBOM
// component -> finding, plus an operator-declared deployment).
//
// The artifact graph has no repository identity of its own, so the caller names
// it (`repository`: the image repository or the source repository the artifact
// was built from). The graph digest is a canonical hash of the graph body.
//
// Relations: commit->build, build->digest and digest->deployment are
// `artifact_derivation`; digest->component and component->finding are
// `dependency`. An operator-declared deployment edge has origin `declared`; an
// edge with evidence 'none' (a commit that is not known) is kept, carries an
// `unknowns` entry, and has grade 'none'.
//
// The generator can list the same SBOM component or finding twice (an OS and an
// application package with one purl). Byte-identical duplicates are collapsed
// in the view and counted in metadata; duplicates that DIFFER are rejected,
// because choosing one would be a silent merge. `reconstruct()` returns the
// original graph, duplicates included.




const ARTIFACT_ADAPTER_VERSION = '1.0.0';

function relationFor(fromKind, toKind) {
  if (toKind === 'sbomComponent' || toKind === 'finding') return 'dependency';
  return 'artifact_derivation';
}

function artifactView(graph, opts) {
  if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new TypeError('artifactView requires a graph with nodes[] and edges[]');
  }
  const graphDigest = digestOf(graph);
  const byId = new Map();
  let duplicateNodes = 0;
  for (const n of graph.nodes) {
    const prev = byId.get(n.id);
    if (prev) {
      if (canonicalJson(prev) !== canonicalJson(n)) throw new GraphViewError('DUPLICATE_ID', `artifact graph has two different nodes with id ${n.id}`, { id: n.id });
      duplicateNodes += 1;
    } else byId.set(n.id, n);
  }
  const nodes = [...byId.values()].map((n) => ({ entityKind: n.kind, localId: n.id, native: n, summary: { kind: n.kind } }));
  const seenEdges = new Map();
  let duplicateEdges = 0;
  const edges = [];
  for (const e of graph.edges) {
    const id = `agedge:${e.from}->${e.to}`;
    const prev = seenEdges.get(id);
    if (prev) {
      if (canonicalJson(prev) !== canonicalJson(e)) throw new GraphViewError('DUPLICATE_ID', `artifact graph has two different edges ${e.from} -> ${e.to}`, { id });
      duplicateEdges += 1;
      continue;
    }
    seenEdges.set(id, e);
    const from = byId.get(e.from);
    const to = byId.get(e.to);
    if (!from || !to) throw new GraphViewError('DANGLING_REF', `artifact edge ${e.from} -> ${e.to} points at a node that is not in the graph`, { id });
    const declared = e.evidence === 'operator-declared' || to.kind === 'deployment';
    const none = e.evidence === 'none';
    edges.push({
      id, relation: relationFor(from.kind, to.kind), origin: declared ? 'declared' : 'derived',
      from: local(from.kind, from.id), to: local(to.kind, to.id),
      evidence: { grade: e.evidence ?? 'none', source: 'artifact-provenance-graph' },
      unknowns: none ? [{ kind: 'unlinked', reason: 'no evidence links these two nodes' }] : (e.digestMatches === false ? [{ kind: 'digest-mismatch', reason: 'declared digest differs from the scanned artifact' }] : []),
      attrs: e.digestMatches === undefined ? {} : { digestMatches: e.digestMatches }, native: e,
    });
  }
  const unlinked = edges.filter((e) => e.unknowns.some((u) => u.kind === 'unlinked')).length;
  const reasons = unlinked ? [`unlinked-edges:${unlinked}`] : [];
  return new IndexedGraphView({
    graphKind: 'artifact', adapterVersion: ARTIFACT_ADAPTER_VERSION, repository: opts?.repository, graphDigest,
    metadata: { nodes: graph.nodes.length, edges: graph.edges.length, duplicateNodes, duplicateEdges },
    completion: { status: reasons.length ? 'partial' : 'complete', reasons, coverage: null },
    nodes, edges,
    reconstruct: () => graph,
  });
}

// EXTERNAL MODULE: ./src/lineage/cross-repo-link.js
var cross_repo_link = __webpack_require__(24974);
;// CONCATENATED MODULE: ./src/graph/adapters/crossrepo.js
//
// adapters/crossrepo.js: read-only view over CrossRepoLink records
// (lineage/cross-repo-link.js), plus a small findings view.
//
// A cross-repository link is an operator DECLARATION. In this view it is an
// edge with origin `declared` and evidence grade `declared`, so the default
// query filter (code-derived and derived edges only) never walks it as if it
// were a code-derived data flow, and it can never be mistaken for observed
// telemetry (R06.4). Its endpoints live in OTHER graphs, so they are foreign
// references, each carrying that graph's repository and digest. An endpoint
// that no registered graph can resolve is reported by the registry as
// unresolved, not dropped.
//
// Both endpoints are `dataflow` node references: that is the only graph kind a
// CrossRepoLink record binds today.





const CROSSREPO_ADAPTER_VERSION = '1.0.0';
const FINDINGS_ADAPTER_VERSION = '1.0.0';

/**
 * @param {object[]} links  CrossRepoLink records
 * @param {{localRepository:string}} opts  the repository the `local` side belongs to
 */
function crossRepoLinkView(links, opts) {
  if (!Array.isArray(links)) throw new TypeError('crossRepoLinkView requires an array of links');
  const localRepository = opts?.localRepository;
  const nodes = [];
  const edges = [];
  for (const l of links) {
    const v = validateCrossRepoLink(l);
    if (!v.valid) throw new GraphViewError('INVALID_LINK', `cross-repo link ${l?.id ?? '?'} is invalid: ${v.errors[0].path} ${v.errors[0].message}`, { errors: v.errors });
    nodes.push({ entityKind: 'link', localId: l.id, native: l, summary: { declaredBy: l.declaredBy, declaredAt: l.declaredAt } });
    const from = makeRef({ graphKind: 'dataflow', repository: localRepository, graphDigest: l.local.graphDigest, entityKind: 'node', localId: l.local.nodeId });
    const to = makeRef({ graphKind: 'dataflow', repository: l.remote.repository, graphDigest: l.remote.graphDigest, entityKind: 'node', localId: l.remote.nodeId });
    edges.push({
      id: l.id, relation: 'data_flow', origin: 'declared',
      from: foreign(from), to: foreign(to),
      evidence: { grade: 'declared', source: 'operator', declaredBy: l.declaredBy },
      unknowns: [{ kind: 'not-observed', reason: 'a declared link is an assertion, not an observed data flow' }],
      attrs: { rationale: l.rationale ?? null, provenance: l.provenance }, native: l,
    });
  }
  return new IndexedGraphView({
    graphKind: 'cross-repo-links', adapterVersion: CROSSREPO_ADAPTER_VERSION, repository: localRepository, graphDigest: digestOf(links),
    metadata: { links: links.length },
    completion: { status: 'complete', reasons: [], coverage: null },
    nodes, edges, allowForeign: true,
    reconstruct: () => links,
  });
}

/**
 * Findings as referenceable entities (no edges): the starting point of a
 * finding -> call site -> witnesses -> flow join.
 * @param {object[]} findings scanner findings; localId is `stableId` when present, else `id`
 */
function findingsView(findings, opts) {
  if (!Array.isArray(findings)) throw new TypeError('findingsView requires an array of findings');
  const nodes = findings.map((f) => {
    const id = f.stableId ?? f.id;
    if (typeof id !== 'string' || !id) throw new GraphViewError('BAD_REF', 'every finding needs a stableId or id');
    return { entityKind: 'finding', localId: id, native: f, summary: { file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null, severity: f.severity ?? null } };
  });
  return new IndexedGraphView({
    graphKind: 'findings', adapterVersion: FINDINGS_ADAPTER_VERSION, repository: opts?.repository, graphDigest: digestOf(findings),
    metadata: { findings: findings.length },
    completion: { status: 'unknown', reasons: ['a finding list says nothing about what was not scanned'], coverage: null },
    nodes, edges: [],
    reconstruct: () => findings,
  });
}

;// CONCATENATED MODULE: ./src/graph/registry.js
//
// registry.js: the set of graph views a query may span (DAG-06 R06.6).
//
// What registration rejects, each with a typed GraphViewError:
//   INCOMPATIBLE_VERSION  an adapter whose major version this build cannot read
//   ID_COLLISION          the same (graph kind, repository, digest) registered
//                         twice with different content: a digest names ONE
//                         immutable graph
//   BAD_REF               a malformed view
//
// What lookups reject:
//   DANGLING_REF          the graph is not registered, or the entity is not in it
//   VERSION_INCOMPATIBLE  a reference written by a newer reference format
//   AMBIGUOUS_LOCAL_ID   a bare local id that exists in more than one graph; a
//                         local id is only meaningful inside its graph, so the
//                         registry will not pick one
//
// A reference never resolves across repositories: the repository is part of the
// reference, so `pnode:abc` in repository A and `pnode:abc` in repository B are
// two different entities.








const major = (v) => Number(String(v).split('.')[0]);

/** Adapter majors this build understands, per graph kind. */
const SUPPORTED_ADAPTER_MAJORS = Object.freeze({
  provenance: [major(PROVENANCE_ADAPTER_VERSION)],
  dataflow: [major(DATAFLOW_ADAPTER_VERSION)],
  semantic: [major(SEMANTIC_ADAPTER_VERSION)],
  artifact: [major(ARTIFACT_ADAPTER_VERSION)],
  'cross-repo-links': [major(CROSSREPO_ADAPTER_VERSION)],
  findings: [major(FINDINGS_ADAPTER_VERSION)],
});

function createGraphRegistry() {
  const views = new Map(); // identity key -> view

  function viewFor(ref) {
    const bad = validateRef(ref);
    if (bad) {
      throw new GraphViewError(ref && ref.v !== undefined && ref.v !== REF_VERSION ? 'VERSION_INCOMPATIBLE' : 'BAD_REF', bad, { ref });
    }
    const v = views.get(graphIdentityKey(ref));
    if (!v) throw new GraphViewError('DANGLING_REF', `no registered ${ref.graphKind} graph for repository ${ref.repository} with digest ${ref.graphDigest.slice(0, 12)}`, { ref });
    return v;
  }

  const foreignViews = () => [...views.values()].filter((v) => v._allowForeign);

  return {
    register(view) {
      const kinds = SUPPORTED_ADAPTER_MAJORS[view?.graphKind];
      if (!kinds) throw new GraphViewError('BAD_REF', `unknown graph kind ${view?.graphKind}`);
      if (!kinds.includes(major(view.adapterVersion))) {
        throw new GraphViewError('INCOMPATIBLE_VERSION', `${view.graphKind} adapter ${view.adapterVersion} is not readable by this build (supported majors: ${kinds.join(',')})`);
      }
      const key = graphIdentityKey(view);
      const prev = views.get(key);
      if (prev) {
        if (prev.fingerprint !== view.fingerprint) {
          throw new GraphViewError('ID_COLLISION', `${view.graphKind}/${view.repository} digest ${view.graphDigest.slice(0, 12)} is already registered with different content`, { key });
        }
        return prev;
      }
      views.set(key, view);
      return view;
    },

    views() { return [...views.values()]; },
    viewFor,

    has(ref) {
      const v = views.get(graphIdentityKey(ref));
      return !!v && v.has(ref);
    },

    node(ref) { return viewFor(ref).node(ref); },

    outgoing(ref, filter) {
      const out = viewFor(ref).outgoing(ref, filter);
      for (const fv of foreignViews()) if (fv.graphKind !== ref.graphKind || fv.repository !== ref.repository || fv.graphDigest !== ref.graphDigest) out.push(...fv.outgoing(ref, filter));
      return out;
    },

    incoming(ref, filter) {
      const inn = viewFor(ref).incoming(ref, filter);
      for (const fv of foreignViews()) if (fv.graphKind !== ref.graphKind || fv.repository !== ref.repository || fv.graphDigest !== ref.graphDigest) inn.push(...fv.incoming(ref, filter));
      return inn;
    },

    /** A bare local id is ambiguous when more than one registered graph has it. */
    resolveLocal(entityKind, localId, { graphKind } = {}) {
      const hits = [];
      for (const v of views.values()) {
        if (graphKind && v.graphKind !== graphKind) continue;
        try { hits.push(v.ref(entityKind, localId)); } catch { /* not in this graph */ }
      }
      if (hits.length === 0) throw new GraphViewError('DANGLING_REF', `no ${entityKind} ${localId} in any registered graph`);
      if (hits.length > 1) throw new GraphViewError('AMBIGUOUS_LOCAL_ID', `${entityKind} ${localId} exists in ${hits.length} registered graphs; use a full reference`, { candidates: hits });
      return hits[0];
    },

    /**
     * Classify a foreign endpoint (for example, a cross-repository link end):
     *   resolved             registered, and the entity exists
     *   unresolved           no registered graph with that identity (not an error:
     *                        the remote graph simply is not loaded)
     *   dangling             the graph is registered but the entity is not in it
     *   repository-mismatch  a graph with that digest is registered, but under a
     *                        different repository than the reference claims
     */
    classify(ref) {
      const bad = validateRef(ref);
      if (bad) throw new GraphViewError('BAD_REF', bad, { ref });
      const v = views.get(graphIdentityKey(ref));
      if (v) return v.has(ref) ? 'resolved' : 'dangling';
      for (const o of views.values()) {
        if (o.graphKind === ref.graphKind && o.graphDigest === ref.graphDigest && o.repository !== ref.repository) return 'repository-mismatch';
      }
      return 'unresolved';
    },
  };
}

;// CONCATENATED MODULE: ./src/graph/crosswalk.js
//
// crosswalk.js: evidence-bearing identity mappings between graph layers
// (DAG-06 R06.2, R06.5).
//
// A crosswalk never merges entities. It records "this entity in graph A
// corresponds to these entities in graph B, by this method, with this
// evidence". Every mapping is:
//   - versioned (CROSSWALK_VERSION);
//   - explicit about cardinality (`one-to-one`, `one-to-many`, or `none` with a
//     stated reason), so a projection that coarsens many underlying sites into
//     one projected node says so instead of pretending to be one-to-one;
//   - evidence-bearing: method, grade and basis are required;
//   - checked against the registry when one is supplied: a reference to a graph
//     or entity that is not registered is rejected as DANGLING_REF.
//
// Mapping types and the graph layers each connects:
//   finding-to-callsite   findings        -> semantic     (location join)
//   callsite-to-witness   semantic        -> provenance   (scope + line join)
//   witness-to-flow       provenance      -> dataflow     (data element join)
//   node-to-sites         dataflow node   -> semantic     (a projected node's underlying call sites)
//   identity              same layer      -> same layer   (the same entity under another reference)
//
// `identity` mappings are only legal inside ONE repository. Declaring two
// entities in different repositories "the same" because their local ids match
// is exactly the collision this module exists to prevent, and is rejected as
// CROSS_REPO_ID_COLLISION.




const CROSSWALK_VERSION = '1.0.0';

const MAPPING_TYPES = Object.freeze({
  'finding-to-callsite': { from: { graphKind: 'findings', entityKind: 'finding' }, to: { graphKind: 'semantic', entityKind: 'callSite' } },
  'callsite-to-witness': { from: { graphKind: 'semantic', entityKind: 'callSite' }, to: { graphKind: 'provenance', entityKind: 'pedge' } },
  'witness-to-flow': { from: { graphKind: 'provenance', entityKind: 'pedge' }, to: { graphKind: 'dataflow', entityKind: 'flow' } },
  'node-to-sites': { from: { graphKind: 'dataflow', entityKind: 'node' }, to: { graphKind: 'semantic', entityKind: 'callSite' } },
  identity: { from: null, to: null },
});

const CARDINALITY = (n) => (n === 0 ? 'none' : n === 1 ? 'one-to-one' : 'one-to-many');

function checkEnd(ref, want, label, type) {
  const bad = validateRef(ref);
  if (bad) throw new GraphViewError('BAD_REF', `${type} ${label}: ${bad}`, { ref });
  if (want && (ref.graphKind !== want.graphKind || ref.entityKind !== want.entityKind)) {
    throw new GraphViewError('BAD_MAPPING', `${type} ${label} must be a ${want.graphKind} ${want.entityKind}, got ${ref.graphKind} ${ref.entityKind}`, { ref });
  }
}

function createCrosswalk({ registry = null } = {}) {
  const mappings = new Map();   // id -> record
  const forward = new Map();    // refKey -> record[]
  const reverse = new Map();    // refKey -> record[]
  const push = (m, k, r) => { const a = m.get(k); if (a) a.push(r); else m.set(k, [r]); };

  function add(spec) {
    const type = spec?.type;
    const desc = MAPPING_TYPES[type];
    if (!desc) throw new GraphViewError('BAD_MAPPING', `unknown mapping type ${JSON.stringify(type)}`);
    checkEnd(spec.from, desc.from, 'from', type);
    if (!Array.isArray(spec.to)) throw new GraphViewError('BAD_MAPPING', `${type}: "to" is a list (empty with an unmapped reason when nothing matched)`);
    for (const t of spec.to) checkEnd(t, desc.to, 'to', type);

    const ev = spec.evidence;
    if (!ev || typeof ev.method !== 'string' || !ev.method || typeof ev.grade !== 'string' || !ev.grade || typeof ev.basis !== 'string' || !ev.basis) {
      throw new GraphViewError('BAD_MAPPING', `${type}: evidence needs { method, grade, basis }`);
    }
    const keys = spec.to.map(refKey);
    if (new Set(keys).size !== keys.length) throw new GraphViewError('BAD_MAPPING', `${type}: duplicate targets in one mapping`);
    if (spec.to.length === 0 && !spec.unmapped) throw new GraphViewError('BAD_MAPPING', `${type}: an empty mapping must say why in "unmapped"`);

    if (type === 'identity') {
      for (const t of spec.to) {
        if (t.repository !== spec.from.repository) {
          throw new GraphViewError('CROSS_REPO_ID_COLLISION', `identity mapping between repositories ${spec.from.repository} and ${t.repository} refused: matching local ids do not make two entities the same`, { from: spec.from, to: t });
        }
        if (t.entityKind !== spec.from.entityKind || t.graphKind !== spec.from.graphKind) {
          throw new GraphViewError('BAD_MAPPING', 'identity maps an entity to the same kind of entity');
        }
      }
    }
    if (registry) {
      for (const r of [spec.from, ...spec.to]) {
        if (!registry.has(r)) throw new GraphViewError('DANGLING_REF', `${type}: ${r.graphKind} ${r.entityKind} ${r.localId} (repository ${r.repository}) is not in a registered graph`, { ref: r });
      }
    }

    const id = `xwalk:${createHash('sha256').update(canonicalJson([type, refKey(spec.from), [...keys].sort(), ev.method])).digest('hex').slice(0, 16)}`;
    if (mappings.has(id)) return mappings.get(id);
    const record = Object.freeze({
      id, version: CROSSWALK_VERSION, type, from: spec.from, to: Object.freeze([...spec.to]),
      cardinality: CARDINALITY(spec.to.length),
      coarsens: !!spec.coarsens,
      evidence: Object.freeze({ ...ev }),
      unknowns: Object.freeze([...(spec.unknowns ?? [])]),
      unmapped: spec.unmapped ?? null,
    });
    mappings.set(id, record);
    push(forward, refKey(record.from), record);
    for (const k of keys) push(reverse, k, record);
    return record;
  }

  const ofType = (list, type) => (type ? list.filter((m) => m.type === type) : list);

  return {
    version: CROSSWALK_VERSION,
    add,
    all: () => [...mappings.values()],
    /** Mappings that start at `ref`. */
    from: (ref, type) => ofType(forward.get(refKey(ref)) ?? [], type),
    /** Mappings that end at `ref` (the reverse direction; many sources may share a target). */
    to: (ref, type) => ofType(reverse.get(refKey(ref)) ?? [], type),

    /**
     * Follow a chain of mapping types from `start`. Returns every chain found
     * and, for each step, which references had NO mapping (a gap is reported,
     * never skipped). `evidence` lists every mapping used, so the join is
     * traceable end to end.
     */
    trace(start, types, { maxChains = 1000 } = {}) {
      let chains = [{ refs: [start], mappings: [] }];
      const gaps = [];
      let truncated = false;
      for (const type of types) {
        const next = [];
        for (const c of chains) {
          const last = c.refs[c.refs.length - 1];
          const ms = this.from(last, type);
          if (ms.length === 0) { gaps.push({ type, ref: last }); continue; }
          for (const m of ms) {
            if (m.to.length === 0) { gaps.push({ type, ref: last, unmapped: m.unmapped, mapping: m.id }); continue; }
            for (const t of m.to) {
              if (next.length >= maxChains) { truncated = true; break; }
              next.push({ refs: [...c.refs, t], mappings: [...c.mappings, m.id] });
            }
          }
        }
        chains = next;
      }
      const used = new Set(chains.flatMap((c) => c.mappings));
      return { start, types: [...types], chains, gaps, truncated, evidence: [...used].map((id) => mappings.get(id)) };
    },
  };
}

;// CONCATENATED MODULE: ./src/graph/crosswalk-builders.js
//
// crosswalk-builders.js: build the standard crosswalk mappings from registered
// views. Every builder joins on facts the two graphs both carry and records
// the join as evidence; none invents an identity.
//
//   finding -> semantic call site       file + line (location-exact)
//   call site -> provenance witnesses   enclosing function (qid) + line
//   witness -> projected flow           data element id
//   projected node -> underlying sites  decision kind/category/coverage/externality
//
// Where a join cannot pin one target, the mapping lists ALL candidates
// (one-to-many) and carries an `unknowns` entry. It never picks one silently.



const crosswalk_builders_stripLine = (qid) => String(qid).replace(/@\d+$/, '');
const normFile = (f) => String(f ?? '').replace(/^\.\//, '').replace(/\\/g, '/');

/**
 * Join findings to semantic call sites by exact file and line.
 * @returns {object[]} the mappings added
 */
function mapFindingsToCallSites(crosswalk, findings, semantic) {
  const byLoc = new Map();
  for (const cs of semantic.entities('callSite')) {
    const k = `${normFile(cs.native.file)}:${cs.native.line}`;
    if (!byLoc.has(k)) byLoc.set(k, []);
    byLoc.get(k).push(cs);
  }
  const added = [];
  for (const f of findings.entities('finding')) {
    const { file, line } = f.native;
    if (!Number.isInteger(line) || !file) {
      added.push(crosswalk.add({
        type: 'finding-to-callsite', from: f.ref, to: [], unmapped: 'finding-has-no-file-and-line',
        evidence: { method: 'file-line', grade: 'none', basis: 'the finding carries no integer line, so it cannot be located' },
      }));
      continue;
    }
    const hits = byLoc.get(`${normFile(file)}:${line}`) ?? [];
    if (hits.length === 0) continue; // not a call-site finding; absence is visible as a trace gap
    added.push(crosswalk.add({
      type: 'finding-to-callsite', from: f.ref, to: hits.map((h) => h.ref), coarsens: hits.length > 1,
      evidence: { method: 'file-line', grade: hits.length === 1 ? 'location-exact' : 'location-ambiguous', basis: `${normFile(file)}:${line}` },
      unknowns: hits.length > 1 ? [{ kind: 'ambiguous-location', count: hits.length, reason: 'several call sites share this line; the finding names a line, not a call' }] : [],
    }));
  }
  return added;
}

/**
 * Join semantic call sites to provenance witnesses (pedges): same enclosing
 * function and same line. The provenance scope is `<qid>@<line>`; the semantic
 * symbol carries the qid without the line suffix.
 */
function mapCallSitesToWitnesses(crosswalk, semantic, provenance) {
  const witnessByKey = new Map();
  for (const w of provenance.entities('pedge')) {
    const k = `${crosswalk_builders_stripLine(w.native.scope)}\u0000${w.native.line}`;
    if (!witnessByKey.has(k)) witnessByKey.set(k, []);
    witnessByKey.get(k).push(w);
  }
  const symQid = new Map(semantic.entities('symbol').map((s) => [s.localId, s.native.qid]));
  const sitesPerKey = new Map();
  const keyOf = (cs) => `${symQid.get(cs.native.caller)}\u0000${cs.native.line}`;
  const sites = semantic.entities('callSite');
  for (const cs of sites) sitesPerKey.set(keyOf(cs), (sitesPerKey.get(keyOf(cs)) ?? 0) + 1);
  const added = [];
  for (const cs of sites) {
    const hits = witnessByKey.get(keyOf(cs)) ?? [];
    if (hits.length === 0) continue;
    const shared = sitesPerKey.get(keyOf(cs));
    added.push(crosswalk.add({
      type: 'callsite-to-witness', from: cs.ref, to: hits.map((h) => h.ref), coarsens: hits.length > 1 || shared > 1,
      evidence: { method: 'scope-line', grade: shared > 1 ? 'location-ambiguous' : 'location-exact', basis: `${symQid.get(cs.native.caller)} line ${cs.native.line}` },
      unknowns: shared > 1 ? [{ kind: 'shared-line', callSites: shared, reason: 'provenance records a line, not a call; these witnesses cannot be pinned to one of the call sites on that line' }] : [],
    }));
  }
  return added;
}

/**
 * Join provenance witnesses to the projected flows that carry their data
 * element. A flow aggregates many witnesses (and many sites), so every mapping
 * is flagged `coarsens`.
 */
function mapWitnessesToFlows(crosswalk, provenance, dataflow) {
  const flowsByDe = new Map();
  for (const fl of dataflow.entities('flow')) {
    for (const de of fl.native.dataElementIds || []) {
      if (!flowsByDe.has(de)) flowsByDe.set(de, []);
      flowsByDe.get(de).push(fl);
    }
  }
  const added = [];
  for (const w of provenance.entities('pedge')) {
    const hits = flowsByDe.get(w.native.dataElementId) ?? [];
    if (hits.length === 0) continue;
    added.push(crosswalk.add({
      type: 'witness-to-flow', from: w.ref, to: hits.map((h) => h.ref), coarsens: true,
      evidence: { method: 'data-element', grade: 'identity-shared', basis: w.native.dataElementId },
      unknowns: [{ kind: 'flow-granularity', reason: 'a projected flow aggregates every witness of its data element; the flow does not say which site this witness belongs to' }],
    }));
  }
  return added;
}

const calleeText = (e) => {
  if (!e || typeof e !== 'object') return null;
  if (e.kind === 'ident') return e.name;
  if (e.kind === 'member') { const o = calleeText(e.object); return o ? `${o}.${e.prop ?? '[]'}` : null; }
  return null;
};

/**
 * Map each projected (category-granular) dataflow node to the underlying call
 * sites it stands for. `sites` is the sink-site list `buildDataFlowGraph`
 * returns. A node with several sites maps one-to-many and is flagged `coarsens`;
 * a site that no semantic call site matches is listed under `unknowns`.
 */
function mapProjectedNodesToSites(crosswalk, dataflow, semantic, sites) {
  const callSites = semantic.entities('callSite');
  const added = [];
  for (const n of dataflow.entities('node')) {
    const node = n.native;
    const matching = (sites || []).filter((s) => s.decision
      && s.decision.kind === node.kind
      && (s.decision.category ?? null) === (node.subtype ?? null)
      && s.decision.coverageStatus === node.coverageStatus
      && s.decision.externality === node.externality?.value
      && canonicalJson(s.destination ?? null) === canonicalJson(node.destination ?? null));
    if (matching.length === 0) continue;
    const targets = new Map();
    const unmapped = [];
    for (const s of matching) {
      const atLine = callSites.filter((c) => normFile(c.native.file) === normFile(s.file) && c.native.line === s.line);
      const want = calleeText(s.calleeExpr);
      const exact = want ? atLine.filter((c) => c.native.calleeText === want) : [];
      const picked = exact.length ? exact : atLine;
      if (picked.length === 0) unmapped.push({ file: s.file, line: s.line, reason: 'no semantic call site at this location' });
      for (const c of picked) targets.set(c.localId, c);
    }
    const to = [...targets.values()].map((c) => c.ref);
    const unknowns = unmapped.map((u) => ({ kind: 'unmapped-site', ...u }));
    if (to.length === 0) continue;
    added.push(crosswalk.add({
      type: 'node-to-sites', from: n.ref, to, coarsens: to.length > 1, unknowns,
      evidence: { method: 'decision-match', grade: to.length === 1 ? 'projection-exact' : 'projection-coarse', basis: `${node.kind}/${node.subtype ?? 'none'}: ${matching.length} sink site(s)` },
    }));
  }
  return added;
}

;// CONCATENATED MODULE: ./src/graph/observation.js
//
// observation.js: attributing a runtime observation to the underlying sites of
// a projected node (DAG-06 acceptance: "a projected node with several
// underlying sites cannot falsely assign one runtime observation to every
// site").
//
// A runtime observation is matched to a PROJECTED node (a destination, store or
// queue). When that node stands for several call sites (a `node-to-sites`
// mapping with more than one target), the observation says nothing about which
// site produced it unless it carries its own discriminator. The result is:
//
//   attributed  exactly one site is justified: the node has a single site, or
//               the observation names a site (`file` + `line`, or a call-site
//               id) that matches exactly one candidate.
//   ambiguous   several candidates remain. `attributedTo` is EMPTY, every
//               candidate is listed, and no site receives the observation.
//   unmatched   the observation names a site that is not one of the candidates.
//
// "Observed" is therefore a property of the projected node unless a site is
// positively identified. An observation is never copied onto each site.



/**
 * @param {object} crosswalk
 * @param {object} registry
 * @param {object} nodeRef  ref to the projected dataflow node the observation matched
 * @param {{file?:string, line?:number, callSiteId?:string}} [observation]
 */
function attributeObservation(crosswalk, registry, nodeRef, observation = {}) {
  const mappings = crosswalk.from(nodeRef, 'node-to-sites');
  const candidates = [];
  const seen = new Set();
  for (const m of mappings) for (const t of m.to) if (!seen.has(refKey(t))) { seen.add(refKey(t)); candidates.push(t); }
  const base = { node: nodeRef, candidates, mappings: mappings.map((m) => m.id) };

  if (candidates.length === 0) {
    return { ...base, status: 'unmatched', attributedTo: [], reason: 'the projected node has no recorded underlying sites' };
  }
  const normFile = (f) => String(f ?? '').replace(/^\.\//, '');
  const hasDiscriminator = observation.callSiteId || (observation.file && Number.isInteger(observation.line));
  if (hasDiscriminator) {
    const hit = candidates.filter((c) => {
      if (observation.callSiteId) return c.localId === observation.callSiteId;
      const n = registry.node(c).native;
      return normFile(n.file) === normFile(observation.file) && n.line === observation.line;
    });
    if (hit.length === 1) return { ...base, status: 'attributed', attributedTo: hit, basis: 'observation-names-site' };
    if (hit.length === 0) return { ...base, status: 'unmatched', attributedTo: [], reason: 'the observation names a site that is not one of the node\'s underlying sites' };
    return { ...base, status: 'ambiguous', attributedTo: [], candidates: hit, reason: 'several call sites share the named location' };
  }
  if (candidates.length === 1) return { ...base, status: 'attributed', attributedTo: candidates, basis: 'sole-underlying-site' };
  return {
    ...base, status: 'ambiguous', attributedTo: [],
    reason: `the projected node stands for ${candidates.length} sites and the observation does not say which one produced it`,
  };
}

;// CONCATENATED MODULE: ./src/graph/index.js
// Typed graph views and identity crosswalks (DAG-06). See CLAUDE.md in this directory.














/***/ })

};
