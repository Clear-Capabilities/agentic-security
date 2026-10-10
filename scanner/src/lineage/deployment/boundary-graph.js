// boundary-graph.js: the deployment boundary graph contract (X-301).
//
// A SEPARATE graph from `DataFlowGraph v1`. That graph answers "where does a
// data element flow"; this one answers "what can reach what, as deployed":
// repositories, services, routes, identities, tenants, resources and
// environments, joined by typed relations that each state which trust
// boundary they cross. It lives in lineage because it is a graph contract, but
// it shares no mutable state with the taint or vulnerability engines. The only
// things imported from elsewhere are pure helpers (the assurance schema kit,
// canonical serialization and content hashing) and three assurance enums, so
// the vocabulary for provenance, path state and observation completeness is
// the one the verification layer already speaks.
//
// Three rules the whole design hangs on:
//
//  1. Static configuration, runtime observation and inference are three
//     different kinds of evidence. `provenance` is one of the assurance
//     BINDING_PROVENANCE values and is part of an edge's identity, so a
//     configured edge and an observed edge between the same two nodes are two
//     edges that stay distinguishable, never merged into one "stronger" edge.
//  2. A path is possible, blocked, unresolved or runtime-supported
//     (assurance PATH_STATES). Blocked comes only from an explicit deny.
//     Unresolved is a first-class answer, carried by unresolved nodes and
//     gaps, never papered over with a guessed edge.
//  3. An old or sampled trace cannot establish complete production coverage.
//     The edge completeness enum here omits `complete` on purpose: this
//     version of the contract has no way to assert it, so no producer can.
//
// Identity: node ids hash (kind, name, environment, tenant), edge ids hash the
// relation, endpoints, environment, tenant, effect, provenance, discriminator
// and cross-repository binding. Order, clocks and source file names never
// enter an id, so ids survive reordering, and two environments or tenants with
// the same service name are two nodes. The owning repository is deliberately
// NOT part of a node id: a caller's reference to "payments in prod" and the
// callee repository's own declaration of it must resolve to the same node, and
// two repositories both claiming one declared identity is an identity
// collision (X-304), which is only detectable if the ids coincide.

import {
  SCHEMA_VERSION, makeCtx, result, guardObject, checkHeader, checkFields, checkEnum, checkDigest, checkString,
  isPlainObject, isNonEmptyString,
} from '../../posture/assurance/schema-kit.js';
import { semanticId, digestOf, canonicalize } from '../../posture/assurance/identity.js';
import { BINDING_PROVENANCE, PATH_STATES, OBSERVATION_COMPLETENESS } from '../../posture/assurance/contracts.js';

export const BOUNDARY_GRAPH_SCHEMA = 'agentic-security/deployment-boundary-graph';
const BOUNDARY_GRAPH_VERSION = SCHEMA_VERSION;

export const NODE_KINDS = Object.freeze(['repository', 'service', 'route', 'identity', 'tenant', 'resource', 'environment']);
export const TRUST_ZONES = Object.freeze(['public', 'edge', 'internal', 'privileged', 'tenant-isolated', 'unknown']);
export const BOUNDARY_TYPES = Object.freeze(['network', 'identity', 'tenant', 'environment', 'repository']);
export const EDGE_EFFECTS = Object.freeze(['allow', 'deny', 'none']);
export const EDGE_CONFIDENCE = Object.freeze(['high', 'medium', 'low']);
// `complete` is deliberately absent: see rule 3 in the header.
export const EDGE_COMPLETENESS = Object.freeze(OBSERVATION_COMPLETENESS.filter(c => c !== 'complete'));
export { BINDING_PROVENANCE as EDGE_PROVENANCE, PATH_STATES };

export const GAP_CODES = Object.freeze([
  'unsupported-syntax', 'unsupported-format', 'malformed-input', 'unresolved-identity', 'conflicting-configuration',
  'identity-collision', 'repository-unavailable', 'access-denied', 'version-mismatch', 'revision-unknown',
  'graph-integrity', 'source-changed', 'source-missing', 'limit-exceeded',
]);

// Explicit edge semantics: which node kinds a relation may join, the trust
// boundary it crosses, and what it means. A relation outside this table is
// refused by the validator.
export const RELATION_SEMANTICS = Object.freeze({
  'defined-in': { from: ['service', 'route', 'identity', 'resource'], to: ['repository'], boundary: 'repository', structural: true, meaning: 'the declaring repository owns this element' },
  'deployed-in': { from: ['service', 'resource', 'route', 'identity'], to: ['environment'], boundary: 'environment', structural: true, meaning: 'the element exists in this deployment environment' },
  'scoped-to': { from: ['service', 'resource', 'identity', 'route'], to: ['tenant'], boundary: 'tenant', structural: true, meaning: 'the element is bound to this tenant' },
  'routes-to': { from: ['route'], to: ['service', 'route'], boundary: 'network', structural: false, meaning: 'a gateway or ingress forwards matching requests to the target' },
  'calls': { from: ['service'], to: ['service', 'route', 'resource'], boundary: 'network', structural: false, meaning: 'the source invokes the target over the network' },
  'depends-on': { from: ['service'], to: ['service', 'resource'], boundary: 'network', structural: false, meaning: 'declared dependency; implies connectivity, not that a call happens' },
  'network-allows': { from: ['service', 'route'], to: ['service', 'resource'], boundary: 'network', structural: false, meaning: 'a network policy or security rule permits traffic from source to target' },
  'network-denies': { from: ['service', 'route'], to: ['service', 'resource'], boundary: 'network', structural: false, meaning: 'a network policy or security rule explicitly refuses traffic from source to target' },
  'assumes': { from: ['service'], to: ['identity'], boundary: 'identity', structural: false, meaning: 'the workload runs as this identity' },
  'grants': { from: ['identity'], to: ['resource'], boundary: 'identity', structural: false, meaning: 'a policy allows or denies the identity actions on the resource' },
});
export const RELATIONS = Object.freeze(Object.keys(RELATION_SEMANTICS));

const NODE_FIELDS = ['id', 'kind', 'name', 'environment', 'tenant', 'repository', 'trustZone', 'resolved', 'unresolvedReason', 'attrs', 'declaredBy'];
const NODE_REQUIRED = NODE_FIELDS;
const EDGE_FIELDS = [
  'id', 'relation', 'from', 'to', 'environment', 'tenant', 'effect', 'provenance', 'confidence', 'pathState',
  'observationInterval', 'completeness', 'sourceRevision', 'source', 'discriminator', 'crossRepo', 'attrs',
];
const EDGE_REQUIRED = EDGE_FIELDS;
const GRAPH_FIELDS = ['schema', 'schemaVersion', 'repository', 'revision', 'nodes', 'edges', 'gaps', 'sources', 'digest'];
const SOURCE_FIELDS = ['file', 'digest', 'parser', 'parserVersion', 'bytes'];
const GAP_FIELDS = ['code', 'subject', 'file', 'message'];

export const MAX_ATTR_KEYS = 16;
const ATTR_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const ATTR_VALUE = /^[A-Za-z0-9_.:\/*,@ +=-]{0,256}$/;
const NAME_RE = /^[^\u0000-\u001f\u007f]{1,256}$/;
const REVISION_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

const NODE_ID_FIELDS = ['kind', 'name', 'environment', 'tenant'];
const EDGE_ID_FIELDS = ['relation', 'from', 'to', 'environment', 'tenant', 'effect', 'provenance', 'discriminator', 'crossRepo'];

function nul(v) { return v === undefined ? null : v; }
function sortedUnique(arr) { return [...new Set(arr)].sort(); }

export function nodeIdOf(node) {
  return semanticId('bnode', { kind: node.kind, name: node.name, environment: nul(node.environment), tenant: nul(node.tenant) }, NODE_ID_FIELDS);
}

export function edgeIdOf(edge) {
  return semanticId('bedge', {
    relation: edge.relation, from: edge.from, to: edge.to, environment: nul(edge.environment), tenant: nul(edge.tenant),
    effect: edge.effect ?? 'none', provenance: edge.provenance, discriminator: nul(edge.discriminator), crossRepo: nul(edge.crossRepo),
  }, EDGE_ID_FIELDS);
}

/** The id of a gap, used to dedupe and order gaps. */
function gapKey(g) { return canonicalize({ code: g.code, subject: g.subject, file: nul(g.file), message: g.message }); }

// ------------------------------------------------------------ normalization

function normalizeAttrs(attrs) {
  if (!isPlainObject(attrs)) return {};
  const out = {};
  for (const k of Object.keys(attrs).sort()) out[k] = attrs[k];
  return out;
}

/** Fill defaults and compute the id. Does not validate. */
export function normalizeNode(n) {
  const kind = n.kind;
  const node = {
    id: '',
    kind,
    name: n.name,
    environment: kind === 'environment' ? n.name : nul(n.environment),
    tenant: kind === 'tenant' ? n.name : nul(n.tenant),
    repository: nul(n.repository),
    trustZone: n.trustZone ?? 'unknown',
    resolved: n.resolved === false ? false : true,
    unresolvedReason: n.resolved === false ? (n.unresolvedReason ?? 'unresolved') : null,
    attrs: normalizeAttrs(n.attrs),
    declaredBy: Array.isArray(n.declaredBy) ? n.declaredBy.map(d => ({ file: d.file, digest: d.digest })).sort(compareRef) : [],
  };
  node.id = nodeIdOf(node);
  return node;
}

function compareRef(a, b) { return a.file < b.file ? -1 : a.file > b.file ? 1 : a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0; }

export function normalizeEdge(e) {
  const edge = {
    id: '',
    relation: e.relation,
    from: e.from,
    to: e.to,
    environment: nul(e.environment),
    tenant: nul(e.tenant),
    effect: e.effect ?? 'none',
    provenance: e.provenance,
    confidence: e.confidence ?? 'medium',
    pathState: e.pathState ?? 'possible',
    observationInterval: e.observationInterval ? { start: e.observationInterval.start, end: e.observationInterval.end } : null,
    completeness: nul(e.completeness),
    sourceRevision: nul(e.sourceRevision),
    source: e.source ? { file: e.source.file, digest: e.source.digest, parser: e.source.parser, parserVersion: e.source.parserVersion } : null,
    discriminator: nul(e.discriminator),
    crossRepo: e.crossRepo ? {
      callerRepository: e.crossRepo.callerRepository, callerRevision: nul(e.crossRepo.callerRevision),
      calleeRepository: e.crossRepo.calleeRepository, calleeRevision: nul(e.crossRepo.calleeRevision),
    } : null,
    attrs: normalizeAttrs(e.attrs),
  };
  edge.id = edgeIdOf(edge);
  return edge;
}

// ------------------------------------------------------------ validation

function checkAttrs(ctx, path, attrs) {
  if (!isPlainObject(attrs)) { ctx.err('BAD_TYPE', path, 'attrs must be an object'); return; }
  const keys = Object.keys(attrs);
  if (keys.length > MAX_ATTR_KEYS) ctx.err('RULE_VIOLATION', path, `attrs may carry at most ${MAX_ATTR_KEYS} keys`);
  for (const k of keys) {
    if (!ATTR_KEY.test(k)) { ctx.err('BAD_TYPE', `${path}.${k}`, 'attribute key is not identifier-shaped'); continue; }
    const v = attrs[k];
    if (typeof v === 'string') { if (!ATTR_VALUE.test(v)) ctx.err('BAD_TYPE', `${path}.${k}`, 'attribute value contains characters outside the metadata grammar'); }
    else if (typeof v === 'number') { if (!Number.isFinite(v)) ctx.err('BAD_TYPE', `${path}.${k}`, 'attribute number must be finite'); }
    else if (typeof v !== 'boolean') ctx.err('BAD_TYPE', `${path}.${k}`, 'attribute value must be a string, number or boolean');
  }
}

function checkRef(ctx, path, ref) {
  if (!isPlainObject(ref)) { ctx.err('BAD_TYPE', path, 'must be an object'); return; }
  for (const k of Object.keys(ref)) if (!SOURCE_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', `${path}.${k}`, 'not part of a source reference');
  checkString(ctx, `${path}.file`, ref.file);
  checkDigest(ctx, `${path}.digest`, ref.digest);
}

function validateNode(ctx, n, i) {
  const p = `nodes[${i}]`;
  if (!isPlainObject(n)) { ctx.err('BAD_TYPE', p, 'node must be an object'); return; }
  for (const k of Object.keys(n)) if (!NODE_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, `field '${k}' is not part of a node`);
  for (const k of NODE_REQUIRED) if (n[k] === undefined) ctx.err('MISSING_FIELD', `${p}.${k}`, `required field '${k}' is missing`);
  const kindOk = checkEnum(ctx, `${p}.kind`, n.kind, NODE_KINDS);
  if (typeof n.name !== 'string' || !NAME_RE.test(n.name)) ctx.err('BAD_TYPE', `${p}.name`, 'name must be 1-256 printable characters');
  checkEnum(ctx, `${p}.trustZone`, n.trustZone, TRUST_ZONES);
  for (const f of ['environment', 'tenant', 'repository']) {
    if (n[f] !== null && n[f] !== undefined && (typeof n[f] !== 'string' || !NAME_RE.test(n[f]))) ctx.err('BAD_TYPE', `${p}.${f}`, `${f} must be null or a printable name`);
  }
  if (typeof n.resolved !== 'boolean') ctx.err('BAD_TYPE', `${p}.resolved`, 'resolved must be a boolean');
  else if (n.resolved === false && !isNonEmptyString(n.unresolvedReason)) ctx.err('RULE_VIOLATION', `${p}.unresolvedReason`, 'an unresolved node must say why');
  else if (n.resolved === true && n.unresolvedReason !== null) ctx.err('RULE_VIOLATION', `${p}.unresolvedReason`, 'a resolved node has no unresolvedReason');
  checkAttrs(ctx, `${p}.attrs`, n.attrs);
  if (!Array.isArray(n.declaredBy)) ctx.err('BAD_TYPE', `${p}.declaredBy`, 'must be an array');
  else n.declaredBy.forEach((d, j) => checkRef(ctx, `${p}.declaredBy[${j}]`, d));
  if (kindOk && n.kind === 'environment' && n.environment !== n.name) ctx.err('RULE_VIOLATION', `${p}.environment`, 'an environment node carries its own name as environment');
  if (kindOk && n.kind === 'tenant' && n.tenant !== n.name) ctx.err('RULE_VIOLATION', `${p}.tenant`, 'a tenant node carries its own name as tenant');
  if (kindOk && typeof n.name === 'string' && typeof n.id === 'string') {
    const expected = nodeIdOf(n);
    if (!n.id.startsWith('bnode:')) ctx.err('BAD_ID', `${p}.id`, "node id must start with 'bnode:'");
    else if (n.id !== expected) ctx.err('ID_MISMATCH', `${p}.id`, `node id does not match its content (expected ${expected})`);
  }
}

function validateEdge(ctx, e, i, nodesById) {
  const p = `edges[${i}]`;
  if (!isPlainObject(e)) { ctx.err('BAD_TYPE', p, 'edge must be an object'); return; }
  for (const k of Object.keys(e)) if (!EDGE_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.${k}`, `field '${k}' is not part of an edge`);
  for (const k of EDGE_REQUIRED) if (e[k] === undefined) ctx.err('MISSING_FIELD', `${p}.${k}`, `required field '${k}' is missing`);
  const relOk = checkEnum(ctx, `${p}.relation`, e.relation, RELATIONS);
  const effOk = checkEnum(ctx, `${p}.effect`, e.effect, EDGE_EFFECTS);
  const provOk = checkEnum(ctx, `${p}.provenance`, e.provenance, BINDING_PROVENANCE);
  checkEnum(ctx, `${p}.confidence`, e.confidence, EDGE_CONFIDENCE);
  const stateOk = checkEnum(ctx, `${p}.pathState`, e.pathState, PATH_STATES);
  for (const f of ['environment', 'tenant', 'discriminator', 'sourceRevision']) {
    if (e[f] !== null && e[f] !== undefined && (typeof e[f] !== 'string' || !NAME_RE.test(e[f]))) ctx.err('BAD_TYPE', `${p}.${f}`, `${f} must be null or a printable string`);
  }
  checkAttrs(ctx, `${p}.attrs`, e.attrs);

  // source reference (X-302.AC03)
  if (e.source !== null && e.source !== undefined) {
    if (!isPlainObject(e.source)) ctx.err('BAD_TYPE', `${p}.source`, 'must be an object or null');
    else {
      for (const k of Object.keys(e.source)) if (!SOURCE_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.source.${k}`, 'not part of a source reference');
      checkString(ctx, `${p}.source.file`, e.source.file);
      checkDigest(ctx, `${p}.source.digest`, e.source.digest);
      checkString(ctx, `${p}.source.parser`, e.source.parser);
      checkString(ctx, `${p}.source.parserVersion`, e.source.parserVersion);
    }
  }
  if (provOk && e.provenance === 'static-config' && !isPlainObject(e.source)) {
    ctx.err('RULE_VIOLATION', `${p}.source`, 'a statically configured edge must reference the exact file or artifact it came from');
  }

  // observation interval and completeness (X-301.AC02, X-303.AC02)
  if (provOk) {
    if (e.provenance === 'runtime-observation') {
      const iv = e.observationInterval;
      if (!isPlainObject(iv) || !ISO.test(iv.start ?? '') || !ISO.test(iv.end ?? '') || !(Date.parse(iv.start) <= Date.parse(iv.end))) {
        ctx.err('RULE_VIOLATION', `${p}.observationInterval`, 'a runtime edge must state a valid observation interval {start <= end}');
      }
      if (e.completeness !== null && !EDGE_COMPLETENESS.includes(e.completeness)) ctx.err('UNKNOWN_ENUM', `${p}.completeness`, `completeness must be one of: ${EDGE_COMPLETENESS.join(', ')} (this contract cannot assert 'complete')`);
      if (e.completeness === null) ctx.err('RULE_VIOLATION', `${p}.completeness`, 'a runtime edge must state whether it is sampled or unknown');
      if (stateOk && !['runtime-supported', 'unresolved'].includes(e.pathState)) ctx.err('RULE_VIOLATION', `${p}.pathState`, `a runtime edge is 'runtime-supported' or 'unresolved', not '${e.pathState}'`);
    } else {
      if (e.observationInterval !== null) ctx.err('RULE_VIOLATION', `${p}.observationInterval`, 'only a runtime edge has an observation interval');
      if (e.completeness !== null) ctx.err('RULE_VIOLATION', `${p}.completeness`, 'only a runtime edge has an observation completeness');
      if (stateOk && e.pathState === 'runtime-supported') ctx.err('RULE_VIOLATION', `${p}.pathState`, "'runtime-supported' requires provenance 'runtime-observation'");
    }
  }
  if (effOk && stateOk) {
    if (e.effect === 'deny' && e.pathState !== 'blocked') ctx.err('RULE_VIOLATION', `${p}.pathState`, "an explicit deny is 'blocked'");
    if (e.pathState === 'blocked' && e.effect !== 'deny') ctx.err('RULE_VIOLATION', `${p}.pathState`, "'blocked' requires an explicit deny; absence of an allow or of an observation never blocks a path");
  }
  if (relOk && effOk) {
    if (e.relation === 'network-denies' && e.effect !== 'deny') ctx.err('RULE_VIOLATION', `${p}.effect`, "'network-denies' has effect 'deny'");
    if (RELATION_SEMANTICS[e.relation].structural && e.effect !== 'none') ctx.err('RULE_VIOLATION', `${p}.effect`, `'${e.relation}' is structural and has no allow/deny effect`);
  }

  // cross-repository binding
  if (e.crossRepo !== null && e.crossRepo !== undefined) {
    if (!isPlainObject(e.crossRepo)) ctx.err('BAD_TYPE', `${p}.crossRepo`, 'must be an object or null');
    else {
      for (const k of Object.keys(e.crossRepo)) if (!['callerRepository', 'callerRevision', 'calleeRepository', 'calleeRevision'].includes(k)) ctx.err('UNKNOWN_FIELD', `${p}.crossRepo.${k}`, 'not part of a cross-repository binding');
      checkString(ctx, `${p}.crossRepo.callerRepository`, e.crossRepo.callerRepository);
      checkString(ctx, `${p}.crossRepo.calleeRepository`, e.crossRepo.calleeRepository);
      for (const f of ['callerRevision', 'calleeRevision']) {
        if (!(typeof e.crossRepo[f] === 'string' && REVISION_RE.test(e.crossRepo[f]))) ctx.err('RULE_VIOLATION', `${p}.crossRepo.${f}`, 'a cross-repository edge binds an exact 40 or 64 hex commit revision');
      }
    }
  }

  // endpoints
  const from = typeof e.from === 'string' ? nodesById.get(e.from) : undefined;
  const to = typeof e.to === 'string' ? nodesById.get(e.to) : undefined;
  if (!from) ctx.err('DANGLING_REF', `${p}.from`, 'from does not reference a node in this graph');
  if (!to) ctx.err('DANGLING_REF', `${p}.to`, 'to does not reference a node in this graph');
  if (from && to && relOk) {
    const sem = RELATION_SEMANTICS[e.relation];
    if (!sem.from.includes(from.kind)) ctx.err('RULE_VIOLATION', `${p}.from`, `'${e.relation}' cannot start at a ${from.kind}`);
    if (!sem.to.includes(to.kind)) ctx.err('RULE_VIOLATION', `${p}.to`, `'${e.relation}' cannot end at a ${to.kind}`);
    // Environments are never merged: a non-structural edge joins nodes of one environment.
    if (!sem.structural) {
      if (from.environment !== null && to.environment !== null && from.environment !== to.environment && !(e.crossRepo)) {
        ctx.err('RULE_VIOLATION', `${p}.environment`, `edge would join environments '${from.environment}' and '${to.environment}'`);
      }
      const envs = sortedUnique([from.environment, to.environment].filter(x => x !== null));
      if (envs.length === 1 && e.environment !== envs[0]) ctx.err('RULE_VIOLATION', `${p}.environment`, `edge environment must be '${envs[0]}' to match its endpoints`);
      if (envs.length === 0 && e.environment !== null) ctx.err('RULE_VIOLATION', `${p}.environment`, 'edge environment is set but neither endpoint has one');
    }
  }
  if (relOk && typeof e.from === 'string' && typeof e.to === 'string' && provOk && effOk) {
    const expected = edgeIdOf(e);
    if (typeof e.id !== 'string' || !e.id.startsWith('bedge:')) ctx.err('BAD_ID', `${p}.id`, "edge id must start with 'bedge:'");
    else if (e.id !== expected) ctx.err('ID_MISMATCH', `${p}.id`, `edge id does not match its content (expected ${expected})`);
  }
}

function graphMaterial(g) {
  return { schema: g.schema, schemaVersion: g.schemaVersion, repository: g.repository, revision: g.revision, nodes: g.nodes, edges: g.edges, gaps: g.gaps, sources: g.sources };
}

export function computeGraphDigest(g) { return digestOf(graphMaterial(g)); }

export function validateBoundaryGraph(g) {
  const gd = guardObject(g);
  const ctx = gd.ctx;
  if (!gd.ok) return result(ctx);
  if (!checkHeader(ctx, g, BOUNDARY_GRAPH_SCHEMA)) return result(ctx);
  for (const k of Object.keys(g)) if (!GRAPH_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', k, `field '${k}' is not part of this schema`);
  for (const k of GRAPH_FIELDS) if (g[k] === undefined) ctx.err('MISSING_FIELD', k, `required field '${k}' is missing`);
  if (g.repository !== null && (typeof g.repository !== 'string' || !NAME_RE.test(g.repository))) ctx.err('BAD_TYPE', 'repository', 'repository must be null or a printable name');
  if (g.revision !== null && !(typeof g.revision === 'string' && REVISION_RE.test(g.revision))) ctx.err('BAD_TYPE', 'revision', 'revision must be null or an exact 40/64 hex commit');
  if (!Array.isArray(g.nodes) || !Array.isArray(g.edges) || !Array.isArray(g.gaps) || !Array.isArray(g.sources)) {
    ctx.err('BAD_TYPE', '', 'nodes, edges, gaps and sources must be arrays');
    return result(ctx);
  }
  const nodesById = new Map();
  g.nodes.forEach((n, i) => {
    validateNode(ctx, n, i);
    if (isPlainObject(n) && typeof n.id === 'string') {
      if (nodesById.has(n.id)) ctx.err('DUPLICATE_ID', `nodes[${i}].id`, `duplicate node id ${n.id}`);
      else nodesById.set(n.id, n);
    }
  });
  const edgeIds = new Set();
  g.edges.forEach((e, i) => {
    validateEdge(ctx, e, i, nodesById);
    if (isPlainObject(e) && typeof e.id === 'string') {
      if (edgeIds.has(e.id)) ctx.err('DUPLICATE_ID', `edges[${i}].id`, `duplicate edge id ${e.id}`);
      edgeIds.add(e.id);
    }
  });
  g.gaps.forEach((gap, i) => {
    if (!isPlainObject(gap)) { ctx.err('BAD_TYPE', `gaps[${i}]`, 'gap must be an object'); return; }
    for (const k of Object.keys(gap)) if (!GAP_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', `gaps[${i}].${k}`, 'not part of a gap');
    checkEnum(ctx, `gaps[${i}].code`, gap.code, GAP_CODES);
    checkString(ctx, `gaps[${i}].subject`, gap.subject);
    checkString(ctx, `gaps[${i}].message`, gap.message);
    if (gap.file !== null && gap.file !== undefined && typeof gap.file !== 'string') ctx.err('BAD_TYPE', `gaps[${i}].file`, 'file must be null or a string');
  });
  g.sources.forEach((s, i) => {
    if (!isPlainObject(s)) { ctx.err('BAD_TYPE', `sources[${i}]`, 'source must be an object'); return; }
    for (const k of Object.keys(s)) if (!SOURCE_FIELDS.includes(k)) ctx.err('UNKNOWN_FIELD', `sources[${i}].${k}`, 'not part of a source');
    checkString(ctx, `sources[${i}].file`, s.file);
    checkDigest(ctx, `sources[${i}].digest`, s.digest);
    checkString(ctx, `sources[${i}].parser`, s.parser);
    checkString(ctx, `sources[${i}].parserVersion`, s.parserVersion);
    if (!Number.isInteger(s.bytes) || s.bytes < 0) ctx.err('BAD_TYPE', `sources[${i}].bytes`, 'bytes must be a non-negative integer');
  });
  if (checkDigest(ctx, 'digest', g.digest) && ctx.errors.length === 0 && g.digest !== computeGraphDigest(g)) {
    ctx.err('BAD_DIGEST', 'digest', 'digest does not match the graph content');
  }
  return result(ctx);
}

// ------------------------------------------------------------ building

function compareById(a, b) { return a.id < b.id ? -1 : a.id > b.id ? 1 : 0; }

function mergeNodes(rawNodes, gaps) {
  const byId = new Map();
  for (const raw of rawNodes) {
    const n = normalizeNode(raw);
    const prev = byId.get(n.id);
    if (!prev) { byId.set(n.id, n); continue; }
    const m = prev;
    m.declaredBy = [...new Map([...m.declaredBy, ...n.declaredBy].map(d => [`${d.file}\n${d.digest}`, d])).values()].sort(compareRef);
    if (m.trustZone !== n.trustZone) {
      if (m.trustZone !== 'unknown' || n.trustZone !== 'unknown') {
        gaps.push({ code: 'conflicting-configuration', subject: m.id, file: null, message: `node '${m.name}' is declared with trust zones '${m.trustZone}' and '${n.trustZone}'; recorded as 'unknown'` });
      }
      m.trustZone = 'unknown';
    }
    if (m.repository !== n.repository) {
      if (m.repository !== null && n.repository !== null) {
        gaps.push({ code: 'identity-collision', subject: m.id, file: null, message: `node '${m.name}' is claimed by repositories '${m.repository}' and '${n.repository}'` });
        m.repository = null; m.resolved = false; m.unresolvedReason = 'identity-collision';
      } else if (m.repository === null) m.repository = n.repository;
    }
    if (m.resolved !== n.resolved) {
      // A resolved declaration wins over an unresolved reference to the same identity.
      if (m.unresolvedReason !== 'identity-collision') { m.resolved = true; m.unresolvedReason = null; }
    }
    for (const k of Object.keys(n.attrs)) {
      if (m.attrs[k] === undefined) m.attrs[k] = n.attrs[k];
      else if (m.attrs[k] !== n.attrs[k]) {
        gaps.push({ code: 'conflicting-configuration', subject: m.id, file: null, message: `node '${m.name}' attribute '${k}' has conflicting values; the attribute is dropped` });
        delete m.attrs[k];
      }
    }
    m.attrs = normalizeAttrs(m.attrs);
  }
  return byId;
}

/**
 * Build a validated graph from loose parts. Never throws. Returns
 * `{ ok, graph, errors }`; on `ok:false` the graph is null and `errors` are
 * typed validator errors, so a bad adapter cannot smuggle an invalid graph out.
 *
 * Normalisation (ids, defaults, ordering, merging of identical declarations) is
 * the only thing done here. Conflicts are recorded as gaps and downgrade the
 * conflicting allow edge to `unresolved`; no edge or node is invented.
 */
export function buildBoundaryGraph({ repository = null, revision = null, nodes = [], edges = [], gaps = [], sources = [] } = {}) {
  const gapList = gaps.map(g => ({ code: g.code, subject: g.subject, file: nul(g.file), message: g.message }));
  const nodeMap = mergeNodes(nodes, gapList);

  const edgeMap = new Map();
  for (const raw of edges) {
    const e = normalizeEdge(raw);
    const prev = edgeMap.get(e.id);
    if (!prev || canonicalize(e) < canonicalize(prev)) edgeMap.set(e.id, e); // deterministic pick among true duplicates
  }
  let edgeList = [...edgeMap.values()];

  // Conflicting allow/deny between the same endpoints and discriminator.
  const groups = new Map();
  for (const e of edgeList) {
    if (e.provenance === 'runtime-observation') continue;
    const k = canonicalize([e.relation, e.from, e.to, e.environment, e.tenant, e.discriminator, e.provenance]);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(e);
  }
  for (const group of groups.values()) {
    const effects = new Set(group.map(e => e.effect));
    if (effects.has('allow') && effects.has('deny')) {
      const sample = group[0];
      gapList.push({ code: 'conflicting-configuration', subject: sample.id, file: sample.source?.file ?? null, message: `'${sample.relation}' is both allowed and denied between the same endpoints; the allow is recorded as unresolved, the deny is kept` });
      for (const e of group) if (e.effect === 'allow') { e.pathState = 'unresolved'; e.confidence = 'low'; }
    }
  }
  // An unresolved endpoint makes a static or inferred path unresolved, never possible.
  for (const e of edgeList) {
    if (e.provenance === 'runtime-observation') continue;
    const f = nodeMap.get(e.from), t = nodeMap.get(e.to);
    if ((f && !f.resolved) || (t && !t.resolved)) {
      if (e.pathState === 'possible') e.pathState = 'unresolved';
    }
  }
  edgeList = edgeList.sort(compareById);

  const uniqueGaps = [...new Map(gapList.map(g => [gapKey(g), g])).values()]
    .sort((a, b) => { const x = gapKey(a), y = gapKey(b); return x < y ? -1 : x > y ? 1 : 0; });
  const uniqueSources = [...new Map(sources.map(s => [`${s.file}\n${s.digest}`, {
    file: s.file, digest: s.digest, parser: s.parser, parserVersion: s.parserVersion, bytes: s.bytes ?? 0,
  }])).values()].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0));

  const graph = {
    schema: BOUNDARY_GRAPH_SCHEMA,
    schemaVersion: BOUNDARY_GRAPH_VERSION,
    repository: nul(repository),
    revision: nul(revision),
    nodes: [...nodeMap.values()].sort(compareById),
    edges: edgeList,
    gaps: uniqueGaps,
    sources: uniqueSources,
    digest: '',
  };
  graph.digest = computeGraphDigest(graph);
  const v = validateBoundaryGraph(graph);
  if (!v.ok) return { ok: false, graph: null, errors: v.errors };
  return { ok: true, graph, errors: [] };
}

// ------------------------------------------------------------ export / import

/** Deterministic text form: canonical key order, no clock, trailing newline. */
export function exportBoundaryGraph(graph) {
  return `${canonicalize(graph)}\n`;
}

const IMPORT_MAX_BYTES = 16 * 1024 * 1024;

/**
 * Parse and validate an exported graph. Returns a typed result, never throws:
 * `{ status: 'ok', graph }`, `{ status: 'malformed' }` for text that is not
 * JSON or is too large, `{ status: 'invalid', errors }` for a graph that parses
 * but fails the contract (including a tampered digest or id).
 */
export function importBoundaryGraph(text, { maxBytes = IMPORT_MAX_BYTES } = {}) {
  if (typeof text !== 'string') return { status: 'malformed', reason: 'input must be text', graph: null, errors: [] };
  if (Buffer.byteLength(text, 'utf8') > maxBytes) return { status: 'malformed', reason: `input is over the ${maxBytes} byte limit`, graph: null, errors: [] };
  let doc;
  try { doc = JSON.parse(text); } catch (e) { return { status: 'malformed', reason: `not valid JSON: ${String(e.message).split('\n')[0]}`, graph: null, errors: [] }; }
  const v = validateBoundaryGraph(doc);
  if (!v.ok) return { status: 'invalid', reason: 'graph failed validation', graph: null, errors: v.errors };
  return { status: 'ok', reason: null, graph: doc, errors: [] };
}

// ------------------------------------------------------------ queries

/** Index a graph for lookups. Pure. */
export function indexGraph(graph) {
  const nodesById = new Map(graph.nodes.map(n => [n.id, n]));
  const out = new Map(), inn = new Map();
  for (const e of graph.edges) {
    if (!out.has(e.from)) out.set(e.from, []);
    out.get(e.from).push(e);
    if (!inn.has(e.to)) inn.set(e.to, []);
    inn.get(e.to).push(e);
  }
  return { nodesById, out, inn };
}

/**
 * Which trust boundaries an edge crosses, from its endpoints and relation.
 * Environment is never crossed (the validator forbids it); tenant and zone
 * crossings come from the endpoints; identity and repository from the relation.
 */
export function boundaryCrossings(edge, nodesById) {
  const from = nodesById.get(edge.from), to = nodesById.get(edge.to);
  const out = [];
  if (!from || !to) return out;
  const sem = RELATION_SEMANTICS[edge.relation];
  if (!sem || sem.structural) return out;
  if (sem.boundary === 'identity') out.push({ type: 'identity', detail: `${from.name} -> ${to.name}` });
  if (from.trustZone !== to.trustZone && (from.trustZone !== 'unknown' || to.trustZone !== 'unknown')) {
    out.push({ type: 'network', detail: `${from.trustZone} -> ${to.trustZone}` });
  }
  if (from.tenant !== null && to.tenant !== null && from.tenant !== to.tenant) out.push({ type: 'tenant', detail: `${from.tenant} -> ${to.tenant}` });
  if (edge.crossRepo) out.push({ type: 'repository', detail: `${edge.crossRepo.callerRepository} -> ${edge.crossRepo.calleeRepository}` });
  return out;
}

/**
 * Shortest path (fewest edges) from one node to another over the edges `accept`
 * allows, as the list of edges, or null. Breadth first with a visited set, so a
 * cycle cannot loop it, and a hop limit, so a large graph cannot make it
 * unbounded. `out` is the `out` map of `indexGraph`.
 */
export function findPath(out, fromId, toId, { accept = () => true, maxHops = 8 } = {}) {
  const queue = [{ id: fromId, path: [] }];
  const seen = new Set([fromId]);
  while (queue.length) {
    const { id, path } = queue.shift();
    if (id === toId && path.length) return path;
    if (path.length >= maxHops) continue;
    for (const e of out.get(id) ?? []) {
      if (seen.has(e.to) || !accept(e)) continue;
      seen.add(e.to);
      queue.push({ id: e.to, path: [...path, e] });
    }
  }
  return null;
}
