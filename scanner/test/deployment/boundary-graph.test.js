// X-301: the deployment boundary graph contract. Every criterion is tested in
// both directions: a well-formed graph passes, and each class of malformed or
// misleading graph is refused with a typed error.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BOUNDARY_GRAPH_SCHEMA, EDGE_CONFIDENCE, GAP_CODES, MAX_ATTR_KEYS, NODE_KINDS, TRUST_ZONES, BOUNDARY_TYPES, RELATION_SEMANTICS, RELATIONS, EDGE_EFFECTS, EDGE_COMPLETENESS, EDGE_PROVENANCE, PATH_STATES,
  nodeIdOf, edgeIdOf, normalizeNode, normalizeEdge, buildBoundaryGraph, validateBoundaryGraph, exportBoundaryGraph, importBoundaryGraph,
  boundaryCrossings, indexGraph, findPath, computeGraphDigest,
} from '../../src/lineage/deployment/boundary-graph.js';
import { oneOfEach, src } from './helpers.js';

const REV = 'd'.repeat(40);

function idOf(n) { return nodeIdOf(normalizeNode(n)); }

function edge(relation, from, to, over = {}) {
  const f = normalizeNode(from), t = normalizeNode(to);
  return {
    relation, from: idOf(from), to: idOf(to), environment: f.environment ?? t.environment ?? null, tenant: null, effect: 'none',
    provenance: 'static-config', confidence: 'high', pathState: 'possible', observationInterval: null, completeness: null,
    sourceRevision: REV, source: src(), discriminator: null, crossRepo: null, attrs: {}, ...over,
  };
}

function codes(r) { return r.errors.map(e => e.code); }

const svc = (name, over = {}) => ({ kind: 'service', name, environment: 'prod', trustZone: 'internal', ...over });
const gw = { kind: 'route', name: 'gw:/pay', environment: 'prod', trustZone: 'public' };

// ------------------------------------------------------------------ AC01

test('[X-301.AC01] the graph represents repositories, services, routes, identities, tenants, resources and environments', () => {
  assert.deepEqual([...NODE_KINDS].sort(), ['environment', 'identity', 'repository', 'resource', 'route', 'service', 'tenant']);
  const built = buildBoundaryGraph({ nodes: oneOfEach(), edges: [], sources: [] });
  assert.equal(built.ok, true, JSON.stringify(built.errors));
  assert.deepEqual([...new Set(built.graph.nodes.map(n => n.kind))].sort(), [...NODE_KINDS].sort());
});

test('[X-301.AC01] every relation has explicit semantics: endpoint kinds, a typed trust boundary and a stated meaning', () => {
  for (const rel of RELATIONS) {
    const s = RELATION_SEMANTICS[rel];
    assert.ok(BOUNDARY_TYPES.includes(s.boundary), `${rel} boundary type`);
    assert.ok(s.from.length > 0 && s.to.length > 0, `${rel} endpoints`);
    for (const k of [...s.from, ...s.to]) assert.ok(NODE_KINDS.includes(k), `${rel} references node kind ${k}`);
    assert.ok(typeof s.meaning === 'string' && s.meaning.length > 10, `${rel} meaning`);
  }
  assert.ok(TRUST_ZONES.includes('public') && TRUST_ZONES.includes('tenant-isolated'));
});

test('[X-301.AC01] a node of an unknown kind, an unknown trust zone, or a relation outside the table is refused', () => {
  let b = buildBoundaryGraph({ nodes: [{ kind: 'database', name: 'x' }] });
  assert.equal(b.ok, false);
  assert.ok(codes(b).includes('UNKNOWN_ENUM'));
  b = buildBoundaryGraph({ nodes: [svc('a', { trustZone: 'dmz' })] });
  assert.equal(b.ok, false);
  b = buildBoundaryGraph({ nodes: [svc('a'), svc('b')], edges: [edge('owns', svc('a'), svc('b'))] });
  assert.equal(b.ok, false);
  assert.ok(codes(b).includes('UNKNOWN_ENUM'));
});

test('[X-301.AC01] a relation joining the wrong kinds of node is refused (grants must start at an identity)', () => {
  const ok = buildBoundaryGraph({
    nodes: [{ kind: 'identity', name: 'role', environment: 'prod' }, { kind: 'resource', name: 'db', environment: 'prod' }],
    edges: [edge('grants', { kind: 'identity', name: 'role', environment: 'prod' }, { kind: 'resource', name: 'db', environment: 'prod' }, { effect: 'allow' })],
  });
  assert.equal(ok.ok, true, JSON.stringify(ok.errors));
  const bad = buildBoundaryGraph({
    nodes: [svc('a'), { kind: 'resource', name: 'db', environment: 'prod' }],
    edges: [edge('grants', svc('a'), { kind: 'resource', name: 'db', environment: 'prod' }, { effect: 'allow' })],
  });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some(e => e.code === 'RULE_VIOLATION' && /grants/.test(e.message)));
});

test('[X-301.AC01] an edge cannot join two deployment environments', () => {
  const a = svc('a'), b = svc('b', { environment: 'staging' });
  const r = buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b)] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => /environments/.test(e.message)));
});

test('[X-301.AC01] boundaryCrossings names the trust boundary an edge crosses, and none for a same-zone call', () => {
  const route = gw, a = svc('pay'), b = svc('ledger');
  const idn = { kind: 'identity', name: 'role', environment: 'prod', trustZone: 'internal' };
  const res = { kind: 'resource', name: 'db', environment: 'prod', trustZone: 'internal' };
  const other = svc('other', { tenant: 'globex' });
  const mine = svc('mine', { tenant: 'acme' });
  const g = buildBoundaryGraph({
    nodes: [route, a, b, idn, res, other, mine],
    edges: [edge('routes-to', route, a), edge('calls', a, b), edge('assumes', a, idn), edge('grants', idn, res, { effect: 'allow' }), edge('calls', mine, other, { tenant: null })],
  });
  assert.equal(g.ok, true, JSON.stringify(g.errors));
  const idx = indexGraph(g.graph);
  const cross = (rel, from, to) => boundaryCrossings(g.graph.edges.find(e => e.relation === rel && idx.nodesById.get(e.from).name === from && idx.nodesById.get(e.to).name === to), idx.nodesById).map(c => c.type);
  assert.deepEqual(cross('routes-to', 'gw:/pay', 'pay'), ['network']);
  assert.deepEqual(cross('calls', 'pay', 'ledger'), []);
  assert.deepEqual(cross('assumes', 'pay', 'role'), ['identity']);
  assert.deepEqual(cross('calls', 'mine', 'other'), ['tenant']);
});

// ------------------------------------------------------------------ AC02

test('[X-301.AC02] every edge stores provenance, confidence, environment, observation interval and source revision', () => {
  const a = svc('a'), b = svc('b');
  const r = buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b)] });
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  const e = r.graph.edges[0];
  for (const f of ['provenance', 'confidence', 'environment', 'observationInterval', 'sourceRevision', 'pathState', 'source']) assert.ok(f in e, f);
  assert.equal(e.environment, 'prod');
  assert.equal(e.sourceRevision, REV);
  assert.equal(e.observationInterval, null);
  assert.deepEqual(EDGE_PROVENANCE, ['static-config', 'runtime-observation', 'inferred']);
  assert.deepEqual([...EDGE_CONFIDENCE], ['high', 'medium', 'low']);
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b, { confidence: 'certain' })] }).ok, false);
  assert.deepEqual(PATH_STATES, ['possible', 'blocked', 'unresolved', 'runtime-supported']);
});

test('[X-301.AC02] configured, observed and inferred edges between the same nodes stay three distinguishable edges', () => {
  const a = svc('a'), b = svc('b');
  const observed = edge('calls', a, b, {
    provenance: 'runtime-observation', source: null, sourceRevision: null, pathState: 'runtime-supported', completeness: 'sampled',
    observationInterval: { start: '2026-01-01T00:00:00Z', end: '2026-01-02T00:00:00Z' }, confidence: 'medium',
  });
  const inferred = edge('calls', a, b, { provenance: 'inferred', source: null, sourceRevision: null, confidence: 'low' });
  const r = buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b), observed, inferred] });
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  assert.equal(r.graph.edges.length, 3);
  assert.equal(new Set(r.graph.edges.map(e => e.id)).size, 3);
  assert.deepEqual(r.graph.edges.map(e => e.provenance).sort(), ['inferred', 'runtime-observation', 'static-config']);
  // an inferred edge is never reported as runtime supported
  assert.equal(r.graph.edges.find(e => e.provenance === 'inferred').pathState, 'possible');
});

test('[X-301.AC02] a statically configured edge with no source reference is refused', () => {
  const a = svc('a'), b = svc('b');
  const r = buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b, { source: null })] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.path.endsWith('.source')));
});

test('[X-301.AC02] a runtime edge must state a valid observation interval and cannot claim complete coverage', () => {
  const a = svc('a'), b = svc('b');
  const rt = (over) => edge('calls', a, b, { provenance: 'runtime-observation', source: null, sourceRevision: null, pathState: 'runtime-supported', completeness: 'sampled', observationInterval: { start: '2026-01-01T00:00:00Z', end: '2026-01-02T00:00:00Z' }, ...over });
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [rt({})] }).ok, true);
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [rt({ observationInterval: null })] }).ok, false, 'no interval');
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [rt({ observationInterval: { start: '2026-02-01T00:00:00Z', end: '2026-01-01T00:00:00Z' } })] }).ok, false, 'end before start');
  const complete = buildBoundaryGraph({ nodes: [a, b], edges: [rt({ completeness: 'complete' })] });
  assert.equal(complete.ok, false, 'complete is not expressible');
  assert.ok(complete.errors.some(e => e.code === 'UNKNOWN_ENUM' && /complete/.test(e.message)));
  assert.ok(!EDGE_COMPLETENESS.includes('complete'));
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [rt({ completeness: null })] }).ok, false, 'sampled or unknown must be stated');
});

test('[X-301.AC02] interval, completeness and runtime-supported belong only to runtime edges', () => {
  const a = svc('a'), b = svc('b');
  const iv = { start: '2026-01-01T00:00:00Z', end: '2026-01-02T00:00:00Z' };
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b, { observationInterval: iv })] }).ok, false);
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b, { completeness: 'sampled' })] }).ok, false);
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b, { pathState: 'runtime-supported' })] }).ok, false);
});

test('[X-301.AC02] blocked comes only from an explicit deny, and an explicit deny is always blocked', () => {
  const idn = { kind: 'identity', name: 'role', environment: 'prod' }, res = { kind: 'resource', name: 'db', environment: 'prod' };
  const g = (over) => buildBoundaryGraph({ nodes: [idn, res], edges: [edge('grants', idn, res, over)] });
  assert.equal(g({ effect: 'deny', pathState: 'blocked' }).ok, true);
  assert.equal(g({ effect: 'allow', pathState: 'blocked' }).ok, false, 'blocked without a deny');
  assert.equal(g({ effect: 'deny', pathState: 'possible' }).ok, false, 'deny that is not blocked');
  assert.equal(g({ effect: 'sometimes' }).ok, false);
  assert.ok(EDGE_EFFECTS.includes('deny'));
});

test('[X-301.AC02] a missing field or an unknown field on an edge is refused (closed schema)', () => {
  const a = svc('a'), b = svc('b');
  const built = buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b)] }).graph;
  const dropped = structuredClone(built);
  delete dropped.edges[0].confidence;
  assert.ok(codes(validateBoundaryGraph(dropped)).includes('MISSING_FIELD'));
  const extra = structuredClone(built);
  extra.edges[0].payload = 'x';
  assert.ok(codes(validateBoundaryGraph(extra)).includes('UNKNOWN_FIELD'));
});

test('[X-301.AC02] attribute values outside the metadata grammar, and more attributes than the cap, are refused', () => {
  const a = svc('a'), b = svc('b');
  const r = buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b, { attrs: { note: 'password=hunter2\nsecond line' } })] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.path.includes('attrs')));
  const many = Object.fromEntries(Array.from({ length: MAX_ATTR_KEYS + 1 }, (_, i) => [`k${i}`, 'v']));
  assert.equal(buildBoundaryGraph({ nodes: [a, b], edges: [edge('calls', a, b, { attrs: many })] }).ok, false);
});

test('[X-301.AC03] the graph schema name is part of the contract and every gap code is typed', () => {
  const g = sampleGraph().graph;
  assert.equal(g.schema, BOUNDARY_GRAPH_SCHEMA);
  const wrong = structuredClone(g); wrong.schema = 'agentic-security/other';
  assert.ok(validateBoundaryGraph(wrong).errors.some(e => e.code === 'SCHEMA_MISMATCH'));
  assert.ok(GAP_CODES.includes('identity-collision') && GAP_CODES.includes('version-mismatch') && GAP_CODES.includes('access-denied'));
  const bad = buildBoundaryGraph({ gaps: [{ code: 'made-up', subject: 's', message: 'm' }] });
  assert.equal(bad.ok, false);
});

// ------------------------------------------------------------------ AC03

function sampleGraph(order = 1) {
  const a = svc('a'), b = svc('b'), c = svc('c');
  const edges = [edge('calls', a, b), edge('calls', b, c), edge('depends-on', a, c)];
  const nodes = [a, b, c, { kind: 'environment', name: 'prod' }];
  if (order === -1) { nodes.reverse(); edges.reverse(); }
  return buildBoundaryGraph({ repository: 'r', revision: REV, nodes, edges, sources: [src()] });
}

test('[X-301.AC03] a versioned export round-trips deterministically: import then export gives identical bytes', () => {
  const g = sampleGraph().graph;
  const text = exportBoundaryGraph(g);
  const imp = importBoundaryGraph(text);
  assert.equal(imp.status, 'ok', JSON.stringify(imp.errors));
  assert.equal(exportBoundaryGraph(imp.graph), text);
  assert.equal(imp.graph.schemaVersion, '1.0.0');
  assert.equal(imp.graph.digest, computeGraphDigest(imp.graph));
});

test('[X-301.AC03] ids and the export survive reordering of nodes and edges', () => {
  const a = sampleGraph(1).graph, b = sampleGraph(-1).graph;
  assert.deepEqual(a.nodes.map(n => n.id), b.nodes.map(n => n.id));
  assert.deepEqual(a.edges.map(e => e.id), b.edges.map(e => e.id));
  assert.equal(exportBoundaryGraph(a), exportBoundaryGraph(b));
});

test('[X-301.AC03] the same service name in two environments, or two tenants, is two nodes and two ids', () => {
  const prod = nodeIdOf({ kind: 'service', name: 'api', environment: 'prod', tenant: null });
  const stg = nodeIdOf({ kind: 'service', name: 'api', environment: 'staging', tenant: null });
  const acme = nodeIdOf({ kind: 'service', name: 'api', environment: 'prod', tenant: 'acme' });
  const globex = nodeIdOf({ kind: 'service', name: 'api', environment: 'prod', tenant: 'globex' });
  assert.equal(new Set([prod, stg, acme, globex]).size, 4);
  const r = buildBoundaryGraph({ nodes: [svc('api'), svc('api', { environment: 'staging' }), svc('api', { tenant: 'acme' }), svc('api', { tenant: 'globex' })] });
  assert.equal(r.ok, true);
  assert.equal(r.graph.nodes.length, 4);
  // and identical declarations do merge, so the id is a real identity rather than a counter
  assert.equal(buildBoundaryGraph({ nodes: [svc('api'), svc('api')] }).graph.nodes.length, 1);
});

test('[X-301.AC03] edges between same-named services in different environments or tenants get different ids', () => {
  const mk = (env, tenant) => edgeIdOf(normalizeEdge(edge('calls', svc('a', { environment: env, tenant }), svc('b', { environment: env, tenant }), { environment: env, tenant })));
  assert.equal(new Set([mk('prod', null), mk('staging', null), mk('prod', 'acme')]).size, 3);
});

test('[X-301.AC03] a tampered export is refused: edited content, edited digest, edited id, extra field, or not JSON', () => {
  const text = exportBoundaryGraph(sampleGraph().graph);
  const doc = JSON.parse(text);

  const renamed = structuredClone(doc); renamed.nodes[0].name = 'renamed';
  assert.equal(importBoundaryGraph(JSON.stringify(renamed)).status, 'invalid');

  const digested = structuredClone(doc); digested.digest = `sha256:${'0'.repeat(64)}`;
  assert.ok(importBoundaryGraph(JSON.stringify(digested)).errors.some(e => e.code === 'BAD_DIGEST'));

  const reid = structuredClone(doc); reid.edges[0].id = 'bedge:0000000000000000';
  assert.ok(importBoundaryGraph(JSON.stringify(reid)).errors.some(e => e.code === 'ID_MISMATCH'));

  const extra = structuredClone(doc); extra.apiKey = 'x';
  assert.equal(importBoundaryGraph(JSON.stringify(extra)).status, 'invalid');

  assert.equal(importBoundaryGraph('not json').status, 'malformed');
  assert.equal(importBoundaryGraph(42).status, 'malformed');
  assert.equal(importBoundaryGraph(text, { maxBytes: 100 }).status, 'malformed', 'oversize input is refused');
  const wrongMajor = structuredClone(doc); wrongMajor.schemaVersion = '2.0.0';
  assert.ok(importBoundaryGraph(JSON.stringify(wrongMajor)).errors.some(e => e.code === 'UNSUPPORTED_MAJOR'));
});

test('[X-301.AC03] ids contain no clock or counter: building twice at different times gives the same graph', () => {
  const realNow = Date.now;
  try {
    Date.now = () => 1;
    const a = exportBoundaryGraph(sampleGraph().graph);
    Date.now = () => 9_999_999_999_999;
    const b = exportBoundaryGraph(sampleGraph().graph);
    assert.equal(a, b);
  } finally { Date.now = realNow; }
});

test('[X-301.AC03] findPath is bounded and cycle safe', () => {
  const a = svc('a'), b = svc('b'), c = svc('c');
  const g = buildBoundaryGraph({ nodes: [a, b, c], edges: [edge('calls', a, b), edge('calls', b, a), edge('calls', b, c)] }).graph;
  const idx = indexGraph(g);
  const id = (n) => g.nodes.find(x => x.name === n).id;
  assert.equal(findPath(idx.out, id('a'), id('c')).length, 2);
  assert.equal(findPath(idx.out, id('a'), id('c'), { maxHops: 1 }), null, 'hop limit applies');
  assert.equal(findPath(idx.out, id('c'), id('a')), null);
});
