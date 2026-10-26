//
// DAG-06 acceptance: typed graph views and identity crosswalks over the real
// producers' output (vulnerable-js build), not hand-built shapes.
//
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { buildFixture } from './graph-fixture.js';
import {
  makeRef, refKey, parseRef, GraphViewError,
  provenanceView, dataflowView, semanticView, artifactView, crossRepoLinkView, findingsView,
  IndexedGraphView, createGraphRegistry, createCrosswalk,
  mapFindingsToCallSites, mapCallSitesToWitnesses, mapWitnessesToFlows, mapProjectedNodesToSites,
  attributeObservation, adjacencyCacheStats, clearAdjacencyCache, local,
} from '../../src/graph/index.js';
import { computeGraphDigest } from '../../src/lineage/export-json.js';
import { validateGraph as validateDataFlowGraph } from '../../src/lineage/validate.js';
import { validateGraph as validateSemanticGraph, serializeGraph } from '../../src/ir/semantic-graph.js';
import { buildArtifactProvenanceGraph } from '../../src/artifact/provenance-graph.js';

const code = (fn) => { try { fn(); } catch (e) { return e.code ?? `non-view-error:${e.message}`; } return null; };

let fx;
beforeEach(() => { clearAdjacencyCache(); fx = buildFixture(); });

function views(repository = 'repo-a') {
  return {
    prov: provenanceView(fx.store, { repository, completion: fx.built.analysisCompletion }),
    df: dataflowView(fx.graph, { repository }),
    sem: semanticView(fx.semantic, { repository }),
  };
}

// ---- references --------------------------------------------------------------------------------------------------------------

test('a reference round-trips through its string form and rejects blanks and unknown versions', () => {
  const r = makeRef({ graphKind: 'dataflow', repository: 'a|b', graphDigest: 'abc', entityKind: 'node', localId: 'node:x|y' });
  assert.deepEqual(parseRef(refKey(r)), r);
  assert.equal(code(() => makeRef({ graphKind: 'dataflow', repository: '', graphDigest: 'd', entityKind: 'node', localId: 'n' })), 'BAD_REF');
  assert.equal(code(() => makeRef({ graphKind: 'nope', repository: 'r', graphDigest: 'd', entityKind: 'node', localId: 'n' })), 'BAD_REF');
  assert.equal(code(() => refKey({ ...r, v: 2 })), 'BAD_REF');
});

// ---- acceptance 1: finding -> call site -> witnesses -> flow -------------------------------------------------------------

test('a finding joins to its semantic call site, provenance witnesses and projected flow with traceable evidence', () => {
  const { prov, df, sem } = views();
  const findings = findingsView([{ id: 'F-sql', stableId: 'F-sql', file: 'app.js', line: 7, vuln: 'SQL Injection' }], { repository: 'repo-a' });
  const registry = createGraphRegistry();
  for (const v of [prov, df, sem, findings]) registry.register(v);
  const xw = createCrosswalk({ registry });
  mapFindingsToCallSites(xw, findings, sem);
  mapCallSitesToWitnesses(xw, sem, prov);
  mapWitnessesToFlows(xw, prov, df);

  const start = findings.ref('finding', 'F-sql');
  const t = xw.trace(start, ['finding-to-callsite', 'callsite-to-witness', 'witness-to-flow']);
  assert.ok(t.chains.length > 0, 'the finding reaches at least one flow');
  assert.deepEqual(t.gaps, []);
  for (const c of t.chains) {
    assert.equal(c.refs.length, 4);
    assert.deepEqual(c.refs.map((r) => r.entityKind), ['finding', 'callSite', 'pedge', 'flow']);
    assert.equal(c.mappings.length, 3, 'every hop names the mapping that justifies it');
    // each end resolves in its own graph
    for (const r of c.refs) assert.ok(registry.has(r));
  }
  // the call site really is the db.query call on that line, the witness really is on that line
  const cs = registry.node(t.chains[0].refs[1]).native;
  assert.equal(cs.calleeText, 'db.query');
  assert.equal(cs.line, 7);
  assert.equal(registry.node(t.chains[0].refs[2]).native.line, 7);
  // mapping evidence is complete and the coarsening of the flow is declared
  for (const m of t.evidence) {
    assert.ok(m.evidence.method && m.evidence.grade && m.evidence.basis);
    assert.equal(m.version, '1.0.0');
  }
  const toFlow = t.evidence.find((m) => m.type === 'witness-to-flow');
  assert.equal(toFlow.coarsens, true);
  assert.ok(toFlow.unknowns.some((u) => u.kind === 'flow-granularity'));
});

test('a line with no provenance reports a gap instead of an invented join', () => {
  const { prov, df, sem } = views();
  const findings = findingsView([
    { id: 'F-nolines', file: 'app.js' },
    { id: 'F-exec', file: 'app.js', line: 14 }, // res.send and exec share line 14
  ], { repository: 'repo-a' });
  const xw = createCrosswalk();
  mapFindingsToCallSites(xw, findings, sem);
  mapCallSitesToWitnesses(xw, sem, prov);
  mapWitnessesToFlows(xw, prov, df);
  const noLine = xw.from(findings.ref('finding', 'F-nolines'));
  assert.equal(noLine[0].cardinality, 'none');
  assert.equal(noLine[0].unmapped, 'finding-has-no-file-and-line');
  const shared = xw.from(findings.ref('finding', 'F-exec'), 'finding-to-callsite')[0];
  assert.equal(shared.cardinality, 'one-to-many');
  assert.equal(shared.evidence.grade, 'location-ambiguous');
  assert.ok(shared.unknowns.some((u) => u.kind === 'ambiguous-location'));
  // a call site that shares its line with another cannot claim the witness exclusively
  const w = xw.from(shared.to[0], 'callsite-to-witness');
  for (const m of w) assert.ok(m.unknowns.some((u) => u.kind === 'shared-line'));
});

// ---- acceptance 2: same local ids, two repositories --------------------------------------------------------------------

test('two repositories with identical local ids stay distinct', () => {
  const a = views('repo-a');
  // the same graph content under another repository (a fork): same digest, same local ids
  const bProv = provenanceView(fx.store, { repository: 'repo-b' });
  assert.equal(a.prov.graphDigest, bProv.graphDigest);
  const id = a.prov.entities('pnode')[0].localId;
  const refA = a.prov.ref('pnode', id);
  const refB = bProv.ref('pnode', id);
  assert.notEqual(refKey(refA), refKey(refB));

  const registry = createGraphRegistry();
  registry.register(a.prov); registry.register(bProv);
  assert.equal(registry.node(refA).ref.repository, 'repo-a');
  assert.equal(registry.node(refB).ref.repository, 'repo-b');
  // a bare local id is ambiguous, never silently resolved to one repository
  assert.equal(code(() => registry.resolveLocal('pnode', id)), 'AMBIGUOUS_LOCAL_ID');
  // a view refuses the other repository's reference
  assert.equal(code(() => a.prov.node(refB)), 'WRONG_GRAPH');
  // results carry the owning repository, even though the adjacency index is shared
  const e = a.prov.edges()[0];
  const eb = bProv.edges()[0];
  assert.equal(e.id, eb.id);
  assert.equal(e.from.repository, 'repo-a');
  assert.equal(eb.from.repository, 'repo-b');
  // matching local ids never justify an identity mapping across repositories
  const xw = createCrosswalk();
  assert.equal(code(() => xw.add({
    type: 'identity', from: refA, to: [refB],
    evidence: { method: 'same-local-id', grade: 'none', basis: 'ids match' },
  })), 'CROSS_REPO_ID_COLLISION');
});

test('a cross-repository link points at the declared repository, and a mismatched repository is flagged', () => {
  const a = views('repo-a');
  const b = views('repo-b');
  const srcNode = fx.graph.nodes[0].id;
  const dstNode = fx.graph.nodes[1].id;
  const link = {
    id: 'crosslink:t1', version: '1.0.0', provenance: 'manual', relationship: 'data_flow',
    local: { graphId: 'g-a', graphDigest: a.df.graphDigest, nodeId: srcNode },
    remote: { graphId: 'g-b', graphDigest: b.df.graphDigest, nodeId: dstNode, repository: 'repo-b', sourceFile: 'app.js' },
    evidence: { declared: true, observed: false }, rationale: null, declaredBy: 'op', declaredAt: '2026-01-01T00:00:00.000Z',
  };
  const lv = crossRepoLinkView([link], { localRepository: 'repo-a' });
  const registry = createGraphRegistry();
  for (const v of [a.df, b.df, lv]) registry.register(v);
  const from = a.df.ref('node', srcNode);
  // not traversed by default (a declaration is not a code-derived flow)
  assert.deepEqual(registry.outgoing(from, 'data_flow'), []);
  const declared = registry.outgoing(from, { relations: ['data_flow'], origins: ['declared'] });
  assert.equal(declared.length, 1);
  assert.equal(declared[0].origin, 'declared');
  assert.equal(declared[0].evidence.grade, 'declared');
  assert.equal(declared[0].to.repository, 'repo-b');
  assert.equal(declared[0].unknowns[0].kind, 'not-observed');
  assert.equal(registry.classify(declared[0].to), 'resolved');
  // same digest, but registered under another repository: flagged, not trusted
  const wrong = makeRef({ ...declared[0].to, repository: 'repo-c' });
  assert.equal(registry.classify(wrong), 'repository-mismatch');
  // a remote graph that is not loaded is unresolved, not an error
  assert.equal(registry.classify(makeRef({ ...declared[0].to, graphDigest: 'f'.repeat(64) })), 'unresolved');
});

// ---- acceptance 3: coarsened projection and runtime observations -------------------------------------------------------

test('a projected node with several underlying sites never assigns one observation to every site', () => {
  const { df, sem } = views();
  const xw = createCrosswalk();
  mapProjectedNodesToSites(xw, df, sem, fx.sites);
  const registry = createGraphRegistry();
  registry.register(df); registry.register(sem);

  const many = xw.all().filter((m) => m.type === 'node-to-sites' && m.to.length > 1);
  assert.ok(many.length > 0, 'the fixture has projected nodes that stand for several sites');
  const m = many.find((x) => x.to.length >= 3) ?? many[0];
  assert.equal(m.cardinality, 'one-to-many');
  assert.equal(m.coarsens, true);

  const ambiguous = attributeObservation(xw, registry, m.from, {});
  assert.equal(ambiguous.status, 'ambiguous');
  assert.deepEqual(ambiguous.attributedTo, [], 'no site receives the observation');
  assert.equal(ambiguous.candidates.length, m.to.length);

  // naming a site attributes it to exactly that site
  const site = registry.node(m.to[0]).native;
  const named = attributeObservation(xw, registry, m.from, { file: site.file, line: site.line });
  assert.ok(['attributed', 'ambiguous'].includes(named.status));
  if (named.status === 'attributed') assert.equal(named.attributedTo.length, 1);
  else assert.deepEqual(named.attributedTo, []);
  const byId = attributeObservation(xw, registry, m.from, { callSiteId: m.to[1].localId });
  assert.equal(byId.status, 'attributed');
  assert.deepEqual(byId.attributedTo.map((r) => r.localId), [m.to[1].localId]);
  // a site that is not among the candidates is unmatched, not forced onto the node
  assert.equal(attributeObservation(xw, registry, m.from, { callSiteId: 'call:0000000000000000' }).status, 'unmatched');

  // a node with a single site is attributable without a discriminator
  const one = xw.all().find((x) => x.type === 'node-to-sites' && x.to.length === 1);
  if (one) assert.equal(attributeObservation(xw, registry, one.from, {}).status, 'attributed');
});

// ---- acceptance 4: adapter round trips ---------------------------------------------------------------------------------

test('provenance round trip preserves ids, grades, unknowns and digest inputs', () => {
  const { prov } = views();
  const rec = prov.reconstruct();
  assert.deepEqual(rec.nodes, fx.store.nodes());
  assert.deepEqual(rec.edges, fx.store.edges());
  assert.deepEqual(prov.entities('pedge').map((e) => e.localId), fx.store.edges().map((e) => e.id));
  assert.deepEqual(prov.entities('pnode').map((e) => e.localId), fx.store.nodes().map((e) => e.id));
  for (const e of prov.edges()) {
    assert.equal(e.id, e.native.id);
    assert.deepEqual(e.unknowns.filter((u) => u.kind === 'loss').map((u) => u.reason), e.native.lossReasons);
    assert.deepEqual(e.unknowns.filter((u) => u.kind === 'widen').map((u) => u.reason), e.native.widenReasons);
  }
  // an ambiguous or severed witness is graded as such, not as explicit
  const synth = {
    nodes: () => [{ id: 'pnode:a', kind: 'path', scope: 's', path: 'x' }, { id: 'pnode:b', kind: 'escape', scope: 's', path: '<return>' }],
    edges: () => [
      { id: 'pedge:1', fromNodeId: 'pnode:a', toNodeId: 'pnode:b', widenReasons: [], lossReasons: ['context-cap-degraded'], scope: 's', line: 1, dataElementId: 'd', crossScope: false, ambiguousCorrelation: false },
      { id: 'pedge:2', fromNodeId: 'pnode:a', toNodeId: 'pnode:b', widenReasons: [], lossReasons: [], scope: 's', line: 2, dataElementId: 'd', crossScope: false, ambiguousCorrelation: true },
    ],
  };
  const sv = provenanceView(synth, { repository: 'r' });
  const byId = Object.fromEntries(sv.edges().map((e) => [e.id, e]));
  assert.equal(byId['pedge:1'].evidence.grade, 'severed');
  assert.equal(byId['pedge:2'].evidence.grade, 'ambiguous');
  assert.equal(byId['pedge:1'].relation, 'returns');
});

test('provenance completion is never complete when the analysis or the store was cut short', () => {
  const partial = provenanceView(fx.store, { repository: 'r', completion: { status: 'partial', incomplete: [{ qid: 'f' }] } });
  assert.equal(partial.completion().status, 'partial');
  assert.ok(partial.completion().reasons.includes('analysis-partial'));
  assert.equal(provenanceView(fx.store, { repository: 'r' }).completion().status, 'complete');
});

test('dataflow round trip preserves the graph object, its ids, its digest and its evidence', () => {
  const before = JSON.stringify(fx.graph);
  const { df } = views();
  assert.equal(df.reconstruct(), fx.graph);
  assert.equal(JSON.stringify(fx.graph), before, 'the adapter does not touch the source graph');
  assert.equal(df.graphDigest, computeGraphDigest(fx.graph), 'the view digest is the export digest');
  assert.equal(df.metadata().schemaVersion, fx.graph.schemaVersion);
  for (const [kind, section] of [['node', 'nodes'], ['edge', 'edges'], ['flow', 'flows'], ['dataElement', 'dataElements']]) {
    assert.deepEqual(df.entities(kind).map((e) => e.localId), fx.graph[section].map((e) => e.id));
  }
  for (const e of df.edges()) {
    assert.equal(e.origin, 'code');
    assert.equal(e.native, fx.graph.edges.find((x) => x.id === e.id));
  }
  assert.equal(df.completion().status, 'partial', 'scan limitations keep it from reading as complete');
  assert.ok(df.completion().coverage.paths);
});

test('dataflow edges map provenance to origin so runtime and manual edges are not walked as code', () => {
  const g = JSON.parse(JSON.stringify(fx.graph));
  g.edges[0].provenance = 'runtime';
  g.edges[1].provenance = 'manual';
  const v = dataflowView(g, { repository: 'r' });
  const from0 = v.ref('node', g.edges[0].from);
  assert.equal(v.outgoing(from0, 'data_flow').filter((e) => e.id === g.edges[0].id).length, 0);
  assert.equal(v.outgoing(from0, { origins: ['observed'] }).filter((e) => e.id === g.edges[0].id).length, 1);
  const from1 = v.ref('node', g.edges[1].from);
  assert.equal(v.outgoing(from1, { origins: ['declared'] }).filter((e) => e.id === g.edges[1].id).length, 1);
});

test('semantic round trip preserves ids and serialization, and keeps unresolved calls as unknowns', () => {
  const before = serializeGraph(fx.semantic);
  const { sem } = views();
  assert.equal(sem.reconstruct(), fx.semantic);
  assert.equal(serializeGraph(fx.semantic), before);
  assert.deepEqual(sem.entities('callSite').map((e) => e.localId), fx.semantic.callSites.map((c) => c.id));
  assert.deepEqual(sem.entities('symbol').map((e) => e.localId), fx.semantic.symbols.map((c) => c.id));
  const c = sem.completion();
  assert.equal(c.status, 'partial');
  assert.ok(c.reasons.some((r) => r.startsWith('unresolved-calls:')));
  assert.equal(sem.metadata().schemaVersion, fx.semantic.schemaVersion);
  // an unresolved call has a declaring caller but no fabricated callee edge
  const unresolved = fx.semantic.callSites.find((x) => !x.callee);
  const ref = sem.ref('callSite', unresolved.id);
  assert.equal(sem.outgoing(ref, 'calls').length, 0);
  assert.equal(sem.incoming(ref, 'declaration').length, 1);
  assert.equal(sem.incoming(ref, 'declaration')[0].evidence.grade, 'unresolved');
  // a resolved call yields a calls edge carrying the inferred tier
  const resolved = fx.semantic.callSites.find((x) => x.callee);
  if (resolved) assert.equal(sem.outgoing(sem.ref('callSite', resolved.id), 'calls')[0].evidence.grade, 'inferred');
});

test('artifact round trip preserves the graph, ids and evidence; unlinked edges are unknowns', () => {
  const inventory = {
    digest: 'sha256:' + 'a'.repeat(64), digestKind: 'manifest', repoTags: ['x:1'], buildLabels: {},
    osPackages: [{ name: 'libc', version: '1', ecosystem: 'deb', purl: 'pkg:deb/libc@1' }],
    appPackages: [{ name: 'libc', version: '1', ecosystem: 'deb', purl: 'pkg:deb/libc@1' }],
  };
  const graph = buildArtifactProvenanceGraph({
    inventory,
    vulnerabilities: [{ type: 'vulnerable_dep', osvId: 'OSV-1', purl: 'pkg:deb/libc@1', severity: 'high' }],
    deployment: { id: 'prod', environment: 'prod', digest: inventory.digest },
  });
  const av = artifactView(graph, { repository: 'registry/x' });
  assert.equal(av.reconstruct(), graph);
  assert.equal(av.metadata().duplicateNodes, 1, 'the duplicated component is collapsed in the view, not in the source');
  assert.equal(graph.nodes.filter((n) => n.kind === 'sbomComponent').length, 2);
  const digestRef = av.ref('ociDigest', `digest:${inventory.digest}`);
  const out = av.outgoing(digestRef, { relations: ['dependency'] });
  assert.equal(out.length, 1);
  assert.equal(out[0].evidence.grade, 'inventory');
  // deployment is operator-declared: hidden from the default query
  assert.equal(av.outgoing(digestRef, 'artifact_derivation').length, 0);
  const dep = av.outgoing(digestRef, { relations: ['artifact_derivation'], origins: ['declared'] });
  assert.equal(dep.length, 1);
  assert.equal(dep[0].evidence.grade, 'operator-declared');
  // the unknown commit is kept with an unknown, not dropped
  const commit = av.ref('gitCommit', 'commit:unknown');
  const e = av.outgoing(commit, 'artifact_derivation')[0];
  assert.equal(e.evidence.grade, 'none');
  assert.equal(e.unknowns[0].kind, 'unlinked');
  assert.equal(av.completion().status, 'partial');
  // two different nodes under one id are refused
  assert.equal(code(() => artifactView({ nodes: [{ id: 'a', kind: 'build' }, { id: 'a', kind: 'ociDigest' }], edges: [] }, { repository: 'r' })), 'DUPLICATE_ID');
});

// ---- acceptance 5: existing validators and exports unchanged ------------------------------------------------------------

test('building every view leaves the source graphs valid and byte-identical', () => {
  const dfBefore = JSON.stringify(fx.graph);
  const semBefore = serializeGraph(fx.semantic);
  const storeBefore = JSON.stringify([fx.store.nodes(), fx.store.edges()]);
  const digestBefore = computeGraphDigest(fx.graph);
  const { prov, df, sem } = views();
  for (const v of [prov, df, sem]) { v.edges(); v.entities(); v.metadata(); v.completion(); }
  assert.equal(JSON.stringify(fx.graph), dfBefore);
  assert.equal(serializeGraph(fx.semantic), semBefore);
  assert.equal(JSON.stringify([fx.store.nodes(), fx.store.edges()]), storeBefore);
  assert.equal(computeGraphDigest(fx.graph), digestBefore);
  assert.equal(validateDataFlowGraph(fx.graph).valid, true);
  assert.equal(validateSemanticGraph(fx.semantic).ok, true);
});

// ---- R06.3 / R06.4: relation kinds and origins -------------------------------------------------------------------------

test('a query chooses traversable relations; unknown relation or origin names are rejected', () => {
  const { prov } = views();
  const pn = prov.entities('pnode').find((n) => prov.outgoing(prov.ref('pnode', n.localId)).length > 0);
  const ref = prov.ref('pnode', pn.localId);
  const all = prov.outgoing(ref);
  assert.ok(all.length > 0);
  const kinds = new Set(prov.edges().map((e) => e.relation));
  for (const k of kinds) assert.ok(prov.outgoing(ref, k).every((e) => e.relation === k));
  assert.equal(prov.outgoing(ref, 'artifact_derivation').length, 0);
  assert.equal(code(() => prov.outgoing(ref, 'flows')), 'BAD_FILTER');
  assert.equal(code(() => prov.outgoing(ref, { origins: ['trusted'] })), 'BAD_FILTER');
});

// ---- R06.6: rejection and caching --------------------------------------------------------------------------------------

test('dangling references, wrong graphs and incompatible versions are rejected', () => {
  const { df, sem } = views();
  const ghost = makeRef({ graphKind: 'dataflow', repository: 'repo-a', graphDigest: df.graphDigest, entityKind: 'node', localId: 'node:ghost' });
  assert.equal(code(() => df.node(ghost)), 'DANGLING_REF');
  assert.equal(df.has(ghost), false);
  assert.equal(code(() => df.outgoing(ghost)), 'DANGLING_REF');
  assert.equal(code(() => df.node(sem.ref('symbol', fx.semantic.symbols[0].id))), 'WRONG_GRAPH');
  assert.equal(code(() => df.node({ ...ghost, v: 2 })), 'VERSION_INCOMPATIBLE');

  const registry = createGraphRegistry();
  registry.register(df);
  const unregistered = sem.ref('symbol', fx.semantic.symbols[0].id);
  assert.equal(code(() => registry.node(unregistered)), 'DANGLING_REF');

  // crosswalk refuses a mapping that names an entity no registered graph holds
  registry.register(sem);
  const xw = createCrosswalk({ registry });
  assert.equal(code(() => xw.add({
    type: 'node-to-sites', from: ghost, to: [sem.ref('callSite', fx.semantic.callSites[0].id)],
    evidence: { method: 'm', grade: 'g', basis: 'b' },
  })), 'DANGLING_REF');
  // evidence is mandatory
  assert.equal(code(() => xw.add({ type: 'node-to-sites', from: df.ref('node', fx.graph.nodes[0].id), to: [sem.ref('callSite', fx.semantic.callSites[0].id)] })), 'BAD_MAPPING');
  // an empty mapping must say why
  assert.equal(code(() => xw.add({ type: 'node-to-sites', from: df.ref('node', fx.graph.nodes[0].id), to: [], evidence: { method: 'm', grade: 'g', basis: 'b' } })), 'BAD_MAPPING');
  // wrong layer pairing
  assert.equal(code(() => xw.add({ type: 'witness-to-flow', from: df.ref('node', fx.graph.nodes[0].id), to: [df.ref('flow', fx.graph.flows[0].id)], evidence: { method: 'm', grade: 'g', basis: 'b' } })), 'BAD_MAPPING');
});

test('an adapter or schema major this build cannot read is refused', () => {
  const registry = createGraphRegistry();
  const future = new IndexedGraphView({
    graphKind: 'artifact', adapterVersion: '2.0.0', repository: 'r', graphDigest: 'd'.repeat(64),
    nodes: [], edges: [], reconstruct: () => ({}),
  });
  assert.equal(code(() => registry.register(future)), 'INCOMPATIBLE_VERSION');
  const g = JSON.parse(JSON.stringify(fx.semantic));
  g.schemaVersion = '2.0.0';
  assert.equal(code(() => semanticView(g, { repository: 'r' })), 'INCOMPATIBLE_VERSION');
  const broken = JSON.parse(JSON.stringify(fx.semantic));
  broken.callSites[0].caller = 'sym:0000000000000000';
  assert.equal(code(() => semanticView(broken, { repository: 'r' })), 'INVALID_GRAPH');
});

test('one digest naming two different contents is refused at registration and at the shared index', () => {
  const mk = (ids, repository = 'r') => new IndexedGraphView({
    graphKind: 'artifact', adapterVersion: '1.0.0', repository, graphDigest: 'e'.repeat(64),
    nodes: ids.map((i) => ({ entityKind: 'build', localId: i, native: { id: i } })), edges: [], reconstruct: () => ids,
  });
  const registry = createGraphRegistry();
  registry.register(mk(['a', 'b']));
  assert.equal(registry.register(mk(['a', 'b'])).metadata().nodeCount, 2, 'identical re-registration is idempotent');
  assert.equal(code(() => registry.register(mk(['a']))), 'DIGEST_CONFLICT', 'caught by the shared index before it can be served');
  // with a cold index cache the registry itself catches the same identity carrying other content
  const v1 = mk(['a', 'b']);
  clearAdjacencyCache();
  const v2 = mk(['x', 'y']);
  const r2 = createGraphRegistry();
  r2.register(v1);
  assert.equal(code(() => r2.register(v2)), 'ID_COLLISION');
  // duplicate ids inside one graph
  assert.equal(code(() => new IndexedGraphView({
    graphKind: 'artifact', adapterVersion: '1.0.0', repository: 'r', graphDigest: '1',
    nodes: [{ entityKind: 'build', localId: 'a', native: {} }, { entityKind: 'build', localId: 'a', native: {} }], edges: [], reconstruct: () => ({}),
  })), 'DUPLICATE_ID');
  // an edge to an entity the graph does not hold
  assert.equal(code(() => new IndexedGraphView({
    graphKind: 'artifact', adapterVersion: '1.0.0', repository: 'r', graphDigest: '2',
    nodes: [{ entityKind: 'build', localId: 'a', native: {} }],
    edges: [{ id: 'e', relation: 'calls', origin: 'code', from: local('build', 'a'), to: local('build', 'zzz') }], reconstruct: () => ({}),
  })), 'DANGLING_REF');
});

test('adjacency indexes are built once per immutable digest and shared', () => {
  clearAdjacencyCache();
  const a = provenanceView(fx.store, { repository: 'repo-a' });
  assert.equal(adjacencyCacheStats().builds, 1);
  const b = provenanceView(fx.store, { repository: 'repo-b' });
  const again = provenanceView(fx.store, { repository: 'repo-a' });
  assert.equal(adjacencyCacheStats().builds, 1, 'same digest, same adapter version: one build');
  assert.equal(adjacencyCacheStats().hits, 2);
  assert.deepEqual(a.edges().map((e) => e.id), again.edges().map((e) => e.id));
  assert.equal(b.edges()[0].from.repository, 'repo-b');
  // different content builds a new index
  const other = { nodes: () => [{ id: 'pnode:q', kind: 'path', scope: 's', path: 'x' }], edges: () => [] };
  provenanceView(other, { repository: 'repo-a' });
  assert.equal(adjacencyCacheStats().builds, 2);
});
