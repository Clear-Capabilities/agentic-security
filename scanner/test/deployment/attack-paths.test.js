// X-305: deployment-conditioned attack paths. Each criterion is tested in both directions: the path appears (or is labelled)
// when the evidence is there, and it is removed, qualified or left unlabelled when the evidence is missing or contradicts it.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { computeAttackPaths, analyzeFindingBoundaries, bindFindingToService, assessVerification, exposureReach } from '../../src/lineage/deployment/attack-paths.js';
import { validateBoundaryGraph } from '../../src/lineage/deployment/boundary-graph.js';
import { ingestOne } from './helpers.js';
import { node, edge, graphOf, baseline, FINDING, BINDINGS, recordFor, SRC } from './path-helpers.js';

const OBS = (start, end) => ({ start, end });

function deployed(o) {
  const b = baseline(o);
  return { ...b, graph: graphOf({ nodes: b.nodes, edges: b.edges }) };
}
const paths = (graph, opts) => computeAttackPaths(graph, opts).paths;
const stateOf = (graph) => paths(graph).map((p) => p.state);

describe('[X-305.AC01] queries find exposed-entry-to-privileged-resource paths across trust boundaries', () => {
  test('[X-305.AC01] a real Kubernetes ingress reaches a granted resource through the service, its workload and its identity', () => {
    const g = ingestOne('k8s-payments/manifests.yaml');
    const r = computeAttackPaths(g);
    assert.equal(r.ok, true);
    const p = r.paths.find((x) => x.entry.name.includes('/v1') && x.target.kind === 'resource');
    assert.ok(p, 'the /v1 ingress reaches the granted resource');
    assert.deepEqual(p.hops.map((h) => h.relations[0]), ['routes-to', 'routes-to', 'assumes', 'grants']);
    assert.equal(p.entry.kind, 'route');
    assert.ok(p.crossings.some((c) => c.type === 'identity'), 'the identity transition is listed');
    assert.equal(p.state, 'possible');
    // the unresolved route to a missing Service never produces a path to the resource
    assert.ok(r.paths.every((x) => !x.entry.name.includes('/missing') || x.state !== 'possible'));
  });

  test('[X-305.AC01] an internal-only route is not an entry point, so no exposure path is invented for it', () => {
    const route = node('route', 'svc/orders', { trustZone: 'internal' });
    const api = node('service', 'shop/api');
    const db = node('resource', 'db/x', { trustZone: 'privileged' });
    const g = graphOf({ nodes: [route, api, db], edges: [edge('routes-to', route, api), edge('network-allows', api, db)] });
    const r = computeAttackPaths(g);
    assert.deepEqual(r.entries, []);
    assert.equal(r.paths.length, 0);
    assert.match(r.statement, /not listed has not been shown to exist or to be absent/);
    // flipping the zone makes the same topology an exposure
    const open = node('route', 'svc/orders', { trustZone: 'public' });
    const g2 = graphOf({ nodes: [open, api, db], edges: [edge('routes-to', open, api), edge('network-allows', api, db)] });
    assert.equal(computeAttackPaths(g2).paths.length, 1);
  });

  test('[X-305.AC01] a tenant transition on a hop is a listed boundary crossing and a condition, not a silent edge', () => {
    const route = node('route', 'edge/x', { trustZone: 'public' });
    const a = node('service', 'shop/a', { tenant: 'acme' });
    const b = node('service', 'shop/b', { tenant: 'globex' });
    const db = node('resource', 'db/x', { trustZone: 'privileged' });
    const g = graphOf({ nodes: [route, a, b, db], edges: [edge('routes-to', route, a), edge('calls', a, b), edge('network-allows', b, db)] });
    const p = paths(g)[0];
    assert.ok(p.crossings.some((c) => c.type === 'tenant' && c.detail === 'acme -> globex'));
    assert.equal(p.conditional, true);
    assert.equal(p.conditions[0].kind, 'tenant-binding');
    // the same topology inside one tenant crosses no tenant boundary and carries no condition
    const a2 = node('service', 'shop/a', { tenant: 'acme' });
    const b2 = node('service', 'shop/b', { tenant: 'acme' });
    const g2 = graphOf({ nodes: [route, a2, b2, db], edges: [edge('routes-to', route, a2), edge('calls', a2, b2), edge('network-allows', b2, db)] });
    const q = paths(g2)[0];
    assert.equal(q.crossings.some((c) => c.type === 'tenant'), false);
    assert.equal(q.conditional, false);
  });

  test('[X-305.AC01] the search is bounded and cycle safe, and says when it stopped at a limit', () => {
    const route = node('route', 'edge/x', { trustZone: 'public' });
    const a = node('service', 'shop/a'), b = node('service', 'shop/b');
    const res = [1, 2, 3, 4].map((i) => node('resource', `db/${i}`, { trustZone: 'privileged' }));
    const g = graphOf({ nodes: [route, a, b, ...res], edges: [edge('routes-to', route, a), edge('calls', a, b), edge('calls', b, a), ...res.map((r) => edge('network-allows', b, r))] });
    const all = computeAttackPaths(g);
    assert.equal(all.truncated, false);
    assert.equal(all.paths.length, 4);
    const capped = computeAttackPaths(g, { maxPaths: 2 });
    assert.equal(capped.truncated, true);
    assert.equal(capped.paths.length, 2);
    assert.match(capped.statement, /more may exist/);
    assert.equal(computeAttackPaths(g, { maxHops: 1 }).paths.length, 0, 'a hop limit shortens the search');
  });

  test('[X-305.AC01] an invalid graph is refused rather than queried', () => {
    const { graph } = deployed();
    const tampered = JSON.parse(JSON.stringify(graph));
    tampered.edges[0].effect = 'deny';
    const r = computeAttackPaths(tampered);
    assert.equal(r.ok, false);
    assert.ok(r.errors.length > 0);
  });

  test('[X-305.AC01] a finding is tied to a service only by an explicit binding: longest prefix wins, ambiguity and absence are typed', () => {
    const { graph } = deployed();
    const f = (file) => ({ file });
    assert.equal(bindFindingToService(f('services/api/handler.js'), BINDINGS, graph).status, 'bound');
    assert.equal(bindFindingToService(f('services/other/x.js'), BINDINGS, graph).status, 'unbound');
    assert.equal(bindFindingToService(f('services/api/x.js'), [], graph).status, 'unbound');
    assert.equal(bindFindingToService({}, BINDINGS, graph).status, 'unbound');
    const nested = [{ pathPrefix: 'services/', service: 'shop/ledger' }, { pathPrefix: 'services/api/', service: 'shop/api' }];
    assert.equal(bindFindingToService(f('services/api/x.js'), nested, graph).service.name, 'shop/api');
    const tie = [{ pathPrefix: 'services/api/', service: 'shop/api' }, { pathPrefix: 'services/api/', service: 'shop/ledger' }];
    assert.equal(bindFindingToService(f('services/api/x.js'), tie, graph).status, 'ambiguous');
    assert.equal(bindFindingToService(f('services/api/x.js'), [{ pathPrefix: 'services/api/', service: 'shop/ghost' }], graph).status, 'service-not-in-graph');
    assert.equal(bindFindingToService(f('services/api/x.js'), [{ pathPrefix: '../etc/', service: 'shop/api' }], graph).status, 'unbound');
    assert.equal(bindFindingToService(f('services/apix/x.js'), [{ pathPrefix: 'services/api', service: 'shop/api' }], graph).status, 'unbound', 'a prefix matches whole path segments');
  });

  test('[X-305.AC01] a finding gets exposure paths to its service and impact paths onward to privileged resources', () => {
    const { graph } = deployed();
    const r = analyzeFindingBoundaries({ graph, finding: FINDING, bindings: BINDINGS });
    assert.equal(r.ok, true);
    const ctx = r.context;
    assert.equal(ctx.binding.status, 'bound');
    assert.equal(ctx.exposure.state, 'possible');
    assert.deepEqual([...new Set(ctx.paths.map((p) => p.kind))].sort(), ['exposure', 'impact']);
    const impact = ctx.paths.find((p) => p.kind === 'impact');
    assert.equal(impact.target.name, 'db/ledger');
    // an unbound finding is not assessed and carries no path
    const un = analyzeFindingBoundaries({ graph, finding: { ...FINDING, file: 'tools/x.js' }, bindings: BINDINGS }).context;
    assert.equal(un.exposure.state, 'not-assessed');
    assert.equal(un.paths.length, 0);
    assert.ok(un.uncovered.some((u) => u.type === 'binding'));
  });
});

describe('[X-305.AC02] every path lists edges, assumptions, blockers and environment; nothing is exploitable without a trusted oracle', () => {
  test('[X-305.AC02] a path names its supporting edges (all in the graph), assumptions, blockers and environment', () => {
    const { graph } = deployed();
    const p = paths(graph)[0];
    const ids = new Set(graph.edges.map((e) => e.id));
    assert.ok(p.supportingEdgeIds.length >= 3);
    for (const id of p.supportingEdgeIds) assert.ok(ids.has(id));
    assert.deepEqual(p.hops.flatMap((h) => h.edges.map((e) => e.id)).sort(), [...p.supportingEdgeIds]);
    assert.ok(p.assumptions.length >= 2);
    assert.ok(p.assumptions.some((a) => /not (?:been )?exercised|none of them shows/.test(a)));
    assert.deepEqual(p.blockers, []);
    assert.deepEqual(p.environments, ['prod']);
    assert.equal(p.hops.every((h) => h.edges.every((e) => e.provenance === 'static-config')), true);
  });

  test('[X-305.AC02] the same path keeps one id when the graph is rebuilt in another order', () => {
    const b = baseline();
    const g1 = graphOf({ nodes: b.nodes, edges: b.edges });
    const g2 = graphOf({ nodes: [...b.nodes].reverse(), edges: [...b.edges].reverse() });
    assert.deepEqual(paths(g1).map((p) => p.id), paths(g2).map((p) => p.id));
  });

  test('[X-305.AC02] with no verification record a path is not labelled exploitable, however reachable it is', () => {
    const { graph } = deployed();
    const ctx = analyzeFindingBoundaries({ graph, finding: FINDING, bindings: BINDINGS }).context;
    assert.ok(ctx.paths.length > 0);
    for (const p of ctx.paths) {
      assert.equal(p.exploitability.label, 'not-established');
      assert.match(p.exploitability.reason, /reachability alone does not show exploitability/);
    }
  });

  test('[X-305.AC02] a trusted runtime-confirmed record for the same hypothesis labels a reachable path exploitable-confirmed', () => {
    const { graph } = deployed();
    const rec = recordFor('trusted');
    const ctx = analyzeFindingBoundaries({ graph, finding: FINDING, bindings: BINDINGS, records: [rec] }).context;
    assert.ok(ctx.paths.every((p) => p.exploitability.label === 'exploitable-confirmed' && p.exploitability.recordId === rec.id));
    assert.equal(ctx.verification[0].applicable, true);
    assert.equal(ctx.verification[0].recordId, rec.id, 'the context shares the verification record id');
  });

  test('[X-305.AC02] model agreement, a refutation, a record for another hypothesis or an edited record never satisfy the oracle rule', () => {
    const { graph } = deployed();
    const label = (records) => analyzeFindingBoundaries({ graph, finding: FINDING, bindings: BINDINGS, records }).context.paths.map((p) => p.exploitability.label);
    const model = recordFor('model');
    assert.deepEqual([...new Set(label([model, model, model]))], ['not-established'], 'repeated model agreement is still inference');
    assert.deepEqual([...new Set(label([recordFor('refuted')]))], ['not-established']);
    assert.deepEqual(analyzeFindingBoundaries({ graph, finding: FINDING, bindings: BINDINGS, records: [recordFor('trusted', { hypothesisId: 'someone-else' })] }).context.verification, [], 'a record for another hypothesis is not even listed');
    const human = recordFor('adjudicated');
    assert.equal(assessVerification(FINDING, [human])[0].applicable, false);
    assert.match(assessVerification(FINDING, [human])[0].reasons[0], /no trusted runtime proof/);
    assert.deepEqual([...new Set(label([human]))], ['not-established'], 'a valid human adjudication is not a trusted oracle replay');
    const edited = { ...recordFor('trusted'), reason: 'edited after its id was computed' };
    const a = assessVerification(FINDING, [edited]);
    assert.equal(a[0].applicable, false);
    assert.match(a[0].reasons[0], /failed validation/);
    assert.deepEqual([...new Set(label([edited]))], ['not-established']);
  });

  test('[X-305.AC02] the oracle must be the one the finding class names, and an unsupported class has none', () => {
    const tenant = { ...FINDING, stableId: 'stable-tenant', cwe: 'CWE-639', family: 'idor' };
    const wrong = assessVerification(tenant, [recordFor('trusted', { hypothesisId: 'stable-tenant' })]);
    assert.equal(wrong[0].applicable, false);
    assert.match(wrong[0].reasons[0], /authorization-decision/);
    const right = assessVerification(tenant, [recordFor('trusted', { hypothesisId: 'stable-tenant', oracleId: 'authorization-decision' })]);
    assert.equal(right[0].applicable, true);
    const csrf = { ...FINDING, stableId: 'stable-csrf', cwe: 'CWE-352', family: 'csrf' };
    const none = assessVerification(csrf, [recordFor('trusted', { hypothesisId: 'stable-csrf' })]);
    assert.equal(none[0].applicable, false);
    assert.match(none[0].reasons.join(' '), /no supported oracle/);
  });

  test('[X-305.AC02] a confirmed oracle result never overrides the deployment: a blocked or unresolved path keeps that state in its label', () => {
    const rec = recordFor('trusted');
    const b = baseline();
    const g = graphOf({ nodes: b.nodes, edges: [...b.edges, edge('network-denies', b.api, b.ledger, { effect: 'deny' })] });
    const ctx = analyzeFindingBoundaries({ graph: g, finding: FINDING, bindings: BINDINGS, records: [rec] }).context;
    const impact = ctx.paths.find((p) => p.kind === 'impact');
    assert.equal(impact.state, 'blocked');
    assert.equal(impact.exploitability.label, 'oracle-confirmed-path-blocked');
    assert.ok(ctx.paths.filter((p) => p.kind === 'exposure').every((p) => p.exploitability.label === 'exploitable-confirmed'));
    const route = node('route', 'edge/x', { trustZone: 'public' });
    const api = node('service', 'shop/api', { tenant: 'acme' });
    const other = node('service', 'shop/other', { tenant: 'globex' });
    const g2 = graphOf({ nodes: [route, api, other], edges: [edge('routes-to', route, other), edge('calls', other, api)] });
    const ctx2 = analyzeFindingBoundaries({ graph: g2, finding: FINDING, bindings: BINDINGS, records: [rec] }).context;
    assert.ok(ctx2.paths.length > 0 && ctx2.paths.every((p) => p.exploitability.label === 'oracle-confirmed-path-unresolved'));
  });

  test('[X-305.AC02] an old or sampled trace is reported as such and never as complete coverage', () => {
    const b = baseline();
    const seen = { provenance: 'runtime-observation', pathState: 'runtime-supported', observationInterval: OBS('2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'), completeness: 'sampled' };
    const g = graphOf({ nodes: b.nodes, edges: [...b.edges, edge('routes-to', b.route, b.api, seen), edge('calls', b.api, b.ledger, seen)] });
    const p = paths(g, { now: '2026-10-09T00:00:00Z' })[0];
    assert.equal(p.state, 'runtime-supported');
    assert.equal(p.coverage.trafficCoverage, 'not-established');
    assert.deepEqual(p.coverage.sampledHops, [0, 1]);
    assert.deepEqual(p.coverage.staleHops, [0, 1], 'a trace older than the window is stale');
    assert.deepEqual(p.coverage.unobservedHops, []);
    assert.deepEqual(p.provenance.sort(), ['runtime-observation', 'static-config']);
    const fresh = paths(g, { now: '2026-01-03T00:00:00Z' })[0];
    assert.deepEqual(fresh.coverage.staleHops, [], 'inside the window the same trace is not stale');
    assert.equal(fresh.coverage.trafficCoverage, 'not-established');
    const noClock = paths(g)[0];
    assert.equal(noClock.coverage.staleEvaluated, false, 'without a clock staleness is not claimed either way');
    // observing only some network hops leaves the path merely possible, with the rest listed as unobserved
    const part = graphOf({ nodes: b.nodes, edges: [...b.edges, edge('routes-to', b.route, b.api, seen)] });
    const q = paths(part)[0];
    assert.equal(q.state, 'possible');
    assert.deepEqual(q.coverage.unobservedHops, [1]);
  });
});

describe('[X-305.AC03] network isolation, a denied IAM permission and tenant binding each remove or qualify the path', () => {
  test('[X-305.AC03] without the control the baseline path is possible', () => {
    assert.deepEqual(stateOf(deployed().graph), ['possible']);
  });

  test('[X-305.AC03] an explicit network deny blocks the hop and names the denying edge as the blocker', () => {
    const b = baseline();
    const deny = edge('network-denies', b.api, b.ledger, { effect: 'deny', source: SRC('netpol.yaml') });
    const g = graphOf({ nodes: b.nodes, edges: [...b.edges, deny] });
    const p = paths(g)[0];
    assert.equal(p.state, 'blocked');
    assert.equal(p.blockers.length, 1);
    assert.equal(p.blockers[0].relation, 'network-denies');
    assert.equal(p.blockers[0].source.file, 'netpol.yaml');
    assert.ok(g.edges.some((e) => e.id === p.blockers[0].edgeId));
  });

  test('[X-305.AC03] a denied IAM permission blocks the grant hop even when an allow sits beside it', () => {
    const b = baseline();
    const g = graphOf({ nodes: b.nodes, edges: [...b.edges, edge('grants', b.ident, b.db, { effect: 'deny' })] });
    assert.ok(g.gaps.some((x) => x.code === 'conflicting-configuration'), 'the conflict is recorded as a gap');
    const p = paths(g)[0];
    assert.equal(p.state, 'blocked');
    assert.equal(p.blockers[0].relation, 'grants');
    assert.equal(p.hops[3].state, 'blocked');
  });

  test('[X-305.AC03] a deny elsewhere in the graph does not block an unrelated path', () => {
    const b = baseline();
    const spare = node('service', 'shop/spare');
    const g = graphOf({ nodes: [...b.nodes, spare], edges: [...b.edges, edge('network-denies', spare, b.ledger, { effect: 'deny' })] });
    assert.deepEqual(stateOf(g), ['possible']);
  });

  test('[X-305.AC03] a tenant binding that differs across a hop qualifies the path as conditional; the same tenant does not', () => {
    const route = node('route', 'edge/x', { trustZone: 'public' });
    const a = node('service', 'shop/a', { tenant: 'acme' });
    const bT = node('service', 'shop/b', { tenant: 'globex' });
    const db = node('resource', 'db/x', { trustZone: 'privileged' });
    const mk = (b2) => graphOf({ nodes: [route, a, b2, db], edges: [edge('routes-to', route, a), edge('calls', a, b2), edge('network-allows', b2, db)] });
    const crossed = paths(mk(bT))[0];
    assert.equal(crossed.state, 'unresolved');
    assert.equal(crossed.conditional, true);
    assert.match(crossed.conditions[0].detail, /no tenant binding is enforced/);
    const same = paths(mk(node('service', 'shop/b', { tenant: 'acme' })))[0];
    assert.equal(same.state, 'possible');
    assert.equal(same.conditional, false);
  });

  test('[X-305.AC03] an unresolved endpoint qualifies a path, and an unresolved path never reads as possible', () => {
    const b = baseline();
    const ghost = node('identity', 'sa/ghost', { resolved: false });
    const g = graphOf({
      nodes: [b.route, b.api, b.ledger, ghost, b.db],
      edges: [edge('routes-to', b.route, b.api), edge('calls', b.api, b.ledger), edge('assumes', b.ledger, ghost), edge('grants', ghost, b.db, { effect: 'allow' })],
    });
    const p = paths(g)[0];
    assert.equal(p.state, 'unresolved');
    assert.ok(p.conditions.some((c) => c.kind === 'unresolved-node'));
  });

  test('[X-305.AC03] exposure reach respects the same controls: a denied hop is not reached', () => {
    const b = baseline();
    const open = exposureReach(graphOf({ nodes: b.nodes, edges: b.edges }));
    const denied = exposureReach(graphOf({ nodes: b.nodes, edges: [...b.edges, edge('network-denies', b.api, b.ledger, { effect: 'deny' })] }));
    const ledgerId = b.nodes.find((n) => n.name === 'shop/ledger');
    const idOf = (g) => g.nodes.find((n) => n.name === ledgerId.name).id;
    const gOpen = graphOf({ nodes: b.nodes, edges: b.edges });
    assert.ok(open.has(idOf(gOpen)));
    assert.equal(denied.has(idOf(gOpen)), false);
    assert.equal(validateBoundaryGraph(gOpen).ok, true);
  });
});
