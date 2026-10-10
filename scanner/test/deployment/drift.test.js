// X-306: boundary drift between two revisions, with dependency-aware invalidation and impact-driven rescans. Each criterion is
// tested in both directions: a real change is reported and mapped to the hypotheses it can affect, and an unrelated one is not.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  diffBoundaryGraphs, explainDrift, planRescan, incrementalAnnotate, compareScoped, scopedSignature, invalidatePathsForSources,
  MATERIAL_CATEGORIES,
} from '../../src/lineage/deployment/drift.js';
import { analyzeFindingBoundaries, computeAttackPaths } from '../../src/lineage/deployment/attack-paths.js';
import { buildBoundaryGraph } from '../../src/lineage/deployment/boundary-graph.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { node, edge, graphOf, SRC, FINDING } from './path-helpers.js';

const F = {
  ingress: SRC('k8s/ingress.yaml', 'ingress v1'),
  mesh: SRC('k8s/mesh.yaml', 'mesh v1'),
  iam: SRC('iam/roles.yaml', 'iam v1'),
  netpol: SRC('k8s/netpol.yaml', 'netpol v1'),
};
const srcRows = (...refs) => refs.map((s) => ({ ...s, bytes: 10 }));

/** Two independent deployments in one graph: shop (route, api, ledger, identity, db) and billing (route, service, identity, db). */
function world(o = {}) {
  const route = node('route', 'edge/orders', { trustZone: o.zone ?? 'public' });
  const api = node('service', 'shop/api', { tenant: o.apiTenant ?? null });
  const ledger = node('service', 'shop/ledger');
  const ident = node('identity', 'sa/ledger');
  const db = node('resource', 'db/ledger', { trustZone: 'privileged' });
  const audit = node('resource', 'db/audit', { trustZone: 'privileged' });
  const broute = node('route', 'edge/billing', { trustZone: 'public' });
  const billing = node('service', 'bill/svc');
  const bident = node('identity', 'sa/billing');
  const bdb = node('resource', 'db/bill', { trustZone: 'privileged' });
  const bdb2 = node('resource', 'db/bill2', { trustZone: 'privileged' });
  const nodes = [route, api, broute, billing, bident, bdb, bdb2];
  const edges = [
    edge('routes-to', route, api, { source: F.ingress }),
    edge('routes-to', broute, billing, { source: F.ingress }),
    edge('assumes', billing, bident, { source: F.iam }),
    edge('grants', bident, bdb, { effect: 'allow', attrs: { verbs: 'get' }, source: F.iam }),
  ];
  if (o.billingGrant) edges.push(edge('grants', bident, bdb2, { effect: 'allow', attrs: { verbs: 'get' }, source: F.iam }));
  if (!o.noLedger) {
    nodes.push(ledger, ident, db, audit);
    edges.push(edge('calls', api, ledger, { source: F.mesh }), edge('assumes', ledger, ident, { source: F.iam }),
      edge('grants', ident, db, { effect: 'allow', attrs: { verbs: o.verbs ?? 'get' }, source: F.iam }));
    if (o.deny !== false) edges.push(edge('network-denies', api, ledger, { effect: 'deny', source: F.netpol }));
    if (o.extraGrant) edges.push(edge('grants', ident, audit, { effect: 'allow', attrs: { verbs: 'get' }, source: F.iam }));
  } else {
    nodes.push(ident, db);
  }
  return graphOf({ nodes, edges, sources: srcRows(F.ingress, F.mesh, F.iam, F.netpol), revision: o.revision ?? null });
}

const idByName = (g, name) => g.nodes.find((n) => n.name === name)?.id;
const categories = (diff) => diff.changes.map((c) => c.category).sort();

describe('[X-306.AC01] graph diffs identify new exposure, changed privilege, tenant weakening and removed controls at stable ids', () => {
  test('[X-306.AC01] removing an explicit deny is a material removed control and exposes the service behind it, at the ids involved', () => {
    const before = world(), after = world({ deny: false });
    const { ok, diff } = diffBoundaryGraphs(before, after);
    assert.equal(ok, true);
    const removed = diff.changes.find((c) => c.category === 'removed-control');
    assert.equal(removed.material, true);
    assert.deepEqual(removed.edgeIds, before.edges.filter((e) => e.relation === 'network-denies').map((e) => e.id));
    assert.ok(removed.nodeIds.includes(idByName(before, 'shop/ledger')));
    const exposed = diff.changes.filter((c) => c.category === 'new-exposure').flatMap((c) => c.nodeIds);
    assert.ok(exposed.includes(idByName(after, 'shop/ledger')), 'the ledger becomes reachable from the exposed route');
    assert.ok(exposed.includes(idByName(after, 'db/ledger')), 'and so does the resource it is granted');
    // every id a change cites exists in one of the two graphs
    const known = new Set([...before.nodes, ...after.nodes, ...before.edges, ...after.edges].map((x) => x.id));
    for (const c of diff.changes) for (const id of [...c.nodeIds, ...c.edgeIds]) assert.ok(known.has(id), id);
  });

  test('[X-306.AC01] the same topology with no change reports no change', () => {
    const { diff } = diffBoundaryGraphs(world(), world());
    assert.deepEqual(diff.changes, []);
    assert.equal(diff.summary.material, 0);
    assert.match(explainDrift(diff).join('\n'), /no change to a non-structural relation/);
  });

  test('[X-306.AC01] a changed or added grant is changed privilege; a removed grant is a reduction, not a material change', () => {
    const widened = diffBoundaryGraphs(world(), world({ verbs: 'get,delete' })).diff;
    const c = widened.changes.find((x) => x.category === 'changed-privilege');
    assert.deepEqual(c.before, { verbs: 'get' });
    assert.deepEqual(c.after, { verbs: 'get,delete' });
    const added = diffBoundaryGraphs(world(), world({ extraGrant: true })).diff;
    assert.ok(added.changes.some((x) => x.category === 'changed-privilege' && x.material));
    const reduced = diffBoundaryGraphs(world({ extraGrant: true }), world()).diff;
    const r = reduced.changes.find((x) => x.category === 'privilege-reduced');
    assert.ok(r);
    assert.equal(r.material, false);
    assert.equal(reduced.changes.some((x) => x.category === 'changed-privilege'), false);
  });

  test('[X-306.AC01] a dropped tenant binding is tenant weakening citing both the old and the new node id; keeping it is not', () => {
    const bound = world({ apiTenant: 'acme' }), loose = world();
    const { diff } = diffBoundaryGraphs(bound, loose);
    const w = diff.changes.find((x) => x.category === 'tenant-weakening');
    assert.ok(w);
    assert.equal(w.material, true);
    assert.deepEqual(w.nodeIds.sort(), [idByName(bound, 'shop/api'), idByName(loose, 'shop/api')].sort());
    assert.notEqual(idByName(bound, 'shop/api'), idByName(loose, 'shop/api'), 'a tenant is part of the node id');
    assert.equal(diffBoundaryGraphs(bound, world({ apiTenant: 'acme' })).diff.changes.some((x) => x.category === 'tenant-weakening'), false);
    // the opposite direction (gaining a binding) is not a weakening
    assert.equal(diffBoundaryGraphs(loose, bound).diff.changes.some((x) => x.category === 'tenant-weakening'), false);
  });

  test('[X-306.AC01] a new edge that crosses tenants is tenant weakening', () => {
    const route = node('route', 'edge/x', { trustZone: 'public' });
    const a = node('service', 'shop/a', { tenant: 'acme' });
    const b = node('service', 'shop/b', { tenant: 'globex' });
    const before = graphOf({ nodes: [route, a, b], edges: [edge('routes-to', route, a)] });
    const after = graphOf({ nodes: [route, a, b], edges: [edge('routes-to', route, a), edge('calls', a, b)] });
    const { diff } = diffBoundaryGraphs(before, after);
    assert.ok(diff.changes.some((x) => x.category === 'tenant-weakening' && x.material));
    assert.equal(diffBoundaryGraphs(before, graphOf({ nodes: [route, a, b], edges: [edge('routes-to', route, a)] })).diff.changes.length, 0);
  });

  test('[X-306.AC01] a service moving into the public zone is new exposure of it and of what it reaches', () => {
    const { diff } = diffBoundaryGraphs(world({ zone: 'internal' }), world());
    assert.ok(diff.changes.some((c) => c.category === 'zone-changed'));
    const exposed = diff.changes.filter((c) => c.category === 'new-exposure').map((c) => c.nodeIds[0]);
    assert.ok(exposed.length >= 2, 'the route and the service behind it');
  });

  test('[X-306.AC01] ids are stable: rebuilding either graph in another order gives a byte-identical diff', () => {
    const a = diffBoundaryGraphs(world(), world({ deny: false, verbs: 'get,delete' })).diff;
    const rev = (g) => buildBoundaryGraph({ repository: g.repository, revision: g.revision, nodes: [...g.nodes].reverse(), edges: [...g.edges].reverse(), gaps: g.gaps, sources: [...g.sources].reverse() }).graph;
    const b = diffBoundaryGraphs(rev(world()), rev(world({ deny: false, verbs: 'get,delete' }))).diff;
    assert.equal(JSON.stringify(a), JSON.stringify(b));
  });

  test('[X-306.AC01] two environments are never merged: a staging copy is new, and prod is unchanged', () => {
    const before = world();
    const sRoute = node('route', 'edge/orders', { trustZone: 'public', environment: 'staging' });
    const sApi = node('service', 'shop/api', { environment: 'staging' });
    const after = graphOf({
      nodes: [...before.nodes.map((n) => ({ ...n })), sRoute, sApi],
      edges: [...before.edges.map((e) => ({ ...e })), edge('routes-to', sRoute, sApi, { source: F.ingress })],
      sources: srcRows(F.ingress, F.mesh, F.iam, F.netpol),
    });
    const { diff } = diffBoundaryGraphs(before, after);
    assert.ok(diff.changes.some((c) => c.category === 'service-added' && c.environment === 'staging'));
    assert.ok(diff.changes.every((c) => c.environment !== 'prod'), 'nothing in prod changed');
  });

  test('[X-306.AC01] graphs of different repositories, or an invalid graph, are refused rather than diffed', () => {
    const other = graphOf({ nodes: [node('service', 'x/y')], edges: [], repository: 'elsewhere' });
    assert.equal(diffBoundaryGraphs(world(), other).ok, false);
    const bad = JSON.parse(JSON.stringify(world()));
    bad.digest = 'sha256:' + '0'.repeat(64);
    const r = diffBoundaryGraphs(world(), bad);
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].side, 'after');
  });

  test('[X-306.AC01] the sources that moved are named with the edges each supported, and the explanation never calls a change safe', () => {
    const before = world();
    const iam2 = SRC('iam/roles.yaml', 'iam v2');
    const after = world({ verbs: 'get,delete' });
    const { diff } = diffBoundaryGraphs(before, after);
    assert.deepEqual(diff.sources.changed, [], 'identical source text is not a change');
    // a source whose digest moved
    const moved = JSON.parse(JSON.stringify(before));
    const rebuilt = buildBoundaryGraph({
      repository: moved.repository, revision: moved.revision, nodes: moved.nodes,
      edges: moved.edges.map((e) => (e.source?.file === 'iam/roles.yaml' ? { ...e, source: iam2 } : e)),
      gaps: moved.gaps, sources: [...srcRows(F.ingress, F.mesh, F.netpol), ...srcRows(iam2)],
    }).graph;
    const d2 = diffBoundaryGraphs(before, rebuilt).diff;
    assert.equal(d2.sources.changed.length, 1);
    assert.equal(d2.sources.changed[0].file, 'iam/roles.yaml');
    assert.ok(d2.sources.changed[0].edgeIdsBefore.length >= 3);
    const text = explainDrift(diffBoundaryGraphs(world(), world({ deny: false })).diff).join('\n');
    assert.match(text, /\[material\] removed-control/);
    assert.doesNotMatch(text, /\b(safe|protected|secure|harmless)\b/i);
    assert.match(text, /does not show how the deployed system behaves/);
  });

  test('[X-306.AC01] material categories are exactly the four that need a reviewer', () => {
    assert.deepEqual([...MATERIAL_CATEGORIES].sort(), ['changed-privilege', 'new-exposure', 'removed-control', 'tenant-weakening']);
    const { diff } = diffBoundaryGraphs(world(), world({ deny: false, extraGrant: true, billingGrant: true }));
    for (const c of diff.changes) assert.equal(c.material, MATERIAL_CATEGORIES.includes(c.category), c.category);
    assert.ok(categories(diff).includes('connectivity-added') === false);
  });
});

// A scan of a hypothesis is its deployment-conditioned context; the "scoped findings" the criterion compares.
const BINDINGS = [
  { pathPrefix: 'services/api/', service: 'shop/api' },
  { pathPrefix: 'services/ledger/', service: 'shop/ledger' },
  { pathPrefix: 'services/billing/', service: 'bill/svc' },
];
const hyp = (name, dir) => ({ hypothesisId: `h-${name}`, finding: { ...FINDING, id: `F-${name}`, stableId: `h-${name}`, file: `services/${dir}/handler.js` } });
const HYPS = [hyp('api', 'api'), hyp('ledger', 'ledger'), hyp('billing', 'billing')];
const annotateOn = (graph) => (h) => analyzeFindingBoundaries({ graph, finding: h.finding, bindings: BINDINGS }).context;
const completeOn = (graph, hyps = HYPS) => Object.fromEntries(hyps.map((h) => [h.hypothesisId, annotateOn(graph)(h)]));

describe('[X-306.AC02] each material diff maps to the hypotheses and focused rescans it affects; the rest are left alone', () => {
  test('[X-306.AC02] a grant change rescans the services that assume the identity or reach them, and not the unrelated deployment', () => {
    const before = world(), after = world({ verbs: 'get,delete' });
    const { diff } = diffBoundaryGraphs(before, after);
    const plan = planRescan({ diff, before, after, hypotheses: HYPS, bindings: BINDINGS });
    assert.deepEqual(plan.rescan.map((r) => r.hypothesisId), ['h-api', 'h-ledger']);
    assert.deepEqual(plan.skipped.map((r) => r.hypothesisId), ['h-billing']);
    assert.match(plan.skipped[0].reason, /no changed relation touches, reaches or is reached by bill\/svc/);
    assert.deepEqual(plan.rescanFiles, ['services/api/handler.js', 'services/ledger/handler.js']);
    assert.equal(plan.status, 'complete');
    // every reason cited is a change in the diff, and the privilege change is among them
    const byId = new Map(diff.changes.map((c) => [c.id, c]));
    for (const r of plan.rescan) {
      assert.ok(r.reasons.length > 0);
      for (const id of r.reasons) assert.ok(byId.has(id));
    }
    assert.ok(plan.rescan[1].reasons.some((id) => byId.get(id).category === 'changed-privilege'));
  });

  test('[X-306.AC02] a change in the other deployment rescans only that deployment', () => {
    const before = world(), after = world({ billingGrant: true });
    const { diff } = diffBoundaryGraphs(before, after);
    const plan = planRescan({ diff, before, after, hypotheses: HYPS, bindings: BINDINGS });
    assert.deepEqual(plan.rescan.map((r) => r.hypothesisId), ['h-billing']);
    assert.deepEqual(plan.skipped.map((r) => r.hypothesisId), ['h-api', 'h-ledger']);
  });

  test('[X-306.AC02] with no change nothing is rescanned and every hypothesis is listed as unaffected', () => {
    const before = world(), after = world();
    const { diff } = diffBoundaryGraphs(before, after);
    const plan = planRescan({ diff, before, after, hypotheses: HYPS, bindings: BINDINGS });
    assert.deepEqual(plan.rescan, []);
    assert.deepEqual(plan.rescanFiles, []);
    assert.equal(plan.skipped.length, 3);
    assert.equal(plan.status, 'complete');
  });

  test('[X-306.AC02] a removed service still maps its hypothesis to a rescan', () => {
    const before = world(), after = world({ noLedger: true });
    const { diff } = diffBoundaryGraphs(before, after);
    const plan = planRescan({ diff, before, after, hypotheses: HYPS, bindings: BINDINGS });
    assert.ok(plan.rescan.some((r) => r.hypothesisId === 'h-ledger'));
    assert.ok(diff.changes.some((c) => c.category === 'service-removed'));
  });
});

describe('[X-306.AC03] an incremental scan and a complete scan of the same changed fixture agree; missing dependencies force an incomplete status', () => {
  const MUTATIONS = {
    'remove the deny': { deny: false },
    'widen a grant': { verbs: 'get,delete' },
    'grant a second resource': { extraGrant: true },
    'billing grant': { billingGrant: true },
    'route goes internal': { zone: 'internal' },
    'api gains a tenant': { apiTenant: 'acme' },
    'ledger removed': { noLedger: true },
    'no change': {},
  };
  const incrementalVsComplete = (beforeOpts, afterOpts) => {
    const before = world(beforeOpts), after = world(afterOpts);
    const { diff } = diffBoundaryGraphs(before, after);
    const plan = planRescan({ diff, before, after, hypotheses: HYPS, bindings: BINDINGS });
    const inc = incrementalAnnotate({ plan, hypotheses: HYPS, previous: completeOn(before), annotate: annotateOn(after) });
    return { before, after, diff, plan, inc, cmp: compareScoped(inc, completeOn(after)) };
  };

  for (const [name, mut] of Object.entries(MUTATIONS)) {
    test(`[X-306.AC03] ${name}: incremental equals complete`, () => {
      const r = incrementalVsComplete({}, mut);
      assert.equal(r.plan.status, 'complete');
      assert.deepEqual(r.cmp.differing, []);
      assert.equal(r.cmp.equivalent, true);
      assert.deepEqual([...r.inc.recomputed, ...r.inc.carried].sort(), HYPS.map((h) => h.hypothesisId).sort());
    });
  }

  test('[X-306.AC03] the comparison is not vacuous: an incremental run that skipped an affected hypothesis differs from the complete run', () => {
    const r = incrementalVsComplete({}, { deny: false });
    assert.ok(r.plan.rescan.some((x) => x.hypothesisId === 'h-ledger'));
    const sabotaged = incrementalAnnotate({ plan: { ...r.plan, rescan: [] }, hypotheses: HYPS, previous: completeOn(r.before), annotate: annotateOn(r.after) });
    const cmp = compareScoped(sabotaged, completeOn(r.after));
    assert.equal(cmp.equivalent, false);
    assert.ok(cmp.differing.includes('h-ledger'));
  });

  test('[X-306.AC03] unaffected hypotheses are carried, not recomputed, and the affected ones really are recomputed', () => {
    const r = incrementalVsComplete({}, { billingGrant: true });
    assert.deepEqual(r.inc.recomputed, ['h-billing']);
    assert.deepEqual(r.inc.carried, ['h-api', 'h-ledger']);
    let calls = 0;
    const counting = (h) => { calls++; return annotateOn(r.after)(h); };
    incrementalAnnotate({ plan: r.plan, hypotheses: HYPS, previous: completeOn(r.before), annotate: counting });
    assert.equal(calls, 1, 'one annotation, not three');
    // the changed fixture really changed the billing result, so the comparison had something to detect
    assert.notEqual(scopedSignature(completeOn(r.before)['h-billing']), scopedSignature(completeOn(r.after)['h-billing']));
  });

  test('[X-306.AC03] a hypothesis that cannot be tied to a service forces an explicit incomplete status that never claims equivalence', () => {
    const stray = { hypothesisId: 'h-stray', finding: { ...FINDING, id: 'F-stray', stableId: 'h-stray', file: 'tools/script.js' } };
    const all = [...HYPS, stray];
    const before = world(), after = world({ deny: false });
    const { diff } = diffBoundaryGraphs(before, after);
    const plan = planRescan({ diff, before, after, hypotheses: all, bindings: BINDINGS });
    assert.equal(plan.status, 'incomplete');
    assert.equal(plan.incomplete[0].code, 'unbound-hypothesis');
    assert.ok(!plan.rescan.some((r) => r.hypothesisId === 'h-stray'), 'it is neither rescanned nor cleared');
    assert.ok(!plan.skipped.some((r) => r.hypothesisId === 'h-stray'));
    const inc = incrementalAnnotate({ plan, hypotheses: all, previous: completeOn(before, all), annotate: annotateOn(after) });
    assert.equal(inc.status, 'incomplete');
    assert.deepEqual(inc.stale, ['h-stray']);
    const cmp = compareScoped(inc, completeOn(after, all));
    assert.equal(cmp.equivalent, false, 'an incomplete result is never reported as equivalent');
    // with nothing changed the same hypothesis needs no proof of independence
    const same = planRescan({ diff: diffBoundaryGraphs(before, before).diff, before, after: before, hypotheses: all, bindings: BINDINGS });
    assert.equal(same.status, 'complete');
  });

  test('[X-306.AC03] a missing source dependency in the new graph forces incomplete even when every hypothesis is bound', () => {
    const before = world();
    const g = world({ deny: false });
    const gapped = buildBoundaryGraph({ repository: g.repository, revision: g.revision, nodes: g.nodes, edges: g.edges, sources: g.sources,
      gaps: [{ code: 'source-missing', subject: 'k8s/mesh.yaml', file: 'k8s/mesh.yaml', message: 'k8s/mesh.yaml is no longer present' }] }).graph;
    const { diff } = diffBoundaryGraphs(before, gapped);
    assert.equal(diff.incomplete[0].code, 'source-missing');
    const plan = planRescan({ diff, before, after: gapped, hypotheses: HYPS, bindings: BINDINGS });
    assert.equal(plan.status, 'incomplete');
    assert.match(plan.statement, /incomplete/);
    assert.equal(compareScoped(incrementalAnnotate({ plan, hypotheses: HYPS, previous: completeOn(before), annotate: annotateOn(gapped) }), completeOn(gapped)).equivalent, false);
    // a gap that does not stand for a missing dependency does not force it
    const benign = buildBoundaryGraph({ repository: g.repository, revision: g.revision, nodes: g.nodes, edges: g.edges, sources: g.sources,
      gaps: [{ code: 'unsupported-syntax', subject: 'main.tf', file: 'main.tf', message: 'HCL is not interpreted' }] }).graph;
    assert.equal(diffBoundaryGraphs(before, benign).diff.incomplete.length, 0);
  });
});

describe('[X-306.AC03] dependency-aware invalidation: a changed source file invalidates exactly the paths it supported', () => {
  const sources = (g) => Object.fromEntries(g.sources.map((s) => [s.file, s.digest]));
  const twoPaths = () => {
    const g = world();
    return { g, paths: computeAttackPaths(g).paths };
  };

  test('[X-306.AC03] changing the identity policy file invalidates the paths that used a grant from it and no others', () => {
    const { g, paths } = twoPaths();
    assert.equal(paths.length, 2, 'one path per deployment');
    const cur = { ...sources(g), 'iam/roles.yaml': digestOf('iam v2') };
    const r = invalidatePathsForSources(paths, g, cur);
    assert.equal(r.ok, true);
    assert.deepEqual(r.staleFiles, ['iam/roles.yaml']);
    assert.equal(r.invalidated.length, 2, 'both paths end in a grant from the changed file');
    const cur2 = { ...sources(g), 'k8s/mesh.yaml': digestOf('mesh v2') };
    const r2 = invalidatePathsForSources(paths, g, cur2);
    assert.equal(r2.invalidated.length, 1, 'only the path that used the service-call edge');
    assert.equal(r2.valid.length, 1);
    const used = new Set(r2.invalidated[0].edgeIds);
    const meshEdges = g.edges.filter((e) => e.source?.file === 'k8s/mesh.yaml').map((e) => e.id);
    assert.deepEqual([...used], meshEdges, 'exactly the edges that file supported');
    assert.ok(paths.find((p) => p.id === r2.valid[0].id).supportingEdgeIds.every((id) => !meshEdges.includes(id)));
  });

  test('[X-306.AC03] an unchanged file or an unknown file invalidates nothing, and a removed file invalidates what it supported', () => {
    const { g, paths } = twoPaths();
    const none = invalidatePathsForSources(paths, g, sources(g));
    assert.deepEqual(none.invalidated, []);
    assert.equal(none.valid.length, paths.length);
    assert.deepEqual(none.staleFiles, []);
    const extra = invalidatePathsForSources(paths, g, { ...sources(g), 'docs/unrelated.yaml': digestOf('x') });
    assert.deepEqual(extra.invalidated, []);
    const gone = { ...sources(g) };
    delete gone['k8s/ingress.yaml'];
    const r = invalidatePathsForSources(paths, g, gone);
    assert.equal(r.invalidated.length, 2, 'both entry routes came from the removed file');
    assert.ok(r.graph.gaps.some((x) => x.code === 'source-missing' && x.file === 'k8s/ingress.yaml'));
    assert.equal(r.graph.edges.some((e) => e.source?.file === 'k8s/ingress.yaml'), false);
  });

  test('[X-306.AC03] after invalidation the surviving paths are exactly the paths of the pruned graph', () => {
    const { g, paths } = twoPaths();
    const cur = { ...sources(g), 'k8s/mesh.yaml': digestOf('mesh v2') };
    const r = invalidatePathsForSources(paths, g, cur);
    const recomputed = computeAttackPaths(r.graph).paths.map((p) => p.id);
    assert.deepEqual(r.valid.map((p) => p.id).sort(), recomputed.sort());
  });
});
