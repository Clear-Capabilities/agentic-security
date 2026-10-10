// X-304: resolve cross-repository boundaries. A link binds exact revisions and
// declared identities, and every way it can fail to resolve (access scope,
// missing repository, version mismatch, identity collision, missing service or
// route, tampered graph) produces a typed gap and an unresolved dependency,
// never a guessed link and never a network read.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveCrossRepoBoundaries, checkDeclaration, declarationId, CROSS_REPO_PARSER, CROSS_REPO_PARSER_VERSION, DEFAULT_DECLARATION_FILE } from '../../src/lineage/deployment/cross-repo.js';
import { validateBoundaryGraph, exportBoundaryGraph, indexGraph, findPath, buildBoundaryGraph, nodeIdOf } from '../../src/lineage/deployment/boundary-graph.js';
import { ingestDeploymentConfig } from '../../src/lineage/deployment/ingest.js';
import { crossRepoGraphs, standardDeclaration, supplied, ingestOne, nodeByName, edgesOf, REV_A, REV_B, REV_C, fx } from './helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCOPE = { authorizedRepositories: ['checkout', 'billing'] };

function resolve(over = {}) {
  const { checkout, billing } = crossRepoGraphs();
  return resolveCrossRepoBoundaries({ graphs: supplied([checkout, billing]), declarations: [standardDeclaration()], accessScope: SCOPE, ...over });
}
const gapCodes = (r) => r.gaps.map(g => g.code);
function crossEdges(r) { return r.graph.edges.filter(e => e.crossRepo); }
function assertNoGuessedLink(r) {
  assert.ok(r.links.every(l => l.status !== 'resolved'), 'no resolved link');
  assert.ok(crossEdges(r).every(e => e.pathState === 'unresolved'), 'every cross-repository edge that exists is explicitly unresolved');
}

// ------------------------------------------------------------------ AC01

test('[X-304.AC01] a resolved cross-repository edge binds the exact revision of both repositories and the declared identities', () => {
  const r = resolve();
  assert.equal(r.status, 'ok', JSON.stringify(r.errors));
  assert.equal(validateBoundaryGraph(r.graph).ok, true);
  assert.equal(r.links[0].status, 'resolved');
  const e = crossEdges(r)[0];
  assert.deepEqual(e.crossRepo, { callerRepository: 'checkout', callerRevision: REV_A, calleeRepository: 'billing', calleeRevision: REV_B });
  assert.equal(e.provenance, 'static-config');
  assert.equal(e.pathState, 'possible');
  assert.equal(e.sourceRevision, REV_A);
  assert.equal(e.source.parser, CROSS_REPO_PARSER);
  assert.equal(e.source.parserVersion, CROSS_REPO_PARSER_VERSION);
  const byId = new Map(r.graph.nodes.map(n => [n.id, n]));
  assert.equal(byId.get(e.from).name, 'shop/web');
  assert.equal(byId.get(e.from).repository, 'checkout');
  assert.equal(byId.get(e.to).repository, 'billing');
});

test('[X-304.AC01] the contract refuses a cross-repository edge bound to a branch name, a short hash or no revision', () => {
  const r = resolve();
  const e = crossEdges(r)[0];
  for (const bad of ['main', 'abc1234', null, 'A'.repeat(40)]) {
    const g = structuredClone(r.graph);
    g.edges.find(x => x.id === e.id).crossRepo.calleeRevision = bad;
    const v = validateBoundaryGraph(g);
    assert.equal(v.ok, false, String(bad));
  }
  for (const side of ['caller', 'callee']) {
    const d = standardDeclaration(); d[side].revision = 'main';
    assert.match(checkDeclaration(d), /exact 40 or 64 hex commit/);
  }
});

test('[X-304.AC01] an unavailable repository keeps the dependency as an unresolved edge bound to the declared revisions', () => {
  const { checkout } = crossRepoGraphs();
  const r = resolveCrossRepoBoundaries({ graphs: supplied([checkout]), declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.links[0].gapCodes, ['repository-unavailable']);
  assert.equal(r.links[0].status, 'unresolved');
  assert.ok(gapCodes(r).includes('repository-unavailable'));
  const e = crossEdges(r)[0];
  assert.ok(e, 'the dependency is not dropped');
  assert.equal(e.pathState, 'unresolved');
  assert.equal(e.crossRepo.calleeRevision, REV_B, 'it still names the revision the operator declared');
  const callee = r.graph.nodes.find(n => n.id === e.to);
  assert.equal(callee.resolved, false);
  assert.match(callee.unresolvedReason, /repository-unavailable/);
  // the caller side is still a resolved, attributed node from its own graph
  assert.equal(nodeByName(r.graph, 'shop/web').resolved, true);
});

test('[X-304.AC01] with neither repository available, the dependency is still preserved and nothing is resolved', () => {
  const r = resolveCrossRepoBoundaries({ graphs: [], declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.links[0].gapCodes, ['repository-unavailable']);
  assertNoGuessedLink(r);
  assert.equal(crossEdges(r).length, 1);
  assert.ok(r.graph.nodes.filter(n => n.kind === 'service').every(n => n.resolved === false));
});

test('[X-304.AC01] a declaration cannot join two environments or two tenants, and must be well formed', () => {
  const d = standardDeclaration(); d.callee.environment = 'staging';
  assert.match(checkDeclaration(d), /two environments/);
  const t = standardDeclaration(); t.caller.tenant = 'acme';
  assert.match(checkDeclaration(t), /tenant/);
  assert.equal(checkDeclaration(standardDeclaration()), null);
  assert.ok(checkDeclaration(null) && checkDeclaration({}) && checkDeclaration({ caller: {}, callee: {} }));
  const r = resolve({ declarations: [d, null, 'x'] });
  assert.equal(r.links.filter(l => l.status === 'invalid').length, 3);
  assert.equal(r.links.filter(l => l.status === 'resolved').length, 0);
  assert.equal(crossEdges(r).length, 0);
  assert.ok(gapCodes(r).includes('malformed-input'));
});

test('[X-304.AC01] declaration ids are stable and distinguish revisions and environments', () => {
  const a = declarationId(standardDeclaration());
  assert.equal(a, declarationId(standardDeclaration()));
  const rev = standardDeclaration(); rev.callee.revision = REV_C;
  const env = standardDeclaration(); env.caller.environment = 'staging'; env.callee.environment = 'staging';
  assert.equal(new Set([a, declarationId(rev), declarationId(env)]).size, 3);
});

// ------------------------------------------------------------------ AC02

test('[X-304.AC02] a caller reaches the callee route, workload, identity and privileges, with attributable evidence', () => {
  const r = resolve();
  const l = r.links[0];
  assert.equal(l.status, 'resolved');
  assert.deepEqual(l.gapCodes, []);
  assert.equal(l.transitions.entry.routeNodeId, nodeByName(r.graph, 'ingress/billing/billing-ingress:billing.internal/charge').id);
  assert.deepEqual(l.transitions.callerIdentities.map(i => i.identity), ['sa/shop/web-sa']);
  const priv = l.transitions.calleePrivileges;
  assert.equal(priv.length, 1);
  assert.equal(priv[0].identity, 'sa/billing/billing-sa');
  assert.equal(priv[0].identityResolved, true);
  assert.deepEqual(priv[0].grants.map(g => [g.resource, g.effect, g.discriminator]), [['k8s/ns:billing/secrets', 'allow', 'get,update']]);
  // the identity boundary and the repository boundary are both named
  const types = l.transitions.crossings.map(c => c.type).sort();
  assert.ok(types.includes('repository'));
  // evidence names the files in BOTH repositories, the declaration, and the graph digests
  const ev = l.evidence;
  assert.equal(ev.caller.revision, REV_A);
  assert.equal(ev.callee.revision, REV_B);
  assert.ok(ev.caller.declaredBy.every(d => d.file === 'xrepo/checkout.yaml'));
  assert.ok(ev.callee.declaredBy.every(d => d.file === 'xrepo/billing.yaml'));
  assert.ok(ev.route.declaredBy.length >= 1 && ev.route.chainEdgeIds.length === 2);
  assert.match(ev.caller.graphDigest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(ev.caller.graphDigest, ev.callee.graphDigest);
  assert.equal(ev.declaration.file, DEFAULT_DECLARATION_FILE);
  assert.equal(l.edgeId, crossEdges(r)[0].id);
});

test('[X-304.AC02] the federated graph holds a traversable path from the caller service to the callee privilege', () => {
  const r = resolve();
  const idx = indexGraph(r.graph);
  const from = nodeByName(r.graph, 'shop/web').id;
  const secrets = nodeByName(r.graph, 'k8s/ns:billing/secrets').id;
  const path = findPath(idx.out, from, secrets, { accept: e => e.pathState !== 'blocked' && !['deployed-in', 'defined-in', 'scoped-to'].includes(e.relation) });
  assert.ok(path, 'caller -> route -> service -> identity -> resource');
  const names = new Map(r.graph.nodes.map(n => [n.id, n.name]));
  assert.deepEqual([names.get(path[0].from), ...path.map(e => names.get(e.to))], [
    'shop/web', 'ingress/billing/billing-ingress:billing.internal/charge', 'svc/billing/billing-api', 'billing/billing-api', 'sa/billing/billing-sa', 'k8s/ns:billing/secrets']);
  assert.deepEqual(path.map(e => e.relation), ['calls', 'routes-to', 'routes-to', 'assumes', 'grants']);
  assert.ok(path[0].crossRepo, 'the first hop is the cross-repository edge');
  // and without the link there is no such path
  const { checkout, billing } = crossRepoGraphs();
  const none = resolveCrossRepoBoundaries({ graphs: supplied([checkout, billing]), declarations: [], accessScope: SCOPE });
  const idx2 = indexGraph(none.graph);
  assert.equal(findPath(idx2.out, nodeByName(none.graph, 'shop/web').id, nodeByName(none.graph, 'k8s/ns:billing/secrets').id), null);
});

test('[X-304.AC02] a link without a declared route resolves to the callee service itself', () => {
  const d = standardDeclaration(); delete d.callee.route;
  const r = resolve({ declarations: [d] });
  assert.equal(r.links[0].status, 'resolved');
  assert.equal(r.links[0].transitions.entry, null);
  assert.equal(crossEdges(r)[0].to, nodeByName(r.graph, 'billing/billing-api').id);
});

test('[X-304.AC02] a declared route that does not reach the callee is unresolved; no route is guessed', () => {
  const bad = standardDeclaration(); bad.callee.route = { host: 'billing.internal', path: '/refund' };
  const r = resolve({ declarations: [bad] });
  assert.equal(r.links[0].status, 'unresolved');
  assert.deepEqual(r.links[0].gapCodes, ['unresolved-identity']);
  assertNoGuessedLink(r);
  const wrongHost = standardDeclaration(); wrongHost.callee.route = { host: 'elsewhere.example.com' };
  assert.equal(resolve({ declarations: [wrongHost] }).links[0].status, 'unresolved');
});

test('[X-304.AC02] results are deterministic: declaration order and graph order do not change the federated graph', () => {
  const { checkout, billing } = crossRepoGraphs();
  const second = standardDeclaration(); delete second.callee.route;
  const a = resolveCrossRepoBoundaries({ graphs: supplied([checkout, billing]), declarations: [standardDeclaration(), second], accessScope: SCOPE });
  const b = resolveCrossRepoBoundaries({ graphs: supplied([billing, checkout]), declarations: [second, standardDeclaration()], accessScope: SCOPE });
  assert.equal(exportBoundaryGraph(a.graph), exportBoundaryGraph(b.graph));
  assert.deepEqual(a.links.map(l => l.declarationId), b.links.map(l => l.declarationId));
});

// ------------------------------------------------------------------ AC03

test('[X-304.AC03] access denial: a repository outside the access scope is not read and the link is an explicit gap', () => {
  const r = resolve({ accessScope: { authorizedRepositories: ['checkout'] } });
  assert.ok(gapCodes(r).includes('access-denied'));
  assert.deepEqual(r.links[0].gapCodes, ['access-denied']);
  assertNoGuessedLink(r);
  // billing's graph was handed over, but nothing of it is in the result
  assert.equal(nodeByName(r.graph, 'sa/billing/billing-sa'), undefined);
  assert.ok(!r.graph.nodes.some(n => n.repository === 'billing'));
  assert.ok(r.graph.sources.every(s => s.file !== 'xrepo/billing.yaml'));
  // an empty scope authorizes nothing, and a missing scope is refused outright
  const none = resolve({ accessScope: { authorizedRepositories: [] } });
  assert.deepEqual(gapCodes(none).filter(c => c === 'access-denied').length >= 2, true);
  assert.equal(resolve({ accessScope: undefined }).status, 'invalid-input');
  assert.equal(resolve({ accessScope: { authorizedRepositories: 'all' } }).status, 'invalid-input');
});

test('[X-304.AC03] version mismatch: a graph at a different revision than the declaration binds is not linked', () => {
  const { checkout, billing } = crossRepoGraphs({ billingRevision: REV_C });
  const r = resolveCrossRepoBoundaries({ graphs: supplied([checkout, billing]), declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.deepEqual(r.links[0].gapCodes, ['version-mismatch']);
  assert.match(r.gaps.find(g => g.code === 'version-mismatch').message, /billing/);
  assertNoGuessedLink(r);
  // the caller side drifting is caught the same way
  const c2 = crossRepoGraphs({ checkoutRevision: REV_C });
  const r2 = resolveCrossRepoBoundaries({ graphs: supplied([c2.checkout, c2.billing]), declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.deepEqual(r2.links[0].gapCodes, ['version-mismatch']);
  // and a graph that records no revision cannot prove it matches
  const noRev = crossRepoGraphs({ billingRevision: null });
  const r3 = resolveCrossRepoBoundaries({ graphs: supplied([noRev.checkout, noRev.billing]), declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.deepEqual(r3.links[0].gapCodes, ['revision-unknown']);
  assertNoGuessedLink(r3);
});

test('[X-304.AC03] identity collision: two repositories defining one declared identity make the callee ambiguous, not guessable', () => {
  const { checkout, billing } = crossRepoGraphs();
  const fork = ingestOne('xrepo/billing.yaml', { repository: 'billing-fork', revision: REV_C });
  const r = resolveCrossRepoBoundaries({
    graphs: supplied([checkout, billing, fork]), declarations: [standardDeclaration()],
    accessScope: { authorizedRepositories: ['checkout', 'billing', 'billing-fork'] },
  });
  assert.ok(r.links[0].gapCodes.includes('identity-collision'));
  assertNoGuessedLink(r);
  const collided = nodeByName(r.graph, 'billing/billing-api', 'service');
  assert.equal(collided.resolved, false);
  assert.equal(collided.unresolvedReason, 'identity-collision');
  assert.ok(r.graph.gaps.some(g => g.code === 'identity-collision' && /billing-fork/.test(g.message)));
});

test('[X-304.AC03] identity collision: two supplied graphs claiming one repository name, or a graph that says it is another repository, are not used', () => {
  const { checkout, billing } = crossRepoGraphs();
  const dup = resolveCrossRepoBoundaries({ graphs: [...supplied([checkout, billing]), ...supplied([billing])], declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.ok(gapCodes(dup).includes('identity-collision'));
  assert.ok(dup.links[0].gapCodes.includes('repository-unavailable'));
  assertNoGuessedLink(dup);
  const imposter = resolveCrossRepoBoundaries({ graphs: [{ repository: 'checkout', text: exportBoundaryGraph(checkout) }, { repository: 'billing', text: exportBoundaryGraph(checkout) }], declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.ok(imposter.gaps.some(g => g.code === 'identity-collision' && /says it is repository 'checkout'/.test(g.message)));
  assertNoGuessedLink(imposter);
  // a service the repository's graph attributes to someone else is a collision too
  const owned = structuredClone(billing);
  owned.nodes.find(n => n.name === 'billing/billing-api' && n.kind === 'service').repository = 'checkout';
  owned.digest = buildBoundaryGraph({ ...owned }).graph?.digest ?? owned.digest;
  const viaObject = resolveCrossRepoBoundaries({ graphs: [{ repository: 'checkout', graph: checkout }, { repository: 'billing', graph: buildBoundaryGraph({ ...owned }).graph }], declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.ok(viaObject.links[0].gapCodes.includes('identity-collision'));
});

test('[X-304.AC03] a declared service that the repository does not define at that revision is unresolved, not linked to a lookalike', () => {
  const d = standardDeclaration(); d.callee.service = 'billing/billing-apii';
  const r = resolve({ declarations: [d] });
  assert.deepEqual(r.links[0].gapCodes, ['unresolved-identity']);
  assertNoGuessedLink(r);
  const wrongEnv = standardDeclaration(); wrongEnv.caller.environment = 'staging'; wrongEnv.callee.environment = 'staging';
  assert.deepEqual(resolve({ declarations: [wrongEnv] }).links[0].gapCodes, ['unresolved-identity'], 'prod and staging are never merged');
});

test('[X-304.AC03] a tampered or malformed supplied graph is a gap and is not used', () => {
  const { checkout, billing } = crossRepoGraphs();
  const doc = JSON.parse(exportBoundaryGraph(billing));
  doc.nodes[0].name = 'tampered';
  const tampered = resolveCrossRepoBoundaries({ graphs: [{ repository: 'checkout', text: exportBoundaryGraph(checkout) }, { repository: 'billing', text: JSON.stringify(doc) }], declarations: [standardDeclaration()], accessScope: SCOPE });
  assert.ok(gapCodes(tampered).includes('graph-integrity'));
  assert.ok(tampered.links[0].gapCodes.includes('repository-unavailable'));
  assertNoGuessedLink(tampered);
  const junk = resolveCrossRepoBoundaries({ graphs: [{ repository: 'billing', text: 'not json' }, { repository: 'x' }, { nope: 1 }, null], declarations: [], accessScope: SCOPE });
  assert.ok(gapCodes(junk).includes('graph-integrity'));
  assert.ok(gapCodes(junk).includes('malformed-input'));
  assert.ok(gapCodes(junk).includes('access-denied'), 'a graph for an unauthorized repository is not read');
});

test('[X-304.AC03] no network: resolution uses only what was supplied, and the module cannot reach a network or a process', async () => {
  const realFetch = globalThis.fetch;
  let called = 0;
  globalThis.fetch = () => { called += 1; throw new Error('no network'); };
  try {
    resolve();
    resolve({ accessScope: { authorizedRepositories: ['checkout'] } });
    resolveCrossRepoBoundaries({ graphs: [], declarations: [standardDeclaration()], accessScope: SCOPE });
  } finally { globalThis.fetch = realFetch; }
  assert.equal(called, 0);
  const text = fs.readFileSync(path.join(HERE, '..', '..', 'src', 'lineage', 'deployment', 'cross-repo.js'), 'utf8');
  assert.ok(!/node:(http|https|net|dns|dgram|tls|child_process|fs)|\bfetch\(|XMLHttpRequest|WebSocket/.test(text), 'cross-repo.js has no network, process or file system import');
  assert.deepEqual([...text.matchAll(/\bfrom '([^']+)'/g)].map(m => m[1]).sort(), ['../../posture/assurance/identity.js', './boundary-graph.js']);
});

test('[X-304.AC03] caller and callee inside one ingest are not mistaken for a cross-repository link', () => {
  // a single repository graph has no crossRepo edge, and cross-repo resolution of it alone links nothing
  const only = ingestDeploymentConfig({ files: [{ path: 'a.yaml', text: fx('xrepo/checkout.yaml') }], environment: 'prod', repository: 'checkout', revision: REV_A }).graph;
  assert.equal(only.edges.filter(e => e.crossRepo).length, 0);
  const r = resolveCrossRepoBoundaries({ graphs: supplied([only]), declarations: [], accessScope: SCOPE });
  assert.equal(crossEdges(r).length, 0);
  assert.equal(nodeIdOf({ kind: 'service', name: 'shop/web', environment: 'prod', tenant: null }), nodeByName(only, 'shop/web').id);
});
