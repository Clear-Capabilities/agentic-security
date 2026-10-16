// E5-06: a coherent route -> library -> sink chain across repos and services, wrong-service edges discriminated, budgets and tenant isolation enforced.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { DEFAULT_BUDGETS, buildServiceChainGraph, findChains } from '../../src/posture/fleet/service-chain-graph.js';

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e5-06-'));
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));
function repoDir(id, pkg) { const d = path.join(ROOT, id); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify(pkg)); return d; }

// web (service "web") --api--> billing (service "billing") --library--> pay-lib (published) --> sink
// search (service "search") also exposes POST /charge: the decoy a careless matcher would pick
const web = () => ({ id: 'web', tenant: 't1', service: 'web', path: repoDir('web', { name: 'web-app', dependencies: {} }),
  routes: [{ method: 'POST', path: '/checkout', handler: 'web.checkout', classification: 'payment-card' }],
  functions: [{ qid: 'web.checkout' }, { qid: 'web.charge' }], calls: [{ from: 'web.checkout', to: 'web.charge' }],
  outboundCalls: [{ from: 'web.charge', service: 'billing', method: 'POST', path: '/charge' }] });
const billing = (over = {}) => ({ id: 'billing', tenant: 't1', service: 'billing', path: repoDir('billing', { name: 'billing-svc', dependencies: { 'pay-lib': '^1.2.0' } }),
  routes: [{ method: 'POST', path: '/charge', handler: 'billing.charge', classification: 'payment-card' }],
  functions: [{ qid: 'billing.charge' }], libraryUses: [{ package: 'pay-lib', symbol: 'render', from: 'billing.charge' }], dependencyVersions: { 'pay-lib': '1.2.3' }, ...over });
const lib = () => ({ id: 'pay-lib', tenant: 't1', path: repoDir('pay-lib', { name: 'pay-lib', dependencies: {} }),
  exports: [{ package: 'pay-lib', symbol: 'render', qid: 'paylib.render' }], functions: [{ qid: 'paylib.render', sinks: [{ kind: 'command-injection', cwe: 'CWE-78' }] }],
  advisories: [{ lt: '1.3.0' }] });
const search = () => ({ id: 'search', tenant: 't1', service: 'search', path: repoDir('search', { name: 'search-svc', dependencies: {} }),
  routes: [{ method: 'POST', path: '/charge', handler: 'search.charge' }], functions: [{ qid: 'search.charge', sinks: [{ kind: 'sql-injection', cwe: 'CWE-89' }] }] });

test('a coherent route -> service -> library -> sink chain across three repos, with every step cited', () => {
  const g = buildServiceChainGraph([web(), billing(), lib(), search()], { tenant: 't1' });
  const { chains } = findChains(g, { sinkKind: 'command-injection', fromRepo: 'web' });
  assert.equal(chains.length, 1);
  assert.equal(findChains(g, { sinkKind: 'command-injection' }).chains.length, 2, 'billing\'s own route reaches the same sink directly');
  const c = chains[0];
  assert.equal(c.route, 'POST /checkout'); assert.equal(c.service, 'web'); assert.equal(c.sink, 'command-injection');
  assert.deepEqual(c.steps.map((s) => s.kind), ['handler', 'call', 'api', 'handler', 'library', 'sink']);
  assert.deepEqual(c.repos.sort(), ['billing', 'pay-lib', 'web']);
  assert.equal(c.crossesServices, true);
  assert.deepEqual(c.throughLibrary, [{ package: 'pay-lib', version: '1.2.3', vulnerable: true }]);
  assert.deepEqual(c.dataClassifications, ['payment-card']);
  for (const s of c.steps) { assert.ok(s.evidence && s.confidence > 0 && s.confidence <= 1); }
  assert.ok(c.confidence > 0 && c.confidence < Math.min(...c.steps.map((s) => s.confidence)) + 1e-9, 'a chain is no more certain than its weakest step');
});

test('WRONG SERVICE: a call that names billing never reaches search, even though search exposes the same route; no SQL chain exists', () => {
  const g = buildServiceChainGraph([web(), billing(), lib(), search()], { tenant: 't1' });
  assert.equal(findChains(g, { sinkKind: 'sql-injection', fromRepo: 'web' }).chains.length, 0, 'the decoy service is not on any path from web');
  const apiEdges = g.edges.filter((e) => e.kind === 'api');
  assert.equal(apiEdges.length, 1); assert.equal(apiEdges[0].toRepo, 'billing');
  const w = web(); w.outboundCalls[0].service = 'search';
  const g2 = buildServiceChainGraph([w, billing(), lib(), search()], { tenant: 't1' });
  assert.equal(g2.edges.find((e) => e.kind === 'api').toRepo, 'search', 'naming the other service goes to the other service');
  assert.equal(findChains(g2, { sinkKind: 'command-injection', fromRepo: 'web' }).chains.length, 0);
  assert.equal(findChains(g2, { sinkKind: 'sql-injection', fromRepo: 'web' }).chains.length, 1);
  const w2 = web(); w2.outboundCalls[0].service = 'inventory';
  const g3 = buildServiceChainGraph([w2, billing(), lib(), search()], { tenant: 't1' });
  assert.equal(g3.edges.filter((e) => e.kind === 'api').length, 0); assert.match(g3.unresolved.find((u) => u.service === 'inventory').reason, /does not expose/);
});

test('AMBIGUOUS: an unnamed call to a route two services expose makes no edge and lists the candidates; one exposer resolves', () => {
  const w = web(); delete w.outboundCalls[0].service;
  const g = buildServiceChainGraph([w, billing(), lib(), search()], { tenant: 't1' });
  assert.equal(g.edges.filter((e) => e.kind === 'api').length, 0);
  assert.deepEqual(g.ambiguous, [{ repo: 'web', from: 'web.charge', path: '/charge', candidates: ['billing', 'search'] }]);
  assert.equal(findChains(g, { fromRepo: 'web' }).chains.length, 0);
  const g2 = buildServiceChainGraph([w, billing(), lib()], { tenant: 't1' });
  const e = g2.edges.find((x) => x.kind === 'api'); assert.equal(e.toRepo, 'billing'); assert.equal(e.confidence, 0.7, 'less certain than a named service (0.9)');
});

test('library edges follow the declared dependency only, and vulnerability follows the declared version', () => {
  const safe = buildServiceChainGraph([web(), billing({ dependencyVersions: { 'pay-lib': '1.3.1' } }), lib()], { tenant: 't1' });
  assert.equal(findChains(safe, { sinkKind: 'command-injection', fromRepo: 'web' }).chains[0].throughLibrary[0].vulnerable, false);
  const noDep = billing(); fs.writeFileSync(path.join(noDep.path, 'package.json'), JSON.stringify({ name: 'billing-svc', dependencies: {} }));
  const g = buildServiceChainGraph([web(), noDep, lib()], { tenant: 't1' });
  assert.equal(g.edges.filter((e) => e.kind === 'library').length, 0); assert.match(g.unresolved.find((u) => u.kind === 'library').reason, /does not declare a dependency/);
  fs.writeFileSync(path.join(noDep.path, 'package.json'), JSON.stringify({ name: 'billing-svc', dependencies: { 'pay-lib': '^1.2.0' } }));
  const wrongSymbol = billing({ libraryUses: [{ package: 'pay-lib', symbol: 'nope', from: 'billing.charge' }] });
  assert.match(buildServiceChainGraph([wrongSymbol, lib()], { tenant: 't1' }).unresolved[0].reason, /does not export/);
  const nobody = billing({ libraryUses: [{ package: 'ghost-lib', symbol: 'x', from: 'billing.charge' }] });
  assert.match(buildServiceChainGraph([nobody], { tenant: 't1' }).unresolved[0].reason, /no repo in this tenant publishes/);
});

test('TWO REPOS, TWO SERVICES: route -> api -> handler -> sink, with the sink inside the second service', () => {
  const b = billing({ libraryUses: [], functions: [{ qid: 'billing.charge', sinks: [{ kind: 'sql-injection', cwe: 'CWE-89' }] }] });
  const g = buildServiceChainGraph([web(), b], { tenant: 't1' });
  const { chains } = findChains(g, { fromRepo: 'web' });
  assert.equal(chains.length, 1); assert.deepEqual(chains[0].steps.map((s) => s.kind), ['handler', 'call', 'api', 'handler', 'sink']); assert.deepEqual(chains[0].repos.sort(), ['billing', 'web']);
});

test('event topics link a publisher to a consumer in another repo; cycles terminate', () => {
  const pub = { id: 'p', tenant: 't1', service: 'p', path: repoDir('p', { name: 'p' }), routes: [{ path: '/in', handler: 'p.in' }], functions: [{ qid: 'p.in' }, { qid: 'p.loop' }], calls: [{ from: 'p.in', to: 'p.loop' }, { from: 'p.loop', to: 'p.in' }], topics: { publishes: [{ topic: 'orders', from: 'p.loop' }] } };
  const con = { id: 'c', tenant: 't1', service: 'c', path: repoDir('c', { name: 'c' }), functions: [{ qid: 'c.on', sinks: [{ kind: 'ssrf' }] }], topics: { consumes: [{ topic: 'orders', handler: 'c.on' }] } };
  const { chains } = findChains(buildServiceChainGraph([pub, con], { tenant: 't1' }));
  assert.equal(chains.length, 1); assert.ok(chains[0].steps.some((s) => s.kind === 'topic')); assert.equal(chains[0].crossesServices, true);
});

test('BUDGETS: each cap stops its own step and is named in truncated; nothing is silently dropped', () => {
  const g = buildServiceChainGraph([web(), billing(), lib(), search()], { tenant: 't1', budgets: { maxRepos: 2 } });
  assert.deepEqual(g.truncated, ['maxRepos']); assert.equal(new Set(g.nodes.map((n) => n.repo).filter(Boolean)).size <= 2, true);
  assert.ok(buildServiceChainGraph([web(), billing(), lib()], { tenant: 't1', budgets: { maxNodes: 3 } }).truncated.includes('maxNodes'));
  assert.ok(buildServiceChainGraph([web(), billing(), lib()], { tenant: 't1', budgets: { maxEdges: 2 } }).truncated.includes('maxEdges'));
  const full = buildServiceChainGraph([web(), billing(), lib()], { tenant: 't1', budgets: { maxDepth: 3 } });
  const r = findChains(full, { fromRepo: 'web' }); assert.equal(r.chains.length, 0); assert.deepEqual(r.truncated, ['maxDepth']);
  const many = findChains(buildServiceChainGraph([web(), billing(), lib()], { tenant: 't1', budgets: { maxChains: 0 } }), { fromRepo: 'web' });
  assert.deepEqual(many.truncated, ['maxChains']);
  assert.deepEqual(buildServiceChainGraph([web(), billing(), lib()], { tenant: 't1' }).truncated, []);
  assert.equal(DEFAULT_BUDGETS.maxDepth, 12); assert.ok(Object.isFrozen(DEFAULT_BUDGETS));
});

test('TENANT ISOLATION: another tenant\'s repos are not read, never linked, and ids are tenant-prefixed', () => {
  const foreign = { ...search(), id: 'billing-x', tenant: 't2', service: 'billing', routes: [{ method: 'POST', path: '/charge', handler: 'x.charge' }], functions: [{ qid: 'x.charge', sinks: [{ kind: 'sql-injection' }] }] };
  const g = buildServiceChainGraph([web(), billing(), lib(), foreign], { tenant: 't1' });
  assert.deepEqual(g.refusedOtherTenant, ['billing-x']);
  assert.ok(g.nodes.every((n) => n.id.startsWith('t1:')));
  assert.equal(findChains(g, { sinkKind: 'sql-injection' }).chains.length, 0, 'the other tenant\'s service of the same name is not a target');
  const only = buildServiceChainGraph([foreign], { tenant: 't1' });
  assert.equal(only.nodes.length, 0); assert.deepEqual(only.refusedOtherTenant, ['billing-x']);
  assert.throws(() => buildServiceChainGraph([web()], {}), /tenant is required/);
  assert.equal(JSON.stringify(g).includes('x.charge'), false, 'nothing of the other tenant appears in the output');
});

test('deterministic: the same facts give the same graph and chains', () => {
  const a = JSON.stringify(findChains(buildServiceChainGraph([web(), billing(), lib(), search()], { tenant: 't1' })));
  const b = JSON.stringify(findChains(buildServiceChainGraph([search(), lib(), billing(), web()], { tenant: 't1' })));
  assert.equal(a, b);
});
