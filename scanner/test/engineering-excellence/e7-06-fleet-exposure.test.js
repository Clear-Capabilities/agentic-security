// E7-06: explainable fleet ranking: impact, exposure, exploitability, confidence and coverage are separate; negative controls for stale runtime evidence,
// non-matching dependencies and the wrong service.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildServiceChainGraph, findChains } from '../../src/posture/fleet/service-chain-graph.js';
import { PRIORITY_RULES, rankFleetExposure } from '../../src/posture/fleet/exposure-ranking.js';

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-06-'));
after(() => fs.rmSync(ROOT, { recursive: true, force: true }));
const dir = (id, pkg) => { const d = path.join(ROOT, id); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify(pkg)); return d; };
const NOW = Date.parse('2026-06-01T00:00:00Z'); const iso = (d) => new Date(NOW - d * 86400000).toISOString();

function fleet({ libVersion = '1.2.3' } = {}) {
  return [
    { id: 'web', tenant: 't', service: 'web', path: dir('web', { name: 'web-app' }), routes: [{ method: 'POST', path: '/checkout', handler: 'web.checkout', classification: 'payment-card' }], functions: [{ qid: 'web.checkout' }, { qid: 'web.charge' }], calls: [{ from: 'web.checkout', to: 'web.charge' }], outboundCalls: [{ from: 'web.charge', service: 'billing', method: 'POST', path: '/charge' }] },
    { id: 'billing', tenant: 't', service: 'billing', path: dir('billing', { name: 'billing-svc', dependencies: { 'pay-lib': '^1.2.0' } }), routes: [{ method: 'POST', path: '/charge', handler: 'billing.charge', classification: 'payment-card' }], functions: [{ qid: 'billing.charge' }], libraryUses: [{ package: 'pay-lib', symbol: 'render', from: 'billing.charge' }], dependencyVersions: { 'pay-lib': libVersion } },
    { id: 'pay-lib', tenant: 't', path: dir('pay-lib', { name: 'pay-lib' }), exports: [{ package: 'pay-lib', symbol: 'render', qid: 'paylib.render' }], functions: [{ qid: 'paylib.render', sinks: [{ kind: 'command-injection' }] }], advisories: [{ lt: '1.3.0' }] },
    { id: 'search', tenant: 't', service: 'search', path: dir('search', { name: 'search-svc' }), routes: [{ method: 'POST', path: '/q', handler: 'search.q' }], functions: [{ qid: 'search.q', sinks: [{ kind: 'sql-injection' }] }] },
    { id: 'reports', tenant: 't', service: 'reports', path: dir('reports', { name: 'reports-svc' }), routes: [{ method: 'GET', path: '/r', handler: 'reports.r' }], functions: [{ qid: 'reports.r' }, { qid: 'reports.orphan', sinks: [{ kind: 'ssrf' }] }] },
  ];
}
const SERVICES = { web: { exposure: 'public' }, billing: { exposure: 'internal' }, search: { exposure: 'internal' }, reports: { exposure: 'internal' } };
const F = (over) => ({ id: 'f', severity: 'high', proofTier: 'taint-proven', scanHealth: 'complete', ...over });
const LIB = (over = {}) => F({ id: 'lib-cmd', repo: 'pay-lib', sinkRef: { repo: 'pay-lib', qid: 'paylib.render', kind: 'command-injection' }, viaLibrary: { package: 'pay-lib' }, ...over });
const SQL = (over = {}) => F({ id: 'search-sql', repo: 'search', sinkRef: { repo: 'search', qid: 'search.q', kind: 'sql-injection' }, ...over });
const ORPHAN = (over = {}) => F({ id: 'reports-ssrf', repo: 'reports', sinkRef: { repo: 'reports', qid: 'reports.orphan', kind: 'ssrf' }, ...over });
const rank = (findings, opts = {}, libVersion) => { const g = buildServiceChainGraph(fleet({ libVersion }), { tenant: 't' }); const chains = findChains(g).chains; return rankFleetExposure({ graph: g, chains, findings, services: SERVICES, now: NOW, ...opts }); };
const by = (r, id) => r.ranked.find((x) => x.id === id);

test('the ranking keeps five dimensions apart, and every finding says why for each of them', () => {
  const r = rank([LIB({ proofTier: 'execution-proven' }), SQL(), ORPHAN()], { fleet: ['web', 'billing', 'pay-lib', 'search', 'reports'], scanned: ['web', 'billing', 'pay-lib', 'search', 'reports'] });
  const lib = by(r, 'lib-cmd');
  for (const x of r.ranked) for (const d of ['impact', 'exposure', 'exploitability', 'confidence', 'coverage']) assert.ok(x.factors.some((f) => f.dimension === d && f.because.length > 5), `${x.id} explains ${d}`);
  assert.deepEqual(Object.keys(lib.tiers), ['impact', 'exposure', 'exploitability', 'confidence']); assert.ok(!('score' in lib) && !('risk' in lib), 'no single opaque number');
  assert.equal(lib.tiers.exposure, 'public', 'reached from web, a public service, through billing and the library'); assert.equal(lib.tiers.impact, 'critical', 'high severity plus card data on the path'); assert.equal(lib.tiers.exploitability, 'high');
  assert.equal(lib.priority, 'P0'); assert.equal(lib.rule, 'P0-proven-public-sensitive'); assert.equal(lib.entryRoute, 'POST /checkout');
  assert.deepEqual(lib.coverage.reposOnPath, ['billing', 'pay-lib', 'web']); assert.equal(lib.coverage.complete, true);
  assert.ok(PRIORITY_RULES.find((x) => x.id === lib.rule), 'the rule that decided it is in the published table');
});

test('ORDER: priority first, then the tiers in a fixed order, then id; the result does not depend on input order', () => {
  const set = [SQL(), ORPHAN(), LIB({ proofTier: 'execution-proven' }), SQL({ id: 'search-sql-2' }), SQL({ id: 'search-sql-0', severity: 'critical' })];
  const a = rank(set).ranked.map((x) => x.id); const b = rank([...set].reverse()).ranked.map((x) => x.id);
  assert.deepEqual(a, b); assert.equal(a[0], 'lib-cmd');
  assert.ok(a.indexOf('search-sql-0') < a.indexOf('search-sql'), 'a critical outranks a high on the same path'); assert.ok(a.indexOf('search-sql') < a.indexOf('search-sql-2'), 'ties end on id');
  assert.ok(a.indexOf('reports-ssrf') > a.indexOf('search-sql'), 'a sink no route reaches comes after reachable ones');
});

test('NEGATIVE CONTROL, WRONG SERVICE: a sink in a service the path never reaches gets no exposure, however severe', () => {
  const r = rank([ORPHAN({ severity: 'critical', proofTier: 'execution-proven' })]); const o = by(r, 'reports-ssrf');
  assert.equal(o.tiers.exposure, 'none'); assert.equal(o.paths, 0); assert.equal(o.priority, 'P4'); assert.equal(o.rule, 'P4-not-reached');
  assert.match(o.factors.find((f) => f.dimension === 'exposure').because, /no path from any route/);
  const unknown = by(rank([F({ id: 'nowhere' })]), 'nowhere'); assert.equal(unknown.tiers.exposure, 'unknown'); assert.match(unknown.factors.find((f) => f.dimension === 'exposure').because, /does not say which sink/);
  // search's sink is reachable from search's own route, which is internal, not from web's public route
  const s = by(rank([SQL()]), 'search-sql'); assert.equal(s.tiers.exposure, 'internal'); assert.equal(s.entryRoute, 'POST /q');
});

test('NEGATIVE CONTROL, NON-MATCHING DEPENDENCY: a library finding does not apply to a path whose dependency is outside the advisory range or is another package', () => {
  const ok = rank([LIB()]); assert.equal(ok.excluded.length, 0); assert.equal(by(ok, 'lib-cmd').paths, 2, 'web\'s checkout route and billing\'s own charge route both reach it');
  const safe = rank([LIB()], {}, '1.3.1');
  assert.equal(safe.ranked.length, 0); assert.deepEqual(safe.excluded.map((e) => e.id), ['lib-cmd']); assert.match(safe.excluded[0].reason, /outside the advisory range/);
  assert.equal(safe.summary.excluded, 1);
  const other = rank([LIB({ viaLibrary: { package: 'other-lib' } })]); assert.deepEqual(other.excluded.map((e) => e.id), ['lib-cmd']); assert.match(other.excluded[0].reason, /does not use other-lib/);
});

test('NEGATIVE CONTROL, STALE RUNTIME EVIDENCE: fresh corroborated evidence raises exploitability one tier; stale, future-dated and unattested evidence raise nothing and say so', () => {
  const base = SQL(); const mk = (runtime) => by(rank([SQL({ runtime })]), 'search-sql');
  const none = mk(undefined); const fresh = mk({ observedAt: iso(2), corroboration: 'corroborated' }); const stale = mk({ observedAt: iso(40), corroboration: 'corroborated' });
  const future = mk({ observedAt: new Date(NOW + 5 * 86400000).toISOString(), corroboration: 'corroborated' }); const unattested = mk({ observedAt: iso(2), corroboration: 'unattested' });
  assert.equal(none.tiers.exploitability, 'medium'); assert.equal(fresh.tiers.exploitability, 'high'); assert.match(fresh.factors.find((f) => /raises it one tier/.test(f.because)).because, /2 day/);
  for (const [name, x] of [['stale', stale], ['future', future], ['unattested', unattested]]) assert.equal(x.tiers.exploitability, 'medium', `${name} evidence does not raise it`);
  assert.equal(stale.factors.find((f) => f.stale).because.includes('stale'), true); assert.match(future.factors.find((f) => /future/.test(f.because)).because, /ignored/);
  assert.match(unattested.factors.find((f) => /not tied to this build/.test(f.because)).because, /noted, not counted/);
  assert.ok(base.id); assert.equal(rank([SQL({ runtime: { observedAt: iso(13), corroboration: 'corroborated' } })]).ranked[0].tiers.exploitability, 'high', 'inside the window'); assert.equal(rank([SQL({ runtime: { observedAt: iso(15), corroboration: 'corroborated' } })]).ranked[0].tiers.exploitability, 'medium', 'just outside it');
  assert.equal(rank([SQL({ runtime: { observedAt: iso(15), corroboration: 'corroborated' } })], { freshnessDays: 30 }).ranked[0].tiers.exploitability, 'high', 'the window is a parameter');
});

test('COVERAGE is reported beside the ranking and never changes it: an unscanned repository on the path or a partial scan is a caveat, not a demotion', () => {
  const complete = by(rank([LIB({ proofTier: 'execution-proven' })], { fleet: ['web', 'billing', 'pay-lib'], scanned: ['web', 'billing', 'pay-lib'] }), 'lib-cmd');
  const partial = by(rank([LIB({ proofTier: 'execution-proven', scanHealth: 'partial' })], { fleet: ['web', 'billing', 'pay-lib'], scanned: ['pay-lib'] }), 'lib-cmd');
  assert.equal(complete.coverage.complete, true); assert.equal(partial.coverage.complete, false); assert.deepEqual(partial.coverage.unscannedReposOnPath, ['billing', 'web']);
  assert.equal(partial.priority, complete.priority, 'the same finding keeps its priority'); assert.deepEqual(partial.tiers, complete.tiers);
  assert.match(partial.factors.find((f) => f.dimension === 'coverage').because, /not scanned: billing, web/);
  assert.equal(rank([LIB()], { fleet: ['web', 'billing', 'pay-lib'], scanned: ['web', 'billing', 'pay-lib'] }).summary.incompleteCoverage, 0);
  assert.equal(rank([LIB({ scanHealth: 'partial' })]).summary.incompleteCoverage, 1);
});

test('THE TABLE: every priority is reachable, first match wins, and the last rule catches everything', () => {
  const t = (impact, exposure, exploitability, confidence) => PRIORITY_RULES.find((r) => r.when({ impact, exposure, exploitability, confidence })).priority;
  assert.equal(t(3, 'public', 3, 2), 'P0'); assert.equal(t(4, 'public', 2, 2), 'P0'); assert.equal(t(3, 'public', 2, 1), 'P1'); assert.equal(t(3, 'internal', 3, 1), 'P1');
  assert.equal(t(2, 'internal', 1, 1), 'P2'); assert.equal(t(3, 'unknown', 1, 0), 'P3'); assert.equal(t(1, 'none', 1, 0), 'P4'); assert.equal(t(4, 'none', 3, 3), 'P4', 'severity alone does not make something urgent');
  assert.equal(PRIORITY_RULES.at(-1).when({}), true); assert.ok(Object.isFrozen(PRIORITY_RULES));
  const empty = rankFleetExposure({ graph: { nodes: [], edges: [] }, chains: [], findings: [], now: NOW }); assert.deepEqual(empty.summary, { findings: 0, ranked: 0, excluded: 0, byPriority: { P0: 0, P1: 0, P2: 0, P3: 0, P4: 0 }, incompleteCoverage: 0 });
});
