// X-303: correlate runtime observations with static boundaries. Sampled, stale
// and missing observations are reported separately, observed coverage never
// implies complete traffic coverage, and imports are sanitized, environment
// isolated, de-duplicated and bounded.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  importTraceLines, mergeObservationSets, correlateObservations, applyCorrelation, normalizePath, eventCountBand,
  exportObservationSet, parseObservationSet, TRACE_LIMITS, DEFAULT_STALE_AFTER_MS, CORRELATION_RULES, OBSERVATION_SET_SCHEMA,
} from '../../src/lineage/deployment/trace-correlation.js';
import { validateBoundaryGraph, buildBoundaryGraph, nodeIdOf } from '../../src/lineage/deployment/boundary-graph.js';
import { ingestOne, ingestText, nodeByName, edgesOf } from './helpers.js';

const NOW = '2026-03-10T00:00:00Z';
const jl = (...recs) => recs.map(r => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n');
const base = (over = {}) => ({ ts: '2026-03-09T10:00:00Z', environment: 'prod', source: { service: 'payments/api', tenant: 'acme' }, destination: { service: 'payments/ledger' }, outcome: 'ok', ...over });

function graph() { return ingestOne('k8s-payments/manifests.yaml', { repository: 'payments', as: 'm.yaml' }); }
function imp(text, opts = {}) {
  const r = importTraceLines(text, { environment: 'prod', ...opts });
  assert.equal(r.status, 'ok', r.reason);
  return r.set;
}
const idOf = (g, name, kind) => nodeByName(g, name, kind).id;

// ------------------------------------------------------------------ AC01

test('[X-303.AC01] a trace between two services correlates by the exact-pair rule and corroborates the static edge', () => {
  const g = graph();
  const c = correlateObservations(g, imp(jl(base(), base({ ts: '2026-03-09T11:00:00Z' }))), { now: NOW });
  assert.equal(c.status, 'ok');
  const e = c.edges.find(x => x.relation === 'calls');
  assert.equal(e.provenance, 'runtime-observation');
  assert.equal(e.pathState, 'runtime-supported');
  assert.equal(e.attrs.rule, 'R1');
  assert.equal(e.from, idOf(g, 'payments/api'));
  assert.equal(e.to, idOf(g, 'payments/ledger'));
  assert.equal(Date.parse(e.observationInterval.start), Date.parse('2026-03-09T10:00:00Z'));
  assert.equal(Date.parse(e.observationInterval.end), Date.parse('2026-03-09T11:00:00Z'));
  const staticAllow = edgesOf(g, 'network-allows', { from: 'payments/api', to: 'payments/ledger' })[0];
  assert.deepEqual(c.corroboration[e.id].corroborates, [staticAllow.id]);
  assert.deepEqual(Object.keys(CORRELATION_RULES), ['R1', 'R2', 'R3', 'R4']);
});

test('[X-303.AC01] a request on a public route correlates through the static route chain to the workload', () => {
  const g = graph();
  const c = correlateObservations(g, imp(jl(base({ source: {}, route: { method: 'GET', host: 'pay.example.com', path: '/v1/charges/123?token=abc' }, destination: { service: 'payments/api', tenant: 'acme' } }))), { now: NOW });
  const hops = c.edges.filter(e => e.attrs.rule === 'R2');
  assert.equal(hops.length, 2);
  const names = new Map(g.nodes.map(n => [n.id, n.name]));
  assert.deepEqual(hops.map(h => `${names.get(h.from)} -> ${names.get(h.to)}`).sort(), [
    'ingress/payments/public:pay.example.com/v1 -> svc/payments/api', 'svc/payments/api -> payments/api']);
  assert.ok(hops.every(h => h.provenance === 'runtime-observation' && h.relation === 'routes-to'));
});

test('[X-303.AC01] the source identity must match the configured identity; a mismatch is a conflict, not a corroboration', () => {
  const g = graph();
  const ok = correlateObservations(g, imp(jl(base({ source: { service: 'payments/api', tenant: 'acme', identity: 'payments-sa' } }))), { now: NOW });
  assert.ok(ok.edges.some(e => e.relation === 'assumes' && e.attrs.rule === 'R3'));
  const bad = correlateObservations(g, imp(jl(base({ source: { service: 'payments/api', tenant: 'acme', identity: 'someone-else' } }))), { now: NOW });
  assert.ok(!bad.edges.some(e => e.relation === 'assumes'));
  assert.ok(bad.conflicts.some(x => x.code === 'identity-mismatch' && x.observedIdentity === 'someone-else'));
});

test('[X-303.AC01] a naming convention produces an INFERRED edge, kept apart from observed edges', () => {
  const g = graph();
  const c = correlateObservations(g, imp(jl(base({ destination: { host: 'ledger.payments.svc.cluster.local' } }), base({ destination: { service: 'ledger' } }))), { now: NOW });
  const inferred = c.edges.filter(e => e.provenance === 'inferred');
  assert.equal(inferred.length, 2);
  assert.ok(inferred.every(e => e.attrs.rule === 'R4' && e.confidence === 'low' && e.pathState === 'possible' && e.observationInterval === null));
  assert.deepEqual(inferred.map(e => e.attrs.basis).sort(), ['dns-name', 'unqualified-name']);
  assert.ok(!c.edges.some(e => e.provenance === 'runtime-observation' && e.relation === 'calls'), 'a convention is not an observation');
});

test('[X-303.AC01] folding a correlation into the graph keeps static edges and adds distinguishable observed edges', () => {
  const g = graph();
  const c = correlateObservations(g, imp(jl(base(), base({ destination: { host: 'ledger.payments.svc.cluster.local' } }))), { now: NOW });
  const r = applyCorrelation(g, c);
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  assert.equal(validateBoundaryGraph(r.graph).ok, true);
  const staticBefore = g.edges.map(e => e.id).sort();
  assert.deepEqual(r.graph.edges.filter(e => e.provenance === 'static-config').map(e => e.id).sort(), staticBefore);
  assert.deepEqual([...new Set(r.graph.edges.map(e => e.provenance))].sort(), ['inferred', 'runtime-observation', 'static-config']);
});

test('[X-303.AC01] unmatched, ambiguous, cross-tenant and non-ok observations create no supported edge', () => {
  const two = ingestText([{ path: 'a.yaml', text: [
    'apiVersion: apps/v1', 'kind: Deployment', 'metadata: {name: web, namespace: a}', 'spec: {template: {metadata: {labels: {app: web}}, spec: {containers: []}}}', '---',
    'apiVersion: apps/v1', 'kind: Deployment', 'metadata: {name: web, namespace: b}', 'spec: {template: {metadata: {labels: {app: web}}, spec: {containers: []}}}', '---',
    'apiVersion: apps/v1', 'kind: Deployment', 'metadata: {name: db, namespace: a}', 'spec: {template: {metadata: {labels: {app: db}}, spec: {containers: []}}}',
  ].join('\n') }]);
  const rec = (over) => ({ ts: '2026-03-09T10:00:00Z', environment: 'prod', source: { service: 'a/db' }, destination: { service: 'web' }, ...over });
  const c = correlateObservations(two, imp(jl(rec({}))), { now: NOW, createObservedOnlyNodes: false });
  assert.equal(c.edges.length, 0, 'an unqualified name that fits two services is not resolved');
  assert.ok(c.unmatched.some(u => u.reason === 'ambiguous-service-name'));

  const g = graph();
  const tenant = correlateObservations(g, imp(jl(base({ source: { service: 'payments/api', tenant: 'globex' } }))), { now: NOW, createObservedOnlyNodes: false });
  assert.equal(tenant.edges.length, 0, 'api belongs to tenant acme, not globex');

  const denied = correlateObservations(g, imp(jl(base({ outcome: 'denied' }), base({ outcome: 'error', ts: '2026-03-09T12:00:00Z' }))), { now: NOW });
  assert.equal(denied.edges.length, 0);
  assert.equal(denied.outcomes.denied, 1);
  assert.equal(denied.coverage.deniedObservedStaticEdgeIds.length, 1, 'the static edge a denial was seen on is listed');

  const empty = importTraceLines(jl(base({ source: {}, destination: {}, route: { method: 'GET' } })), { environment: 'prod' }).set;
  assert.equal(empty.observations.length, 0, 'a record with no topology field is rejected on import');
  assert.equal(empty.stats.rejectReasons['no-topology-fields'], 1);
  const nowhere = correlateObservations(g, imp(jl(base({ destination: { service: 'payments/ghost' } }))), { now: NOW, createObservedOnlyNodes: false });
  assert.equal(nowhere.edges.length, 0);
  assert.deepEqual(nowhere.unmatched.map(u => u.reason), ['no-service-node']);
});

test('[X-303.AC01] a service seen at runtime that static configuration does not know is an unresolved node, not a resolved one', () => {
  const g = graph();
  const c = correlateObservations(g, imp(jl(base({ destination: { service: 'payments/ghost' } }))), { now: NOW });
  assert.equal(c.observedNodes.length, 1);
  assert.equal(c.observedNodes[0].resolved, false);
  const r = applyCorrelation(g, c);
  assert.equal(r.ok, true, JSON.stringify(r.errors));
  assert.equal(nodeByName(r.graph, 'payments/ghost').resolved, false);
  const e = edgesOf(r.graph, 'calls', { to: 'payments/ghost' })[0];
  assert.equal(e.pathState, 'runtime-supported', 'it was observed, and that is all that is claimed');
});

test('[X-303.AC01] observation windows: the edge interval is exactly the first to last observation, widened by merging', () => {
  const g = graph();
  const c = correlateObservations(g, imp(jl(base({ ts: '2026-03-01T00:00:00Z' }), base({ ts: '2026-03-05T12:30:00Z' }), base({ ts: '2026-03-03T00:00:00Z', sampled: true }))), { now: NOW });
  const e = c.edges.find(x => x.relation === 'calls' && x.provenance === 'runtime-observation');
  assert.equal(new Date(e.observationInterval.start).toISOString(), '2026-03-01T00:00:00.000Z');
  assert.equal(new Date(e.observationInterval.end).toISOString(), '2026-03-05T12:30:00.000Z');
});

// ------------------------------------------------------------------ AC02

test('[X-303.AC02] observed coverage is never complete: not with fresh unsampled data, not with every static edge observed', () => {
  const g = ingestText([{ path: 'c.yml', text: 'services:\n  a: {depends_on: [b]}\n  b: {}\n' }]);
  const set = imp(jl({ ts: '2026-03-09T10:00:00Z', environment: 'prod', source: { service: 'a' }, destination: { service: 'b' }, sampled: false, count: 5000 }));
  const c = correlateObservations(g, set, { now: NOW });
  assert.equal(c.staleAfterMs, DEFAULT_STALE_AFTER_MS, 'the freshness threshold is stated, not implicit');
  assert.deepEqual(c.coverage.missingStaticEdgeIds, [], 'every static edge was seen');
  assert.equal(c.coverage.trafficCoverage, 'not-established');
  assert.ok(c.edges.every(e => e.completeness !== 'complete'));
  assert.equal(c.edges.find(e => e.provenance === 'runtime-observation').completeness, 'unknown');
  const r = applyCorrelation(g, c);
  assert.ok(r.graph.edges.every(e => e.completeness !== 'complete'));
});

test('[X-303.AC02] sampled, stale and missing observations are reported separately', () => {
  const g = ingestText([{ path: 'c.yml', text: 'services:\n  a: {depends_on: [b, c, d]}\n  b: {}\n  c: {}\n  d: {}\n' }]);
  const o = (dst, over) => ({ ts: '2026-03-09T10:00:00Z', environment: 'prod', source: { service: 'a' }, destination: { service: dst }, ...over });
  const c = correlateObservations(g, imp(jl(o('b', { sampled: true }), o('c', { ts: '2026-01-01T00:00:00Z' }))), { now: NOW });
  const idTo = (dst) => c.edges.find(e => e.provenance === 'runtime-observation' && e.to === idOf(g, dst)).id;
  assert.deepEqual(c.coverage.sampled, [idTo('b')]);
  assert.deepEqual(c.coverage.stale, [idTo('c')]);
  assert.deepEqual(c.coverage.observed, []);
  const missing = g.edges.filter(e => e.relation === 'depends-on' && e.to === idOf(g, 'd')).map(e => e.id);
  assert.deepEqual(c.coverage.missingStaticEdgeIds, missing);
  assert.equal(c.edges.find(e => e.id === idTo('b')).completeness, 'sampled');
  assert.equal(c.edges.find(e => e.id === idTo('c')).attrs.stale, true);
  assert.equal(c.edges.find(e => e.id === idTo('c')).confidence, 'medium');
  // fresh and unsampled lands in `observed` only
  const fresh = correlateObservations(g, imp(jl(o('b', {}))), { now: NOW });
  assert.equal(fresh.coverage.observed.length, 1);
  assert.deepEqual([fresh.coverage.sampled, fresh.coverage.stale], [[], []]);
});

test('[X-303.AC02] a missing observation never blocks a path, and a block never comes from absence', () => {
  const g = ingestText([{ path: 'c.yml', text: 'services:\n  a: {depends_on: [b]}\n  b: {}\n' }]);
  const empty = imp('');
  const c = correlateObservations(g, empty, { now: NOW });
  const r = applyCorrelation(g, c);
  assert.ok(r.graph.edges.filter(e => e.relation === 'depends-on').every(e => e.pathState === 'possible'));
  assert.equal(c.coverage.missingStaticEdgeIds.length, 1);
  // and the contract cannot express it either
  const bad = structuredClone(r.graph);
  bad.edges.find(e => e.relation === 'depends-on').pathState = 'blocked';
  assert.equal(validateBoundaryGraph(bad).ok, false);
});

test('[X-303.AC02] an observation over a path static configuration blocks is a conflict, listed, not hidden', () => {
  const g = ingestText([{ path: 'p.json', text: JSON.stringify({ format_version: '1.2', resource_changes: [
    { address: 'aws_lambda_function.a', type: 'aws_lambda_function', change: { actions: ['create'], after: { function_name: 'a', role: 'arn:aws:iam::1:role/r' }, after_unknown: {} } },
  ] }) }, { path: 'c.yml', text: 'services:\n  x: {}\n  y: {}\n' }]);
  // hand-build a blocked network path between two services
  const x = g.nodes.find(n => n.name === 'x'), y = g.nodes.find(n => n.name === 'y');
  const built = buildBoundaryGraph({ nodes: g.nodes, gaps: g.gaps, sources: g.sources, edges: [...g.edges, {
    relation: 'network-denies', from: x.id, to: y.id, environment: 'prod', tenant: null, effect: 'deny', provenance: 'static-config', confidence: 'high', pathState: 'blocked',
    observationInterval: null, completeness: null, sourceRevision: null, source: g.sources[1] ?? g.sources[0], discriminator: null, crossRepo: null, attrs: {},
  }] });
  assert.equal(built.ok, true, JSON.stringify(built.errors));
  const c = correlateObservations(built.graph, imp(jl({ ts: '2026-03-09T10:00:00Z', environment: 'prod', source: { service: 'x' }, destination: { service: 'y' } })), { now: NOW });
  assert.equal(c.conflicts[0].code, 'observed-over-blocked-path');
});

test('[X-303.AC02] the edge count is a band, never a raw number', () => {
  assert.deepEqual([1, 2, 10, 11, 100, 101, 1000, 1001, 99999].map(eventCountBand), ['1', '2-10', '2-10', '11-100', '11-100', '101-1k', '101-1k', '1k+', '1k+']);
  const g = graph();
  const c = correlateObservations(g, imp(jl(base({ count: 4321 }))), { now: NOW });
  const e = c.edges.find(x => x.relation === 'calls');
  assert.equal(e.attrs.countBand, '1k+');
  assert.ok(!JSON.stringify(c.edges).includes('4321'));
});

// ------------------------------------------------------------------ AC03

const SECRETS = ['Bearer abc123SECRET', ('sk_' + 'live_4eC39HqLyjWDarjtT1zdp7dc'), 'hunter2-password', 'session=deadbeefcafe', 'card=4111111111111111', 'jwtpayloadvalue', 'user@example.com'];

test('[X-303.AC03] credentials and payloads are removed on import, never stored, and counted', () => {
  const dirty = {
    ts: '2026-03-09T10:00:00Z', environment: 'prod',
    source: { service: 'payments/api', authorization: SECRETS[0], cookie: SECRETS[3] },
    destination: { service: 'payments/ledger', body: { card: SECRETS[4] } },
    route: { method: 'POST', host: 'pay.example.com', path: `/v1/charges/4111111111111111/${SECRETS[1]}?token=${SECRETS[2]}#frag`, headers: { Authorization: SECRETS[0] } },
    headers: { Authorization: SECRETS[0], 'X-Api-Key': SECRETS[1] }, requestBody: { email: SECRETS[6] }, token: SECRETS[2], message: SECRETS[5],
  };
  const set = imp(jl(dirty));
  const text = JSON.stringify(set);
  for (const s of SECRETS) assert.ok(!text.includes(s), `leaked ${s}`);
  assert.ok(!/authorization|cookie|requestBody|headers|X-Api-Key|token|message/i.test(text.replace(/"tenant"/g, '')), 'field names are not kept either');
  assert.equal(set.observations.length, 1);
  assert.equal(set.observations[0].route.path, '/v1/charges/:id/:id');
  assert.ok(set.sanitization.credentialShaped >= 3 && set.sanitization.payloadShaped >= 4 && set.sanitization.recordsWithRemovedFields === 1);
  assert.equal(set.sanitization.removedFieldCount, set.sanitization.credentialShaped + set.sanitization.payloadShaped + set.sanitization.other);
  // sanitized data still correlates
  const c = correlateObservations(graph(), set, { now: NOW });
  assert.ok(c.edges.some(e => e.attrs.rule === 'R1'));
});

test('[X-303.AC03] a value that is kept but is not identifier shaped rejects the whole record', () => {
  const bad = [
    base({ source: { service: 'payments api; drop table' } }), base({ destination: { host: 'ledger payments' } }), base({ destination: { port: 99999 } }),
    base({ route: { method: 'GET\r\nX: y' } }), base({ ts: 'yesterday' }), base({ count: 1.5 }), base({ outcome: 'maybe' }), base({ environment: undefined }),
    'not json', '[1,2]', base({ source: 'payments/api' }), base({ source: {}, destination: {} }),
  ];
  const r = importTraceLines(jl(...bad), { environment: 'prod' });
  assert.equal(r.status, 'ok');
  assert.equal(r.set.observations.length, 0);
  assert.equal(r.set.stats.rejected, bad.length);
  assert.ok(Object.keys(r.set.stats.rejectReasons).length >= 8);
  assert.equal(normalizePath('/a/b?x=1'), '/a/b');
  assert.equal(normalizePath('/users/12345/orders/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'), '/users/:id/orders/:id');
  assert.equal(normalizePath('no-leading-slash'), null);
  assert.equal(normalizePath(`/${'a/'.repeat(300)}`) === null || normalizePath(`/${'a/'.repeat(300)}`).length <= 200, true);
});

test('[X-303.AC03] environment isolation: other-environment records are not imported, not relabelled, and never correlate', () => {
  const r = importTraceLines(jl(base(), base({ environment: 'staging' }), base({ environment: 'staging', source: { service: 'payments/api' } })), { environment: 'prod' });
  assert.equal(r.set.observations.length, 1);
  assert.equal(r.set.stats.rejectedEnvironment, 2);
  assert.ok(r.set.observations.every(o => o.environment === 'prod'));
  // a graph that exists only in staging is untouched by a prod trace
  const stg = ingestOne('k8s-payments/manifests.yaml', { environment: 'staging', repository: 'payments', as: 'm.yaml' });
  const c = correlateObservations(stg, r.set, { now: NOW, createObservedOnlyNodes: false });
  assert.equal(c.edges.length, 0);
  assert.ok(c.unmatched.length >= 1);
  // merging across environments is refused
  const prod = imp(jl(base()));
  const staging = importTraceLines(jl(base({ environment: 'staging' })), { environment: 'staging' }).set;
  const m = mergeObservationSets(prod, staging);
  assert.equal(m.status, 'environment-mismatch');
  assert.equal(m.set, null);
  // and an import without an environment is refused
  assert.equal(importTraceLines(jl(base()), {}).status, 'invalid-input');
});

test('[X-303.AC03] duplicates merge: the same observation repeated is one observation with a summed count and a widened interval', () => {
  const set = imp(jl(base({ ts: '2026-03-01T00:00:00Z', count: 3 }), base({ ts: '2026-03-09T00:00:00Z' }), base({ ts: '2026-03-04T00:00:00Z' })));
  assert.equal(set.observations.length, 1);
  assert.equal(set.observations[0].eventCount, 5);
  assert.equal(set.observations[0].firstObservedAt, '2026-03-01T00:00:00Z');
  assert.equal(set.observations[0].lastObservedAt, '2026-03-09T00:00:00Z');
  assert.equal(set.stats.duplicates, 2);
  // sampled and unsampled sightings of the same path are different observations
  assert.equal(imp(jl(base(), base({ sampled: true }))).observations.length, 2);
  // merging a later import of the same observation does not duplicate it either
  const merged = mergeObservationSets(imp(jl(base({ count: 2 }))), imp(jl(base({ ts: '2026-03-09T12:00:00Z', count: 4 }))));
  assert.equal(merged.status, 'ok');
  assert.equal(merged.set.observations.length, 1);
  assert.equal(merged.set.observations[0].eventCount, 6);
});

test('[X-303.AC03] storage is bounded: observations, input bytes, line length and line count', () => {
  const many = Array.from({ length: 50 }, (_, i) => base({ ts: `2026-03-09T10:${String(i).padStart(2, '0')}:00Z`, destination: { service: `svc/n${i}` } }));
  const r = importTraceLines(jl(...many), { environment: 'prod', limits: { maxObservations: 10 } });
  assert.equal(r.set.observations.length, 10);
  assert.equal(r.set.stats.evicted, 40);
  const newest = new Set(many.slice(-10).map(o => o.destination.service));
  assert.ok(r.set.observations.every(o => newest.has(o.to.service)), 'the newest are kept');

  const big = importTraceLines('x'.repeat(5000), { environment: 'prod', limits: { maxInputBytes: 1000 } });
  assert.equal(big.status, 'limit-exceeded');
  assert.equal(big.set, null);

  const long = importTraceLines(jl(base({ route: { path: `/${'a'.repeat(9000)}` } }), base()), { environment: 'prod' });
  assert.equal(long.set.stats.rejectReasons['line-too-long'], 1);
  assert.equal(long.set.observations.length, 1);

  const lines = importTraceLines(jl(...many), { environment: 'prod', limits: { maxLines: 5 } });
  assert.equal(lines.set.stats.truncatedLines, true);
  assert.equal(lines.set.stats.linesRead, 5);

  const merged = mergeObservationSets(imp(jl(...many.slice(0, 8))), imp(jl(...many.slice(8, 16))), { maxObservations: 10 });
  assert.equal(merged.set.observations.length, 10);
  assert.equal(merged.set.stats.evicted, 6);
  assert.ok(Buffer.byteLength(exportObservationSet(merged.set)) < 20_000);
  assert.equal(TRACE_LIMITS.maxObservations, 2000);
});

test('[X-303.AC03] a stored observation set is read back closed-world, bounded and digest-checked', () => {
  const set = imp(jl(base(), base({ destination: { service: 'payments/other' } })));
  const text = exportObservationSet(set);
  const back = parseObservationSet(text);
  assert.equal(back.status, 'ok');
  assert.equal(exportObservationSet(back.set), text);
  const doc = JSON.parse(text);
  const edit = (fn) => { const c = structuredClone(doc); fn(c); return parseObservationSet(JSON.stringify(c)); };
  assert.equal(edit(c => { c.observations[0].eventCount = 9; }).status, 'invalid', 'edited count');
  assert.equal(edit(c => { c.observations[0].headers = { a: 1 }; }).status, 'invalid', 'extra field on an observation');
  assert.equal(edit(c => { c.extra = 1; }).status, 'invalid', 'extra field on the set');
  assert.equal(edit(c => { c.observations[0].environment = 'staging'; }).status, 'invalid', 'mixed environments');
  assert.equal(edit(c => { c.observations[0].to.service = 'has spaces here'; }).status, 'invalid');
  assert.equal(edit(c => { c.digest = `sha256:${'0'.repeat(64)}`; }).status, 'invalid');
  assert.equal(parseObservationSet(text, { maxObservations: 1 }).status, 'invalid', 'over the cap');
  assert.equal(parseObservationSet('x'.repeat(100), { maxBytes: 10 }).status, 'malformed');
  assert.equal(parseObservationSet('{').status, 'malformed');
  assert.equal(doc.schema, OBSERVATION_SET_SCHEMA);
});

test('[X-303.AC03] correlation needs an explicit clock and a valid set; it reads no file and no network', () => {
  const g = graph();
  assert.equal(correlateObservations(g, imp(jl(base())), {}).status, 'invalid-input');
  assert.equal(correlateObservations(g, { schema: 'nope' }, { now: NOW }).status, 'invalid-input');
  const realFetch = globalThis.fetch;
  let called = 0;
  globalThis.fetch = () => { called += 1; throw new Error('no network'); };
  try { correlateObservations(g, imp(jl(base())), { now: NOW }); } finally { globalThis.fetch = realFetch; }
  assert.equal(called, 0);
  assert.equal(nodeIdOf({ kind: 'service', name: 'x', environment: 'prod', tenant: null }).startsWith('bnode:'), true);
});
