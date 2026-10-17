// E2-07: static service relationships: observed / inferred / unknown, bounded traversal, nothing called proven.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_HOPS, buildServiceEdges, extractFacts, traceFrom } from '../../src/dataflow/service-edges.js';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildSemanticGraph, validateGraph } from '../../src/ir/semantic-graph.js';

const FILES = {
  'services/gateway/index.js': "const express = require('express');\nconst app = express();\napp.post('/checkout', async (req, res) => {\n  const r = await fetch('http://orders/api/items/42', { method: 'POST' });\n  res.json(await r.json());\n});\n",
  'services/orders/index.js': "const app = require('express')();\nconst db = require('./db');\napp.post('/api/items/:id', async (req, res) => {\n  await producer.send({ topic: 'order.created', messages: [] });\n  await pool.query(\"INSERT INTO orders (id, item) VALUES ($1, $2)\", [1, 2]);\n  res.sendStatus(201);\n});\n",
  'services/billing/worker.js': "consumer.subscribe({ topic: 'order.created' });\nasync function onMessage(m) {\n  await pool.query('SELECT total FROM orders WHERE id = $1', [m.id]);\n  await fetch('http://gateway/notify', { method: 'POST' });\n}\n",
  'services/reporting/job.py': "import requests\ndef run(cur):\n    cur.execute(\"SELECT * FROM orders WHERE day = %s\", (1,))\n",
};
const SERVICES = [{ name: 'gateway', root: 'services/gateway' }, { name: 'orders', root: 'services/orders' }, { name: 'billing', root: 'services/billing' }, { name: 'reporting', root: 'services/reporting' }];
const ev = (g, kind, from, to) => g.edges.find((e) => e.kind === kind && e.from.service === from && e.to.service === to);

test('HTTP: a literal client URL and a matching route are an observed edge, with the route\'s own location', () => {
  const g = buildServiceEdges(FILES, { services: SERVICES });
  const e = ev(g, 'http', 'gateway', 'orders');
  assert.ok(e); assert.equal(e.evidence, 'observed'); assert.equal(e.via.method, 'POST'); assert.equal(e.via.path, '/api/items/:p');
  assert.equal(e.to.file, 'services/orders/index.js'); assert.equal(e.from.line, 4);
});

test('messaging: the same literal topic on a producer and a consumer in different services is an observed edge', () => {
  const e = ev(buildServiceEdges(FILES, { services: SERVICES }), 'messaging', 'orders', 'billing');
  assert.ok(e); assert.equal(e.evidence, 'observed'); assert.equal(e.via.topic, 'order.created');
});

test('persistence: a table one service writes and another reads is INFERRED unless the project declares a shared database', () => {
  const inferred = buildServiceEdges(FILES, { services: SERVICES });
  assert.equal(ev(inferred, 'persistence', 'orders', 'billing').evidence, 'inferred');
  assert.equal(ev(inferred, 'persistence', 'orders', 'reporting').evidence, 'inferred');
  assert.match(ev(inferred, 'persistence', 'orders', 'billing').basis, /nothing declares/);
  const declared = buildServiceEdges(FILES, { services: SERVICES, sharedDatabases: [{ name: 'main', services: ['orders', 'billing'], tables: ['orders'] }] });
  assert.equal(ev(declared, 'persistence', 'orders', 'billing').evidence, 'observed');
  assert.equal(ev(declared, 'persistence', 'orders', 'reporting').evidence, 'inferred', 'the declaration covers only the services it names');
});

test('a trace spans two services and an asynchronous and a persistence hop; its label is the weakest hop and is never "proven"', () => {
  const g = buildServiceEdges(FILES, { services: SERVICES });
  const t = traceFrom(g, 'gateway');
  const toReporting = t.paths.find((p) => p.services.join('>') === 'gateway>orders>reporting');
  assert.ok(toReporting); assert.deepEqual(toReporting.kinds, ['http', 'persistence']); assert.equal(toReporting.label, 'static-inferred');
  const toBilling = t.paths.find((p) => p.services.join('>') === 'gateway>orders>billing' && p.kinds.join() === 'http,messaging');
  assert.ok(toBilling); assert.equal(toBilling.label, 'static-observed');
  for (const p of t.paths) assert.notEqual(p.label, 'proven');
  assert.ok(t.paths.every((p) => ['static-observed', 'static-inferred', 'unproven'].includes(p.label)));
});

test('negative: a dynamic topic, a URL from configuration, an undeclared host and a missing route are recorded as unknown and never connected', () => {
  const files = {
    ...FILES,
    'services/orders/extra.js': "const name = pick();\nproducer.send({ topic: name, messages: [] });\nproducer.send({ topic: 'nobody.listens', messages: [] });\n",
    'services/gateway/more.js': "fetch(process.env.BILLING_URL);\nfetch('http://stranger/x');\nfetch('http://orders/api/missing', { method: 'POST' });\n",
  };
  const g = buildServiceEdges(files, { services: SERVICES });
  const reasons = g.unknown.map((u) => u.reason).join(' | ');
  assert.match(reasons, /comes from `name`/);
  assert.match(reasons, /no other service consumes topic "nobody.listens"/);
  assert.match(reasons, /host stranger is not a declared service/);
  assert.match(reasons, /orders has no POST route matching \/api\/missing/);
  assert.ok(g.unknown.every((u) => u.evidence === 'unknown'));
  assert.equal(g.edges.some((e) => e.via.topic === 'nobody.listens' || e.via.path === '/api/missing'), false);
  assert.equal(ev(g, 'messaging', 'orders', 'billing').evidence, 'observed', 'the supported edge is unaffected');
});

test('opt-in: fewer than two declared services infers nothing, and an undeclared file belongs to no service', () => {
  const none = buildServiceEdges(FILES, {});
  assert.deepEqual(none.edges, []); assert.equal(none.optedIn, false); assert.match(none.note, /fewer than two/);
  assert.deepEqual(buildServiceEdges(FILES, { services: [SERVICES[0]] }).edges, []);
  const stray = buildServiceEdges({ ...FILES, 'tools/stray.js': "fetch('http://orders/api/items/1', { method: 'POST' });\n" }, { services: SERVICES });
  assert.equal(stray.edges.filter((e) => e.from.file === 'tools/stray.js').length, 0);
});

test('traversal is bounded: a cycle ends, the hop limit holds, and the path count is capped', () => {
  const ring = {};
  const n = 10;
  for (let i = 0; i < n; i++) ring[`s${i}/a.js`] = `producer.send({ topic: 't${i}', messages: [] });\nconsumer.subscribe({ topic: 't${(i + n - 1) % n}' });\n`;
  const services = Array.from({ length: n }, (_, i) => ({ name: `s${i}`, root: `s${i}` }));
  const g = buildServiceEdges(ring, { services });
  const t = traceFrom(g, 's0', { maxHops: 3 });
  assert.ok(t.paths.every((p) => p.edges.length <= 3)); assert.equal(t.truncated, true);
  assert.equal(new Set(t.paths.map((p) => p.services.join('>'))).size, t.paths.length, 'no duplicate path');
  const full = traceFrom(g, 's0', { maxHops: 99 });
  assert.equal(full.maxHops, MAX_HOPS);
  assert.ok(full.paths.every((p) => new Set(p.services).size === p.services.length), 'a service appears once per path: the ring does not loop');
  assert.equal(traceFrom(g, 's0', { maxPaths: 2 }).paths.length, 2);
});

test('the Python route and client forms are read too', () => {
  const f = extractFacts('app.py', "@app.route('/ping', methods=['POST'])\ndef ping(): pass\n@app.get('/items/<id>')\ndef item(id): pass\nrequests.post('http://orders/api/items/1')\n");
  assert.deepEqual(f.routes.map((r) => `${r.method} ${r.path}`), ['POST /ping', 'GET /items/<id>']);
  assert.equal(f.clients[0].method, 'POST');
});

test('the semantic graph carries the relationships when opted in, as observed/inferred/unresolved, and stays schema-only otherwise', () => {
  const ir = buildProjectIR({ 'a.js': 'exports.f = (x) => x;\n' });
  const plain = buildSemanticGraph(ir);
  assert.equal(plain.coverage.serviceBoundaries.state, 'schema-only'); assert.match(plain.coverage.serviceBoundaries.reason, /opt-in/);
  const files = { ...FILES, 'services/orders/extra.js': "producer.send({ topic: 'nobody.listens', messages: [] });\n" };
  const g = buildSemanticGraph(ir, { serviceEdges: buildServiceEdges(files, { services: SERVICES }) });
  const v = validateGraph(g); assert.equal(v.ok, true, JSON.stringify(v.errors));
  assert.equal(g.coverage.serviceBoundaries.state, 'populated'); assert.equal(g.coverage.storageEdges.state, 'populated');
  assert.ok(g.serviceBoundaries.some((b) => b.confidence.tier === 'observed' && b.kind === 'http'));
  assert.ok(g.storageEdges.every((b) => b.confidence.tier === 'inferred'));
  const dangling = g.serviceBoundaries.find((b) => b.to === null && /nobody.listens/.test(b.confidence.basis));
  assert.ok(dangling); assert.equal(dangling.confidence.tier, 'unresolved');
  assert.ok(g.serviceBoundaries.filter((b) => b.to === null).every((b) => b.evidence === 'unknown'));
});
