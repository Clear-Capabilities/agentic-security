// E4-03: cross-route and cross-layer consistency: a multi-route IDOR and a cross-tenant gap are evidenced; public-by-policy is suppressed; unknown is not proof.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildContext } from '../../src/context-intelligence/build.js';
import { normalizeConfig } from '../../src/context-intelligence/config.js';
import { findCrossRouteInconsistencies, resourceKey } from '../../src/context-intelligence/cross-route.js';

const NOW = new Date('2026-10-16T00:00:00Z');
async function bundlesOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e4d-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
    for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true }); fs.writeFileSync(path.join(root, f), t); }
    return (await buildContext(root, { config: normalizeConfig({}).config })).bundles;
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
const HEAD = "const app = require('express')();\nfunction requireUser(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }\n";
const find = (r, route, dim) => r.findings.find((f) => f.route === route && f.dimension === dim);

test('a multi-route IDOR: GET is owner-scoped, PUT and DELETE on the same resource are not', async () => {
  const b = await bundlesOf({ 'app.js': HEAD
    + "app.get('/orders/:id', requireUser, async (req, res) => { res.json(await db.orders.findOne({ id: req.params.id, ownerId: req.user.id })); });\n"
    + "app.put('/orders/:id', requireUser, async (req, res) => { await db.orders.updateOne({ id: req.params.id }, { $set: req.body }); res.sendStatus(204); });\n"
    + "app.delete('/orders/:id', requireUser, async (req, res) => { await db.orders.deleteOne({ id: req.params.id }); res.sendStatus(204); });\n" });
  const r = findCrossRouteInconsistencies(b, { now: NOW });
  assert.deepEqual(r.resourcesCompared, ['order']);
  const put = find(r, 'PUT /orders/:id', 'ownership'); const del = find(r, 'DELETE /orders/:id', 'ownership');
  assert.ok(put && del, JSON.stringify(r.findings.map((f) => f.route + f.dimension)));
  assert.equal(put.class, 'idor'); assert.deepEqual(put.operations, ['update']); assert.deepEqual(del.operations, ['delete']);
  assert.deepEqual(put.enforcedAt.map((e) => e.route), ['GET /orders/:id']);
  assert.ok(put.enforcedAt[0].evidence.length >= 1, 'the enforcing route is cited');
  assert.match(put.explanation, /GET \/orders\/:id enforce ownership on order; PUT \/orders\/:id \(update\) does not/);
  assert.equal(find(r, 'GET /orders/:id', 'ownership'), undefined, 'the enforcing route is not flagged');
  assert.equal(r.findings.some((f) => f.dimension === 'authentication'), false, 'all three are authenticated');
});

test('a cross-tenant gap: the read is tenant-scoped and the list is not', async () => {
  const b = await bundlesOf({ 'app.js': HEAD
    + "app.get('/invoices/:id', requireUser, async (req, res) => { res.json(await db.invoices.findOne({ id: req.params.id, tenantId: req.user.tenantId })); });\n"
    + "app.get('/invoices', requireUser, async (req, res) => { res.json(await db.invoices.find({})); });\n" });
  const r = findCrossRouteInconsistencies(b, { now: NOW });
  const f = find(r, 'GET /invoices', 'tenant-scope');
  assert.ok(f, JSON.stringify(r.findings.map((x) => x.route + x.dimension))); assert.equal(f.class, 'cross-tenant');
});

test('a check in the service layer counts for the route that reaches it (cross-layer)', async () => {
  const b = await bundlesOf({
    'routes.js': HEAD + "const svc = require('./svc');\napp.get('/notes/:id', requireUser, async (req, res) => { res.json(await svc.getNote(req.params.id, req.user)); });\napp.put('/notes/:id', requireUser, async (req, res) => { res.json(await db.notes.updateOne({ id: req.params.id }, req.body)); });\n",
    'svc.js': "exports.getNote = async (id, currentUser) => db.notes.findOne({ id, ownerId: currentUser.id });\n",
  });
  const r = findCrossRouteInconsistencies(b, { now: NOW });
  const f = find(r, 'PUT /notes/:id', 'ownership');
  assert.ok(f, JSON.stringify(r.findings.map((x) => x.route + x.dimension) ));
  assert.deepEqual(f.enforcedAt.map((e) => e.route), ['GET /notes/:id']);
});

test('consistent routes, different resources and a single route produce nothing', async () => {
  const same = await bundlesOf({ 'app.js': HEAD
    + "app.get('/a/:id', requireUser, async (req, res) => { res.json(await db.items.findOne({ id: req.params.id, ownerId: req.user.id })); });\n"
    + "app.put('/a/:id', requireUser, async (req, res) => { await db.items.updateOne({ id: req.params.id, ownerId: req.user.id }, req.body); res.sendStatus(204); });\n" });
  assert.deepEqual(findCrossRouteInconsistencies(same, { now: NOW }).findings, []);
  const different = await bundlesOf({ 'app.js': HEAD
    + "app.get('/a/:id', requireUser, async (req, res) => { res.json(await db.items.findOne({ id: req.params.id, ownerId: req.user.id })); });\n"
    + "app.get('/b/:id', requireUser, async (req, res) => { res.json(await db.reports.findOne({ id: req.params.id })); });\n" });
  assert.deepEqual(findCrossRouteInconsistencies(different, { now: NOW }).findings, [], 'items and reports are not compared with each other');
  const single = await bundlesOf({ 'app.js': HEAD + "app.get('/a/:id', async (req, res) => { res.json(await db.items.findOne({ id: req.params.id })); });\n" });
  const r = findCrossRouteInconsistencies(single, { now: NOW });
  assert.deepEqual(r.findings, []); assert.deepEqual(r.resourcesCompared, []);
});

test('intentionally public access is suppressed with the policy that allows it, and only for the control the policy waives', async () => {
  const b = await bundlesOf({ 'app.js': HEAD
    + "app.get('/docs/:id', requireUser, async (req, res) => { res.json(await db.docs.findOne({ id: req.params.id, ownerId: req.user.id })); });\n"
    + "app.get('/docs/shared/:id', requireUser, async (req, res) => { res.json(await db.docs.findOne({ id: req.params.id })); });\n" });
  const policy = { schema: 'agentic-security/dci-invariants', schemaVersion: '1.0.0', invariants: [{ id: 'SHARED-001', title: 'Shared documents are readable by any signed-in user', rule: 'public-by-design', appliesTo: { routes: ['/docs/shared/*'] }, waives: ['ownership'], public: { reason: 'documents shared with the whole workspace', owner: 'docs-team', reviewBy: '2099-01-01' } }] };
  const without = findCrossRouteInconsistencies(b, { now: NOW });
  assert.ok(find(without, 'GET /docs/shared/:id', 'ownership'), 'flagged when no policy says otherwise');
  const withPolicy = findCrossRouteInconsistencies(b, { now: NOW, invariants: policy });
  assert.equal(find(withPolicy, 'GET /docs/shared/:id', 'ownership'), undefined);
  const s = withPolicy.suppressed.find((x) => x.route === 'GET /docs/shared/:id' && x.dimension === 'ownership');
  assert.ok(s); assert.deepEqual(s.waivedBy, ['SHARED-001']);
  const narrow = findCrossRouteInconsistencies(b, { now: NOW, invariants: { ...policy, invariants: [{ ...policy.invariants[0], waives: ['authentication'] }] } });
  assert.ok(find(narrow, 'GET /docs/shared/:id', 'ownership'), 'waiving authentication does not waive ownership');
  const expired = findCrossRouteInconsistencies(b, { now: NOW, invariants: { ...policy, invariants: [{ ...policy.invariants[0], public: { ...policy.invariants[0].public, reviewBy: '2020-01-01' } }] } });
  assert.ok(find(expired, 'GET /docs/shared/:id', 'ownership'), 'an expired public-by-design no longer suppresses: openness must be re-approved');
});

test('dynamic dispatch is unknown, not proof of absence: a route that hides its data access behind a computed call is not called weaker', async () => {
  const b = await bundlesOf({ 'app.js': HEAD
    + "app.get('/tasks/:id', requireUser, async (req, res) => { res.json(await db.tasks.findOne({ id: req.params.id, ownerId: req.user.id })); });\n"
    + "app.post('/tasks/:id', requireUser, async (req, res) => { await handlers[req.body.op](req.params.id); await db.tasks.updateOne({ id: req.params.id }, req.body); res.sendStatus(204); });\n" });
  const r = findCrossRouteInconsistencies(b, { now: NOW });
  const flagged = find(r, 'POST /tasks/:id', 'ownership');
  const unk = r.unknown.find((x) => x.route === 'POST /tasks/:id' && x.dimension === 'ownership');
  assert.ok(flagged || unk, 'one or the other');
  if (unk) { assert.equal(flagged, undefined); assert.match(unk.reason, /not proof of absence/); }
});

test('resource naming: collections, tables, models and repositories collapse plural and singular, and unnameable operations are counted', () => {
  assert.equal(resourceKey("db.orders.findOne({ id })"), 'order');
  assert.equal(resourceKey("pool.query('SELECT * FROM Orders WHERE id = $1')"), 'order');
  assert.equal(resourceKey("Order.findByPk(id)"), 'order');
  assert.equal(resourceKey("db.collection('orders').find({})"), 'order');
  assert.equal(resourceKey("orderRepo.findById(id)"), 'order');
  assert.equal(resourceKey("db.companies.find({})"), 'company');
  assert.equal(resourceKey("something(else)"), null);
  assert.equal(resourceKey("db.models.find({})"), null);
});
