// E4-02: first-class security invariants: a versioned schema, path-scoped validity, malformed-policy validation, satisfied and violated examples.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { REPO } from './helpers.js';
import { buildContext } from '../../src/context-intelligence/build.js';
import { normalizeConfig } from '../../src/context-intelligence/config.js';
import { CONTROL_DIMENSIONS, INVARIANTS_FILE, VERDICTS, evaluateInvariants, globToRegExp, loadInvariants, validateInvariants } from '../../src/context-intelligence/invariants.js';

const EXAMPLE = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner/test/fixtures/engineering-excellence/dci-invariants.example.json'), 'utf8'));
const NOW = new Date('2026-10-16T00:00:00Z');
const codes = (doc, opts) => validateInvariants(doc, { now: NOW, ...opts }).errors.map((e) => `${e.code}:${e.path}`);
const mut = (f) => { const d = structuredClone(EXAMPLE); f(d); return d; };

test('the example policy is valid, and every verdict name is accounted for', () => {
  const v = validateInvariants(EXAMPLE, { now: NOW });
  assert.deepEqual(v, { ok: true, errors: [], warnings: [] });
  assert.deepEqual([...VERDICTS].sort(), ['expired', 'not_applicable', 'public_by_policy', 'satisfied', 'unknown', 'violated']);
  assert.deepEqual([...CONTROL_DIMENSIONS], ['authentication', 'authorization-role', 'ownership', 'tenant-scope']);
});

test('malformed policies are refused with a code and a path, never silently dropped', () => {
  for (const bad of [null, [], 'x', 3]) assert.equal(validateInvariants(bad).ok, false);
  assert.ok(codes({ schema: 'other' }).includes('SCHEMA_MISMATCH:schema'));
  assert.ok(codes({ schema: EXAMPLE.schema, schemaVersion: 'one', invariants: [] }).includes('BAD_VERSION:schemaVersion'));
  assert.ok(codes({ schema: EXAMPLE.schema, schemaVersion: '2.0.0', invariants: [] }).includes('UNSUPPORTED_MAJOR:schemaVersion'));
  assert.ok(codes({ schema: EXAMPLE.schema, schemaVersion: '1.0.0' }).includes('MISSING_FIELD:invariants'));
  assert.ok(codes(mut((d) => { d.extra = 1; })).includes('UNKNOWN_FIELD:extra'));
  assert.ok(codes(mut((d) => { d.invariants[0].surprise = 1; })).includes('UNKNOWN_FIELD:invariants[0].surprise'));
  assert.ok(codes(mut((d) => { d.invariants[0].id = 'orders'; })).includes('BAD_ID:invariants[0].id'));
  assert.ok(codes(mut((d) => { d.invariants[1].id = 'ORDERS-001'; })).includes('DUPLICATE_ID:invariants[1].id'));
  assert.ok(codes(mut((d) => { d.invariants[0].rule = 'maybe'; })).includes('UNKNOWN_ENUM:invariants[0].rule'));
  assert.ok(codes(mut((d) => { d.invariants[0].requires = []; })).includes('MISSING_FIELD:invariants[0].requires'));
  assert.ok(codes(mut((d) => { d.invariants[0].requires = ['authentication', 'magic']; })).includes('UNKNOWN_ENUM:invariants[0].requires[1]'));
  assert.ok(codes(mut((d) => { d.invariants[0].requires = ['authentication', 'authentication']; })).includes('DUPLICATE_ID:invariants[0].requires'));
  assert.ok(codes(mut((d) => { d.invariants[0].appliesTo.routes = []; })).includes('MISSING_FIELD:invariants[0].appliesTo.routes'));
  assert.ok(codes(mut((d) => { d.invariants[0].appliesTo.routes = ['../etc']; })).includes('BAD_GLOB:invariants[0].appliesTo.routes[0]'));
  assert.ok(codes(mut((d) => { d.invariants[0].appliesTo.methods = ['FETCH']; })).includes('UNKNOWN_ENUM:invariants[0].appliesTo.methods'));
  assert.ok(codes(mut((d) => { d.invariants[0].waives = ['authentication']; })).includes('RULE_VIOLATION:invariants[0]'));
  assert.ok(codes(mut((d) => { d.invariants[1].requires = ['authentication']; })).includes('RULE_VIOLATION:invariants[1].requires'));
  assert.ok(codes(mut((d) => { delete d.invariants[1].public; })).includes('MISSING_FIELD:invariants[1].public'));
  assert.ok(codes(mut((d) => { d.invariants[1].public.reason = 'ok'; })).includes('MISSING_FIELD:invariants[1].public.reason'));
  assert.ok(codes(mut((d) => { d.invariants[1].public.owner = ''; })).includes('MISSING_FIELD:invariants[1].public.owner'));
  assert.ok(codes(mut((d) => { d.invariants[1].public.reviewBy = 'soon'; })).includes('BAD_DATE:invariants[1].public.reviewBy'));
  assert.ok(codes(mut((d) => { d.invariants[0].validity.from = '2030-01-01'; d.invariants[0].validity.until = '2029-01-01'; })).includes('RULE_VIOLATION:invariants[0].validity'));
  assert.ok(codes(mut((d) => { d.invariants[0].validity.paths = []; })).includes('BAD_TYPE:invariants[0].validity.paths'));
  assert.ok(codes(mut((d) => { d.invariants[0].severity = 'dire'; })).includes('UNKNOWN_ENUM:invariants[0].severity'));
});

test('openness must be re-approved: an expired public-by-design is an error, an expired validity window is a warning', () => {
  assert.ok(codes(mut((d) => { d.invariants[1].public.reviewBy = '2020-01-01'; })).includes('EXPIRED:invariants[1].public.reviewBy'));
  const w = validateInvariants(mut((d) => { d.invariants[0].validity.until = '2020-01-01'; }), { now: NOW });
  assert.equal(w.ok, true); assert.ok(w.warnings.some((x) => x.code === 'PAST_UNTIL'));
  assert.ok(validateInvariants(mut((d) => { d.invariants[0].appliesTo.routes = ['**']; }), { now: NOW }).warnings.some((x) => x.code === 'BROAD_SCOPE'));
});

test('globs: * stays inside a path segment, ** crosses them, everything else is literal', () => {
  assert.equal(globToRegExp('/orders/*').test('/orders/:id'), true);
  assert.equal(globToRegExp('/orders/*').test('/orders/:id/items'), false);
  assert.equal(globToRegExp('/orders/**').test('/orders/:id/items'), true);
  assert.equal(globToRegExp('/a.b').test('/aXb'), false, 'the dot is literal');
  assert.equal(globToRegExp('src/**').test('src/routes/orders.js'), true);
});

// ---- evaluation against real bundles --------------------------------------------------------------------------------------------

const APP = `const app = require('express')();
function requireUser(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }
app.get('/orders/:id', requireUser, async (req, res) => { res.json(await db.orders.findOne({ id: req.params.id, ownerId: req.user.id })); });
app.get('/orders', requireUser, async (req, res) => { res.json(await db.orders.find({})); });
app.delete('/orders/:id', async (req, res) => { await db.orders.deleteOne({ id: req.params.id }); res.sendStatus(204); });
app.get('/health', async (req, res) => { res.json(await db.pings.findOne({})); });
`;
async function bundlesOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e4b-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
    for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true }); fs.writeFileSync(path.join(root, f), t); }
    return (await buildContext(root, { config: normalizeConfig({}).config })).bundles;
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
const verdictOf = (res, inv, label) => res.results.find((r) => r.invariantId === inv && r.label === label)?.verdict;

test('a satisfied invariant, a violated one, and a documented public route, each with its evidence', async () => {
  const bundles = await bundlesOf({ 'app.js': APP });
  const res = evaluateInvariants(EXAMPLE, bundles, { now: NOW });
  assert.deepEqual(res.problems, []);
  assert.equal(verdictOf(res, 'ORDERS-001', 'GET /orders/:id'), 'satisfied');
  const open = res.results.find((r) => r.invariantId === 'ORDERS-001' && r.label === 'DELETE /orders/:id');
  assert.equal(open.verdict, 'violated');
  assert.ok(open.reasons.some((x) => /authentication/.test(x)), JSON.stringify(open.reasons));
  assert.ok(open.controls.some((c) => c.dim === 'ownership' && c.state === 'absent'));
  assert.equal(open.severity, 'high');
  const listing = res.results.find((r) => r.label === 'GET /orders');
  assert.equal(listing.verdict, 'violated', 'authenticated but not owner-scoped: the listing leaks other users\' orders');
  assert.match(listing.reasons.join(' '), /ownership/);
});

test('public-by-design waives only the dimensions it names, on the routes it names, with a stated reason', async () => {
  const bundles = await bundlesOf({ 'app.js': APP });
  const doc = mut((d) => { d.invariants[0].appliesTo.routes.push('/health'); });
  const res = evaluateInvariants(doc, bundles, { now: NOW });
  const health = res.results.find((r) => r.label === 'GET /health');
  assert.equal(health.verdict, 'public_by_policy'); assert.deepEqual(health.waivedBy, ['HEALTH-001']); assert.match(health.reasons.join(' '), /load balancer probe/);
  const del = res.results.find((r) => r.label === 'DELETE /orders/:id');
  assert.equal(del.verdict, 'violated', 'the waiver does not leak onto other routes');
  const narrow = evaluateInvariants(mut((d) => { d.invariants[0].appliesTo.routes.push('/health'); d.invariants[1].waives = ['authentication']; }), bundles, { now: NOW });
  assert.equal(narrow.results.find((r) => r.label === 'GET /health').verdict, 'violated', 'waiving authentication does not waive ownership');
});

test('path-scoped validity: a handler outside the validity paths is not_applicable, never satisfied', async () => {
  const bundles = await bundlesOf({ 'legacy/app.js': APP });
  const res = evaluateInvariants(EXAMPLE, bundles, { now: NOW });
  const r = res.results.filter((x) => x.invariantId === 'ORDERS-001');
  assert.ok(r.length >= 3 && r.every((x) => x.verdict === 'not_applicable'), JSON.stringify(r.map((x) => x.verdict)));
  assert.match(r[0].reasons[0], /outside this invariant's validity paths/);
  const inScope = evaluateInvariants(mut((d) => { d.invariants[0].validity.paths = ['legacy/**']; }), bundles, { now: NOW });
  assert.ok(inScope.results.some((x) => x.invariantId === 'ORDERS-001' && x.verdict === 'violated'));
});

test('time bounds: before `from` is not_applicable, after `until` is expired', async () => {
  const bundles = await bundlesOf({ 'app.js': APP });
  const future = evaluateInvariants(mut((d) => { d.invariants[0].validity.from = '2099-01-01'; }), bundles, { now: NOW });
  assert.ok(future.results.filter((x) => x.invariantId === 'ORDERS-001').every((x) => x.verdict === 'not_applicable'));
  const past = evaluateInvariants(mut((d) => { d.invariants[0].validity.until = '2020-01-01'; }), bundles, { now: NOW });
  assert.ok(past.results.filter((x) => x.invariantId === 'ORDERS-001').every((x) => x.verdict === 'expired'));
});

test('a route that touches nothing sensitive has nothing to protect: not_applicable, and an unresolved call is unknown, not satisfied', async () => {
  const bundles = await bundlesOf({ 'app.js': "const app = require('express')();\napp.get('/orders/ping', (req, res) => res.send('pong'));\napp.get('/orders/x/:id', requireUser, async (req, res) => { await mystery(req.params.id); res.json(await db.orders.findOne({ id: req.params.id })); });\n" });
  const res = evaluateInvariants(mut((d) => { d.invariants[0].appliesTo.routes = ['/orders/**']; }), bundles, { now: NOW });
  assert.equal(verdictOf(res, 'ORDERS-001', 'GET /orders/ping'), 'not_applicable');
  const x = res.results.find((r) => r.label === 'GET /orders/x/:id');
  assert.ok(['unknown', 'violated'].includes(x.verdict), x.verdict);
  assert.notEqual(x.verdict, 'satisfied');
});

test('an invalid policy produces no verdicts, only the reasons it is invalid', async () => {
  const bundles = await bundlesOf({ 'app.js': APP });
  const res = evaluateInvariants(mut((d) => { d.invariants[0].requires = []; }), bundles, { now: NOW });
  assert.deepEqual(res.results, []); assert.ok(res.problems.length >= 1);
});

test('the file loader: missing is "none", malformed JSON and invalid policies are reported, a good file loads', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e4c-'));
  try {
    assert.equal(loadInvariants(root).present, false);
    fs.writeFileSync(path.join(root, INVARIANTS_FILE), '{nope');
    assert.equal(loadInvariants(root).validation.errors[0].code, 'BAD_JSON');
    fs.writeFileSync(path.join(root, INVARIANTS_FILE), JSON.stringify({ schema: EXAMPLE.schema, schemaVersion: '1.0.0', invariants: [{}] }));
    assert.equal(loadInvariants(root).validation.ok, false);
    fs.writeFileSync(path.join(root, INVARIANTS_FILE), JSON.stringify(EXAMPLE));
    const l = loadInvariants(root, { now: NOW });
    assert.equal(l.present, true); assert.equal(l.validation.ok, true); assert.equal(l.doc.invariants.length, 2);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
