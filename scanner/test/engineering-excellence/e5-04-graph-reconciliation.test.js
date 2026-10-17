// E5-04: static and runtime edges are reconciled into five states; matching and non-matching builds never produce a falsely corroborated path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildSemanticGraph } from '../../src/ir/semantic-graph.js';
import { EDGE_STATES, edgeKey, normalizeRouteKey, normalizeSymbol, pathCorroboration, readRuntimeEdges, reconcileGraphs, staticEdgesFromGraph } from '../../src/posture/graph-reconciliation.js';
import { ingestRuntimeRecords } from '../../src/posture/runtime-trace-ingest.js';

const SRC = 'function validate(x) { return x; }\nfunction save(x) { return x; }\nfunction handler(req) { const v = validate(req.body); return save(v); }\nfunction other(req) { return validate(req.query); }\n';
const NORM = { rewrite: [['^app\\.js::<module>::', 'app.']] };
const C1 = 'a'.repeat(40); const C2 = 'b'.repeat(40);
const SNAP = { commit: C1, environment: 'production' };
const graph = () => buildSemanticGraph(buildProjectIR({ 'app.js': SRC }));
const statics = () => staticEdgesFromGraph(graph(), { routes: [{ path: '/orders/:orderId', handler: 'app.js::<module>::handler' }] }, NORM);

async function reconcile(records, { snapshotIdentity = SNAP, sampleRate = 1, normalize = NORM } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e5-04-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{}'); fs.mkdirSync(path.join(root, '.agentic-security'));
  try {
    const r = ingestRuntimeRecords(root, records, { policy: { collect: true }, sampleRate });
    assert.equal(r.ok, true); assert.equal(r.accepted, records.length, JSON.stringify(r.rejected));
    const rt = await readRuntimeEdges(path.join(root, '.agentic-security', 'runtime-trace.jsonl'), { snapshotIdentity, normalize });
    return reconcileGraphs(statics(), rt, { sampling: sampleRate === 1 ? { state: 'complete' } : { state: 'sampled', rate: sampleRate } });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
const state = (r, key) => (r.edges.find((e) => e.key === key) || {}).state;
const K = { route: edgeKey('route', '/orders/:id', 'app.handler'), save: edgeKey('call', 'app.handler', 'app.save'), validate: edgeKey('call', 'app.handler', 'app.validate'), other: edgeKey('call', 'app.other', 'app.validate') };
const rec = (over) => ({ kind: 'function-call', ts: new Date().toISOString(), commit: C1, ...over });

test('static edges come from the semantic graph: resolved calls, supplied routes; nothing invented', () => {
  const e = statics();
  assert.deepEqual([...e.keys()].sort(), [K.route, K.other, K.save, K.validate].sort());
  assert.equal(normalizeRouteKey('/orders/{id}/items/42?x=1'), '/orders/:id/items/:id'); assert.equal(normalizeRouteKey('nope'), null);
  assert.equal(normalizeSymbol('a.b.C@12', {}), 'a.b.C'); assert.equal(normalizeSymbol('Pkg.Fn', { caseInsensitive: true }), 'pkg.fn');
  assert.equal(normalizeSymbol('com.acme.X', { stripPrefixes: ['com.acme.'] }), 'X');
  assert.deepEqual(EDGE_STATES, ['statically_inferred', 'runtime_observed', 'both', 'conflicted', 'unknown']);
});

test('MATCHING build: edges the trace shows become both; the rest stay statically_inferred; a path of both edges is corroborated', async () => {
  const r = await reconcile([
    { kind: 'route-hit', ts: new Date().toISOString(), commit: C1, route: '/orders/42', qid: 'app.handler' },
    rec({ caller: 'app.handler', qid: 'app.validate' }), rec({ caller: 'app.handler', qid: 'app.save' }),
  ]);
  assert.equal(state(r, K.route), 'both'); assert.equal(state(r, K.validate), 'both'); assert.equal(state(r, K.save), 'both');
  assert.equal(state(r, K.other), 'statically_inferred', 'no record about it: neither confirmed nor refuted');
  assert.equal(pathCorroboration(r, [K.route, K.validate, K.save]).state, 'corroborated');
  assert.equal(pathCorroboration(r, [K.route, K.other]).state, 'partial');
  assert.deepEqual(pathCorroboration(r, [K.route, K.other]).missing, [K.other]);
  assert.equal(r.edges.find((e) => e.key === K.save).confidence, 0.95);
  assert.equal(r.partialCoverage, false);
});

test('NON-MATCHING build: the same trace from another build never makes an edge both and never corroborates a path', async () => {
  const records = [
    { kind: 'route-hit', ts: new Date().toISOString(), commit: C2, route: '/orders/42', qid: 'app.handler' },
    rec({ commit: C2, caller: 'app.handler', qid: 'app.validate' }), rec({ commit: C2, caller: 'app.handler', qid: 'app.save' }),
  ];
  const r = await reconcile(records);
  for (const k of [K.route, K.validate, K.save]) { assert.equal(state(r, k), 'statically_inferred', k); const e = r.edges.find((x) => x.key === k); assert.ok(e.mismatchedRecords >= 1); assert.ok(e.confidence < 0.4, `decayed: ${e.confidence}`); assert.ok(e.factors.some((f) => f.name === 'records-from-a-different-build')); }
  const p = pathCorroboration(r, [K.route, K.validate, K.save]);
  assert.notEqual(p.state, 'corroborated'); assert.equal(p.state, 'uncorroborated');
  assert.equal(r.counts.both, 0);
});

test('NO build identity on the records: edges are unknown, never both', async () => {
  const r = await reconcile([{ kind: 'route-hit', ts: new Date().toISOString(), route: '/orders/42', qid: 'app.handler' }, { kind: 'function-call', ts: new Date().toISOString(), caller: 'app.handler', qid: 'app.save' }]);
  assert.equal(state(r, K.route), 'unknown'); assert.equal(state(r, K.save), 'unknown');
  assert.match(r.edges.find((e) => e.key === K.save).reason, /no build identity/);
  assert.notEqual(pathCorroboration(r, [K.route, K.save]).state, 'corroborated');
  const noSnapshot = await reconcile([rec({ caller: 'app.handler', qid: 'app.save' })], { snapshotIdentity: null });
  assert.equal(state(noSnapshot, K.save), 'unknown', 'with no snapshot identity nothing can be corroborated');
});

test('MIXED builds: a matched record is enough for both, and the mismatched ones decay the confidence and are counted', async () => {
  const r = await reconcile([rec({ caller: 'app.handler', qid: 'app.save' }), rec({ commit: C2, caller: 'app.handler', qid: 'app.save' })]);
  const e = r.edges.find((x) => x.key === K.save);
  assert.equal(e.state, 'both'); assert.equal(e.matchedRecords, 1); assert.equal(e.mismatchedRecords, 1); assert.equal(e.confidence, 0.475);
});

test('runtime_observed: an edge only the trace shows; one seen only in another build is unknown, not observed', async () => {
  const r = await reconcile([rec({ caller: 'app.other', qid: 'app.save' }), rec({ commit: C2, caller: 'app.save', qid: 'app.validate' })]);
  assert.equal(state(r, edgeKey('call', 'app.other', 'app.save')), 'runtime_observed');
  assert.equal(state(r, edgeKey('call', 'app.save', 'app.validate')), 'unknown');
});

test('conflicted: a matched build routed the route to a different handler; the static edge is conflicted too and no path through it is corroborated', async () => {
  const r = await reconcile([{ kind: 'route-hit', ts: new Date().toISOString(), commit: C1, route: '/orders/7', qid: 'app.other' }, rec({ caller: 'app.handler', qid: 'app.save' })]);
  const rival = edgeKey('route', '/orders/:id', 'app.other');
  assert.equal(state(r, rival), 'conflicted'); assert.equal(state(r, K.route), 'conflicted');
  assert.deepEqual(r.edges.find((e) => e.key === K.route).conflictsWith, [rival]);
  assert.equal(pathCorroboration(r, [K.route, K.save]).state, 'conflicted');
  // a conflicting record from a DIFFERENT build is not a conflict
  const other = await reconcile([{ kind: 'route-hit', ts: new Date().toISOString(), commit: C2, route: '/orders/7', qid: 'app.other' }]);
  assert.equal(state(other, K.route), 'statically_inferred'); assert.equal(state(other, rival), 'unknown');
});

test('partial coverage decays confidence and is stated; sampling does not change what a record says', async () => {
  const full = await reconcile([rec({ caller: 'app.handler', qid: 'app.save' })]);
  const sampled = await reconcile([rec({ caller: 'app.handler', qid: 'app.save' })], { sampleRate: 0.1 });
  assert.equal(sampled.partialCoverage, true);
  const e = sampled.edges.find((x) => x.key === K.save);
  assert.equal(e.state, 'both'); assert.equal(e.confidence, 0.808); assert.ok(e.confidence < full.edges.find((x) => x.key === K.save).confidence);
  assert.ok(e.factors.some((f) => f.name === 'partial-or-undeclared-coverage'));
  assert.ok(sampled.limitations.some((l) => /Spans are not used/.test(l)));
});

test('service edges: a declared service pair is reconciled the same way', async () => {
  const g = graph();
  g.serviceBoundaries.push({ id: 'svc:1', kind: 'http', from: { service: 'web' }, to: { service: 'billing' }, via: null });
  const st = staticEdgesFromGraph(g, {}, NORM);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e5-04s-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{}'); fs.mkdirSync(path.join(root, '.agentic-security'));
  try {
    ingestRuntimeRecords(root, [{ kind: 'service-call', service: 'web', peer: 'billing', commit: C1 }, { kind: 'service-call', service: 'web', peer: 'search', commit: C1 }], { policy: { collect: true }, sampleRate: 1 });
    const rt = await readRuntimeEdges(path.join(root, '.agentic-security', 'runtime-trace.jsonl'), { snapshotIdentity: SNAP });
    const r = reconcileGraphs(st, rt, { sampling: { state: 'complete' } });
    assert.equal(state(r, edgeKey('service', 'web', 'billing')), 'both'); assert.equal(state(r, edgeKey('service', 'web', 'search')), 'runtime_observed');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('an empty or missing trace leaves every static edge statically_inferred, and a path with no edges is not corroborated', () => {
  const r = reconcileGraphs(statics(), null, { sampling: { state: 'undisclosed' } });
  assert.equal(r.counts.statically_inferred, 4); assert.equal(r.counts.both, 0); assert.equal(r.partialCoverage, true);
  assert.equal(pathCorroboration(r, []).state, 'uncorroborated');
  assert.equal(pathCorroboration(r, ['call|nope|nope']).state, 'uncorroborated');
});
