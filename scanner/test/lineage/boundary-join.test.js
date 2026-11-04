//
// boundary-join.test.js: GA-03.3 (0.195.25): cross-service handoffs in the
// lineage graph. Real parser, real builder; every fixture is written in the
// test so nothing here reads a label file.
//
// BJ/1-3  discovered joins: queue (AWS SDK v3 command shape), store, chain
// BJ/4-6  what is NOT joined: a computed identity, a different identity, a
//         producer whose record carries nothing
// BJ/7    field precision across the join: a sibling field never crosses
// BJ/8    a declared DAG-08 contract seeds the bound parameter, renames a
//         field, and a contract without a producer site is a gap
// BJ/9    off by default: the graph is byte-identical with the option absent
// BJ/10   the round bound is reported as truncation, never as convergence
// BJ/11   the JSON round trip is structure-preserving in the resolver
// BJ/12   the reuse boundary of the new module

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { buildProjectIR } from '../../src/ir/index.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildDataFlowGraph, enumerateSinkSites } from '../../src/lineage/graph-builder.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { createBoundaryContract } from '../../src/lineage/boundary-contract.js';
import { collectBoundaryEndpoints, planBoundaryJoins, recordShape, resolveIdentityExpr, queueCommandOf, MAX_BOUNDARY_ROUNDS } from '../../src/lineage/boundary-join.js';
import { resolveExprIdentities } from '../../src/lineage/engine.js';
import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';

const build = (files, opts = {}) => {
  const { callGraph } = buildProjectIR(files);
  const built = buildGraphWithCoverage(callGraph, { repository: 't', generatedAt: '1970-01-01T00:00:00.000Z', ...opts });
  assert.deepEqual(validateGraph(built.graph).errors, []);
  return built;
};
const withJoins = (files, extra = {}) => build(files, { boundaries: { enabled: true, ...extra } });

function flows(graph) {
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  const deById = new Map(graph.dataElements.map((d) => [d.id, d]));
  return graph.flows.map((f) => {
    const s = nodeById.get(f.source); const k = nodeById.get(f.sink);
    const des = f.dataElementIds.map((id) => deById.get(id));
    return {
      from: `${s.kind}/${s.subtype}`, to: `${k.kind}/${k.subtype}`,
      fields: des.map((d) => d.name).sort(),
      files: [...new Set(des.flatMap((d) => d.sourceLocations.map((l) => l.file)))].sort(),
      edge: graph.edges.find((e) => e.id === f.edgeIds[0]),
    };
  });
}
const has = (fl, from, to, field, file) => fl.some((f) => f.from === from && f.to === to && f.fields.includes(field) && (!file || f.files.includes(file)));

const API = `
const { SQSClient, SendMessageCommand } = require('@aws-sdk/client-sqs');
const sqs = new SQSClient({});
const ORDERS_QUEUE = process.env.ORDERS_QUEUE_URL;
app.post('/orders', async (req, res) => {
  const note = req.body.note;
  const email = req.body.email;
  await sqs.send(new SendMessageCommand({ QueueUrl: ORDERS_QUEUE, MessageBody: JSON.stringify({ note, contact: email }) }));
  res.status(202).json({ ok: true });
});
`;
const WORKER = `
const { SQSClient, ReceiveMessageCommand } = require('@aws-sdk/client-sqs');
const { MongoClient } = require('mongodb');
const sqs = new SQSClient({});
const db = new MongoClient(process.env.MONGO_URL).db('shop');
const ORDERS_QUEUE = process.env.ORDERS_QUEUE_URL;
async function drain() {
  const out = await sqs.send(new ReceiveMessageCommand({ QueueUrl: ORDERS_QUEUE }));
  for (const m of out.Messages || []) {
    const body = JSON.parse(m.Body);
    await db.collection('orders').insertOne({ note: body.note, who: body.contact });
  }
}
`;
const REPORT = `
const { MongoClient } = require('mongodb');
const db = new MongoClient(process.env.MONGO_URL).db('shop');
app.get('/report', async (req, res) => {
  const rows = await db.collection('orders').find({}).toArray();
  let html = '';
  for (const o of rows) html += '<li>' + o.note + '</li>';
  res.send(html);
});
app.get('/who', async (req, res) => {
  const doc = await db.collection('orders').findOne({});
  res.send(doc.who);
});
`;

test('BJ/1: a queue publish (AWS SDK v3 command) and its receive, naming the same environment variable, are joined on the fields the producer put in the message; the consumer flow starts at the queue node', () => {
  const b = withJoins({ 'api.js': API, 'worker.js': WORKER });
  const fl = flows(b.graph);
  assert.ok(has(fl, 'source/http-body', 'queue/queue', 'note'), 'producer side: http-body -> queue');
  assert.ok(has(fl, 'queue/queue', 'store/database', 'note', 'worker.js'), 'consumer side: queue -> store, with the consumer file as a source location');
  // The renamed key crosses under the consumer's name of it (`contact`), still as the producer's element (`email`).
  const who = fl.find((f) => f.from === 'queue/queue' && f.to === 'store/database' && f.fields.includes('email'));
  assert.ok(who, 'the email element crosses under the message key contact');
  assert.equal(who.edge.provenance, 'code');
  assert.deepEqual(who.edge.boundaryCrossings.map((c) => [c.kind, c.identity, c.modeledInput, c.observed]), [['queue', 'queue:env:ORDERS_QUEUE_URL', true, false]]);
  const cov = b.graph.coverage.boundaries;
  assert.equal(cov.enabled, true);
  assert.equal(cov.discovered, 1);
  assert.equal(cov.declared, 0);
  assert.equal(cov.joinedFields, 2);
  assert.deepEqual(cov.unjoined, []);
  assert.ok(b.graph.limitations.some((l) => /modeled from code, never an observed message or row/.test(l)));
  const de = b.graph.dataElements.find((d) => d.name === 'note');
  assert.deepEqual(de.sourceLocations.map((l) => `${l.file}:${l.path}`), ['api.js:req.body.note', 'worker.js:out.Messages.Body.note']);
});

test('BJ/2: a store write and a later read of the same collection literal are joined for both find().toArray() and findOne(); the read-side flow starts at the store node', () => {
  const b = withJoins({ 'worker.js': WORKER, 'report.js': REPORT, 'api.js': API });
  const fl = flows(b.graph);
  assert.ok(has(fl, 'store/database', 'sink/http-response', 'note', 'report.js'), 'find().toArray(): orders.note -> res.send');
  assert.ok(has(fl, 'store/database', 'sink/http-response', 'email', 'report.js'), 'findOne(): orders.who -> res.send');
  const read = fl.find((f) => f.from === 'store/database' && f.to === 'sink/http-response' && f.fields.includes('note'));
  assert.deepEqual(read.edge.boundaryCrossings.map((c) => [c.kind, c.identity, c.basis]), [['storage', 'storage:collection:orders', 'object-literal']]);
});

test('BJ/3: the whole chain, HTTP to queue to store to HTTP response, resolves in bounded rounds and is reported as such', () => {
  const b = withJoins({ 'api.js': API, 'worker.js': WORKER, 'report.js': REPORT });
  const cov = b.graph.coverage.boundaries;
  assert.equal(cov.rounds, 2, 'the store reader needs the queue consumer analysed with its seeds first');
  assert.equal(cov.truncated, false);
  assert.equal(cov.maxRounds, MAX_BOUNDARY_ROUNDS);
  assert.equal(b.graph.scanHealth.status, 'complete');
  const fl = flows(b.graph);
  const note = b.graph.dataElements.find((d) => d.name === 'note');
  assert.deepEqual([...new Set(note.sourceLocations.map((l) => l.file))], ['api.js', 'worker.js', 'report.js']);
  for (const [from, to] of [['source/http-body', 'queue/queue'], ['queue/queue', 'store/database'], ['store/database', 'sink/http-response']]) {
    assert.ok(has(fl, from, to, 'note'), `${from} -> ${to}`);
  }
});

test('BJ/4: a computed identity is never joined and is listed with the reason (unknown dynamic edges remain unknown)', () => {
  const dynWorker = WORKER.replace('QueueUrl: ORDERS_QUEUE', 'QueueUrl: queueUrlFor(region)');
  const b = withJoins({ 'api.js': API, 'worker.js': dynWorker });
  const fl = flows(b.graph);
  assert.ok(!has(fl, 'queue/queue', 'store/database', 'note'));
  assert.deepEqual(b.graph.coverage.boundaries.unjoined.map((u) => [u.side, u.kind, u.reason]), [['consumer', 'queue', 'dynamic-identity']]);
  const dynColl = REPORT.replace("collection('orders').find", 'collection(name).find');
  const c = withJoins({ 'worker.js': WORKER, 'report.js': dynColl, 'api.js': API });
  assert.ok(c.graph.coverage.boundaries.unjoined.some((u) => u.side === 'consumer' && u.kind === 'storage' && u.reason === 'dynamic-identity'));
});

test('BJ/5: a different identity on the consumer side is not joined, and a producer whose record carries no identity hands nothing across', () => {
  const other = WORKER.replace('const ORDERS_QUEUE = process.env.ORDERS_QUEUE_URL;', 'const ORDERS_QUEUE = process.env.AUDIT_QUEUE_URL;');
  const b = withJoins({ 'api.js': API, 'worker.js': other });
  assert.ok(!has(flows(b.graph), 'queue/queue', 'store/database', 'note'));
  assert.deepEqual(b.graph.coverage.boundaries.unjoined.map((u) => [u.side, u.reason]), [['consumer', 'no-producer-in-scope']]);
  const constant = API.replace("MessageBody: JSON.stringify({ note, contact: email })", "MessageBody: 'order created'");
  const c = withJoins({ 'api.js': constant, 'worker.js': WORKER });
  assert.ok(!has(flows(c.graph), 'queue/queue', 'store/database', 'note'));
  const cov = c.graph.coverage.boundaries;
  assert.equal(cov.joins, 1, 'the join exists (same identity) but carried nothing');
  assert.equal(cov.joinedFields, 0);
  assert.equal(c.boundaries.joins[0].basis, 'none');
});

test('BJ/6: a store write and read with the same collection name but different literal database names are not joined', () => {
  const otherDb = REPORT.replace(".db('shop')", ".db('archive')");
  const b = withJoins({ 'worker.js': WORKER, 'report.js': otherDb, 'api.js': API });
  assert.ok(!has(flows(b.graph), 'store/database', 'sink/http-response', 'note'));
  assert.ok(b.graph.coverage.boundaries.unjoined.some((u) => u.kind === 'storage' && u.reason === 'no-producer-in-scope'));
});

test('BJ/7: field precision across the join: a key carries only the elements its own value references, so a sibling never crosses under another key', () => {
  const b = withJoins({ 'api.js': API, 'worker.js': WORKER });
  const fl = flows(b.graph);
  const toStore = fl.filter((f) => f.from === 'queue/queue' && f.to === 'store/database');
  for (const f of toStore) assert.equal(f.fields.length, 1, `one element per flow: ${f.fields}`);
  const seeds = b.seeds.filter((s) => s.boundary);
  assert.deepEqual(seeds.map((s) => [s.seedPath, s.canonicalName]).sort(), [['out.Messages.Body.contact', 'contact'], ['out.Messages.Body.note', 'note']]);
  const byPath = Object.fromEntries(seeds.map((s) => [s.seedPath, b.graph.dataElements.find((d) => d.id === s.dataElementId).name]));
  assert.deepEqual(byPath, { 'out.Messages.Body.note': 'note', 'out.Messages.Body.contact': 'email' });
  // The record shape itself, on the real hop stream: each key maps to exactly one element.
  const { callGraph } = buildProjectIR({ 'api.js': API, 'worker.js': WORKER });
  const q = b.sites.find((s) => s.decision.category === 'queue');
  const ep = collectBoundaryEndpoints(callGraph, b.sites);
  assert.equal(ep.producers.filter((p) => p.kind === 'queue').length, 1);
  const shape = recordShape(ep.producers.find((p) => p.kind === 'queue').recordExpr, b.hops.filter((h) => h.scope === q.qid && h.nodeId === q.nodeId));
  assert.equal(shape.basis, 'object-literal');
  assert.deepEqual([...shape.byKey.keys()].sort(), ['contact', 'note']);
  for (const ids of shape.byKey.values()) assert.equal(ids.size, 1);
});

test('BJ/8: a declared DAG-08 contract seeds the bound consumer parameter from the producer site it names, applies the field rename, carries manual provenance, and a contract without a producer site is a gap, never a guess', () => {
  const producer = `
const { SQSClient, SendMessageCommand } = require('@aws-sdk/client-sqs');
const sqs = new SQSClient({});
function publishOrder(req) {
  const note = req.body.note;
  sqs.send(new SendMessageCommand({ QueueUrl: makeUrl(), MessageBody: JSON.stringify({ note }) }));
}
`;
  const consumer = `
const { MongoClient } = require('mongodb');
const db = new MongoClient(process.env.MONGO_URL).db('shop');
function handleOrder(evt) {
  db.collection('orders').insertOne({ text: evt.body.memo });
}
`;
  const contract = createBoundaryContract({
    id: 'boundary:orders', kind: 'queue', channel: { topic: 'orders' }, schema: { name: 'order', version: '1' },
    producer: { service: 'api', site: { file: 'p.js', function: 'publishOrder' } },
    consumer: { service: 'worker', site: { file: 'c.js', function: 'handleOrder', param: 'evt', recordPath: 'body' } },
    fieldMappings: [{ from: 'note', to: 'memo' }], declaredBy: 'ops',
  });
  const b = withJoins({ 'p.js': producer, 'c.js': consumer }, { contracts: [contract] });
  const fl = flows(b.graph);
  const crossed = fl.find((f) => f.from === 'queue/queue' && f.to === 'store/database' && f.fields.includes('note'));
  assert.ok(crossed, 'the producer element note reaches the consumer store through the declared contract');
  assert.equal(crossed.edge.provenance, 'manual');
  assert.equal(crossed.edge.boundaryCrossings[0].contractId, 'boundary:orders');
  const seed = b.seeds.find((s) => s.boundary);
  assert.equal(seed.seedPath, 'evt.body.memo');
  assert.equal(seed.seedKind, 'entry');
  assert.equal(seed.boundary.provenance, 'manual');
  const cov = b.graph.coverage.boundaries;
  assert.equal(cov.declared, 1);
  // The producer's own QueueUrl is computed: with no contract it is an unjoined producer; the contract is what names the edge.
  assert.deepEqual(cov.unjoined.map((u) => [u.side, u.reason]), [['producer', 'dynamic-identity']]);
  // No producer site: a gap with a reason, no seed.
  const noSite = createBoundaryContract({ ...contract, id: 'boundary:nosite', producer: { service: 'api', site: null } });
  const g = withJoins({ 'p.js': producer, 'c.js': consumer }, { contracts: [noSite] });
  assert.equal(g.seeds.filter((s) => s.boundary).length, 0);
  assert.ok(g.boundaries.gaps.some((x) => x.contractId === 'boundary:nosite' && x.reason === 'producer-site-required'));
  assert.equal(g.graph.coverage.boundaries.gaps, 1);
});

test('BJ/9: off by default: with no boundaries option the graph, the ledger and the limitations are byte-identical to a build that never heard of joins, and the receive is still not a sink', () => {
  const files = { 'api.js': API, 'worker.js': WORKER, 'report.js': REPORT };
  const off = build(files);
  assert.equal(off.boundaries, null);
  assert.equal(off.graph.coverage.boundaries, undefined);
  assert.ok(!off.graph.limitations.some((l) => /handoff/.test(l)));
  assert.ok(!has(flows(off.graph), 'queue/queue', 'store/database', 'note'));
  const again = build(files);
  assert.deepEqual(JSON.stringify(off.graph), JSON.stringify(again.graph));
  // The SDK v3 recognition is unconditional: the publish is a queue sink and the receive is not a sink at all.
  const { callGraph } = buildProjectIR(files);
  const { sites } = enumerateSinkSites(callGraph);
  assert.deepEqual(sites.filter((s) => s.file === 'worker.js').map((s) => [s.line, s.decision.category]), [[11, 'database']]);
  assert.ok(sites.some((s) => s.file === 'api.js' && s.decision.category === 'queue' && s.queueCommand === 'SendMessageCommand'));
});

test('BJ/10: the round bound: a chain longer than the bound is reported truncated and the graph partial, never read as converged', () => {
  // store A -> read A, write B -> read B, write C ... five handoffs need five rounds; the bound is four.
  let src = `
const { MongoClient } = require('mongodb');
const db = new MongoClient(process.env.MONGO_URL).db('shop');
app.post('/in', async (req, res) => { await db.collection('c0').insertOne({ v: req.body.v }); res.json({}); });
`;
  for (let i = 0; i < MAX_BOUNDARY_ROUNDS + 1; i++) {
    src += `
async function hop${i}() { const d${i} = await db.collection('c${i}').findOne({}); await db.collection('c${i + 1}').insertOne({ v: d${i}.v }); }
`;
  }
  src += `
app.get('/out', async (req, res) => { const last = await db.collection('c${MAX_BOUNDARY_ROUNDS + 1}').findOne({}); res.send(last.v); });
`;
  const b = withJoins({ 'chain.js': src });
  const cov = b.graph.coverage.boundaries;
  assert.equal(cov.rounds, MAX_BOUNDARY_ROUNDS);
  assert.equal(cov.truncated, true);
  assert.equal(b.graph.scanHealth.status, 'partial');
  assert.equal(b.graph.scanHealth.analysisCompletion.boundaries.truncated, true);
  assert.ok(!has(flows(b.graph), 'store/database', 'sink/http-response', 'v'), 'the last hop was not reached and is not claimed');
});

test('BJ/11: JSON.parse and JSON.stringify are structure-preserving in the resolver; any other call still flattens', () => {
  const fn = parseJsFile('t.js', 'function f(o) { const s = JSON.stringify(o); const back = JSON.parse(s); const k = keep(o); return [back.a, k.a]; }').functions[0];
  const nodes = Object.values(fn.cfg.nodes);
  const stringify = nodes.find((n) => n.kind === 'assign' && n.target === 's').source;
  const other = nodes.find((n) => n.kind === 'assign' && n.target === 'k').source;
  let st = emptyState();
  st = addIdentity(st, 'o.a', 'data:a');
  st = addIdentity(st, 'o.b', 'data:b');
  const r = resolveExprIdentities(st, stringify);
  assert.deepEqual([...r.flat].sort(), ['data:a', 'data:b']);
  assert.deepEqual([...r.byPath.keys()].sort(), ['a', 'b'], 'structure kept through stringify');
  assert.equal(r.widened, false);
  const u = resolveExprIdentities(st, other);
  assert.equal(u.byPath.size, 0, 'an unresolved call flattens');
  assert.equal(u.widened, true);
  // End to end: the field read off the parsed copy carries only its own element.
  const { callGraph } = buildProjectIR({ 't.js': 'app.post("/", (req, res) => { const s = JSON.stringify(req.body); const back = JSON.parse(s); res.send(back.card_number); });' });
  const built = buildGraphWithCoverage(callGraph, { repository: 't', generatedAt: '1970-01-01T00:00:00.000Z' });
  const fl = flows(built.graph);
  // The container element (`body`, from the `req.body` seed) reaches the sink as well, exactly as it does
  // through a plain alias (seeding-across-calls.test.js SA/1); the point here is that the FIELD survives the round trip.
  const names = fl.filter((f) => f.to === 'sink/http-response').flatMap((f) => f.fields).sort();
  assert.ok(names.includes('card_number'), `field identity survives JSON.parse(JSON.stringify(...)): ${names}`);
});

test('BJ/12: helpers and the reuse boundary: identity resolution reads literals and process.env through module constants only; the new module imports nothing from the taint engine', () => {
  const { callGraph } = buildProjectIR({ 'm.js': "const A = process.env.Q; const B = 'lit'; const C = A; const D = compute(); let E = 1; E = 2;" });
  const fn = [...callGraph.functions.values()][0];
  const ident = (n) => ({ kind: 'ident', name: n });
  assert.deepEqual(resolveIdentityExpr(ident('A'), callGraph, 'm.js'), { kind: 'env', value: 'Q' });
  assert.deepEqual(resolveIdentityExpr(ident('B'), callGraph, 'm.js'), { kind: 'literal', value: 'lit' });
  assert.deepEqual(resolveIdentityExpr(ident('C'), callGraph, 'm.js'), { kind: 'env', value: 'Q' });
  assert.equal(resolveIdentityExpr(ident('D'), callGraph, 'm.js'), null);
  assert.equal(resolveIdentityExpr(ident('E'), callGraph, 'm.js'), null, 'assigned twice: not a constant');
  assert.equal(resolveIdentityExpr(ident('nope'), callGraph, 'm.js'), null);
  assert.ok(fn);
  assert.equal(queueCommandOf({ kind: 'member', prop: 'send', object: ident('sqs') }, [{ kind: 'call', isNew: true, callee: ident('ListQueuesCommand'), args: [] }]), null);
  assert.equal(queueCommandOf('sqs.send', []), null);
  assert.equal(planBoundaryJoins({ endpoints: { producers: [], consumers: [], unjoined: [] }, hops: [], callGraph }).seeds.length, 0);
  const src = fs.readFileSync(new URL('../../src/lineage/boundary-join.js', import.meta.url), 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, ['node:crypto', '../dataflow/access-paths.js', './source-seeding.js', './boundary-contract.js', './classification.js']);
});
