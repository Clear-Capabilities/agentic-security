// DAG-08: field-aware cross-boundary propagation (HTTP -> queue -> consumer -> SQL), against parsed code.
import { test } from 'node:test';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import assert from 'node:assert/strict';
import { buildProjectIR } from '../../src/ir/index.js';
import { runTaintEngine } from '../../src/dataflow/engine.js';
import { runBoundaryTaint } from '../../src/dataflow/cross-service-taint.js';
import {
  createBoundaryContract, validateBoundaryContract, contractDigest, bindBoundaryContracts, analyzeServiceBoundaries,
  correlateStorage, attributeEvidence, contractEvidence, evidenceItem, BOUNDARY_CONTRACT_VERSION,
} from '../../src/lineage/boundary-contract.js';

const FILES = {
  'gateway/routes.js': `
const express = require('express');
const app = express();
app.post('/orders', (req, res) => {
  producer.send({ topic: 'orders.created', messages: [{ value: JSON.stringify({ customer_id: req.body.customer_id, display_name: req.body.display_name }) }] });
  res.send('ok');
});
`,
  'worker/consumer.js': `
const db = require('./db');
async function handleOrder(evt) {
  const q = "SELECT * FROM orders WHERE customer = '" + evt.customerId + "'";
  db.query(q);
}
async function logName(evt) {
  const label = "SELECT '" + evt.displayName + "'";
  db.query(label);
}
module.exports = { handleOrder, logName };
`,
};

function parsed() { return buildProjectIR(FILES); }

const queueContract = (over = {}) => createBoundaryContract({
  id: 'boundary:orders-created', kind: 'queue', persistence: 'persisted',
  channel: { topic: 'orders.created' }, schema: { name: 'OrderCreated', version: '2' },
  producer: { service: 'gateway', site: { file: 'gateway/routes.js', function: '<module>' }, untrustedFields: ['customer_id', 'display_name'] },
  consumer: { service: 'worker', site: { file: 'worker/consumer.js', function: 'handleOrder', param: 'evt' } },
  fieldMappings: [{ from: 'customer_id', to: 'customerId' }],
  declaredBy: 'ross@example.test',
  ...over,
});

test('baseline: the consumer has no ordinary HTTP source, so the plain engine finds nothing', () => {
  const r = parsed();
  assert.equal(runTaintEngine(r.perFile, r.callGraph, {}).length, 0);
});

test('HTTP to queue to consumer to SQL: the consumer-side flow is discovered from the contract alone', () => {
  const r = parsed();
  const res = runBoundaryTaint(r.perFile, r.callGraph, [queueContract()]);
  assert.equal(res.gaps.filter((g) => g.side === 'consumer').length, 0);
  assert.equal(res.findings.length, 1);
  const f = res.findings[0];
  assert.equal(f.file, 'worker/consumer.js');
  assert.match(f.cwe, /89/);
  assert.equal(f.boundarySeeded, true);
  assert.equal(f.boundary.contractId, 'boundary:orders-created');
  assert.equal(f.boundary.upstream.service, 'gateway');
  assert.equal(f.boundary.persistence, 'persisted');
  // a declaration is a modeled input, never an observation or an exploit
  assert.equal(f.boundary.modeledInput, true);
  assert.equal(f.boundary.observed, false);
  assert.equal(f.boundary.exploited, false);
  assert.equal(f.boundary.attribution.declaredOnly, true);
  // the shared call graph is left unseeded
  for (const fn of r.callGraph.functions.values()) assert.equal(fn.boundarySeeds, undefined);
});

test('producer customer_id mapped to consumer customerId tracks that field and not the sibling displayName', () => {
  const r = parsed();
  const res = runBoundaryTaint(r.perFile, r.callGraph, [
    queueContract({ consumer: { service: 'worker', site: { file: 'worker/consumer.js', function: 'logName', param: 'evt' } } }),
  ]);
  // logName reads only evt.displayName, which this contract does not map
  assert.equal(res.findings.length, 0);
  const both = runBoundaryTaint(r.perFile, r.callGraph, [queueContract()]);
  assert.deepEqual(both.findings[0].boundary.fields.map((x) => [x.producerField, x.consumerField]), [['customer_id', 'customerId']]);
  assert.deepEqual(both.bindings[0].seeds, ['evt.customerId']);
});

test('mapping the sibling explicitly seeds that field and attributes it to its own producer field', () => {
  const r = parsed();
  const res = runBoundaryTaint(r.perFile, r.callGraph, [
    queueContract({ consumer: { service: 'worker', site: { file: 'worker/consumer.js', function: 'logName', param: 'evt' } }, fieldMappings: [{ from: 'display_name', to: 'displayName' }] }),
  ]);
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].boundary.fields[0].producerField, 'display_name');
});

test('a declared but unbound queue consumer reports a gap and never a finding', () => {
  const r = parsed();
  const missingFn = queueContract({ consumer: { service: 'worker', site: { file: 'worker/consumer.js', function: 'noSuchHandler', param: 'evt' } } });
  const missingFile = queueContract({ id: 'boundary:other', consumer: { service: 'worker', site: { file: 'worker/nowhere.js', function: 'handleOrder', param: 'evt' } } });
  const missingParam = queueContract({ id: 'boundary:param', consumer: { service: 'worker', site: { file: 'worker/consumer.js', function: 'handleOrder', param: 'message' } } });
  const res = runBoundaryTaint(r.perFile, r.callGraph, [missingFn, missingFile, missingParam]);
  assert.equal(res.findings.length, 0);
  assert.deepEqual(res.gaps.filter((g) => g.side === 'consumer').map((g) => g.reason).sort(), ['file-not-found', 'function-not-found', 'param-not-found']);
  assert.ok(res.gaps.every((g) => g.kind === 'unbound-boundary'));
  assert.equal(res.coverage.bound, 0);
  assert.equal(res.coverage.unbound, 3);
});

test('an invalid contract is rejected, not bound, and not silently dropped', () => {
  const r = parsed();
  const bad = { ...queueContract(), evidence: { declared: true, observed: true } };
  const res = runBoundaryTaint(r.perFile, r.callGraph, [bad]);
  assert.equal(res.rejected.length, 1);
  assert.equal(res.findings.length, 0);
  assert.equal(validateBoundaryContract({ ...queueContract(), version: '9.9.9' }).valid, false);
});

test('a producer site that does not resolve is a gap, and the consumer still binds from its own declaration', () => {
  const r = parsed();
  const c = queueContract({ producer: { service: 'gateway', site: { file: 'gateway/missing.js', function: 'send' }, untrustedFields: [] } });
  const { bindings, gaps } = bindBoundaryContracts([c], r.callGraph);
  assert.equal(bindings.length, 1);
  assert.deepEqual(gaps.map((g) => [g.side, g.reason]), [['producer', 'file-not-found']]);
});

test('digest covers the contract meaning, and a stale configDigest is a failed digest check, not an observation', () => {
  const c = queueContract();
  assert.equal(c.configDigest, contractDigest(c));
  assert.notEqual(contractDigest({ ...c, fieldMappings: [{ from: 'customer_id', to: 'other' }] }), c.configDigest);
  const stale = { ...c, fieldMappings: [{ from: 'customer_id', to: 'other' }] };
  const ev = contractEvidence(stale);
  assert.equal(ev.find((e) => e.kind === 'digest-check').ok, false);
  assert.equal(attributeEvidence(ev).observed, false);
  assert.equal(c.version, BOUNDARY_CONTRACT_VERSION);
});

test('storage write then later read correlate only under a storage contract; field names alone never join', () => {
  const c = createBoundaryContract({
    id: 'boundary:orders-table', kind: 'storage', persistence: 'persisted',
    channel: { store: 'postgres', table: 'orders', key: 'order_id' }, schema: { name: 'orders', version: '3' },
    producer: { service: 'api', site: null }, consumer: { service: 'billing', site: { file: 'worker/consumer.js', function: 'handleOrder', param: 'evt' } },
    fieldMappings: [{ from: 'customer_id', to: 'customerId' }], declaredBy: 'ops',
  });
  const w = { store: 'postgres', table: 'orders', key: 'order_id', schemaVersion: '3', fields: ['customer_id', 'note'], site: 'api/save.js:10' };
  const rd = { store: 'postgres', table: 'orders', key: 'order_id', schemaVersion: '3', fields: ['customerId'], site: 'billing/load.js:4' };
  const otherTable = { store: 'postgres', table: 'invoices', key: 'order_id', fields: ['customerId'], site: 'billing/inv.js:2' };
  const wrongVersion = { store: 'postgres', table: 'orders', key: 'order_id', schemaVersion: '1', fields: ['customerId'], site: 'billing/old.js:2' };
  const { joins, unjoined } = correlateStorage([c], [w], [rd, otherTable, wrongVersion]);
  assert.equal(joins.length, 1);
  assert.deepEqual(joins[0].fields, [{ from: 'customer_id', to: 'customerId' }]);
  assert.equal(joins[0].persistence, 'persisted');
  assert.equal(joins[0].immediate, false);
  assert.deepEqual(unjoined.map((u) => u.site).sort(), ['billing/inv.js:2', 'billing/old.js:2']);
  // same field names, no contract: nothing joins
  const none = correlateStorage([], [w], [rd]);
  assert.equal(none.joins.length, 0);
  assert.equal(none.unjoined.length, 2);
  // a contract for a different table does not join this pair either
  const other = createBoundaryContract({ ...c, channel: { ...c.channel, table: 'customers' } });
  assert.equal(correlateStorage([other], [w], [rd]).joins.length, 0);
});

test('storage and http contracts must declare the persistence class that matches their edge', () => {
  assert.equal(validateBoundaryContract({ ...queueContract({ kind: 'storage', channel: { store: 's', table: 't', key: 'k' } }), persistence: 'immediate' }).valid, false);
  assert.equal(validateBoundaryContract({ ...queueContract({ kind: 'http', channel: { route: '/x' } }), persistence: 'persisted' }).valid, false);
});

test('service cycles are solved with SCC and a worklist, never assumed to be a DAG', () => {
  const mk = (id, from, to, mappings, extra = {}) => createBoundaryContract({
    id, kind: 'queue', persistence: 'persisted', channel: { topic: id }, schema: { name: id, version: '1' },
    producer: { service: from, site: null, ...extra }, consumer: { service: to, site: { file: 'f.js', function: 'g', param: 'p' } },
    fieldMappings: mappings, declaredBy: 'ops',
  });
  const cs = [
    mk('boundary:ab', 'A', 'B', [{ from: 'cust_id', to: 'customerId' }], { untrustedFields: ['cust_id'] }),
    mk('boundary:bc', 'B', 'C', [{ from: 'customerId', to: 'cid' }]),
    mk('boundary:ca', 'C', 'A', [{ from: 'cid', to: 'cust_id2' }]),
    mk('boundary:ab2', 'A', 'B', [{ from: 'cust_id2', to: 'customerId2' }]),
  ];
  const res = analyzeServiceBoundaries(cs);
  assert.deepEqual(res.cycles, [['A', 'B', 'C']]);
  assert.equal(res.converged, true);
  assert.equal(res.truncated, false);
  assert.deepEqual(res.taintedFields.B, ['customerId', 'customerId2']);
  assert.deepEqual(res.taintedFields.C, ['cid']);
  assert.deepEqual(res.taintedFields.A, ['cust_id2']);
  // budgets are honored and reported, never treated as convergence
  const tight = analyzeServiceBoundaries(cs, { maxFacts: 2 });
  assert.equal(tight.truncated, true);
  assert.equal(tight.converged, false);
  const rounds = analyzeServiceBoundaries(cs, { maxRounds: 1 });
  assert.equal(rounds.converged, false);
});

test('only an observed-connection item can make evidence observed, and contracts never create one', () => {
  const declared = [evidenceItem('manual-assertion'), evidenceItem('code-mapping'), evidenceItem('digest-check'), evidenceItem('foreign-graph-validation')];
  const a = attributeEvidence(declared);
  assert.equal(a.observed, false);
  assert.equal(a.declaredOnly, true);
  assert.equal(Object.keys(a.byKind).length, 5);
  assert.equal(attributeEvidence([...declared, evidenceItem('observed-connection', { source: 'otel' })]).observed, true);
  assert.throws(() => evidenceItem('guessed'));
  assert.equal(contractEvidence(queueContract()).some((e) => e.kind === 'observed-connection'), false);
});

test('contracts are read from .agentic-security/boundary-contracts.json when none are passed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-boundary-'));
  fs.mkdirSync(path.join(root, '.agentic-security'));
  fs.writeFileSync(path.join(root, '.agentic-security', 'boundary-contracts.json'), JSON.stringify({ contracts: [queueContract()] }));
  const r = parsed();
  const res = runBoundaryTaint(r.perFile, r.callGraph, undefined, { scanRoot: root });
  assert.equal(res.findings.length, 1);
  fs.writeFileSync(path.join(root, '.agentic-security', 'boundary-contracts.json'), '{not json');
  const bad = runBoundaryTaint(r.perFile, r.callGraph, undefined, { scanRoot: root });
  assert.equal(bad.findings.length, 0);
  assert.equal(bad.loadErrors.length, 1);
  fs.rmSync(root, { recursive: true, force: true });
});
