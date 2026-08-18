// PRD Theme 5 (T5.1–T5.4) — business-logic authorization.
//
// The largest single family in the evidence table: 19 of the 96 root-caused
// real-world misses. The caller IS authenticated; the handler just never
// checks that the object belongs to them — which is why route-level authz
// rules (api-authz.js) cannot see any of these.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanOwnershipAuthz } from '../src/sast/ownership-authz.js';

const sub = (f) => f.map(x => x.subfamily);

test('T5.1: a request-supplied object id reaching a lookup with no ownership check fires', () => {
  const f = scanOwnershipAuthz('org.controller.ts', [
    'export async function getCustomerSource(req, res) {',
    '  const customerId = req.query.customerId;',
    '  const cust = await identityManager.findOneBy({ id: customerId });',
    '  return res.json(cust);',
    '}',
  ].join('\n'));
  assert.deepEqual(sub(f), ['ownership-missing']);
  assert.equal(f[0].cwe, 'CWE-639');
  assert.ok(f[0].checkedFor);
});

test('T5.1 FIX-DISCRIMINATION: scoping the query by the principal silences it', () => {
  const f = scanOwnershipAuthz('org.controller.ts', [
    'export async function getCustomerSource(req, res) {',
    '  const customerId = req.query.customerId;',
    '  const cust = await identityManager.findOneBy({ id: customerId, userId: req.user.id });',
    '  return res.json(cust);',
    '}',
  ].join('\n'));
  assert.deepEqual(f, []);
});

test('T5.1 recognises ANY *Id parameter, not just `id`/`userId`', () => {
  // The real entries use credentialId / subscriptionId / chatflowId — which is
  // precisely why business-logic.js's id heuristic missed them.
  for (const p of ['credentialId', 'subscriptionId', 'chatflowId']) {
    const f = scanOwnershipAuthz('c.ts', [
      'export async function h(req, res) {',
      `  const x = req.params.${p};`,
      '  return await repo.findOneBy({ id: x });',
      '}',
    ].join('\n'));
    assert.equal(f.length, 1, `${p} should be recognised as an object identifier`);
  }
});

test('T5.2: an unscoped lookup in a file that scopes by tenant elsewhere fires', () => {
  const f = scanOwnershipAuthz('svc.ts', [
    'export async function listAll(req, res) {',
    '  return await repo.findOne({ where: { workspaceId: req.user.workspaceId } });',
    '}',
    'export async function getOne(req, res) {',
    '  const chatflowId = req.params.chatflowId;',
    '  return await repo.findOneBy({ id: chatflowId, userId: req.user.id });',
    '}',
  ].join('\n'));
  assert.ok(sub(f).includes('tenant-scope-missing'));
});

test('T5.2 REFUSES when the file establishes no tenant convention', () => {
  const f = scanOwnershipAuthz('svc.ts', [
    'export async function getOne(req, res) {',
    '  const chatflowId = req.params.chatflowId;',
    '  return await repo.findOneBy({ id: chatflowId, userId: req.user.id });',
    '}',
  ].join('\n'));
  assert.ok(!sub(f).includes('tenant-scope-missing'),
    'no tenant convention in the file means there is nothing to deviate from');
});

test('REFUSES: a handler that takes no object id at all', () => {
  assert.deepEqual(scanOwnershipAuthz('h.ts',
    'export async function health(req, res) {\n  return res.json(await repo.findOne({}));\n}'), []);
});

test('REFUSES: an id that never reaches a lookup or mutation', () => {
  assert.deepEqual(scanOwnershipAuthz('h.ts',
    'export async function log(req, res) {\n  const orderId = req.query.orderId;\n  console.log(orderId);\n}'), []);
});

test('non-source files are skipped cheaply', () => {
  assert.deepEqual(scanOwnershipAuthz('a.go', 'req.params.userId'), []);
});
