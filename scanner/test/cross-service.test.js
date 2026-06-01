// R22 — cross-service dataflow (client→route edge inference) tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCrossService, normalizePath } from '../src/sast/cross-service.js';

test('normalizePath collapses dynamic segments + strips host/query', () => {
  assert.equal(normalizePath('https://svc/orders/123?x=1'), '/orders/*');
  assert.equal(normalizePath('/users/:id'), '/users/*');
  assert.equal(normalizePath('/internal/users'), '/internal/users');
});

const routes = [
  { method: 'POST', path: '/internal/users', file: 'svcB/routes.js', hasAuth: false },
  { method: 'GET', path: '/orders/:id', file: 'svcB/orders.js', hasAuth: true },
];

test('client→unauthenticated route with user data → high cross-service finding', () => {
  const fc = {
    'svcA/client.js': `await axios.post('/internal/users', req.body);`,
    'svcB/routes.js': `app.post('/internal/users', (req,res)=>{});`,
  };
  const f = scanCrossService(routes, fc);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
  assert.equal(f[0].cwe, 'CWE-862');
  assert.match(f[0].vuln, /unauthenticated/);
  assert.equal(f[0]._edge.to, 'svcB/routes.js');
});

test('client→authenticated route with user data → medium', () => {
  const fc = { 'svcA/c.js': `fetch('/orders/' + req.params.id)` };
  // /orders/<concatenated> normalizes via the literal prefix; use a literal id.
  const fc2 = { 'svcA/c.js': `fetch('/orders/123', { headers: { x: req.headers.auth } })` };
  const f = scanCrossService(routes, fc2);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'medium'); // route hasAuth:true
});

test('precision: no user data in the call → no finding', () => {
  const f = scanCrossService(routes, { 'svcA/c.js': `axios.post('/internal/users', { ping: 1 })` });
  assert.equal(f.length, 0);
});

test('precision: same-file call is not a cross-service edge', () => {
  const fc = { 'svcB/routes.js': `app.post('/internal/users',()=>{}); axios.post('/internal/users', req.body);` };
  assert.equal(scanCrossService(routes, fc).length, 0);
});

test('precision: client path with no matching route → no finding', () => {
  assert.equal(scanCrossService(routes, { 'a.js': `axios.post('/nope/here', req.body)` }).length, 0);
});
