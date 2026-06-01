// R21 — RBAC role-tier consistency tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanRbacConsistency, _internals } from '../src/sast/rbac-consistency.js';

test('tierOf ranks privilege levels', () => {
  assert.ok(_internals.tierOf('superadmin') > _internals.tierOf('admin'));
  assert.ok(_internals.tierOf('admin') > _internals.tierOf('user'));
  assert.ok(_internals.tierOf('user') > _internals.tierOf('guest'));
});

test('missing role on a state-changer among role-checked siblings fires', () => {
  const fc = {
    'r.js': [
      "app.get('/users', requireRole('admin'), h);",      // line 1
      "app.delete('/users/:id', h);",                       // line 2 — no role!
    ].join('\n'),
  };
  const routes = [
    { method: 'GET', path: '/users', file: 'r.js', line: 1 },
    { method: 'DELETE', path: '/users/:id', file: 'r.js', line: 2 },
  ];
  const f = scanRbacConsistency(routes, fc);
  assert.equal(f.length, 1);
  assert.match(f[0].vuln, /Missing role-based authorization/);
  assert.equal(f[0].cwe, '285');
});

test('tier inversion: delete at lower tier than read fires', () => {
  const fc = {
    'r.js': [
      "app.get('/reports', requireRole('admin'), h);",     // read needs admin (tier 2)
      "app.delete('/reports/:id', requireRole('user'), h);", // delete needs only user (tier 1)
    ].join('\n'),
  };
  const routes = [
    { method: 'GET', path: '/reports', file: 'r.js', line: 1 },
    { method: 'DELETE', path: '/reports/:id', file: 'r.js', line: 2 },
  ];
  const f = scanRbacConsistency(routes, fc);
  assert.ok(f.some(x => /tier inversion/.test(x.vuln)));
});

test('precision: consistent roles do not fire', () => {
  const fc = {
    'r.js': [
      "app.get('/x', requireRole('admin'), h);",
      "app.delete('/x/:id', requireRole('admin'), h);",
    ].join('\n'),
  };
  const routes = [
    { method: 'GET', path: '/x', file: 'r.js', line: 1 },
    { method: 'DELETE', path: '/x/:id', file: 'r.js', line: 2 },
  ];
  assert.equal(scanRbacConsistency(routes, fc).length, 0);
});

test('precision: a resource that uses no roles at all is not flagged', () => {
  const fc = { 'r.js': "app.get('/p', h);\napp.post('/p', h);" };
  const routes = [
    { method: 'GET', path: '/p', file: 'r.js', line: 1 },
    { method: 'POST', path: '/p', file: 'r.js', line: 2 },
  ];
  assert.equal(scanRbacConsistency(routes, fc).length, 0);
});
