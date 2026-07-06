// R19 — route-level BOLA/BFLA tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanApiBrokenAuthz } from '../src/sast/api-authz.js';

const R = (over) => ({ method: 'GET', path: '/x', file: 'routes.js', line: 1, hasAuth: false, ...over });

test('BFLA: unauthed state-changer among authed siblings fires', () => {
  const f = scanApiBrokenAuthz([
    R({ method: 'GET', path: '/users', line: 1, hasAuth: true }),
    R({ method: 'POST', path: '/users', line: 2, hasAuth: true }),
    R({ method: 'DELETE', path: '/admin/purge', line: 3, hasAuth: false }), // missing!
  ]);
  assert.equal(f.length, 1);
  assert.match(f[0].vuln, /Function Level/);
  assert.equal(f[0].cwe, '285');
});

test('BOLA: unauthed object-id route among authed siblings fires', () => {
  const f = scanApiBrokenAuthz([
    R({ method: 'GET', path: '/orders', line: 1, hasAuth: true }),
    R({ method: 'GET', path: '/orders/:id', line: 2, hasAuth: false }), // object id, no auth
  ]);
  assert.equal(f.length, 1);
  assert.match(f[0].vuln, /Object Level/);
  assert.equal(f[0].cwe, '639');
});

test('precision: fully-public API (no authed sibling) does not fire', () => {
  assert.equal(scanApiBrokenAuthz([
    R({ method: 'GET', path: '/p/:id', line: 1, hasAuth: false }),
    R({ method: 'POST', path: '/p', line: 2, hasAuth: false }),
  ]).length, 0);
});

test('precision: all-authed API does not fire', () => {
  assert.equal(scanApiBrokenAuthz([
    R({ method: 'GET', path: '/a/:id', line: 1, hasAuth: true }),
    R({ method: 'POST', path: '/a', line: 2, hasAuth: true }),
  ]).length, 0);
});

test('precision: a single route never fires (no siblings to compare)', () => {
  assert.equal(scanApiBrokenAuthz([R({ method: 'DELETE', path: '/a/:id', hasAuth: false })]).length, 0);
});

test('precision: an unauthed GET without an id among authed siblings is not flagged (read, no object id)', () => {
  // GET /health with no id, sibling authed → neither BOLA (no id) nor BFLA (not state-changing).
  assert.equal(scanApiBrokenAuthz([
    R({ method: 'GET', path: '/users', line: 1, hasAuth: true }),
    R({ method: 'GET', path: '/health', line: 2, hasAuth: false }),
  ]).length, 0);
});

// #9 — CWE-306: destructive route with no auth in an all-public FILE, but the
// app authenticates elsewhere (so auth-detection works). The in-file rules can't
// see this; the app-level pass does.
test('#9 CWE-306: unauthed DELETE in an all-public file fires when the app authenticates elsewhere', () => {
  const f = scanApiBrokenAuthz([
    R({ method: 'GET', path: '/me', file: 'a.js', line: 1, hasAuth: true }),          // app has auth somewhere
    R({ method: 'DELETE', path: '/widgets/:id', file: 'b.js', line: 9, hasAuth: false }), // public destructive
  ]);
  assert.equal(f.length, 1);
  assert.equal(f[0].cwe, '306');
  assert.match(f[0].vuln, /Missing authentication/);
});

test('#9 precision: a public POST (login/signup-shaped) does NOT fire as missing-auth', () => {
  assert.equal(scanApiBrokenAuthz([
    R({ method: 'GET', path: '/me', file: 'a.js', line: 1, hasAuth: true }),
    R({ method: 'POST', path: '/login', file: 'b.js', line: 2, hasAuth: false }), // intentionally public
  ]).length, 0);
});

test('#9 precision: no CWE-306 when the app has NO auth anywhere (can\'t trust detection)', () => {
  assert.equal(scanApiBrokenAuthz([
    R({ method: 'DELETE', path: '/widgets/:id', file: 'b.js', line: 9, hasAuth: false }),
    R({ method: 'GET', path: '/widgets', file: 'b.js', line: 1, hasAuth: false }),
  ]).length, 0);
});
