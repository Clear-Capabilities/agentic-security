// R19 — route-level BOLA/BFLA tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanApiBrokenAuthz } from '../src/sast/api-authz.js';
import { runScan } from '../src/runScan.js';

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

// Regression: found while root-causing independent-population false negative
// GHSA-fm2f-4339-4p2f. engine.js's scanRoutes() hasAuth-detection regex
// didn't recognize permission-string-based RBAC middleware (checkPermission/
// checkAnyPermission), so a route family entirely gated by it — GET/DELETE
// guarded, PUT left open — was seen as having ZERO authed routes and the
// whole-file BFLA inconsistency check never fired. This exercises the real
// scanRoutes() regex end-to-end, not a mocked hasAuth boolean.
test('BFLA end-to-end: checkAnyPermission-guarded siblings are recognized as authed, so the unguarded PUT fires', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'checkpermission-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
    fs.writeFileSync(
      path.join(dir, 'executions.js'),
      [
        "const router = require('express').Router();",
        "",
        "router.get('/', checkAnyPermission('executions:view'), executionController.getAll);",
        "",
        "",
        "",
        "",
        "router.delete('/:id', checkAnyPermission('executions:delete'), executionController.remove);",
        "",
        "",
        "",
        "",
        "router.put('/:id', executionController.updateExecution);",
        "",
        'module.exports = router;',
      ].join('\n')
    );
    const { scan } = await runScan(dir);
    const putRoute = (scan.routes || []).find(r => r.method === 'PUT');
    const getRoute = (scan.routes || []).find(r => r.method === 'GET');
    assert.ok(getRoute, 'GET route must be inventoried');
    assert.equal(getRoute.hasAuth, true, 'checkAnyPermission(...) must be recognized as auth');
    assert.ok(putRoute, 'PUT route must be inventoried');
    assert.equal(putRoute.hasAuth, false, 'the genuinely unguarded PUT must still read as unauthed');
    // PUT /:id carries an id param, so api-authz.js classifies the finding as
    // BOLA (Object Level) rather than BFLA (Function Level) — either is the
    // correct broken-access-control family; what this test actually pins is
    // that the inconsistency fires AT ALL now that the guarded siblings are
    // recognized as authed (previously the whole file read as unauthenticated,
    // so `authed === group.length` in api-authz.js's own precision gate
    // (authed < 1 || authed === group.length → skip) was 0 === 3, silently
    // skipping the file entirely).
    const putFindings = scanApiBrokenAuthz(scan.routes || []).filter(f => f.line === putRoute.line);
    assert.ok(putFindings.length > 0, 'the unguarded PUT among checkAnyPermission-guarded siblings must fire a broken-access-control finding');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
