// FR-LOGIC-1 + FR-LOGIC-2 + FR-LOGIC-7 tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanBusinessLogic, _internals } from '../src/posture/business-logic.js';

test('AuthZ inconsistency flagged when sibling route has auth and this one does not', () => {
  const fc = {
    'a.js': `
const router = require('express').Router();
router.get('/api/users/:id', requireAuth, (req, res) => { res.json({ ok: true }) });
router.get('/api/users/list', (req, res) => { res.json({ ok: true }) });
`,
  };
  const findings = scanBusinessLogic(fc);
  assert.ok(findings.some(f => f.family === 'authz-matrix-inconsistency'));
});

test('Potential IDOR (AuthZ matrix) flagged on mutation with :id param + no ownership', () => {
  const fc = {
    'a.js': `
const router = require('express').Router();
router.put('/api/items/:id', requireAuth, (req, res) => {
  Item.findByIdAndUpdate(req.params.id, req.body);
  res.json({});
});`,
  };
  const findings = scanBusinessLogic(fc);
  assert.ok(findings.some(f => f.family === 'idor'));
});

test('State-machine bypass flagged when literal not in declared set', () => {
  const fc = {
    'a.js': `
const STATUSES = ['pending', 'approved', 'rejected'];
function fix(order) { order.status = 'auto-approved'; }
`,
  };
  const findings = scanBusinessLogic(fc);
  assert.ok(findings.some(f => f.family === 'state-machine-bypass'));
  const f = findings.find(x => x.family === 'state-machine-bypass');
  assert.ok(f.vuln.includes('auto-approved'));
});

test('State-machine bypass NOT flagged when value is in declared set', () => {
  const fc = {
    'a.js': `
const STATUSES = ['pending', 'approved', 'rejected'];
function approve(order) { order.status = 'approved'; }
`,
  };
  const findings = scanBusinessLogic(fc);
  assert.equal(findings.filter(f => f.family === 'state-machine-bypass').length, 0);
});

test('State-machine bypass is judged against the set in the SAME file, not a set from another module', () => {
  const fc = {
    'orders.js': `const STATUSES = ['pending', 'approved', 'rejected'];\nfunction ok(o) { o.status = 'approved'; }\n`,
    'jobs.js': `function run(job) { job.status = 'running'; }\n`,
  };
  assert.equal(scanBusinessLogic(fc).filter(f => f.family === 'state-machine-bypass').length, 0);
});

test('State-machine bypass skips test files', () => {
  const fc = {
    'a.js': `const STATUSES = ['pending', 'approved'];\n`,
    'test/a.test.js': `const STATUSES = ['pending', 'approved'];\nfunction t(o) { o.status = 'weird'; }\n`,
  };
  assert.equal(scanBusinessLogic(fc).filter(f => f.family === 'state-machine-bypass').length, 0);
});

test('Negative-test gap flagged when auth route has no 401/403 test', () => {
  const fc = {
    'app.js': `
const router = require('express').Router();
router.delete('/admin/users/:id', requireAuth, (req, res) => { res.json({}) });
`,
    'tests/happy.test.js': `
test('admin can delete user', async () => {
  const r = await fetch('/admin/users/1', { method: 'DELETE' });
  expect(r.status).toBe(200);
});`,
  };
  const findings = scanBusinessLogic(fc);
  assert.ok(findings.some(f => f.family === 'negative-test-gap'));
});

test('Negative-test gap NOT flagged when 403 test exists', () => {
  const fc = {
    'app.js': `
const router = require('express').Router();
router.delete('/admin/users/:id', requireAuth, (req, res) => { res.json({}) });
`,
    'tests/auth.test.js': `
test('unauthorized user cannot delete', async () => {
  const r = await fetch('/admin/users/1', { method: 'DELETE' });
  expect(r.status).toBe(403);
});`,
  };
  const findings = scanBusinessLogic(fc);
  assert.equal(findings.filter(f => f.family === 'negative-test-gap').length, 0);
});

test('null input is safe', () => {
  assert.deepEqual(scanBusinessLogic(null), []);
  assert.deepEqual(scanBusinessLogic({}), []);
});

test('_internals expose the three sub-analyzers', () => {
  assert.equal(typeof _internals.extractAuthZMatrix, 'function');
  assert.equal(typeof _internals.extractStateMachine, 'function');
  assert.equal(typeof _internals.findNegativeTestGaps, 'function');
});
