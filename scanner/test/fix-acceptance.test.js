// R25 — auto-fix acceptance-rate metric tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { acceptanceFromEntries } from '../src/posture/fix-history.js';

test('acceptance rate excludes pending from the denominator', () => {
  const r = acceptanceFromEntries([
    { status: 'applied' }, { status: 'applied' }, { status: 'applied' },
    { status: 'reverted' }, { status: 'failed' },
    { status: 'pending' }, // not resolved → not counted
  ]);
  // 3 applied / (3 applied + 1 reverted + 1 failed) = 3/5 = 0.6
  assert.equal(r.acceptanceRate, 0.6);
  assert.equal(r.accepted, 3);
  assert.equal(r.resolved, 5);
  assert.equal(r.pending, 1);
  assert.equal(r.total, 6);
});

test('all applied → 1.0', () => {
  assert.equal(acceptanceFromEntries([{ status: 'applied' }, { status: 'applied' }]).acceptanceRate, 1);
});

test('no resolved attempts → null (not a misleading 0)', () => {
  assert.equal(acceptanceFromEntries([{ status: 'pending' }]).acceptanceRate, null);
  assert.equal(acceptanceFromEntries([]).acceptanceRate, null);
});

test('tolerates malformed input', () => {
  assert.equal(acceptanceFromEntries(null).acceptanceRate, null);
  assert.equal(acceptanceFromEntries([null, { status: 'applied' }, {}]).accepted, 1);
});
