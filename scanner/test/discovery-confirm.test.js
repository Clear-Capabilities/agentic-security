import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CONFIRMATION_TIERS, confirmCandidate, confirmAll } from '../src/discovery/confirm.js';

const C = { id: 'c1', file: 'auth.js', line: 1, family: 'injection', title: 't' };

test('tiers are ordered strongest-first and frozen', () => {
  assert.deepEqual([...CONFIRMATION_TIERS], ['taint-confirmed', 'sink-adjacent', 'unconfirmed']);
  assert.ok(Object.isFrozen(CONFIRMATION_TIERS));
});

test('a probe that finds a taint path yields taint-confirmed with its evidence', async () => {
  const taintProbe = async () => ({ tier: 'taint-confirmed', evidence: { source: 'req.body.n', sink: 'db.query' } });
  const out = await confirmCandidate(C, { taintProbe });
  assert.equal(out.confirmation.tier, 'taint-confirmed');
  assert.equal(out.confirmation.evidence.sink, 'db.query');
  assert.equal(out.confirmation.probedBy, 'taintProbe');
  assert.equal(out.id, 'c1', 'the candidate must pass through unmodified');
});

test('a probe returning null lowers to unconfirmed, not refuted', async () => {
  const out = await confirmCandidate(C, { taintProbe: async () => null });
  assert.equal(out.confirmation.tier, 'unconfirmed');
  assert.equal(out.confirmation.evidence, null);
});

test('a probe that throws lowers to unconfirmed and records why', async () => {
  const out = await confirmCandidate(C, { taintProbe: async () => { throw new Error('IR build failed'); } });
  assert.equal(out.confirmation.tier, 'unconfirmed');
  assert.match(out.confirmation.reason, /IR build failed/);
});

test('no probe at all is unconfirmed, never confirmed by default', async () => {
  const out = await confirmCandidate(C, {});
  assert.equal(out.confirmation.tier, 'unconfirmed');
  assert.equal(out.confirmation.probedBy, null);
});

test('an unknown tier from a probe is rejected rather than trusted', async () => {
  const out = await confirmCandidate(C, { taintProbe: async () => ({ tier: 'definitely-real', evidence: {} }) });
  assert.equal(out.confirmation.tier, 'unconfirmed');
  assert.match(out.confirmation.reason, /unknown tier/);
});

test('confirmAll preserves input order and confirms each independently', async () => {
  const probe = async (c) => (c.line === 2 ? { tier: 'sink-adjacent', evidence: { token: 'eval' } } : null);
  const out = await confirmAll([{ ...C, line: 1 }, { ...C, id: 'c2', line: 2 }], { taintProbe: probe });
  assert.deepEqual(out.map(o => o.confirmation.tier), ['unconfirmed', 'sink-adjacent']);
});
