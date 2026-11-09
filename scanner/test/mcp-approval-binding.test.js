// Threat-model PRD FR-06.3 and AC-06B: a high-impact approval binds the tool, action, target finding, exact change and expiry. A copied,
// expired or re-targeted approval cannot approve a write; under the restricted profile an unbound approval is refused outright.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { approvalBindingRefusal } from '../src/mcp/tools.js';

const NOW = Date.parse('2026-11-08T12:00:00Z');
const EXPECT = { tool: 'apply_fix', action: 'apply-patch', target: 'stable-1', change: 'c'.repeat(64) };
const bound = (over = {}) => ({ approvedBy: 'lead', reason: 'reviewed', expires: '2026-11-09T00:00:00Z', scope: { ...EXPECT }, ...over });

test('a bound, unexpired approval for exactly this change passes', () => {
  assert.equal(approvalBindingRefusal(bound(), EXPECT, { now: NOW, restricted: true }), null);
});

test('a copied or re-targeted approval is refused, naming what differs', () => {
  for (const k of ['tool', 'action', 'target', 'change']) {
    const r = approvalBindingRefusal(bound({ scope: { ...EXPECT, [k]: 'other' } }), EXPECT, { now: NOW });
    assert.equal(r, `the approval was issued for another ${k}`, k);
  }
  assert.equal(approvalBindingRefusal(bound({ scope: 'all' }), EXPECT, { now: NOW }), 'the approval scope is not an object');
});

test('an expired or undated-garbage approval is refused', () => {
  assert.equal(approvalBindingRefusal(bound({ expires: '2026-11-01T00:00:00Z' }), EXPECT, { now: NOW }), 'the approval has expired');
  assert.equal(approvalBindingRefusal(bound({ expires: 'tomorrow' }), EXPECT, { now: NOW }), 'the approval expiry is not a date');
});

test('under the restricted profile an approval without scope or expiry is refused; elsewhere the legacy approval still works', () => {
  const legacy = { approvedBy: 'lead', reason: 'reviewed' };
  assert.match(approvalBindingRefusal(legacy, EXPECT, { now: NOW, restricted: true }), /must carry an expiry and a scope/);
  assert.equal(approvalBindingRefusal(legacy, EXPECT, { now: NOW, restricted: false }), null, 'outside the restricted profile the documented legacy approval is unchanged');
});
