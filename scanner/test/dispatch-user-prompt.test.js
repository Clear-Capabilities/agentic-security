// Tests for the UserPromptSubmit dispatcher merge (#24) and the advisor savings
// ledger summary (#12). CJS hook modules, loaded via createRequire.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { mergeOutputs } = require('../../hooks/dispatch-user-prompt.js');
const { summarizeAdvisorLedger } = require('../../hooks/model-cost-advisor.js');

test('mergeOutputs: alias-only → additionalContext, no systemMessage', () => {
  const out = mergeOutputs({ aliasHit: { alias: 'status', replacement: '/posture --status', rest: '' }, adviceOut: null });
  assert.equal(out.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
  assert.match(out.hookSpecificOutput.additionalContext, /\/posture --status/);
  assert.equal(out.systemMessage, undefined);
});

test('mergeOutputs: tip-only (legacy shape, interactive off) → systemMessage, no additionalContext', () => {
  const out = mergeOutputs({ aliasHit: null, adviceOut: { systemMessage: '\u{1F4A1} try haiku' } });
  assert.equal(out.systemMessage, '\u{1F4A1} try haiku');
  assert.equal(out.hookSpecificOutput, undefined);
});

test('mergeOutputs: alias fires + advisor tip-only → union of the two hook outputs', () => {
  const out = mergeOutputs({
    aliasHit: { alias: 'harden', replacement: '/fix --harden', rest: 'x' },
    adviceOut: { systemMessage: 'tip' },
  });
  assert.ok(out.hookSpecificOutput && out.systemMessage);
});

test('mergeOutputs: neither fires → empty object (dispatcher writes nothing)', () => {
  assert.deepEqual(mergeOutputs({ aliasHit: null, adviceOut: null }), {});
});

test('mergeOutputs: alias AND the interactive advisor BOTH set additionalContext on the same prompt → joined, not clobbered', () => {
  const out = mergeOutputs({
    aliasHit: { alias: 'status', replacement: '/posture --status', rest: '' },
    adviceOut: { systemMessage: 'tip', additionalContext: '[model-advisor] call AskUserQuestion...' },
  });
  assert.equal(out.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
  assert.match(out.hookSpecificOutput.additionalContext, /\/posture --status/);
  assert.match(out.hookSpecificOutput.additionalContext, /model-advisor/);
  assert.match(out.hookSpecificOutput.additionalContext, /AskUserQuestion/);
  assert.equal(out.systemMessage, 'tip');
});

test('mergeOutputs: interactive advisor additionalContext only (no alias) → still surfaced under hookSpecificOutput', () => {
  const out = mergeOutputs({
    aliasHit: null,
    adviceOut: { systemMessage: 'tip', additionalContext: '[model-advisor] call AskUserQuestion...' },
  });
  assert.equal(out.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
  assert.match(out.hookSpecificOutput.additionalContext, /model-advisor/);
  assert.equal(out.systemMessage, 'tip');
});

test('summarizeAdvisorLedger (#12): aggregates predicted savings + tier counts', () => {
  const s = summarizeAdvisorLedger([
    { tier: 'simple', kind: 'switch', savings: 0.02 },
    { tier: 'simple', kind: 'switch', savings: 0.03 },
    { tier: 'medium', kind: 'effort', savings: 0.01 },
  ]);
  assert.equal(s.adviceCount, 3);
  assert.ok(Math.abs(s.totalPredictedSavingUsd - 0.06) < 1e-9);
  assert.deepEqual(s.byTier, { simple: 2, medium: 1 });
});

test('summarizeAdvisorLedger: empty / garbage input → zeroed, never throws', () => {
  assert.deepEqual(summarizeAdvisorLedger([]), { adviceCount: 0, totalPredictedSavingUsd: 0, byTier: {} });
  assert.deepEqual(summarizeAdvisorLedger(null), { adviceCount: 0, totalPredictedSavingUsd: 0, byTier: {} });
});
