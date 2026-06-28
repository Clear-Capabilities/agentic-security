'use strict';
// Tests for the model-cost advisor (PRD R10). Run: node --test hooks/
const { test } = require('node:test');
const assert = require('node:assert');
const {
  classifyTier, modelKey, estimateCost, buildAdvice,
  cacheRewarmPenalty, savingsFractionFloor, biasedDial,
} = require('./model-cost-advisor.js');

test('classifyTier — simple prompts', () => {
  assert.equal(classifyTier('what is a closure?'), 'simple');
  assert.equal(classifyTier('summarize this paragraph for me'), 'simple');
  assert.equal(classifyTier('rename the variable x to count'), 'simple');
});

test('classifyTier — complex prompts', () => {
  assert.equal(classifyTier('refactor the auth module to use JWT and migrate the session store'), 'complex');
  assert.equal(classifyTier('debug this:\n```\nat foo (src/app.js:42)\nTypeError: undefined\n```'), 'complex');
  assert.equal(classifyTier('design a multi-tenant architecture for ' + 'x'.repeat(1600)), 'complex');
});

test('classifyTier — medium prompts', () => {
  assert.equal(classifyTier('Improve this loop:\n```\nfor (const x of items) doThing(x)\n```'), 'medium');
});

test('modelKey — normalises ids, snapshots, and family words', () => {
  assert.equal(modelKey('claude-opus-4-8'), 'claude-opus-4-8');
  assert.equal(modelKey('claude-haiku-4-5-20251001'), 'claude-haiku-4-5');
  assert.equal(modelKey('Sonnet'), 'claude-sonnet-4-6');
  assert.equal(modelKey('gpt-4'), null);
  assert.equal(modelKey(''), null);
});

test('estimateCost — opus complex costs more than haiku simple', () => {
  const opus = estimateCost('claude-opus-4-8', 'complex', 'high');
  const haiku = estimateCost('claude-haiku-4-5', 'simple', null);
  assert.ok(opus > haiku);
  assert.equal(estimateCost('bogus-model', 'simple', null), null);
});

test('buildAdvice — Opus/high on a simple prompt suggests Haiku', () => {
  const tip = buildAdvice({
    prompt: 'what is a promise in javascript?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
  });
  assert.match(tip, /Haiku 4\.5/);
  assert.match(tip, /\/model haiku/);
  assert.match(tip, /est\./);
});

test('buildAdvice — never recommends an upgrade (already on Haiku)', () => {
  const tip = buildAdvice({
    prompt: 'refactor the entire billing service and migrate the schema',
    currentModel: 'claude-haiku-4-5',
    currentEffort: null,
  });
  assert.equal(tip, null);
});

test('buildAdvice — same model, lower depth suggests an effort drop only', () => {
  const tip = buildAdvice({
    prompt: 'Improve this loop:\n```\nfor (const x of items) doThing(x)\n```',
    currentModel: 'claude-sonnet-4-6',
    currentEffort: 'high',
  });
  assert.match(tip, /\/effort low/);
  assert.doesNotMatch(tip, /\/model/); // no model change for an effort-only tip
});

test('buildAdvice — respects minSavingsUsd threshold', () => {
  const tip = buildAdvice({
    prompt: 'what is a closure?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
    minSavingsUsd: 1000, // absurdly high → nothing clears it
  });
  assert.equal(tip, null);
});

test('buildAdvice — unknown model declines to advise', () => {
  const tip = buildAdvice({
    prompt: 'what is a closure?',
    currentModel: 'some-other-llm',
    assumedModel: 'also-unknown',
  });
  assert.equal(tip, null);
});

// ── #1 prompt-cache awareness ────────────────────────────────────────────────

test('cacheRewarmPenalty — switching to a pricier-input model costs rewarm; zero ctx is free', () => {
  const p = cacheRewarmPenalty(20000, 'claude-opus-4-8', 'claude-sonnet-4-6');
  assert.ok(p > 0); // sonnet cache-write (1.25×3) exceeds opus cache-read (0.1×5)
  assert.equal(cacheRewarmPenalty(0, 'claude-opus-4-8', 'claude-sonnet-4-6'), 0);
});

test('buildAdvice — small cached context still recommends the cheaper model', () => {
  const tip = buildAdvice({
    prompt: 'what is a promise in javascript?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
    cachedContextTokens: 0,
  });
  assert.match(tip, /\/model haiku/);
});

test('buildAdvice — a moderate cache still advises the switch, with a break-even caveat', () => {
  const tip = buildAdvice({
    prompt: 'what is a promise in javascript?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
    cachedContextTokens: 40000, // break-even ~1-2 turns → still worth switching
  });
  assert.match(tip, /\/model haiku/);
  assert.match(tip, /worth it past ~\d+ more turns/);
});

test('buildAdvice — a deep cache on a simple one-off suggests a Haiku subagent (F5)', () => {
  const tip = buildAdvice({
    prompt: 'what is a promise in javascript?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
    cachedContextTokens: 200000, // switch is cache-blocked → offload to a subagent
  });
  assert.match(tip, /subagent/i);
  assert.match(tip, /Haiku 4\.5/);
  assert.doesNotMatch(tip, /\/model/);   // don't switch the main model
  assert.doesNotMatch(tip, /\/effort/);  // subagent beats a partial effort drop here
});

test('buildAdvice — F5 can be disabled; deep cache then falls back to an effort drop', () => {
  const tip = buildAdvice({
    prompt: 'what is a promise in javascript?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
    cachedContextTokens: 200000,
    subagentAdvice: false,
  });
  assert.match(tip, /\/effort low/);
  assert.doesNotMatch(tip, /subagent/i);
  assert.doesNotMatch(tip, /\/model/);
});

test('buildAdvice — F4 depth-first: a high margin prefers the effort drop over a switch', () => {
  const base = {
    prompt: 'what is a promise in javascript?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
    cachedContextTokens: 0, // cold cache → switch is otherwise on the table
  };
  // Default margin → the 2× cheaper switch is chosen.
  assert.match(buildAdvice(base), /\/model haiku/);
  // A very high margin → the cache-safe effort drop wins instead.
  const tip = buildAdvice({ ...base, depthFirstMargin: 10 });
  assert.match(tip, /\/effort low/);
  assert.doesNotMatch(tip, /\/model/);
});

test('biasedDial — F6 budget biases the dial toward cheaper near/over budget', () => {
  assert.equal(biasedDial(7, 0.50, 1.0), 7);   // under 75% → unchanged
  assert.equal(biasedDial(7, 0.80, 1.0), 9);   // ≥75% → +2
  assert.equal(biasedDial(7, 1.20, 1.0), 10);  // over budget → cheapest
  assert.equal(biasedDial(10, 0.80, 1.0), 10); // capped at 10
  assert.equal(biasedDial(7, 0.99, null), 7);  // no budget → unchanged
});

test('buildAdvice — cold cache (size 0) switches freely with no break-even caveat', () => {
  const tip = buildAdvice({
    prompt: 'what is a promise in javascript?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
    cachedContextTokens: 0,
  });
  assert.match(tip, /\/model haiku/);
  assert.doesNotMatch(tip, /worth it past/);
});

// ── #2 cost-quality dial ─────────────────────────────────────────────────────

test('savingsFractionFloor — monotonic; 0 never advises, 10 is most eager', () => {
  assert.equal(savingsFractionFloor(0), Infinity);
  assert.equal(savingsFractionFloor(10), 0);
  assert.ok(savingsFractionFloor(1) > savingsFractionFloor(5));
  assert.ok(savingsFractionFloor(5) > savingsFractionFloor(9));
  assert.ok(Math.abs(savingsFractionFloor(7) - 0.12) < 1e-9);
});

test('buildAdvice — costQualityTradeoff 0 (pure quality) never downgrades', () => {
  const tip = buildAdvice({
    prompt: 'what is a closure?',
    currentModel: 'claude-opus-4-8',
    currentEffort: 'high',
    costQualityTradeoff: 0,
  });
  assert.equal(tip, null);
});

test('buildAdvice — a higher dial surfaces a borderline saving a lower dial suppresses', () => {
  const base = {
    prompt: 'Improve this loop:\n```\nfor (const x of items) doThing(x)\n```', // medium
    currentModel: 'claude-sonnet-4-6',
    currentEffort: 'medium', // ~26% saving dropping to low
  };
  assert.equal(buildAdvice({ ...base, costQualityTradeoff: 3 }), null);            // floor 28% > 26%
  assert.match(buildAdvice({ ...base, costQualityTradeoff: 6 }), /\/effort low/);  // floor 16% < 26%
});
