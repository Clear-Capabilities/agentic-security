'use strict';
// Tests for the model-cost advisor (PRD R10). Run: node --test hooks/
const { test } = require('node:test');
const assert = require('node:assert');
const {
  classifyTier, modelKey, estimateCost, buildAdvice,
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
