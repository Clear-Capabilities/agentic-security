// Adversarial-review fix (2026-09): `ollama-model-out-of-memory` was a real,
// defined error code (ollama-provider.js) with zero call sites reacting to
// it — a wrong memory-admission estimate that caused a genuine OOM would
// silently repeat the identical wrong decision forever. This module is the
// feedback loop that lets a real observed failure affect the NEXT admission
// decision for the same model on the same machine.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { recordOOMEvent, priorOOMFor, _internals } from '../src/llm-validator/oom-feedback.js';

function cleanupModel(model) {
  try {
    const log = JSON.parse(fs.readFileSync(_internals.LOG_PATH, 'utf8'));
    delete log[model];
    fs.writeFileSync(_internals.LOG_PATH, JSON.stringify(log));
  } catch { /* nothing to clean up */ }
}

test('priorOOMFor: a model with no recorded history returns null', () => {
  const model = 'oom-feedback-never-seen:unique-' + Date.now();
  assert.equal(priorOOMFor(model), null);
});

test('recordOOMEvent + priorOOMFor: a recorded event is readable back with count and timestamps', () => {
  const model = 'oom-feedback-test-model:unique-' + Date.now();
  try {
    recordOOMEvent(model);
    const prior = priorOOMFor(model);
    assert.ok(prior);
    assert.equal(prior.count, 1);
    assert.ok(Number.isFinite(prior.firstAt));
    assert.ok(Number.isFinite(prior.lastAt));
  } finally { cleanupModel(model); }
});

test('recordOOMEvent: repeated events on the same model increment count, not overwrite', () => {
  const model = 'oom-feedback-repeat-model:unique-' + Date.now();
  try {
    recordOOMEvent(model);
    recordOOMEvent(model);
    recordOOMEvent(model);
    const prior = priorOOMFor(model);
    assert.equal(prior.count, 3);
  } finally { cleanupModel(model); }
});

test('recordOOMEvent: a different model is unaffected by another model\'s recorded events', () => {
  const modelA = 'oom-feedback-a:unique-' + Date.now();
  const modelB = 'oom-feedback-b:unique-' + Date.now();
  try {
    recordOOMEvent(modelA);
    assert.equal(priorOOMFor(modelB), null);
  } finally { cleanupModel(modelA); cleanupModel(modelB); }
});

test('recordOOMEvent / priorOOMFor: non-string or empty model degrades safely, never throws', () => {
  assert.doesNotThrow(() => recordOOMEvent(undefined));
  assert.doesNotThrow(() => recordOOMEvent(''));
  assert.doesNotThrow(() => recordOOMEvent(null));
  assert.equal(priorOOMFor(undefined), null);
  assert.equal(priorOOMFor(''), null);
});
