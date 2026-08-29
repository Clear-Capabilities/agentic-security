import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AI_PROCESSING_CONTEXTS, LINEAGE_DATA_CLASSES, isAiContext, classifyDataElementName,
} from '../../src/lineage/classification.js';

test('AI_PROCESSING_CONTEXTS has all 15 contexts from PRD section 9.2', () => {
  assert.equal(AI_PROCESSING_CONTEXTS.length, 15);
  for (const c of AI_PROCESSING_CONTEXTS) assert.match(c, /^ai\./);
  assert.ok(AI_PROCESSING_CONTEXTS.includes('ai.system_prompt'));
  assert.ok(AI_PROCESSING_CONTEXTS.includes('ai.rag_context'));
  assert.ok(AI_PROCESSING_CONTEXTS.includes('ai.model_artifact'));
});

test('LINEAGE_DATA_CLASSES extends the privacy taxonomy with CONFIDENTIAL', () => {
  assert.ok(LINEAGE_DATA_CLASSES.includes('PII'));
  assert.ok(LINEAGE_DATA_CLASSES.includes('PHI'));
  assert.ok(LINEAGE_DATA_CLASSES.includes('PCI'));
  assert.ok(LINEAGE_DATA_CLASSES.includes('CREDENTIALS'));
  assert.ok(LINEAGE_DATA_CLASSES.includes('CONFIDENTIAL'));
});

test('isAiContext validates against the enum, not a loose prefix check', () => {
  assert.equal(isAiContext('ai.model_input'), true);
  assert.equal(isAiContext('ai.made_up_context'), false);
  assert.equal(isAiContext('not-ai-at-all'), false);
});

test('classifyDataElementName reuses the privacy taxonomy for classes and never guesses AI contexts from a name', () => {
  const hit = classifyDataElementName('card_number');
  assert.ok(hit.classes.includes('PCI'));
  assert.deepEqual(hit.aiContexts, [], 'AI processing can only be proven by flow evidence, not a field name');
});

test('classifyDataElementName returns empty classes for an unrecognized name', () => {
  const hit = classifyDataElementName('totally_unrelated_field');
  assert.deepEqual(hit.classes, []);
});
