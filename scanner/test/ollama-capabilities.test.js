// agentic-security-ollama-offline-prd.md §13, §14, §15, §22.3, §30 — family
// classification and RAM-aware memory admission. Pure functions throughout;
// no network, no real memory measurement (freeBytes is always injected).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyModelFamily, capabilitiesFromFamilyHint, detectMemoryTier,
  evaluateMemoryAdmission, recommendAdmission, MEMORY_PROFILES, KNOWN_MODEL_SIZE_GB,
} from '../src/llm-validator/model-capabilities.js';
import { recordOOMEvent } from '../src/llm-validator/oom-feedback.js';
import * as fs from 'node:fs';
import { _internals as oomInternals } from '../src/llm-validator/oom-feedback.js';

function cleanupOOMModel(model) {
  try {
    const log = JSON.parse(fs.readFileSync(oomInternals.LOG_PATH, 'utf8'));
    delete log[model];
    fs.writeFileSync(oomInternals.LOG_PATH, JSON.stringify(log));
  } catch { /* nothing to clean up */ }
}

const GB = 1024 * 1024 * 1024;

// ── Family classification (FR-1203) ─────────────────────────────────────────

test('classifyModelFamily: qwen3.5 is distinguished from bare qwen3', () => {
  assert.equal(classifyModelFamily('qwen3.5:4b'), 'qwen3.5');
  assert.equal(classifyModelFamily('qwen3:8b'), 'qwen3');
  assert.equal(classifyModelFamily('qwen3-coder:30b'), 'qwen3-coder');
  assert.equal(classifyModelFamily('qwen3-coder-next:latest'), 'qwen3-coder-next');
  assert.equal(classifyModelFamily('qwen2.5-coder:7b'), 'qwen2.5-coder');
});

test('classifyModelFamily: gemma4 is distinguished from gemma3/functiongemma', () => {
  assert.equal(classifyModelFamily('gemma4:e2b'), 'gemma4');
  assert.equal(classifyModelFamily('gemma4:12b'), 'gemma4');
  assert.equal(classifyModelFamily('gemma3:4b'), 'gemma3');
  assert.equal(classifyModelFamily('functiongemma:2b'), 'functiongemma');
});

test('classifyModelFamily: unrecognized/future model names classify as unknown, never rejected', () => {
  assert.equal(classifyModelFamily('some-brand-new-model:99b'), 'unknown');
  assert.equal(classifyModelFamily(''), 'unknown');
  assert.equal(classifyModelFamily(undefined), 'unknown');
});

test('capabilitiesFromFamilyHint: is explicitly marked non-authoritative (source.familyHint, not metadata/runtimeProbe)', () => {
  const c = capabilitiesFromFamilyHint('qwen3.5:4b');
  assert.equal(c.chat, true);
  assert.equal(c.source.familyHint, true);
  assert.equal(c.source.metadata, false);
  assert.equal(c.source.runtimeProbe, false);
});

test('capabilitiesFromFamilyHint: an unknown model gets conservative "unknown" capabilities, not false', () => {
  const c = capabilitiesFromFamilyHint('brand-new-model:1b');
  assert.equal(c.chat, true); // chat is always assumed since Ollama serves /api/chat generically
  assert.equal(c.structuredJson, 'unknown');
  assert.equal(c.tools, 'unknown');
});

// ── Memory tier detection ────────────────────────────────────────────────────

test('detectMemoryTier: real-world "8 GB" machines (slightly under 8*1024^3) still classify as 8gb', () => {
  // Firmware/GPU reservations mean a real 8 GB machine often reports ~7.5-7.8 GB
  // usable to userspace — a naive `< 8*GB` cutoff would misclassify it. The
  // 8gb/16gb boundary itself sits at 9 GB for the same reason (a real 16 GB
  // machine can report as low as ~15 GB), so 8*GB is still inside the 8gb tier.
  assert.equal(detectMemoryTier(7.6 * GB), '8gb');
  assert.equal(detectMemoryTier(8 * GB), '8gb');
  assert.equal(detectMemoryTier(8.9 * GB), '8gb');
});

test('detectMemoryTier: 16 GB and above classify as 16gb', () => {
  assert.equal(detectMemoryTier(16 * GB), '16gb');
  assert.equal(detectMemoryTier(32 * GB), '16gb');
});

test('detectMemoryTier: invalid input is "unknown", not a guess', () => {
  assert.equal(detectMemoryTier(NaN), 'unknown');
  assert.equal(detectMemoryTier(0), 'unknown');
  assert.equal(detectMemoryTier(undefined), 'unknown');
});

// ── Memory admission (PRD §22.3 algorithm) ──────────────────────────────────

test('evaluateMemoryAdmission: qwen3.5:4b at 4K context is admitted on a plentiful-memory machine', () => {
  const r = evaluateMemoryAdmission({
    modelName: 'qwen3.5:4b', contextTokens: 4096, freeBytes: 10 * GB, minFreeRamMb: 1536,
  });
  assert.equal(r.admitted, true);
});

test('evaluateMemoryAdmission: the same model+context is REFUSED when free memory is scarce', () => {
  const r = evaluateMemoryAdmission({
    modelName: 'qwen3.5:4b', contextTokens: 4096, freeBytes: 1.5 * GB, minFreeRamMb: 1536,
  });
  assert.equal(r.admitted, false);
});

test('evaluateMemoryAdmission: a larger context on the same model requires more memory', () => {
  const small = evaluateMemoryAdmission({ modelName: 'qwen3.5:4b', contextTokens: 4096, freeBytes: 5 * GB, minFreeRamMb: 1536 });
  const large = evaluateMemoryAdmission({ modelName: 'qwen3.5:4b', contextTokens: 65536, freeBytes: 5 * GB, minFreeRamMb: 1536 });
  assert.ok(large.requiredMb > small.requiredMb);
});

test('evaluateMemoryAdmission: an unknown model tag is treated pessimistically (8 GB assumed), never optimistically', () => {
  const known = evaluateMemoryAdmission({ modelName: 'qwen3.5:4b', contextTokens: 4096, freeBytes: 5 * GB, minFreeRamMb: 1536 });
  const unknown = evaluateMemoryAdmission({ modelName: 'totally-unrecognized:1b', contextTokens: 4096, freeBytes: 5 * GB, minFreeRamMb: 1536 });
  assert.ok(unknown.requiredMb > known.requiredMb, 'an unrecognized tag must never estimate lower than a known small model');
});

test('evaluateMemoryAdmission: gemma4:e2b at ~7.2GB is refused on an 8 GB machine with typical headroom', () => {
  // PRD §15.1/§15.2: Gemma 4 is explicitly NOT the 8 GB default because even
  // the smallest artifact leaves insufficient headroom.
  const eightGbFreeAfterOsAndApps = 5 * GB; // generous assumption for what's actually free
  const r = evaluateMemoryAdmission({
    modelName: 'gemma4:e2b', contextTokens: 4096, freeBytes: eightGbFreeAfterOsAndApps, minFreeRamMb: 1536,
  });
  assert.equal(r.admitted, false, 'gemma4:e2b (~7.2GB) + KV cache + reserve should not fit in 5GB free');
});

test('recommendAdmission: 8gb profile admits qwen3.5:4b directly when memory is plentiful', () => {
  const r = recommendAdmission({ profile: '8gb', freeBytes: 6 * GB });
  assert.equal(r.admitted, true);
  assert.equal(r.model, 'qwen3.5:4b');
  assert.equal(r.reducedContext, undefined);
});

test('recommendAdmission: 8gb profile REDUCES CONTEXT before falling back to a smaller model', () => {
  // Free memory sized between the target-context (8K) requirement (~5.66GB)
  // and the initial-context (4K) requirement (~5.53GB) for qwen3.5:4b, so
  // only the reduced context fits.
  const r = recommendAdmission({ profile: '8gb', freeBytes: 5.6 * GB });
  assert.equal(r.admitted, true);
  assert.equal(r.model, 'qwen3.5:4b', 'must try context reduction on the SAME model before switching models');
  assert.equal(r.reducedContext, true);
  assert.equal(r.fellBackToSmallerModel, undefined);
});

test('recommendAdmission: 8gb profile falls back to qwen3.5:2b only when 4b does not fit even at minimum context', () => {
  // Between qwen3.5:2b@4K (~3.83GB) and qwen3.5:4b@4K (~5.53GB) requirements —
  // 4b cannot fit even at its smallest context, so the profile must fall back.
  const r = recommendAdmission({ profile: '8gb', freeBytes: 4.5 * GB });
  assert.equal(r.admitted, true);
  assert.equal(r.model, 'qwen3.5:2b');
  assert.equal(r.fellBackToSmallerModel, true);
});

test('recommendAdmission: never recommends cloud — an unfittable profile returns admitted:false with a reason, nothing else', () => {
  const r = recommendAdmission({ profile: '8gb', freeBytes: 200 * 1024 * 1024 /* 200MB, unusably low */ });
  assert.equal(r.admitted, false);
  assert.ok(r.reason);
  assert.equal('provider' in r, false);
  assert.doesNotMatch(JSON.stringify(r).toLowerCase(), /anthropic|openai|gemini|claude|cloud/);
});

test('recommendAdmission: 16gb-qwen profile admits qwen3.5:9b with generous headroom', () => {
  const r = recommendAdmission({ profile: '16gb-qwen', freeBytes: 12 * GB });
  assert.equal(r.admitted, true);
  assert.equal(r.model, 'qwen3.5:9b');
});

test('recommendAdmission: 16gb-gemma profile admits gemma4:e2b with generous 16GB headroom', () => {
  const r = recommendAdmission({ profile: '16gb-gemma', freeBytes: 12 * GB });
  assert.equal(r.admitted, true);
  assert.equal(r.model, 'gemma4:e2b');
});

test('recommendAdmission: unknown profile name fails closed, not silently', () => {
  const r = recommendAdmission({ profile: 'does-not-exist', freeBytes: 100 * GB });
  assert.equal(r.admitted, false);
  assert.match(r.reason, /unknown memory profile/);
});

// Adversarial-review fix (2026-09): a memory-admission estimate that has
// already caused a real, observed OOM on this machine must not keep being
// presented with the same unqualified confidence.
test('recommendAdmission: a model with a prior recorded OOM gets an explicit warning attached, even when still admitted', () => {
  const model = 'oom-admission-test-model:unique-' + Date.now();
  try {
    recordOOMEvent(model);
    const r = recommendAdmission({ profile: '16gb-qwen', freeBytes: 100 * GB, requestedModel: model });
    assert.equal(r.admitted, true, 'plenty of free memory — still admitted');
    assert.ok(r.priorOOMWarning, 'expected a priorOOMWarning field');
    assert.match(r.priorOOMWarning, new RegExp(model.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.match(r.priorOOMWarning, /1 time/);
  } finally { cleanupOOMModel(model); }
});

test('recommendAdmission: a model with NO prior OOM history has no warning field at all', () => {
  const model = 'oom-admission-clean-model:unique-' + Date.now();
  const r = recommendAdmission({ profile: '16gb-qwen', freeBytes: 100 * GB, requestedModel: model });
  assert.equal(r.priorOOMWarning, undefined);
});

test('MEMORY_PROFILES: all three required profiles exist with concurrency 1 (PRD §22.1)', () => {
  assert.ok(MEMORY_PROFILES['8gb']);
  assert.ok(MEMORY_PROFILES['16gb-qwen']);
  assert.ok(MEMORY_PROFILES['16gb-gemma']);
  for (const p of Object.values(MEMORY_PROFILES)) assert.equal(p.maxConcurrency, 1);
});

test('KNOWN_MODEL_SIZE_GB includes both required launch targets', () => {
  assert.ok(KNOWN_MODEL_SIZE_GB['qwen3.5:4b'] > 0);
  assert.ok(KNOWN_MODEL_SIZE_GB['gemma4:e2b'] > 0);
});
