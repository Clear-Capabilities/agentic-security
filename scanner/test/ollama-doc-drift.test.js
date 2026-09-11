// Adversarial-review fix (2026-09): docs/guides/ollama.md states specific
// numeric defaults (context sizes, timeouts, cache TTL, the tool-loop
// iteration ceiling) as prose, with nothing anywhere that fails if the
// SOURCE constants those numbers describe ever change — `check-doc-drift.mjs`
// only catches broken FILE references, not numeric claims. This file is that
// missing check, for the specific numbers a maintainer is most likely to
// tune without remembering to update the guide.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_MAX_TOOL_ITERATIONS } from '../src/llm-validator/agent-loop.js';
import { DEFAULT_CACHE_TTL_MS } from '../src/llm-validator/model-probe.js';
import { ollamaEndpointConfig } from '../src/llm-validator/ollama-provider.js';
import { MEMORY_PROFILES } from '../src/llm-validator/model-capabilities.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GUIDE_PATH = path.resolve(__dirname, '..', '..', 'docs', 'guides', 'ollama.md');
const guide = fs.readFileSync(GUIDE_PATH, 'utf8');

test('docs/guides/ollama.md: the tool-loop iteration ceiling matches DEFAULT_MAX_TOOL_ITERATIONS', () => {
  // Prose in the guide wraps across lines (a real newline, not a literal
  // space, can sit between the number and the word it describes) — match
  // on whitespace-normalized text so a markdown re-wrap alone never breaks
  // this check.
  const flat = guide.replace(/\s+/g, ' ');
  assert.match(flat, new RegExp(`${DEFAULT_MAX_TOOL_ITERATIONS} tool-call iterations`),
    `guide's stated iteration ceiling must match agent-loop.js's real DEFAULT_MAX_TOOL_ITERATIONS (${DEFAULT_MAX_TOOL_ITERATIONS})`);
});

test('docs/guides/ollama.md: the capability-probe cache TTL matches DEFAULT_CACHE_TTL_MS', () => {
  const flat = guide.replace(/\s+/g, ' ');
  const days = DEFAULT_CACHE_TTL_MS / (24 * 60 * 60 * 1000);
  assert.match(flat, new RegExp(`${days}-day safety-net expiry`),
    `guide's stated cache TTL must match model-probe.js's real DEFAULT_CACHE_TTL_MS (${days} days)`);
});

test('docs/guides/ollama.md: the connect-timeout / request-timeout / keep-alive defaults match ollamaEndpointConfig\'s real values', () => {
  const flat = guide.replace(/\s+/g, ' ');
  const cfg = ollamaEndpointConfig({}).config;
  const connectSeconds = cfg.connectTimeoutMs / 1000;
  assert.match(flat, new RegExp(`~${connectSeconds} seconds?`),
    `guide's stated connect-timeout must match ollama-provider.js's real default (${connectSeconds}s)`);
  assert.match(flat, new RegExp(`default ${cfg.requestTimeoutMs}ms`),
    `guide's stated request-timeout must match ollama-provider.js's real default (${cfg.requestTimeoutMs}ms)`);
  assert.match(flat, new RegExp(`default ${cfg.keepAlive}`),
    `guide's stated keep-alive default must match ollama-provider.js's real default (${cfg.keepAlive})`);
});

test('docs/guides/ollama.md: the 8GB/16GB RAM-tier context tables match MEMORY_PROFILES\'s real values', () => {
  const kb = (tokens) => tokens / 1024;
  const p8 = MEMORY_PROFILES['8gb'];
  const pQwen = MEMORY_PROFILES['16gb-qwen'];
  const pGemma = MEMORY_PROFILES['16gb-gemma'];
  assert.match(guide, new RegExp(`${kb(p8.initialContextTokens)}K, target ${kb(p8.targetContextTokens)}K after admission`),
    'guide\'s 8GB row must match the real 8gb profile\'s context tokens');
  assert.match(guide, new RegExp(`${kb(pQwen.initialContextTokens)}K, target ${kb(pQwen.targetContextTokens)}K\\+? after admission`),
    'guide\'s 16GB Qwen row must match the real 16gb-qwen profile\'s context tokens');
  assert.match(guide, new RegExp(`${kb(pGemma.initialContextTokens)}K, target ${kb(pGemma.targetContextTokens)}K after admission`),
    'guide\'s 16GB Gemma row must match the real 16gb-gemma profile\'s context tokens');
});
