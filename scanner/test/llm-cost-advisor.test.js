// LLM cost + prompt-cache advisor detector (PRD CACHE_ECONOMICS_V2 F1/P3).
import { test } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanLlmCost } from '../src/sast/llm-cost-advisor.js';
import { detectProvider, cheaperModel, modelEntry } from '../src/posture/provider-catalog.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FX = path.join(HERE, 'fixtures', 'llm-cost-advisor');
const read = (rel) => fs.readFileSync(path.join(FX, rel), 'utf8');
const scan = (rel) => scanLlmCost(rel, read(rel));

test('provider-catalog — detection + ladder helpers', () => {
  assert.equal(detectProvider('from openai import OpenAI'), 'openai');
  assert.equal(detectProvider('import Anthropic from "@anthropic-ai/sdk"'), 'anthropic');
  assert.equal(detectProvider('import google.generativeai as genai'), 'google');
  assert.equal(detectProvider('const x = await fetch("https://api.x.ai/v1")'), 'xai');
  assert.equal(detectProvider('const a = 1;'), null);
  assert.equal(modelEntry('openai', 'gpt-5.5').tier, 3);
  assert.equal(cheaperModel('anthropic', 'claude-opus-4-8').id, 'claude-sonnet-4-6');
  assert.equal(cheaperModel('anthropic', 'claude-haiku-4-5'), null); // already cheapest
});

test('vulnerable — flags both the cache-killer and the over-provisioned model', () => {
  const py = scan('vulnerable/openai_app.py');
  assert.ok(py.some(f => f.family === 'llm-cache'), 'cache-killer not flagged');
  assert.ok(py.some(f => f.family === 'llm-cost'), 'over-provisioned not flagged');
  assert.match(py.find(f => f.family === 'llm-cache').remediation, /never hits and you pay full input price/);
  assert.match(py.find(f => f.family === 'llm-cost').remediation, /gpt-5\.4 at reasoning_effort=low/);

  const js = scan('vulnerable/anthropic_app.js');
  assert.ok(js.some(f => f.family === 'llm-cache'));
  assert.ok(js.some(f => f.family === 'llm-cost'));
  assert.match(js.find(f => f.family === 'llm-cost').remediation, /claude-sonnet-4-6 at effort=low/);
  // Advisory severity only — never inflates security counts.
  assert.ok([...py, ...js].every(f => f.severity === 'low' || f.severity === 'info'));
});

test('clean — no findings (static prefix, cheaper model, timestamp outside the prompt)', () => {
  assert.deepEqual(scan('clean/openai_clean.py'), []);
  assert.deepEqual(scan('clean/anthropic_clean.js'), []);
});

test('no provider detected → detector is silent (low FP on non-LLM code)', () => {
  const src = 'const t = Date.now();\nconst system = `at ${t}`;\nconsole.log(system);';
  assert.deepEqual(scanLlmCost('util.js', src), []);
});
