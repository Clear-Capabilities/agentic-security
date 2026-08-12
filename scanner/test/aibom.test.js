// AI-BOM extraction — smoke test against a labelled fixture set.
//
// "F1" here is extraction correctness: every model in the fixture must be
// extracted; nothing not in the fixture should appear.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { buildAIBOM, aibomToMarkdown } from '../src/posture/aibom.js';
import { readTree } from '../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(__dirname, 'fixtures', 'aibom');

test('AI-BOM: extracts models, prompt templates, frameworks, vector stores', async () => {
  const { scan } = await runScan(FIX);
  const tree = await readTree(FIX);
  const aibom = buildAIBOM(scan, { ...tree.fileContents, ...tree.depFileContents });

  // Models — at least 4: bert-base-uncased, microsoft/phi-3, gpt-4o-mini, claude-sonnet-4-6
  const modelIds = aibom.models.map(m => m.modelId);
  assert.ok(modelIds.includes('bert-base-uncased'), 'expected bert-base-uncased; got: ' + modelIds.join(', '));
  assert.ok(modelIds.includes('microsoft/phi-3-mini-4k-instruct'), 'expected microsoft/phi-3-mini-4k-instruct');
  assert.ok(modelIds.includes('gpt-4o-mini'), 'expected gpt-4o-mini');
  assert.ok(modelIds.includes('claude-sonnet-4-6'), 'expected claude-sonnet-4-6');

  // Pinned vs unpinned: bert-base-uncased should be pinned (revision present)
  const bert = aibom.models.find(m => m.modelId === 'bert-base-uncased');
  assert.equal(bert.pinned, true, 'bert-base-uncased should be pinned');
  const phi = aibom.models.find(m => m.modelId === 'microsoft/phi-3-mini-4k-instruct');
  assert.equal(phi.pinned, false, 'phi-3 should be unpinned in fixture');

  // Prompt templates — system.j2
  const promptFiles = aibom.promptTemplates.map(p => p.file.replace(/\\/g, '/'));
  assert.ok(promptFiles.some(p => p.endsWith('prompts/system.j2')), 'expected prompts/system.j2; got: ' + promptFiles.join(', '));

  // Frameworks — openai + @anthropic-ai/sdk + langchain from package.json
  const fwNames = aibom.frameworks.map(f => f.name);
  assert.ok(fwNames.includes('openai'), 'expected openai framework; got: ' + fwNames.join(', '));
  assert.ok(fwNames.includes('@anthropic-ai/sdk'), 'expected @anthropic-ai/sdk');
  assert.ok(fwNames.includes('langchain'), 'expected langchain');

  // Vector stores — @pinecone-database/pinecone
  const vsNames = aibom.vectorStores.map(v => v.name);
  assert.ok(vsNames.includes('@pinecone-database/pinecone'), 'expected pinecone; got: ' + vsNames.join(', '));

  // Stage 4 correctness audit: _classifyFramework checks FRAMEWORK_PACKAGES
  // before EMBEDDING_PACKAGES and returns on first match — but every member
  // of EMBEDDING_PACKAGES (openai, @anthropic-ai/sdk, sentence-transformers)
  // is ALSO in FRAMEWORK_PACKAGES, so the embedding-provider branch can
  // never be reached for any real package; aibom.embeddings is always [].
  // openai/@anthropic-ai/sdk here are legitimately both an inference
  // framework AND an embedding provider — classification isn't mutually
  // exclusive in reality and shouldn't be treated that way in code.
  const embNames = aibom.embeddings.map(e => e.name);
  assert.ok(embNames.includes('openai'), 'expected openai to also appear as an embedding provider; got: ' + embNames.join(', '));

  // Markdown rendering doesn't crash and contains the section headers
  const md = aibomToMarkdown(aibom);
  assert.match(md, /^# AI-BOM/m);
  assert.match(md, /## Summary/);
  assert.match(md, /## Models/);
  assert.match(md, /## Prompt templates/);
  assert.match(md, /## Inference frameworks/);

  console.log('[AI-BOM] models=' + aibom.models.length + ' prompts=' + aibom.promptTemplates.length + ' frameworks=' + aibom.frameworks.length + ' vectorStores=' + aibom.vectorStores.length);
});
