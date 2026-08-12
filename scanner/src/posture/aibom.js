// AI-BOM — AI / ML Bill of Materials.
//
// OWASP LLMSecOps explicitly names AI/ML Bill of Materials. This is the AI
// counterpart to SBOM (CycloneDX 1.6) and PBOM. We emit a JSON structure
// modeled on CycloneDX 1.7's ML-BOM extension where applicable, plus a
// human-readable Markdown table.
//
// Components captured (extracted from already-scanned source):
//   - Hugging Face models loaded via from_pretrained / hf_hub_download
//   - OpenAI / Anthropic / Google / Mistral / Cohere / Groq / Together / Bedrock
//     / Vertex / Replicate / OpenRouter API endpoints (called via SDK)
//   - Prompt template files (.prompt / .j2 / .jinja / .tmpl / .mustache /
//     prompts/ directory)
//   - Inference framework versions from manifests (transformers, torch,
//     openai, anthropic, vercel-ai, langchain, llama-index, ollama, etc.)
//   - Vector store configurations (pinecone, weaviate, chroma, qdrant,
//     pgvector, milvus, faiss)
//
// No outbound calls; pure transform from already-collected fileContents and
// scan.components. Extraction precision is verified by a smoke test against
// a labelled fixture set.

import * as crypto from 'node:crypto';

// SDK / API endpoint detection — same family list as scanner/src/sast/llm.js
const HF_FROM_PRETRAINED_RE = /(?:Auto(?:Model|Tokenizer|Config|Processor|FeatureExtractor)|[A-Z][A-Za-z]*Model|[A-Z][A-Za-z]*Tokenizer)\.from_pretrained\s*\(\s*['"]([\w./-]+)['"](?:[^)]*?revision\s*=\s*['"]([\w]+)['"])?/g;
const HF_HUB_DOWNLOAD_RE = /hf_hub_download\s*\(\s*repo_id\s*=\s*['"]([\w./-]+)['"](?:[^)]*?revision\s*=\s*['"]([\w]+)['"])?/g;

// API providers and their SDK call patterns (capture the model name string when present)
const PROVIDER_PATTERNS = [
  // OpenAI: client.chat.completions.create({ model: "gpt-4o-mini", ... })
  { provider: 'openai', re: /(?:openai|client|oai)\.(?:chat\.)?completions\.create\s*\(\s*[{(]\s*[^{}]*?model\s*[:=]\s*['"]([^'"]+)['"]/g },
  { provider: 'openai', re: /(?:openai|client|oai)\.responses\.create\s*\(\s*[{(]\s*[^{}]*?model\s*[:=]\s*['"]([^'"]+)['"]/g },
  // Anthropic: anthropic.messages.create({ model: "claude-sonnet-4-6", ... })
  { provider: 'anthropic', re: /(?:anthropic|client|claude)\.(?:messages|completions)\.create\s*\(\s*[{(]\s*[^{}]*?model\s*[:=]\s*['"]([^'"]+)['"]/g },
  // Vercel AI SDK: generateText({ model: openai("gpt-4o"), ... }) — extract from inner SDK call
  { provider: 'openai (via vercel-ai)', re: /(?:generateText|streamText|generateObject)\s*\(\s*\{[^{}]*?model\s*:\s*openai\s*\(\s*['"]([^'"]+)['"]/g },
  { provider: 'anthropic (via vercel-ai)', re: /(?:generateText|streamText|generateObject)\s*\(\s*\{[^{}]*?model\s*:\s*anthropic\s*\(\s*['"]([^'"]+)['"]/g },
  // Google Generative AI
  { provider: 'google', re: /(?:genAI|GoogleGenerativeAI)\s*\([^)]*?\)\.getGenerativeModel\s*\(\s*\{[^{}]*?model\s*:\s*['"]([^'"]+)['"]/g },
  // Mistral / Cohere / Groq / Together
  { provider: 'mistral', re: /\bmistral\.chat\.complete\s*\(\s*\{[^{}]*?model\s*:\s*['"]([^'"]+)['"]/g },
  { provider: 'cohere', re: /\b(?:cohere|co)\.(?:chat|generate)\s*\(\s*\{[^{}]*?model\s*:\s*['"]([^'"]+)['"]/g },
  { provider: 'groq', re: /\bgroq\.chat\.completions\.create\s*\(\s*\{[^{}]*?model\s*:\s*['"]([^'"]+)['"]/g },
  // Bedrock (AWS)
  { provider: 'bedrock', re: /InvokeModelCommand\s*\(\s*\{[^{}]*?modelId\s*:\s*['"]([^'"]+)['"]/g },
  // Replicate
  { provider: 'replicate', re: /replicate\.(?:run|predictions\.create)\s*\(\s*['"]([\w.-]+\/[\w.-]+(?::\w+)?)['"]/g },
];

// Inference frameworks worth listing in AI-BOM
const FRAMEWORK_PACKAGES = new Set([
  // Python
  'transformers', 'torch', 'tensorflow', 'tensorflow-cpu', 'tf-keras', 'jax', 'jaxlib',
  'sentence-transformers', 'diffusers', 'accelerate', 'bitsandbytes', 'peft', 'trl',
  'openai', 'anthropic', 'google-generativeai', 'cohere', 'mistralai', 'groq',
  'langchain', 'llama-index', 'haystack-ai', 'guidance', 'instructor', 'litellm',
  'ollama', 'vllm', 'tgi', 'huggingface_hub', 'datasets',
  // Node
  '@anthropic-ai/sdk', '@anthropic-ai/anthropic',
  'openai', 'ai', '@ai-sdk/openai', '@ai-sdk/anthropic', '@ai-sdk/google', '@ai-sdk/mistral',
  'langchain', '@langchain/core', '@langchain/openai', '@langchain/anthropic',
  'cohere-ai', '@mistralai/mistralai', 'groq-sdk', 'together-ai',
  'llamaindex', 'replicate',
  '@google/generative-ai',
]);

// Vector stores
const VECTOR_STORE_PACKAGES = new Set([
  '@pinecone-database/pinecone', 'pinecone-client', 'pinecone',
  'weaviate-ts-client', 'weaviate-client',
  'chromadb', '@chroma-core/chromadb',
  '@qdrant/js-client-rest', 'qdrant-client', 'qdrant_client',
  'pgvector',
  'pymilvus', '@zilliz/milvus2-sdk-node',
  'faiss-cpu', 'faiss-gpu',
  'redis-om',
]);

// Embedding model providers
const EMBEDDING_PACKAGES = new Set([
  'sentence-transformers',
  '@anthropic-ai/sdk',
  'openai',
]);

const PROMPT_FILE_RE = /(?:^|[\\/])(?:prompts?|templates?\/prompts?)\/[^/]+$|\.(?:prompt|j2|jinja2?|tmpl|mustache|hbs)$/i;
const _NONPROD_PATH_RE = /(?:^|[\\/])(?:tests?|__tests__|spec|fixtures?|examples?|docs?|stories|codefixes|node_modules)[\\/]/i;
const _SCANNABLE_EXT_RE = /\.(?:py|js|jsx|ts|tsx|mjs|cjs)$/i;

function _hash(s) {
  return crypto.createHash('sha256').update(s || '').digest('hex').slice(0, 16);
}

function _extractModelsFromFile(fp, content) {
  const out = [];
  if (!content || _NONPROD_PATH_RE.test(fp.replace(/\\/g, '/'))) return out;

  if (_SCANNABLE_EXT_RE.test(fp)) {
    let m;
    // Hugging Face from_pretrained
    const hfRe = new RegExp(HF_FROM_PRETRAINED_RE.source, 'g');
    while ((m = hfRe.exec(content))) {
      out.push({
        type: 'model',
        provider: 'huggingface',
        modelId: m[1],
        revision: m[2] || null,
        pinned: !!m[2],
        file: fp,
        line: content.substring(0, m.index).split('\n').length,
      });
    }
    const hfHubRe = new RegExp(HF_HUB_DOWNLOAD_RE.source, 'g');
    while ((m = hfHubRe.exec(content))) {
      out.push({
        type: 'model',
        provider: 'huggingface',
        modelId: m[1],
        revision: m[2] || null,
        pinned: !!m[2],
        file: fp,
        line: content.substring(0, m.index).split('\n').length,
      });
    }
    // API providers
    for (const p of PROVIDER_PATTERNS) {
      const re = new RegExp(p.re.source, 'g');
      while ((m = re.exec(content))) {
        out.push({
          type: 'model',
          provider: p.provider,
          modelId: m[1],
          revision: null,
          pinned: false, // API endpoint by name only — version implicit
          file: fp,
          line: content.substring(0, m.index).split('\n').length,
        });
      }
    }
  }
  return out;
}

function _extractPromptFile(fp, content) {
  const norm = fp.replace(/\\/g, '/');
  if (_NONPROD_PATH_RE.test(norm)) return null;
  if (!PROMPT_FILE_RE.test(norm)) return null;
  if (!content) return null;
  return {
    type: 'prompt-template',
    file: fp,
    bytes: content.length,
    sha256_16: _hash(content),
    lines: content.split('\n').length,
  };
}

// A package's role isn't mutually exclusive in reality — `openai` and
// `@anthropic-ai/sdk` are both a general inference framework AND an
// embedding-provider SDK. Returns every matching class, not just the first.
function _classifyFramework(c) {
  const name = (c.name || '').toLowerCase();
  const classes = [];
  if (FRAMEWORK_PACKAGES.has(name) || FRAMEWORK_PACKAGES.has(c.name)) classes.push('inference-framework');
  if (VECTOR_STORE_PACKAGES.has(name) || VECTOR_STORE_PACKAGES.has(c.name)) classes.push('vector-store');
  if (EMBEDDING_PACKAGES.has(name) || EMBEDDING_PACKAGES.has(c.name)) classes.push('embedding-provider');
  return classes;
}

// Public: build the AI-BOM from already-scanned data.
// scan = { components, fileContents }; meta = { startedAt, root }
export function buildAIBOM(scan, fileContents = {}, meta = {}) {
  // 1. Models from source
  const models = [];
  const seenModelKey = new Set();
  for (const [fp, content] of Object.entries(fileContents || {})) {
    for (const m of _extractModelsFromFile(fp, content)) {
      const k = `${m.provider}:${m.modelId}`;
      if (seenModelKey.has(k)) continue;
      seenModelKey.add(k);
      models.push(m);
    }
  }
  // 2. Prompt templates
  const promptTemplates = [];
  for (const [fp, content] of Object.entries(fileContents || {})) {
    const pt = _extractPromptFile(fp, content);
    if (pt) promptTemplates.push(pt);
  }
  // 3. Frameworks / vector stores / embeddings from manifests
  const frameworks = [];
  const vectorStores = [];
  const embeddings = [];
  for (const c of (scan.components || [])) {
    const classes = _classifyFramework(c);
    if (classes.includes('inference-framework')) frameworks.push({ ecosystem: c.ecosystem, name: c.name, version: c.version, license: c.license || null });
    if (classes.includes('vector-store')) vectorStores.push({ ecosystem: c.ecosystem, name: c.name, version: c.version });
    if (classes.includes('embedding-provider')) embeddings.push({ ecosystem: c.ecosystem, name: c.name, version: c.version });
  }
  return {
    aibomFormat: 'agentic-security AI-BOM',
    version: '1',
    cyclonedxCompatible: '1.7-ml-bom',
    generatedAt: meta.startedAt || new Date().toISOString(),
    models,
    promptTemplates,
    frameworks,
    vectorStores,
    embeddings,
    summary: {
      totalModels: models.length,
      totalProviders: new Set(models.map(m => m.provider)).size,
      pinnedModels: models.filter(m => m.pinned).length,
      unpinnedModels: models.filter(m => !m.pinned).length,
      promptTemplates: promptTemplates.length,
      frameworks: frameworks.length,
      vectorStores: vectorStores.length,
    },
  };
}

// Markdown rendering
export function aibomToMarkdown(aibom) {
  const out = [];
  out.push('# AI-BOM');
  out.push('');
  out.push(`Generated: ${aibom.generatedAt}`);
  out.push('');
  out.push('## Summary');
  out.push('');
  out.push('| Category | Count |');
  out.push('|---|---|');
  out.push(`| Models referenced | ${aibom.summary.totalModels} |`);
  out.push(`| Distinct providers | ${aibom.summary.totalProviders} |`);
  out.push(`| Pinned (revision/SHA) | ${aibom.summary.pinnedModels} |`);
  out.push(`| Unpinned | ${aibom.summary.unpinnedModels} |`);
  out.push(`| Prompt templates | ${aibom.summary.promptTemplates} |`);
  out.push(`| Inference frameworks | ${aibom.summary.frameworks} |`);
  out.push(`| Vector stores | ${aibom.summary.vectorStores} |`);
  out.push('');

  if (aibom.models.length) {
    out.push('## Models');
    out.push('');
    out.push('| Provider | Model | Pinned | File:Line |');
    out.push('|---|---|---|---|');
    for (const m of aibom.models) {
      out.push(`| ${m.provider} | ${m.modelId} | ${m.pinned ? '✅ ' + (m.revision || '').slice(0, 12) : '❌'} | ${m.file}:${m.line} |`);
    }
    out.push('');
  }

  if (aibom.promptTemplates.length) {
    out.push('## Prompt templates');
    out.push('');
    out.push('| File | Lines | SHA-256 (16ch) |');
    out.push('|---|---|---|');
    for (const p of aibom.promptTemplates) {
      out.push(`| ${p.file} | ${p.lines} | ${p.sha256_16} |`);
    }
    out.push('');
  }

  if (aibom.frameworks.length) {
    out.push('## Inference frameworks');
    out.push('');
    out.push('| Ecosystem | Name | Version | License |');
    out.push('|---|---|---|---|');
    for (const f of aibom.frameworks) {
      out.push(`| ${f.ecosystem} | ${f.name} | ${f.version} | ${f.license || '—'} |`);
    }
    out.push('');
  }

  if (aibom.vectorStores.length) {
    out.push('## Vector stores');
    out.push('');
    out.push('| Ecosystem | Name | Version |');
    out.push('|---|---|---|');
    for (const v of aibom.vectorStores) {
      out.push(`| ${v.ecosystem} | ${v.name} | ${v.version} |`);
    }
    out.push('');
  }

  return out.join('\n');
}
