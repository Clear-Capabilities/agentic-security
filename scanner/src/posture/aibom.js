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
    // PRD F5.5 — this document is PROPRIETARY and now says so.
    //
    // It previously carried `cyclonedxCompatible: '1.7-ml-bom'`, which was an
    // unverified claim: nothing validated it, and the document has no
    // `bomFormat`, no `specVersion` and no CycloneDX `components` array, so it
    // would not have parsed as CycloneDX at all. A consumer reading that field
    // and feeding this to a CycloneDX tool would have got an error, not a BOM.
    //
    // The honest options F5.5 gives are "validate mechanically, or be labelled
    // proprietary". Both are taken: the field below states the truth, and
    // `toCycloneDXMLBOM()` emits a REAL ML-BOM that `validateMLBOM()` checks.
    proprietary: true,
    cyclonedxMlBom: 'not this document — call toCycloneDXMLBOM() for a CycloneDX 1.6 ML-BOM view',
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


// ── CycloneDX ML-BOM (PRD F5.5) ────────────────────────────────────────────
//
// A real CycloneDX 1.6 document describing the models this scan found, using the
// ML-BOM shape: `components[].type: 'machine-learning-model'` carrying a
// `modelCard`. Emitted separately from the proprietary AI-BOM rather than
// pretending the proprietary one already conforms.
//
// The serial number derives from content under --deterministic, for the same
// reason toCycloneDX's does: an attestation over a BOM is meaningless if the BOM
// changes on every run.
import * as _crypto from 'node:crypto';
import { isDeterministic as _isDet } from './deterministic.js';

function _mlbomSerial(seed) {
  if (!_isDet()) return `urn:uuid:${_crypto.randomUUID()}`;
  const h = _crypto.createHash('sha256').update(String(seed)).digest('hex');
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${((parseInt(h[16], 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export function toCycloneDXMLBOM(aibom, meta = {}) {
  const models = (aibom && aibom.models) || [];
  const components = models.map((m) => ({
    type: 'machine-learning-model',
    'bom-ref': `model:${m.provider || 'unknown'}/${m.name || 'unknown'}${m.version ? `@${m.version}` : ''}`,
    name: m.name || 'unknown',
    ...(m.version ? { version: m.version } : {}),
    modelCard: {
      modelParameters: {
        ...(m.provider ? { approach: { type: 'supervised' } } : {}),
        ...(m.task ? { task: m.task } : {}),
      },
      // `considerations` is where CycloneDX expects known risks to live. Pinning
      // status is a real supply-chain property of a model reference: an unpinned
      // model can change under you between runs.
      considerations: {
        technicalLimitations: m.pinned
          ? []
          : ['model reference is not pinned to a version; the served model can change between runs'],
      },
    },
    properties: [
      ...(m.provider ? [{ name: 'agentic-security:provider', value: String(m.provider) }] : []),
      ...(m.file ? [{ name: 'agentic-security:declaredIn', value: String(m.file) }] : []),
      { name: 'agentic-security:pinned', value: String(!!m.pinned) },
    ],
  }));

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: _mlbomSerial(JSON.stringify(components.map((c) => c['bom-ref']))),
    version: 1,
    metadata: {
      timestamp: meta.startedAt || (aibom && aibom.generatedAt) || new Date().toISOString(),
      tools: [{ vendor: 'Clear Capabilities', name: 'agentic-security', version: meta.engineVersion || 'dev' }],
      component: { type: 'application', name: 'scan-target', version: '1.0.0' },
    },
    components,
  };
}

/**
 * Mechanical validation of an ML-BOM.
 *
 * STRUCTURAL, not full JSON-Schema validation: fetching the official CycloneDX
 * schema at scan time would break the no-runtime-network rule, and vendoring it
 * would add a file that silently rots against upstream. So this checks the
 * required fields and the ML-BOM-specific shape, and SAYS that is what it does —
 * a check labelled "validates against CycloneDX" that only tests a few keys
 * would be the same unverified claim this item exists to remove.
 */
export function validateMLBOM(doc) {
  const errors = [];
  const req = (cond, msg) => { if (!cond) errors.push(msg); };

  req(doc && typeof doc === 'object', 'not an object');
  if (!doc || typeof doc !== 'object') return { ok: false, errors, checked: 'structural' };

  req(doc.bomFormat === 'CycloneDX', `bomFormat must be "CycloneDX", got ${JSON.stringify(doc.bomFormat)}`);
  req(/^1\.[4-9]$/.test(String(doc.specVersion || '')), `specVersion must be 1.4-1.9, got ${JSON.stringify(doc.specVersion)}`);
  req(Number.isInteger(doc.version) && doc.version >= 1, 'version must be a positive integer');
  req(/^urn:uuid:[0-9a-f-]{36}$/i.test(String(doc.serialNumber || '')), 'serialNumber must be a urn:uuid');
  req(doc.metadata && typeof doc.metadata === 'object', 'metadata is required');
  req(Array.isArray(doc.components), 'components must be an array');

  for (const [i, c] of (Array.isArray(doc.components) ? doc.components : []).entries()) {
    req(typeof c.name === 'string' && c.name, `components[${i}].name is required`);
    req(typeof c.type === 'string' && c.type, `components[${i}].type is required`);
    if (c.type === 'machine-learning-model') {
      req(c.modelCard && typeof c.modelCard === 'object',
        `components[${i}] is a machine-learning-model but carries no modelCard — that is the whole ML-BOM extension`);
    }
  }
  return { ok: errors.length === 0, errors, checked: 'structural (required fields + ML-BOM component shape), NOT full JSON-Schema validation' };
}
