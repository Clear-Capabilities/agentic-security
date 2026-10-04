// Haskell and Nix AI-BOM extraction (X-002).
//
// Inventory, not behaviour: every entry says HOW it is known and no more.
//   declared   a dependency or option names it                        (a manifest, services.x.enable = true)
//   installed  a package selector puts it on a system/user profile
//   enabled    a NixOS service is enabled in the EFFECTIVE configuration (priority and conditions applied)
//   invoked    source shows a call, an endpoint literal or a model literal in code
// A model CALL and any egress of sensitive data need their own usage/flow evidence: an installed SDK or an
// enabled inference service proves neither, and each entry carries `egress: {status:'not-established'}` to
// say so. A model, endpoint or provider that source does not spell out is `unresolved`, never guessed.
//
// Secrets never enter the BOM: header values are not captured at all, URL userinfo and credential-looking
// query values are replaced, and prompt bodies are hashed, not stored. Nothing here contacts a provider.

import { createHash } from 'node:crypto';
import { tokenizeHaskell, stripUrlCredentials } from './secrets.js';
import { buildHaskellIR } from './haskell-ir.js';
import { hackageComponents } from './haskell-supply.js';
import { resolveNixosConfig } from './nixos-module-resolver.js';
import { analyzeNix } from './nix-ir.js';
import { parseNix } from './nix-parser.js';
import { analyzeNixInputs } from './nix-inventory.js';

export const LANGUAGE_AIBOM_VERSION = 'language-aibom/1';

// ── curated registries (names are curated, not verified against a registry during a scan) ──
export const HS_AI_PACKAGES = Object.freeze({
  'openai-hs': { provider: 'openai', kind: 'sdk', modules: ['OpenAI.Client', 'OpenAI.Resources', 'OpenAI.Api'] },
  'openai-servant': { provider: 'openai', kind: 'sdk', modules: ['OpenAI'] },
  'openai': { provider: 'openai', kind: 'sdk', modules: ['OpenAI'] },
  'ollama-haskell': { provider: 'ollama', kind: 'sdk', modules: ['Data.Ollama', 'Ollama'] },
  'langchain-hs': { provider: null, kind: 'framework', modules: ['Langchain'] },
  'hnswlib': { provider: null, kind: 'vector-store', modules: ['HNSW', 'Data.HNSW'] },
  'pgvector': { provider: 'pgvector', kind: 'vector-store', modules: ['Database.PostgreSQL.Simple.Vector', 'PgVector'] },
  'qdrant-client': { provider: 'qdrant', kind: 'vector-store', modules: ['Qdrant'] },
});
const PROVIDER_HOSTS = [
  [/^api\.openai\.com$/i, 'openai'], [/^[\w-]+\.openai\.azure\.com$/i, 'azure-openai'], [/^api\.anthropic\.com$/i, 'anthropic'],
  [/^generativelanguage\.googleapis\.com$/i, 'google'], [/^api\.mistral\.ai$/i, 'mistral'], [/^api\.cohere\.(?:ai|com)$/i, 'cohere'],
  [/^api\.groq\.com$/i, 'groq'], [/^openrouter\.ai$/i, 'openrouter'], [/^api\.together\.xyz$/i, 'together'], [/^api\.deepseek\.com$/i, 'deepseek'],
  [/^bedrock-runtime\.[\w-]+\.amazonaws\.com$/i, 'bedrock'], [/^(?:localhost|127\.0\.0\.1|\[::1\]):11434$/i, 'ollama'], [/^api-inference\.huggingface\.co$/i, 'huggingface'], [/^api\.replicate\.com$/i, 'replicate'],
];
const PATH_KINDS = [[/\/embeddings?\b/, 'embedding'], [/\/chat\/completions|\/messages|\/api\/chat|:generateContent|\/converse/, 'chat'], [/\/completions\b|\/api\/generate/, 'completion']];
const MODEL_PROVIDER = [[/^(?:gpt-|o[134](?:-|$)|text-embedding-|chatgpt-|dall-e|whisper-|davinci|babbage)/i, 'openai'], [/^claude-/i, 'anthropic'], [/^gemini-|^text-embedding-00/i, 'google'], [/^(?:mistral|mixtral|codestral|ministral)/i, 'mistral'], [/^command(?:-|$)|^embed-/i, 'cohere']];
const OPEN_WEIGHTS = /^(?:llama|qwen|phi|gemma|deepseek|mixtral|mistral|smollm|tinyllama|nomic-embed|mxbai|codellama|starcoder)[\w.:-]*$/i;
const SENSITIVE_QUERY = /^(?:key|api[_-]?key|token|access[_-]?token|secret|password|pwd|auth|signature|sig|code)$/i;

const sha16 = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, 16);
const lineAt = (text, idx) => { let l = 1; for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) l++; return l; };

/** URL safe to store: no userinfo, no fragment, credential-looking query values replaced. */
export function redactEndpoint(u) {
  let s = stripUrlCredentials(String(u));
  s = s.replace(/#.*$/, '');
  s = s.replace(/([?&;])([^=&;#]+)=([^&;#]*)/g, (m, sep, k, v) => (SENSITIVE_QUERY.test(decodeURIComponent(k)) ? `${sep}${k}=REDACTED` : m));
  s = s.replace(/\/(?:key|token|apikey|api-key)\/[^/?#]+/gi, '/$1/REDACTED');
  return s;
}
const providerOfHost = (host) => { for (const [re, p] of PROVIDER_HOSTS) if (re.test(host)) return p; return null; };
const providerOfModel = (id) => { for (const [re, p] of MODEL_PROVIDER) if (re.test(id)) return p; return OPEN_WEIGHTS.test(id) ? 'open-weights' : null; };
const isModelId = (v) => /^[A-Za-z0-9][\w.:/@-]{1,100}$/.test(v) && /[A-Za-z]/.test(v) && (providerOfModel(v) !== null || /^[\w.-]+\/[\w.-]+$/.test(v));

const ident = (kind, o) => ({ ...o, componentClass: 'ai', kind, egress: { status: 'not-established', reason: 'an AI component being present does not show that any data is sent to it; that needs flow evidence' } });

function addEvidence(map, key, base, ev) {
  if (!map.has(key)) map.set(key, { ...base, evidence: [] });
  const e = map.get(key);
  if (!e.evidence.some((x) => x.file === ev.file && x.line === ev.line && x.kind === ev.kind)) e.evidence.push(ev);
  return e;
}

// ── Haskell ──────────────────────────────────────────────────────────────────
const HTTP_FNS = new Set(['parseRequest', 'parseRequest_', 'parseUrlThrow', 'parseUrlThrow_', 'parseUrl']);   // functions whose first argument IS the URL

export function extractHaskellAI(files) {
  const sources = Object.entries(files).filter(([p, t]) => /\.l?hs$/i.test(p) && typeof t === 'string');
  const models = new Map(); const endpoints = new Map(); const prompts = []; const vector = new Map(); const embeddings = new Map();
  const frameworks = new Map(); const unresolved = []; const gaps = [];
  const comps = hackageComponents(files).components;
  const declared = new Map(comps.filter((c) => HS_AI_PACKAGES[c.name]).map((c) => [c.name, c]));
  let ir = null;
  try { ir = buildHaskellIR(Object.fromEntries(sources)); } catch (e) { gaps.push({ kind: 'haskell-ir-failed', detail: e.message }); }
  const importsOf = (f) => (ir && ir.perFile ? (Object.values(ir.perFile).find((x) => x.file === f) || {}).imports || [] : []);

  for (const [file, text] of sources) {
    const toks = tokenizeHaskell(text);
    const imports = importsOf(file);
    // a module may belong to several package names (OpenAI.Client is openai-hs, `OpenAI` is a prefix of others):
    // exact module matches beat prefix matches, and a declared package beats an undeclared one
    const scored = Object.entries(HS_AI_PACKAGES).map(([pkg, d]) => {
      let score = 0;
      for (const i of imports) for (const m of d.modules) { if (i.module === m) score = Math.max(score, 3); else if (i.module.startsWith(`${m}.`)) score = Math.max(score, 2); }
      if (score && declared.has(pkg)) score += 1;
      return [pkg, d, score];
    }).filter(([, , sc]) => sc > 0);
    const best = scored.reduce((a, [, , sc]) => Math.max(a, sc), 0);
    const sdkHit = scored.filter(([, , sc]) => sc === best).map(([pkg, d]) => [pkg, d]);
    const aiContext = sdkHit.length > 0 || toks.some((t) => t.k === 's' && /^(?:model|messages|prompt|temperature|max_tokens|embedding)$/.test(t.v));
    for (const [pkg, d] of sdkHit) {
      const first = imports.find((i) => d.modules.some((m) => i.module === m || i.module.startsWith(`${m}.`)));
      const ev = { file, line: first.line || 1, kind: 'import', detail: first.module };
      const bucket = d.kind === 'vector-store' ? vector : frameworks;
      const c = declared.get(pkg);
      addEvidence(bucket, `${pkg}`, ident(d.kind === 'vector-store' ? 'vector-store' : 'inference-framework', { ecosystem: 'hackage', name: pkg, version: c ? c.version : null, versionResolved: !!(c && c.version), provider: d.provider, status: 'invoked', usage: 'imported' }), ev);
    }
    const providerHints = new Set(sdkHit.map(([, d]) => d.provider).filter(Boolean));
    let fileProvider = null; let fileEndpoint = null;
    // endpoints: URL literals on a known provider host
    for (const t of toks) {
      if (t.k !== 's') continue;
      const m = /^(?:[A-Z]+\s+)?(https?:\/\/)([^/\s"']+)(\/[^\s"']*)?/.exec(t.v);
      if (!m) continue;
      const host = m[2].replace(/^[^@]*@/, ''); const path = m[3] || '';
      const prov = providerOfHost(host);
      if (!prov) continue;
      const url = redactEndpoint(`${m[1]}${host}${path}`);
      const kind = (PATH_KINDS.find(([re]) => re.test(path)) || [null, 'unknown'])[1];
      fileProvider = fileProvider || prov; fileEndpoint = fileEndpoint || url;
      addEvidence(endpoints, url, ident('endpoint', { url, host, provider: prov, purpose: kind, status: 'invoked', usage: 'endpoint-literal' }), { file, line: lineAt(text, t.start), kind: 'url-literal' });
      if (kind === 'embedding') addEvidence(embeddings, `endpoint:${url}`, ident('embedding', { name: `${prov} embeddings endpoint`, provider: prov, endpoint: url, status: 'invoked', usage: 'endpoint-literal' }), { file, line: lineAt(text, t.start), kind: 'embeddings-path' });
    }
    // models: "model" key followed by a literal, or `model = "x"`
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      const isKey = (t.k === 's' && t.v === 'model') || (t.k === 'i' && /^(?:model|modelName|chatModel|embeddingModel)$/.test(t.v));
      if (!isKey) continue;
      const op = toks[i + 1];
      if (!op || op.k !== 'o' || !/^(?:\.=|:|=|=\s*)$/.test(op.v)) continue;
      // skip an optional function application: `T.pack "x"`, `ModelId "x"`, `(` ...
      let j = i + 2; while (toks[j] && (toks[j].k === 'x' && toks[j].v === '(' || toks[j].k === 'i')) j++;
      const val = toks[j];
      const line = lineAt(text, t.start);
      if (val && val.k === 's' && isModelId(val.v)) {
        const prov = providerOfModel(val.v) || fileProvider || [...providerHints][0] || 'unknown';
        const key = `${prov}:${val.v}`;
        addEvidence(models, key, ident('model', { type: 'model', provider: prov, modelId: val.v, revision: null, pinned: false, pinnedBy: null, status: 'invoked', usage: 'model-literal', providerBasis: providerOfModel(val.v) ? 'model-id prefix' : (fileProvider ? 'endpoint in the same file' : (providerHints.size ? 'imported SDK' : 'none')) }), { file, line, kind: 'model-literal' });
        if (/embed/i.test(val.v)) addEvidence(embeddings, `model:${key}`, ident('embedding', { name: val.v, provider: prov, status: 'invoked', usage: 'model-literal' }), { file, line, kind: 'embedding-model' });
      } else if (aiContext && t.k === 's' && val && !(val.k === 's')) {
        unresolved.push({ kind: 'model', file, line, reason: 'the model identifier is not a literal (a variable, a record field or a configuration value)', provider: fileProvider || [...providerHints][0] || null });
      }
    }
    // dynamic endpoints: an HTTP request builder fed something that is not a URL literal, in an AI-looking file
    if (aiContext) for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.k !== 'i' || !HTTP_FNS.has(t.v)) continue;
      let j = i + 1; while (toks[j] && toks[j].k === 'x' && toks[j].v === '(') j++;
      const arg = toks[j];
      if (arg && arg.k === 'i' && !HTTP_FNS.has(arg.v) && !/^(?:def|opts|defaults|manager|mgr)$/.test(arg.v)) unresolved.push({ kind: 'endpoint', file, line: lineAt(text, t.start), reason: `${t.v} is given ${arg.v}, not a URL literal: the endpoint cannot be read statically`, provider: fileProvider || [...providerHints][0] || null });
    }
    // prompt templates: long literals bound to a prompt-like name, or with template placeholders
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.k !== 's' || t.v.length < 40) continue;
      const prev = toks[i - 1]; const prev2 = toks[i - 2];
      const named = prev && prev.k === 'o' && /^(?:=|<-)$/.test(prev.v) && prev2 && prev2.k === 'i' && /(?:prompt|instruction|template|systemMessage)/i.test(prev2.v);
      const looks = /\{\{[^}]+\}\}|%s|\$\{\w+\}/.test(t.v) && /\b(?:you are|answer|assistant|respond|user|system)\b/i.test(t.v);
      if (!(named || looks)) continue;
      prompts.push({ type: 'prompt-template', file, line: lineAt(text, t.start), bytes: Buffer.byteLength(t.v), sha256_16: sha16(t.v), lines: t.v.split('\\n').length, source: 'inline-literal', name: named ? prev2.v : null, placeholders: (t.v.match(/\{\{[^}]+\}\}|%s|\$\{\w+\}/g) || []).length });
    }
    // pgvector in SQL text
    for (const t of toks) if (t.k === 's' && /(?:<->|<=>|<#>)|\bvector\s*\(\s*\d+\s*\)|CREATE\s+EXTENSION\s+(?:IF\s+NOT\s+EXISTS\s+)?vector/i.test(t.v)) addEvidence(vector, 'pgvector (SQL)', ident('vector-store', { ecosystem: null, name: 'pgvector', provider: 'pgvector', status: 'invoked', usage: 'sql-literal' }), { file, line: lineAt(text, t.start), kind: 'sql-vector-operator' });
  }
  // declared-only AI packages (no import found): present in a manifest, nothing more
  for (const [pkg, c] of declared) {
    const d = HS_AI_PACKAGES[pkg];
    const bucket = d.kind === 'vector-store' ? vector : frameworks;
    if (!bucket.has(pkg)) bucket.set(pkg, { ...ident(d.kind === 'vector-store' ? 'vector-store' : 'inference-framework', { ecosystem: 'hackage', name: pkg, version: c.version, versionResolved: !!c.version, declaredRange: c.declaredRange, provider: d.provider, status: 'declared', usage: 'none-found' }), evidence: [{ file: c.manifest, line: c.line, kind: 'build-depends' }] });
    else { const e = bucket.get(pkg); e.declaredIn = { file: c.manifest, line: c.line }; e.evidence.push({ file: c.manifest, line: c.line, kind: 'build-depends' }); }
  }
  const arr = (m) => [...m.values()];
  return { models: arr(models), endpoints: arr(endpoints), frameworks: arr(frameworks), vectorStores: arr(vector), embeddings: arr(embeddings), promptTemplates: prompts, unresolved, gaps, services: [] };
}

// ── Nix ──────────────────────────────────────────────────────────────────────
export const NIX_AI_SERVICES = Object.freeze({
  'services.ollama': { name: 'ollama', kind: 'inference-server', provider: 'ollama', defaultPort: 11434, modelsOption: 'loadModels', packages: ['ollama', 'ollama-cuda', 'ollama-rocm'] },
  'services.open-webui': { name: 'open-webui', kind: 'chat-ui', provider: 'open-webui', defaultPort: 8080, packages: ['open-webui'] },
  'services.llama-cpp': { name: 'llama-cpp', kind: 'inference-server', provider: 'llama.cpp', defaultPort: 8080, modelOption: 'model', packages: ['llama-cpp'] },
  'services.tabby': { name: 'tabby', kind: 'inference-server', provider: 'tabby', defaultPort: 8080, modelOption: 'model', packages: ['tabby'] },
  'services.nextjs-ollama-llm-ui': { name: 'nextjs-ollama-llm-ui', kind: 'chat-ui', provider: 'ollama', defaultPort: 3000, packages: [] },
  'services.litellm': { name: 'litellm', kind: 'llm-proxy', provider: 'litellm', defaultPort: 4000, packages: ['litellm'] },
});
const NIX_AI_PACKAGES = new Set(['ollama', 'ollama-cuda', 'ollama-rocm', 'llama-cpp', 'whisper-cpp', 'open-webui', 'tabby', 'litellm', 'aider-chat', 'python3Packages.openai', 'python3Packages.anthropic', 'python3Packages.transformers', 'python3Packages.langchain', 'python3Packages.torch', 'python312Packages.openai', 'python312Packages.transformers', 'python312Packages.torch']);
const OCI_AI = [[/(?:^|\/)ollama\/ollama/i, 'ollama'], [/vllm\/vllm-openai|vllm/i, 'vllm'], [/ggerganov\/llama\.cpp|llama\.cpp/i, 'llama.cpp'], [/huggingface\/text-generation-inference/i, 'tgi'], [/open-webui/i, 'open-webui']];
const WEIGHTS = /\.(?:gguf|safetensors|ggml|onnx|bin|pt|pth)(?:$|\?)/i;

const spanLine = (s) => (s && s.startLine) || (s && s.line) || null;

export function extractNixAI(files) {
  const nix = Object.fromEntries(Object.entries(files).filter(([p, t]) => /\.nix$/i.test(p) && typeof t === 'string'));
  const services = []; const models = new Map(); const frameworks = new Map(); const unresolved = []; const gaps = []; const links = [];
  if (!Object.keys(nix).length) return { services, models: [], frameworks: [], vectorStores: [], embeddings: [], endpoints: [], promptTemplates: [], unresolved, gaps, links };
  // the NixOS entry point: a configuration.nix (shortest path wins), else the file no other file imports by name
  const names = Object.keys(nix).sort((a, b) => a.length - b.length || a.localeCompare(b));
  const base = (p) => p.replace(/^.*\//, '');
  const importedBy = (f) => names.some((o) => o !== f && new RegExp(`\\./?(?:[\\w./-]*/)?${base(f).replace(/\./g, '\\.')}\\b`).test(nix[o]));
  const entry = names.find((p) => base(p) === 'configuration.nix') || names.find((p) => !importedBy(p)) || names[0];
  let cfg = null;
  try { cfg = resolveNixosConfig({ entry, files: nix }); } catch (e) { gaps.push({ kind: 'nixos-resolution-failed', detail: e.message }); }
  const lookup = (p) => (cfg ? cfg.lookup(p) : null);
  const srcLine = (r) => { const w = r && (r.sources || []).find((s) => s.role === 'winner') || (r && r.sources && r.sources[0]); return w ? { file: w.file, line: spanLine(w.span) } : { file: null, line: null }; };
  const stateOf = (r) => {
    if (!r || !(r.sources || []).length) return 'unknown';
    if (r.status === 'conditional') return 'conditional';
    if (r.status !== 'set') return 'unknown';
    const win = r.sources.find((s) => s.role === 'winner') || r.sources[0];
    if (r.value === false) return 'disabled';
    if (r.value === true) return (win.conditions && win.conditions.length) || (r.caveats && r.caveats.length) || !r.definite ? 'conditional' : 'enabled';
    return 'unknown';
  };
  const byPrefix = new Map();
  for (const [prefix, d] of Object.entries(NIX_AI_SERVICES)) {
    const en = lookup(`${prefix}.enable`);
    if (!en || !(en.sources || []).length) continue;
    const st = stateOf(en); const where = srcLine(en);
    const port = lookup(`${prefix}.port`); const host = lookup(`${prefix}.host`);
    const svc = ident('service', { name: d.name, kind: d.kind, provider: d.provider, option: `${prefix}.enable`, status: st === 'enabled' ? 'enabled' : st, listen: { host: host && host.value !== undefined ? host.value : null, port: port && port.value !== undefined ? port.value : null, defaultPort: d.defaultPort, hostKnown: !!(host && host.value !== undefined), portKnown: !!(port && port.value !== undefined) }, evidence: [{ file: where.file, line: where.line, kind: 'nixos-option' }], precedence: { winnerPriority: en.precedence && en.precedence.winnerPriority, conditions: ((en.sources || [])[0] || {}).conditions || [] } });
    services.push(svc); byPrefix.set(prefix, svc);
    if (st === 'disabled') continue;
    if (d.modelsOption) {
      const lm = lookup(`${prefix}.${d.modelsOption}`);
      if (lm && lm.status === 'set') {
        const w = srcLine(lm);
        const list = Array.isArray(lm.value) ? lm.value : null;
        if (!list) unresolved.push({ kind: 'model', file: w.file, line: w.line, reason: `${prefix}.${d.modelsOption} is not a literal list`, provider: d.provider });
        for (const id of list || []) {
          if (typeof id !== 'string') { unresolved.push({ kind: 'model', file: w.file, line: w.line, reason: 'a model entry is not a literal string', provider: d.provider }); continue; }
          const digest = /@sha256:[0-9a-f]{64}$/.test(id);
          addEvidence(models, `${d.provider}:${id}`, ident('model', { type: 'model', provider: d.provider, modelId: id, revision: digest ? id.split('@')[1] : null, pinned: digest, pinnedBy: digest ? 'digest' : null, status: st === 'enabled' ? 'enabled' : st, usage: 'service-config', service: d.name }), { file: w.file, line: w.line, kind: `${prefix}.${d.modelsOption}` });
        }
      }
    }
    if (d.modelOption) {
      const mo = lookup(`${prefix}.${d.modelOption}`);
      if (mo && mo.status === 'set') {
        const w = srcLine(mo);
        if (typeof mo.value === 'string') {
          const id = mo.value.replace(/^.*\//, '');
          addEvidence(models, `${d.provider}:${mo.value}`, ident('model', { type: 'model', provider: d.provider, modelId: id, artifactPath: mo.value, revision: null, pinned: false, pinnedBy: null, status: st === 'enabled' ? 'enabled' : st, usage: 'service-config', service: d.name, note: 'a path or name: nothing pins the content' }), { file: w.file, line: w.line, kind: `${prefix}.${d.modelOption}` });
        } else unresolved.push({ kind: 'model', file: w.file, line: w.line, reason: `${prefix}.${d.modelOption} is not a literal string (a derivation or an expression)`, provider: d.provider });
      }
    }
  }
  // open-webui -> ollama is a link ONLY when the configuration says so (a literal base URL naming the same host/port)
  const owu = byPrefix.get('services.open-webui'); const oll = byPrefix.get('services.ollama');
  if (owu && oll) {
    const env = lookup('services.open-webui.environment.OLLAMA_BASE_URL') || lookup('services.open-webui.environment');
    const val = env && env.status === 'set' ? (typeof env.value === 'string' ? env.value : (env.value && env.value.OLLAMA_BASE_URL)) : null;
    const port = oll.listen.port ?? oll.listen.defaultPort;
    if (typeof val === 'string' && new RegExp(`(?:localhost|127\\.0\\.0\\.1|\\[::1\\]):${port}\\b`).test(val)) links.push({ from: 'open-webui', to: 'ollama', kind: 'configured-backend', evidence: { option: 'services.open-webui.environment.OLLAMA_BASE_URL', value: redactEndpoint(val) }, flow: 'configuration-only: no data flow is claimed' });
    else links.push({ from: 'open-webui', to: 'ollama', kind: 'both-enabled', evidence: null, flow: 'not established: two enabled services are not a link' });
  }
  // installed packages (selectors on a profile)
  let inv = null;
  try { inv = analyzeNixInputs({ files: nix }); } catch { inv = null; }
  for (const s of (inv && inv.selectors) || []) {
    if (!NIX_AI_PACKAGES.has(s.attr)) continue;
    addEvidence(frameworks, `nix:${s.attr}`, ident('inference-framework', { ecosystem: 'nix', name: s.attr, version: null, versionResolved: false, status: 'installed', usage: s.role === 'build' ? 'build-input' : `${s.role}-profile`, provider: null }), { file: s.file, line: s.line, kind: 'package-selector' });
  }
  // OCI containers and fetched weights: walk the AST
  for (const [file, text] of Object.entries(nix)) {
    const parse = parseNix(text, { file }); if (!parse.ast) continue;
    const stack = [parse.ast];
    while (stack.length) {
      const n = stack.pop(); if (!n || typeof n !== 'object') continue;
      if (n.type === 'attrset') {
        for (const b of n.bindings || []) {
          if (b.kind !== 'attr' || !b.value) continue;
          const key = (b.path || []).map((s) => (s && s.kind === 'static' ? s.name : null)).join('.');
          const v = b.value && b.value.type === 'paren' ? b.value.expr : b.value;
          if (/(?:^|\.)image$/.test(key) && v && v.type === 'string' && !v.interpolated && v.literal) { const hit = OCI_AI.find(([re]) => re.test(v.literal)); if (hit) addEvidence(frameworks, `oci:${v.literal}`, ident('inference-framework', { ecosystem: 'oci', name: v.literal, provider: hit[1], status: 'declared', usage: 'container-declaration', imageLayerScan: 'not-performed' }), { file, line: spanLine(b.span), kind: 'oci-container-image' }); }
        }
      }
      if (n.type === 'app') {
        let f = n; const args = []; while (f && f.type === 'app') { args.unshift(f.arg); f = f.fn && f.fn.type === 'paren' ? f.fn.expr : f.fn; }
        const name = f && f.type === 'ident' ? f.name : (f && f.type === 'select' ? (f.attrpath[f.attrpath.length - 1] || {}).name : null);
        if (name === 'fetchurl' || name === 'fetchFromHuggingFace') {
          const a = args[0] && (args[0].type === 'paren' ? args[0].expr : args[0]);
          let url = null; let hash = null;
          if (a && a.type === 'attrset') for (const b of a.bindings) { if (b.kind !== 'attr') continue; const k = (b.path || []).map((s) => s && s.name).join('.'); const val = b.value && b.value.type === 'paren' ? b.value.expr : b.value; if (k === 'url' && val && val.literal) url = val.literal; if (/^(?:sha256|hash)$/.test(k) && val && val.literal) hash = val.literal; if (k === 'url' && val && !val.literal) unresolved.push({ kind: 'model', file, line: spanLine(n.span), reason: 'a fetched model URL is built by an expression', provider: 'huggingface' }); }
          if (url && (WEIGHTS.test(url) || /huggingface\.co/.test(url))) {
            const m = /huggingface\.co\/([^/]+\/[^/]+)\/resolve\/([^/]+)\/([^?]+)/.exec(url);
            const id = m ? `${m[1]}/${m[3]}` : url.replace(/^.*\//, '').replace(/\?.*$/, '');
            const rev = m ? m[2] : null; const revPinned = !!(rev && /^[0-9a-f]{40}$/.test(rev));
            addEvidence(models, `huggingface:${id}`, ident('model', { type: 'model', provider: 'huggingface', modelId: id, revision: rev, pinned: !!hash, pinnedBy: hash ? (revPinned ? 'content-hash+revision' : 'content-hash') : null, refPinned: revPinned, source: redactEndpoint(url), status: 'declared', usage: 'fetched-weights', note: hash ? 'the content hash pins the bytes' : 'no hash: the fetched bytes can change' }), { file, line: spanLine(n.span), kind: 'fetchurl' });
          }
        }
      }
      for (const k of Object.keys(n)) { const c = n[k]; if (c && typeof c === 'object' && k !== 'span') { if (Array.isArray(c)) stack.push(...c); else stack.push(c); } }
    }
  }
  return { services, models: [...models.values()], frameworks: [...frameworks.values()], vectorStores: [], embeddings: [], endpoints: [], promptTemplates: [], unresolved, gaps, links };
}

/** Both languages, merged by identity with evidence kept (never one entry per mention). */
export function extractLanguageAI(files) {
  const hs = extractHaskellAI(files); const nx = extractNixAI(files);
  const merge = (a, b, keyFn) => { const m = new Map(); for (const x of [...a, ...b]) { const k = keyFn(x); if (m.has(k)) { const e = m.get(k); e.evidence = [...(e.evidence || []), ...(x.evidence || [])]; } else m.set(k, { ...x }); } return [...m.values()]; };
  return {
    models: merge(hs.models, nx.models, (x) => `${x.provider}:${x.modelId}`),
    endpoints: hs.endpoints,
    services: nx.services,
    frameworks: merge(hs.frameworks, nx.frameworks, (x) => `${x.ecosystem}:${x.name}`),
    vectorStores: hs.vectorStores, embeddings: hs.embeddings, promptTemplates: hs.promptTemplates,
    unresolved: [...hs.unresolved, ...nx.unresolved], links: nx.links, gaps: [...hs.gaps, ...nx.gaps],
  };
}
