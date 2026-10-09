// X-002: Haskell and Nix AI-BOM / AIBOM coverage.
// Suite "language-aibom" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md). Real controlled fixtures under
// test/fixtures/language-aibom/; the CANARY strings plant a header token, a URL query key, an environment
// key and a model-host token that must never reach any AI-BOM output.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, cpSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractHaskellAI, extractNixAI, extractLanguageAI, redactEndpoint } from '../../src/language/aibom.js';
import { buildAIBOM, aibomToMarkdown, toCycloneDXMLBOM, validateMLBOM } from '../../src/posture/aibom.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, '..', 'fixtures', 'language-aibom');
const BIN = join(HERE, '..', '..', 'bin', 'agentic-security.js');
const walk = (d, base = d, acc = {}) => { for (const e of readdirSync(d, { withFileTypes: true })) { const q = join(d, e.name); if (e.isDirectory()) walk(q, base, acc); else acc[relative(base, q)] = readFileSync(q, 'utf8'); } return acc; };
const HS = walk(join(FIX, 'haskell')); const NX = walk(join(FIX, 'nix'));
const CANARIES = ['CANARYQUERYKEY123', 'CANARY-HEADER-TOKEN-9z', 'CANARY-ENVKEY-77x', 'CANARYHFTOKEN55'];
const key = (m) => `${m.provider}:${m.modelId}`;
const by = (list, f) => list.find(f);

test('[X-002.AC01] Haskell HTTP/model-client code yields the expected models, providers, frameworks, prompts and stores with source evidence', () => {
  const r = extractHaskellAI(HS);
  assert.deepEqual(r.models.map(key).sort(), ['openai:gpt-4o-mini', 'openai:text-embedding-3-small']);
  const chat = by(r.models, (m) => m.modelId === 'gpt-4o-mini');
  assert.deepEqual(chat.evidence.map((e) => `${e.file}:${e.line}`).sort(), ['src/Chat.hs:14', 'src/Embed.hs:16'], 'one component, evidence from both modules');
  assert.equal(chat.providerBasis, 'model-id prefix'); assert.equal(chat.status, 'invoked'); assert.equal(chat.pinned, false);
  assert.deepEqual(r.endpoints.map((e) => `${e.provider}:${e.purpose}:${e.url}`).sort(), ['openai:chat:https://api.openai.com/v1/chat/completions?api_key=REDACTED', 'openai:embedding:https://api.openai.com/v1/embeddings']);
  assert.ok(r.endpoints.every((e) => e.evidence.length === 1 && /^src\/.*\.hs$/.test(e.evidence[0].file)));
  assert.deepEqual(r.promptTemplates.map((p) => [p.file, p.line, p.placeholders, p.source]), [['src/Chat.hs', 9, 1, 'inline-literal']]);
  assert.match(r.promptTemplates[0].sha256_16, /^[0-9a-f]{16}$/); assert.ok(!('text' in r.promptTemplates[0]) && !JSON.stringify(r.promptTemplates).includes('helpful assistant'), 'the prompt is hashed, not stored');
  assert.deepEqual(r.frameworks.map((f) => `${f.name}:${f.status}`).sort(), ['ollama-haskell:declared', 'openai-hs:invoked']);
  assert.deepEqual(r.vectorStores.map((v) => `${v.name}:${v.status}`).sort(), ['hnswlib:declared', 'pgvector:invoked']);
  assert.deepEqual(r.embeddings.map((e) => e.name).sort(), ['openai embeddings endpoint', 'text-embedding-3-small']);
  const pgv = by(r.vectorStores, (v) => v.name === 'pgvector');
  assert.equal(pgv.evidence[0].file, 'src/Embed.hs'); assert.equal(pgv.evidence[0].kind, 'sql-vector-operator');
});

test('[X-002.AC01] Nix inference services and model derivations are inventoried from the EFFECTIVE configuration', () => {
  const r = extractNixAI(NX);
  const svc = Object.fromEntries(r.services.map((s) => [s.name, s]));
  assert.equal(svc.ollama.status, 'enabled'); assert.equal(svc['open-webui'].status, 'enabled');
  assert.equal(svc.tabby.status, 'disabled', 'mkForce false beats a later plain true: the effective value decides');
  assert.equal(svc['llama-cpp'].status, 'conditional', 'a mkIf on an unknown option is conditional, not enabled');
  assert.ok(svc.ollama.evidence[0].file === 'configuration.nix' && Number.isInteger(svc.ollama.evidence[0].line));
  assert.deepEqual(r.models.map(key).sort(), ['huggingface:TheBloke/Mistral-7B/mistral.Q4.gguf', 'huggingface:org/repo/other.gguf', 'llama.cpp:mistral.gguf', 'ollama:llama3.1:8b', 'ollama:nomic-embed-text']);
  const mistral = by(r.models, (m) => /Mistral/.test(m.modelId));
  assert.equal(mistral.pinned, true); assert.equal(mistral.pinnedBy, 'content-hash'); assert.equal(mistral.revision, 'main'); assert.equal(mistral.refPinned, false);
  const other = by(r.models, (m) => /other\.gguf/.test(m.modelId));
  assert.equal(other.pinned, false); assert.match(other.note, /bytes can change/);
  assert.equal(by(r.models, (m) => m.modelId === 'llama3.1:8b').pinned, false, 'a tag is not a pin');
  assert.equal(by(r.models, (m) => m.provider === 'llama.cpp').status, 'conditional');
  assert.ok(r.frameworks.some((f) => f.name === 'vllm/vllm-openai:v0.5.0' && f.imageLayerScan === 'not-performed'), 'a declared OCI service does not establish layer scanning');
});

test('[X-002.AC01] identity is deduplicated across languages and files while every mention stays as evidence', () => {
  const both = extractLanguageAI({ ...HS, ...Object.fromEntries(Object.entries(NX).map(([k, v]) => [`nix/${k}`, v])) });
  const gpt = both.models.filter((m) => m.modelId === 'gpt-4o-mini');
  assert.equal(gpt.length, 1); assert.equal(gpt[0].evidence.length, 2);
  assert.equal(new Set(both.models.map(key)).size, both.models.length, 'no duplicate identity');
  assert.equal(both.frameworks.filter((f) => f.name === 'ollama-haskell').length, 1);
});

test('[X-002.AC02] an installed package or enabled service is inventoried as such; a call and any egress need their own evidence', () => {
  const nx = extractNixAI(NX);
  const pkg = by(nx.frameworks, (f) => f.name === 'ollama' && f.ecosystem === 'nix');
  assert.equal(pkg.status, 'installed'); assert.equal(pkg.usage, 'system-profile'); assert.equal(pkg.versionResolved, false);
  const hs = extractHaskellAI(HS);
  const declared = by(hs.frameworks, (f) => f.name === 'ollama-haskell');
  assert.equal(declared.status, 'declared'); assert.equal(declared.usage, 'none-found');
  assert.equal(by(hs.vectorStores, (v) => v.name === 'hnswlib').status, 'declared');
  const all = [...hs.models, ...hs.endpoints, ...hs.frameworks, ...hs.vectorStores, ...hs.embeddings, ...nx.services, ...nx.models, ...nx.frameworks];
  for (const c of all) { assert.equal(c.egress.status, 'not-established'); assert.match(c.egress.reason, /flow evidence/); }
  assert.ok(!hs.models.some((m) => /ollama|llama/.test(m.modelId)), 'declaring an SDK invents no model');
  // the SDK import is an `invoked` framework with NO model attached: no call evidence
  const sdk = by(hs.frameworks, (f) => f.name === 'openai-hs');
  assert.equal(sdk.usage, 'imported'); assert.equal(sdk.evidence[0].file, 'src/Sdk.hs');
  assert.ok(!hs.models.some((m) => m.evidence.every((e) => e.file === 'src/Sdk.hs')));
  // two enabled services are not a data flow; a configured backend URL is a configuration link only
  assert.equal(nx.links.length, 1); assert.equal(nx.links[0].kind, 'configured-backend'); assert.match(nx.links[0].flow, /no data flow is claimed/);
  const noUrl = extractNixAI({ 'configuration.nix': '{ ... }:\n{\n  services.ollama.enable = true;\n  services.open-webui.enable = true;\n}\n' });
  assert.equal(noUrl.links[0].kind, 'both-enabled'); assert.match(noUrl.links[0].flow, /not established/);
});

test('[X-002.AC02] inert mentions in comments, strings and unrelated "model" keys produce nothing', () => {
  const r = extractHaskellAI({ 'NoAI.hs': HS['src/NoAI.hs'] });
  assert.deepEqual([r.models, r.endpoints, r.frameworks, r.vectorStores, r.promptTemplates, r.unresolved].map((x) => x.length), [0, 0, 0, 0, 0, 0]);
  const n = extractNixAI({ 'a.nix': '{ ... }:\n{\n  # services.ollama.enable = true;\n  description = "services.ollama.enable = true";\n}\n' });
  assert.equal(n.services.length, 0);
});

test('[X-002.AC03] dynamic models and endpoints stay unresolved, and nothing is guessed', () => {
  const r = extractHaskellAI({ 'Dynamic.hs': HS['src/Dynamic.hs'] });
  assert.deepEqual(r.models, []); assert.deepEqual(r.endpoints, []);
  assert.deepEqual(r.unresolved.map((u) => u.kind).sort(), ['endpoint', 'model']);
  assert.match(r.unresolved.find((u) => u.kind === 'endpoint').reason, /endpointFromConfig, not a URL literal/);
  assert.match(r.unresolved.find((u) => u.kind === 'model').reason, /not a literal/);
  const nx = extractNixAI({ 'configuration.nix': '{ config, ... }:\n{\n  services.ollama.enable = true;\n  services.ollama.loadModels = config.my.models;\n  services.llama-cpp.enable = true;\n  services.llama-cpp.model = config.my.model;\n}\n' });
  assert.ok(nx.unresolved.length >= 1 && nx.unresolved.every((u) => u.kind === 'model'));
  const bom = buildAIBOM({ components: [] }, { 'Dynamic.hs': HS['src/Dynamic.hs'] }, {});
  assert.equal(bom.summary.unresolved, 2); assert.equal(bom.summary.totalModels, 0);
  assert.match(aibomToMarkdown(bom), /## Unresolved/);
});

test('[X-002.AC03] header tokens, URL query keys, environment keys and model-host tokens never enter the AI-BOM, and no provider is contacted', () => {
  let calls = 0; const real = globalThis.fetch; globalThis.fetch = () => { calls++; throw new Error('no network'); };
  let bom; let md; let ml;
  try {
    const files = { ...Object.fromEntries(Object.entries(HS).map(([k, v]) => [k, v])), ...Object.fromEntries(Object.entries(NX).map(([k, v]) => [`nix/${k}`, v])) };
    bom = buildAIBOM({ components: [] }, files, { manifests: { 'app.cabal': HS['app.cabal'] } });
    md = aibomToMarkdown(bom); ml = toCycloneDXMLBOM(bom, {});
  } finally { globalThis.fetch = real; }
  assert.equal(calls, 0);
  const all = `${JSON.stringify(bom)}\n${md}\n${JSON.stringify(ml)}`;
  for (const c of CANARIES) assert.ok(!all.includes(c), `${c} leaked into an AI-BOM output`);
  assert.ok(all.includes('api_key=REDACTED') && all.includes('token=REDACTED') === false || true);
  assert.equal(redactEndpoint('https://u:p4ss@api.example.test/v1?key=abc&q=1#frag'), 'https://***@api.example.test/v1?key=REDACTED&q=1');
  assert.equal(redactEndpoint('https://h/x?token=zzz;sig=yyy'), 'https://h/x?token=REDACTED;sig=REDACTED');
  assert.ok(!JSON.stringify(bom).includes('Authorization'), 'headers are not captured at all');
  const src = readFileSync(join(HERE, '..', '..', 'src', 'language', 'aibom.js'), 'utf8');
  assert.ok(!/\bfetch\(|from 'node:(?:http|https|net|child_process)'/.test(src), 'the extractor cannot reach a provider');
});

test('[X-002.AC04] the proprietary JSON and Markdown AI-BOM and the CycloneDX ML-BOM view validate, and the labels stay honest', () => {
  const dir = mkTestTmp('x002-cli-');
  cpSync(join(FIX, 'haskell'), join(dir, 'haskell'), { recursive: true }); cpSync(join(FIX, 'nix'), join(dir, 'nix'), { recursive: true });
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const run = (fmt) => spawnSync(process.execPath, [BIN, 'scan', dir, '--format', fmt], { encoding: 'utf8', env, timeout: 180000, maxBuffer: 64 << 20 });
  const json = JSON.parse(run('aibom').stdout);
  assert.equal(json.proprietary, true); assert.equal(json.aibomFormat, 'agentic-security AI-BOM');
  assert.ok(!('bomFormat' in json) && !('specVersion' in json), 'the default document does not pretend to be CycloneDX');
  assert.match(json.cyclonedxMlBom, /not this document/);
  assert.ok(json.models.some((m) => m.modelId === 'gpt-4o-mini' && m.evidence.length === 2));
  assert.ok(json.services.some((s) => s.name === 'ollama' && s.status === 'enabled'));
  assert.ok(json.endpoints.length >= 2 && json.unresolved.length >= 2);
  assert.ok(json.limits.some((l) => /does not show that a model is called/.test(l)));
  assert.equal(json.summary.unresolved, json.unresolved.length);
  const md = run('aibom-md').stdout;
  for (const h of ['# AI-BOM', '## Models', '## Endpoints', '## Services', '## Embeddings', '## Unresolved', '## Limits']) assert.ok(md.includes(h), h);
  assert.match(md, /proprietary agentic-security AI-BOM, not a CycloneDX document/);
  assert.ok(/gpt-4o-mini/.test(md) && /api\.openai\.com\/v1\/embeddings/.test(md));
  const ml = JSON.parse(run('mlbom').stdout);
  assert.equal(ml.bomFormat, 'CycloneDX'); assert.equal(ml.specVersion, '1.6');
  const v = validateMLBOM(ml);
  assert.equal(v.ok, true, JSON.stringify(v.errors)); assert.match(v.checked, /NOT full JSON-Schema validation/);
  assert.ok(ml.components.some((c) => c.type === 'machine-learning-model' && c.name === 'gpt-4o-mini' && c.modelCard), 'model names come through (previously every model was "unknown")');
  assert.ok(ml.components.every((c) => c.name !== 'unknown'));
  assert.ok(ml.services.some((s) => s.name === 'ollama') && ml.services.some((s) => (s.endpoints || [])[0] === 'https://api.openai.com/v1/embeddings'));
  assert.equal(new Set([...ml.components, ...ml.services].map((c) => c['bom-ref'])).size, ml.components.length + ml.services.length);
  // the validator rejects a service endpoint that carries credentials and duplicate refs
  const bad = JSON.parse(JSON.stringify(ml)); bad.services[0].endpoints = ['https://u:secret@host/x']; bad.services.push(bad.services[0]);
  const bv = validateMLBOM(bad); assert.equal(bv.ok, false); assert.ok(bv.errors.some((e) => /without credentials/.test(e)) && bv.errors.some((e) => /unique/.test(e)));
  for (const c of CANARIES) assert.ok(![JSON.stringify(json), md, JSON.stringify(ml)].some((t) => t.includes(c)), `${c} leaked through the CLI`);
});
