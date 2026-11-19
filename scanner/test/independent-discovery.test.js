// The `deep+discovery` configuration of the independent measurement (bench/independent/discovery.mjs), the driver's
// configuration handling (scripts/engineering-excellence/independent-baseline.mjs), and the two product seams it relies on:
// `selectHuntFiles` (the CLI's own file selection) and the run budget applying to a configuration-resolved model callback.
//
// What these pin: discovery is reached with the tree and nothing the benchmark knows; the model is local or the run refuses
// to start; the deterministic half keeps its environment; a discovery run can never be named, filed or merged as a
// deterministic one; an exhausted budget is recorded, never read as clean.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import {
  discoveryOptionsFromArgv, configurationName, configurationTag, discoveryEnv, withScopedEnv, preflightDiscovery, discoverTree,
  discoveryTotals, DEFAULT_DISCOVERY_BUDGET_MIN,
} from '../../bench/independent/discovery.mjs';
import {
  CONFIG_DEEP, configDeepDiscovery, configRunnerArgs, configFromArgs, defaultChunkTimeoutMs,
} from '../../scripts/engineering-excellence/independent-baseline.mjs';
import { configSnapshot } from '../../scripts/engineering-excellence/lib/measurement-identity.mjs';
import { selectHuntFiles, runDiscovery } from '../src/discovery/index.js';
import { buildProjectIR } from '../src/ir/index.js';
import { listOllamaModels } from '../src/llm-validator/ollama-provider.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNNER = path.resolve(HERE, '..', '..', 'bench', 'independent', 'runner.mjs');

function tmpTree(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-ind-disc-'));
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

const APP = {
  'src/app.js': "const express = require('express');\nconst db = require('./db');\nconst app = express();\napp.get('/u', (req, res) => {\n  db.find(req.query.id).then((u) => res.json(u));\n});\nmodule.exports = app;\n",
  'src/db.js': "function find(id) {\n  return query('SELECT * FROM users WHERE id = ' + id);\n}\nfunction query(sql) { return Promise.resolve(sql); }\nmodule.exports = { find };\n",
  'node_modules/dep/index.js': 'module.exports = 1;\n',
  'dist/bundle.js': 'var x = 1;\n',
  'README.md': '# not code\n',
};

/** A fake Ollama on loopback: /api/tags lists `models`, /api/chat answers hunter prompts with one candidate and refuters with `refuted`. */
function fakeOllama({ models = [{ name: 'local-model:1b', digest: 'sha256:aaa', size: 1 }], candidate = { file: 'src/db.js', line: 2 }, refuted = false } = {}) {
  const seen = { chat: 0, prompts: [] };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (req.method === 'GET' && req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ models })); return; }
      if (req.method === 'POST' && req.url === '/api/chat') {
        seen.chat += 1;
        const prompt = JSON.parse(body).messages[0].content;
        seen.prompts.push(prompt);
        const content = /REFUTE/.test(prompt)
          ? JSON.stringify({ refuted, reason: 'fake' })
          : JSON.stringify({ candidates: [{ title: 'SQL built from a request value', ...candidate, rationale: 'r', entryPoint: 'GET /u', sink: 'query' }] });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ message: { role: 'assistant', content }, done: true }));
        return;
      }
      res.writeHead(404); res.end('{}');
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, host: `http://127.0.0.1:${server.address().port}` })));
}

// ------------------------------------------------------------------ options and naming
test('discovery is opt-in: no --discovery flag, no discovery options', () => {
  assert.equal(discoveryOptionsFromArgv(['node', 'runner.mjs', '--deep'], {}, 'm'), null);
});

test('discovery options: default budget, model precedence, refusals', () => {
  const o = discoveryOptionsFromArgv(['--deep', '--discovery'], {}, 'product-default:4b');
  assert.equal(o.model, 'product-default:4b');
  assert.equal(o.budgetMs, DEFAULT_DISCOVERY_BUDGET_MIN * 60000);
  assert.equal(o.host, 'http://127.0.0.1:11434');
  assert.equal(discoveryOptionsFromArgv(['--discovery'], { AGENTIC_SECURITY_BENCH_DISCOVERY_MODEL: 'env:1b' }, 'd').model, 'env:1b');
  assert.equal(discoveryOptionsFromArgv(['--discovery', '--discovery-model=flag:7b', '--discovery-budget-min=2.5'], { AGENTIC_SECURITY_BENCH_DISCOVERY_MODEL: 'env:1b' }, 'd').budgetMs, 150000);
  assert.throws(() => discoveryOptionsFromArgv(['--discovery', '--discovery-budget-min=0'], {}, 'd'), /positive/);
  assert.throws(() => discoveryOptionsFromArgv(['--discovery', '--discovery-budget-min=abc'], {}, 'd'), /positive/);
  assert.throws(() => discoveryOptionsFromArgv(['--discovery'], {}, null), /needs a model/);
});

test('a discovery configuration never shares a name or a file tag with a deterministic one', () => {
  assert.equal(configurationName(true, false), 'deep');
  assert.equal(configurationName(false, false), 'pattern-only');
  assert.equal(configurationName(true, true), 'deep+discovery');
  assert.equal(configurationTag(true, false), 'deep');
  assert.equal(configurationTag(true, true), 'deep-discovery');
  // merge-chunks.mjs selects deterministic chunks by /^RESULT-chunk-deep-\d+\.json$/; a discovery chunk must not match it
  assert.equal(/^RESULT-chunk-deep-\d+\.json$/.test(`RESULT-chunk-${configurationTag(true, true)}-00000.json`), false);
});

test('the scoped environment is the loopback ollama preset and nothing inherited, restored afterwards even on a throw', async () => {
  const env = { AGENTIC_SECURITY_LLM_ENDPOINT: 'https://remote.example/v1', AGENTIC_SECURITY_LLM_MODEL_HUNT: 'x', AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE: '1', AGENTIC_SECURITY_DEEP: '1', PATH: '/bin' };
  const before = { ...env };
  const overrides = discoveryEnv({ model: 'm:1b', host: 'http://127.0.0.1:11434', budgetMs: 600000 });
  let inside = null;
  await withScopedEnv(overrides, async () => { inside = { ...env }; }, env);
  assert.equal(inside.AGENTIC_SECURITY_LLM_PRESET, 'ollama');
  assert.equal(inside.AGENTIC_SECURITY_LLM_MODEL, 'm:1b');
  assert.equal(inside.AGENTIC_SECURITY_LLM_VALIDATE, '0');
  assert.equal(inside.AGENTIC_SECURITY_LLM_TIMEOUT_MS, '300000');
  assert.equal(inside.AGENTIC_SECURITY_LLM_ENDPOINT, undefined, 'an inherited remote endpoint must not be visible to discovery');
  assert.equal(inside.AGENTIC_SECURITY_LLM_MODEL_HUNT, undefined);
  assert.equal(inside.AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE, undefined);
  assert.equal(inside.AGENTIC_SECURITY_DEEP, '1', 'non-model settings are untouched');
  assert.deepEqual(env, before);
  await assert.rejects(withScopedEnv(overrides, async () => { throw new Error('boom'); }, env), /boom/);
  assert.deepEqual(env, before);
});

// ------------------------------------------------------------------ preflight: local or refuse
test('preflight refuses a non-loopback host before contacting anything', async () => {
  let listed = false;
  await assert.rejects(preflightDiscovery({ model: 'm', host: 'http://10.0.0.5:11434', budgetMs: 1 }, { listModels: async () => { listed = true; return { ok: true, models: [] }; }, env: {} }), /not loopback/);
  assert.equal(listed, false);
});

test('preflight refuses an Ollama model served from a remote host, and one that is not installed', async () => {
  const opts = { model: 'big:cloud', host: 'http://127.0.0.1:11434', budgetMs: 1 };
  const models = [{ name: 'big:cloud', remoteHost: 'https://remote.example' }, { name: 'tagged-remote', remoteHost: 'https://remote.example' }, { name: 'local:4b', digest: 'sha256:abc' }];
  await assert.rejects(preflightDiscovery(opts, { listModels: async () => ({ ok: true, models }), env: {} }), /remote host/);
  await assert.rejects(preflightDiscovery({ ...opts, model: 'tagged-remote' }, { listModels: async () => ({ ok: true, models }), env: {} }), /remote host/);
  await assert.rejects(preflightDiscovery({ ...opts, model: 'absent:1b' }, { listModels: async () => ({ ok: true, models }), env: {} }), /not installed/);
  await assert.rejects(preflightDiscovery({ ...opts, model: 'local:4b' }, { listModels: async () => ({ ok: false, code: 'ollama-not-running', reason: 'down' }), env: {} }), /not reachable/);
  const id = await preflightDiscovery({ ...opts, model: 'local:4b' }, { listModels: async () => ({ ok: true, models }), env: { AGENTIC_SECURITY_LLM_ENDPOINT: 'https://remote.example' } });
  assert.equal(id.modelEndpointMode, 'loopback');
  assert.equal(id.provider, 'ollama');
  assert.equal(id.model, 'local:4b');
  assert.equal(id.modelDigest, 'sha256:abc');
  assert.match(id.selection, /no label input/);
});

test('listOllamaModels reports the remote host of a model Ollama forwards off the machine', async () => {
  const { server, host } = await fakeOllama({ models: [{ name: 'a:cloud', remote_host: 'https://remote.example', remote_model: 'a' }, { name: 'b:1b', size: 5 }] });
  try {
    const r = await listOllamaModels({ host });
    assert.equal(r.ok, true);
    assert.equal(r.models[0].remoteHost, 'https://remote.example');
    assert.equal(r.models[1].remoteHost, null);
  } finally { server.close(); }
});

// ------------------------------------------------------------------ what discovery is given
test('discoverTree hands the product only the tree and the deterministic findings, with product defaults', async () => {
  const dir = tmpTree(APP);
  const calls = [];
  const fake = async (ctx, opts) => {
    calls.push({ ctxKeys: Object.keys(ctx).sort(), files: Object.keys(ctx.fileContents).sort(), prior: ctx.priorScan.findings.length, opts, preset: process.env.AGENTIC_SECURITY_LLM_PRESET, endpoint: process.env.AGENTIC_SECURITY_LLM_ENDPOINT });
    return { fresh: [{ id: 'd1', file: 'src/db.js', line: 2, cwe: 'CWE-74', parser: 'DISCOVERY', discovery: { confirmation: { tier: 'unconfirmed' }, refutation: { undecided: true } } }], runs: [{ candidateCount: 1 }], duplicates: [], refutedCandidates: [],
      coverage: { areasPlanned: 1, degradedRuns: 0, llmCalls: 4, maxLlmCalls: 200, budgetExhausted: false, candidatesCapped: 0, reasons: [] } };
  };
  const saved = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  process.env.AGENTIC_SECURITY_LLM_ENDPOINT = 'https://remote.example/v1';
  try {
    const r = await discoverTree(dir, [{ id: 'det', file: 'src/db.js', line: 2 }], { model: 'm', host: 'http://127.0.0.1:11434', budgetMs: 60000 }, { runDiscoveryImpl: fake });
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].ctxKeys, ['callGraph', 'fileContents', 'perFileIR', 'priorScan', 'triageFeedback']);
    assert.deepEqual(calls[0].files, ['src/app.js', 'src/db.js'], 'the product selection: source files only, no node_modules or dist');
    assert.equal(calls[0].prior, 1);
    assert.deepEqual(calls[0].opts, { maxWallMs: 60000 }, 'only the wall clock is set; areas, lenses and ceilings are the product defaults');
    assert.equal(calls[0].preset, 'ollama');
    assert.equal(calls[0].endpoint, undefined);
    assert.equal(process.env.AGENTIC_SECURITY_LLM_ENDPOINT, 'https://remote.example/v1', 'restored afterwards');
    assert.equal(process.env.AGENTIC_SECURITY_LLM_PRESET, undefined);
    assert.equal(r.findings.length, 1);
    assert.equal(r.summary.complete, true);
    assert.equal(r.summary.freshUnvetted, 1);
    assert.deepEqual(r.summary.freshByTier, { unconfirmed: 1 });
  } finally {
    if (saved === undefined) delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT; else process.env.AGENTIC_SECURITY_LLM_ENDPOINT = saved;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the runner hands discovery the tree, never the advisory entry', () => {
  const src = fs.readFileSync(RUNNER, 'utf8');
  const calls = [...src.matchAll(/discoverTree\(([^;]*?)\);/g)].map((m) => m[1]);
  assert.equal(calls.length, 2, 'pre and post');
  for (const args of calls) {
    assert.doesNotMatch(args, /\be\.|\bentry\b|cwe|files|ranges|manifest/i, `discoverTree(${args}) must not receive label data`);
  }
});

test('an exhausted budget and a hard stop are recorded as incomplete, never as clean', async () => {
  const dir = tmpTree(APP);
  try {
    const exhausted = async () => ({ fresh: [], runs: [{ candidateCount: 0, degraded: true, reason: 'hunter llm call failed: discovery budget exhausted' }], duplicates: [], refutedCandidates: [],
      coverage: { areasPlanned: 1, degradedRuns: 1, llmCalls: 0, maxLlmCalls: 200, budgetExhausted: true, candidatesCapped: 0, reasons: ['RUN INCOMPLETE'] } });
    const a = await discoverTree(dir, [], { model: 'm', host: 'http://127.0.0.1:11434', budgetMs: 60000 }, { runDiscoveryImpl: exhausted });
    assert.equal(a.summary.complete, false);
    assert.equal(a.summary.budgetExhausted, true);
    const never = () => new Promise(() => {});
    const b = await discoverTree(dir, [], { model: 'm', host: 'http://127.0.0.1:11434', budgetMs: 20 }, { runDiscoveryImpl: never, graceMs: 20 });
    assert.equal(b.summary.timedOut, true);
    assert.equal(b.summary.complete, false);
    assert.deepEqual(b.findings, []);
    const totals = discoveryTotals([{ discovery: { pre: a.summary, post: b.summary } }, { tp: 1 }]);
    assert.equal(totals.trees, 2);
    assert.equal(totals.incompleteTrees, 2);
    assert.equal(totals.budgetExhaustedTrees, 1);
    assert.equal(totals.timedOutTrees, 1);
    assert.equal(totals.entriesWithIncompleteDiscovery, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('discovery that writes into the scanned tree fails the entry', async () => {
  const dir = tmpTree(APP);
  try {
    const writer = async () => { fs.writeFileSync(path.join(dir, 'planted.json'), '{}'); return { fresh: [], runs: [], coverage: {} }; };
    await assert.rejects(discoverTree(dir, [], { model: 'm', host: 'http://127.0.0.1:11434', budgetMs: 60000 }, { runDiscoveryImpl: writer }));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('end to end against a loopback Ollama: the real pipeline runs under the preset and its findings carry the DISCOVERY parser', async () => {
  const dir = tmpTree(APP);
  const { server, seen, host } = await fakeOllama({ refuted: false });
  try {
    const r = await discoverTree(dir, [], { model: 'local-model:1b', host, budgetMs: 60000 });
    assert.ok(seen.chat > 0, 'the model was called through the ollama preset');
    assert.ok(seen.prompts.every((p) => !/CWE-\d+|GHSA-/.test(p.split('--- SOURCE FILE')[0])), 'no label vocabulary in the instructions');
    assert.ok(r.findings.length >= 1);
    assert.equal(r.findings[0].parser, 'DISCOVERY');
    assert.equal(r.findings[0].file, 'src/db.js');
    assert.equal(r.summary.llmCalls, seen.chat, 'every call was counted by the product budget');
    assert.equal(r.summary.unparseableRuns, 0);
    assert.equal(fs.existsSync(path.join(dir, '.agentic-security')), false, 'no state written into the tree');
  } finally { server.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ product seams
test('selectHuntFiles is the CLI selection: source languages only, dependency and build directories skipped', async () => {
  const dir = tmpTree({ ...APP, 'pkg/x.py': 'x = 1\n', 'vendor/y.go': 'package y\n', '.agentic-security/state.js': 'x\n' });
  try {
    const sel = await selectHuntFiles(dir);
    assert.equal(sel.overCap, false);
    assert.deepEqual(Object.keys(sel.fileContents).sort(), ['pkg/x.py', 'src/app.js', 'src/db.js']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the run budget bounds a model callback resolved from configuration, not only an injected one', async () => {
  const { server, seen, host } = await fakeOllama();
  const keys = ['AGENTIC_SECURITY_LLM_PRESET', 'AGENTIC_SECURITY_OLLAMA_HOST', 'AGENTIC_SECURITY_LLM_MODEL'];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  Object.assign(process.env, { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: host, AGENTIC_SECURITY_LLM_MODEL: 'local-model:1b' });
  try {
    const fileContents = { 'src/app.js': APP['src/app.js'], 'src/db.js': APP['src/db.js'] };
    const { perFile, callGraph } = buildProjectIR(fileContents);
    const report = await runDiscovery({ perFileIR: perFile, callGraph, fileContents }, { maxLlmCalls: 3 });
    assert.equal(seen.chat, 3, 'no fourth call reached the model');
    assert.equal(report.coverage.llmCalls, 3);
    assert.equal(report.coverage.budgetExhausted, true);
    assert.ok(report.coverage.reasons.some((r) => /RUN INCOMPLETE/.test(r)));
  } finally {
    for (const k of keys) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    server.close();
  }
});

// ------------------------------------------------------------------ driver configuration and identity
test('the driver: deterministic config unchanged, discovery config carries model, budget and loopback mode', () => {
  assert.deepEqual(configRunnerArgs(CONFIG_DEEP), ['--deep']);
  assert.equal(configFromArgs(['--run']), CONFIG_DEEP);
  const c = configFromArgs(['--run', '--discovery', '--discovery-model', 'local:4b', '--discovery-budget-min', '5']);
  assert.equal(c.name, 'deep+discovery');
  assert.equal(c.model, 'local:4b');
  assert.equal(c.modelEndpointMode, 'loopback');
  assert.deepEqual(configRunnerArgs(c), ['--deep', '--discovery', '--discovery-model=local:4b', '--discovery-budget-min=5']);
  assert.throws(() => configDeepDiscovery({}), /needs a model/);
  assert.equal(defaultChunkTimeoutMs(CONFIG_DEEP, 20), 90 * 60000);
  assert.equal(defaultChunkTimeoutMs(c, 2), 2 * (2 * (5 + 5 + 1) + 5) * 60000, 'two sides, each up to the budget plus one model call plus the grace minute');
});

test('the identity names a preset model and its endpoint mode', () => {
  const local = configSnapshot({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_LLM_MODEL: 'local:4b' });
  assert.equal(local.modelEndpointMode, 'loopback');
  assert.equal(local.modelPreset, 'ollama');
  assert.equal(local.model, 'local:4b');
  assert.equal(configSnapshot({ AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_OLLAMA_HOST: 'http://10.1.2.3:11434' }).modelEndpointMode, 'remote');
  assert.equal(configSnapshot({}).modelEndpointMode, 'none');
  assert.equal(configSnapshot({ AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:8080' }).modelEndpointMode, 'loopback');
});
