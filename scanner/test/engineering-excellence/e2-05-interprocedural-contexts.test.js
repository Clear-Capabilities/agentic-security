// E2-05: interprocedural contexts: distinct call sites, recursion, no exponential growth, explicit incompleteness on budget exhaustion.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { buildProjectIR } from '../../src/ir/index.js';
import { runTaintEngine, INCOMPLETE_REASONS } from '../../src/dataflow/engine.js';
import { SummaryCache } from '../../src/dataflow/summaries.js';

// Deep analysis is off under CI unless asked for (engine.js); these tests need the deep layer, so a hosted runner must not change what they measure.
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

const H = "const { exec } = require('child_process');\nconst express = require('express');\nconst app = express();\n";
async function scan(src, env = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2e-'));
  const saved = {}; for (const k of Object.keys(env)) saved[k] = process.env[k];
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}'); fs.writeFileSync(path.join(root, 'a.js'), src);
    process.env.AGENTIC_SECURITY_DEEP = '1'; Object.assign(process.env, env);
    return (await runScan(root)).scan;
  } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } cleanup(root); }
}
const cmdi = (s) => s.findings.filter((f) => /CWE-78$/.test(f.cwe || '') && f.parser === 'IR-TAINT');
const route = (body, pre = '') => `${H}${pre}app.get('/a', (req, res) => {\n${body}\n});\n`;

test('distinct call sites of one helper are treated separately: the clean call does not inherit the tainted one', async () => {
  const pre = "function id(v) { return v; }\n";
  assert.equal(cmdi(await scan(route("  const a = id(req.query.c);\n  const b = id('ls');\n  exec('x ' + a);", pre))).length, 1);
  assert.equal(cmdi(await scan(route("  const a = id(req.query.c);\n  const b = id('ls');\n  exec('x ' + b);", pre))).length, 0);
});

test('a wrapper reports its sink only for the call that passes tainted data', async () => {
  const pre = "function run(cmd) { exec('x ' + cmd); }\n";
  assert.equal(cmdi(await scan(route("  run('ls');", pre))).length, 0);
  assert.equal(cmdi(await scan(route("  run('ls');\n  run(req.query.c);", pre))).length, 1);
});

test('self recursion and mutual recursion terminate, find the flow, and keep the clean twin silent', async () => {
  const self = (arg) => route(`  rec(3, ${arg});`, "function rec(n, v) { if (n <= 0) { exec('x ' + v); return; } rec(n - 1, v); }\n");
  assert.equal(cmdi(await scan(self('req.query.c'))).length, 1);
  assert.equal(cmdi(await scan(self("'ls'"))).length, 0);
  const mut = (arg) => route(`  a(4, ${arg});`, "function a(n, v) { if (n <= 0) { exec('x ' + v); return; } b(n - 1, v); }\nfunction b(n, v) { a(n - 1, v); }\n");
  assert.equal(cmdi(await scan(mut('req.query.c'))).length, 1);
  assert.equal(cmdi(await scan(mut("'ls'"))).length, 0);
});

test('no exponential growth: a diamond of two-calls-per-level wrappers, 24 levels deep, is found once and quickly', async () => {
  let pre = ''; for (let i = 0; i < 24; i++) pre += `function f${i}(x) { return f${i + 1}(x) + f${i + 1}(x); }\n`; pre += "function f24(x) { exec('x ' + x); return x; }\n";
  const t0 = Date.now();
  const s = await scan(route('  f0(req.query.c);', pre));
  assert.equal(cmdi(s).length, 1, 'one sink, one finding');
  assert.ok(Date.now() - t0 < 30000);
  assert.equal(cmdi(await scan(route("  f0('ls');", pre))).length, 0);
});

test('a 300-deep call chain is followed to its sink', async () => {
  let pre = ''; for (let i = 0; i < 300; i++) pre += `function g${i}(x) { return g${i + 1}(x); }\n`; pre += "function g300(x) { exec('x ' + x); }\n";
  assert.equal(cmdi(await scan(route('  g0(req.query.c);', pre))).length, 1);
});

test('a callee finding is merged into its caller once, however many times the call is evaluated', () => {
  let src = ''; for (let i = 0; i < 20; i++) src += `function g${i}(x) { return g${i + 1}(x); }\n`; src += "function g20(x) { require('child_process').exec('x ' + x); }\nexports.h = (req) => { g0(req.query.c); };\n";
  const ir = buildProjectIR({ 'a.js': src });
  const found = runTaintEngine(ir.perFile, ir.callGraph, {});
  assert.equal(found.filter((f) => /CWE-78$/.test(f.cwe)).length, 1);
});

test('budget exhaustion is reported, never silent: function limit, time budget, summary budget', async () => {
  const many = (() => { let s = ''; for (let i = 0; i < 12; i++) s += `function h${i}(x) { exec('x ' + x); }\n`; return s; })();
  const limited = await scan(route("  h0(req.query.c);", many), { AGENTIC_SECURITY_DEEP_FN_LIMIT: '3' });
  const inc = limited.scanHealth.deepAnalysis.incomplete;
  assert.ok(limited.scanHealth.conditions.some((c) => /analysis_incomplete/.test(c)), 'it is also a health condition');
  assert.ok(Array.isArray(inc) && inc.some((x) => x.reason === 'function-limit' && x.count >= 1), JSON.stringify(inc));
  assert.ok(inc.every((x) => x.reason in INCOMPLETE_REASONS && x.example !== undefined));

  const complete = await scan(route("  h0(req.query.c);", many));
  assert.equal('incomplete' in complete.scanHealth.deepAnalysis, false, 'a complete run says nothing');

  const ir = buildProjectIR({ 'a.js': many + "exports.h = (req) => { h0(req.query.c); h1(req.query.c); h2(req.query.c); };\n" });
  const late = runTaintEngine(ir.perFile, ir.callGraph, { deadlineMs: Date.now() - 1 });
  assert.ok(late.analysisIncomplete.some((x) => x.reason === 'deadline'));

  const tiny = new SummaryCache(); tiny._maxIter = 2;
  const starved = runTaintEngine(ir.perFile, ir.callGraph, { summaryCache: tiny });
  assert.ok(tiny._budgetHits > 0);
  assert.ok(starved.analysisIncomplete.some((x) => x.reason === 'summary-budget'), JSON.stringify(starved.analysisIncomplete));
  assert.deepEqual(runTaintEngine(ir.perFile, ir.callGraph, {}).analysisIncomplete, [], 'an unconstrained run reports nothing');
});

test('every incompleteness reason has a stated meaning', () => {
  for (const [k, v] of Object.entries(INCOMPLETE_REASONS)) { assert.match(k, /^[a-z-]+$/); assert.ok(v.length > 30); }
});
