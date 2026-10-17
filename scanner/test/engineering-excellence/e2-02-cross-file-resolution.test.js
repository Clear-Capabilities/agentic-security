// E2-02: import-aware cross-file resolution, end to end. Every positive has a matched safe twin; cycles and unresolved imports terminate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { cleanup } from './helpers.js';
import { runScan } from '../../src/runScan.js';
import { buildProjectIR, buildProjectIRAsync } from '../../src/ir/index.js';
import { MAX_HOPS, buildModuleIndex, extractJsFacts, extractPyFacts } from '../../src/ir/module-resolver.js';

// Deep analysis is off under CI unless asked for (engine.js); these tests need the deep layer, so a hosted runner must not change what they measure.
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

const UTIL_VULN = "const { exec } = require('child_process');\nexports.exec = (c) => exec('sh -c ' + c);\n";
const UTIL_SAFE = "const { execFile } = require('child_process');\nexports.exec = (c) => execFile('sh', ['-c', 'true', String(c)]);\n";
const SERVICE = "const util = require('./util');\nexports.run = (c) => util.exec(c);\n";
const ROUTES = "const svc = require('./service');\nexports.handler = (req, res) => {\n  const out = svc.run(req.query.cmd);\n  res.send(out);\n};\n";

async function scanFiles(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2b-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0' }));
    for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true }); fs.writeFileSync(path.join(root, f), t); }
    const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
    let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
    return scan.findings.filter((f) => /CWE-78$|CWE-77$/.test(f.cwe || '') && f.parser === 'IR-TAINT').map((f) => `${f.file}:${f.line}`).sort();
  } finally { cleanup(root); }
}
const index = (files) => { const ir = buildProjectIR(files); return buildModuleIndex(files, ir.perFile); };

// ---- resolver ---------------------------------------------------------------------------------------------------------------

test('CommonJS: a member call through a required module, a destructured require, and module.exports = {..} all resolve to the exporting function', () => {
  const files = { 'routes.js': ROUTES, 'service.js': SERVICE, 'util.js': UTIL_VULN };
  const idx = index(files);
  const r = idx.resolveCall('routes.js', 'svc.run');
  assert.equal(r.status, 'resolved'); assert.match(r.qid, /^service\.js::.*run/); assert.equal(r.file, 'service.js');
  assert.equal(idx.resolveCall('service.js', 'util.exec').status, 'resolved');
  const d = index({ 'a.js': "const { run: go, other } = require('./b');\ngo(1);\n", 'b.js': "function run(x) { return x; }\nfunction other() {}\nmodule.exports = { run, other };\n" });
  assert.equal(d.resolveCall('a.js', 'go').status, 'resolved'); assert.match(d.resolveCall('a.js', 'go').qid, /b\.js::.*run/);
  assert.match(d.resolveCall('a.js', 'other').qid, /b\.js::.*other/);
  const m = index({ 'a.js': "const f = require('./b');\nf(1);\n", 'b.js': "module.exports = function handler(x) { return x; };\n" });
  assert.equal(m.resolveCall('a.js', 'f').status, 'resolved');
});

test('ES modules: named, aliased, default, namespace, barrel re-export, export * and TypeScript .js specifiers resolve; hops are reported', () => {
  const files = {
    'a.ts': "import { run as go } from './index.js';\nimport def from './d';\nimport * as ns from './d';\ngo(1); def(2); ns.helper(3);\n",
    'index.ts': "export { run } from './svc';\nexport * from './more';\n",
    'svc.ts': "export function run(x: number) { return x; }\n",
    'more.ts': "export function extra() {}\n",
    'd.ts': "export default function main() {}\nexport function helper() {}\n",
  };
  const idx = index(files);
  const go = idx.resolveCall('a.ts', 'go');
  assert.equal(go.status, 'resolved'); assert.match(go.qid, /svc\.ts::.*run/);
  assert.ok(go.hops.length >= 2, 'the barrel hop is recorded');
  assert.equal(idx.resolveCall('a.ts', 'def').status, 'resolved'); assert.match(idx.resolveCall('a.ts', 'def').qid, /d\.ts::.*main/);
  assert.match(idx.resolveCall('a.ts', 'ns.helper').qid, /d\.ts::.*helper/);
  assert.match(idx.resolveExport('index.ts', 'extra').qid, /more\.ts::.*extra/, 'export * reaches the target');
});

test('termination: a re-export cycle ends as cycle, a chain longer than the bound as depth-limit, never a hang', () => {
  const cyc = index({ 'a.js': "export { f } from './b.js';\n", 'b.js': "export { f } from './a.js';\n", 'u.js': "import { f } from './a.js';\nf();\n" });
  const r = cyc.resolveCall('u.js', 'f');
  assert.equal(r.status, 'cycle'); assert.match(r.reason, /cycle/);
  const files = { 'u.js': "import { f } from './m0.js';\nf();\n", [`m${MAX_HOPS + 3}.js`]: 'export function f() {}\n' };
  for (let i = 0; i < MAX_HOPS + 3; i++) files[`m${i}.js`] = `export { f } from './m${i + 1}.js';\n`;
  const deep = index(files).resolveCall('u.js', 'f');
  assert.equal(deep.status, 'depth-limit'); assert.ok(deep.hops.length <= MAX_HOPS + 1);
});

test('unresolved, external, aliased, dynamic and ambiguous cases each get their own named status and never a guess', () => {
  const idx = index({
    'u.js': "import { gone } from './missing.js';\nimport fs from 'fs';\nimport axios from 'axios';\nimport { at } from '@/lib/x';\nconst dyn = require(name);\nimport * as star from './stars.js';\ngone(); fs.readFile(); axios.get(); at(); star.dup();\nstar.a.b.c();\n",
    'stars.js': "export * from './s1.js';\nexport * from './s2.js';\n",
    's1.js': 'export function dup() {}\n', 's2.js': 'export function dup() {}\n',
  });
  assert.equal(idx.resolveCall('u.js', 'gone').status, 'unresolved-import');
  assert.equal(idx.resolveCall('u.js', 'fs.readFile').status, 'external');
  assert.equal(idx.resolveCall('u.js', 'axios.get').status, 'external');
  const alias = idx.resolveCall('u.js', 'at'); assert.equal(alias.status, 'unresolved-import'); assert.match(alias.reason, /alias/);
  const amb = idx.resolveCall('u.js', 'star.dup'); assert.equal(amb.status, 'ambiguous'); assert.equal(amb.candidates.length, 2);
  assert.equal(idx.resolveCall('u.js', 'star.a.b.c').status, 'unsupported');
  assert.equal(idx.resolveCall('u.js', 'notImported').status, 'not-imported');
  assert.ok(idx.facts.get('u.js').unsupported.includes('dynamic-require'), 'the syntax it cannot follow is listed');
  assert.equal(idx.resolveCall('nofile.js', 'x').status, 'no-facts');
});

test('Python: from-import, aliased module import, dotted import and relative import resolve; stdlib is external', () => {
  const files = { 'pkg/__init__.py': '', 'pkg/db.py': 'def run(q):\n    return q\n', 'pkg/api.py': 'from . import db\nfrom .db import run as go\ndb.run(1)\ngo(2)\n', 'app.py': 'import pkg.db\nimport pkg.db as store\nfrom pkg.db import run\nimport os\nrun(1)\nstore.run(2)\npkg.db.run(3)\nos.system("x")\n' };
  const idx = index(files);
  for (const [from, call] of [['app.py', 'run'], ['app.py', 'store.run'], ['app.py', 'pkg.db.run'], ['pkg/api.py', 'go']]) {
    const r = idx.resolveCall(from, call);
    assert.equal(r.status, 'resolved', `${from} ${call}: ${r.status} ${r.reason || ''}`); assert.match(r.qid, /pkg\/db\.py/);
  }
  assert.equal(idx.resolveCall('app.py', 'os.system').status, 'external');
});

test('hostile input does not throw: unparseable files, huge files and odd specifiers produce facts that say so', () => {
  const idx = index({ 'bad.js': 'import { from "x"; (((', 'ok.js': "import { a } from './bad.js';\na();\n" });
  assert.ok(idx.facts.get('bad.js').unsupported.includes('parse-failed'));
  assert.doesNotThrow(() => idx.resolveCall('ok.js', 'a'));
  assert.doesNotThrow(() => idx.resolveCall('ok.js', ''));
  assert.doesNotThrow(() => idx.resolveCall(undefined, 'a'));
  assert.equal(extractJsFacts('x.js', 'const a = 1;').imports.length, 0);
  assert.equal(extractPyFacts('x.py', 'import os, sys as s\n').imports.length, 2);
});

// ---- call graph --------------------------------------------------------------------------------------------------------------

test('the call graph records import edges with their hops, and a call bound to an external package no longer binds to a same-named project function', () => {
  const files = { 'util.js': UTIL_VULN, 'service.js': SERVICE, 'routes.js': ROUTES };
  const ir = buildProjectIR(files);
  const viaImport = ir.callGraph.edges.find((e) => e.calleeName === 'util.exec');
  assert.equal(viaImport.via, 'import'); assert.match(viaImport.callee, /util\.js::.*exec/); assert.ok(viaImport.hops.length >= 1);
  const ext = ir.callGraph.edges.find((e) => e.caller.startsWith('util.js') && e.calleeName === 'exec');
  assert.equal(ext.callee, null, 'child_process exec is not the module\'s own exports.exec');
  assert.equal(ext.external, true);
  assert.equal(ir.callGraph.resolve('svc.run', 'routes.js'), ir.callGraph.resolveKnownCallee('svc.run', 'routes.js'));
});

// ---- end to end through the scanner ------------------------------------------------------------------------------------------

test('three files, CommonJS: the vulnerable chain is found at the real sink line and its safe twin is silent', async () => {
  const vuln = await scanFiles({ 'routes.js': ROUTES, 'service.js': SERVICE, 'util.js': UTIL_VULN });
  assert.ok(vuln.includes('util.js:2'), JSON.stringify(vuln));
  assert.ok(!vuln.some((x) => x.startsWith('service.js')), 'the pass-through helper is not reported as a sink');
  assert.deepEqual(await scanFiles({ 'routes.js': ROUTES, 'service.js': SERVICE, 'util.js': UTIL_SAFE }), []);
});

test('three files, ES modules with a barrel re-export: found, and the safe twin is silent', async () => {
  const mk = (sink) => ({ 'routes.js': "import { run } from './index.js';\nexport function handler(req, res) { res.send(run(req.query.cmd)); }\n", 'index.js': "export { run } from './service.js';\n", 'service.js': `import { exec, execFile } from 'child_process';\nexport function run(c) { return ${sink}; }\n` });
  assert.ok((await scanFiles(mk("exec('sh -c ' + c)"))).includes('service.js:2'));
  assert.deepEqual(await scanFiles(mk("execFile('sh', ['-c', 'true', String(c)])")), []);
});

test('precision: two modules export the same name; the route imports the safe one and nothing is reported, imports the dangerous one and it is', async () => {
  const base = { 'safe.js': UTIL_SAFE.replace('exports.exec', 'exports.go'), 'danger.js': UTIL_VULN.replace('exports.exec', 'exports.go') };
  const routes = (m) => `const m = require('./${m}');\nexports.handler = (req, res) => {\n  res.send(m.go(req.query.cmd));\n};\n`;
  assert.deepEqual(await scanFiles({ ...base, 'routes.js': routes('safe') }), [], 'the dangerous module of the same name is not mistaken for the imported one');
  assert.ok((await scanFiles({ ...base, 'routes.js': routes('danger') })).includes('danger.js:2'));
});

test('a mutual-import cycle terminates in bounded time and the flow through it is still found', async () => {
  const t0 = Date.now();
  const found = await scanFiles({
    'a.js': "const b = require('./b');\nexports.f = (x) => b.g(x);\n",
    'b.js': "const a = require('./a');\nconst { exec } = require('child_process');\nexports.g = (x) => (x ? a.f(x - 1) : exec('echo ' + x));\n",
    'routes.js': "const a = require('./a');\nexports.h = (req, res) => res.send(a.f(req.query.n));\n",
  });
  assert.ok(found.includes('b.js:3'), JSON.stringify(found));
  assert.ok(Date.now() - t0 < 60000);
});

test('an unresolved import does not break the scan or invent a finding', async () => {
  assert.deepEqual(await scanFiles({ 'routes.js': "const svc = require('./not-there');\nexports.handler = (req, res) => res.send(svc.run(req.query.cmd));\n" }), []);
});
